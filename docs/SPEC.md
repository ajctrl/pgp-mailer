# pgp-mailer initial specification

A general-purpose PGP mail notification service built with Go and distroless. HTTP inputs use configurable routes and conversion rules; encryption, the persistent queue and SMTP delivery are shared.

The [configurable intake extension](inputs.md) supersedes fixed-route and unconditional intake-secret requirements below. The original two routes remain the default presets.

This document defines how the default configuration behaves. How the implementation settles points it leaves open is described in [implementation-notes.md](implementation-notes.md).

## Runtime environment and layout

- A static Go binary; OpenPGP processing is done entirely in Go.
- The container is distroless, nonroot and read-only. Only the persistent queue is writable.
- The service uses a dedicated Docker network inside the Portainer stack and does not publish its port to the host.
- Inside the stack, connections use HTTP with authentication. If the service is exposed externally, a reverse proxy provides HTTPS.
- Gotify is notified directly by Grafana over a separate path.

```text
Grafana ── HTTP + HMAC ───→ pgp-mailer ── SMTP/TLS ──→ PGP mail
Other apps ─ HTTP + Bearer ─┘
```

## Common input

- `POST /v1/messages`, JSON, Bearer authentication.
- Input is UTF-8, at most 256 KiB for the whole request. Attachments are not supported.
- In the initial version the only destination is the configured `ops`. Requests may not name arbitrary addresses.

| Field | Specification |
| --- | --- |
| `receiver` | Required. Only `ops` is allowed |
| `title` | Required, 1 to 200 characters. Whitespace-only values and values containing line breaks are rejected |
| `message` | Required, at most 64 KiB. Whitespace-only values are rejected |
| `level` | Optional. Lower case only, one of `trace / debug / info / warn / error / fatal / unknown`. Defaults to `info`. Anything else is `422` |

```json
{
  "receiver": "ops",
  "title": "Error rate rising",
  "message": "15 errors in the last 5 minutes.",
  "level": "error"
}
```

### Acceptance and de-duplication

- `202 Accepted` and an acceptance ID are returned after encryption and persistence complete. SMTP sending is asynchronous.
- `Idempotency-Key` is required. Callers issue a new key for each notification and reuse the same key when retrying after a communication failure.
- A key is 1 to 128 printable ASCII characters. A missing or malformed key is `400`.
- Keys are scoped per caller (Bearer token) and never collide with another caller's keys.
- Same key, same content: `202` with the same acceptance ID, and nothing more is sent.
- Same key, different content: `409 Conflict`.
- If an earlier request with the same key is still being accepted: `409 Conflict` (distinguished from a content mismatch by the error type). The caller retries later with the same key.
- If acceptance fails (`4xx`, `5xx`), the key is not recorded, and a retry with the same key is accepted.
- Different keys mean separate notifications, even with the same title.
- De-duplication records are kept while processing and for 24 hours after processing ends, without the message content. The delivery queue stores the encrypted mail.
- A full queue is `503`. A write failure or an encryption failure also fails the acceptance. There is never a fallback to plaintext.

## Grafana input

- `POST /webhooks/grafana`.
- A timestamped HMAC-SHA256 signature is verified.
- One webhook is converted to the common format and handled as one mail. Both firing and resolved notifications are sent.
- No `Idempotency-Key` is needed. De-duplication is based on the body, as described below.
- The acceptance rules (`202` after encryption and persistence, `503` when the queue is full, never plaintext) are the same as for the common input. An invalid or missing signature is `401`; more than 256 KiB is `413`.
- Conversion rules:
  - `receiver` is always `ops`.
  - `title` is the webhook's `title`. Line breaks and control characters are replaced with spaces, and anything beyond 200 characters is cut off.
  - `level` is `error` for `firing` and `info` for `resolved`.
  - `message` is the webhook's `message`. If it exceeds 64 KiB, the end is cut off and a note about the truncation is appended to the body (it is not rejected, so the alert is not lost).
- For each sender, an identical request body is suppressed for 5 minutes. The signature timestamp header is not used to identify requests.
- A suppressed request also gets `202` with the original acceptance ID, so Grafana does not retry.
- A change in the body or in the firing/resolved state makes a separate notification. After 5 minutes, the same content is treated as a new notification.
- Grafana's repeat notifications are set to a 1-hour interval.
- De-duplication is best effort. An intended identical notification within 5 minutes is also suppressed, and a resend after more than 5 minutes may be a duplicate.

## Public key and the startup encryption check

- The public key is read from `PGP_PUBLIC_KEY_BASE64`.
- The full fingerprint of the primary key is compared with `PGP_FINGERPRINT`.
- The public key, its expiry, revocation information and encryption subkeys are verified.
- The recipient's secret key is never placed on the server.

### Mandatory startup checks

Verifying the key information alone does not make startup succeed; the following real encryption test is required.

1. Load the public key, check the fingerprint, and verify expiry, revocation information and the encryption subkey.
2. Using the verified public key, actually encrypt a short piece of test data in memory.
3. Confirm that the ciphertext is produced successfully, including the finalisation of the encryption.
4. Start HTTP intake and delivery from the queue only if all of the above succeed.

If the check fails, it is handled as follows depending on the reason. In neither case is there a fallback to plaintext.

| Reason | Handling |
| --- | --- |
| Key not set, cannot be parsed, fingerprint mismatch, revoked, no encryption subkey, or encryption test failed | Startup fails. Neither intake nor delivery of the existing queue starts |
| Expired only (the primary key has expired, or every valid encryption subkey has expired; the fingerprint matches and the key is not revoked) | Start in delivery-only mode |

The existing queue is already encrypted, so technically it could be delivered. The first case still stops everything so that nothing is delivered before a decision on quarantine has been made, in a situation where the key may be misconfigured or compromised. Expiry does not indicate compromise, so it is no reason to stop delivery.

#### Delivery-only mode

- After quarantine (`PGP_QUARANTINE_FINGERPRINTS`) has been applied, delivery of the existing queue starts.
- An expired key cannot encrypt, so the encryption test is not run.
- `POST /v1/messages` and `POST /webhooks/grafana` return `503` after authentication (error type `key_expired`).
- The admin API and `/metrics` work as usual.
- `/healthz` returns `503` and `pgp_mailer_key_valid` is `0`, so monitoring can detect the state.
- A key that expires while the service is running leads to the same mode.
- To recover, set a public key with an extended expiry (same fingerprint) or a new key, and recreate the container.

Items whose retry deadline (1 hour after acceptance) passed while the service was stopped move to the failed queue after startup. They can be resent manually during the 24-hour retention.

No test mail is sent, and neither the test data nor its ciphertext is stored in the queue. Because the server holds no secret key, the test does not include decryption. Decryption is verified separately on the receiving side.

### Key replacement and handling while running

| Situation | Handling |
| --- | --- |
| Normal key replacement | Update the Base64 public key and the fingerprint and recreate the container. After the startup checks succeed, new notifications use the new key |
| Queue from before the replacement | Encrypted mail is sent as it is. The receiving side keeps the old secret key as well |
| Expiry (while running or at startup) | Checked before encryption; the service moves to delivery-only mode. New requests get `503`; existing ciphertext keeps being delivered |
| Emergency revocation because of compromise or misconfiguration | Items for the specified key are quarantined and their delivery stops. Callers resend the notifications they need |

Revocation information is verified as contained in the loaded public key; new revocation information takes effect when the key is updated. Re-encrypting old ciphertext to a new public key is not implemented.

## Mail and delivery

- PGP/MIME is used, with a static outer subject configurable per input. The original subject and body go inside the encrypted part.
- Outer headers such as recipient and sender are in plaintext.
- The outer `Message-ID` and `Date` are generated at acceptance, stored in the queue, and reused on every resend.
- SMTP uses implicit TLS or mandatory STARTTLS, with certificate verification.
- Responsibility ends at a successful hand-over to the SMTP server. Arrival in the inbox and a complete absence of duplicates during delivery are not guaranteed.

### Error classification

| Kind | Examples | Handling |
| --- | --- | --- |
| Temporary error | SMTP `4xx`, connection failure, DNS failure, timeout, TLS certificate verification failure | Retried until the retry deadline |
| Permanent error | SMTP `5xx` in response to sending the mail (`MAIL FROM` through `DATA`) | Moved to the failed queue at once |

A certificate verification failure can resolve itself (for example, when certificate renewal is out of step), so it is a temporary error. It is still logged as an error.

A `5xx` during connection or authentication (authentication failure `535`, `554` on connect, and so on) is a problem with the server or the configuration, not with an individual mail, so it is a temporary error. Once fixed, mails still within their retry deadline are delivered automatically. It is logged as an error. After a connection or authentication failure, the next connection waits for the same interval as the retry schedule (30 seconds up to at most 5 minutes).

## Persistent queue, retries and retention

- Encrypted mail is stored in the persistent queue.
- The retry deadline is 1 hour after acceptance. After it passes, the item moves to the failed queue.
- Temporary errors are retried after 30 seconds → 1 minute → 2 minutes → 4 minutes → at most 5 minutes. Each interval gets ±20% jitter.
- Permanent errors also move items to the failed queue.
- Pending items, the failed queue and management data together have an application-level storage limit of 256 MiB. Requests beyond the limit get `503`.
- The failed queue counts toward the limit, so a prolonged outage can make new requests get `503`. This is accepted and detected through monitoring.
- The failed queue keeps ciphertext for 24 hours, then deletes it automatically. During retention, items can be resent or deleted manually.
- The queue volume must be writable by the distroless nonroot UID/GID `65532`.

### Shutdown

- On `SIGTERM`, intake stops and an SMTP transmission in progress is given up to 30 seconds to complete.
- Mail that did not complete stays in the queue and is resent at the next start. Duplicates may therefore occur across a shutdown.

## Configuration

| Environment variable | Contents |
| --- | --- |
| `PGP_PUBLIC_KEY_BASE64` | The recipient's public key (Base64) |
| `PGP_FINGERPRINT` | Full fingerprint of the primary key |
| `SMTP_HOST` / `SMTP_PORT` | SMTP server |
| `SMTP_TLS_MODE` | `implicit` or `starttls` |
| `SMTP_USERNAME` / `SMTP_PASSWORD` | SMTP credentials |
| `MAIL_FROM` | Sender address |
| `RECEIVER_OPS` | Destination address of `ops` |
| `API_TOKENS` | Pairs of caller name and Bearer token |
| `GRAFANA_HMAC_SECRET` | Shared secret for verifying Grafana signatures |
| `QUEUE_DIR` | Directory of the persistent queue |
| `ADMIN_TOKEN` | Bearer token for the admin API |
| `PGP_QUARANTINE_FINGERPRINTS` | Primary key fingerprints to quarantine on emergency revocation (comma-separated, optional) |

Missing or invalid settings make startup fail.

- Secrets (`SMTP_PASSWORD`, `API_TOKENS`, `GRAFANA_HMAC_SECRET`, `ADMIN_TOKEN`) can also be given through `*_FILE` variables (a file path) for Docker secrets. Setting both for the same item makes startup fail.
- `API_TOKENS` is a comma-separated list of `name:token`. Names match `[a-z0-9-]{1,32}`; tokens are at least 32 characters. Duplicate names or tokens, or use of the reserved name `grafana`, make startup fail.
- Tokens are compared in constant time.

## Logging and monitoring

- Logs never contain `title`, `message`, plaintext bodies or secrets (tokens, the HMAC secret, the SMTP password).
- Logs may contain the acceptance ID, caller name, `receiver`, `level`, result, SMTP reply code and retry count.
- `GET /healthz` requires no authentication. It returns `200` only if the key is valid (not expired) and the queue is writable, and `503` otherwise.
- distroless has no shell or curl, so a `pgp-mailer healthcheck` subcommand is provided for the Docker health check. It calls `/healthz` and reports the result as its exit code.
- Moves to the failed queue, key expiry and storage pressure are detected by monitoring `/metrics` in Grafana (see "Metrics").

## Detailed specification

### Character counts and content comparison

- Invalid UTF-8 input is `400`.
- The length of `title` is counted in Unicode code points. The limit on `message` is counted in bytes.
- No Unicode normalisation is applied; values are compared as byte sequences.
- For the common input, content is compared by the SHA-256 of the length-prefixed concatenation of the validated, defaulted `receiver`, `title`, `message` and `level`. JSON key order and whitespace do not affect it.
- Grafana de-duplication uses the SHA-256 of the raw bytes of the request body.

### Persistence

- The pure Go embedded KV store bbolt (`go.etcd.io/bbolt`) is used, with a single file in `QUEUE_DIR`.
- De-duplication records, pending items, the failed queue, the quarantine queue and the storage counter are kept in the same file. At acceptance, the de-duplication record and the queue entry are committed in one write transaction.
- `202` is returned only after the transaction has committed (fsync completed).

### Grafana HMAC signature

- The HMAC signature setting of Grafana's webhook contact point is used (this requires a Grafana version that has the HMAC setting; some sources say it first appeared in 11.6 or 12.0, so check the contact point settings of the version in use).
  - Signature header: `X-Grafana-Alerting-Signature` (Grafana's default). The value is the HMAC-SHA256 in lower-case hex, without a prefix such as `sha256=`.
  - Timestamp header: `X-Grafana-Alerting-Timestamp`. Grafana has no default name, so this name must be set as the contact point's Timestamp Header. The value is Unix seconds as a decimal string.
  - Signed data: `timestamp + ":" + raw bytes of the request body`
- The receiver verifies the signature over the raw bytes before parsing the body as JSON. The hex is decoded and compared in constant time with `hmac.Equal`.
- The allowed clock difference is ±5 minutes.
- A missing signature or timestamp, a malformed value, a mismatch, or a clock difference beyond the limit all return `401`. The reason is recorded only in the log, not in the response body.
- The above has been confirmed with Grafana's official documentation and its signing implementation (`http/hmac.go` in `grafana/alerting`). Integration testing also confirms reception from a real Grafana.

### Grafana sender and suppression window

- There is one Grafana instance, treated as the fixed sender `grafana`, with one HMAC secret.
- The suppression window is fixed at 5 minutes from the first reception. Duplicates do not extend it.

### Manual resend and deletion

- The admin API uses Bearer authentication with `ADMIN_TOKEN`.
  - `GET /admin/v1/failed` lists items (acceptance ID, caller, `level`, failure reason and times only; no content)
  - `POST /admin/v1/failed/{acceptance ID}/retry` resends
  - `DELETE /admin/v1/failed/{acceptance ID}` deletes
  - For the quarantine queue: `GET /admin/v1/quarantine` and `DELETE /admin/v1/quarantine/{acceptance ID}`
- A `pgp-mailer admin ...` subcommand is provided to call the admin API via `docker exec`. bbolt cannot be opened by two processes at once, so the command never opens the DB file directly.
- A resend keeps the acceptance ID, `Message-ID` and ciphertext unchanged. The retry deadline is reset to 1 hour from the resend operation, and the retry intervals start over.
- If it fails again, the item returns to the failed queue, and its 24-hour retention is counted again from that moment.
- De-duplication records are kept for 24 hours after processing finally ends (successful delivery, deletion or automatic deletion).

### Emergency revocation and quarantine

- Each queue item stores the fingerprint of the primary key and the ID of the encryption subkey used to encrypt it.
- Procedure: set the new public key and `PGP_FINGERPRINT`, put the old key's fingerprint in `PGP_QUARANTINE_FINGERPRINTS`, and recreate the container.
- At startup, before delivery begins, pending and failed items encrypted to the specified keys are moved to the quarantine queue in one transaction.
- The quarantine queue is never delivered or resent. Items can only be listed and deleted; they are deleted automatically after 24 hours. They count toward the storage limit.
- The de-duplication records of quarantined items are deleted at the same time, so callers can resend with the same `Idempotency-Key`. Grafana body suppression records are deleted as well.
- If `PGP_FINGERPRINT` is included in `PGP_QUARANTINE_FINGERPRINTS`, it is a configuration error and startup fails.

### Measuring storage

- The 256 MiB limit is judged by the total logical bytes of the stored values (ciphertext, metadata and de-duplication records).
- The total is kept as a counter in the DB and updated in the same transaction as each write.
- A bbolt file does not shrink when data is deleted, so keep at least 512 MiB free on the queue volume.

### MIME structure and subject protection

- The outer part is PGP/MIME (RFC 3156) `multipart/encrypted; protocol="application/pgp-encrypted"`.
- The outer subject defaults to `[pgp-mailer] encrypted notification`. Set `public_subject` in an `INPUTS_FILE` route to override it for new messages on that route.
- The protected subject defaults to `[level] title`. Each input can customize it with `protected_subject_template` using literal text and the placeholders `{{.Title}}`, `{{.Level}}`, `{{.Level | upper}}`, and `{{.Level | lower}}`. Unsupported expressions prevent startup. If the expanded subject exceeds 256 KiB, delivery uses the default protected subject.
- The encrypted part contains `multipart/mixed; protected-headers="v1"` with the headers `Subject`, `From`, `To`, `Date` and `Message-ID` and a single `text/plain; charset=utf-8` body.
- Messages are not signed (the server holds no secret key). The receiving side cannot verify the sender's authenticity through PGP.
- Compatibility is checked against Thunderbird (latest stable desktop release). The receiving side confirms the following:
  - The message decrypts
  - The protected subject is displayed
  - Japanese subjects and bodies are not garbled

### Metrics

`GET /metrics` exposes metrics in Prometheus format. It requires no authentication and is not published to the host. Labels never contain `title`, `message` or addresses.

| Metric | Contents |
| --- | --- |
| `pgp_mailer_accepted_total{source}` | Accepted requests (`source` is the caller name or `grafana`) |
| `pgp_mailer_rejected_total{source,code}` | Rejected requests (by HTTP status) |
| `pgp_mailer_delivered_total` | Successful hand-overs to SMTP |
| `pgp_mailer_failed_total{reason}` | Moves to the failed queue (`expired` / `permanent`) |
| `pgp_mailer_queue_messages{state}` | Item counts (`pending` / `failed` / `quarantined`) |
| `pgp_mailer_storage_bytes` / `pgp_mailer_storage_limit_bytes` | Usage and limit |
| `pgp_mailer_key_expiry_timestamp_seconds` | Key expiry (not emitted if the key never expires) |
| `pgp_mailer_key_valid` | 1 if the key is valid |

Set the following alerts in Grafana and notify through the existing Gotify path.

- `increase(pgp_mailer_failed_total[5m]) > 0`
- `pgp_mailer_key_valid == 0`, or less than 14 days until the key expires
- `pgp_mailer_storage_bytes / pgp_mailer_storage_limit_bytes > 0.8`
- `up{job="pgp-mailer"} == 0`
