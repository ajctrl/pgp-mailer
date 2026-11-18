# Configurable HTTP inputs

All intake URLs use the same handler. Set `INPUTS_FILE` to a JSON array of input
definitions; no code change or rebuild is required. Restart after edits.
Malformed configuration prevents startup.

When unset, the embedded [default configuration](../internal/config/inputs.default.json)
defines `/v1/messages` and `/webhooks/grafana`. Copy this file to retain or
customize these routes. An explicit file **replaces** defaults; `[]` disables
intake. Health, metrics and admin endpoints remain available.

```sh
cp internal/config/inputs.default.json inputs.json
INPUTS_FILE=/absolute/path/inputs.json ./pgp-mailer
```

The usual SMTP, PGP, queue and admin settings are still required. `API_TOKENS`
(or `API_TOKENS_FILE`) is required only if a bearer input exists. HMAC secrets
are required only when referenced by an input.

## Custom JSON and raw text

```json
[
  {
    "path": "/hooks/example",
    "source": "example",
    "auth": "bearer",
    "caller": "app-a",
    "format": "json",
    "public_subject": "[Monitoring] Notification",
    "title": "{{ .event.name }}",
    "body": "{{ .event.description }}\n\n{{ toPrettyJSON . }}",
    "level": "info",
    "dedup": "body"
  },
  {
    "path": "/hooks/raw",
    "source": "raw",
    "auth": "bearer",
    "format": "text",
    "dedup": "none"
  }
]
```

`caller` names an entry in `API_TOKENS`. Omit it to accept any configured API
caller. Bearer messages retain the authenticated caller as their queue/metrics
source. Raw requests do not need an Idempotency-Key:

```sh
curl http://pgp-mailer:8080/hooks/raw \
  -H "Authorization: Bearer $TOKEN" \
  --data-binary 'Any text to encrypt and send'
```

## Fields

| Field | Meaning |
| --- | --- |
| `path` | Unique literal POST path; no wildcards, trailing slash, or reserved health/metrics/admin paths |
| `source` | Name matching `[a-z0-9-]{1,32}`; source for HMAC inputs and default title for all inputs |
| `auth` | `bearer` or `hmac-sha256` |
| `caller` | Optional restriction to one named bearer caller |
| `secret_env` | HMAC secret environment variable name; its `_FILE` variant also works |
| `signature_header`, `timestamp_header` | Required distinct header names for HMAC |
| `format` | `json` accepts any JSON value including arrays; `text` accepts UTF-8 text |
| `validation` | Optional `message` validates original JSON against the existing receiver/title/message/level API contract; cannot combine with templates or require_any |
| `require_any` | Optional top-level JSON field names; at least one must be non-null and nonblank |
| `public_subject` | Optional literal subject visible to mail servers before decryption. Up to 200 characters on one line, without control characters. Omitted or blank uses `[pgp-mailer] encrypted notification`. Works with all validation modes. |
| `title`, `body`, `level` | Go text templates; defaults are source, original request body, and info |
| `dedup_namespace` | Optional stable scope instead of path; empty retains historical caller-only keys. Shared scopes intentionally share suppression |
| `dedup` | Required: `idempotency-key`, `body`, or `none` |

`validation: "message"` retains strict API validation, including rejection of
unknown fields and requiring `receiver: "ops"`. Other inputs always deliver to
configured `RECEIVER_OPS`. Payloads cannot select arbitrary email addresses.

Template data is the decoded JSON value, or text string. JSON numbers preserve
precision. Standard Go template operations (if, range, index) work, plus:

- `toPrettyJSON`: indented JSON.
- `text`: string unchanged, null/missing as empty, other values as JSON.
- `trim`: remove surrounding whitespace.
- `clean`: replace control characters with spaces.
- `cut N`: limit a string to N characters.

Templates cannot execute shell commands or read files. Missing direct map fields
produce zero values. Invalid nested access or evaluation failures return 422;
template errors and payloads are not logged or returned. Output is bounded to
256 KiB per template. JSON pretty-printing checks an upper bound on expanded
size before allocating indentation and rejects oversized expansions. Titles are sanitized and limited to 200 characters; blank
titles use source. Bodies over 64 KiB are truncated with a notice. Blank bodies
and invalid levels are rejected.

## Authentication and deduplication

Bearer inputs use the existing named token list. Admin and API tokens must differ.

HMAC verifies a hexadecimal `HMAC-SHA256(secret, timestamp + ":" + raw body)`
before decoding. Timestamps are Unix seconds within five minutes. This matches
the default Grafana scheme; it is not universal across webhook providers.
Replay marks persist for the full signature validity period, regardless of
dedup mode.

- `idempotency-key` requires the header. Identical normalized content returns the
  existing ID; different content under the same key returns 409. Existing queue
  retention rules apply.
- `body` suppresses identical raw request bytes for five minutes. JSON whitespace
  changes count as different bodies.
- `none` creates one message per authenticated request, except signed replays.

Suppression is isolated by route and authenticated source. The two original
paths retain historical keys so upgrades preserve pending suppression records.
Keep paths stable when retrying requests.

Each request creates one email. Success is `202 {"id":"..."}` after encryption
and persistence, or when returning an existing ID. Requests are limited to
256 KiB.

## Alert arrays

An array can be accepted without a product-specific adapter:

```json
[
  {
    "path": "/api/v2/alerts",
    "source": "alerts",
    "auth": "bearer",
    "caller": "monitoring",
    "format": "json",
    "title": "Monitoring alerts",
    "body": "{{ range . }}{{ text .labels.alertname }}\n{{ toPrettyJSON . }}\n\n{{ end }}",
    "dedup": "body"
  }
]
```

Configure a monitoring entry in API_TOKENS and make the sender supply its bearer
token. This sends a snapshot email per request; it does not implement
Alertmanager grouping, silencing, active/resolved state tracking or repeat
intervals. Changing timestamps also change body hashes. Use an upstream alert
manager when those notification policies are needed.
