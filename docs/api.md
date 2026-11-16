# API

For a request example and the Grafana settings, see the [README](../README.md).

Intake paths are configurable; examples assume default inputs. See
[inputs.md](inputs.md) for custom paths, templates and authentication.

## Error responses

A failed request is answered with `{"error":"<type>","message":"<description>"}`.

| Status | `error` | When |
| --- | --- | --- |
| 400 | `invalid_request` | Invalid UTF-8, not readable as JSON, extra data after the JSON |
| 400 | `invalid_idempotency_key` | `Idempotency-Key` missing, repeated or malformed |
| 401 | `unauthorized` | Bearer token missing or wrong |
| 409 | `idempotency_conflict` | Same key with different content |
| 409 | `idempotency_in_progress` | An earlier request with the same key is still being processed. Retry later with the same key |
| 413 | `payload_too_large` | Body larger than 256 KiB |
| 422 | `validation_failed` | Missing field, invalid value or unknown field |
| 500 | `encryption_failed` / `internal_error` | Encryption or queue write failed |
| 503 | `queue_full` | Storage limit reached |
| 503 | `key_expired` | Delivery-only mode |
| 503 | `shutting_down` | Shutting down |

When the Grafana webhook gets `401`, the reason (missing, mismatch, clock skew and so on) appears only in the log field `reason`.

## Admin API

Use it through `docker exec`. The command reads `LISTEN_ADDR` and `ADMIN_TOKEN` (or `ADMIN_TOKEN_FILE`) from the environment and calls the admin API over loopback.

```sh
docker exec pgp-mailer /pgp-mailer admin failed list
docker exec pgp-mailer /pgp-mailer admin failed retry <acceptance-id>
docker exec pgp-mailer /pgp-mailer admin failed delete <acceptance-id>
docker exec pgp-mailer /pgp-mailer admin quarantine list
docker exec pgp-mailer /pgp-mailer admin quarantine delete <acceptance-id>
```

In the failed-queue listing, `reason` reads like `permanent (smtp 550)` or `expired (timeout)`: the kind of failure plus the last SMTP reply code or error class. The SMTP server's reply text is not stored, because it may contain addresses.
