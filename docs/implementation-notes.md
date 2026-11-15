# Implementation notes

## Decisions not covered by the specification

How the implementation settles points that [SPEC.md](SPEC.md) leaves open.

| Topic | Implementation |
| --- | --- |
| How `level` appears inside the encrypted part | The protected subject reads `[error] original title`. One line with the acceptance ID, caller and `level` is appended to the body |
| Characters forbidden in `title` | Besides line breaks, every control character (tab included) and U+2028 / U+2029 are rejected |
| Unknown JSON fields | `422`, so that a field meant to set, say, a recipient is not silently ignored. Key names must match exactly, including case (`Title` is an unknown field) |
| Resent requests in delivery-only mode | `503` even for a key that was already accepted ("`503` after authentication" applied as written) |
| Leaving the expired state | Once expiry has been detected, delivery-only mode lasts until restart, even if the clock goes back |
| Detecting a request still in progress | Tracked in process memory. Grafana requests are processed one at a time |
| Grafana `status` other than `firing` / `resolved` | Not rejected; `level` becomes `unknown` |
| The same signed request sent again | Each accepted signature is remembered while it is valid (until signing time + 5 minutes), and a resend with the same signature is a duplicate that returns the original acceptance ID. This matters because, when Grafana's clock runs ahead, a signature stays valid longer than the 5-minute body suppression. Notifications signed anew are not affected |
| Empty Grafana `title` / `message` | Not rejected; a fixed placeholder is used. Only a body in which `status`, `title` and `message` are all empty is treated as not being a Grafana webhook and gets `400` |
| Grafana `status` / `title` / `message` that are not strings | Not rejected; the JSON text of the value is used as the string |
| Envelope sender and recipient | The values at acceptance time are stored with the queue item and reused on every resend |
| SMTP connection or authentication failure | Recorded in one write as a failed attempt for every item whose delivery was due at that moment, so only one connection is tried. Items whose deadline passes during the pause may move to the failed queue when it ends |
| Item cannot be removed from the queue after a successful send | It is not sent again; only the removal is retried. Across a restart it may be sent once more (the same as for a shutdown) |
| Stored mail cannot be read | No SMTP connection is made; the item is retried on the normal schedule. If the mail does not exist it is a permanent error and the item moves to the failed queue |
| Server does not advertise STARTTLS or AUTH | Treated as a temporary error and retried (never sent in plaintext) |
| Rejections of unauthenticated requests | Counted in `pgp_mailer_rejected_total` with `source` set to `_unauthenticated` |
| How storage is measured | The total bytes of keys and values in the queues, de-duplication records, signature records and indexes. All entries are recounted at startup to correct the counters |
