# Operations

## Replacing the key

1. Set the Base64 and fingerprint of the new public key and recreate the container.
2. Once the startup checks and the encryption self-test pass, new notifications use the new key.
3. Ciphertext queued before the change is sent as it is, encrypted to the old key. Keep the old secret key on the receiving side.

## Expiry

If expiry is the key's only problem, the service runs in "delivery-only mode": existing ciphertext keeps being delivered, new notifications get `503` (`key_expired`), `/healthz` returns `503` and `pgp_mailer_key_valid` is `0`. A key that expires while the service is running leads to the same state, with one error in the log. To recover, set a public key with an extended expiry, or a new key, and recreate the container.

## Emergency revocation

1. Set the new key in `PGP_PUBLIC_KEY_BASE64` and `PGP_FINGERPRINT`.
2. Set the old key's fingerprint in `PGP_QUARANTINE_FINGERPRINTS` and recreate the container.
3. Before any delivery starts, pending and failed items encrypted to the old key move to the quarantine queue.
4. Callers can resend the notifications they need with the same `Idempotency-Key`.

## When startup fails

In these cases the process exits with code 1 and starts neither intake nor delivery of the existing queue. The log fields `stage` and `error` show the cause.

- Missing or invalid configuration
- Key cannot be parsed, fingerprint mismatch, key revoked, no encryption subkey, or secret key material supplied
- Encryption self-test failed
- Queue directory not writable

## Logs

JSON, one line per entry, on standard output. `severity` is the importance of the log entry itself; `level` is the level of the notification. Entries record the acceptance ID, caller, `receiver`, `level`, result, SMTP reply code and attempt count. Titles, bodies and secrets are never logged.
