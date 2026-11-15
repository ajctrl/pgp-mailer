# pgp-mailer

A notification service that encrypts messages received over HTTP to an OpenPGP public key, stores them in a persistent queue and then sends them over SMTP.

```text
Grafana ── HTTP + HMAC ───→ pgp-mailer ── SMTP/TLS ──→ PGP mail
Other apps ─ HTTP + Bearer ─┘
```

- Nothing is ever stored or sent in plaintext. A request whose encryption or persistence fails is answered with an error.
- The recipient's secret key is not needed. Supplying secret key material makes startup fail.
- The only dependencies are bbolt and ProtonMail/go-crypto; the result is a static binary without cgo.

## Documentation

| Document | Contents |
| --- | --- |
| [docs/SPEC.md](docs/SPEC.md) | Specification |
| [docs/configuration.md](docs/configuration.md) | Notes on settings, preparing the key and fingerprint |
| [docs/api.md](docs/api.md) | Error responses, admin API |
| [docs/operations.md](docs/operations.md) | Key replacement, expiry, emergency revocation, startup failures, logs |
| [docs/implementation-notes.md](docs/implementation-notes.md) | Decisions on points the specification leaves open |

## Build and test

Requires Go 1.24 or later.

```sh
go build -o pgp-mailer ./cmd/pgp-mailer
go test ./...          # includes integration tests (a few to a dozen seconds)
go test -short ./...   # skips integration tests
docker build -t pgp-mailer:latest .
```

The tests in `cmd/pgp-mailer` start the real binary and have it deliver to a test SMTP server with TLS. The GnuPG decryption test in `internal/mailmsg` is skipped when `gpg` is not installed.

## Running

Pull the published Linux amd64 image:

```sh
docker pull ghcr.io/ajctrl/pgp-mailer:latest
```

The [Docker workflow](.github/workflows/docker.yml) tests the service and publishes
the image on every push to `main`. It can also be run manually from the Actions
tab on `main`. Images are tagged `latest` and `sha-<full commit SHA>`.
Authentication uses the workflow's `GITHUB_TOKEN`; no extra secret is needed.
After the first publication, the package owner must set the package visibility
to **Public** under GitHub **Packages → pgp-mailer → Package settings** to allow
pulling without authentication. Repository visibility does not set package visibility.

An example Portainer stack is in [deploy/compose.yaml](deploy/compose.yaml).

- Do not publish ports (no `ports:`); join the same dedicated network as the callers.
- Run with `read_only: true`. The only writable location is the `QUEUE_DIR` volume (UID/GID `65532`, at least 512 MiB free).
- Set `stop_grace_period` longer than 30 seconds (40 seconds in the example).
- Docker secrets files must be readable by UID `65532` inside the container.

| Command | Purpose |
| --- | --- |
| `pgp-mailer` (or `pgp-mailer serve`) | Run the service |
| `pgp-mailer healthcheck` | Call `/healthz`; exit code 0 on `200`, 1 otherwise |
| `pgp-mailer admin ...` | Call the admin API ([docs/api.md](docs/api.md)) |

## Usage

```sh
curl -sS -X POST http://pgp-mailer:8080/v1/messages \
  -H "Authorization: Bearer $TOKEN" \
  -H "Idempotency-Key: $(uuidgen)" \
  -d '{"receiver":"ops","title":"Error rate rising","message":"15 errors in the last 5 minutes.","level":"error"}'
# => 202 {"id":"8875a9dc48cd886f09121af41aca0ad8"}
```

For Grafana, configure the webhook contact point as follows.

| Setting | Value |
| --- | --- |
| URL | `http://pgp-mailer:8080/webhooks/grafana` |
| HMAC Signature secret | Same value as `GRAFANA_HMAC_SECRET` |
| Header | `X-Grafana-Alerting-Signature` (keep the default) |
| Timestamp Header | `X-Grafana-Alerting-Timestamp` (required; without it every request gets `401`) |
| Notification policy repeat interval | 1 hour |
