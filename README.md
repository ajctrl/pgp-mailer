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
| [docs/inputs.md](docs/inputs.md) | Configurable HTTP routes, authentication and templates |
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

Dependabot checks Go modules (including indirect dependencies), GitHub Actions
and Docker base images weekly and opens update PRs. Minor and patch updates for
Go and Actions are grouped; major updates remain separate. PRs run the tests
and a Docker build. Verified Dependabot patch/minor/major updates are squash-merged
automatically only after CI succeeds for that exact PR head, then the image
publication workflow is dispatched. Unclassified updates remain manual.
CI runs the full test suite with the race detector and requires GnuPG so the
OpenPGP interoperability checks run. Regression tests also check encryption
failure handling and reading/updating a frozen queue database written by bbolt
v1.4.3. The merge workflow only checks out trusted automation from the base
commit. It uses GITHUB_TOKEN except for updating PR branches, which requires
the DEPENDABOT_UPDATE_TOKEN Actions secret described below. The repository's
native auto-merge setting is not needed. Main must require
the GitHub Actions `test` and `build` checks with strict (up-to-date branch)
protection. This blocks merges validated against an older main, including races
between concurrent update PRs. If main advances, the automation updates the PR
branch using the dedicated token, waits for normal pull_request test/build CI
on its new head, then retries the merge (up to three attempts). Test failures, conflicts, unexpected
head changes, or repeated main updates stop the process. Additional
branch protection requirements still apply. See [Dependabot configuration](.github/dependabot.yml)
and the [merge workflow](.github/workflows/dependabot-merge.yml).

To enable automatic branch refresh, register an **Actions repository secret**
named DEPENDABOT_UPDATE_TOKEN. Use a dedicated fine-grained personal access
token restricted to this repository with Contents and Pull requests read/write
permissions. Allow Workflows read/write as well for updates that change workflow
files. A GitHub App installation token with equivalent permissions can also be
supplied. Token-generated events use that token's actor, not Dependabot; the
merge workflow ignores those events without cancelling the original run.

The token is passed only to the branch-update API call in the trusted merge job;
PR test/build jobs never receive it. If it is missing, an outdated PR stops before
mutation and reports the required secret. Keep the token valid; expired tokens
stop branch refresh. Unchanged, current PRs can still merge with GITHUB_TOKEN.

GITHUB_TOKEN updates do not trigger pull_request CI, and workflow_dispatch CI
cannot satisfy required PR checks. These constraints are why the extra token is
required for branch refresh. See the [GitHub token documentation](https://docs.github.com/en/actions/concepts/security/github_token)
and [required-check event restrictions](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks#checks-from-some-workflow-jobs-are-not-evaluated).

The initial main protection configuration is tracked in
[main-protection.json](.github/main-protection.json). For a new repository, apply
it with an administrator's GitHub CLI credentials:

```sh
gh api --method PUT repos/OWNER/REPO/branches/main/protection \
  --input .github/main-protection.json
```

This command replaces branch protection settings. If protection already exists,
preserve its other requirements and add strict `test`/`build` checks instead.

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

All intake routes are configuration-defined. Set INPUTS_FILE to a JSON file to
replace, rename or add routes without rebuilding. When unset, the embedded
defaults provide the two routes below. See [configurable inputs](docs/inputs.md).

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
