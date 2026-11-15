# Configuration

The full list of environment variables and their meaning is in the Configuration section of [SPEC.md](SPEC.md). This page lists only what the implementation adds or makes more specific.

| Setting | How the implementation treats it |
| --- | --- |
| `LISTEN_ADDR` | Not in the specification. Listen address, default `:8080` |
| `PGP_PUBLIC_KEY_BASE64` | Base64 of either a binary or an ASCII-armored key. Exactly one key |
| `PGP_FINGERPRINT` | 40 (v4) or 64 (v6) hex digits. Spaces and letter case are ignored. A key ID (16 digits) is not accepted |
| `SMTP_HOST` | Host name or IP address only. A value with a port such as `host:465` fails at startup (the port goes in `SMTP_PORT`) |
| `SMTP_USERNAME` / `SMTP_PASSWORD` | Required. Relays without authentication are not supported. Authentication uses PLAIN, or LOGIN if PLAIN is not offered |
| `MAIL_FROM` / `RECEIVER_OPS` | One address each. The `Name <addr>` form is allowed |
| `ADMIN_TOKEN` | At least 32 characters, and different from every token in `API_TOKENS` |
| `GRAFANA_HMAC_SECRET` | At least 32 characters |
| Secret values | A value from an environment variable is used as is; leading and trailing spaces are part of it. From a `*_FILE` file, only the trailing line break is removed |

The public key and fingerprint can be prepared like this:

```sh
gpg --export <fingerprint> | base64 -w0     # PGP_PUBLIC_KEY_BASE64
gpg --fingerprint <fingerprint>             # PGP_FINGERPRINT
```

Configuration error messages name the variable but never show its value.
