# Private pilot setup

This milestone secures access to the existing application. It does not add real
log ingestion, verify a remote deployment, or make a live model request. Start
with mock AI while collecting the prerequisites for the SSH-log pilot.

## Create local credentials

From the repository root, the following creates a **new** `.env` with independent
random database, operator, and viewer credentials. It refuses to overwrite an
existing file and does not print credentials:

```bash
python3 - <<'PY'
import os
import secrets
from pathlib import Path

content = Path('.env.example').read_text()
for name in ('POSTGRES_PASSWORD', 'AUTH_OPERATOR_TOKEN', 'AUTH_VIEWER_TOKEN'):
    content = content.replace(name + '=\n', name + '=' + secrets.token_hex(32) + '\n')
fd = os.open('.env', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w') as output:
    output.write(content)
PY
```

If `.env` already exists, edit it locally, set its permissions with `chmod 600
.env`, and generate each missing credential independently with `openssl rand
-hex 32`. Do not paste credentials into chat, commit them, use them in URLs, or
put them in `VITE_*` variables. Keep the generated database password hexadecimal
so it can be embedded safely in the Compose database URL. The server rejects
missing or short database passwords and missing, malformed, or identical role
tokens. Leave `AUTH_VIEWER_TOKEN` empty if read-only access is not needed.

The API tokens are SecurityLens credentials; they are separate from any OpenAI
or Anthropic key. Give an operator token only to analysts allowed to change
alerts and invoke AI. A viewer token grants access to all collected evidence,
without write or AI permissions. These shared role credentials do not identify
individual people or isolate tenants. Use a private identity-aware gateway or
add individual accounts before requiring per-person revocation or audit trails.

## Start a separate pilot stack

Use a separate project name and volume from any previous demo:

```bash
docker compose -p securitylens-pilot --env-file .env config -q
docker compose -p securitylens-pilot --env-file .env up --build -d
docker compose -p securitylens-pilot ps
```

Only the dashboard is published, at `127.0.0.1:3000`. Postgres and Redis share an
internal Docker network with the backend. The dashboard and backend share a
second internal network. Only the backend joins an outbound network for provider
access; it has no published API port. A localhost bind is a host access boundary,
not isolation from other users or containers with administrative host access.
Protect access to the host and Docker daemon.

Open `http://127.0.0.1:3000` and enter the operator or viewer token from your local
`.env`. The dashboard initially has no events. `SEED_ON_START=false` prevents new
synthetic inserts; it does not delete data in an existing volume. Keep the pilot
empty until a real collector is added. The role appears beside the sign-out
button; viewers cannot use alert-write or model actions.

For a remote staging host, keep the published port on localhost and use an SSH
tunnel from the analyst workstation:

```bash
ssh -N -L 127.0.0.1:3000:127.0.0.1:3000 analyst@your-staging-host
```

Then open the same localhost URL on the workstation. `.env.example` sets
`AUTH_COOKIE_SECURE=false` for this HTTP-on-loopback workflow, with SSH encrypting
the remote hop. For access over a private network, terminate HTTPS at a private
gateway, set `AUTH_COOKIE_SECURE=true`, and recreate the backend. Do not expose
this HTTP listener on a public interface. The repository does not provision the
gateway, VPN, firewall, or TLS certificates.

## Authentication and access checks

All `/api` routes, including `/api/health` and `/api/stream`, require a valid
Bearer token or session. API health reports configuration and dependencies; it
does not prove provider connectivity. `/readyz` returns minimal readiness for the
container health check and is not proxied by the dashboard.

| Access | Read logs, evidence, metrics, stream | Change alert status | AI triage, investigation, rule drafting |
| --- | --- | --- | --- |
| Unauthenticated | 401 | 401 | 401 |
| Viewer | Allowed | 403 | 403 |
| Operator | Allowed | Allowed | Allowed |

Browser login uses `POST /api/session` with JSON `{ "token": "..." }` and the
header `X-SecurityLens-Request: 1`. The response sets an opaque HttpOnly,
SameSite=Strict cookie with an eight-hour absolute lifetime. The token is not
persisted in browser storage. Cookie-authenticated writes require that same
custom header; cross-site requests are rejected and cross-origin access is not
enabled. `DELETE /api/session` revokes the session and clears the cookie. Logout
and expiry terminate session-backed streams. Backend restarts invalidate all
browser sessions. Sessions are kept in memory for this single-backend pilot.
Sign-in is limited to ten attempts per minute per direct network peer and 120
globally. Analysts behind the same reverse proxy share its peer limit; forwarded
client IP headers are not trusted for this check. A 429 response means to wait
one minute before trying again.

CLI callers can send `Authorization: Bearer <role token>` in a request header.
Do not place it in query strings or share command output containing it. Avoid
using literal credentials in shell history. The dashboard handles sign-in and
sign-out without requiring a CLI secret exchange.

Verify denial without credentials (no real log, model call, or database change
is needed):

```bash
curl -i http://127.0.0.1:3000/api/logs
curl -i -X POST http://127.0.0.1:3000/api/alerts/not-an-alert/status
curl -i -X POST http://127.0.0.1:3000/api/alerts/not-an-alert/triage
curl -i -X POST http://127.0.0.1:3000/api/rules/generate
```

Each must return **401**, without reaching data or model handlers. In the
browser, confirm a viewer can read pages but has no action controls, sign out,
and confirm the dashboard returns to sign-in. The automated API suite also
checks viewer writes receive 403 and that every protected route rejects absent
or invalid credentials, using no live provider or production database:

```bash
go test ./internal/api ./internal/config
```

## Existing volumes and credential rotation

Postgres uses `POSTGRES_PASSWORD` only when initializing an empty data directory.
Updating `.env` alone cannot replace `lens:lens` on an existing database. A new
`securitylens-pilot` project creates a separate volume if that project name has
not been used before. Do not delete an old volume to resolve a password mismatch.

If reusing a database is deliberate, back it up first. Using the existing
administrator connection, open `psql` and run `\password lens`; enter the new
random password interactively, then update the local `.env` to match and
recreate the backend. Keep that database private throughout the change. Preserve
any data that must be retained; demo logs in a reused volume remain synthetic.

To rotate an API role token, generate a replacement in `.env` and recreate the
backend with the same Compose project name. Existing Bearer credentials stop
working, and restarting the backend invalidates all browser sessions. Sign-out
revokes only that browser session; someone retaining the role token can sign in
again until the token is rotated.

## Native development

Provision Postgres and Redis on localhost or a private network. Export a
`DATABASE_URL` containing the real database user and generated password (at least
32 characters), and `AUTH_OPERATOR_TOKEN` containing 32 random bytes encoded as
64 hexadecimal characters. There is no built-in database password. If the
password has URL-reserved characters, URL-encode it; generated hex avoids this.

Export `AUTH_VIEWER_TOKEN` if needed, `AUTH_COOKIE_SECURE=false` only for localhost
HTTP, and `LLM_MODE=mock`. Run `make run` and the Vite development server. Both
bind to `127.0.0.1` by default. The Go process does not read `.env` automatically.
Never run `make seed` or `make eval` against pilot data: these commands replace
data or detections and are for a separate synthetic database.

## Boundaries still pending

This setup does not address real ingestion, live detection latency, model-bound
log redaction, individual accounts, or notification delivery. Keep AI in mock
mode until the data-sharing policy and redaction work are ready for real logs.
No live deployment or model quality claim follows from passing authentication
tests.

Session design references: [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html).
Network configuration reference: [Docker Compose networking](https://docs.docker.com/compose/how-tos/networking/).
