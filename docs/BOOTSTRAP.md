# Bootstrapping a New Anchorix Deployment

Anchorix ships **no default operator account** and **no default password**.
That is intentional (CLAUDE.md §6.5, §6.12): the only way an admin exists
is because someone deliberately created one.

## Bootstrap Flow

The first time you bring up the control plane against an empty database,
follow this sequence.

### 1. Configure environment

```bash
./scripts/dev-env.sh                       # generates .env with a real ANCHORIX_SESSION_KEY
docker compose up -d --build postgres      # start the database first
```

`./scripts/dev-env.sh` populates `DATABASE_URL` and a fresh
`ANCHORIX_SESSION_KEY`; the control plane refuses to start on the
placeholder value from `.env.example` (CLAUDE.md §8.9: no silent
fallback for security-sensitive settings). To generate the key
manually instead, run `openssl rand -base64 32` and paste it into `.env`.

### 2. Apply migrations

```bash
docker compose run --rm api migrate up
```

The image's `ENTRYPOINT` is `/anchorix`, so the subcommand
(`migrate up`) is passed directly — do **not** prefix it with
`/anchorix` again. The migrate runner is idempotent (CLAUDE.md §16):
applied on a pristine DB it creates the schema; applied on an
up-to-date DB it is a no-op. A pristine schema includes an empty
`users` table — there is no seeded admin.

### 3. Create the first operator

Today, only **Option A — CLI bootstrap** is implemented and supported.

**Option B — first-run bootstrap token** is planned, not implemented,
and documented only as the future design contract.

#### Option A — CLI (recommended, implemented)

The CLI **requires** `--password` — there is no default and no
auto-generate path. Operators are expected to supply the password
through their shell so it never appears in command history or logs:

```bash
# Interactive prompt (preferred — password is never written down).
read -srp 'Password: ' PW && echo
docker compose run --rm -T \
  -e ANCHORIX_BCRYPT_COST \
  -e DATABASE_URL \
  -e ANCHORIX_SESSION_KEY \
  api admin create \
    --email alice@example.com \
    --display-name "Alice" \
    --password "$PW"
unset PW
```

Or, if your shell hides command lines from history and you trust the
generation source:

```bash
docker compose run --rm api admin create \
    --email alice@example.com \
    --display-name "Alice" \
    --password "$(openssl rand -base64 24)"
```

Behaviour:

- The created user gets the `admin` role.
- The organization row referenced by `--organization` (default
  `anchorix`) is upserted before the user insert, so a pristine
  database is enough.
- An audit event of type `auth.admin_created` is recorded.
- **The CLI never prints the password back.** Capture it yourself
  during the shell flow; if you forget it, rotate using
  `anchorix admin reset-password` (planned).

This is the path the v0.1 documentation, deploy templates, and operator
runbooks assume.

#### Option B — First-run bootstrap token (planned, not yet implemented)

For environments where running an interactive command on the control
plane host is awkward (e.g. fully unattended deployment), Anchorix
will support a one-shot bootstrap token. Option B is **not** wired up
in v0.1; only Option A (CLI) is available today. The contract below
is preserved here as the design that the bootstrap-token PR must
follow:

1. The operator sets `ANCHORIX_BOOTSTRAP_TOKEN` in the control plane's
   environment **before** the very first start.
2. On boot, if the `users` table is empty, the API surfaces a single
   endpoint `POST /api/v1/auth/bootstrap` that accepts the token plus
   the desired admin's `email`, `display_name`, and `password`.
3. The token is single-use. After consumption — or after any user
   exists — the endpoint disappears and the env var is ignored.
4. The control plane refuses to start if the env var is set in
   production with `ANCHORIX_TLS_TERMINATION=disabled_dev`.

Once Option B ships, deployments must pick exactly one mechanism per
database. Both must never be enabled together — the CLI path is safer
because it never exposes a bootstrap endpoint over HTTP. Until then,
Option A is the only supported path.

### 4. Start the control plane

```bash
docker compose up --build
```

`anchorix serve` calls `EnsureSchema` against the embedded migrations
and refuses to start when the DB is behind the binary; if you skipped
step 2, run it now.

### 5. Log in and rotate

Sign in via `POST /api/v1/auth/login` with the credentials from step 3:

```bash
curl -sS -i -X POST http://localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","password":"…"}'
```

A successful login returns 200, a `Set-Cookie: anchorix_session=...`
header, and the user profile body documented in
[`docs/api/REST_API.md`](./api/REST_API.md#post-authlogin).
Subsequent `GET /api/v1/auth/me` calls with the cookie return the same
profile; `POST /api/v1/auth/logout` revokes the session.

Immediately:

- rotate the password if you suspect it was captured by anything other than your shell;
- create additional operator accounts as needed;
- restrict the `admin` role to as few accounts as practical.

## What Anchorix Will Never Do

- **Never** ship a default admin account.
- **Never** accept a default password.
- **Never** silently re-enable a bootstrap mechanism after first use.
- **Never** log the bootstrap token, the supplied password, or the
  resulting password hash.

If you find any of these in the code or in a deployment, that is a
security bug — file it via the process in
[`docs/security/REPORTING.md`](./security/REPORTING.md).
