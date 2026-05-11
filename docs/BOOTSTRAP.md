# Bootstrapping a New Anchorix Deployment

Anchorix ships **no default operator account** and **no default password**.
That is intentional (CLAUDE.md §6.5, §6.12): the only way an admin exists
is because someone deliberately created one.

## Bootstrap Flow

The first time you bring up the control plane against an empty database,
follow this sequence.

### 1. Configure environment

```bash
./scripts/dev-env.sh        # generates .env with a real ANCHORIX_SESSION_KEY
docker compose up -d postgres
```

### 2. Apply migrations

```bash
docker compose run --rm api /anchorix migrate up
```

This creates schema and an empty `users` table. There is no seeded admin.

### 3. Create the first operator (Phase 1+)

Two mechanisms are supported. Pick **one** at deployment time:

#### Option A — CLI (recommended)

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
  api /anchorix admin create \
    --email alice@example.com \
    --display-name "Alice" \
    --password "$PW"
unset PW
```

Or, if your shell hides command lines from history and you trust the
generation source:

```bash
docker compose run --rm api /anchorix admin create \
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

#### Option B — First-run bootstrap token

For environments where running an interactive command on the control
plane host is awkward (e.g. fully unattended deployment), Anchorix
supports a one-shot bootstrap token:

1. The operator sets `ANCHORIX_BOOTSTRAP_TOKEN` in the control plane's
   environment **before** the very first start.
2. On boot, if the `users` table is empty, the API surfaces a single
   endpoint `POST /api/v1/auth/bootstrap` that accepts the token plus
   the desired admin's `email`, `display_name`, and `password`.
3. The token is single-use. After consumption — or after any user
   exists — the endpoint disappears and the env var is ignored.
4. The control plane refuses to start if the env var is set in
   production with `ANCHORIX_TLS_TERMINATION=disabled_dev`.

Pick exactly one mechanism per deployment. Do not enable both for the
same database — the CLI path is safer because it never exposes a
bootstrap endpoint over HTTP.

### 4. Log in and rotate

Sign in with the credentials from step 3. Immediately:

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
