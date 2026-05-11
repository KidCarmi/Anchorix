# Development Guide

This guide describes how to bring up Anchorix v0.1 locally.

> Read [`CLAUDE.md`](./CLAUDE.md) before contributing. It's binding.

## Prerequisites

- **Docker** 24+ and **Docker Compose** v2
- **Go** 1.25+ (matches `backend/go.mod`; agent module uses the same toolchain)
- **Node.js** 20+ and **npm** 10+ (for frontend development outside Docker)
- **PostgreSQL** client tools (`psql`) optional but useful
- A POSIX shell (Linux or macOS). Windows contributors should use WSL2.

The Windows agent is built with Go. Cross-compilation from Linux is supported.

## Getting Started

```bash
git clone https://github.com/kidcarmi/anchorix.git
cd anchorix

# 1. Generates .env with a real ANCHORIX_SESSION_KEY.
#    Refuses to overwrite an existing .env (use --force if you really mean it).
./scripts/dev-env.sh

# 2. Start the database first.
docker compose up -d --build postgres

# 3. Apply embedded migrations. `anchorix serve` refuses to start
#    against a DB whose schema_migrations version does not match
#    what the binary expects (CLAUDE.md §16, fail-closed schema).
docker compose run --rm api migrate up

# 4. Create the first operator. Anchorix ships **no default admin**
#    and the CLI requires `--password`; it never prints the password
#    back. Pass it via a shell variable so it stays out of history.
read -srp 'Password: ' PW && echo
docker compose run --rm -T api admin create \
  --email alice@example.com --display-name "Alice" --password "$PW"
unset PW

# 5. Bring up the full stack (api + frontend).
docker compose up --build
```

> The control plane refuses to start with the placeholder
> `ANCHORIX_SESSION_KEY` from `.env.example`, so you must run the
> bootstrap script (or generate a key by hand) before `docker compose up`.
> By hand: `openssl rand -base64 32` and paste into `.env`.

See [`docs/BOOTSTRAP.md`](./docs/BOOTSTRAP.md) for the full first-operator
flow, including the bootstrap-token (Option B) alternative for unattended
deployments.

Services exposed by Compose:

| Service        | URL                             | Notes                    |
| -------------- | ------------------------------- | ------------------------ |
| Frontend (UI)  | <http://localhost:5173>         | React dev server         |
| Backend (API)  | <http://localhost:8080/api/v1>  | Go control plane         |
| Liveness       | <http://localhost:8080/healthz> | Process is up            |
| Readiness      | <http://localhost:8080/readyz>  | DB ping + registered probes |
| PostgreSQL     | `localhost:5432`                | User/db from `.env`      |

`/readyz` reports `{"status":"ready","checks":{"postgres":"ok"}}` once
the postgres probe registered in `cmd/anchorix/serve.go` succeeds; it
flips to 503 when the database is unreachable (CLAUDE.md §18).

## Running Components Individually

### Backend

```bash
cd backend
go mod download
go run ./cmd/anchorix
```

Configuration is read from environment variables (see `.env.example`).
The backend will refuse to start if required secrets are missing.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

The dev server proxies `/api` to `http://localhost:8080`.

### Windows Agent

```bash
cd agent/windows
GOOS=windows GOARCH=amd64 go build -o ../../dist/anchorix-agent.exe ./cmd/anchorix-agent
```

Run the resulting binary on a Windows host. For development you can also run
it on Linux with a stub discovery provider (`ANCHORIX_AGENT_DISCOVERY=stub`).

## Make Targets

```bash
make help          # list targets
make dev           # docker compose up with rebuild
make backend-test  # go test ./...
make backend-lint  # go vet + golangci-lint
make frontend-test # npm test
make frontend-lint # npm run lint
make migrate       # apply pending DB migrations against $DATABASE_URL
make clean         # remove build artifacts
```

## Running Tests

```bash
# Backend unit tests (fast, offline)
cd backend && go test ./...

# Frontend
cd frontend && npm test

# Backend integration tests. Build-tagged `//go:build integration`, so the
# default `go test ./...` skips them. Requires a running Postgres reachable
# via DATABASE_URL. The `migrate` subcommand goes through `config.Load()`,
# so ANCHORIX_SESSION_KEY must also be set — `.env` produced by
# `./scripts/dev-env.sh` already contains both values.
cd backend
set -a; . ../.env; set +a   # export DATABASE_URL + ANCHORIX_SESSION_KEY from .env
# Or set them explicitly if you don't have a .env yet:
#   export DATABASE_URL='postgres://anchorix:change-me-locally@localhost:5432/anchorix?sslmode=disable'
#   export ANCHORIX_SESSION_KEY="$(openssl rand -base64 32)"
go run ./cmd/anchorix migrate up           # ensure schema is current
go test -tags integration -count=1 ./test/integration/...
```

The full tier model — unit / integration / frontend / smoke /
Windows — is documented in
[`docs/engineering/TESTING_STRATEGY.md`](./docs/engineering/TESTING_STRATEGY.md).
Adding tests for a new behavior must reference that document.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `anchorix serve` exits with `schema check: ...` | DB schema version doesn't match the binary's expectation (CLAUDE.md §16, fail-closed). | Run `anchorix migrate up`. |
| `/readyz` returns 503 with `postgres:"error..."` | DB is unreachable or restarting. | Check `docker compose ps postgres` and the container logs. |
| `admin create: --password is required` | Auto-generate path was removed in PR-002. | Supply `--password` via your shell. The CLI never prints it back. |
| `anchorix serve` fails on `ANCHORIX_SESSION_KEY` | Placeholder value in `.env`. | Re-run `./scripts/dev-env.sh` or paste `openssl rand -base64 32` into `.env`. |
| Integration tests pass but unit `go test ./...` shows no integration runs | Integration tests live under build tag `integration`. | Add `-tags integration` and point `DATABASE_URL` at a live Postgres. |

## Database Migrations

Migrations live in `backend/migrations/` as numbered SQL files
(`0001_init.sql`, `0002_*.sql`, …). They are append-only.

Apply them with:

```bash
make migrate
# or
go run ./cmd/anchorix migrate up
```

Never edit a previously merged migration. Add a new one instead.

## Linting & Formatting

- Go: `gofmt`, `go vet`, `golangci-lint run`
- TypeScript: `npm run lint`, `npm run typecheck`
- SQL: keep statements explicit, no implicit casts

CI runs the same commands. Don't merge with red CI.

## Coding Conventions

See [`CLAUDE.md` §8](./CLAUDE.md). Highlights:

- small focused packages, no god objects
- interface-driven boundaries
- structured errors with `%w`
- centralized config via `internal/config`
- structured logging via `internal/logger`
- never log secrets

## Branching

- The default branch is **`main`** and is protected.
- Feature branches: `<author>/<short-topic>` or `claude/<short-topic>-<suffix>`.
- All changes — including Claude-authored ones — land on `main` via
  pull request only. Direct pushes to `main` are forbidden.
- Full policy: [`docs/BRANCHING.md`](./docs/BRANCHING.md).
- Every PR must conform to [`CLAUDE.md`](./CLAUDE.md) §19
  (Engineering Discipline).

## Reporting Security Issues

Do not file security issues in public. See
[`docs/security/REPORTING.md`](./docs/security/REPORTING.md) for the process.
