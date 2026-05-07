# Development Guide

This guide describes how to bring up Anchorix v0.1 locally.

> Read [`CLAUDE.md`](./CLAUDE.md) before contributing. It's binding.

## Prerequisites

- **Docker** 24+ and **Docker Compose** v2
- **Go** 1.22+ (for backend / agent development outside Docker)
- **Node.js** 20+ and **npm** 10+ (for frontend development outside Docker)
- **PostgreSQL** client tools (`psql`) optional but useful
- A POSIX shell (Linux or macOS). Windows contributors should use WSL2.

The Windows agent is built with Go. Cross-compilation from Linux is supported.

## Getting Started

```bash
git clone https://github.com/kidcarmi/anchorix.git
cd anchorix
cp .env.example .env
docker compose up --build
```

Services exposed by Compose:

| Service        | URL                             | Notes                    |
| -------------- | ------------------------------- | ------------------------ |
| Frontend (UI)  | <http://localhost:5173>         | React dev server         |
| Backend (API)  | <http://localhost:8080/api/v1>  | Go control plane         |
| Health check   | <http://localhost:8080/healthz> | Liveness                 |
| PostgreSQL     | `localhost:5432`                | User/db from `.env`      |

The first run initializes the database via the bundled migration runner.

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
# Backend
cd backend && go test ./...

# Frontend
cd frontend && npm test

# Integration (requires running Postgres)
cd backend && go test ./test/integration/...
```

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

- Feature branches: `claude/<short-topic>` or `<author>/<short-topic>`
- The current foundation branch is **`claude/anchorix-foundation-hN43r`**
- All changes go through pull request review against `main`

## Reporting Security Issues

Do not file security issues in public. See
[`docs/security/REPORTING.md`](./docs/security/REPORTING.md) for the process.
