# Anchorix

**Machine Identity & Certificate Operations Platform.**

Anchorix is a control plane that gives organizations visibility into their
certificates and machine identities **without replacing their PKI**. It
discovers, inventories, and risk-scores certificates across an estate, and
integrates with existing trust infrastructure (Microsoft ADCS, HashiCorp
Vault PKI, Smallstep, EJBCA, manual CSR workflows).

> **Core philosophy: visibility before automation.**

This repository contains v0.1 — a foundation release focused on:

- a Windows discovery agent
- a Go control plane with PostgreSQL
- a React + Tailwind operator UI
- structured logging and audit events
- Docker Compose deployment

It is **not** a CA, **not** a key escrow, **not** a renewal automation engine,
and **not** a Kubernetes-native platform. See [`CLAUDE.md`](./CLAUDE.md) for
the full scope and engineering rules.

## Repository Layout

```
.
├── CLAUDE.md                # Engineering constitution (binding rules)
├── ARCHITECTURE.md          # System architecture
├── DEVELOPMENT.md           # Local development setup
├── ROADMAP.md               # v0.1 implementation roadmap
├── docker-compose.yml       # Local Docker Compose stack
├── Makefile                 # Common developer commands
├── backend/                 # Go control plane
│   ├── cmd/anchorix/        # Control plane binary entrypoint
│   ├── internal/            # Private packages (domain, providers, http)
│   ├── migrations/          # PostgreSQL schema migrations
│   └── Dockerfile
├── frontend/                # React + Tailwind operator UI
│   └── Dockerfile
├── agent/
│   └── windows/             # Windows discovery agent (Go)
├── deploy/
│   ├── compose/             # docker-compose overlays
│   └── docker/              # Dockerfiles & helper assets
└── docs/
    ├── api/                 # REST API design
    ├── architecture/        # data model, agent protocol, provider model
    └── security/            # threat model, trust model, controls
```

## Quick Start

See [`DEVELOPMENT.md`](./DEVELOPMENT.md) for full instructions and
[`docs/BOOTSTRAP.md`](./docs/BOOTSTRAP.md) for the first-operator flow.
Short version:

```bash
./scripts/dev-env.sh                    # generates .env with a real ANCHORIX_SESSION_KEY
docker compose up -d --build postgres   # start the database first
docker compose run --rm api migrate up  # apply embedded migrations
# Create the first operator (no default admin, --password is required;
# the CLI never prints the password back):
read -srp 'Password: ' PW && echo
docker compose run --rm -T api admin create \
  --email you@example.com --display-name "You" --password "$PW"
unset PW
docker compose up --build               # bring up api + frontend
```

The UI will be available at <http://localhost:5173> and the API at
<http://localhost:8080/api/v1>.

## Status

v0.1 is under active development. Refer to [`ROADMAP.md`](./ROADMAP.md) for
the current implementation plan. The repository will not contain advanced
features (renewal, revocation, AI, multi-tenancy, Kubernetes) until those
phases are explicitly opened.

## Engineering Rules

All contributors must read [`CLAUDE.md`](./CLAUDE.md) before opening a PR.
If a PR conflicts with `CLAUDE.md`, the PR loses.

## License

License selection deferred to project owner. See `LICENSE` placeholder.
