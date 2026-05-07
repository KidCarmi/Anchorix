# Provider Abstraction (Ops Freedom Rule)

CLAUDE.md §10 requires Anchorix to support future provider integrations
without architectural rewrites. This document describes how to add a new
provider correctly.

## Provider Domains

| Domain     | Interface                                          | v0.1 implementation |
| ---------- | -------------------------------------------------- | ------------------- |
| `pki`      | [`internal/providers/pki.Provider`](../../backend/internal/providers/pki/provider.go) | `none` (introspection only) |
| `secrets`  | [`internal/providers/secrets.Provider`](../../backend/internal/providers/secrets/provider.go) | `env` (process env) |
| `transport`| [`internal/providers/transport.Provider`](../../backend/internal/providers/transport/provider.go) | HTTPS (Phase 1+) |

## Adding a New Provider

1. Create a subpackage under the right domain:
   `internal/providers/pki/<vendor>/`.
2. Implement the `Provider` interface for that domain.
3. Register the provider in the composition root (`cmd/anchorix/main.go`)
   based on configuration. **Never** import the vendor package from
   `internal/inventory`, `internal/risks`, `internal/agents`, or
   `internal/httpapi`.
4. Add config fields under `internal/config` that describe the provider.
5. If the provider needs migration-tracked state, add a new migration.
6. Add a short threat model under `docs/security/providers/<vendor>.md`
   covering: trust assumptions, network surface, secret handling, blast
   radius if compromised. Required by CLAUDE.md §6.10.
7. Document the provider in `docs/architecture/PROVIDER_ABSTRACTION.md`
   (this file) and in the operator-facing docs.

## Forbidden Patterns

- Importing a vendor package from `internal/httpapi/...`. Handlers
  consume providers via the `Registry`, not by name.
- Storing vendor-specific fields on the `Certificate` or `Finding`
  domain types. Use `evidence` / `metadata` JSONB instead.
- Hardcoding vendor capabilities in switch statements scattered across
  packages. Capabilities are advertised via `Descriptor()`.
- Initializing a provider from `init()`. All wiring happens in the
  composition root so it is greppable and testable.

## Capability Negotiation

The control plane queries `Descriptor().Capabilities` to decide which
UI affordances and API behaviors are available for a configured
provider. v0.1 only uses the `discovery` capability (passive cert
introspection). `issue` and `revoke` are reserved for future phases and
are explicitly out of v0.1 scope (CLAUDE.md §4).
