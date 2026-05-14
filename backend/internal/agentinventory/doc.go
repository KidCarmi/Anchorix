// Package agentinventory owns the agent machine-inventory snapshot
// domain.
//
// Ownership boundaries (CLAUDE.md §19):
//
//   - Owns: the Snapshot type (an agent's currently-reported host
//     facts — hostname, OS, version, architecture, local IPs), the
//     Service that records and reads snapshots, and the
//     SnapshotRepository interface this package consumes.
//   - Does NOT own: SQL (lives in internal/storage/postgres), HTTP
//     wire shape (lives in internal/httpapi/handlers), or anything
//     related to *certificate* inventory (that is the unrelated
//     internal/inventory package).
//
// Forbidden dependencies:
//
//   - Must not import internal/httpapi or internal/httpapi/handlers.
//   - Must not import any storage/* implementation; the
//     SnapshotRepository interface is owned by this package and
//     implemented in internal/storage/postgres
//     (CLAUDE.md §8.8 — interfaces belong to the consumer).
//   - Must not import internal/inventory; certificate inventory is
//     a separate domain and the two packages must not entangle.
//
// Architectural role: domain layer. Plain Go types and pure
// business logic; persistence is delegated to SnapshotRepository.
//
// Snapshot semantics (PR-018):
//
//   - One *current* snapshot row per (organization_id, agent_id).
//     POST /api/v1/agent/inventory UPSERTs the row; there is no
//     history table in v0.1.
//   - The agent_id and organization_id on the snapshot ALWAYS come
//     from the authenticated agent principal (AgentFromContext),
//     never from the request body. The HTTP handler enforces this;
//     the service additionally rejects empty values for
//     defense-in-depth.
//   - The snapshot endpoint is operational state sync (matches the
//     heartbeat audit policy in AGENT_ENROLLMENT.md). Successful
//     submissions emit NO audit row. Failed auth is already audited
//     by the agent-auth middleware.
//
// Validation contract:
//
//   - hostname, os_name, os_version, agent_version, machine_arch
//     are trimmed and capped at the documented per-field byte limits
//     (see Service.Submit). Oversize input is rejected with
//     ErrInvalidSnapshotInput; the HTTP layer maps that to 400.
//   - local_ips is capped at MaxLocalIPs entries and per-entry
//     MaxLocalIPLength bytes. Empty list is valid.
//   - installed_at is optional; the agent may report zero time
//     when it has no install metadata.
package agentinventory
