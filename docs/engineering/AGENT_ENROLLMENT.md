# Agent Enrollment — Deployment Package Foundation

Reference for the deployment-package + agent-enrollment foundation
that landed in PR #13 (Phase 2 of the roadmap).

**Source of truth for rules:** [`CLAUDE.md`](../../CLAUDE.md). If
this file and CLAUDE.md disagree, CLAUDE.md wins.

## Goal

Give an admin a single-button way to onboard a fleet of Windows
agents without ever copying a token between two terminals. A
fleet-management tool (SCCM, Intune, GPO, …) deploys an installer
that already knows how to call the control plane and enroll
silently. The control plane sees each enrollment, organizes the
agent into the right group, and audits the whole flow.

Phase 2 builds **the backend, API, and identity model** that the
future installer / installer generator will sit on top of. The
installer binary, MSI builder, SCCM scripts, Intune profiles, and
GPO templates are out of scope for PR #13.

## Concepts

### Deployment Package

An admin-issued enrollment artifact:

- has a single high-entropy `bootstrap_secret` (server stores
  only `sha256(bootstrap_secret)`),
- has a `package_type` from a closed vocabulary,
- has bounded usage (`max_uses`), bounded lifetime (`expires_at`),
  and operator revocation (`revoked_at`),
- carries default group / labels copied onto each enrolled agent.

The package's purpose is to be embedded in a deployment artifact
(MSI, .intunewin, GPO MSI) so the installer can present the
bootstrap secret on first boot and never store it locally after
that.

### `package_type` vocabulary

| Value         | Intended rollout context                                   |
| ------------- | ---------------------------------------------------------- |
| `baseline`    | Standard approved agent version. Long expiry, generous max_uses. |
| `bulk_sccm`   | Fleet-management tool rollout (SCCM, Intune, GPO).         |
| `technician`  | Small-batch hands-on installs by an operator.              |
| `vip`         | Tightly scoped sensitive installs. Low max_uses, short expiry. |
| `lab`         | Temporary lab/test package. Low max_uses, short expiry.    |

`package_type` is metadata. v0.1 domain logic does not branch on
it; the future GUI uses it to organize the package list and to
default UX knobs (e.g. shorter TTL on `vip`).

### Agent Credential

After successful enrollment the control plane issues a high-entropy
bearer credential to the agent. The plaintext appears in the
enrollment response **once** and is never reissued. The control
plane persists only `sha256(agent_credential)`. mTLS replaces the
bearer credential in Phase 6 (CLAUDE.md §6.4).

## End-to-end flow

```
┌──────────────────────────────────────────────────────────────────────────┐
│ 1. Admin (operator UI, future)                                           │
│    POST /api/v1/deployment-packages                                      │
│       {name, package_type, ttl_seconds, max_uses, default_group_name,    │
│        default_labels, ...}                                              │
│    ←  201 + {bootstrap_secret, bootstrap_metadata}    (shown ONCE)       │
└──────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ 2. Future GUI bakes bootstrap_metadata + bootstrap_secret into an        │
│    installer artifact (MSI, .intunewin, ...).                            │
│                                                                          │
│    OUT OF SCOPE for PR #13 — the artifact builder lives in a later PR.   │
└──────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ 3. SCCM / Intune / GPO deploys the artifact silently to hundreds /       │
│    thousands of Windows endpoints. Same bootstrap_secret on every box.   │
└──────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ 4. Agent service first run on each endpoint:                             │
│    POST /api/v1/agents/enroll                                            │
│       {bootstrap_secret, hostname, agent_version, machine_fingerprint,   │
│        install_id}                                                       │
│    ←  201 + {agent_id, agent_credential, ...}     (credential shown ONCE)│
│                                                                          │
│    Agent persists agent_credential locally (DPAPI etc. — Phase 6) and    │
│    erases the bootstrap_secret from its config.                          │
└──────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌──────────────────────────────────────────────────────────────────────────┐
│ 5. Agent appears in GET /api/v1/agents with the package's group_name /  │
│    labels.                                                               │
└──────────────────────────────────────────────────────────────────────────┘
```

The agent must treat `bootstrap_secret` as transient: after the
single successful `POST /agents/enroll` call it removes it from
disk and uses `agent_credential` for every subsequent request.

## Package lifecycle

A package is **active** when all three conditions hold:

1. `revoked_at IS NULL`
2. `expires_at > now()`
3. `uses_count < max_uses`

Failing any one makes future enrollments rejected. **Already
enrolled agents are unaffected** — revoking a package is a future
gate, not a fleet teardown. To disable an already-enrolled agent
the operator revokes the agent itself (Phase 3+ UI).

> **Revocation surface.** The `deployment_packages` schema has
> `revoked_at`, `revoked_by_user_id`, and `revoked_reason` columns,
> and the enrollment service / SQL `IncrementUses` enforce the
> revoked state atomically. An **operator-facing revoke API** —
> `POST /api/v1/deployment-packages/{id}/revoke` — landed in PR
> #15 (H-005). It is admin-only, organization-scoped (cross-org
> ids surface as 404 not_found, not 403, so admins cannot
> enumerate packages in neighboring tenants), idempotent on a
> second revoke (200 with `already_revoked: true`, no duplicate
> audit row), and commits the row UPDATE in the same transaction
> as a `deployment_package.revoked` audit event. The full
> contract lives in `docs/api/REST_API.md`.

### Typical lifecycle: baseline + version bump

```
T0   admin creates "Baseline Windows 0.1.0" (max_uses=5000, 30d expiry)
       │  SCCM rolls it out; 1,200 agents enroll over the next week
T1   admin creates "Baseline Windows 0.1.1" (new version available)
       │  SCCM rolls 0.1.1 to the next wave; 800 agents enroll
T2   admin revokes "Baseline Windows 0.1.0"
       ✓ no new agents can enroll through the 0.1.0 package
       ✓ the 1,200 agents already enrolled through it stay active
```

### Typical lifecycle: VIP / sensitive install

```
T0   admin creates "VIP technician package" (max_uses=10, 6h expiry,
                                              package_type=vip)
       │  technician walks to ten endpoints, installs each one
T1   max_uses reached → package is exhausted; further attempts rejected
       │  (or expiry hits at T0+6h, whichever first)
```

## Rejection model

Every enrollment failure mode collapses to one wire envelope:

```
401 enrollment_rejected
```

The internal reason is recorded as an `agent.enrollment_rejected`
audit event with `severity: "security"`:

| `metadata.reason`               | Cause                                           |
| ------------------------------- | ----------------------------------------------- |
| `bootstrap_secret_unknown`      | Hash matched no package                         |
| `package_revoked`               | Operator revoked the package                    |
| `package_expired`               | `expires_at` is in the past                     |
| `package_exhausted`             | `uses_count >= max_uses`                        |
| `install_id_already_enrolled`   | Duplicate `install_id` in the same org          |

Operators query the audit feed; agents only ever see the generic
envelope. This matches the deterministic-auth posture
`auth.login_failed` already establishes (CLAUDE.md §6).

## Concurrency and SCCM readiness

A bulk_sccm rollout may attempt hundreds of enrollments in a short
window — sometimes against a package whose `max_uses` is itself in
the hundreds. The atomicity guarantee is enforced by a single
conditional UPDATE inside
`storage/postgres.DeploymentPackageRepository.IncrementUses`:

```sql
UPDATE deployment_packages
   SET uses_count   = uses_count + 1,
       last_used_at = $2
 WHERE id = $1
   AND revoked_at IS NULL
   AND expires_at > $2
   AND uses_count < max_uses;
```

If the UPDATE affects 0 rows, the caller's transaction rolls
back (no agent created, no audit event written) and a follow-up
SELECT classifies the failure into one of revoked / expired /
exhausted. Tested under contention by
`backend/test/integration/enrollment_test.go::TestEnrollAgentMaxUsesAtomicUnderConcurrency`.

## Grouping and labels

Each deployment package can carry `default_group_name` and
`default_labels`. The enrollment service copies both onto every
agent created through that package. Examples:

| Package                                | Group     | Labels                  |
| -------------------------------------- | --------- | ----------------------- |
| "SCCM rollout - Finance"               | Finance   | `["sccm", "finance"]`   |
| "VIP technician package"               | VIP       | `["vip", "technician"]` |
| "Lab temporary package"                | Lab       | `["test", "temporary"]` |

`GET /api/v1/agents` returns `group_name` and `labels` so the UI
can organize the fleet view without a separate group/label CRUD
surface.

Group/label management is **enrollment-time only** in v0.1. There
is no policy-by-group engine, no RBAC-by-group, no label taxonomy
service. Those land in later phases if the product demands them.

## Reinstall behavior in v0.1

The enrollment request accepts identity hints:

- `hostname`
- `machine_fingerprint` (hashed before storage)
- `install_id` (stable installer-issued id)
- `agent_version`

The contract for `install_id` in v0.1 is **single-use identity
binding**, deliberately:

- `install_id` is unique per organization (enforced by the
  conditional unique index on `agents(organization_id, install_id)
  WHERE install_id IS NOT NULL` introduced in migration 0002).
- A second enrollment with the same `install_id` is rejected with
  the standard `enrollment_rejected` envelope and an
  `agent.enrollment_rejected` audit row tagged
  `reason: "install_id_already_enrolled"`.
- The previously issued agent credential is **never returned
  again** by any endpoint. The plaintext exists only in the
  original `POST /agents/enroll` response struct and is GC'd as
  soon as that response is written.
- Reinstall, rebind, and recovery flows are **intentionally
  deferred**. Re-issuing a credential to a "returning"
  `install_id` requires an explicit design (probably a Phase-3
  admin-approved reinstall token + credential rotation flow), and
  v0.1 does not paper over the gap.
- Future versions may support explicit rebind / rotation flows
  with operator approval. The current behavior is **fail-closed by
  design** so two installers cannot race to take over the same
  logical agent identity, and so a stolen `install_id` cannot be
  re-used to mint a fresh credential.

Operators handling an actual reinstall today should:

1. Revoke the existing agent row (Phase 3+ UI; direct
   `UPDATE agents SET status='revoked' WHERE id='...'` for now),
2. re-deploy the installer with a **fresh** `install_id`.

`machine_fingerprint` is hashed at the API boundary and stored as
bytes. The raw fingerprint never reaches the DB; it serves as a
diagnostic signal for operators trying to recognize a returning
host without being a stable identity primitive.

## Schema notes

### `agents.public_key_fingerprint` is now nullable

Migration 0001 declared `agents.public_key_fingerprint` as
`NOT NULL` under the assumption that agents would identify with a
pinned public key from the start. PR-013 introduces a
**bearer-credential identity model** for v0.1 — see "Agent
Credential" above — and `public_key_fingerprint` is therefore
**not** populated by the current enrollment flow. Migration 0002
relaxes the column to nullable so the bearer flow can write `NULL`
without a synthetic placeholder.

This change is **deliberate and additive**, not a trust-model
weakening:

- The bearer credential (server-issued, SHA-256-stored,
  returned-once) remains the v0.1 agent identity primitive.
- The Phase 6 mTLS migration will populate the column for every
  agent that completes the mTLS bootstrap, restoring the pinned-
  public-key model on top of the bearer flow.
- The column kept its UNIQUE constraint on
  `(organization_id, public_key_fingerprint)`. PostgreSQL treats
  multiple NULLs as distinct under default UNIQUE semantics, so
  v0.1 enrollments coexist; once Phase 6 populates the column,
  the constraint enforces one mTLS identity per agent per org as
  originally designed.
- No existing data is dropped or rewritten by 0002; only the
  NOT NULL declaration is relaxed.

## Audit events

The enrollment service writes the following actions:

| Action                          | Actor           | Notes                                                  |
| ------------------------------- | --------------- | ------------------------------------------------------ |
| `deployment_package.created`    | `user` (admin)  | Metadata: package_type, max_uses, expires_at, group, label_count |
| `agent.enrolled`                | `agent`         | Metadata: deployment_package_id, hostname, agent_version, group, label_count |
| `agent.enrollment_rejected`     | `agent`         | `severity: "security"`. Metadata: reason, package_id (when known), hostname, has_install_id, has_machine_fp |

The plaintext `bootstrap_secret` and `agent_credential` are
**never** written into audit metadata. Enforced by:

- a unit-test assertion that scans the audit metadata for the
  plaintext after a successful create + enroll;
- an integration test that does the same against the live
  `audit_events` table;
- the broader H-001 redaction sweep test
  (`backend/test/integration/redaction_test.go`) which scans the
  raw log stream for any sensitive value during a full flow.

All three actions write the audit row in the same transaction as
the state change. An audit-write failure rolls back the package
insert / agent insert / uses_count increment — there is no state
where a package exists without an audit row.

## Security properties

These are invariants of the foundation:

- **No plaintext bootstrap secret storage.** Only `sha256` is
  persisted. The plaintext lives in exactly one response struct
  (`CreatePackageOutput`) and is GC'd after the response is
  written.
- **No plaintext agent credential storage.** Same model as above.
- **No secrets in logs.** Enforced by `internal/logger` redaction
  allow-list, the H-001 full-flow sweep, and explicit
  audit-metadata builders that whitelist non-sensitive fields only.
- **Generic rejection envelope.** A failed enrollment cannot be
  used to enumerate package state.
- **Fail closed.** Every classification ambiguity surfaces as
  `enrollment_rejected`. Duplicate `install_id`, unclassifiable
  increment failures, and bogus input all return the same wire
  shape.
- **Organization scoping.** Packages, agents, and audit events are
  org-keyed at the schema level. The `/agents` list endpoint
  derives the org from the operator's session.
- **Least privilege.** Package creation is admin-only;
  non-admin operators cannot mint enrollment artifacts.

## Non-goals (Phase 2 boundary)

These are deliberately not implemented in PR #13. Each would build
on the foundation but is reserved for a focused later PR.

- **Installer / MSI / .intunewin generator.** The GUI that turns a
  deployment package into a deployable artifact.
- **SCCM, Intune, and GPO templates.** Operator-facing rollout
  scripts and profiles.
- **Agent service lifecycle.** Windows service installer, auto-update,
  uninstall.
- **DPAPI-protected local credential storage on the agent.** Phase 6
  hardening.
- **mTLS between agent and control plane.** Phase 6.
- **Heartbeat / inventory ingest.** Phase 3 (`POST /agents/{id}/heartbeat`,
  `POST /agents/{id}/inventory`).
- **Findings / risk-rule evaluation.** Phase 4.
- **Package revocation UI.** The operator-facing **API**
  (`POST /deployment-packages/{id}/revoke`) shipped in PR #15
  (H-005); a frontend UI for the revoke flow lands when the
  agents/deployment-packages list view is built out (Phase 2
  remainder).
- **Agent revocation UI / API.** Phase 3+; today revocation requires a
  direct DB UPDATE.
- **Reinstall idempotency that returns the existing agent.** v0.1 fails
  closed on duplicate `install_id` rather than re-issuing a credential.
- **Multi-tenant org isolation.** v0.1 is single-tenant; the schema is
  org-keyed for future use.
- **Auto-renewal of bootstrap secrets.** Operators rotate packages
  explicitly (create new, revoke old).

## References

- [`backend/migrations/0002_deployment_packages.sql`](../../backend/migrations/0002_deployment_packages.sql)
  — schema additions.
- [`backend/internal/enrollment/`](../../backend/internal/enrollment/)
  — domain types, service, atomicity contract.
- [`backend/internal/storage/postgres/deployment_package_repository.go`](../../backend/internal/storage/postgres/deployment_package_repository.go)
  — atomic `IncrementUses`.
- [`backend/internal/httpapi/handlers/deployment_packages.go`](../../backend/internal/httpapi/handlers/deployment_packages.go),
  [`backend/internal/httpapi/handlers/agents.go`](../../backend/internal/httpapi/handlers/agents.go)
  — HTTP boundary.
- [`docs/api/REST_API.md`](../api/REST_API.md) — endpoint contract.
- [`docs/engineering/AUTH_FOUNDATION.md`](./AUTH_FOUNDATION.md) — operator
  session model (admin permissioning consumed by this endpoint).
