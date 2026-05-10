# Architecture Evolution Path

**Source of truth for binding rules:** [`CLAUDE.md`](../../CLAUDE.md).
The version sketches below are **directional**, not commitments.
Every line item below v0.1 still requires CLAUDE.md to be amended
before the work can begin.

## Why this document exists

So that every PR opened today carries enough context to know
whether it is "shaping the platform for v0.2" or "scope-creeping
into territory the constitution still excludes". The clean test:
*if your PR adds a row from one of the "Out of scope" boxes below,
amend `CLAUDE.md` first.*

---

## v0.1 — Walking Skeleton (current)

**Theme:** ship the minimum platform that proves the architecture.

**State at end of v0.1 (cumulative):**

- Modular monolith control plane in Go (`backend/`).
- Single Windows agent (`agent/windows/`).
- React + Tailwind operator UI.
- PostgreSQL persistence; explicit migration runner; no auto-DDL.
- HTTPS for agent ↔ control plane; pinned trust after enrollment.
- `cmd/anchorix admin create` to bootstrap the first operator. No
  default admin / no default password (CLAUDE.md §6.5,
  `docs/BOOTSTRAP.md`).
- Audit events for state-changing operations; structured logging
  with redaction.
- 14 blocking CI gates; Windows CI activates at the end of v0.1
  (Phase 6) per [`WINDOWS_CI.md`](../engineering/WINDOWS_CI.md).
- Single organization row; basic role split (operator / admin).
- One PKI provider stub (`pki/none`); the abstraction is in place
  for real backends.

**What v0.1 deliberately is not:** see CLAUDE.md §13.

---

## v0.2 — Real Trust Surface (sketch)

**Theme:** the agent is more trustworthy on the wire and the
platform integrates with one real PKI.

**Direction (subject to CLAUDE.md amendment per item):**

- **Agent identity hardening:** items H1–H4 from
  [`AGENT_HARDENING.md`](../engineering/AGENT_HARDENING.md):
  local identity ACLs, enrollment-token rate limiting + reasons,
  TLS SPKI pinning beyond hostname, retry/offline queue.
- **First concrete PKI provider:** one of {ADCS, Vault PKI,
  Smallstep, EJBCA}. The choice is operator-driven; the
  abstraction lands in v0.1, the first concrete in v0.2. CLAUDE.md
  §10 (Ops Freedom Rule) governs.
- **Inventory export:** CSV (always) and PDF (later). Read-only
  surface; no automation.
- **Outbound webhooks:** an additive `/webhooks` provider for
  routing findings to operator alerting. Lives behind the same
  provider abstraction as PKI; same threat-model requirement
  (CLAUDE.md §6.10).
- **Admin role split refinement:** the v0.1 two-role model
  (`operator` / `admin`) gains a third for "viewer" /
  "auditor", read-only. Driven by operator demand. **No** RBAC
  matrix UI yet — roles are configured at admin-create time and
  via an audited API call.
- **API additions inside `/api/v1`:** new endpoints, never
  breaking changes. CLAUDE.md §17 governs.
- **CI growth:** advisory DAST baseline (`zap-baseline` or
  similar) running on every PR; promotion to blocking requires a
  documented green streak per [`CI_PLAN.md`](../engineering/CI_PLAN.md).

**Explicitly out of scope for v0.2 (CLAUDE.md amendment required):**

- Automated renewal or revocation.
- Built-in CA.
- Linux agent.
- macOS agent.
- SSH key inventory.
- Kubernetes deployment artefacts.
- AI / ML risk classification.
- Multi-tenant org isolation in code.
- HA clustering.

---

## v0.3 — Operator Maturity (sketch)

**Theme:** the platform is comfortable to run in production for a
single tenant; the inventory and findings story has depth.

**Direction:**

- **Linux agent (separate Go module under `agent/linux/`).**
  Same protocol, same hardening posture (H1–H4 carry over). Adds
  a CI matrix entry under `WINDOWS_CI.md`'s sibling
  `LINUX_CI.md`.
- **Expanded risk rules:** chain trust verification, CT log
  divergence, weak-signature detection beyond MD5/SHA1, EKU
  policy mismatches, host-name mismatches at observation time.
  Rules remain pure functions per CLAUDE.md §10 / package
  boundaries.
- **Per-organization isolation prep:** the schema already carries
  `organization_id` on every domain table; v0.3 enforces it in
  code (queries scoped, sessions scoped, audit-event reader
  scoped). **Not** multi-tenant SaaS yet — single org per
  deployment, but the path to multi-tenancy is opened.
- **Read-replica support for the inventory query path:** a
  read-only repository implementation that targets a Postgres
  read replica. Writes still target primary. CLAUDE.md §16
  governs (storage layer ownership; no auto-DDL on the replica).
- **H5 Hardware-backed agent identity** — TPM/KSP-backed key
  storage on Windows where TPM 2.0 is available. Falls back to
  software KSP with a capability bit so risk rules can flag
  weaker storage at the operator's option.
- **Operator UI maturity:** dashboards with real charts (still
  no AI / no automation), saved filters, finding state-change
  audit trail viewer.
- **API: still `/api/v1`.** Anything that would require `/api/v2`
  triggers the §17 process — coexistence + deprecation in
  REST_API.md.

**Explicitly out of scope for v0.3 (CLAUDE.md amendment required):**

- Built-in CA.
- Automated renewal/revocation.
- Multi-tenant SaaS.
- Distributed control plane (the modular monolith is preserved).
- AI features.
- Kubernetes operator / Helm chart as the *primary* deploy
  target. (A community-supported operator may exist; it isn't
  the supported path.)

---

## Beyond v0.3 — Provider Integration & Automation Track (longer horizon)

These are **tracked**, not roadmapped to a specific version. Each
needs an explicit CLAUDE.md amendment before any work begins.

- **Additional concrete PKI providers** (ADCS, Vault, Smallstep,
  EJBCA) one per release, each with its own threat model under
  `docs/security/providers/<vendor>.md`.
- **Automation track:** automated renewal, automated revocation,
  certificate rotation. CLAUDE.md §3 ("visibility before
  automation") makes this a deliberate later step. Each automated
  action is operator-confirmable in v0.x; full automation needs
  an audit-grade approval workflow.
- **Built-in CA:** no commitment. If it ever ships, it ships as
  its own opt-in deployment with its own hardening doc. Most
  customers are expected to keep using their existing CA.
- **HA / multi-region:** the modular monolith is amenable to
  active-passive failover (it's stateless beyond Postgres).
  Active-active distributed coordination is out of scope and
  remains so.

---

## Out of Scope — Permanent (or until amended)

These items are **not** on any version's path right now. Adding any
of them to a release plan requires amending CLAUDE.md §13 first.

- Replacing PostgreSQL with another database.
- Replacing the modular-monolith deployment model with
  microservices, a service mesh, or an event bus.
- Acting as a Certificate Authority by default.
- Multi-tenant SaaS billing / quotas.
- AI features (any).
- Bundling a Kubernetes operator as the primary supported
  deployment.

---

## How This Document Is Updated

Per CLAUDE.md §15 — by amendment, with rationale, in a PR that
modifies this file (and CLAUDE.md if a non-goal moves). Sketches
in this doc are revised as new information arrives; the
"Permanent / until amended" list is the brake.
