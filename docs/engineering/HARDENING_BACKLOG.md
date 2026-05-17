# Hardening Backlog

This file tracks **real** follow-up engineering items surfaced during
the post-PR-002 hardening pass (PR-005). Each entry is small enough
to land in a focused PR but was deferred from PR-005 to keep that PR
documentation-only.

**This is not a TODO list.** Per CLAUDE.md §19, TODO-driven
architecture is forbidden. Each entry below has a clear scope, a
recommended PR title, and a rationale for why it wasn't fixed in
PR-005. New items get added only when the work is real, scoped, and
justifiable.

**Source of truth for rules:** [`CLAUDE.md`](../../CLAUDE.md). If
this file and CLAUDE.md disagree, CLAUDE.md wins.

## Open Items

### H-019 — Certificate ingestion: audit-row amplification under sustained rejected batches

- **Title:** `feat(inventory): rate-limit per-agent batch-rejection audit rows`
- **Risk:** low-medium (operational + storage). The certificate
  ingestion service writes one `agent.certificate_batch_rejected`
  / `agent.certificate_batch_invalid` audit row per rejected
  batch (severity:"security" for the private-key case). A
  compromised or buggy agent credential that submits malformed
  batches at the endpoint's request rate produces one audit row
  per request, with no in-product cap. Over hours or days this
  inflates the `audit_events` table and dilutes the security
  signal the rows are supposed to carry — exactly the
  alert-fatigue failure mode CLAUDE.md §9 is trying to avoid by
  labelling these `severity:"security"`.
- **Scope:** per-agent + per-action sliding-window suppression
  inside `internal/inventory` (e.g. coalesce repeated rejections
  for the same `(agent_id, action)` within N minutes into a
  single audit row with `count` metadata; emit a fresh row when
  the agent's behavior changes — rejection reason flips, or the
  window expires). Storage layer requires no change. The first
  rejection in a fresh window always audits — alerting is never
  silenced for a new event class. Coalescing state may live in
  the existing `audit_events` table (query the last N minutes
  before inserting a new row) or in a small in-memory LRU on the
  Service; pick whichever survives a control-plane restart
  cleanly (CLAUDE.md §5.3 stateless preference).
- **Recommended PR:** `feat(inventory): rate-limit per-agent
  batch-rejection audit rows`.
- **Reason not fixed now:** rate-limiting is explicitly out of
  scope for the post-PR-026 hardening pass per the operator's
  framing — the pass exists to catch correctness gaps, not to
  add new operational surface. The current behavior is
  documented (one audit per batch; rejections are bounded by the
  agent's request rate, which is itself bounded by the bearer
  credential's privileges); the v0.1 trust model
  (CLAUDE.md §12) places agents inside the operator-trusted
  network boundary, so unbounded audit rows from a single
  credential indicate a compromised credential and are exactly
  the signal we want operators to investigate. Promoting this
  to a hard limit is a v0.x concern once rate-limiting
  primitives exist control-plane-wide.
- **References:** CLAUDE.md §9 (severity:"security" alerting);
  `docs/engineering/CERTIFICATE_INVENTORY.md` §6 (audit
  cardinality); `internal/inventory/service.go`
  `recordBatchRejection` / `recordBatchInvalid`.

### H-012 — Agent rebind: admin token issuance + redemption

- **Title:** `feat(enrollment): admin rebind-token issuance + agent rebind execution`
- **Risk:** medium (operational + security). The bearer-credential
  identity model has no in-product recovery path today; operators
  reinstalling a workstation orphan its observation history or
  drop to direct SQL. The design landed (see References) commits
  to **rebind reuses the same `agent_id`**, which keeps heartbeat,
  inventory, and future certificate observations continuous
  across reinstalls.
- **Scope:** ship both endpoints in one PR — they share the
  `agent_rebind_tokens` table and atomicity model, and shipping
  issuance without a consumer would leak admin tokens with no way
  to redeem them. Concretely: new migration for
  `agent_rebind_tokens` (composite FK to `agents(organization_id,
  id)`, hashed token, single-use lifecycle bounds);
  `internal/enrollment` service additions for issuance + atomic
  redemption (conditional UPDATE pattern); two handlers
  (`POST /agents/{id}/rebind-token` admin, `POST /agents/rebind`
  anonymous); audit actions `agent.rebind_token_issued`,
  `agent.rebound`, `agent.rebind_rejected` (all
  severity:"security"); full unit + integration test coverage
  following the deployment-package precedent (concurrency,
  cross-org, idempotency-like behavior, generic-rejection
  envelope).
- **Recommended PR:** `feat(enrollment): admin rebind-token
  issuance + agent rebind execution`.
- **Reason not fixed now:** spawned by the H-006 design PR
  ([`AGENT_REINSTALL_REBIND.md`](./AGENT_REINSTALL_REBIND.md)).
  Land design first so the implementation can lock the wire
  shape; H-012 then implements against the agreed contract.
- **References:** CLAUDE.md §6, §9, §16, §18;
  [`docs/engineering/AGENT_REINSTALL_REBIND.md`](./AGENT_REINSTALL_REBIND.md)
  §4, §8, §9, §10; H-008 (Phase 6 mTLS carries the design forward).

### H-013 — Agent-initiated credential rotation

- **Title:** `feat(enrollment): agent-initiated credential rotation`
- **Risk:** low-medium. Independent of H-012 — rotation requires a
  valid current credential and so does not need the rebind token
  primitive. The endpoint is small but security-significant: every
  rotation atomically invalidates the previous credential.
- **Scope:** `POST /api/v1/agent/credential/rotate` behind the
  existing agent-bearer middleware (`/agent/*` singular-prefix
  convention). Mints new credential, swaps `agents.credential_hash`
  atomically, returns plaintext exactly once. Adds
  `last_credential_rotated_at` and `credential_version` columns to
  `agents` (small migration). Audit action
  `agent.credential_rotated` (severity:"security") in the same
  transaction as the swap. No overlap window — see the design's §5
  rationale. Full unit + integration test coverage including the
  old-credential-immediately-invalid assertion.
- **Recommended PR:** `feat(enrollment): agent-initiated
  credential rotation`.
- **Reason not fixed now:** spawned by the H-006 design PR. Can
  ship before or after H-012; the two are independent (rebind
  recovers from a LOST credential, rotation requires a VALID one).
- **References:** CLAUDE.md §6, §9, §18;
  [`docs/engineering/AGENT_REINSTALL_REBIND.md`](./AGENT_REINSTALL_REBIND.md)
  §5, §8, §9, §10.

### H-008 — Future mTLS / device crypto identity hardening

- **Title:** `design(security): Phase 6 mTLS migration for agent identity`
- **Risk:** high (security; Phase 6, not v0.1). The v0.1
  identity is a bearer credential. CLAUDE.md §6.4 commits to
  mTLS in Phase 6: each agent presents a client certificate, the
  control plane pins it at enrollment, and the agent's identity
  becomes its key pair rather than a long-lived shared secret.
  Migration 0002 already relaxed
  `agents.public_key_fingerprint` to NULL specifically so a
  future mTLS migration can populate it for every agent without a
  schema reshape. The design + migration are deferred but should
  be tracked formally.
- **Scope:** **design first**. Enrollment flow needs a key-pair
  generation step on the agent, a CSR to the control plane, an
  issuance flow (a built-in CA? a delegated PKI provider?), and
  a pinning model. The `internal/providers/pki/` package already
  exists for the provider abstraction. The agent side requires
  Windows-native key storage (CNG / DPAPI). The transition story
  matters: a fleet enrolled on bearer must be able to upgrade
  in-place without re-deploying installers.
- **Recommended PR:** First a design doc
  (`docs/security/AGENT_MTLS.md`); then a migration that
  populates `public_key_fingerprint`; then the issuance flow.
- **Reason not fixed now:** Phase 6 boundary; the bearer
  credential is the documented v0.1 primitive and the migration
  preserves the schema for the upgrade.
- **References:** CLAUDE.md §6.4 (mTLS by Phase 6); §10 (provider
  abstraction); `docs/engineering/AGENT_ENROLLMENT.md` Schema
  notes section.

## How items get added or removed

- **Added** when a deferred follow-up has clear scope, a real risk,
  and a recommended PR shape. "We might want to look at X someday"
  is not an entry; design speculation lives in
  `docs/architecture/EVOLUTION.md`.
- **Removed** when the recommended PR has merged. Crossing the entry
  out is not enough — delete it. The merge commit + this file's git
  history are the audit trail.
- **Promoted** to a CLAUDE.md amendment if the item turns out to
  encode a binding rule. CLAUDE.md is the constitution; this file is
  the punch list.
