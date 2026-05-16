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

### H-009 — Shared strict JSON body decoder helper

- **Title:** `refactor(httpapi): shared strict-decode helper for optional JSON bodies`
- **Risk:** low (correctness / maintainability; no security gap
  today — every existing call site already does the right thing).
  The "single object body, no trailing JSON, optional empty body"
  idiom is duplicated across `handlers/agents.go` (heartbeat),
  `handlers/agent_inventory.go` (snapshot submit), and
  `handlers/deployment_packages.go` (revoke). The duplication is
  three identical `json.NewDecoder(http.MaxBytesReader(...)).Decode`
  + second-Decode-must-EOF blocks, which is exactly the shape
  CLAUDE.md §8.5 warns against (copy-paste instead of a small
  shared helper). A regression in one site (e.g. a future PR
  drops the second Decode) would not surface as a test failure
  in the others.
- **Scope:** introduce one helper — likely
  `envelope.DecodeStrictOptional(r, &body)` returning a clear
  error sentinel — and migrate the three current call sites.
  Keep the existing 400 envelope and 64 KiB cap. No wire-shape
  change.
- **Recommended PR:** `refactor(httpapi): centralize strict
  optional-body JSON decode in envelope package`.
- **Reason not fixed now:** PR-019 is scoped to docs + tests +
  stub cleanup; a multi-handler refactor is its own focused PR.
- **References:** CLAUDE.md §8.5 (no copy-paste implementations
  instead of a small shared helper), §17 (envelope ownership);
  `backend/internal/httpapi/handlers/agent_inventory.go`,
  `agents.go::AgentHeartbeat`, `deployment_packages.go::DeploymentPackagesRevoke`.

### H-011 — Certificate inventory (Phase 3 follow-up)

- **Title:** `feat(inventory): certificate inventory upload + observations`
- **Risk:** medium (real product work; touches schema, the
  no-private-key invariant, and risk-rule wiring later). The
  `internal/inventory` package already carries domain types
  (`Certificate`, `CertificateObservation`, `InventoryBatch`,
  `DiscoveredCertificate`), the `Ingestor` skeleton with the
  no-private-key safety check, and a `Repository` interface.
  None of it is wired — there is no HTTP route, no postgres
  repository, no service composition. PR-018 deliberately did
  NOT touch any of this (different domain, different cost
  model: certificates are append-style observations, not a
  replace-in-place snapshot).
- **Scope:** **design first, then implement.** The design
  needs to settle: (a) the agent-keyed endpoint shape (`POST
  /agent/inventory-certificates`? `POST /agent/certificates`?)
  and how it composes with the existing
  `POST /agent/inventory` snapshot endpoint without name
  confusion; (b) idempotency-key contract per CLAUDE.md §18
  (inventory batches are non-idempotent without one);
  (c) audit policy — per-batch summary vs. per-cert row vs.
  silence — applying the cardinality reasoning from
  AGENT_ENROLLMENT.md "Heartbeat"; (d) `(certificate_id,
  agent_id, store_location)` uniqueness vs. the
  `(fingerprint_sha256, source_host, source_store)` shape the
  ROADMAP currently hints at — these disagree and the schema
  must be the one that wins.
- **Recommended PR:** First a design doc
  (`docs/engineering/CERTIFICATE_INVENTORY.md`); then a
  migration + storage repo + service wiring + handler +
  REST_API additions, ideally split across two implementation
  PRs (storage + ingestion service, then handler + tests).
- **Reason not fixed now:** explicit Phase 3 scope item
  (ROADMAP.md), and PR-018 was scoped to machine-inventory
  snapshot only. Tracking it here so it doesn't get lost in
  the gap between the snapshot foundation and Phase 4
  findings.
- **References:** CLAUDE.md §4 (v0.1 scope), §6.2 (no private
  key exfiltration), §18 (idempotency keys);
  `backend/internal/inventory/`; ROADMAP.md Phase 3.

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
