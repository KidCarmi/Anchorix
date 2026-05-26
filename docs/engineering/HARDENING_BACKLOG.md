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

### H-027 — Ownership explanation retention policy

- **Title:** `feat(governance): ownership_match_explanations retention sweep`
- **Risk:** low-medium (storage growth). H-026's
  `ownership_match_explanations` table only writes a row when
  a cert's decision changes; for a stable fleet this caps
  cardinality. But fleets undergoing active classification
  rollout (every operator iteration on rules flips a slice of
  certs) can grow this table by tens of thousands of rows per
  day during onboarding. v0.x keeps every row forever and
  relies on the `certificate_ownership.explanation_id` pointer
  to keep the latest reachable; older rows accumulate without
  a query path beyond the explanation timeline endpoint.
- **Scope:** background sweep (sibling to the ownership
  scheduler) that prunes per-cert explanation history beyond a
  retention window. Concrete policy: "keep the latest 10
  explanations per cert; rows older than 90 days that are not
  in the latest-10 set are deleted". Each cleanup pass emits
  one `governance.explanation_pruned` audit row with a count;
  no per-row audit. The sweep takes the per-org advisory lock
  so it serializes with recompute. The
  `certificate_ownership.explanation_id` invariant must hold —
  the current explanation is never pruned.
- **Recommended PR:** `feat(governance): explanation retention sweep`.
- **Reason not fixed now:** picking a retention window before
  pilot data exists picks an arbitrary number. The H-026A
  schema is unchanged whichever policy lands. Defer until
  pilot measurements indicate the storage cost is meaningful.
- **References:** CLAUDE.md §16 (no destructive migrations —
  this is a scheduled DELETE, not a migration);
  `docs/engineering/H026_TRUST_GOVERNANCE_PLAN.md` §3.10.

### H-028 — Policy waiver abuse signal

- **Title:** `feat(governance): policy waiver extension abuse detection`
- **Risk:** low (governance, not security). H-026's policy
  waiver model requires `expires_at` and audits every grant,
  but operators can repeatedly extend the same waiver to
  effectively make it permanent. The audit history exposes
  this, but no in-product signal surfaces "this waiver has
  been extended four times in 90 days".
- **Scope:** small read-side helper that returns a "waivers
  needing governance review" list — waivers with N grants
  for the same `(policy_definition_id, policy_rule_local_id,
  scope_kind, scope_id)` tuple within the last 90 days where
  N exceeds a configurable threshold. No automatic
  rejection; the goal is surfacing for review. Lives behind
  `GET /policy-waivers?review_needed=true`.
- **Recommended PR:** `feat(governance): waiver review signal`.
- **Reason not fixed now:** v0.x has no waivers yet; the
  feature requires real data to tune the threshold. Defer
  until H-026D ships and pilot operators have written enough
  waivers to calibrate.
- **References:** `docs/engineering/H026_TRUST_GOVERNANCE_PLAN.md`
  §3.13, §5.6.

### H-029 — Ownership: paginate `ListOverridesExpiringBy`

- **Title:** `perf(governance): paginate expiring-override sweep read`
- **Risk:** low (memory, not correctness). H-026B1's
  `OwnershipRepository.ListOverridesExpiringBy` is intentionally
  unpaged: it returns every active override whose `expires_at`
  has passed in one slice. Overrides are operator-created pins,
  expected to be low-cardinality (hundreds), and the H-026B
  recompute auto-clears them every pass so the expired set stays
  bounded by what expired since the previous pass. The unbounded
  read is therefore safe for the expected workload.
- **Scope:** add a cursor-paged variant
  (`ListOverridesExpiringByPaged(ctx, orgID, now, cursorCertID, limit)`)
  and switch the H-026B recompute to drain it page-by-page, the
  same way it pages signals and ownership rows. Keep the unpaged
  method or remove it once no caller remains.
- **Reason not fixed now:** building pagination before a caller
  (the B2 recompute) exists is speculative, and the realistic
  override cardinality does not justify it yet. The risk only
  materializes under a pathological pattern — e.g. a bulk
  override import followed by a long scheduler outage so tens of
  thousands expire before the next sweep. If bulk override
  import lands (it is not in v0.x scope), revisit this first.
- **References:**
  `docs/engineering/H026B_OWNERSHIP_ENGINE_PLAN.md` §3.4;
  `docs/engineering/H026_TRUST_GOVERNANCE_PLAN.md` §3.9.

### H-030 — Ownership recompute: collation-independent stream merge

- **Title:** `hardening(governance): collation-independent ownership stream merge`
- **Risk:** low and currently unreachable. The H-026B2 ownership
  recompute streams certificates and prior ownership in two paginated
  streams, both `ORDER BY certificate_id`, and merges them in Go with a
  `<` string comparison (`streamAndDecide`). Correctness requires Go
  byte order to agree with the PostgreSQL collation used by the SQL
  `ORDER BY` / cursor `>`. It does today because every `certificate_id`
  is server-minted by `ids.New()` — a fixed-length lowercase-hex string
  `[0-9a-f]{32}` — for which byte order equals collation order under any
  PostgreSQL collation. Cert ids are never operator-supplied, so the
  punctuation/case/length cases where glibc `en_US.UTF-8` diverges from
  byte order cannot occur.
- **Scope:** if a future change ever makes `certificate_id` (or another
  merge key) non-hex or operator-influenced, the merge must stop relying
  on the implicit ordering agreement. Two clean options: (a) fetch
  prior ownership per signal-page via a set lookup
  (`WHERE certificate_id = ANY($ids)`), which is order-independent; or
  (b) order both streams `COLLATE "C"` with matching `COLLATE "C"`
  indexes so SQL order is byte order. Option (a) is preferred (no index
  churn, no full-fleet sort).
- **Reason not fixed now:** there is no reachable defect — the invariant
  holds for all server-minted ids, and is asserted by
  `TestOwnershipMergeHandlesNewCertInterleavedAmongOwned`
  (new-cert-interleaved-among-owned, which exercises the skip-loop) and
  documented inline on `streamAndDecide`. Restructuring would add a repo
  method or a perf-regressing `COLLATE "C"` sort for a non-reachable
  case.
- **References:**
  `backend/internal/governance/ownership/recompute.go` (`streamAndDecide`);
  `docs/engineering/H026B_OWNERSHIP_ENGINE_PLAN.md` §3.3.

### H-025 — Findings scheduler: per-recompute timeout

- **Title:** `feat(findings): per-org recompute timeout in scheduler`
- **Risk:** low (operational). `Scheduler.recomputeOrg` invokes
  `Service.RecomputeScheduled(ctx, orgID)` and blocks until it
  returns. The v0.1 rules are pure functions of `(cert, now)`
  with no I/O — they cannot hang. But a future rule that does
  something exotic (a database call, a regex with catastrophic
  backtracking, a chain validation against an OCSP responder)
  could block indefinitely; the scheduler would block until
  process-level `ctx` cancellation, missing all subsequent
  ticks for every org in the sweep.
- **Scope:** wrap each `recomputeOrg` call in a
  `context.WithTimeout(ctx, perOrgBudget)` where `perOrgBudget`
  is a new config knob defaulting to (say) 5 × the recompute
  duration p99 once we have one. The wrapper would log a
  `recompute timed out` line at error level and the loop
  continues to the next org. Pairs naturally with adding the
  first non-pure rule.
- **Recommended PR:** `feat(findings): per-org recompute timeout`.
- **Reason not fixed now:** v0.1 has only deterministic pure
  rules; the hang scenario is unreachable. Adding a timeout
  before there's a real recompute-duration baseline would pick
  an arbitrary number; better to wait until the first non-pure
  rule arrives (Phase 4) and size the timeout against measured
  data.
- **References:** `internal/findings/scheduler.go`
  `recomputeOrg`; `docs/engineering/CERTIFICATE_FINDINGS.md`
  §7 (Background scheduler).

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
