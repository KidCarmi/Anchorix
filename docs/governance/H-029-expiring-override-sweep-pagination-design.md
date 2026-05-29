# H-029 — Expiring Override Sweep Pagination: Design Proposal

> **Status:** design / proposal only. **No code in this PR.** Source of
> truth for rules: [`CLAUDE.md`](../../CLAUDE.md). Builds on the merged
> ownership engine (H-026B1→B3B) — see
> [`H-026B3B-closure-summary.md`](./H-026B3B-closure-summary.md). H-029
> backlog entry:
> [`HARDENING_BACKLOG.md`](../engineering/HARDENING_BACKLOG.md) §H-029.
>
> This proposal designs **what** the expiring-override sweep primitives
> are and **how** they stay safe. It deliberately stops short of any
> caller (no scheduler, no endpoint, no background loop). Implement only
> after review.

## 1. Problem statement

`OwnershipRepository.ListOverridesExpiringBy` (added in H-026B1) returns
**every** active override in the org whose `expires_at` has passed, as
one unpaginated slice. Override cardinality is low by design (operator
pins), so the unbounded read is safe for the expected workload — and
the method has **zero production callers** today. The H-026B2 recompute
does **not** call it; the per-cert auto-clear inside `processCert`
operates on the override that came in on the cert stream, alongside
the cert and prior ownership. The method exists for a not-yet-built
B4 scheduler.

But:

- **A future B4 sweeper or a manual operator trigger** will want to
  drain the expired set out of band (cheaper than a full recompute when
  only pins changed). Without pagination, a pathological cardinality —
  e.g. a bulk override import followed by a long scheduler outage —
  yields an unbounded read.
- **Two distinct operations need pagination**, not one: *list expiring*
  (read-only operator visibility) and *sweep expired* (mutating: clear
  + per-cert re-derive + audit). The unpaged read covers neither
  cleanly.

H-029 designs **deterministic, per-org, paged primitives** for both
list and sweep, so a future caller has a small surface and the dead
unpaged method can either be removed or kept as a thin compatibility
shim.

## 2. Current override expiry behavior (as merged)

The merged engine has TWO independent ways an active override leaves
the system:

1. **Operator-initiated** (`Service.ClearOverride`, B3B): under
   `WithTxLockedOwnership(org)`, sets `cleared_at = now`,
   `cleared_by = <operator>`, `cleared_reason = <operator reason>`,
   re-derives the certificate via `rederiveCertificate`, and emits
   one `ownership.override_cleared` audit row.
2. **Recompute auto-expiry** (`processCert` in `recompute.go`): when
   the recompute streams a cert whose currently-active override has
   `expires_at <= now`, it clears the override inline
   (`cleared_by = "system"`, `cleared_reason = "auto-expired"`), then
   continues the cert's normal recompute decision, then emits one
   `ownership.override_expired` audit row per cleared override.
   Cardinality is per-override (low by design); no rollup.

**Neither path uses `ListOverridesExpiringBy`.** A standalone sweep
(decoupled from a full recompute) is the only consumer the unpaged
method anticipates.

## 3. Tables in scope

**In scope (read + UPDATE):**

- `certificate_ownership_overrides` — the row whose `cleared_at`,
  `cleared_by`, `cleared_reason` are set on auto-expiry. Soft-delete
  semantics already established (B3B).

**In scope (read; UPDATE via the existing `rederiveCertificate`):**

- `certificate_ownership` — the per-cert current-ownership row whose
  `explanation_id`, `service_id`, `decision`, etc. shift when the
  override that was its `winning_rule_id` basis is cleared.
- `ownership_match_explanations` — a new row inserted by
  `rederiveCertificate` to reflect the post-clear decision (H-026B2
  invariant: the cert's `certificate_ownership.explanation_id` always
  points at a current row).
- `audit_events` — one `ownership.override_expired` per cleared
  override, append-only.

**Explicitly NOT touched** by H-029 beyond the existing engine paths:
inventory tables, identity vocabulary (services, tags, agent_groups,
service_groups), ownership_rules, recompute runs.

## 4. What should happen when an override expires (sweep semantics)

A single sweep page processes a bounded batch of expired-but-still-
active overrides. For each row in the batch, **in the same transaction
as the page's listing read**:

1. **Clear** via the existing `ClearOwnershipOverride(ctx, org, id,
   "system", "auto-expired", now)` repository method (which sets
   `cleared_at = now`, `cleared_by = "system"`,
   `cleared_reason = "auto-expired"` and frees the partial-unique
   active-override slot). `ErrOwnershipOverrideNotFound` is treated as
   a **silent no-op** (the row was cleared by a concurrent operator
   between the listing read and the clear — there is nothing left to
   do for this row, no audit emission).
2. **Re-derive** the certificate via `rederiveCertificate(ctx, org,
   certID, nil, now)`, reusing the B3B single-cert primitive. The cert's
   `certificate_ownership` flips to whatever the rule engine decides in
   the override's absence (back to a matched rule, unowned, etc.), with
   a new explanation row written and pinned. This **mirrors the B3B
   `ClearOverride` flow exactly**.
3. **Emit** one per-override `ownership.override_expired` audit row
   (severity:"security", target_type:"certificate", target_id:certID,
   metadata: {override_id, service_id, reason:"auto-expired",
   sweep_id}). Cardinality is per-override; **no rollup**, mirroring
   B2's recompute auto-clear contract (override cardinality is low by
   design; rollup would obscure operationally meaningful events).

A sweep that finds no eligible rows in its page is a quiet no-op:
zero clears, zero re-derivations, zero audit rows. Idempotent —
re-running over an already-swept dataset selects nothing.

## 5. Pagination model

**Two distinct primitives**, both per-org, both cursor-paged:

### 5.1 `ListExpiringOverridesPaged` — read-only

Returns one page of active overrides whose `expires_at <= now`, with
the same data shape as `GetActiveOwnershipOverride` returns today.
Intended consumers: a future operator-visibility endpoint ("what's
about to drop?"), a notification path, the sweep primitive's listing
read. **No state change.**

### 5.2 `SweepExpiringOverridesPage` — mutating + audited

Drives one bounded sweep page. Internally calls the listing read, then
the clear-and-re-derive-and-audit cycle in §4 for each row. **One
call = one page = one `WithTxLockedOwnership(org)` transaction.**

Both primitives are dormant in this design: H-029 implements neither
a scheduler nor an endpoint that drives them.

## 6. Cursor design

**Cursor = `certificate_id`, exclusive.** A page is
`WHERE organization_id = $1 AND cleared_at IS NULL
AND expires_at IS NOT NULL AND expires_at <= $2
AND certificate_id > $3 ORDER BY certificate_id ASC LIMIT $4`.

Rationale:

- **Index-aligned.** The partial-unique index
  `certificate_ownership_overrides_active_idx (organization_id,
  certificate_id) WHERE cleared_at IS NULL` already exists and is
  ideal for this filter shape. The `expires_at <= now` predicate is a
  bounded filter on the index range, not a separate sort key.
- **No new index needed** for v0.x. If profile-driven measurement later
  shows the `expires_at` filter is selectivity-bound on a deep set, an
  additive partial index on `(organization_id, expires_at)
  WHERE cleared_at IS NULL AND expires_at IS NOT NULL` can be added
  later — same H-027 discipline (measure first, add only if EXPLAIN
  justifies).
- **Stable forward progress.** Once a sweep page clears a row, that
  row's `cleared_at IS NOT NULL` removes it from the partial index;
  the cursor (`certificate_id > $3`) never revisits it. A row inserted
  for a cert already passed by an earlier page (race window between
  pages) is **eventually consistent** — picked up on the next sweep
  pass.
- **Simple cursor.** One opaque column, matching every other paged
  read in the codebase (signals, ownership decision, explanations).
- **Cross-org safe.** The `organization_id = $1` predicate is the lead
  column of the partial index; no fleet-wide scan is reachable.

Rejected alternative: cursor by `(expires_at, id)` compound. Would
order "oldest expired first" (operationally appealing for surfacing
overdue pins to operators), but adds a second cursor column the caller
must serialize, requires a new index, and makes resumption fragile if
multiple overrides share a `set_at` second. Compelling only with a
verified operator need — defer.

## 7. Ordering strategy

`ORDER BY certificate_id ASC` — same as every other paged read in the
governance layer. The active partial index's prefix supplies the
ordering for free.

Deterministic for equal cursors (no `(expires_at, id)` tiebreaker
needed since `certificate_id` is unique within active overrides via
the partial-unique constraint). H-030's collation invariant holds:
server-minted hex ids → byte order == collation order under any
PostgreSQL collation.

## 8. Transaction / locking model

- **One sweep call = one bounded page = one
  `WithTxLockedOwnership(org)` transaction.** Acquires the per-org
  ownership advisory lock (xact-scope, READ COMMITTED), shared with
  full recompute and override mutations (governance plan §3.9).
- **Lock hold is bounded by page work**: limit × (one clear + one
  `rederiveCertificate` + one audit row). Default limit (TBD at
  implementation: ~50 mirrors B3B's bounded per-cert work; cap at
  ~500 absolute max).
- **The lock is NEVER held across a full-org sweep.** A caller that
  wants to drain the whole org calls `SweepExpiringOverridesPage`
  repeatedly with the returned cursor; **the responsibility for the
  loop belongs to the caller (B4 scheduler / manual trigger), not to
  H-029.** Between pages the lock is released, so operator mutations
  and full recomputes are not blocked across the sweep.
- **No nested or recursive lock acquisition.** The page handler is
  flat: list → for each → clear → re-derive → audit → commit. The
  re-derivation already runs under the same lock (it's the B3B
  primitive without its own lock acquisition).
- **Read-only list** (`ListExpiringOverridesPaged`) does **not**
  acquire the ownership lock — it is a pure read, snapshot-consistent
  with whatever transaction the caller runs it in. (The sweep wraps
  its own internal listing read inside its locked tx.)

## 9. Audit model

- **Per-override `ownership.override_expired`**, severity:"security",
  target_type:"certificate", target_id:certificate_id.
- **Metadata**: `{severity, override_id, service_id, reason:"auto-expired", sweep_id}`.
  `sweep_id` is a per-page ULID/UUID (analogous to B2's `run_id`)
  so multiple expirations from the same sweep page are correlatable.
- **One audit row per successfully-cleared override**. A row that
  was already cleared between listing and clear emits **no audit**.
  A row that failed to clear (DB error) rolls the whole page back —
  no partial audit state observable.
- **No sweep rollup.** Override cardinality is low by design; per-row
  audit is the right granularity. (Contrast with H-027 explanation
  pruning, where deletion cardinality scales with fleet × churn and a
  rollup is necessary.) If a deployment-pathological cardinality
  materializes — same trigger as the H-029 backlog entry (bulk import
  + long outage) — a rollup variant is a follow-up, not part of this
  design.
- **Audit failure rolls the page back.** Clears + re-derivations +
  audit rows commit atomically per page; an audit-write failure rolls
  the whole transaction back (mirrors B3B `ClearOverride`'s
  contract).
- **`audit_events` is never deleted** by H-029 (CLAUDE.md §9).

## 10. Repository primitives needed

- **`ListExpiringOverridesPagedQuery`** (exported const string) — the
  SQL the EXPLAIN test pins:
  ```
  SELECT id, organization_id, certificate_id, service_id, reason,
         set_by, set_at, expires_at, cleared_at, cleared_by, cleared_reason
    FROM certificate_ownership_overrides
   WHERE organization_id = $1
     AND cleared_at IS NULL
     AND expires_at IS NOT NULL
     AND expires_at <= $2
     AND certificate_id > $3
   ORDER BY certificate_id ASC
   LIMIT $4
  ```
- **`OwnershipRepository.ListExpiringOverridesPaged`** — Go wrapper
  for the SQL above, mirroring the
  `ListActiveOwnershipOverridesPaged` shape and helpers.

**Existing primitives reused (no new repo method required for the
mutating path):**

- `ClearOwnershipOverride` (B3A) — already idempotent, already returns
  `ErrOwnershipOverrideNotFound` on race.
- `GetCertificateSignals` (single-cert PK lookup) — already drives
  the B3B `rederiveCertificate`.

**`ListOverridesExpiringBy` (the existing unpaged method):** keep it
during the transition (zero callers, zero risk of removal hurting
anyone); remove in PR-2 once the paged method lands and the
integration test that exercises it is switched over. **Decision at
review:** "remove vs. retain as a thin wrapper that drains the paged
read." Recommendation: **remove**, since no production caller exists.

## 11. API / engine behavior after sweep

H-029 adds **no HTTP endpoint, no engine entry point** in this phase.
The only observable post-sweep effects come from the existing engine
contracts:

- The cleared override appears with `cleared_at != NULL`,
  `cleared_by = "system"`, `cleared_reason = "auto-expired"` in
  B3A's read endpoints.
- The cert's `certificate_ownership` reflects the re-derived decision
  (matched rule / unowned / etc.) via the existing
  `rederiveCertificate` primitive — no new shape, no `/api/v2`.
- The cert's `GET .../ownership/explanation` returns the new
  post-clear explanation row as `current`, with the previous
  `overridden` explanation moving into history. B3A's existing
  timeline endpoint continues to work unchanged.
- Operators see the per-override `ownership.override_expired` audit
  row exactly as the recompute auto-clear emits them today (same
  action, same shape).

A future caller (manual trigger / B4 scheduler) will surface the sweep
into the API layer; H-029 stays below that line.

## 12. Tests required (for the implementation PR, not this one)

- **Listing**: paged read returns expired-and-active overrides only,
  in `certificate_id ASC`, cursor advances strictly; non-expired
  overrides excluded; already-cleared excluded; `expires_at = now`
  included (`<=` boundary).
- **Strict `<=` cutoff** for `expires_at`: row exactly at `now` is
  selected (verified at SQL primitive level, like H-027's strict-`<`
  boundary test).
- **Cross-org isolation**: identical fixture in two orgs; sweep org
  A; org B's rows and audit log untouched.
- **Pagination determinism**: walk completes; each cert visited
  exactly once; resumed cursor produces stable next page.
- **Bounded page**: a deep expired set (e.g. 50 expired with
  page=10) drains across exactly 5 pages; pageSize > max clamped;
  pageSize <= 0 defaulted.
- **Per-cert sweep effects**: cleared override's `cleared_at`/`by`/
  `reason` set correctly; cert's `certificate_ownership` flips to
  the rule-derived decision (or to unowned, depending on the
  fixture); a new explanation row is written and pinned as current.
- **Audit**: exactly one `ownership.override_expired` per
  successfully cleared override (severity:"security"), in the same
  tx as the clears + re-derivations; failing the audit recorder
  rolls the entire page back (no partial cleared/re-derived state).
- **Race: lost-to-operator-clear**: between listing and the sweep
  page's clear, another transaction clears the override. The page
  treats `ErrOwnershipOverrideNotFound` as a silent no-op (no error,
  no audit), and the rest of the page completes normally.
- **Race: lost-to-recompute-auto-clear**: similar — covered by the
  same advisory lock plus the `ErrOwnershipOverrideNotFound`
  no-op behavior, but proven by an injected concurrent recompute
  that auto-clears the same row mid-page.
- **Idempotency**: running the sweep twice over the same dataset —
  second pass finds zero, emits zero audit rows.
- **Re-derivation correctness**: a swept override that was the cert's
  basis flips the cert to a rule-derived owner (when a matching rule
  exists) or to `unowned` (when none does); the new explanation row
  is the cert's `current`.
- **Other tables untouched**: ownership_rules, services, tags,
  agent_groups, certificate_observations counts unchanged across a
  sweep.
- **EXPLAIN**: the paged listing query plan contains a `Limit` and
  no fleet-wide `Group Key`, aligned with the H-027 EXPLAIN
  convention.
- **Empty-org fail-closed**: empty `organization_id` rejected.
- **Removal of `ListOverridesExpiringBy`** (if we choose remove): the
  one integration test that exercises it is updated to call the
  paged variant.

## 13. Rollout plan

1. **H-029-PR1 — paged listing primitive.** Add
   `ListExpiringOverridesPaged` to `governance.OwnershipRepository` +
   postgres implementation + the EXPLAIN-pinned const. Removes or
   retains `ListOverridesExpiringBy` per review decision. Unit /
   integration coverage for the read shape. **No caller** of the
   sweep yet.
2. **H-029-PR2 — sweep service primitive.**
   `Service.SweepExpiringOverridesPage(ctx, org, actor, now, cursorCertID, pageSize)`
   returning `{StartCursor, NextCursor, CertsScanned, ClearedCount, Done}`.
   Internally calls the listing read inside
   `WithTxLockedOwnership(org)`, then per-row clear + re-derive +
   audit. Full integration suite (§12). Reversible (dead path; no
   caller).
3. **H-029-PR2-hardening — adversarial pass.** Race windows,
   audit-rollback, cross-org isolation, cursor determinism after
   clears, bounded-page boundaries, multi-cert atomicity. Mirrors
   the H-027 hardening pass shape.
4. **(Optional) H-029-PR3 — manual operator trigger.** Only if
   review wants a pilot-exercisable endpoint before the scheduler.
   Auth + lock + audit mirror B3A recompute-trigger and B3B override-
   clear patterns.
5. **Scheduler wiring is NOT an H-029 PR** — it belongs to the B4
   ownership-scheduler phase, explicitly out of scope here.
6. **Default-safe**: until a caller is wired, H-029 has zero runtime
   effect.

## 14. Failure modes

- **Listing read fails** → no clears attempted; whole page transaction
  aborts; result returned as an error to the caller.
- **A row's clear returns `ErrOwnershipOverrideNotFound`** → silent
  no-op; page continues; no audit row for that row.
- **A row's clear returns any other error** → whole page transaction
  rolls back (atomicity); no clears, no audit rows.
- **`rederiveCertificate` fails** → whole page transaction rolls back.
  (B3B's `rederiveCertificate` already fail-closes on missing signals,
  which would re-surface here only if the cert was deleted mid-page —
  the FK cascade on `certificate_ownership_overrides → certificates
  ON DELETE CASCADE` already removed the override row, so the listing
  read couldn't have returned it; defensive coverage.)
- **Audit write fails** → whole page transaction rolls back; no clears
  observable, no audit rows committed.
- **Lock contention with in-flight recompute** → the sweep page waits
  for `WithTxLockedOwnership`; a future `?nowait` variant could
  surface 409 (mirroring B3A recompute-trigger), but not in this
  phase.
- **Invalid actor / org input** → fail-closed at the call boundary
  before the lock is acquired.
- **Pagination cursor drift** → server-minted hex ids guarantee byte
  == collation order (H-030); a row inserted for an already-passed
  cert is picked up on the next pass (eventually consistent, never
  lost-while-current).

## 15. Abuse cases

- **Operator races a sweep with a manual `ClearOverride` to deny the
  sweep its audit.** The advisory lock serializes both calls per org,
  so the race only exists in the listing → clear window of a single
  page. The `ErrOwnershipOverrideNotFound` no-op handles it
  gracefully: either the operator wins (manual clear audited as
  `ownership.override_cleared`) or the sweep wins
  (`ownership.override_expired`). Exactly one audit row either way —
  no double-audit, no orphan.
- **Operator inserts a flood of overrides with `expires_at = now()`
  to amplify sweep cost.** Bounded per-page work caps the cost per
  call. A future scheduler is responsible for backoff if it observes
  per-pass cleared counts at the page limit.
- **Sweep-triggered DoS** (if a manual trigger is exposed later):
  same posture as the recompute trigger — operator-only,
  advisory-lock-serialized, idempotent.

## 16. Migration requirements

- **No destructive migration.** The paged read uses an existing
  partial index. The sweep mutates only via existing methods.
- **At most one additive migration** — a partial index on
  `(organization_id, expires_at) WHERE cleared_at IS NULL AND
  expires_at IS NOT NULL` **only if** EXPLAIN on real workloads
  shows the existing partial-unique-active index is insufficient.
  Decide at PR-1 review; do not add speculatively.
- No schema change to `certificate_ownership_overrides`,
  `certificate_ownership`, or `ownership_match_explanations`.

## 17. Proposed PR split

- **H-029-PR1 — repository: paged listing + remove dead unpaged
  method.** Adds `ListExpiringOverridesPaged` + EXPLAIN const + repo
  test. Removes `ListOverridesExpiringBy` (or retains it as a thin
  wrapper, per review). ~small.
- **H-029-PR2 — service: bounded sweep primitive.** Adds
  `SweepExpiringOverridesPage` (one page, locked, re-derive +
  per-override audit per cleared row). Wired to **no caller**.
- **H-029-PR2-hardening — adversarial pass.** Race windows,
  audit-rollback, cross-org, cursor determinism after clears,
  pageSize bounds, EXPLAIN.
- **(Optional) H-029-PR3 — manual operator trigger.** Only on review
  decision.
- **Scheduler wiring is NOT an H-029 PR** — B4 phase.

## 18. Explicit out-of-scope items

- **Scheduler / background job** that invokes the sweep (B4 / sibling
  phase).
- **Manual HTTP endpoint** (e.g. `POST /api/v1/ownership/overrides/sweep`)
  — deferred to optional PR-3 or B4.
- **Soon-to-expire notifications** ("these will drop in 24h") — a
  separate notification surface, not an H-029 concern.
- **Hard delete of long-cleared overrides** — pure history retention,
  out of scope; if v0.x ever wants it, a separate H-029-style
  retention design applies (deletion target would be cleared rows,
  not active expired ones).
- **Audit retention or rollup of `ownership.override_expired`** —
  per-override cardinality is low by design; rollup is unnecessary
  and would obscure operator signal.
- **UI / dashboards** for expiring overrides.
- **Policy / findings integration** of expired overrides.
- **Per-org configurable sweep limit** (page size is deployment-global
  in v0.x).
- **`?nowait` variant** of the sweep (analogous to B3A
  recompute-trigger). Defer.
- **B4 ownership scheduler** wiring — that phase is separate and may
  choose to compose H-029 sweep calls into its loop, but H-029 itself
  exposes only the primitive.

## 19. Stability / readiness note

The safety surface H-029 sweeps depends on is **already merged and
hardened**: B3A's `ClearOwnershipOverride` is idempotent and
race-safe, B3B's `rederiveCertificate` is bounded and fail-closed
on missing signals, and `audit_events` is independently permanent.
The partial-unique active-override index already enforces "at most
one active override per cert" — a sweep that clears one cannot leak
duplicates. Combined with the per-org advisory lock serializing
sweep / recompute / mutation, the H-029 primitive is a low-blast-
radius composition of existing safety floors: it adds no new
correctness invariant, only a bounded read shape and a paged caller
contract for the existing per-cert clear + re-derive + audit cycle.
Recommend proceeding to H-029-PR1 after this design is reviewed.
