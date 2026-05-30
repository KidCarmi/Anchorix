# H-030 — Collation-Independent Merge Ordering: Phase Closure

> **Status:** closed / **stable**. Source of truth for rules:
> [`CLAUDE.md`](../../CLAUDE.md). Design proposal:
> [`H-030-collation-independent-merge-ordering-design.md`](./H-030-collation-independent-merge-ordering-design.md).
> Touches the ownership engine (H-026B1→B3B) — see
> [`H-026B3B-closure-summary.md`](./H-026B3B-closure-summary.md). Sibling
> phase closures:
> [`H-027-closure-summary.md`](./H-027-closure-summary.md),
> [`H-029-closure-summary.md`](./H-029-closure-summary.md).

## 0. Merged PRs

| PR | Title | Class |
|----|-------|-------|
| #72 | H-030 collation-independent merge ordering design | docs |
| #73 | H-030 PR-1 collation-independent recompute merge refactor | feature (internal) |
| #74 | H-030 PR-1 hardening pass | test-only + static guard |

H-030 removes a load-bearing-but-fragile cross-language ordering
invariant from the H-026B2 ownership recompute. The previous merge
required Go byte order to agree with PostgreSQL collation order on
`certificate_id` — sound today (server-minted hex ids) but silently
breakable by any future change to id semantics. The refactor replaces
the two-stream merge with a bounded per-page set lookup that has no
ordering coupling at all. **No external behavior change**; no
migration; no API change; no schema change.

## 1. What H-030 delivered

- **Design proposal** (#72): identified `streamAndDecide` as the
  **only** load-bearing risk site in the codebase; documented why
  every other paged read is collation-safe by SQL construction;
  recommended Option (a) bounded set-lookup over Option (b) explicit
  `COLLATE "C"` (which would have meant index churn + perf regression
  while preserving the cross-language coupling).
- **Refactor** (#73): replaced the recompute's two-stream merge with
  a per-signal-page set lookup keyed on `cert_id = ANY($2::text[])`.
  Added `GetCertificateOwnershipByCertificateIDs` to
  `governance.OwnershipRepository`. Removed the
  `ownPager` and the `ownCur.CertificateID < sig.CertificateID`
  comparator. Updated the godoc on `streamAndDecide` to describe the
  new shape and explain what was replaced.
- **Hardening** (#74): static guard on the `streamAndDecide` function
  body asserting the legacy merge tokens are absent and the new
  tokens are present; instrumented integration tests proving the
  lookup batch is bounded by signal page size; orphan-not-queried
  proof; explicit collation-hazard fixture (mixed-case + hyphens —
  the classic Go-byte-vs-glibc divergence shape); absent-prior
  first-run pin.

## 2. The original collation risk

The H-026B2 recompute's inner loop (`streamAndDecide` in
`backend/internal/governance/ownership/recompute.go`) used to merge
**two** paginated streams — `ListCertificateSignalsPaged` and
`ListCertificateOwnershipPaged` — both `ORDER BY certificate_id ASC`,
and pair each signal with its prior ownership using a Go string
comparison:

```go
for ownHas && ownCur.CertificateID < sig.CertificateID {
    // advance prior-ownership cursor past orphans
}
```

Correctness depended on Go byte order agreeing with the PostgreSQL
collation used by SQL `ORDER BY` and the cursor `id > $N`. That
agreement held because `certificate_id` is always server-minted by
`ids.New()` — a 32-character lowercase hex string `[0-9a-f]{32}` — for
which byte order equals collation order under any PostgreSQL collation
(`C`, `en_US.UTF-8`, ICU, …).

The invariant was:

- **Cross-language**: Go runtime + PostgreSQL collation had to agree.
- **Silent**: a divergence would cause the merge to skip a cert's
  prior ownership and write a wrong decision, with no error or test
  failure unless the specific divergence shape happened to be
  exercised.
- **Action-at-a-distance**: `streamAndDecide`'s correctness depended
  on a property of `ids.New()` documented two files away.

H-030 removes the invariant from the codebase entirely — no future
change to certificate-id semantics can silently break recompute
correctness.

## 3. Why streamAndDecide was the only load-bearing risk site

`grep -n "ORDER BY certificate_id ASC"` in the governance ownership
repository returns 8+ matches. Every one of them — except
`ListCertificateOwnershipPaged` in the recompute's merge — passes the
cursor to SQL as a parameter:

```sql
WHERE organization_id = $1
  AND certificate_id > $2     -- cursor as SQL parameter
ORDER BY certificate_id ASC
LIMIT $3
```

These reads' comparison (`certificate_id > $2`) and `ORDER BY` both
run **under PostgreSQL's collation, inside one query**. Go code never
compares two cert ids across streams. The collation is internally
consistent within each query, and the cursor is opaque to Go. They
were not at risk and remain unchanged.

Only `streamAndDecide` did a cross-stream Go-side merge. That is the
exact scope of H-030's change.

## 4. New architecture: signal-page + bounded set-lookup

`streamAndDecide` now drives the recompute by signal pagination
alone. For each signal page:

1. Collect the page's `certificate_id`s.
2. Bulk-load prior ownership via
   `GetCertificateOwnershipByCertificateIDs(org, certIDs)` — one
   bounded round-trip returning `map[cert_id] → CertificateOwnership`.
3. Iterate the signal page in page order; for each signal, look up
   `prior` by direct map access.
4. Move the cursor to the page's last cert_id and continue.

What this removes:

- The second pager (`ownPager` / `pager[governance.CertificateOwnership]`).
- The `ownCur.CertificateID < sig.CertificateID` Go-side comparator.
- The skip-loop for orphan ownership rows (no longer needed —
  orphans are simply never queried).
- The cross-language ordering invariant. The only string comparison
  left is PostgreSQL's `= ANY($2::text[])`, which is internally
  consistent under any collation; Go does `map[cert_id]` lookups on
  opaque keys.

What this preserves:

- Streaming: one signal page + its prior-ownership map in memory at
  a time. Never the fleet.
- Per-cert determinism: each cert's decision depends on its own
  signals + prior ownership + override; iteration order does not
  affect the decision.
- Audit-row contract: per-cert transition rows and
  `governance.recomputed` rollup metadata remain byte-identical.
- `ListCertificateOwnershipPaged` stays on the repository — it
  serves the H-026B3A operator-facing read endpoint and was not
  removed.

## 5. Repository primitive added

`governance.OwnershipRepository.GetCertificateOwnershipByCertificateIDs(ctx, org, certIDs) → map[cert_id]CertificateOwnership`.

Properties:

- **Empty / nil input**: returns an empty map with **no DB
  round-trip**.
- **Oversize input**: `len(certIDs) > MaxOwnershipByIDsBatchSize`
  (1000) returns an error — fail-closed defense in depth. The
  recompute caller is bounded by `pageSize` (≤ 500 default), so this
  is a guard against caller bugs, not a reachable production path.
- **Cross-org isolation**: `WHERE organization_id = $1` is binding.
  Foreign-org cert ids do not match (composite PK probe).
- **Duplicate input ids**: safe — the SQL `ANY` filter de-duplicates
  and the result map collapses by key.
- **Missing ids**: silently absent from the result map. The caller
  treats them as "first-run for that cert", preserving the
  pre-refactor `prior == nil` semantic.
- **Plan shape**: `Index Scan` (with heap fetches for non-key
  columns) or `Bitmap Index Scan + Bitmap Heap Scan` via the existing
  `certificate_ownership` PK `(organization_id, certificate_id)`.
  **Not** an `Index Only Scan` — the projected columns
  (decision / service_id / explanation_id / …) exceed the PK,
  intentionally; no covering index is added (design §8).
- **No new index**, **no migration**.

The exported `postgres.GetCertificateOwnershipByCertificateIDsQuery`
SQL const lets the hardening EXPLAIN test pin the structural index
path (with `SET LOCAL enable_seqscan = off` to demonstrate the index
path is **available** even when the planner correctly chooses Seq
Scan on tiny test fixtures).

## 6. Transaction / streaming / boundedness guarantees

- **No transactional change**: the recompute still runs under
  `WithTxLockedOwnershipRepeatableRead(org)`. The set lookup
  inherits the same snapshot, so prior ownership reads are consistent
  with the signal page they came with. The advisory-lock contract is
  unchanged.
- **Streaming preserved**: one signal page + its prior-ownership map
  in memory at any moment. The recompute walks the signal stream
  once, never the fleet.
- **Bounded per-page**: the lookup batch is exactly the signal
  page's cert_ids — at most `pageSize` (default 500, cap 1000 if a
  future caller raises pageSize). Pinned concretely by the
  hardening's instrumented `countingOwnershipRepo`:
  - `fleet=10, pageSize=3` → exactly 4 lookup calls, batches `[3, 3,
    3, 1]`, total certs = 10 (each visited exactly once).
  - `fleet=3, pageSize=500` → exactly 1 lookup call with batch=3.
    Rules out a regression that might accumulate batches across
    pages.
- **No fleet-wide scan reachable**: every read is `LIMIT`-bound
  (signal page) or `ANY($2)`-bound (ownership lookup);
  EXPLAIN-pinned.
- **No new round-trip count**: pre-refactor the recompute paged BOTH
  signals and prior ownership independently — one round-trip per
  page per stream. Post-refactor it pages signals and bulk-loads
  prior per page — one round-trip per page for each. Net round-trip
  count is unchanged for a fleet with prior ownership; one extra
  round-trip per perfectly-divisible fleet (same as before).

## 7. Cross-org isolation guarantees

- The new primitive's `WHERE organization_id = $1` is mandatory and
  pinned by the cross-org isolation test (both directions: anchorix
  cannot see other-org's rows, other-org cannot see anchorix's).
- No call path in `streamAndDecide` constructs a SQL statement
  without binding `organization_id`. The repository method is the
  only ownership lookup the recompute uses, and the method takes
  `organizationID` as an explicit parameter.
- The collation-independence property does not weaken cross-org
  isolation in any way — it strengthens nothing org-related either;
  the org filter has always been a SQL-side equality predicate that
  was never collation-dependent.

## 8. First-run semantics preservation

`firstRun` semantically means "this org has no prior ownership
decisions to compare against".

- **Pre-refactor**: `out.firstRun = false` was set whenever the
  ownership stream produced ANY row — either via the skip-loop or
  via the exact-match path.
- **Post-refactor**: `out.firstRun = false` is set whenever the
  per-page lookup returns a non-empty map for the page's cert_ids.

Equivalence: if any signal cert has a matching prior ownership, the
map will contain that prior, so the flag flips. The only edge case
where the two paths diverge is **"signals empty, prior ownership
present"** — which is structurally impossible (orphan ownership rows
without matching certs are the only way to get there, and the
pre-refactor signal loop would never have fired the skip-loop either
since it's nested inside the signal loop). Both paths produce
`firstRun = true` for that edge case. Behavior is preserved.

The single-cert-becomes-first-run path is pinned by the hardening
test `AbsentPriorTreatedAsFirstRunForThatCert`: 3 certs classified in
pass 1, a 4th seeded between passes, pass 2 reports `evaluated=4`,
`becameOwned=1`, `unchanged=3`.

## 9. Orphan ownership behavior

An "orphan" ownership row is a `certificate_ownership` row whose
parent `certificates` row has been deleted. The FK has `ON DELETE
CASCADE`, so the only way to produce one in production is
catastrophic state corruption or a CASCADE bypass. The existing
integration test (`TestOwnershipMergeSkipLoopHandlesOrphanOwnershipRows`)
uses `SET LOCAL session_replication_role = 'replica'` to bypass the
cascade and inject orphans for test purposes.

- **Pre-refactor**: orphans were visited by the merge's skip-loop
  and silently advanced past (the "defensive — every ownership row
  has a matching cert, so this normally does not fire" branch).
- **Post-refactor**: orphans are **never queried**. The lookup is
  keyed on signal-page cert_ids; an orphan's cert_id by definition
  is not in any signal page. Orphans linger in the
  `certificate_ownership` table until something cleans them up
  (currently nothing does — they're invalid state and the
  pre-refactor was equally non-cleaning).

This is a **strengthening** of the contract: not just "orphans
don't perturb a live signal's decision" (already true pre-refactor)
but "orphans are not even part of the recompute's working set"
(pinned by the hardening test
`OrphanOwnershipNotQueriedUnderNewMechanism`, which uses the
counting wrapper repo to assert the orphan cert_id never appears in
any batch).

## 10. Deterministic recompute guarantees

- Per-cert decisions remain deterministic: each cert's decision is a
  pure function of its signals + prior ownership + active override
  + compiled rules + now. The iteration order has never affected
  per-cert decisions.
- Persistent state determinism: repeated recomputes over a stable
  input produce identical `certificate_ownership` row counts,
  identical service assignments, and the same explanation count
  (stable input → no flips → no new explanations). Pinned by
  `TestRecomputeDeterministicAcrossRepeatedRuns`: 3 successive
  recomputes over a 10-cert fixture leave the persisted state
  unchanged.
- Audit-row determinism: pre-refactor and post-refactor produce
  byte-identical audit row sets for any fixture (the audit shape is
  governed by `processCert`, which is unchanged). The existing
  recompute integration tests (incl. `TestOwnershipRecomputeFirstRunUnownedIsQuiet`,
  `TestOwnershipMergeHandlesNewCertInterleavedAmongOwned`,
  `TestOwnershipMergeSkipLoopHandlesOrphanOwnershipRows`) **all pass
  unchanged** through the refactor, which is the strongest
  preservation evidence available.

## 11. Test / hardening coverage

**PR-1 tests (#73, 10 new):**

- `ownership_get_ownership_by_ids_test.go` (8 tests): empty/nil
  no-op, happy-path map keying, duplicate collapse, cross-org
  isolation (both directions), oversize fail-closed,
  order-independence, EXPLAIN PK path (with `enable_seqscan = off`
  to demonstrate the structural index path; no `Index Only Scan`),
  interface-satisfaction compile-time guard.
- `ownership_collation_independence_test.go` (2 tests): UUIDv7-style
  hyphenated/mixed-case cert_ids end-to-end recompute (two-pass);
  determinism across 3 repeated recomputes.

**PR-1 hardening (#74, 5 new + 1 static guard):**

- Static unit guard (`streamanddecide_static_test.go`): reads
  `recompute.go` via `runtime.Caller(0)`, extracts `streamAndDecide`'s
  executable body via brace matching, asserts forbidden
  legacy-merge tokens are **absent** (`ownCur.CertificateID`,
  `ownPager`, `pager[governance.CertificateOwnership]`,
  `ListCertificateOwnershipPaged`) and the new H-030 tokens are
  **present** (`GetCertificateOwnershipByCertificateIDs`,
  `ListCertificateSignalsPaged`). Function-body scoping is
  intentional: the godoc above streamAndDecide intentionally
  references the legacy comparator to explain what was replaced.
- `LookupBatchSizeBoundedByPageSize`: counting wrapper proves
  fleet=10/pageSize=3 → 4 calls × batches `[3,3,3,1]`.
- `NoFleetWideLookupInOneBatch`: counting wrapper proves
  fleet=3/pageSize=500 → exactly 1 call with batch=3.
- `WithCaseSensitiveCollationHazardIDs`: mixed-case + hyphenated
  cert_ids deliberately chosen so Go byte order and glibc
  `en_US.UTF-8` collation **diverge**. Two passes (all owned, then
  all unchanged); every prior must be found regardless of
  byte/collation order.
- `OrphanOwnershipNotQueriedUnderNewMechanism`: extends the legacy
  orphan test with the counting wrapper; pins the structural
  property "the orphan cert id never appears in any lookup batch".
- `AbsentPriorTreatedAsFirstRunForThatCert`: 3 prior certs + 1 new
  between passes → `becameOwned=1`, `unchanged=3`.

All verified against PostgreSQL 16 with the full ownership +
overrides + expiring + sweep + recompute integration suite green.

## 12. Explicitly out of scope for H-030

- **Scheduler / background recompute loop** that drives the
  recompute on a cadence (sibling phase B4).
- **Manual operator endpoint** for the recompute — the existing
  B3A operator-triggered recompute is unchanged; H-030 added no new
  trigger.
- **Preview / Apply** ("what would this rule/override change?") —
  separate phase B3C.
- **Findings / policy integration** of recompute output — H-026D.
- **Changing any other paged read's ordering.** Single-stream paged
  reads remain `ORDER BY certificate_id ASC` under default
  collation; they were never at risk.
- **`COLLATE "C"` indexes anywhere.** Rejected in design §7 (index
  churn, perf regression, preserves the coupling rather than
  removing it).
- **Allowing operator-supplied cert ids.** Out of scope — H-030
  makes such a future feature **safe to add**, since no merge
  correctness coupling remains.
- **Changing `ids.New()` shape.** The refactor is forward-compatible
  with any future id format.
- **Migration / schema change.** None.
- **UI / dashboards.**
- **Audit shape changes.** Per-cert transition audits and the
  `governance.recomputed` rollup are byte-identical to the
  pre-refactor.

## 13. Remaining backlog / next-phase candidates

Sequenced; do **not** start without an explicit decision:

- **H-026D — Findings & policy integration**. The next logical
  engine consumer; independent of H-030 but unblocked by it.
- **B3C — Preview / Apply**. Dry-run diff of a proposed rule /
  override against current ownership before commit.
- **B4 — Ownership scheduler**. Dark-by-default background recompute
  loop; may also compose H-027 retention prune and H-029 expiring
  override sweep into its cadence.
- **Optional H-030 follow-up** — broader invariant cleanup: audit
  the rest of the codebase for any other cross-language ordering
  coupling. Likely none, but worth a focused pass after PR-1 + PR-1
  hardening have soaked in production.

Pre-existing governance backlog (unchanged by H-030):

- **H-027 closure** documented in `H-027-closure-summary.md` —
  dormant.
- **H-029 closure** documented in `H-029-closure-summary.md` —
  dormant.

## 14. Stability verdict

**H-030 is stable.** The recompute's correctness contract — already
stable today because the H-026B invariant held for all production
ids — is now **architecturally stable** as well: the cross-language
ordering coupling that made the contract fragile has been removed
from the codebase. A future change to certificate-id semantics
(non-hex, UUIDv7-text, operator-supplied) cannot silently break
correctness. The hardening's static guard makes "no legacy merge
shape" machine-verifiable for `streamAndDecide`'s executable body,
caught in CI's `go test ./...` phase long before any integration
test would surface a fixture-specific regression.

The refactor introduces no new index, no migration, no API change,
no scheduler, no caller change. All pre-existing recompute
integration tests pass unchanged through the refactor — the
strongest preservation evidence available. The ownership engine
(H-026B1→B3B), the retention surface (H-027), the override-sweep
surface (H-029), and the now collation-independent recompute (H-030)
together provide the **read + decide + bounded-history +
bounded-clear + ordering-robust** floor on which the operational
layers (manual trigger, B4 scheduler, H-026D findings/policy, B3C
preview) can build.
