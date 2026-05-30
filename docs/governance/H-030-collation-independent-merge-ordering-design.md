# H-030 — Collation-Independent Merge Ordering: Design Proposal

> **Status:** design / proposal only. **No code in this PR.** Source of
> truth for rules: [`CLAUDE.md`](../../CLAUDE.md). H-030 backlog entry:
> [`HARDENING_BACKLOG.md`](../engineering/HARDENING_BACKLOG.md) §H-030.
> Touches the ownership engine (H-026B1→B3B) — see
> [`H-026B3B-closure-summary.md`](./H-026B3B-closure-summary.md).
>
> This proposal designs **how** to remove a load-bearing-but-fragile
> cross-language ordering invariant from the recompute, before a future
> change to certificate-id semantics breaks it silently. Implement only
> after review.

## 1. Problem statement

The H-026B2 ownership recompute's inner loop (`streamAndDecide` in
`backend/internal/governance/ownership/recompute.go`) merges TWO
paginated streams — `ListCertificateSignalsPaged` and
`ListCertificateOwnershipPaged` — both `ORDER BY certificate_id ASC`,
and pairs each signal with its prior ownership using a **Go string
comparison**:

```go
for ownHas && ownCur.CertificateID < sig.CertificateID {
    // advance prior-ownership cursor
}
```

Correctness depends on Go byte order agreeing with the PostgreSQL
collation used by the SQL `ORDER BY` and the cursor `id > $N`
predicate. This agreement holds today because every `certificate_id`
is server-minted by `ids.New()` — `crypto/rand(16)` + `hex.EncodeToString`
yielding a fixed-length lowercase hex string `[0-9a-f]{32}`. For that
character set, byte order equals collation order under any PostgreSQL
collation (`C`, `en_US.UTF-8`, …). Cert ids are never operator-
supplied: the inventory pipeline's `UpsertCertificate` mints the id
when the caller passes an empty string, and the ingest path
(`certificateForIngestion`) deliberately leaves it empty.

The invariant is fragile, however:

- it is **cross-language** (Go runtime + PostgreSQL collation must
  agree),
- it is **silent** — a divergence would cause the merge to skip a
  cert's prior ownership and write a wrong decision, with no error or
  test failure unless the specific divergence shape was exercised,
- it is **action-at-a-distance** — `streamAndDecide`'s correctness
  depends on a property of `ids.New()` documented two files away.

H-030 designs a structural fix that removes the invariant from the
codebase entirely, so a future change to certificate-id semantics
cannot silently break correctness.

## 2. Current ordering assumptions

The invariant — documented inline on `streamAndDecide` (lines 211–220
of `recompute.go`) — is:

> Ordering invariant: the merge advances the ownership cursor using a
> Go string comparison (`ownCur.CertificateID < sig.CertificateID`),
> which must agree with the SQL `ORDER BY certificate_id` of both
> streams. It does, because every `certificate_id` is server-minted by
> `ids.New()` — a fixed-length lowercase-hex string `[0-9a-f]{32}` —
> for which byte order equals collation order under any PostgreSQL
> collation (C, en_US.UTF-8, …). Cert ids are never operator-supplied,
> so a punctuation/case/length collation surprise cannot occur. If
> that ever changes (non-hex cert ids), this merge must switch to a
> collation-independent pairing (see HARDENING_BACKLOG H-030).

The invariant is asserted on the merge behavior by
`TestOwnershipMergeHandlesNewCertInterleavedAmongOwned`, which
exercises the cursor-advance loop on a fixture where a signal cert
has no prior ownership and lies between two certs that do.

## 3. Where merge ordering matters (scope)

There is exactly **one** place in the codebase where Go-side ordering
of cert ids is load-bearing for correctness: `streamAndDecide` in
`recompute.go`. Every other paged query in `OwnershipRepository`
(visible via `grep -n "ORDER BY certificate_id ASC"` in
`backend/internal/storage/postgres/governance_ownership_repository.go`
— 8+ matches) follows the pattern:

```sql
WHERE organization_id = $1
  AND certificate_id > $2     -- cursor as SQL parameter
ORDER BY certificate_id ASC
LIMIT $3
```

These reads pass the cursor to SQL as a parameter; the comparison
`certificate_id > $2` and the `ORDER BY` both run under PostgreSQL's
collation, **inside one query**. Go code never compares two cert ids
across streams. **These are not at risk**, regardless of cert-id
character set, because the collation is internally consistent within
each query and the cursor is opaque to Go.

The narrow scope:

- **In scope**: `streamAndDecide`'s two-stream merge of
  `ListCertificateSignalsPaged` × `ListCertificateOwnershipPaged`.
- **Out of scope**: all single-stream paged reads (signal page, sweep
  page, prune page, ownership-by-decision page, override pages,
  explanation timeline page). These already are collation-safe.

## 4. Are ids truly server-minted hex everywhere relevant?

**Production cert ids**: yes.

- `internal/storage/postgres/certificate_inventory_repository.go`
  `UpsertCertificate` calls `ids.New()` when the caller hands in an
  empty `c.ID`.
- `internal/inventory/service.go` `certificateForIngestion` (the only
  ingest-path caller) deliberately constructs the `Certificate` with
  `ID: ""`, so the repository always mints. The ingest service is the
  only path from the agent wire shape into the certificates table.
- `ON CONFLICT (organization_id, fingerprint_sha256) DO UPDATE` keeps
  the existing row's id on re-ingestion — so even an agent-supplied
  duplicate cannot leak a new id.
- Fixtures (`internal/inventory/fixtures/`) also use `ids.New()` for
  the canonical happy path; integration tests sometimes seed
  deterministic ids like `'cert-foo-01'` for readability (the H-027
  prune, H-029 sweep tests do this, as does the existing recompute
  test).

**Test cert ids in the merge path**: probably *also* sort identically
under Go byte order and `en_US.UTF-8` because the ids are pure
lowercase ASCII alphanumeric with hyphens, and length is constant
within a fixture. But this is no longer a *guarantee* — it depends on
glibc's `en_US.UTF-8` behavior for hyphens, which is not byte-order in
general. The test ids happen to sort the same way today; a future
fixture that mixes string lengths (`'cert-a'` vs `'cert-abc-01'`)
could surface a divergence even in tests.

**Other merge keys** (none currently): if a future feature introduces
a second cross-stream Go-side merge keyed on operator-supplied text
(e.g. service slug, tag key, agent hostname), it would be a fresh
collation hazard. The fix proposed below makes the recompute resistant
to such additions by removing the merge pattern, not by adding
case-by-case guards.

## 5. Risks from DB collation differences

Even with hex cert ids today, the invariant is fragile to the
following plausible-future changes:

1. **Non-hex cert ids.** If a future change ever shifts cert id
   generation to `UUIDv7` text (`8-4-4-4-12` hyphenated), or to URL-
   safe base64, or accepts an operator-supplied id, the invariant
   breaks. UUIDv7's hyphens land at fixed positions; under
   `en_US.UTF-8` they are mostly ignored for ordering compared to
   alphanumeric, so byte order ≠ collation order in general for
   mixed character sets.
2. **A new cross-stream merge.** Any future engine that merges two
   paginated streams keyed on text — e.g. an explanation timeline
   merged with an audit timeline — inherits the same fragility unless
   the design explicitly avoids it.
3. **A database-side collation change.** Operators upgrading glibc /
   ICU could see existing indexes' physical order diverge from a new
   text-comparison result without any SQL change. PostgreSQL emits a
   warning but does not force a re-index. In a multi-language
   `en_US.UTF-8` deployment, this is a known operational hazard.
4. **Per-column / per-index collation overrides.** A future migration
   that adds `COLLATE "C"` on one index but not the other could put
   the two streams' cursors out of agreement even *within* PostgreSQL.

None of these is reachable today. The H-030 fix removes the risk class
entirely instead of mitigating individual instances.

## 6. Recommended strategy: per-page bounded set lookup

**Replace the two-stream merge with a bounded per-page set lookup.**

The recompute already pages signals (its outer loop). For each
signal-page, fetch the prior ownership rows for *exactly the cert ids
in that page* via a single bounded set lookup:

```sql
SELECT … FROM certificate_ownership
 WHERE organization_id = $1
   AND certificate_id = ANY($2::text[])
```

The repo returns a map (or a slice the service folds into a map)
keyed on `cert_id`. The service iterates the signal page; for each
signal, it looks up `prior` by direct map access. The
`ListCertificateOwnershipPaged` call disappears from the recompute,
and so does the `ownCur.CertificateID < sig.CertificateID` comparison.

**Properties of this approach:**

- **No cross-language ordering invariant remains.** PostgreSQL handles
  all string equality (`ANY($2)`); Go does map lookups on `cert_id`
  as an opaque key. Future cert id changes cannot break correctness.
- **Bounded.** The lookup operates on at most `pageSize` (500 default)
  cert ids per outer-page iteration. Memory and per-iteration latency
  are unchanged in shape.
- **Index-aligned.** The primary key on `certificate_ownership` is
  `(organization_id, certificate_id)`. A `WHERE organization_id = $1
  AND certificate_id = ANY($2)` predicate hits the PK directly — no
  new index, no fleet-wide scan, EXPLAIN-pinnable.
- **Per-cert determinism.** Ownership decisions are per-cert: each
  cert's signals + prior ownership + override → one decision. The
  *order* the recompute visits certs does not affect the decision a
  cert receives. So the iteration is still deterministic per-cert,
  even if the prior-ownership lookup returns rows in undefined order
  (we fold into a map; order doesn't matter).
- **Removes one full paginated read** (`ListCertificateOwnershipPaged`
  was paged the same way as signals — double the round-trip count).
  The set lookup adds one round-trip per outer page; the prior
  per-page round-trip for ownership is gone. Net: same round-trip
  count, simpler control flow.
- **Concurrency unchanged.** Both reads happen inside the same
  `WithTxLockedOwnershipRepeatableRead` snapshot; the set lookup
  inherits the snapshot. The advisory-lock contract is unchanged.

**Streaming property preserved.** The recompute's outer page-by-page
loop over signals remains. We're not loading the fleet; one page's
worth of signals + that page's prior-ownership rows is the working
set at any moment.

## 7. Why not Option (b): explicit `COLLATE "C"`

The backlog entry's alternative — `ORDER BY certificate_id COLLATE
"C"` on both streams + matching `COLLATE "C"` indexes — preserves the
two-stream merge but pins SQL ordering to byte order. Rejected
because:

- **Index churn**: a `COLLATE "C"` `ORDER BY` does not use a default-
  collation index efficiently; you must add a parallel `COLLATE "C"`
  index for both reads. Two new indexes; doubled write cost on
  `certificate_ownership` and `certificates`.
- **Perf regression risk**: sorting a fleet of 50k–500k certs with
  `COLLATE "C"` on a non-`COLLATE "C"` index is a full sort, not a
  paginated index scan. On a large fleet this turns a paginated
  100-row read into a full-fleet sort.
- **Preserves the invariant** rather than removing it. The cross-
  language coupling is still in the code; a future operator who adds
  a new index without the `COLLATE "C"` clause re-introduces the
  risk silently.
- **Larger migration surface**: at least one append-only migration
  per index. Set-lookup is a Go-side refactor with no schema change.

Option (b) is the right choice only if a future requirement makes the
two-stream merge structurally necessary (e.g. streaming reconciliation
across two terabyte-scale tables where memory cannot hold one page's
worth of ids). That is not the H-026B recompute's workload.

## 8. Index impact

**None.** The proposed set lookup is index-aligned with the existing
`certificate_ownership` PK:

```
PRIMARY KEY (organization_id, certificate_id)   -- migration 0010
```

A `WHERE organization_id = $1 AND certificate_id = ANY($2)` query plan
is an index-only scan on the PK with one index lookup per element of
`$2`. EXPLAIN should show `Index Scan` (or `Bitmap Index Scan` for
larger batches), bounded by the array size, with no `Group Key` and
no `Seq Scan`. The H-030 PR-1 implementation MUST pin this with an
EXPLAIN test on a small fixture, aligned with the existing H-027 /
H-029 EXPLAIN convention.

## 9. Migration impact

**None.** The fix is a Go-side refactor of `streamAndDecide` plus the
addition of one repository read method:

```go
// GetCertificateOwnershipByIDs returns the prior-ownership rows for
// the requested cert ids in one org, as a map keyed on cert_id.
// Bounded by len(certIDs); the caller (the recompute) caps that at
// one signal-page worth (pageSize, default 500).
GetCertificateOwnershipByIDs(
    ctx context.Context,
    organizationID string,
    certIDs []string,
) (map[string]governance.CertificateOwnership, error)
```

The existing `ListCertificateOwnershipPaged` stays (it is consumed by
the operator-facing read endpoint H-026B3A, not just by the
recompute). No removal required; no migration; no schema change.

## 10. Tests required (for the implementation PR, not this one)

- **Unit test on the new repository primitive**: empty `certIDs`
  returns an empty map without error and without a DB round-trip;
  oversized batch (e.g. > `pageSize`) is rejected (fail closed —
  callers must cap).
- **Behavior equivalence test on the recompute**: against a fixture
  that the existing `TestOwnershipMergeHandlesNewCertInterleavedAmongOwned`
  exercises, the post-refactor recompute produces byte-identical
  `certificate_ownership` and `ownership_match_explanations` row sets
  + identical audit rows + identical `governance.recomputed` rollup
  metadata to the pre-refactor version. (The merge invariant test
  itself can stay as a regression guard against the old shape, or be
  rewritten to assert correctness via the set-lookup path — decide at
  implementation; prefer keeping a renamed equivalent so the
  interleaved-new-cert path still has explicit coverage.)
- **Cross-org isolation**: the set lookup MUST bind `organization_id`;
  a malformed call with a foreign-org cert id in the batch returns
  zero rows for that id (not the foreign row). Pinned by a focused
  test.
- **Bounded read**: an EXPLAIN test on the set-lookup query proves
  the plan uses the PK index and is bounded by the array size — no
  `Seq Scan`, no fleet-wide `Group Key`.
- **Collation-independence**: a small fixture with non-hex test ids
  (e.g. mixed-case + hyphens) that would have been a hazard under
  the old merge — assert recompute produces the correct decision for
  every cert. This is the regression guard for the invariant being
  *gone*.
- **Determinism**: same DB state, same recompute → same audit row set
  (by row id) across two runs.
- **Performance smoke**: a 1000-cert fixture's recompute pages
  identically before and after the refactor (same number of round
  trips, same shape of working memory). This is a sanity check, not a
  binding benchmark.
- **Removal of the invariant comment**: the inline documentation on
  `streamAndDecide` referencing `ids.New()` / `[0-9a-f]{32}` is
  updated to describe the new shape, and the H-030 cross-reference in
  the comment is closed out.

## 11. EXPLAIN requirements

Pin the new set-lookup query plan in an integration test (aligned
with H-027's `TestPrunableExplanationIDsQueryBounded` /
H-029's `TestListExpiringOverridesPagedExplainBounded`):

- `Limit` is irrelevant here (the query is bounded by `ANY($2)`
  array size, not by `LIMIT`).
- The plan MUST use the `certificate_ownership` PK index. Assert
  `Index Scan` or `Bitmap Index Scan` is present; assert `Seq Scan`
  on `certificate_ownership` is NOT present.
- No fleet-wide `Group Key` (the query is per-id; no grouping).
- The `organization_id = $1` predicate appears in the index condition
  (not as a post-scan filter).

## 12. Failure modes

- **Repository call fails** → the recompute returns the wrapped error;
  the locked transaction rolls back; no partial state observable.
  Mirrors the existing recompute error paths.
- **A signal-page cert is unexpectedly absent from the
  prior-ownership map** → behavior matches today's "no prior row"
  branch in the merge: this is a **first-run** signal, `prior = nil`,
  `processCert` treats it as a fresh classification, no transition
  audit is emitted (the existing first-run quiet contract). The fix
  preserves this semantic.
- **The signal page contains duplicate cert ids** (it should not — the
  paged read is over `certificates`, which is keyed by org+cert_id) →
  the map collapses them; only one ownership decision per cert. The
  set-lookup naturally deduplicates.
- **An oversized batch is passed to the new primitive** (caller bug)
  → reject before the round-trip; the recompute caps the batch at
  one signal-page's worth (`pageSize`, ≤ 500 in production), so this
  is a defensive guard, not a reachable production path.
- **A cert is deleted between the signal-page read and the prior-
  ownership lookup** → the lookup returns no row for it; `prior = nil`;
  `processCert` writes the first-run shape. Under REPEATABLE READ this
  is structurally unreachable (the snapshot is pinned by
  `WithTxLockedOwnershipRepeatableRead`); the defensive coverage
  remains.

## 13. Rollout plan

1. **H-030-PR1 — repository primitive + recompute refactor.** Add
   `GetCertificateOwnershipByIDs` to the
   `governance.OwnershipRepository` interface + postgres impl +
   exported SQL const. Refactor `streamAndDecide` to use it. Remove
   the `ownPager` and the `ownCur.CertificateID < sig.CertificateID`
   comparison; update the inline doc comment. Full unit + integration
   coverage (§10). The pre-refactor merge is replaced atomically; no
   coexistence window needed (the change is internal to the recompute
   under the per-org advisory lock).
2. **H-030-PR1 hardening — adversarial pass.** A focused regression
   pass mirroring H-027 / H-029 hardening: collation-independence on
   non-hex test ids, EXPLAIN re-pin, cross-org isolation on the new
   primitive, empty-batch / oversized-batch fail-closed,
   determinism. Plus a forbidden-surface check that the old merge
   pattern (`ownCur.CertificateID < sig.CertificateID` or equivalent
   shape) does not reappear.
3. **Default-safe**: the refactor changes only internal recompute
   behavior; no scheduler, no caller change, no API change. The
   recompute remains operator-triggered (B3A) and otherwise
   dormant-loop-wise (B4 not present).
4. **Optional H-030-PR2 — broader invariant cleanup.** Audit the rest
   of the codebase for any other cross-language ordering coupling
   (likely none, but the H-026B3A read endpoints and any future
   pagination should be examined). Defer until PR-1 lands; may be
   unnecessary.

## 14. Proposed PR split

- **H-030-PR1** — repository `GetCertificateOwnershipByIDs` +
  recompute `streamAndDecide` refactor + tests + EXPLAIN. Includes
  the invariant comment removal. ~small (one method + one function
  rewrite + tests).
- **H-030-PR1 hardening** — adversarial regression coverage,
  forbidden-surface guard, performance smoke.
- **Scheduler / B4 wiring is NOT an H-030 PR** — separate phase.

## 15. Explicit out-of-scope items

- **Changing any other paged read's ordering.** Single-stream paged
  reads are not at risk; they remain `ORDER BY certificate_id ASC`
  under the default collation.
- **Adding `COLLATE "C"` indexes anywhere.** Rejected (§7).
- **Changing `ids.New()` shape.** The fix is forward-compatible with
  any future id format; touching id generation is independent and
  out of scope here.
- **Allowing operator-supplied cert ids.** Out of scope for H-030;
  if a future feature wants it, this fix makes that feature safe to
  add (no merge-correctness coupling remains).
- **Scheduler / background recompute loop** (B4).
- **Manual operator endpoint** (already exists via B3A; not changed).
- **Findings / policy integration** (H-026D).
- **UI / dashboards.**
- **Audit shape changes** — the recompute's `governance.recomputed`
  rollup and per-cert transition audits remain byte-identical to
  today.
- **Migration / schema change.** None required.

## 16. Stability / readiness note

The recompute's correctness contract is **already** stable today
because the H-026B invariant holds for all production ids. H-030's
proposal does not fix a reachable defect; it **removes a fragile
cross-language coupling** so a future change to certificate-id
semantics cannot silently break correctness. The fix composes existing
primitives only (the PK index on `certificate_ownership`, the existing
`WithTxLockedOwnershipRepeatableRead` snapshot, the existing
`processCert` per-cert decision), introduces no new index or
migration, and is bounded at every layer. Hardening makes the
collation-independence property machine-verifiable via a non-hex-id
fixture test. Recommend proceeding to H-030-PR1 after this design is
reviewed.
