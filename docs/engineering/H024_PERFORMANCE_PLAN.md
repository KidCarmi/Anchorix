# H-024 — Findings & Inventory Performance at Fleet Scale

> **Status:** planning. No code in this PR. This document is the
> source of truth for the H-024 implementation PR(s) that follow.
>
> **Source of truth for rules:** [`CLAUDE.md`](../../CLAUDE.md). If
> this plan and CLAUDE.md disagree, CLAUDE.md wins and this plan
> is revised.

## 0. Scope and explicit non-goals

H-024 is the **findings recompute + certificate read performance**
follow-up flagged in
[`HARDENING_BACKLOG.md`](./HARDENING_BACKLOG.md). The backlog
entry pins recompute as the immediate driver; this plan widens
the lens to every read path that becomes O(fleet) at scale, since
the same data model and the same indexes feed both. The plan
intentionally stays inside the wire contract and the existing
storage shape — see §13.

**Out of scope** (binding, not deferral):

- New finding rules. The rule registry stays frozen
  ([`CERTIFICATE_FINDINGS.md`](./CERTIFICATE_FINDINGS.md) §4).
- API wire-shape changes. JSON field names, error envelope, and
  pagination cursor format do not move
  ([`REST_API.md`](../api/REST_API.md), CLAUDE.md §17).
- Frontend / UI work.
- ADCS / Vault / EJBCA / Smallstep provider integration.
- New dependencies in `go.mod` unless §12 has a strong
  justification.
- CLAUDE.md amendments. Every rule the plan touches is satisfied
  inside existing rules.
- H-025 (per-recompute timeout). Tracked separately; touched by
  this plan only for the seam it shares with recompute.
- Findings UI, dashboards, alerting.

## 1. Current architecture (as built, not as designed)

The current ingestion → recompute → read pipeline is:

```
agent batch ──► POST /agent/certificates ──► WithTxLockedAgent(agent_id)
                                              │
                                              ├─ UpsertCertificate (per cert) — INSERT…ON CONFLICT, RETURNING id
                                              ├─ GetCertificate    (per cert) — re-read canonical row
                                              ├─ UpsertObservation (per cert) — INSERT…ON CONFLICT
                                              └─ MarkMissingObservationsRemoved (1 statement, ANY($::text[]))

scheduler tick ─► ListOrganizationIDs ──► for each org ──► RecomputeScheduled
operator POST  ─► Service.Recompute ───┘                     │
                                                              └─ WithTxLockedFindings(organization_id)
                                                                  ├─ ListAllCertificateSummariesForOrg   (1 query, ALL rows)
                                                                  ├─ rule pass in-memory                 (O(certs × rules))
                                                                  ├─ ListAllForOrg                       (1 query, ALL findings)
                                                                  ├─ per-(cert,rule) match loop:         (per row)
                                                                  │     InsertFinding | UpdateFinding
                                                                  ├─ per-(cert,rule) miss  loop:         (per row)
                                                                  │     UpdateFinding (resolve)
                                                                  └─ recordRecomputeAudit                (1 insert)

operator GET /certificates ─► ListCertificates ─► 1 SQL with 2 scalar COUNT subqueries per row
operator GET /findings     ─► ListFindings     ─► 1 SQL with LEFT JOIN certificates per row
```

Concrete code anchors:

- `backend/internal/findings/service.go` `Service.runDiff`
  (loads-all → diff → per-row writes).
- `backend/internal/storage/postgres/findings_repository.go`
  `ListAllForOrg` (full-org scan, ordered by id).
- `backend/internal/storage/postgres/findings_repository.go`
  `ListAllCertificateSummariesForOrg` (full-org scan, two scalar
  COUNT subqueries per row).
- `backend/internal/storage/postgres/certificate_inventory_list_repository.go`
  `ListCertificates` (same two scalar subqueries; ILIKE with
  `c.sans::text` cast for the `q` filter).
- `backend/internal/storage/postgres/certificate_inventory_list_repository.go`
  `ListObservationsPage` (LEFT JOIN `agent_inventory_snapshots`).
- `backend/internal/storage/postgres/certificate_inventory_repository.go`
  `UpsertCertificate` (RETURNING id, then `GetCertificate`
  re-read).
- `backend/internal/storage/postgres/postgres.go`
  `WithTxLockedAgent`, `WithTxLockedFindings`
  (`pg_advisory_xact_lock`, two-int32 namespace+key hashed via
  `hashtext`).
- `backend/internal/findings/scheduler.go` `Scheduler.runOnce`
  (per-org sequential sweep, no concurrency, no per-org
  timeout — H-025).

What the design docs already commit to and the implementation
honors:

- Set-reconciliation per `store_coverage`
  ([`CERTIFICATE_INVENTORY.md`](./CERTIFICATE_INVENTORY.md) §3).
- Per-agent advisory lock for cert ingestion (H-017).
- Per-org advisory lock for recompute (H-021).
- Audit-in-transaction (CLAUDE.md §9, H-021 brief).
- Determinism over unchanged inventory at fixed `now`
  ([`CERTIFICATE_FINDINGS.md`](./CERTIFICATE_FINDINGS.md) §5).

None of those move in H-024.

## 2. Bottleneck map

The list below is empirical (read the code, walk the SQL) — not
speculative. Each entry calls out the file, the symptom, and the
worst-case cardinality at fleet scale.

### 2.1 `runDiff`: load-all-certs into memory

`Service.runDiff` (service.go:230) calls
`ListAllCertificateSummariesForOrg`. At v0.1 scale (≤ 1K certs)
the snapshot fits in tens of KB of Go heap. At fleet scale (10K
agents × ~100 distinct shared certs ≈ 10K–50K distinct certs per
org) the in-memory slice and the
`matches map[matchKey]match` keyed by struct of two strings hit
single-digit MB plus garbage-collector pressure.

The bigger symptom is **the SQL feeding the load**, not the
Go-side allocation — see §2.4.

### 2.2 `runDiff`: load-all-findings into memory

`Repository.ListAllForOrg`
(findings_repository.go:190–221) is unpaginated and returns
every status: `open`, `resolved`, `acknowledged`, `suppressed`.
For an org with 50K certs and a steady-state findings density of
~3 open per cert + ~3 resolved (rule pass over historical
inventory) → ~300K rows. Each row carries `evidence` JSONB which
the scan unmarshals into `json.RawMessage` (allocations + copy).

The `existingByKey` map (service.go:262) is `O(findings)` Go
allocations regardless of how many actually match this pass.

### 2.3 `runDiff`: per-row UPDATE / INSERT

Every (cert, rule) match path issues one round-trip to Postgres:
`InsertFinding`, `UpdateFinding` (open), `UpdateFinding`
(reopen / acknowledged / suppressed). At 50K certs × 6 rules → up
to 300K state transitions per recompute, each its own SQL call
through pgx, all serialized inside one transaction holding the
per-org advisory lock. Round-trip latency dominates over the
actual write work.

### 2.4 Scalar COUNT subqueries in the cert read paths

`ListAllCertificateSummariesForOrg`
(findings_repository.go:452) and `ListCertificates`
(certificate_inventory_list_repository.go:28) both select two
counters per row:

```sql
(SELECT COUNT(*) FROM certificate_observations o
   WHERE o.organization_id = c.organization_id
     AND o.certificate_id = c.id) AS observation_count,
(SELECT COUNT(*) FROM certificate_observations o
   WHERE o.organization_id = c.organization_id
     AND o.certificate_id = c.id
     AND o.removed_at IS NULL) AS active_observation_count
```

This is two index range scans per certificate row. The
`certificate_observations_org_certificate_idx` index handles
each scan, but a 50K-row recompute load runs 100K subquery
executions. For the cert list endpoint at limit=50 it's only
100 subqueries per page — invisible at v0.1 scale, but the
recompute's full-org variant pays N×2 every six hours.

`ListAllCertificateSummariesForOrg` only needs the cert fields —
`runDiff` never reads the counters. The subqueries are dead
weight on the recompute path. (They are needed by the operator
read endpoint, hence two callers sharing one query.)

### 2.5 `q` substring search shape

`ListCertificates` for `?q=...` ORs four ILIKEs:

```sql
c.subject ILIKE $N ESCAPE '\'   OR
c.issuer  ILIKE $N ESCAPE '\'   OR
c.fingerprint_sha256 ILIKE $N ESCAPE '\' OR
c.sans::text ILIKE $N ESCAPE '\'
```

with the pattern wrapped `%…%`. Trailing wildcards defeat the
btree indexes on `subject` and `issuer`; `sans::text` is a
cast over JSONB, which forces a sequential scan regardless of
index. The query is correct (and the LIKE-meta-escape pattern
is already in place — `escapeLikePattern`), but the worst-case
plan is a full table scan with a per-row JSONB-to-text
materialization. At 50K certs that's measurable; at 10K certs
it isn't.

### 2.6 ListObservations pagination cursor

`ListObservationsPage` (certificate_inventory_list_repository.go:195)
orders by `(last_seen_at DESC, agent_id ASC, store_location ASC)`
and encodes a three-component cursor. The corresponding WHERE
clause is a three-way disjunction. The planner can use
`certificate_observations_org_certificate_idx` for the equality on
`(organization_id, certificate_id)`, but the ordering tuple has
no matching index; the LIMIT clause does not push down through
the `OR`. At fleet scale (a popular shared cert observed by 5K
agents) deep pagination scans more pages than necessary.

### 2.7 Findings list join shape

`ListFindings` (findings_repository.go:239) joins `certificates`
LEFT JOIN to surface `fingerprint_sha256` and `subject`. The join
is per-row, the index
`findings_org_last_seen_idx (organization_id, last_seen_at DESC, id ASC)`
covers the ORDER BY, and `certificates`'s lookup is by primary
key — this is the right shape and stays as is.

### 2.8 Scheduler sweep is strictly sequential

`Scheduler.runOnce` (scheduler.go:179) iterates org IDs and
calls `recomputeOrg` one at a time. For v0.1 with a single org
this is fine; with a two-org pilot it doubles wall-clock. The
per-org advisory lock would let two orgs proceed concurrently
without correctness risk, but the scheduler doesn't run them in
parallel. Not a v0.1 problem (single tenant per CLAUDE.md §4)
and **not in H-024 scope** — see §13.

### 2.9 Ingestion: per-cert UPSERT then re-read

`UpsertCertificate`
(certificate_inventory_repository.go:56) issues
`INSERT … RETURNING id`, then `GetCertificate` re-reads the
canonical row. That's two round-trips per cert. For a 500-cert
batch this is 1000 round-trips plus 500
`UpsertObservation` round-trips plus 1
`MarkMissingObservationsRemoved`. The advisory lock is held the
whole time. Network RTT (~0.5 ms) dominates here.

The re-read is documented as required: ON CONFLICT only updates
timestamps, so the input row's subject/issuer/PEM may differ
from the canonical stored row. The re-read keeps the contract
honest. There is room to fold the re-read into the upsert's
RETURNING clause (return canonical columns, not just id) for a
50% reduction in per-cert round-trips — see §6.6.

### 2.10 In-memory diff growth

The `matches` map in `runDiff` (service.go:242) is
`map[struct{certID, ruleID string}]match`. At 50K certs × 6
rules with a 30% match rate that's ~90K map entries plus the
per-match `Evidence` `json.RawMessage`. Sub-100 MB at the
worst case, so this is the bound that the scope was sized
against — and the bound H-024 should explicitly measure rather
than reason about.

## 3. Scale targets

The numbers below are deliberate planning anchors. They are not
SLO commitments and they are not in CLAUDE.md; they exist so
this PR's tests have something concrete to assert against. Any
revision of these targets is a separate PR that updates this
section.

| Dimension                       | v0.1 (current) | pilot           | future / “fleet”     |
| ------------------------------- | -------------- | --------------- | -------------------- |
| organizations (in this process) | 1              | 1               | 1 (multi-tenant out) |
| agents per org                  | ≤ 100          | 1K              | 10K                  |
| distinct certs per org          | ≤ 1K           | 5K              | 50K                  |
| observations per cert (avg)     | ≤ 5            | 50              | 200                  |
| total observations per org      | ≤ 5K           | 250K            | 10M                  |
| findings per org (open+resolved)| ≤ 1K           | 30K             | 300K                 |
| ingestion batch size (per agent)| ~50 certs      | ~200 certs      | ~500 certs           |
| ingestion concurrency           | ~10 agents     | ~100 agents     | ~1K agents           |
| recompute interval (scheduler)  | 6h             | 6h              | 6h                   |
| recompute wall-clock budget     | < 1s           | < 10s           | < 60s                |
| `GET /certificates` p95         | < 100 ms       | < 250 ms        | < 500 ms             |
| `GET /findings` p95             | < 100 ms       | < 250 ms        | < 500 ms             |
| `POST /agent/certificates` p95  | < 500 ms       | < 1s            | < 2s                 |
| audit-row growth                | ~tens/day      | ~hundreds/day   | ~thousands/day       |

Budgets are wall-clock with a warm database and a non-saturated
host. The recompute budget at fleet scale (60s) is the
governing constraint: a 6h tick has plenty of headroom; any
recompute that crosses minutes blocks the per-org advisory lock
against operator-triggered runs and starts to feel like a
correctness symptom, not just a perf one.

CLAUDE.md §4 keeps multi-tenancy out for v0.1, so the
"organizations" axis stays at 1. The plan respects that — every
optimization is measured against a single-org workload, and the
scheduler's per-org loop stays sequential.

## 4. Test strategy

> Important: the existing CI gate (`go test ./...` per
> CLAUDE.md §11) must stay fast and deterministic on every PR.
> Heavy load tests do NOT join the blocking set.

### 4.1 Tiers

| Tier                        | Where it lives                         | When it runs                | Purpose                                          |
| --------------------------- | -------------------------------------- | --------------------------- | ------------------------------------------------ |
| **Correctness integration** | `backend/test/integration/*_test.go`   | every PR (CI gate)          | Pin set reconciliation, recompute state machine, operator override lifecycle, pagination cursor, org isolation. |
| **Perf regression (light)** | `backend/test/integration/perf_*_test.go` with `//go:build perf` build tag | every PR (CI gate, but tiny dataset; cf. §4.4) | Bound the **query count** and **rows scanned** for known hot paths, not wall-clock. |
| **Stress / soak**           | `backend/test/stress/`, `//go:build stress` | manual + nightly workflow (§4.5) | Load the pilot/fleet datasets, measure wall-clock, allocations, lock waits. |
| **Benchmark-only**          | `*_bench_test.go`, `testing.B`         | manual `go test -bench=...` and nightly | Track per-iteration cost of pure-Go pieces (rule pass, cursor decode, in-memory diff). |

### 4.2 Correctness integration — what to extend

These tests already exist and stay where they are:
`findings_test.go`, `operator_certificates_test.go`,
`agent_certificates_test.go`. H-024 does NOT add new
correctness tests — performance work that changes behavior is
out of scope.

### 4.3 Perf regression (in CI, tiny dataset)

Pin the **structural cost** of hot paths so a future regression
fails noisily even on a CI runner. Tiny dataset (~50 certs / 100
observations / 30 findings) — measured in milliseconds on a CI
runner, NOT in seconds. Assertions:

- `runDiff` issues ≤ K queries for the cert load + finding load
  + writes. The exact `K` is set by the implementation PR; the
  point is to FAIL when the per-row pattern of §2.3 sneaks in.
- `ListCertificates` page-50 issues exactly 1 SQL statement
  (no N+1).
- `ListFindings` page-50 issues exactly 1 SQL statement.
- `POST /agent/certificates` for an N-cert batch issues ≤ M
  statements, with M proportional to N (no quadratic blow-up
  from per-cert subqueries).

Implementation hook: a thin pgx middleware that counts
statements in test mode. Built behind `//go:build perf` so it
costs nothing in production binaries.

### 4.4 Stress / soak — what to land, what to gate

- `stress/recompute_fleet_test.go` — generate the §3 "future"
  dataset, run one recompute, assert it completes within the
  budget. Run on demand: `go test -tags=stress -timeout 30m ./backend/test/stress/...`.
- `stress/ingestion_concurrent_test.go` — 100 simulated agents
  concurrently POSTing a batch each, assert no deadlocks, p95
  within budget.
- `stress/list_pagination_test.go` — deep paginate
  `GET /certificates` and `GET /findings` across the full
  dataset, assert per-page latency stays in budget.

These do NOT run on every PR. They run nightly (§4.5) and on
demand. The build tag keeps `go test ./...` clean.

### 4.5 Optional: nightly workflow (NOT in this PR)

The nightly workflow concept is sketched here for the H-024
implementation PR to either adopt or defer. A
`.github/workflows/perf-nightly.yml`:

- builds the backend,
- stands up Postgres in a service container,
- runs `go test -tags=stress ./backend/test/stress/...`,
- captures duration / allocations as workflow artifacts,
- opens an issue (or comments on the H-024 follow-up) when a
  budget is breached.

This is **not** in the blocking CI set (CLAUDE.md §11). If
adopted, the H-024 PR introduces a separate workflow file with a
clear "not blocking branch protection" banner in its job
summary and in `CI_PLAN.md`.

### 4.6 Benchmark-only

`go test -bench=.` units, no DB:

- `BenchmarkRuleSetEvaluate` — rule pass over N synthetic
  certs (already partially covered in `rules_test.go`; widen
  to a Benchmark).
- `BenchmarkRunDiff` — in-memory diff over N rule matches +
  M existing findings, repo + tx mocked.
- `BenchmarkCertCursorDecode` — cursor encode/decode.

Outputs are not asserted; they exist so reviewers can compare
before/after numbers on the H-024 implementation PR.

## 5. Synthetic data generation strategy

A deterministic fixture builder under
`backend/internal/inventory/fixtures` (test-only build tag) so
both perf-regression and stress tests share the same data
distribution. Determinism is non-negotiable — random seeds are
fixed and documented per fixture; CI runs must produce
byte-identical inputs.

### 5.1 Population shape

The fleet generator parameters (and their defaults at the three
tiers from §3):

| Knob                  | v0.1 | pilot | fleet |
| --------------------- | ---- | ----- | ----- |
| `Organizations`       | 1    | 1     | 1     |
| `AgentsPerOrg`        | 100  | 1000  | 10000 |
| `CertsPerAgent`       | 50   | 100   | 200   |
| `SharedCertRatio`     | 0.30 | 0.50  | 0.70  |
| `StoresPerAgent`      | 3    | 5     | 5     |
| `ExpiredRatio`        | 0.02 | 0.05  | 0.10  |
| `ExpiringSoonRatio`   | 0.05 | 0.10  | 0.15  |
| `WeakKeyRatio`        | 0.01 | 0.02  | 0.05  |
| `WeakSigRatio`        | 0.01 | 0.02  | 0.05  |
| `SelfSignedLeafRatio` | 0.02 | 0.05  | 0.10  |
| `LongLivedRatio`      | 0.03 | 0.05  | 0.05  |
| `RemovedObsRatio`     | 0.05 | 0.10  | 0.15  |
| `AcknowledgedRatio`   | 0.05 | 0.05  | 0.05  |
| `SuppressedRatio`     | 0.05 | 0.05  | 0.05  |

`SharedCertRatio` is the fraction of certs observed by more
than one agent — the realistic case (Windows trust-store roots,
internal CA leafs deployed via SCCM).
[`CERTIFICATE_INVENTORY.md`](./CERTIFICATE_INVENTORY.md) §10
already commits to ≤ 1K distinct certs even for a 10K-host
fleet; the dedup behavior is what we're exercising.

### 5.2 Cert content

Generate **real X.509 bytes**, not synthetic strings: ingestion
parses PEM with `crypto/x509` and rejects malformed input. A
fixture-internal CA mints leafs with the desired
`not_before` / `not_after` / `signature_algorithm` /
`public_key_algorithm` / `public_key_bits` / SANs to populate
each rule's match / no-match buckets per the ratios above.

Self-signed certs are leafs whose subject == issuer and signed
by their own key (matches the rule's
[`CERTIFICATE_FINDINGS.md`](./CERTIFICATE_FINDINGS.md) §4
boundary).

### 5.3 Observation generation

Build observations from the cert/agent cross-product per
`StoresPerAgent` and `SharedCertRatio`. Reconciled-absent /
re-appeared lineage is generated by a second pass that:

1. Picks `RemovedObsRatio × total` observations,
2. Sets `removed_at = now - random(1d..30d)`,
3. For half of those, re-inserts a present row at
   `last_seen_at = now` to simulate "cert disappeared, came
   back" (matches §3 history retention).

### 5.4 Findings state generation

For perf tests that target the recompute diff, the fixture
optionally **pre-seeds** the `findings` table to simulate
steady state — without that, the first run is dominated by INSERTs
and looks artificially expensive. The seeder:

- Runs the rule registry once over the fixture inventory.
- Inserts the resulting open findings at `last_seen_at = now -
  6h`.
- Promotes `AcknowledgedRatio` and `SuppressedRatio` slices to
  the override states with synthetic `status_reason`,
  `status_actor`, `status_changed_at`.

The second recompute call (the one we measure) then exercises
the steady-state diff: mostly Updates, a few Opens / Resolves,
and the override-preserving paths from H-023.

### 5.5 Reproducibility

- Single entry point: `fixtures.NewFleetBuilder(seed int64,
  cfg FleetConfig)` returns a `*Fleet` with deterministic IDs
  (hex of `sha256(seed || index)`), deterministic
  `collected_at`, deterministic PEMs.
- Documented in `fixtures/doc.go` with the §5.1 table and the
  CLAUDE.md §8.4 naming-rule conformance.
- No env-driven knobs (CLAUDE.md §8.9). The cfg is passed
  explicitly from the test that uses it.

## 6. Candidate improvements (evaluation only — no implementation here)

Each candidate has a benefit, complexity, migration risk,
correctness risk, and a recommendation. Recommendations are
graded "**now**" (in the H-024 PR), "**next**" (next perf PR),
or "**defer**" (revisit after pilot measurements).

### 6.1 Repository-level pagination for recompute scans

- **Benefit:** caps memory at one page × row size; the load
  cost grows linearly but stays predictable; opens the door to
  streaming the diff via row-channel rather than materializing
  every cert / finding up front.
- **Complexity:** medium. Adds `ListCertificateSummariesPage`
  + `ListFindingsAllPage` repository methods with the same
  H-010 cursor pattern. `runDiff` becomes a two-stream merge.
- **Migration risk:** none (schema unchanged).
- **Correctness risk:** medium. The recompute must observe the
  org's certificates **consistently** during one tick.
  PostgreSQL's REPEATABLE READ inside the existing `WithTxLockedFindings`
  transaction already guarantees this for paginated scans — so
  the snapshot stays coherent. The risk is implementer error
  in the cursor-merge: a missed boundary becomes a wrong-diff
  bug, which is far worse than a slow recompute. Mitigate with
  a unit test that diff-compares the streaming and
  load-all paths on the §5 fixture.
- **Recommended:** **now** (this is the H-024 backlog entry's
  stated scope).

### 6.2 Replace scalar COUNT subqueries on the cert summary path

- **Benefit:** the recompute path doesn't need the counters at
  all; the operator list path benefits from precomputing them
  once instead of twice per row. Cuts N×2 subquery executions
  to one aggregate join.
- **Complexity:** low.
  - For the recompute load: a separate
    `ListCertificateBareSummariesForRecompute` query that
    omits the counters entirely (recompute doesn't read them).
  - For the operator list: replace the two scalar subqueries
    with a single `LEFT JOIN LATERAL` aggregating
    `count(*)` and `count(*) FILTER (WHERE removed_at IS NULL)`
    in one pass over the cert's observation slice. The existing
    `certificate_observations_org_certificate_idx` covers it.
- **Migration risk:** none (no schema change, just a query
  rewrite).
- **Correctness risk:** low. The two queries are pure reads;
  output JSON is byte-identical when the math is right.
  Mitigate with an integration test asserting the counters
  match the existing query's output across the §5 fixture.
- **Recommended:** **now** (recompute variant), **next**
  (operator-list variant; lower urgency since the page size is
  bounded at 200).

### 6.3 Materialized counters on `certificates`

Two columns: `observation_count`, `active_observation_count`,
maintained by ingestion's UPSERT/RemoveObs SQL.

- **Benefit:** the cert read endpoints stop computing counters
  at all; recompute (if it ever needs them) stops scanning the
  observations table.
- **Complexity:** medium. Requires a new migration; ingestion
  service must keep the counters in sync; backfill on
  migration is non-trivial for an installed fleet.
- **Migration risk:** medium. CLAUDE.md §16 destructive-pattern
  rules apply: ship reading-tolerant code first (the column is
  optional / fallback to subquery), then the column, then
  drop the fallback in a third PR.
- **Correctness risk:** medium-high. Counters can drift if any
  write path misses an update; drift is invisible until an
  operator notices a wrong number, which is the worst kind of
  bug for a security tool ("explainable" — CLAUDE.md §7.2).
- **Recommended:** **defer**. The aggregate JOIN in §6.2 buys
  most of the same win without the drift risk. Reconsider only
  if pilot data shows the JOIN is still the bottleneck.

### 6.4 Indexes

Concrete candidates (each is a single `CREATE INDEX` in a new
migration; CLAUDE.md §16 requires per-index documented intent):

| Index                                                                                | Purpose                                                                                              | Recommended |
| ------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------- | ----------- |
| `certificate_observations (organization_id, certificate_id) WHERE removed_at IS NULL` | Speeds up the `current_only` EXISTS subquery in `ListCertificates`. Partial index keeps it small.    | **now**     |
| `certificates (organization_id, last_seen_at DESC, id ASC)`                          | Matches the operator cert list's ORDER BY tuple; turns the cursor walk into an index-only scan.       | **now**     |
| `certificates USING GIN (sans jsonb_path_ops)`                                       | Replaces the `c.sans::text ILIKE '%…%'` cast with a GIN-backed containment query.                    | **defer** (requires query rewrite; raises the bar on `q` semantics) |
| `findings (organization_id, certificate_id)`                                         | Already implicit via `findings_certificate_idx`; verify it's used.                                   | **none**    |
| Functional `lower(c.subject) varchar_pattern_ops`                                    | Speeds up prefix-only ILIKE; not useful for `%…%` substring.                                         | **none**    |

The GIN-on-`sans` option is tempting but changes the `q`
semantics — current `ILIKE '%…%'` matches any substring of any
SAN string; a GIN containment query requires a token / shape
choice. Defer until pilot data shows `q` over SANs is actually
slow in practice.

### 6.5 Incremental recompute on ingestion

Recompute only the certs touched by the latest batch, not the
whole org.

- **Benefit:** reactive recompute becomes O(batch) instead of
  O(org); the 6h scheduled sweep stays as the backstop.
- **Complexity:** high. Per-rule "rule depends on" mapping is
  not trivial — rules over a cert touch only that cert's
  findings, but a rule like "duplicate across hosts" (Phase 4)
  is observation-wide.
- **Migration risk:** none directly; conceptual risk that
  future cross-cert rules require a redesign.
- **Correctness risk:** high. Incremental + scheduled must
  converge. A bug where the incremental path misses an open →
  resolved transition becomes "stale findings that operators
  rely on" — same explainability concern as §6.3.
- **Recommended:** **defer**. Get §6.1 + §6.2 first; only
  consider incremental once the scheduled-recompute baseline
  is measured against pilot load.

### 6.6 Fold `GetCertificate` re-read into `UpsertCertificate`'s RETURNING

- **Benefit:** halves the per-cert round-trip count on
  ingestion.
- **Complexity:** low. The `RETURNING` clause already exists;
  expand it to the full canonical column set.
- **Migration risk:** none.
- **Correctness risk:** low. The current re-read returns the
  same row the UPSERT just touched, in the same transaction.
  Mitigate with the existing canonical-row tests in
  `agent_certificates_test.go` / `certificate_inventory_test.go`.
- **Recommended:** **now** (small, isolated, easy win).

### 6.7 Bulk INSERT / UPDATE for findings diff

`pgx.CopyFrom` for inserts, `UPDATE … FROM (VALUES …)` for the
update set.

- **Benefit:** dramatic per-row latency reduction on the diff
  apply (§2.3).
- **Complexity:** medium. Conditional updates (open vs
  acknowledged vs suppressed) make a single UPDATE statement
  more complex than the current per-row branch; the H-023
  override metadata must be preserved per-row, which is the
  whole reason the current code is per-row.
- **Migration risk:** none.
- **Correctness risk:** medium. The current per-row switch
  (service.go:268–393) is the documented state machine —
  H-023's review effort went into making it provably correct.
  Re-expressing it as bulk SQL re-opens that surface.
- **Recommended:** **defer**. §6.1 (pagination) reduces the
  pressure that this would relieve; revisit only if recompute
  wall-clock still exceeds budget after streaming.

### 6.8 Per-org timeout (H-025 seam)

- **Benefit:** prevents a slow recompute from blocking the
  scheduler indefinitely; required once any non-pure rule
  arrives.
- **Complexity:** trivial (one `context.WithTimeout`).
- **Migration risk:** none.
- **Correctness risk:** low — graceful tx rollback on context
  cancel is already the pgx default.
- **Recommended:** **defer** (H-025 owns this). H-024 leaves
  the seam ready: scheduled recomputes already accept a `ctx`
  that the H-025 PR will wrap.

### 6.9 Separate perf workflow

Already discussed in §4.5. Adopt only if H-024 chooses to
land a nightly workflow; otherwise leave the stress tests
on-demand and revisit when pilot data justifies it.

### 6.10 Org-level recompute watermarks

Mark each org's last-recompute `last_seen_at` and skip
recomputes when nothing has changed since then.

- **Benefit:** the 6h scheduler tick becomes a no-op when no
  inventory has moved.
- **Complexity:** medium. Requires a per-org timestamp,
  maintained on every cert/observation write.
- **Migration risk:** new table or new column on
  `organizations`.
- **Correctness risk:** medium. The watermark must include
  finding-state changes too (an operator suppress with
  expiry must trigger a recompute at expiry time even with
  no inventory change). Otherwise findings drift.
- **Recommended:** **defer**. The §6.1 + §6.2 wins are
  larger and have lower correctness risk.

## 7. Metrics to collect

The first H-024 PR should add lightweight, opt-in
instrumentation — not a metrics dependency. Concretely:

- **Structured log fields on the existing recompute log line**
  (scheduler.go:253–262 already logs duration / counters).
  Extend with:
  - `loaded_certificates`, `loaded_findings` — how many rows
    each phase materialized.
  - `db_queries` — count of SQL statements issued, via a
    pgx middleware that's wired only when the new config knob
    `ANCHORIX_FINDINGS_RECOMPUTE_QUERY_LOG=true` is set.
    Default false — production is silent.
  - `peak_alloc_bytes` — captured with `runtime.MemStats`
    around the diff, only when the same knob is on.
- **No metrics framework** (Prometheus, OpenTelemetry) in
  H-024. v0.1 is structured-log-only (CLAUDE.md §9). The
  instrumentation lands inside the log envelope that
  operators already grep.
- **Operator-visible counters in the recompute response**:
  unchanged — preserved per
  [`REST_API.md`](../api/REST_API.md) §"Findings".
- **DB-side**: PostgreSQL `pg_stat_statements` is the right
  primary source for query-level metrics in any real
  deployment; the H-024 PR adds a runbook entry in
  `docs/engineering/` showing the queries to monitor (the
  recompute load, the cert list, the ingestion upsert) but
  does NOT take a dependency on `pg_stat_statements` being
  installed.
- **Lock-wait visibility**: when `WithTxLockedFindings` waits
  for a contending recompute, log a single `findings
  scheduler: waiting on advisory lock` line with the wait
  duration once acquired. Same for `WithTxLockedAgent`.

Counter list for the perf tier:

| Counter / Gauge                  | Source                                    | Why                                          |
| -------------------------------- | ----------------------------------------- | -------------------------------------------- |
| `recompute_duration_ms`          | scheduler log line                        | wall-clock budget                            |
| `recompute_loaded_certificates`  | new field                                 | input-size regression                         |
| `recompute_loaded_findings`      | new field                                 | state-size regression                         |
| `recompute_opened/updated/resolved/unchanged` | existing audit metadata    | state-transition shape                        |
| `recompute_db_queries`           | new field (opt-in)                        | regression on N+1 patterns                    |
| `recompute_peak_alloc_bytes`     | new field (opt-in)                        | memory regression                             |
| `ingestion_batch_certs`          | existing log line (extend with one field) | batch-size baseline                           |
| `ingestion_duration_ms`          | new field                                 | per-batch latency                             |
| `ingestion_db_queries`           | new field (opt-in)                        | regression on per-cert round-trips            |
| `lock_wait_ms` (per scope)       | new field                                 | contention visibility                         |

These do NOT become permanent CLAUDE.md commitments — they
exist as observable side effects of structured logs the
operator can grep. If/when v0.x grows a real metrics stack,
the same fields surface there without rename.

## 8. Risk analysis (per candidate, condensed)

The table summarizes §6 plus the §4 test work, scored against
the v0.1 engineering principles (CLAUDE.md §14, §19).

| Item                                              | Benefit | Complexity | Migration risk | Correctness risk | Needed now?                                                          |
| ------------------------------------------------- | ------- | ---------- | ---------------- | ----------------- | -------------------------------------------------------------------- |
| §6.1 Paginated/streaming recompute scans          | high    | medium     | none             | medium            | **yes — core of H-024**                                              |
| §6.2 Aggregate JOIN counters (recompute path)     | high    | low        | none             | low               | **yes**                                                              |
| §6.2 Aggregate JOIN counters (operator list path) | medium  | low        | none             | low               | next perf PR                                                          |
| §6.3 Materialized counters on `certificates`      | medium  | medium     | medium           | high              | defer                                                                |
| §6.4 Partial index `obs(org, cert_id) WHERE removed_at IS NULL` | medium | low | low | low | **yes**                                                              |
| §6.4 Index `certificates(org, last_seen_at DESC, id ASC)` | medium | low | low | low       | **yes**                                                              |
| §6.4 GIN on `sans`                                | medium  | medium     | medium           | medium            | defer (semantic change)                                              |
| §6.5 Incremental recompute on ingestion           | high    | high       | none             | high              | defer                                                                |
| §6.6 Fold `GetCertificate` re-read into RETURNING | low     | low        | none             | low               | **yes**                                                              |
| §6.7 Bulk INSERT/UPDATE for findings diff         | high    | medium     | none             | medium            | defer                                                                |
| §6.8 Per-org recompute timeout (H-025)            | medium  | trivial    | none             | low               | defer (H-025)                                                        |
| §6.9 Nightly perf workflow                        | low     | medium     | none             | none              | **yes if we land §6.1 deliverable; otherwise next**                  |
| §6.10 Org-level recompute watermarks              | medium  | medium     | medium           | medium            | defer                                                                |
| §5 Synthetic fixture builder                      | enabler | medium     | none             | low               | **yes — every other item depends on it**                             |
| §4.3 In-CI perf regression with statement count   | medium  | low        | none             | low               | **yes**                                                              |
| §4.4 Stress / soak tests (`//go:build stress`)    | medium  | medium     | none             | low               | **yes (added but not in blocking CI)**                               |

Nothing in the "yes" column requires a CLAUDE.md amendment.

## 9. Recommended H-024 scope (split into two PRs)

H-024 lands as **two sequential implementation PRs**. The
split isolates the risky control-flow rewrite (the streaming
two-cursor diff) from the lower-risk groundwork (fixtures,
perf tests, indexes, the ingestion RETURNING optimization),
so each PR can be reviewed against its own correctness bar
without the reviewer juggling unrelated concerns.

H-024A lands first; H-024B depends on A's fixture builder and
on A's perf tests being green so any regression introduced by
B is attributable.

### 9.A H-024A — fixtures, perf tier, indexes, ingestion RETURNING

Lower-risk, no changes to the findings state machine, no
changes to the recompute control flow.

**Migration**

1. `backend/migrations/0008_perf_indexes.sql`:
   - `CREATE INDEX certificate_observations_org_cert_active_idx
      ON certificate_observations(organization_id, certificate_id)
      WHERE removed_at IS NULL;` (partial index for §6.4).
   - `CREATE INDEX certificates_org_last_seen_idx
      ON certificates(organization_id, last_seen_at DESC, id ASC);`
      (operator-list cursor walk, §6.4).
   - Each `CREATE INDEX` carries an inline comment per
     CLAUDE.md §16 documenting the query pattern it serves.

**Storage / service**

2. Fold the `GetCertificate` re-read into
   `UpsertCertificate`'s `RETURNING` clause (§6.6). The
   ingestion service consumes the canonical row directly from
   the upsert; the standalone `GetCertificate` call on the
   ingestion hot path goes away. `GetCertificate` itself
   stays — operator reads still use it.

**Tests**

3. `backend/internal/inventory/fixtures/` deterministic
   builder (§5). Two presets: `Smallv01` (tiny — used by
   in-CI perf-regression tests) and `Pilot` (used by stress
   tests, build-tagged `stress`). Documented in
   `fixtures/doc.go` per CLAUDE.md §19.
4. `backend/test/integration/perf_query_count_test.go`
   (`//go:build perf`) — assert query counts on `runDiff`
   (against the **current** load-all implementation; the
   baseline H-024B will compare against), `ListCertificates`,
   `ListFindings`, ingestion (including the new RETURNING
   path).
5. `backend/test/stress/` skeleton with one or two stub
   tests (`//go:build stress`), `recompute_fleet_test.go`
   and `ingestion_concurrent_test.go`, runnable on demand
   with the Pilot fixture. The stress tests assert §3 pilot
   budgets against the **current** code so H-024B has a
   pre-change baseline.

**Docs**

6. Update [`CI_PLAN.md`](./CI_PLAN.md) with the perf tier
   table (§4.1) and the build-tag conventions. The H-024A
   PR DOES NOT change the blocking-CI gate; the `perf` tier
   joins the blocking set in a follow-up once stable (see
   §11 Q5).
7. Update this file's §13 status table to mark H-024A
   shipped.

**Explicit non-shipping from H-024A:**

- Paginated repository methods.
- Any change to `runDiff`'s control flow.
- Any change to the recompute audit metadata shape.
- Removal of `ListAllCertificateSummariesForOrg` /
  `ListAllForOrg` — they stay so H-024B's
  byte-identical comparison test can call both paths.

PR title: `perf(inventory): fixtures, perf/stress test tier, perf
indexes, upsert RETURNING`. LOC budget: aim for < 1000 LOC
including tests.

### 9.B H-024B — paginated recompute scans + streaming diff

Depends on H-024A. Carries the higher-risk control-flow
rewrite around the findings state machine. Reviewed in
isolation against the byte-identical comparison test introduced
in this PR.

**Storage layer**

1. New repository method
   `ListCertificateBareSummariesForOrgPaged(ctx, orgID, cursor,
   pageSize) ([]inventory.CertificateSummary, nextCursor,
   err)` — no counters, cursor by `(id ASC)`. Backs the
   recompute load.
2. New repository method
   `ListAllFindingsForOrgPaged(ctx, orgID, cursor, pageSize)`
   — cursor by `(id ASC)`. Backs `runDiff`'s existing-finding
   load.
3. `ListAllCertificateSummariesForOrg` and `ListAllForOrg`
   stay in the repository for the duration of this PR so the
   byte-identical comparison test (item 6) can drive both
   paths from the same fixture. Removal is **deferred to a
   follow-up cleanup PR** that lands only after H-024B has
   soaked in `main` for one minor release and no fallback
   has been needed.

**Service layer**

4. `Service.runDiff` rewritten as a streaming two-cursor merge:
   pull a page of certs, evaluate rules over it, pull
   matching-key findings, apply diff, advance. Existing-finding
   rows that match no still-pending cert pages get walked at
   the end. The state-machine switch (service.go:268–393)
   stays byte-identical — only the surrounding control flow
   changes. H-023 override-preserving paths are NOT touched.
5. Recompute audit row writes the new `loaded_certificates` and
   `loaded_findings` metadata fields. JSON is additive
   (CLAUDE.md §17); existing readers don't break.

**Tests**

6. `backend/test/integration/recompute_pagination_test.go` —
   correctness: drive **both** the old load-all and the new
   streaming implementations against the `Smallv01` fixture
   from H-024A, snapshot each implementation's resulting
   `findings` table state, and assert byte-identical
   equivalence. This is the gating test for H-024B's merge.
7. Extend the H-024A perf-regression test to assert the new
   streaming `runDiff`'s query-count and per-page bounds.
8. Stress: extend H-024A's stress skeleton to assert the
   pilot/fleet recompute budgets from §3 against the
   streaming implementation. Captures the post-change
   baseline.

**Docs**

9. Update [`CERTIFICATE_FINDINGS.md`](./CERTIFICATE_FINDINGS.md)
   §5 to reflect "streaming load" instead of "full snapshot",
   and §10 to add an entry for H-024B's ship status. Note
   that `ListAllCertificateSummariesForOrg` and
   `ListAllForOrg` remain present-but-unused until the
   follow-up cleanup PR.
10. Update [`HARDENING_BACKLOG.md`](./HARDENING_BACKLOG.md):
    remove the H-024 entry, replace with a short pointer to
    H-024A and H-024B / commits. H-025 stays.
11. Update this file's §13 status table to mark H-024B
    shipped.

**Explicit non-shipping from H-024B** (each is in §6 with a
"defer" recommendation):

- materialized counters,
- aggregate JOIN replacement on the operator-list path,
- bulk INSERT/UPDATE,
- GIN on `sans`,
- incremental recompute,
- per-org timeout (H-025 owns it),
- nightly workflow (revisit after measuring),
- org watermarks,
- removal of the legacy load-all methods (separate cleanup PR
  per item 3).

PR title: `perf(findings): paginate Recompute scans + streaming
two-cursor diff`. LOC budget: aim for < 1000 LOC including the
comparison test; split if it grows past 1500.

### 9.C Why the split

The streaming two-cursor diff is the **only** item in the
H-024 envelope that changes control flow around the findings
state machine. Every other item is additive (a new method, a
new test, a new index, a tighter SQL).

Reviewing the streaming rewrite alongside indexes, fixtures,
and an ingestion-side optimization would dilute reviewer
attention exactly where it matters most — the H-023 state
machine took explicit hardening passes
([`CERTIFICATE_FINDINGS.md`](./CERTIFICATE_FINDINGS.md) §5
"Defensive: unsupported finding status fails loudly") and
H-024B's rewrite must demonstrably preserve every transition
in that switch.

The split also lets H-024A's perf tests land first as a
**baseline**, so H-024B's measurements are diff-able against
the pre-change numbers from the same fixture on the same
runner. Without that ordering, the streaming rewrite would
land without a comparable baseline and any regression would
be invisible to CI.

## 10. Constraint check

The plan keeps every binding constraint from the briefing:

- **API contract preserved.** No JSON field renames, no
  envelope changes, no error code changes — recompute's
  response stays as in
  [`REST_API.md`](../api/REST_API.md) §"Findings". The audit
  metadata gains two additive integer fields, which CLAUDE.md
  §17 allows.
- **Org isolation preserved.** Every new SQL clause carries
  `organization_id` in the WHERE; the partial index in §6.4
  leads with `organization_id`. No cross-org reads possible.
- **Audit behavior preserved.** One `findings.recomputed` row
  per recompute, written in the same transaction. Audit
  failure still rolls back. Acknowledge / suppress audit
  rows are untouched.
- **Advisory locks preserved.** `WithTxLockedAgent` and
  `WithTxLockedFindings` are not modified. Streaming
  recompute runs inside one
  `WithTxLockedFindings(orgID)` transaction so the snapshot
  view stays consistent across pages
  ([`CERTIFICATE_FINDINGS.md`](./CERTIFICATE_FINDINGS.md) §5
  determinism).
- **Acknowledge / suppress lifecycle preserved.** The
  service.go state-machine switch is moved, not modified.
  The H-023 integration tests
  (`findings_test.go` ack/suppress + override-clearing) keep
  passing without changes.
- **No UI / frontend changes.**
- **No ADCS integration.**
- **No new findings rules.**
- **No new dependencies.** Streaming uses
  the existing `pgx` cursor patterns; the deterministic
  fixture builder uses `crypto/x509` from stdlib.
- **No CLAUDE.md changes.**

## 11. Open questions

These don't block the design but the implementation PR should
resolve them:

1. **Page size for the streaming load.** 500? 1000? 5000?
   Goal: keep the matches map bounded; minimize round-trips.
   Suggestion: start at 1000 and measure on the Pilot fixture.
2. **Snapshot consistency mechanism.** PostgreSQL's default
   `READ COMMITTED` is sufficient for the locking model used,
   but `REPEATABLE READ` would give a guaranteed coherent
   snapshot across pages. Trade-off: REPEATABLE READ can
   surface serialization conflicts; for a single advisory-lock-
   protected writer this is essentially never hit, but worth
   measuring. Suggestion: keep the default; rely on the
   advisory lock for serialization.
3. **Streaming via cursor vs `LIMIT/OFFSET`.** The H-010
   cursor pattern is already in use; cursor wins on large
   page-N because it stays index-only. Suggestion: cursor.
4. **Where to put `pg_stat_statements` guidance.** New
   `docs/engineering/PERF_OPS.md` vs append to `CI_PLAN.md`.
   Suggestion: new file; keep CI_PLAN scoped to CI shape.
5. **Whether the `//go:build perf` tier joins the blocking
   CI gate.** Pro: catches N+1 regressions on every PR. Con:
   tiny dataset is fine but the structural assertion can be
   brittle. Suggestion: yes to blocking once the assertions
   are stable for two consecutive weeks of PRs.
6. **Per-org recompute concurrency in the scheduler.** Two
   orgs could safely run in parallel under separate advisory
   locks. The current sequential sweep is fine at v0.1 (single
   org). Implementing parallelism is a 10-LOC change. Risk:
   the per-org goroutine ownership story
   (CLAUDE.md §8.10) needs to be documented. Suggestion:
   defer to a separate PR once multi-org becomes real.

## 12. References

- [`CLAUDE.md`](../../CLAUDE.md) §4, §8.5, §8.10, §9, §11, §14,
  §16, §17, §18, §19.
- [`HARDENING_BACKLOG.md`](./HARDENING_BACKLOG.md) — H-024 and
  H-025 backlog entries.
- [`CERTIFICATE_INVENTORY.md`](./CERTIFICATE_INVENTORY.md) §3,
  §10, §12 — fleet sizing, observation index intent.
- [`CERTIFICATE_FINDINGS.md`](./CERTIFICATE_FINDINGS.md) §4, §5,
  §7, §8 — rule set, recompute lifecycle, scheduler,
  override workflow.
- [`REST_API.md`](../api/REST_API.md) — wire contract that
  H-024 preserves.
- [`CI_PLAN.md`](./CI_PLAN.md) — CI tiers; the perf tier
  documentation lands alongside H-024.
- `backend/internal/findings/service.go`,
  `backend/internal/findings/scheduler.go`,
  `backend/internal/findings/repository.go` — recompute
  orchestration and consumer interfaces.
- `backend/internal/storage/postgres/findings_repository.go`,
  `backend/internal/storage/postgres/certificate_inventory_repository.go`,
  `backend/internal/storage/postgres/certificate_inventory_list_repository.go`,
  `backend/internal/storage/postgres/postgres.go` —
  current SQL shapes and advisory-lock helpers.
- `backend/migrations/0001_init.sql`,
  `backend/migrations/0005_certificate_inventory.sql`,
  `backend/migrations/0006_findings_lifecycle.sql`,
  `backend/migrations/0007_findings_overrides.sql` —
  current schema; H-024 adds `0008_perf_indexes.sql`.

## 13. Status

| Item                                                | Status                                  |
| --------------------------------------------------- | --------------------------------------- |
| H-024 plan (this doc)                               | **draft — awaiting review and merge**   |
| H-024A — fixtures, perf tier, indexes, RETURNING    | not started                              |
| H-024B — paginated scans + streaming diff           | not started (depends on H-024A)          |
| Legacy-method cleanup PR (post-H-024B soak)         | deferred                                 |
| H-024 nightly perf workflow                         | optional (§4.5)                          |
| H-025 per-recompute timeout                         | tracked separately in HARDENING_BACKLOG  |
