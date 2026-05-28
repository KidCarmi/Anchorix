# H-026B Ownership Engine — Threat Model

> **Status:** required by CLAUDE.md §6.10 and §19 before the
> operator-facing ownership surface (H-026B3A) merges. Source of
> truth for rules: [`CLAUDE.md`](../../CLAUDE.md). If this document
> and CLAUDE.md disagree, CLAUDE.md wins and this document is revised.

## 0. Scope

This document covers the threat surface introduced by the H-026B
ownership engine — its storage primitives (B1), the inference engine
+ streaming recompute (B2), and the **operator-facing visibility +
recompute trigger surface** that H-026B3A exposes:

```
POST   /api/v1/ownership/recompute[?nowait=true]
GET    /api/v1/ownership/{unowned,ambiguous,stale}
GET    /api/v1/certificates/{id}/ownership
GET    /api/v1/certificates/{id}/ownership/explanation[?include_history=&limit=]
GET    /api/v1/certificates/{id}/ownership/override
GET    /api/v1/ownership-rules[?cursor=&limit=&enabled=]
GET    /api/v1/ownership-rules/{id}
GET    /api/v1/governance/recompute-runs[?kind=]
```

It also addresses the lifecycle behaviors the engine performs
internally during a recompute (auto-expiry of overrides, regex
compile failure handling, audit emission).

It does **not** yet address rule CRUD or override CRUD (those land
in H-026B3B and have their own threat model entry on merge), the
preview endpoint (H-026B3C), the scheduler (H-026B4), or policy /
findings integration (H-026D).

## 1. Trust model assumptions

Carry-over from CLAUDE.md §12 and the H-026 plan §0:

- The control plane runs in an environment the operator trusts.
- The PostgreSQL database is on a trusted network.
- Operators access the API from authenticated sessions over TLS.
- Operator identity is established by the H-026A2 auth stack
  (session cookie, signed); agent bearer credentials are
  **not** honored on any governance route.
- Cross-org requests within a single deployment are governed by the
  session's `organization_id`. Cross-org ids surface as `404
  not_found`, never `403`, so the existence of a foreign-org row
  cannot be enumerated (CLAUDE.md §6 deterministic auth).
- Single-org per process (CLAUDE.md §4); no multi-tenant policy
  layer beyond the row-level org scoping the schema enforces via
  composite FKs (H-009).

## 2. Attacker / mistake model

Threats considered:

| Actor | Capabilities |
|---|---|
| **Malicious or compromised operator** | Valid session, authenticated, mistyped intent or hostile. |
| **Curious operator** | Valid session; attempts to enumerate other orgs by guessing ids. |
| **Buggy operator UI / script** | Valid session; floods endpoints with retries. |
| **Internal infrastructure flake** | DB collation drift, FK CHECK drift, clock skew. |
| **Operator data error** | Invalid regex, oversized pattern, conflicting rule pair. |

Out of scope: arbitrary code execution inside the control-plane
process, supply-chain attack on direct deps (covered by Dependency
Obituary / govulncheck / CodeQL CI gates), DB host compromise
(trusted infrastructure assumption).

## 3. Threat catalogue

### 3.1 Recompute abuse (DoS via flood + WAL amplification)

**Threat.** An operator (or a buggy UI loop) POSTs
`/ownership/recompute` repeatedly. The engine is heavy: a
streaming RR-transaction over all certs, writes to
`certificate_ownership` + `ownership_match_explanations`, and an
audit row per transition (or one bulk rollup per group). WAL
amplification is measured at ~2.1 KB per changed cert; a 50k-cert
bulk flip is ~100 MB of WAL in one transaction.

**Mitigations.**
- **Per-org session-scope advisory lock** in
  `WithTxLockedOwnershipRepeatableRead` serializes concurrent
  recomputes for the same org. A flood queues; only one is in
  flight at any time.
- **`?nowait=true`** lets a careful client opt out of queueing —
  `pg_try_advisory_lock` returns false → 409
  `ownership_recompute_in_progress`. Recommended for UIs that
  fire on every reload.
- **Idempotency.** A no-op replay (no inputs changed) only bumps
  `last_evaluated_at`; no new explanation rows, no transition
  audit, no bulk rollup. Replay floods are cheap.
- **Bulk audit rollup** prevents audit table amplification during
  the one-off, intentionally large flips (first deploy + fallback
  rule). Threshold tuned per
  `ANCHORIX_OWNERSHIP_BULK_AUDIT_THRESHOLD`.
- Authn (operator session) limits the attacker surface to
  authenticated principals.

**Residual risk.** A flood of distinct-input recomputes (e.g., a
loop creating one rule + recompute + delete rule) is not gated
beyond the per-org lock — they queue and run sequentially, growing
WAL and `governance_recompute_runs` history. Operator-level
remediation: monitor `governance_recompute_runs` row rate.

### 3.2 Preview abuse *(future — H-026B3C)*

**Threat.** Preview reuses the engine over a synthetic rule set
without writing — but the compute is identical to a real
recompute. A flood of previews from one operator can consume the
DB pool.

**Planned mitigations** (B3C):
- Per-request context deadline (`ANCHORIX_OWNERSHIP_PREVIEW_TIMEOUT`,
  default 30s).
- Capped `sample_certs` (≤ 200) per response.
- Snapshot metadata (`snapshot_at`, `ruleset_hash`) lets clients
  detect drift instead of polling.

### 3.3 Ownership poisoning

**Threat.** A malicious operator creates rules that route specific
certificates to a service they control, granting themselves
visibility of those certs' findings + policy enrichment downstream.

**Mitigations.**
- All rule and override mutations are audited at
  severity:"security" (rule_created/_updated/_disabled/_enabled,
  overridden, override_cleared). Audit rows survive code rollback.
- Recompute writes a `governance.recomputed` summary + per-cert
  transition rows (or bulk rollups) at severity:"security", so
  poisoning leaves an evidence trail.
- Explanation rows are persisted: every decision points at a
  `winning_rule_id` and a `signals_seen` snapshot. An operator
  reviewing audit can reconstruct *who routed what to whom*.
- **No silent ownership flips.** The bulk rollup row carries
  count + sample, the `governance.recomputed` carries first_run +
  created_unowned_rows, and per-cert flips are emitted under the
  threshold — operator-visible by design.
- B3A is read-only for rules and overrides; **rule CRUD lands in
  B3B with create-time validators** (regex length, reject
  `service_member`, service existence, tier-vs-kind consistency)
  that catch most operator mistakes at create-time.

**Residual risk.** A malicious operator with valid credentials can
write rules and accept audit visibility — same residual as
`finding.acknowledge` / `finding.suppress` (CLAUDE.md §9). Detection
is operator-policy: review `audit_events` filtered on
`action LIKE 'ownership.%'` and on first-run / bulk-rollup
metadata.

### 3.4 Regex abuse (operator-supplied SAN_regex patterns)

**Threat.** Go's `regexp` is RE2, so classic catastrophic
backtracking is not the threat (no backtracking, linear time). The
real risks are: (a) oversized patterns, (b) expensive giant
alternations that inflate compile cost and per-match CPU/memory,
(c) operator mistake — a pattern that matches far more or less
than intended.

**Mitigations.**
- **Compile once per recompute** (`rules.go`) — not per cert.
- **Length cap** at compile time (`maxRegexPatternLen = 1024`).
- **Fail closed on compile error:** the rule is marked inert
  (never matches) and recorded as a `ruleCompileFailure`. An
  `ownership.rule_compile_failed` audit row is emitted in the
  same transaction so the operator sees the failure without
  bringing down the whole pass.
- **Create-time validation** in B3B will reject oversized /
  invalid patterns at POST so operators get immediate feedback.

**Residual risk.** A pattern within the length cap but with
expensive alternations could slow the recompute; the per-org lock
+ RR snapshot limit blast radius to one org's pass.

### 3.5 Cross-org isolation

**Threat.** A multi-org deployment (single-org per process today,
but the schema carries `organization_id` everywhere). An operator
in org A guesses ids belonging to org B and either reads them or
infers their existence.

**Mitigations.**
- Every read endpoint scopes by `user.OrganizationID` from the
  session. The repository SQL binds the same id; cross-org rows
  are filtered server-side.
- Cross-org ids surface as `404 not_found`, never `403`. An
  attacker cannot distinguish "exists in another org" from "does
  not exist."
- The composite FK pattern (H-009) means even an attacker who
  somehow bypassed the WHERE clause would hit a referential
  integrity failure when reading joined rows.
- The B1 signal-join query is **EXPLAIN-pinned** to be paged by
  `certificates` (the org-scoped driving table) and to never use
  a fleet-wide GROUP BY that could leak across orgs.
- Disabled tags / disabled agent-groups / removed observations
  are excluded from signals (B1 hardening), so org-scoped
  classification never leaks even when soft-deleted state lingers.

**Residual risk.** None reachable in v0.x (single-org per process).
Multi-tenant deployment is out of scope and requires a separate
threat model.

### 3.6 Audit integrity

**Threat.** Audit rows are the only evidence trail for ownership
flips, override grants, and rule edits. If an attacker can suppress
or alter them, governance decisions become unaccountable.

**Mitigations.**
- Audit rows are written **inside the same transaction** as the
  state change (recompute, override clear-on-expiry,
  rule_compile_failed). An audit-write failure rolls back the
  entire pass — there is no half-state where the change persists
  but the audit row does not.
- `audit_events` is append-only at the database level
  (`audit_events_no_update` / `audit_events_no_delete` triggers,
  migration 0001). UPDATE/DELETE on the table fails at the
  trigger; even an attacker with table-level write privilege
  cannot retroactively alter or remove an audit row from inside
  the database (CLAUDE.md §9).
- Bulk rollup rows carry `count`, `from_decision`, `to_decision`,
  `driver_rule_id`, and a 100-cert sample so they remain
  forensically useful — they reduce row count without erasing
  signal.
- The `governance.recomputed` summary always carries `run_id`,
  `first_run`, `created_unowned_rows`, evaluated/changed counters,
  and `engine_version`, giving operators an "is this normal?"
  cross-check on every pass.

**Residual risk.** A SUPERUSER on the database host could disable
the audit triggers. Trust boundary assumption (§1) places the DB
host inside the trusted infrastructure.

### 3.7 Override misuse

**Threat.** An override pins a specific cert to a specific service,
always winning over rules. A malicious or careless operator could
use overrides to misroute high-value certs.

**Mitigations.**
- Every override grant and clear is audited at severity:"security"
  (B2 emits `ownership.override_expired` on auto-clear; B3B will
  add `ownership.overridden` and `ownership.override_cleared` for
  operator actions).
- Overrides MUST carry a `reason` (operator free-text); the partial
  unique index enforces one active override per cert.
- B2 auto-expiry: an override past its `expires_at` is cleared in
  the next recompute with `cleared_by="system"`,
  `cleared_reason="auto-expired"`, freeing the slot and emitting
  `ownership.override_expired`. Expired-but-not-cleared overrides
  cannot accumulate.
- Operator-set `expires_at` is required for time-bounded pins
  (operator-policy in B3B); permanent overrides are visible in
  `/certificates/{id}/ownership/override` as `expires_at: null`
  and remain auditable.

**Residual risk.** A malicious operator with valid credentials can
pin certs at will. Detection: query `audit_events` for
`action='ownership.overridden'` and review per-operator override
rates.

### 3.8 Stale ownership risk

**Threat.** A cert's ownership reflects the state of the world at
the most recent recompute. Between passes, ownership can drift —
the cert's SANs may change (ingestion), rules may be edited, or
the cert may be removed from a host (observation `removed_at`).
An operator acting on stale ownership routes the wrong team.

**Mitigations.**
- `/ownership/stale` surfaces certs whose `last_evaluated_at` is
  older than `ANCHORIX_OWNERSHIP_STALE_THRESHOLD` (default 168h /
  7d). Operators can identify and refresh.
- The recompute is **operator-triggered** in B3A (no scheduler
  yet, B4 work). An operator-visible "trigger recompute" button
  means staleness is operator-aware.
- The `governance.recomputed` summary's `evaluated_certificates`
  count + `engine_version` make it possible to audit how recently
  the engine ran.
- Idempotency means a recompute "just to be safe" is cheap when
  nothing changed.

**Residual risk.** A long gap between recomputes lets ownership
drift. B4 (scheduler) will close this; until then, the stale view
is the operator's mitigation.

### 3.9 Pagination / large result set safety

**Threat.** Endpoints like `/ownership/unowned` can return many
certs (50k on first deploy). A naive client request without paging
could exhaust memory.

**Mitigations.**
- Every paginated endpoint caps `limit` at 200 (returns 400 on
  larger / zero / negative).
- Cursors are base64-encoded opaque strings; the server validates
  and returns 400 on decode failure.
- The B1 storage methods backing these endpoints are cursor-paged
  by `certificate_id` ASC, so each page is a bounded SQL fetch.

### 3.10 Concurrent recompute / operator race

**Threat.** A recompute is in flight when an operator (B3B, future)
edits a rule. Could the operator see inconsistent state, or could
the recompute commit a decision based on a half-edited ruleset?

**Mitigations.**
- The recompute opens a **REPEATABLE READ** snapshot, so the rule
  set it sees is consistent for the whole pass. A concurrent rule
  edit lands in the next pass.
- The session-scope advisory lock serializes concurrent
  recomputes for the same org; a second recompute waits for the
  first to commit before snapshotting.
- Override CRUD in B3B will perform a **single-cert immediate
  re-derivation** under `WithTxLockedOwnership` (xact-scope) so a
  newly-created override is reflected before the response
  returns, but the recompute itself is unaffected.

**Residual risk.** A B3B rule edit committed during a sweep takes
effect at the next recompute; documented in `/ownership-rules`
response as expected behavior (eventual consistency over rule
edits).

## 4. Pre-merge checklist

Required to be true before this PR (B3A) merges:

- [x] Every operator route is behind `RequireAuth`.
- [x] Every operator route is org-scoped on `user.OrganizationID`.
- [x] Cross-org ids surface as 404 (not 403).
- [x] Every paginated route caps `limit ≤ 200` and returns 400 on
      zero/negative/over-cap.
- [x] Cursor strings are validated; bad cursors return 400.
- [x] `?nowait=true` returns 409 `ownership_recompute_in_progress`
      when the lock is held.
- [x] Blocking recompute serializes via the advisory lock under
      contention (no duplicate-key errors).
- [x] Routes are not registered when
      `ANCHORIX_GOVERNANCE_API_ENABLED=false` (404).
- [x] Anonymous requests return 401 on every route.
- [x] Recompute response carries `run_id`, `first_run`,
      `evaluated_certificates`, `changed_certificates`, `duration_ms`
      (and not just `{"status":"ok"}`).
- [x] Engine errors are mapped to operator-friendly envelope codes
      (`ownership_recompute_in_progress`, `bad_request`, `not_found`,
      `internal_error`).

## 5. Open follow-ups (tracked elsewhere)

- **H-027** — ownership explanation retention sweep.
- **H-029** — paginate `ListOverridesExpiringBy`.
- **H-030** — collation-independent stream merge (currently safe;
  documented invariant).
- **B3B** — rule CRUD threat model addendum.
- **B3C** — preview threat model addendum.
- **B4** — scheduler fail-closed behavior, per-org cooldown.
