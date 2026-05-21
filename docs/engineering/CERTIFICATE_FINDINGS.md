# Certificate Findings (H-021)

This document describes Anchorix's certificate findings engine.
Findings are **derived state** over the
[certificate inventory](./CERTIFICATE_INVENTORY.md): a deterministic
rule pass reads the inventory and produces rows in the `findings`
table. The recompute is synchronous, idempotent, and safe to re-run.

This is the H-021 foundation. It is **not** remediation, not
alerting, not a dashboard, not a background worker, not an
ML/AI scorer, not a trust-chain validator, not OCSP/CRL.

## 1. Goal

Give operators a visible answer to "what is wrong with my
certificate inventory?" using rules that are:

- **deterministic** — same inputs always produce the same
  finding rows;
- **explainable** — every finding row carries a stable
  `rule_id`, a static severity, a human-readable title, and a
  per-rule `evidence` JSON object that documents why the rule
  fired;
- **testable** — each rule is a pure function of
  `(certificate, now)` with no I/O, evaluated in unit tests
  alongside its boundary cases;
- **organization-scoped** — every read and write is bound by
  `organization_id`;
- **safe to regenerate** — re-running recompute against
  unchanged inventory is a counter-only operation (no INSERTs,
  no resolves). Re-running against changed inventory diffs to
  exactly the changed set.

## 2. Source of truth

The authoritative inputs are:

- `certificates` (one row per `(organization_id,
  fingerprint_sha256)` cert seen by the fleet).
- `certificate_observations` (one row per `(organization_id,
  certificate_id, agent_id, store_location)` sighting).

Findings are derived from `certificates` only. v0.1 rules do
not yet consume the observation set — finding identity is
**certificate-wide**, not observation-wide. A cert that fires
`weak_rsa_key` produces ONE finding regardless of how many
agents or stores observed it.

## 3. Data model

### `findings` table

Defined in migrations `0001_init.sql` (initial shape) +
`0006_findings_lifecycle.sql` (lifecycle columns + composite FK).
Columns the H-021 implementation depends on:

| column            | type        | meaning                                                |
| ----------------- | ----------- | ------------------------------------------------------ |
| `id`              | TEXT PK     | service-minted hex id                                  |
| `organization_id` | TEXT FK     | always set; scopes every read                          |
| `certificate_id`  | TEXT        | composite FK to `certificates(organization_id, id)` (0006) |
| `rule_id`         | TEXT        | stable rule identifier (e.g. `weak_rsa_key`)            |
| `rule_version`    | INTEGER     | bumped when the rule body changes (0006)                |
| `severity`        | TEXT enum   | `info`/`low`/`medium`/`high`/`critical`                |
| `status`          | TEXT enum   | `open`/`resolved` (v0.1); `acknowledged`/`suppressed` reserved |
| `title`           | TEXT        | short human-readable label                             |
| `evidence`        | JSONB       | per-rule explanation payload                            |
| `opened_at`       | TIMESTAMPTZ | API: `first_seen_at` — preserved across resolve↔reopen |
| `last_seen_at`    | TIMESTAMPTZ | every recompute that re-confirms bumps this (0006)      |
| `resolved_at`     | TIMESTAMPTZ | non-NULL when status=`resolved` (0006)                  |
| `updated_at`      | TIMESTAMPTZ | touched on any state change                             |

### Identity

`UNIQUE (organization_id, certificate_id, rule_id)` is the
finding identity key. There is never more than one row for the
same (org, cert, rule) triple — resolves and reopens UPDATE the
existing row.

### Composite FK

`FOREIGN KEY (organization_id, certificate_id) REFERENCES
certificates(organization_id, id) ON DELETE CASCADE` — the
PR-019 H-009 cross-org-safety pattern. A buggy repo writing a
finding whose `organization_id` disagrees with the cert's own
`organization_id` is rejected at the DB level.

## 4. Rule registry (v0.1)

Six rules, each a small pure function. All live in
`internal/findings/rules_certificate.go` and are wired via
`findings.DefaultRules()`.

| rule_id                      | severity | rule body                                                                 | evidence fields                                                          |
| ---------------------------- | -------- | ------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| `certificate_expired`        | high     | `now.After(cert.NotAfter)`                                                | `not_after`, `expired_for`                                               |
| `certificate_expiring_soon`  | medium   | `cert.NotAfter > now AND cert.NotAfter <= now + 30d`                      | `not_after`, `expires_in`, `window_days`                                 |
| `weak_signature_algorithm`   | high     | sig algo name contains `MD5` or `SHA1` (case-insensitive)                 | `signature_algorithm`, `weak_hash`                                       |
| `weak_rsa_key`               | high     | `key_alg = RSA AND bits < 2048`                                           | `public_key_algorithm`, `public_key_bits`, `threshold_bits`              |
| `self_signed_leaf`           | medium   | `is_self_signed AND NOT is_ca`                                            | `subject`                                                                |
| `long_lived_certificate`     | low      | `NOT is_ca AND (not_after - not_before) > 398d`                           | `not_before`, `not_after`, `validity_days`, `threshold_days`             |

### Rule boundaries (pinned by `rules_test.go`)

- `certificate_expired` uses **strict-after** on `now > NotAfter`;
  a cert with `NotAfter == now` is NOT yet expired.
- `certificate_expiring_soon` uses **`NotAfter > now AND
  NotAfter <= now + 30d`** — the 30-day mark IS in-window; the
  rule does NOT overlap with `certificate_expired`.
- `weak_rsa_key` uses **strict-less** on the threshold;
  exact 2048-bit RSA does NOT trigger.
- `long_lived_certificate` uses **strict-greater**; exactly 398
  days does NOT trigger.
- `self_signed_leaf` scopes out CAs deliberately — self-signed
  CAs are operationally normal (they ARE roots).
- `long_lived_certificate` scopes out CAs deliberately — CAs
  legitimately have long lifetimes.

### Severity policy

Severity is **statically mapped per rule** in v0.1. Different
RSA bit-sizes do NOT produce different severities; that's a
future refinement. Operators who want finer granularity will
get it via the (out-of-scope) override workflow.

## 5. Recompute lifecycle

`POST /api/v1/findings/recompute` invokes `Service.Recompute`.
The pass runs under
`Transactor.WithTxLockedFindingsRepeatableRead` (H-024B): a
session-scope advisory lock on `(findings-recompute, orgID)`
serializes concurrent recomputes for the same org, then a
REPEATABLE READ transaction opens AFTER the lock is held so
every paginated read inside the recompute sees ONE consistent
input snapshot. The lock-before-snapshot ordering is binding —
acquiring an xact-scope lock inside the REPEATABLE READ tx
would let the second tx's snapshot fix BEFORE the first tx
commits, defeating snapshot isolation and re-introducing the
unique-constraint race the H-021 advisory lock was meant to
prevent.

The streaming pass (`Service.runDiffStreaming`):

1. **Phase 1 — Page certs by id ASC.** Calls
   `CertificateLister.ListCertificateBareSummariesForOrgPaged`
   in pages of `recomputeStreamingPageSize = 500`. The "bare"
   variant deliberately omits the two scalar
   observation-count subqueries that the operator list path
   needs, shaving N×2 subquery executions per page. For each
   cert × rule, evaluate the rule. Matches accumulate into the
   `matches map[matchKey]matchEntry` keyed by
   `(cert_id, rule_id)`.
2. **Phase 2 — Page existing findings by id ASC.** Calls
   `Repository.ListAllFindingsForOrgPaged` in pages of the
   same size. For each finding:
   - If `matches[key]` exists →
     `decideMatchTransition(prior, rule, match, now)`, then
     `delete(matches, key)` so phase 3 only sees never-existed
     keys.
   - Else → `decideNoMatchTransition(prior, now)`.
3. **Phase 3 — Remaining matches.** Entries left in the map
   after phase 2 have no prior finding row, so they're
   brand-new INSERTs. `decideMatchTransition(nil, ...)`
   produces the new row.
4. Insert the single `findings.recomputed` audit row with the
   counter set in `metadata` (including the H-024B additive
   fields `loaded_certificates` and `loaded_findings`).
5. Commit; the deferred path releases the session lock and
   returns the connection to the pool.

The per-(cert, rule) decisions live in
`internal/findings/service_diff.go` as `decideMatchTransition`
and `decideNoMatchTransition` — pure functions of
`(prior, rule, match, now)`. Both the streaming path
(production) and the legacy load-all path
(`Service.RecomputeLegacyLoadAll`, retained for the H-024B
byte-identical equivalence test) consume the same helpers,
which is what guarantees final table state matches between
the two implementations.

### State transitions (matrix preserved across paths)

| prior status | rule matches | action                                                                |
| ------------ | ------------ | --------------------------------------------------------------------- |
| (no row)     | yes          | INSERT open; counter `opened++`                                       |
| open         | yes          | UPDATE rule-derived fields; counter `updated++`                       |
| resolved     | yes          | UPDATE → open, preserve `first_seen_at`; counter `opened++`           |
| acknowledged | yes          | UPDATE rule-derived, preserve override metadata; counter `updated++`  |
| suppressed   | yes (live)   | UPDATE rule-derived, preserve override metadata; counter `updated++`  |
| suppressed   | yes (expired)| UPDATE → open, clear override metadata; counter `opened++`            |
| open         | no           | UPDATE → resolved, stamp `resolved_at`; counter `resolved++`          |
| ack / sup    | no           | UPDATE → resolved, clear override metadata; counter `resolved++`      |
| resolved     | no           | no write; counter `unchanged++`                                       |
| any other    | either       | `ErrUnsupportedFindingStatus` (fail loudly)                           |

### Determinism

Rules are pure. Given the same (cert summary, now), evaluation
produces the same match decision and the same evidence. The
recompute SQL is deterministic — `UPDATE` predicates bind on
`(id, organization_id)`, ordering for paginated reads is
`id ASC`, and the rule pass walks `certs ASC, rules in
registration order`.

REPEATABLE READ pins the snapshot at the first statement of
the tx, taken AFTER the session-scope lock is acquired. A
concurrent ingestion batch that commits during the recompute
is INVISIBLE to the in-flight pass; the next recompute will
see it.

A recompute against unchanged inventory at the same wall-clock
second produces:

- `opened = 0`
- `updated = N` (one update per still-matching finding)
- `resolved = 0`
- `unchanged = M` (any pre-existing resolved findings)

### Snapshot isolation guarantee (H-024B)

The lock-before-snapshot ordering is exercised by
`backend/test/integration/findings_streaming_test.go`
`TestFindingsStreamingRecomputeSnapshotIsolation`, which
commits a new weak-RSA cert through a deterministic channel
barrier WHILE a streaming recompute is between cert pages
and asserts the in-flight recompute does NOT see it. Without
the session-scope lock + REPEATABLE READ this test fails.

### Byte-identical equivalence with the legacy load-all path

`TestFindingsByteIdenticalLoadAllVsStreaming` seeds the
Smallv01 fixture twice (fresh DB between runs), runs
`RecomputeLegacyLoadAll` against one copy and `Recompute`
against the other, and asserts the resulting `findings`
tables are equivalent up to row IDs (which are crypto/rand
freshly minted on each insert). The legacy path stays in
tree until the post-H-024B-soak cleanup PR (per
[`H024_PERFORMANCE_PLAN.md`](./H024_PERFORMANCE_PLAN.md)
§9.B item 3); no other caller depends on it.

### Audit-transaction coupling

The `findings.recomputed` audit row is inserted inside the same
transaction as the finding state changes. An audit failure
rolls back the entire recompute. `service_test.go`
TestServiceRecompute_AuditFailureRollsBackFindings pins this
with a fake audit recorder that errors on Record.

### Read endpoints emit no audit

`GET /findings`, `GET /findings/{id}` are read-only —
`CLAUDE.md §9` reserves audit for state changes. An integration
test (`TestFindingsReadEndpointsEmitNoAuditRows`) diffs the
`audit_events` count before/after a read sweep to catch
regressions.

### Defensive: unsupported finding status fails loudly

`decideMatchTransition` and `decideNoMatchTransition` handle
exactly `StatusOpen`, `StatusResolved`, `StatusAcknowledged`,
and `StatusSuppressed`. Any other value hits an explicit
`default:` arm that returns `ErrUnsupportedFindingStatus`.
This is intentional: an earlier draft used `default: // …`
fall-throughs which would have silently mis-handled a future
status addition.

Pinned by `service_test.go`
`TestServiceRecompute_UnsupportedStatusFailsLoudly_StillMatching`
and `_NoLongerMatching`.

## 6. API

See [REST_API.md "Findings"](../api/REST_API.md#findings) for
the wire contract.

- `POST /api/v1/findings/recompute` (operator) — synchronous
  recompute; returns the counter set.
- `GET /api/v1/findings` (operator) — paginated list, default
  `status=open`; filters: `status`, `severity`, `rule_id`,
  `certificate_id`, `cursor`, `limit`.
- `GET /api/v1/findings/{id}` (operator) — single finding; the
  detail shape equals the list-row shape (small payloads in v0.1
  — evidence is a few-hundred-byte JSON object).

Cross-org / missing ids return `404 not_found`. Agent bearer
credentials are NOT honored.

## 7. Background scheduler (H-022)

A single in-process scheduler started from the composition
root (`cmd/anchorix/serve.go`) recomputes findings on a tick,
per organization, without operator-triggered HTTP calls. The
manual `POST /findings/recompute` endpoint remains available
for on-demand recomputes — the scheduler is additive, not a
replacement.

### Configuration

| Env var                                  | Default | Meaning                                                          |
| ---------------------------------------- | ------- | ---------------------------------------------------------------- |
| `ANCHORIX_FINDINGS_SCHEDULER_ENABLED`    | `true`  | When `false`, the loop never ticks (NewScheduler still wires).   |
| `ANCHORIX_FINDINGS_SCHEDULER_INTERVAL`   | `6h`    | Spacing between ticks. Must be ≥ 30s when enabled.               |

Validation runs at startup in `internal/config.validate` so a
misconfigured deployment fails closed before the scheduler is
constructed.

### Architecture

- One long-running goroutine owned by the composition root.
- Cancellation path: `context.Context` propagated from
  `serve.go`. On signal, `ticker` is stopped and `Run` returns
  nil; the deferred `db.Close()` waits for the goroutine to
  drain via a `schedDone` channel.
- No external scheduler system, no distributed coordination,
  no cron dependency.

### Audit envelope

Scheduled recomputes write `findings.recomputed` audit rows
with `actor="scheduler"` and `actor_type="system"` (the
`findings.SchedulerActorID` constant). This is distinct from
operator-triggered recomputes, which carry the real user ID
with `actor_type="user"`. Operators filtering audit history
can therefore separate scheduled vs manual runs without
inspecting metadata.

Pinned by `TestFindingsRecomputeScheduledWritesSchedulerActor`.

### Error handling

- **Failure in one org's recompute** — logged with structured
  fields (organization_id, duration, err). The loop continues
  to the next org. No global stop.
- **Panic in one org's recompute** — recovered in
  `Scheduler.recomputeOrg`'s deferred `recover()`. Logged with
  the panic message. The loop continues.
- **Organization-lister failure** — logged. The current sweep
  is skipped; the next tick retries. No global stop.

### Concurrency with manual recompute

The scheduler does NOT add a second lock layer. The
`WithTxLockedFindings` advisory lock already serializes
concurrent recomputes per-organization (PR-021 / PR-026
H-017 pattern). A scheduled run and a simultaneous manual run
for the same org block at the lock barrier; whichever wins
sees the other's state on its next read.

Pinned by `TestFindingsRecomputeScheduledSerializesWithManual`
(5 iterations of concurrent manual + scheduled recompute; both
must return without error and findings count must stay at 1).

### Observability

Structured `info` log per successful org recompute, with
fields: `organization_id`, `duration`, `evaluated_certificates`,
`opened`, `updated`, `resolved`, `unchanged`, `rule_count`.
Structured `error` log per failure (or panic) with `err` /
`panic` fields. No metrics system in v0.1.

## 8. Operator override workflow (H-023)

Operators can override the recompute's default open/resolved
decisions via two POST endpoints. The current state goes onto
the `findings` row (denormalized current intent); the immutable
history goes into `audit_events`. The recompute pass honors
overrides during subsequent ticks per the transition table
below.

### Status state machine

```
                  +-----------+   ack    +--------------+
                  |   open    |--------->| acknowledged |
                  +-----------+          +--------------+
                       |                          |
                       | resolve / no-match       | no-match
                       v                          v
                  +-----------+                +-----------+
                  | resolved  |<---------------|           |
                  +-----------+                +-----------+
                       ^                          ^
                       | rule no longer matches   | rule still
                       |                          | matches
                  +-----------+   suppress  +--------------+
                  |   open    |------------>|  suppressed  |
                  +-----------+             +--------------+
                                              |        |
                                expired+match |        | no-match
                                              v        v
                                         (back to open) / resolved
```

### Recompute transition table

| Current status | Rule matches | Action                                      |
| -------------- | ------------ | ------------------------------------------- |
| open           | yes          | UPDATE (last_seen_at bumped)                |
| open           | no           | resolve                                     |
| resolved       | yes          | reopen → open (first_seen_at preserved)     |
| resolved       | no           | unchanged                                   |
| acknowledged   | yes          | UPDATE; override metadata PRESERVED         |
| acknowledged   | no           | resolve; override metadata CLEARED          |
| suppressed     | yes, expired | reopen → open; override metadata CLEARED    |
| suppressed     | yes, live    | UPDATE; override metadata PRESERVED         |
| suppressed     | no           | resolve; override metadata CLEARED          |

### Override metadata columns (migration 0007)

| Column                | Type        | Meaning                                                |
| --------------------- | ----------- | ------------------------------------------------------ |
| `status_reason`       | TEXT        | Operator's free-text reason (≤ 1000 bytes).            |
| `status_actor`        | TEXT        | User id who set the override.                          |
| `status_changed_at`   | TIMESTAMPTZ | Wall-clock at the time of the operator action.         |
| `suppress_expires_at` | TIMESTAMPTZ | Only set when status=suppressed AND operator gave one. |

All four are nullable. They are CLEARED back to NULL by the
recompute when it transitions a finding OUT of an override
(resolve from acknowledged/suppressed; reopen from expired
suppression). The original override action remains in
`audit_events` forever.

### Endpoints

```
POST /api/v1/findings/{id}/acknowledge   body: {"reason": "..."}
POST /api/v1/findings/{id}/suppress      body: {"reason": "...", "expires_at": "RFC3339"|null}
```

Both are operator-only (RequireAuth + session resolver), org-
scoped, with cross-org / missing id → 404 not_found and agent
bearer → 401 unauthorized.

### Validation

- `reason` is required, trimmed-non-empty, ≤ `MaxOverrideReasonLength` (1000 bytes).
- `expires_at` is optional on suppress. If present, MUST be
  strictly in the future (`> now`). The service re-checks
  with the injected clock; the HTTP handler does no separate
  time check.

### Audit envelope

```
action:       finding.acknowledged | finding.suppressed
actor:        <user.id>
actor_type:   user
target_type:  finding
target_id:    <finding.id>
metadata: {
  "severity":         "security",
  "organization_id":  "...",
  "finding_id":       "...",
  "previous_status":  "open" | "acknowledged" | ...,
  "new_status":       "acknowledged" | "suppressed",
  "reason":           "<operator's text>",
  "suppress_expires_at": "RFC3339" | absent
}
```

`severity: "security"` per CLAUDE.md §9 — finding overrides are
explicitly listed as security events.

The audit row is INSERTED in the same transaction as the
status update (the per-org `WithTxLockedFindings` advisory
lock serializes the override with concurrent recomputes for
the same org). An audit failure ROLLS BACK the override.

## 9. Non-goals (still out of scope)

- **Alerting / notification** — no push, no email, no
  webhooks.
- **Trust-chain validation, OCSP, CRL** — out of scope; the
  inventory does not yet carry chain state.
- **Dynamic severity** — the static per-rule mapping is the
  v0.1 contract.
- **Findings UI** — no React component, no dashboard widget;
  the API is the v0.1 surface.

## 10. Status

| Phase                                       | Status                |
| ------------------------------------------- | --------------------- |
| H-021 design (this doc)                     | shipped (PR #30)      |
| H-021 implementation                        | shipped (PR #30)      |
| H-022 scheduled recompute                   | shipped (PR #32)      |
| H-023 acknowledge / suppress workflow       | shipped (PR #34)      |
| H-024A perf groundwork                      | shipped (PR #37)      |
| H-024A post-groundwork hardening            | shipped (PR #38)      |
| H-024B streaming recompute + REPEATABLE READ| **shipped (this PR)** |
| Legacy load-all cleanup PR (post-soak)      | deferred              |
| H-025 per-recompute timeout                 | HARDENING_BACKLOG     |

## 11. References

- [CLAUDE.md](../../CLAUDE.md) §6 (deterministic auth), §8.6
  (consumer-owned interfaces), §8.8 (constructor DI), §9 (audit
  policy), §16 (append-only migrations), §17 (additive API
  evolution), §18 (graceful state machines).
- [CERTIFICATE_INVENTORY.md](./CERTIFICATE_INVENTORY.md) §3, §10
  (data model and fleet sizing assumptions).
- [REST_API.md](../api/REST_API.md) "Findings" (wire contract).
