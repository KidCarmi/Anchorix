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
The pass:

1. Open a transaction (`Transactor.WithTx`).
2. Load every certificate summary for the organization
   (`CertificateLister.ListAllCertificateSummariesForOrg`). v0.1
   fleet scale per [CERTIFICATE_INVENTORY.md §10](./CERTIFICATE_INVENTORY.md)
   is ≤ 1K certs per org; the full snapshot fits comfortably in
   memory. A backlog entry tracks the findings-era replacement
   (paginated scan).
3. Run every registered rule against every cert. Each match
   becomes a `(cert_id, rule_id) → evidence` entry in an
   in-memory map.
4. Load every existing finding for the organization
   (`Repository.ListAllForOrg`).
5. Walk the rule-match map:
   - **No existing row**: INSERT a new open finding. Counter
     `opened++`.
   - **Existing OPEN row**: UPDATE `last_seen_at`, `severity`,
     `title`, `rule_version`, `evidence`. Counter `updated++`.
   - **Existing RESOLVED row** (rule matches again): UPDATE to
     `status=open`, `last_seen_at=now`, `resolved_at=NULL`.
     `opened_at` (API: `first_seen_at`) stays at the original
     detection time. Counter `opened++` — from the operator's
     POV the finding is newly visible again.
6. Walk the existing-findings map:
   - **OPEN row not in match set**: UPDATE to
     `status=resolved`, `resolved_at=now`. `last_seen_at` is
     unchanged. Counter `resolved++`.
   - **RESOLVED row not in match set**: nothing to do. Counter
     `unchanged++`.
7. Insert the single `findings.recomputed` audit row with the
   counter set in `metadata`.
8. Commit.

### Determinism

Rules are pure. Given the same (cert summary, now), evaluation
produces the same match decision and the same evidence. The
recompute SQL is deterministic — `UPDATE` predicates bind on
`(id, organization_id)`, ordering for the existing-findings
load is `id ASC`, and the rule pass walks `certs ASC, rules in
registration order`.

A recompute against unchanged inventory at the same wall-clock
second produces:

- `opened = 0`
- `updated = N` (one update per still-matching finding)
- `resolved = 0`
- `unchanged = M` (any pre-existing resolved findings)

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

`Service.runDiff`'s state-transition switches handle exactly
`StatusOpen` and `StatusResolved`. Any other value (the
schema-reserved `acknowledged` / `suppressed`, or any future
addition) hits an explicit `default:` arm that returns
`ErrUnsupportedFindingStatus`. This is intentional: an earlier
draft used `default: // resolved → reopen` which would have
silently flipped a future `suppressed` finding back to `open`
on every recompute, defeating the override workflow's purpose.

The defensive arm is the H-023 breadcrumb: when the override
workflow ships, it MUST extend both switches in `runDiff`
(matches loop AND unmatched loop) to decide what to do for
each reserved value. Until then, the path is unreachable
because v0.1 has no public surface that writes those status
values.

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

## 8. Non-goals (out of scope for H-021)

- **Remediation workflow** — no mutation surface beyond
  `recompute`. Acknowledge / suppress are reserved by the
  schema's `status` CHECK but the HTTP handlers stay as
  `notImplemented` stubs.
- **Alerting / notification** — no push, no email, no
  webhooks.
- **Background scheduler** — `recompute` runs on operator
  demand only. A scheduled recompute is a future follow-up.
- **Trust-chain validation, OCSP, CRL** — out of scope; the
  inventory does not yet carry chain state.
- **Dynamic severity** — the static per-rule mapping is the
  v0.1 contract.
- **Findings UI** — no React component, no dashboard widget;
  the API is the v0.1 surface.

## 9. Status

| Phase                             | Status                                  |
| --------------------------------- | --------------------------------------- |
| H-021 design (this doc)           | shipped (PR #30)                        |
| H-021 implementation              | shipped (PR #30)                        |
| H-022 scheduled recompute         | **shipped** (this PR)                   |
| H-023 acknowledge / suppress workflow | HARDENING_BACKLOG follow-up         |
| H-024 findings performance optimization | HARDENING_BACKLOG follow-up       |

## 10. References

- [CLAUDE.md](../../CLAUDE.md) §6 (deterministic auth), §8.6
  (consumer-owned interfaces), §8.8 (constructor DI), §9 (audit
  policy), §16 (append-only migrations), §17 (additive API
  evolution), §18 (graceful state machines).
- [CERTIFICATE_INVENTORY.md](./CERTIFICATE_INVENTORY.md) §3, §10
  (data model and fleet sizing assumptions).
- [REST_API.md](../api/REST_API.md) "Findings" (wire contract).
