# Certificate Inventory — Design

> **Status:** design only. Implementation lands in dedicated follow-up
> PRs (see "Recommended PR sequence" below). This document is the
> source of truth for those PRs' contracts.
>
> **Source of truth for rules:** [`CLAUDE.md`](../../CLAUDE.md). If
> this design and CLAUDE.md disagree, CLAUDE.md wins and this
> document is updated.

## Goal and motivation

Anchorix's stated v0.1 mission (`CLAUDE.md` §1) is certificate
**discovery**, **inventory**, **risk identification**, and
**visibility** above existing PKI infrastructure. Heartbeat
(`PR-017`), machine-inventory snapshot (`PR-018` / `H-010`), and
agent rebind / rotation (`H-006` design, H-012/H-013
implementation) are the precursors. This design defines the
ingestion model for the central data domain — the certificates
themselves and where they've been observed.

The work is sequenced after the H-006 design **specifically because
certificate observations attach to `agent_id`**: rebind preserving
`agent_id` is the precondition that makes observation continuity
work across reinstalls. Without H-006's commitment, every
reinstalled host would orphan its certificate history. With it,
the operator's view of "what's on workstation 001" survives every
reinstall, OS rebuild, and credential rotation.

The design also commits to a model that **never accepts private
keys**. `CLAUDE.md` §6.2 is the binding rule; this document
operationalizes it through detection, rejection envelope, and
audit policy.

## 1. Data model

Two tables. The `certificates` table is per-organization,
deduplicated by SHA-256 fingerprint of the canonical DER form. The
`certificate_observations` table records every (agent, store)
where each certificate has been seen.

The shapes below match what `internal/inventory/types.go` already
sketches (the v0.1 schema proposal anticipated this domain). The
*storage* implementation lands in H-014; this doc only commits to
the shapes.

### `certificates` (proposed)

```sql
CREATE TABLE certificates (
    id                      TEXT        PRIMARY KEY,
    organization_id         TEXT        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    fingerprint_sha256      TEXT        NOT NULL,
    subject                 TEXT        NOT NULL,
    issuer                  TEXT        NOT NULL,
    serial_number_hex       TEXT        NOT NULL,
    signature_algorithm     TEXT        NOT NULL,
    public_key_algorithm    TEXT        NOT NULL,
    public_key_bits         INTEGER     NOT NULL,
    not_before              TIMESTAMPTZ NOT NULL,
    not_after               TIMESTAMPTZ NOT NULL,
    sans                    JSONB       NOT NULL DEFAULT '[]'::jsonb,
    key_usages              JSONB       NOT NULL DEFAULT '[]'::jsonb,
    ext_key_usages          JSONB       NOT NULL DEFAULT '[]'::jsonb,
    is_self_signed          BOOLEAN     NOT NULL DEFAULT FALSE,
    is_ca                   BOOLEAN     NOT NULL DEFAULT FALSE,
    pem                     TEXT        NOT NULL, -- PUBLIC certificate PEM only.
    first_seen_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, fingerprint_sha256)
);
```

### `certificate_observations` (proposed)

```sql
CREATE TABLE certificate_observations (
    id              TEXT        PRIMARY KEY,
    organization_id TEXT        NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    certificate_id  TEXT        NOT NULL,
    agent_id        TEXT        NOT NULL,
    store_location  TEXT        NOT NULL,
    friendly_name   TEXT        NOT NULL DEFAULT '',
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at    TIMESTAMPTZ NOT NULL,
    removed_at      TIMESTAMPTZ,
    UNIQUE (organization_id, certificate_id, agent_id, store_location),
    -- Composite FK matching PR-019 H-009 pattern: snapshot org MUST
    -- match agent org at the DB level.
    FOREIGN KEY (organization_id, agent_id)
        REFERENCES agents(organization_id, id) ON DELETE CASCADE,
    -- certificate_id always belongs to the same org as the
    -- observation (enforced by the composite FK below).
    FOREIGN KEY (organization_id, certificate_id)
        REFERENCES certificates(organization_id, id) ON DELETE CASCADE
);
```

### Field-level rules

- **`fingerprint_sha256`** is computed by the **control plane**
  from the canonical DER form of the agent-supplied PEM. The agent
  may supply a fingerprint in the request body for diagnostic
  comparison, but the server NEVER trusts an agent-supplied value
  as the identity primitive. This mirrors how agent identity is
  decided by the credential, not by hostname or `install_id`
  (H-006 §3).
- **`pem`** stores the **public certificate only**. Private keys
  are rejected at the API boundary (§7). The PEM is canonical (the
  raw bytes the agent sent, normalized to a single
  `-----BEGIN/END CERTIFICATE-----` block).
- **`is_self_signed`** is computed by the server. The server
  trusts the cert's structure for this; the cert is self-signed if
  `subject == issuer` AND signature verifies against the cert's
  own public key. Bare `subject == issuer` without signature
  verification is insufficient (an attacker could mint a cert with
  the same subject/issuer strings but a different signer).
- **`is_ca`** is read from the cert's BasicConstraints extension.
- **Normalized fields** are the server's parsed view. Even if the
  agent supplies pre-parsed metadata in the request body (it
  shouldn't — see §4), the server's parse is authoritative.

### Why deduplicate by fingerprint

A fleet of 10,000 Windows hosts shares root certs, intermediate
CAs, internal-CA-signed leafs deployed via SCCM, and so on.
Deduplicating by fingerprint keeps the `certificates` table O(N)
in the number of *distinct* certs in the org (low thousands),
not O(N × agents) which is multiplicative.

The `certificate_observations` table grows linearly with
(distinct certs) × (agents that observed them) × (stores on each
agent). For a 10K-host fleet with ~100 certs per host (5 stores
each) and ~50% shared, that's ~5M observation rows. Manageable
with the indexes proposed in §10.

### Why store the PEM

Operators may want to download the cert for offline inspection,
load it into an external tool, or pass it to a future
chain-validation step. Future findings (Phase 4) may also want
to re-parse extensions the v0.1 schema doesn't normalize
explicitly. Storing the raw PEM keeps that future open without
forcing a re-collection from agents.

Cost: ~1-4 KiB per distinct cert. For ~5,000 distinct certs in a
large fleet, ~10-20 MB total. Negligible.

## 2. Observation continuity

This section is the design's explicit dependency on H-006
([`AGENT_REINSTALL_REBIND.md`](./AGENT_REINSTALL_REBIND.md)).

| Scenario                                          | `agent_id` outcome   | Observation continuity                                                                 |
| ------------------------------------------------- | -------------------- | -------------------------------------------------------------------------------------- |
| Agent enrolls fresh                               | New `agent_id`       | Fresh observation lineage starts.                                                       |
| Agent is rebound (H-006 flow)                     | **Same `agent_id`**  | Observations remain attached. The history "cert X was on this host since DATE" survives the reinstall. |
| Agent is force-revoked + a fresh installer enrolls| New `agent_id`       | Fresh observation lineage; the old observations remain queryable but no longer receive updates. |
| Agent rotates credential (H-013 flow)             | Same `agent_id`      | No effect on observations.                                                              |
| Agent's `hostname` changes                        | Same `agent_id`      | No effect on observations. Hostname is descriptive only.                                |

The first three rows are the operator-visible distinction.
Operators choose continuity vs clean-break **at rebind time** by
deciding whether to issue a rebind token (continuity) or to do a
revoke + redeploy with a fresh installer (clean break).

Without this commitment, the ingestion model would have to deal
with "merge two agents' histories when one is recognized as a
reinstall of the other" — an ops burden the design explicitly
avoids.

## 3. Snapshot vs observation semantics

Machine inventory (`PR-018`) is **snapshot/replace**: one current
row per agent, UPSERTed in place, no history.

Certificate observations are **set-reconciliation per store**:
each upload describes the complete set of certs the agent
currently observes in a declared set of stores; the server
reconciles by marking absent observations as `removed_at` and
clearing `removed_at` when an absent cert reappears.

### Decision: scope each upload by `store_coverage` (required, non-empty)

Each batch declares which stores it covers:

```json
{
  "collected_at": "2026-05-16T14:00:00Z",
  "store_coverage": ["LocalMachine\\My", "LocalMachine\\WebHosting"],
  "certificates": [...]
}
```

`store_coverage` is **required and must be non-empty**. The server
rejects a missing or empty `store_coverage` with `400 bad_request`.
There is no implicit "upsert-only / no-reconcile" mode in v0.1 — see
"Why store_coverage is required" below.

Reconciliation is then well-defined:

1. For every `(agent_id, store_location)` pair in `store_coverage`:
   - Upsert observations present in the batch. Set
     `last_seen_at = collected_at` and `removed_at = NULL`.
   - Existing observations NOT in the batch: set
     `removed_at = collected_at` if currently NULL. Leave
     `last_seen_at` untouched.
2. Observations whose `store_location` is **not** in
   `store_coverage` are untouched. Allows an agent to upload one
   store at a time without affecting others — but the agent MUST
   declare which stores it is uploading, even if it is uploading
   only one.

### Why store_coverage is required

Allowing an empty `store_coverage` would create two ingestion
modes for the same endpoint:

1. Full-set reconciliation for declared stores.
2. Upsert-only / no-reconcile partial mode.

That ambiguity is unsafe. A buggy agent that accidentally omits
`store_coverage` (or sends it empty) would silently stop
reconciliation: certificates that disappear from the host would
remain marked "currently observed" forever, polluting operator
queries and any future findings that depend on currency.

v0.1 fail-closes: the agent declares the stores it fully
observed, the server reconciles exactly those stores, no
implicit partial mode. If an explicit upsert-only mode ever
becomes operationally necessary, it lands as a separate field
(e.g. `mode: "upsert_only"`) with its own audit posture — never
as the absent-field default.

### Why set-reconciliation, not delta

A pure delta model (agent reports only "new since last upload")
requires the agent to track what it has reported. State on the
agent is fragile (lost on reinstall, on credential rotation, etc.).
A full-set-per-store model lets the agent be stateless — it
enumerates the store at each collection cycle and the server
reconciles.

It also matches operator intuition: "tell me what's on this
machine *right now*" is a meaningful query, and the answer is the
union of all observations with `removed_at IS NULL`.

### Why NOT a snapshot/replace model

Snapshot/replace would mean each upload replaces ALL observations
for the agent. That model has two problems:

- An upload covering one store would wipe observations for every
  other store. The agent would have to upload every store every
  time, even unchanged ones. Heavy and pointless.
- It loses the "this cert was here yesterday, gone today" signal.
  Set reconciliation preserves it cleanly via `removed_at`.

### v0.1 history retention

Latest-state only. Each `(agent_id, store_location, certificate_id)`
has exactly one observation row. Re-appearances clear `removed_at`
and bump `last_seen_at`; they do not create a new row.

A future "audit-style observation history" table (every
appear/disappear as a separate row) is explicitly **out of scope**.
The audit_events table already provides high-level signals for
state changes operators care about; per-cert-per-event history
multiplies cardinality by orders of magnitude without obvious
operator value.

## 4. Ingestion API contract

Future endpoint shape. **No implementation in this PR.**

### `POST /api/v1/agent/certificates`

Singular `/agent/*` prefix matches the established convention for
agent-bearer-keyed routes (`/agent/me`, `/agent/heartbeat`,
`/agent/inventory`).

**Auth:** `RequireAuthenticatedAgent` (existing middleware).
Operator session cookies are NOT honored. Identity (`agent_id`,
`organization_id`) comes from `AgentFromContext`, NEVER from the
request body.

### Request

```json
{
  "collected_at": "2026-05-16T14:00:00Z",
  "store_coverage": ["LocalMachine\\My", "LocalMachine\\WebHosting"],
  "certificates": [
    {
      "store_location": "LocalMachine\\My",
      "friendly_name": "ws-001.corp.example",
      "certificate_pem": "-----BEGIN CERTIFICATE-----\n..."
    },
    {
      "store_location": "LocalMachine\\WebHosting",
      "certificate_pem": "-----BEGIN CERTIFICATE-----\n..."
    }
  ]
}
```

Field rules:

- **`collected_at`** is the agent's wall-clock time of collection.
  Used as the observation's `last_seen_at` and `removed_at` on
  reconciliation. Future > now + 24h is rejected as clock skew
  (matches the existing v0.1 inventory contract in REST_API.md).
- **`store_coverage`** is the explicit list of stores this batch
  reconciles. **Required and non-empty** — see §3 "Why
  store_coverage is required" for the rationale. A missing or
  empty `store_coverage` returns `400 bad_request`. Stores
  outside the list are untouched by this batch; the agent MUST
  declare every store it observed in this batch even if it is
  uploading only one.
- **`certificates`** is the array of observed certs. Every
  entry's `store_location` MUST be in `store_coverage`. The
  server rejects the batch otherwise with `400 bad_request` and
  reason metadata `unknown_store_location` (in audit, not on the
  wire).
- **`certificate_pem`** is the wire format. Required.
- **`friendly_name`** is descriptive, optional, capped at 255 bytes.
- The agent does NOT supply parsed metadata (subject, issuer,
  fingerprint, etc.) in the wire shape. The server parses
  authoritatively from the PEM (§4 "Why server-side parsing").

### Wire-format decision: PEM only

The wire format is **PEM**. Not DER, not base64-DER, not a
JSON-encoded structure. Rationale:

- Matches the existing internal/inventory/types.go `CertificatePEM`
  field naming.
- Matches `REST_API.md`'s existing certificate-inventory mention.
- PEM is human-readable, debuggable in transit, and trivially
  validatable as a string.
- DER costs less bytes-on-the-wire but PEM's overhead is
  modest (~33%) and the gzip layer in production deployments
  recovers most of it.
- Supporting two formats doubles the validation surface for
  no operator-visible benefit in v0.1.

### Why server-side parsing

The agent supplies the PEM bytes; the server parses, fingerprints,
classifies. The agent's parsed fields are NEVER trusted as
identity. Rationale:

- A malicious or buggy agent could supply wrong fingerprints,
  wrong subjects, wrong "is_self_signed" flags. Trusting any of
  these is a security defect.
- The Go `crypto/x509` parse is well-tested; the agent's parse
  may not be (Windows agents would use CryptoAPI; Linux agents
  would use OpenSSL; their behaviors diverge).
- Having ONE parse on the control plane keeps the inventory
  internally consistent — two observations of the same cert from
  different agents always produce the same normalized fields.

### Response

```json
{
  "status": "ok",
  "received_at": "2026-05-16T14:00:00Z",
  "accepted": 47,
  "reconciled_absent": 3
}
```

- `accepted` is the number of cert observations successfully
  upserted (deduped + observation row written).
- `reconciled_absent` is the number of previously-current
  observations now marked `removed_at`. Operators can read this
  in the response to detect "cert disappeared" events synchronously
  with the upload.
- No `next_collection_seconds`: collection cadence is operator-
  controlled (config or scheduler), like machine inventory's
  cadence (`PR-018`).

### Size / count limits

| Limit                              | Value     | Rationale                                                                        |
| ---------------------------------- | --------- | -------------------------------------------------------------------------------- |
| `MaxJSONBodyBytes` (per request)   | 4 MiB     | Hundreds of certs × ~2 KiB PEM each + overhead. Configurable via `internal/config`. |
| `MaxCertsPerBatch`                 | 5000      | A Windows host with thousands of certs uploads in one go. Above this, paginate by store coverage. |
| `MaxCertPEMBytes` (per cert)       | 32 KiB    | Real-world certs are well under 10 KiB. 32 KiB catches a malformed cert without rejecting legitimate ones. |
| `MaxStoreCoverageEntries`          | 64        | Far more than any Windows host's reasonable store list (typical 3-8 stores). |
| `MaxStoreLocationLength`           | 255       | Standard Windows path length. Matches `hostname` cap in machine inventory.       |

Oversize input is rejected with `400 bad_request`. No silent
truncation. Cap values become real constants in `internal/inventory`
when H-014 lands.

### Failure modes

| Status | `code`                  | When                                                                                                          |
| ------ | ----------------------- | ------------------------------------------------------------------------------------------------------------- |
| 400    | `bad_request`           | Malformed JSON, trailing JSON, oversize body, oversize cert, too many certs, missing or empty `store_coverage`, store_location not in `store_coverage`, `collected_at` > now+24h |
| 400    | `private_key_rejected`  | Any cert in the batch contains private-key material (entire batch rejected — see §7)                          |
| 400    | `certificate_unparseable` | Any cert in the batch fails to parse as X.509. (Entire batch rejected — see "Reject-whole-batch" in §7.)    |
| 401    | `agent_unauthorized`    | Bearer missing / malformed / unknown / agent revoked / disabled (handled by existing middleware)              |
| 413    | `bad_request`           | Body > `MaxJSONBodyBytes` — surfaced via `http.MaxBytesReader` from the shared `envelope.DecodeStrictOptionalJSON` helper (H-009) |
| 500    | `internal_error`        | Transaction failure, unexpected DB error                                                                       |

All `bad_request` causes collapse to the same envelope shape; the
specific cause lives in the audit row only.

## 5. Idempotency model

Certificate ingestion is **set-reconciliation**, which is its own
form of idempotency — replaying the exact same batch produces the
exact same database state. No explicit `Idempotency-Key` is
required for v0.1.

Concretely:

- **Cert UPSERT** is idempotent by `(organization_id, fingerprint_sha256)`
  unique key. Replay of the same PEM produces the same cert row.
- **Observation UPSERT** is idempotent by
  `(organization_id, certificate_id, agent_id, store_location)`
  unique key. Replay bumps `last_seen_at` to the same
  `collected_at` value (it's already that value).
- **Reconciliation** is idempotent for the same input set —
  observations not in the input get `removed_at = collected_at`.
  Replay sets `removed_at` to the same value (no change).

What's **not** idempotent across changing inputs:

- If batch A reports cert X, then batch B (later, larger
  `collected_at`) doesn't report cert X, X gets
  `removed_at = B.collected_at`. Then if batch B is retried with
  the same `collected_at`, the result is the same (idempotent).
  But if a *different* batch C (larger `collected_at`) reports X
  again, X's `removed_at` clears. That's set reconciliation
  working as intended — the latest batch wins, by `collected_at`
  ordering.

### Out-of-order arrival

In a distributed deployment, an older batch may arrive after a
newer one (network retry on the agent side, proxy reorder, etc.).
Two strategies:

1. **Server-side ordering by `collected_at`.** The reconciliation
   SQL respects `collected_at`: a row's `last_seen_at` is only
   bumped if the incoming `collected_at` is `>=` the stored value.
   Older batches are effectively dropped.
2. **First-write-wins on `collected_at`.** Same idea, different
   wording.

Recommend **option 1**: ignore out-of-order older batches. The
SQL is:

```sql
UPDATE certificate_observations
   SET last_seen_at = $collected_at, removed_at = NULL
 WHERE ... AND last_seen_at <= $collected_at;
```

Zero-row-affected outcomes are silently OK (an older batch tried
to bump a newer state — the newer state already reflects later
observations). The agent's response shows `accepted: 0` for those
certs, which is honest.

### Duplicate cert in the same batch (e.g., cert X in stores My
and WebHosting)

Same cert in multiple stores produces **multiple observation
rows** — one per store. The cert row is deduplicated to one. The
batch's `certificates` array has the cert appearing twice (once
per store entry). Both are processed; both observations are
upserted.

The agent does NOT need to deduplicate before sending. The server
treats each array entry as a distinct observation.

## 6. Audit policy

This section follows the heartbeat / inventory precedent
documented in
[`AGENT_ENROLLMENT.md`](./AGENT_ENROLLMENT.md) "Heartbeat" and
[`AGENT_REINSTALL_REBIND.md`](./AGENT_REINSTALL_REBIND.md) §8.

### What is audited

| Event                                | Severity   | When                                                              |
| ------------------------------------ | ---------- | ----------------------------------------------------------------- |
| `agent.certificate_batch_rejected`   | security   | Private-key material detected; entire batch rejected.             |
| `agent.certificate_batch_invalid`    | (info)     | Parse failure or validation failure for any cert in the batch.    |
| `agent.authentication_failed`        | security   | Existing (H-007). Covers all agent-auth failures on this endpoint. |

### What is NOT audited

- **Per-cert observations.** A fleet of 10,000 agents × 100 certs ×
  5 minutes between uploads would produce ~2.9M audit rows/day for
  routine cert observation. The audit table is the wrong cost
  model. Operators query `certificate_observations` directly.
- **Successful batches.** Same cardinality argument as heartbeat
  and machine-inventory snapshot. A successful batch is operational
  state sync, not a state-change worth investigating.
- **`removed_at` transitions.** Same argument. The
  `certificate_observations` table preserves the state change;
  operators query it directly. Future findings (Phase 4) may emit
  audit rows when a tracked cert disappears, but those are
  findings-level audits, not ingestion-level.

### Metadata rules

- **Never log or audit the PEM, private-key marker text, or any
  cert byte content.** Subject / issuer / fingerprint are public
  and may appear in audit metadata. Private-key markers are not
  public and MUST NOT be echoed.
- **`agent.certificate_batch_rejected` metadata:**
  - `agent_id`
  - `reason: "private_key_material"`
  - `batch_size: N` (count of certs in the offending batch)
  - `severity: "security"`
  - NEVER cert content, NEVER private-key marker text
- **`agent.certificate_batch_invalid` metadata:**
  - `agent_id`
  - `reason: "certificate_unparseable" | "fingerprint_mismatch" | ...`
  - `affected_count: N`
  - NEVER cert content
- These metadata rules match the `agent.enrollment_rejected` and
  `agent.rebind_rejected` precedents — small whitelisted fields,
  no plaintext echo of the offending input.

### Audit transaction model

Following the established pattern (deployment-package create /
revoke, rebind, rotation): the audit row for a rejected batch
is written in the SAME transaction as the ingestion attempt's
side effects. Since a rejected batch has no DB side effects (no
cert rows, no observation rows), the audit row stands alone but
is still written transactionally so a failed audit write
surfaces as a 500 internal error rather than silently dropping
the security signal.

For successful batches, no audit row is written — there's nothing
to keep atomically consistent.

## 7. Private key rejection policy

`CLAUDE.md` §6.2 ("The agent **must never** transmit private key
material to the control plane") is the binding rule. This section
operationalizes it.

### What counts as private-key material

Any of the following strings appearing in any `certificate_pem`
field in the batch, case-insensitive:

- `BEGIN PRIVATE KEY`
- `BEGIN RSA PRIVATE KEY`
- `BEGIN EC PRIVATE KEY`
- `BEGIN DSA PRIVATE KEY`
- `BEGIN ENCRYPTED PRIVATE KEY`

This is the same allow-list `internal/inventory/looksLikePrivateKey`
already implements (the stub the H-014 implementation will lift).

### Detection strategy

Pre-parse string scan. The check runs **before** any X.509 parse
attempt, so even a malformed PEM that happens to contain a
private-key marker is rejected before any further processing.

### Reject scope: WHOLE BATCH

If ANY cert in the batch contains a private-key marker, the
**entire batch** is rejected with `400 private_key_rejected`. No
partial accept.

Rationale:

- An agent that includes a private key is misbehaving and the
  whole upload is suspect. Partial accept would suggest "this
  cert is fine, that one isn't" — but the agent's serializer or
  scanner is the problem, not any one cert.
- Partial accept would leak information about the server's
  per-cert validation logic ("oh, server accepted #3 and rejected
  #5, so it must be the marker on #5 that triggered the reject" —
  enabling probing of the marker list).
- Whole-batch rejection forces the agent to fix its serializer
  before retrying. Operationally clean.

### Logging restrictions

Per the logger redaction allow-list (`internal/logger/redact.go`):

- The PEM bytes never appear in any log line, structured or
  unstructured.
- Private-key marker text never appears in any log line.
- The fact of rejection appears in a structured log line with
  `agent_id`, `reason`, and `batch_size` — no cert content.

### Audit metadata restrictions

Already covered in §6:

- `agent.certificate_batch_rejected` carries `reason:
  "private_key_material"`, `batch_size`, and `agent_id`. No cert
  content. No private-key marker text.
- `severity: "security"` so downstream alerting can filter on it.

## 8. Observation uniqueness

**Decision:** `UNIQUE (organization_id, certificate_id, agent_id,
store_location)`.

### Why include `store_location`

The same cert can legitimately appear in multiple stores on the
same host with different operational semantics:

- `LocalMachine\My` — system identity certs (used by IIS, SQL
  Server, etc.).
- `LocalMachine\WebHosting` — IIS site certs (subset of My on
  modern Windows).
- `LocalMachine\Root` — trusted root CAs.
- `LocalMachine\CA` — trusted intermediate CAs.
- `CurrentUser\My` — per-user certs.

A cert that's *both* a trusted root AND somehow also installed in
`My` is operationally interesting — different from being in
just one. Each location is a distinct observation.

### Why include `organization_id`

Defense-in-depth at the unique-index level. The composite FKs
`(organization_id, certificate_id) → certificates(organization_id, id)`
and `(organization_id, agent_id) → agents(organization_id, id)`
already guarantee no cross-org rows, but indexing the org column
keeps the SQL planner honest on per-org queries.

### Why NOT include `hostname`

Per H-006 §3, `hostname` is **descriptive**, not identity.
Hostnames change. `agent_id` is the stable identity axis.

### Why NOT include `friendly_name`

Same reason. `friendly_name` is operator-facing display text. The
agent reports it; the server stores it; nobody indexes on it.

### What this enables

- "Where is cert X right now?" — query observations by
  `certificate_id`, filter `removed_at IS NULL`. Returns
  `(agent_id, store_location)` pairs.
- "What's on agent Y?" — query observations by `agent_id`.
- "What's the latest set of certs in My on agent Y?" —
  `agent_id = ? AND store_location = ? AND removed_at IS NULL`.

## 9. Chain handling

**Decision:** chain relationships are **not** modeled in v0.1.

Each cert in a batch is treated as an independent observation.
The `certificates` table stores leafs, intermediates, and roots
as separate rows — each identified by its own fingerprint.

### Duplicates across stores

Already covered in §8: same fingerprint in multiple stores on the
same host = multiple observation rows, one cert row.

### Same cert across multiple agents

Same fingerprint observed by different agents = one cert row,
multiple observation rows (one per `(agent_id, store_location)`).
The cert's `last_seen_at` on the `certificates` row is the
**most recent** observation across the fleet, not per-agent.

### Self-signed

Just a normal `certificates` row with `is_self_signed = true`.
Future findings (Phase 4) can flag self-signed certs that operators
care about; the ingestion layer doesn't gate on it.

### Why no chain modeling

- Chain validity is a **query-time** concern, not a storage-time
  concern. An operator who wants "is this leaf chained to a
  trusted root in our trust store?" can compute the answer by
  joining observations by subject/issuer at query time.
- Modeling chains in v0.1 requires:
  - Building parent-child links by matching issuer → subject
    across the cert table.
  - Handling cross-signed certs (which have multiple valid
    parents).
  - Handling missing intermediates (the agent observed a leaf but
    not its issuer).
  - Handling cyclic structures from misissuance.
- All of that is real PKI chain-validation work and belongs in
  Phase 4 findings or a dedicated "chain analysis" feature, not
  in the ingestion data model.

The schema doesn't *prevent* future chain modeling — a follow-on
migration can add a `certificate_chain_links` table that joins
two cert ids. v0.1 simply doesn't ship one.

## 10. Scale assumptions

### Fleet sizing target

- Agents per organization: up to 10,000 (matches SCCM-class
  deployments, the explicit v0.1 target per `AGENT_ENROLLMENT.md`).
- Certs per agent: 100-500 typical, 1000+ for cert-heavy hosts
  (build servers with many test certs).
- Stores per agent: typically 3-8 covered.
- Collection cadence: configurable; expected 6-24 hours (slower
  than heartbeat's 5-minute cadence — cert state changes much
  less often than liveness).

### Resulting cardinality

- `certificates` table: ~1,000-10,000 distinct certs per org. Most
  certs are widely shared (Windows root certs, internal CA certs
  pushed to every endpoint).
- `certificate_observations` table: ~1M-5M rows for a 10K-host
  fleet. Each row is small (~200 bytes), so ~200-1000 MB.

### Expected indexes

| Index                                                                  | Query pattern                                              |
| ---------------------------------------------------------------------- | ---------------------------------------------------------- |
| `certificates(organization_id, fingerprint_sha256)` UNIQUE             | Dedup lookup on ingestion.                                  |
| `certificates(organization_id, not_after)`                             | "Expiring soon" queries (Phase 4 findings).                 |
| `certificates(organization_id, subject)`                               | Operator search.                                            |
| `certificate_observations(organization_id, certificate_id, agent_id, store_location)` UNIQUE | Reconciliation upsert key.                  |
| `certificate_observations(organization_id, agent_id)`                  | "Certs on agent X" queries.                                 |
| `certificate_observations(organization_id, certificate_id)`            | "Who has cert X" queries.                                   |
| `certificate_observations(organization_id, removed_at)`                | "Currently observed" filter (often combined with above).    |

H-014 ships these alongside the migration. Index intent is
documented inline per `CLAUDE.md` §16.

### Transaction sizing

A single batch's reconciliation transaction:

- Reads existing observations for `(agent_id, store_coverage)` —
  up to a few hundred rows.
- Upserts cert rows (deduped — most rows already exist; only
  novel certs INSERT).
- Upserts observation rows.
- Marks absent observations as `removed_at`.

Worst case: an agent with 5,000 certs across 8 stores. Transaction
touches ~5,000 cert lookups, ~5,000 observation upserts, ~few-hundred
reconciliation updates. Well within Postgres's comfortable
transaction size — but the H-014 implementation should commit
batches per store to keep transaction latency bounded.

### Retention / stale cleanup

**v0.1 keeps all observations forever.** A `removed_at IS NOT
NULL` row is a queryable historical record: "cert X *was* on
agent Y from DATE_A until DATE_B".

Operational cleanup (e.g., "delete observations older than 90
days") is **out of scope**. It's an ops-policy decision, not a
schema-level one. If operators want it, a follow-up migration
adds a soft-delete policy or a scheduled job.

## 11. Future findings compatibility

The schema is designed to make these Phase 4 (`findings`) queries
efficient:

| Finding                              | Query shape                                                                                |
| ------------------------------------ | ------------------------------------------------------------------------------------------ |
| Expired certificate                  | `SELECT ... FROM certificates WHERE not_after < now()`                                       |
| Expiring soon                        | `WHERE not_after BETWEEN now() AND now() + interval '30 days'`                                |
| Weak signature algorithm             | `WHERE signature_algorithm IN ('MD5-RSA', 'SHA1-RSA', ...)`                                   |
| Weak key length                      | `WHERE public_key_algorithm = 'RSA' AND public_key_bits < 2048`                              |
| Self-signed                          | `WHERE is_self_signed = TRUE`                                                                |
| Rogue / unknown issuer               | `WHERE issuer NOT IN (<operator-configured trusted issuer list>)`                            |
| Duplicate cert across hosts          | `GROUP BY certificate_id` on observations; flag where `COUNT(DISTINCT agent_id) > THRESHOLD` |
| Certificate currently observed       | Join `certificates ↔ certificate_observations WHERE removed_at IS NULL`                       |
| Certificate disappeared (was present)| `WHERE removed_at IS NOT NULL` — "this used to be on agent Y, now it's not"                  |

### Deferred to a future agent-side change

- **Private key presence per observation.** The control plane
  can't tell whether the agent's certificate also has its private
  key on disk — that's an agent-side property. Future work: the
  agent reports an optional `has_private_key` boolean per
  observation (the agent computes it from Windows' CryptoAPI
  `CertGetCertificateContextProperty` with the key-prov property).
  Adding the column later is additive per CLAUDE.md §16. Not in
  the v0.1 wire shape.
- **Trust-store visibility.** Whether a cert is in a trust store
  (`Root`, `CA`) vs a leaf store (`My`, `WebHosting`) is **already**
  observable from `store_location`. Future trust-relationship
  modeling (which cert in `Root` chains to which leaf in `My`) is
  Phase 4+ work.

## 12. Operator read model

Future endpoints. **No implementation in this PR.** Shapes match
the established v0.1 patterns from `PR-018` / `H-010` / `H-005`.

### `GET /api/v1/certificates`

Operator-only, org-scoped. Paginated cursor (`cursor`, `limit`,
`next_cursor` — same pattern as `GET /agent-inventory`).

Query parameters:

- `q` — substring match against subject / SANs / issuer.
- `expiring_before` — RFC3339 timestamp; returns certs with
  `not_after < value`.
- `is_ca` — boolean filter.
- `agent_id` — filter to certs observed by a specific agent
  (joins through observations).
- `current_only` — boolean; default `true`. When true, excludes
  certs whose only observations have `removed_at IS NOT NULL`.

Slim row format (similar to `GET /agent-inventory`):

```json
{
  "items": [
    {
      "id": "...",
      "fingerprint_sha256": "ab12...",
      "subject": "CN=ws-001.corp.example",
      "issuer": "CN=Internal Issuing CA",
      "not_after": "2026-12-01T00:00:00Z",
      "is_ca": false,
      "is_self_signed": false,
      "observation_count": 3,
      "current_observation_count": 1,
      "last_seen_at": "2026-05-16T14:00:00Z"
    }
  ],
  "next_cursor": null
}
```

The full PEM is NOT in the list payload (same pattern as
machine-inventory's exclusion of `local_ips` — list summaries
stay small).

### `GET /api/v1/certificates/{id}`

Single cert detail. Includes the full PEM, the full normalized
field set, and a small summary of observations (count, latest
last_seen_at, distinct agent count).

### `GET /api/v1/certificates/{id}/observations`

List observations for one cert. Filters:

- `agent_id` — narrow to one agent.
- `store_location` — narrow to one store.
- `current_only` — boolean; default `true`.

Slim row format:

```json
{
  "items": [
    {
      "id": "...",
      "agent_id": "...",
      "store_location": "LocalMachine\\My",
      "friendly_name": "...",
      "first_seen_at": "...",
      "last_seen_at": "...",
      "removed_at": null
    }
  ],
  "next_cursor": null
}
```

### `GET /api/v1/agents/{id}/certificates`

Certs observed by one agent. Same shape as
`GET /api/v1/certificates` but scoped to one `agent_id`. Convenient
for the future per-agent operator view.

### Wire-shape stability

All operator endpoints follow:

- The cursor-based pagination convention defined by `H-010` and
  documented in `REST_API.md` "Pagination".
- The slim-summary-vs-full-detail split established by `H-010`
  (list endpoints exclude bulky fields; detail endpoints include
  everything).
- The cross-org → 404 not_found posture (no enumeration via
  error code; CLAUDE.md §6).

## 13. Non-goals

Explicitly **NOT** in scope for this design or the implementation
PRs it spawns:

- **Findings engine.** Phase 4. The schema supports finding queries
  (§11) but the runtime evaluator, severity model, acknowledgment
  workflow, and finding lifecycle are separate work.
- **Risk scoring.** Same scope as findings.
- **Auto-remediation.** Out of v0.1 (`CLAUDE.md` §1, §13).
- **Trust validation.** Chain validation requires Phase 4+ work.
- **OCSP / CRL checking.** Not in v0.1 (would require outbound
  network access from the control plane to revocation endpoints —
  an `internal/providers/transport` concern that's its own design).
- **UI dashboards.** Operator UI is a separate concern; the
  REST API contracts in §12 are the data plane that future UI
  builds against.
- **Real-time streaming.** Batch HTTP POST only. Web-socket /
  server-sent-event push of cert state changes is out of scope.
- **mTLS rollout.** Phase 6 (`H-008`). The cert-ingestion design
  carries forward unchanged when bearer credentials become mTLS
  client certs.
- **Command execution.** No agent-side actions are triggered by
  ingestion. Agents observe; operators decide.
- **Full certificate path validation.** §9 covers why chain
  modeling is deferred. Path validation is a query-time concern,
  not a storage-time one.

## Recommended PR sequence after this design

1. **This PR (H-011 design)** — docs only. No code.
2. **H-014 — `feat(inventory): certificate + observations storage layer`.**
   Migration introducing `certificates` and `certificate_observations`
   with composite FKs to `agents` (PR-019 H-009 pattern), the
   internal/inventory repository implementation, the deduplication
   model, and the reconciliation SQL pattern. Indexes per §10. No
   HTTP surface yet.
3. **H-015 — `feat(inventory): agent certificate ingestion endpoint`.**
   `POST /api/v1/agent/certificates` wired behind
   `RequireAuthenticatedAgent`. Uses the H-014 storage layer plus
   the existing `envelope.DecodeStrictOptionalJSON` helper
   (`H-009`). Implements §4 (request/response), §5 (idempotency),
   §6 (audit), §7 (private-key rejection). Full unit + integration
   test coverage.
4. **H-016 — `feat(inventory): operator certificate read API`.**
   `GET /api/v1/certificates`, `/certificates/{id}`,
   `/certificates/{id}/observations`, `/agents/{id}/certificates`.
   All operator-side, paginated per H-010 pattern.
5. **(Phase 4) Findings integration** — separate design, separate
   PR. The schema landed in H-014 is the substrate.

H-014 and H-015 must ship in order (H-015 depends on the schema
landing first). H-016 is loosely independent — it could ship
between H-014 and H-015 (with no real observations to read) but
the operator-useful state is after H-015.

## Unresolved questions

Flagged for the implementation PRs to confirm with operators
before locking the wire.

1. **Collection cadence default.** §4 says no
   `next_collection_seconds` in the response. Operators may want
   a server-side suggestion (e.g., "ask me again in 6 hours").
   Additive per CLAUDE.md §17 — can land later without breaking
   v1 callers.
2. **Configurable size limits.** §4's `MaxJSONBodyBytes`,
   `MaxCertsPerBatch`, `MaxCertPEMBytes`, `MaxStoreCoverageEntries`,
   `MaxStoreLocationLength` are reasonable defaults; the H-015
   implementation should expose them via `internal/config` for
   future tuning without code changes.
3. **Out-of-order batch handling for `removed_at`.** §5 covers
   `last_seen_at` but not the symmetric `removed_at` clear:
   should an older batch be able to clear `removed_at` if the
   stored `last_seen_at` is younger? Recommend NO — only the
   newest batch can transition state. The SQL becomes:

   ```sql
   ... WHERE last_seen_at <= $collected_at
   ```

   for both bump-up and clear-removed actions.
4. **Trust-store classification by `store_location`.** Should the
   server label `LocalMachine\Root` observations as
   `is_trust_store_observation = TRUE` (a denormalized column on
   observations) to make Phase 4 trust-store findings faster? Or
   should the operator's trust-store query handle the
   classification at query time? Recommend query-time for v0.1 —
   simpler schema, the operator's `WHERE store_location IN (...)`
   list is operator-policy anyway.
5. **PEM canonicalization.** Should the server canonicalize the
   PEM (strip trailing whitespace, fix line endings, re-wrap to
   64-column lines) before storage? Recommend YES — gives a
   stable on-disk representation regardless of the agent's
   serializer. Implementation detail for H-014; doesn't affect
   the wire contract.

None of the above block the design from merging.

### Resolved during review

- **`store_coverage` empty-list semantics.** Initially listed as
  an unresolved question with two readings (strict vs lenient).
  Resolved during PR #23 review in favor of the strict reading:
  `store_coverage` is required and non-empty; missing or empty
  returns `400 bad_request`. §3 carries the rationale; §4 carries
  the wire contract. An explicit upsert-only mode is deferred
  until there is operator demand and lands as a separate field,
  never as the absent-field default.

## References

- [`CLAUDE.md`](../../CLAUDE.md) §1, §6.2, §6.4, §6.6, §6.7, §9,
  §16, §17, §18 — product mission, no-private-key rule, audit /
  migration / robustness invariants.
- [`docs/engineering/AGENT_ENROLLMENT.md`](./AGENT_ENROLLMENT.md)
  — agent identity model this design builds on.
- [`docs/engineering/AGENT_REINSTALL_REBIND.md`](./AGENT_REINSTALL_REBIND.md)
  — H-006 design. The "rebind preserves agent_id" commitment is
  the precondition for §2 observation continuity.
- [`docs/api/REST_API.md`](../api/REST_API.md) — pagination,
  envelope, and error-code conventions the §4 and §12 contracts
  conform to.
- [`backend/internal/inventory/`](../../backend/internal/inventory/)
  — pre-existing domain stubs (`Certificate`,
  `CertificateObservation`, `InventoryBatch`, `DiscoveredCertificate`,
  `Ingestor`'s no-private-key check). H-014 will lift these into
  production code.
- [`backend/migrations/0001_init.sql`](../../backend/migrations/0001_init.sql)
  — original `certificates` / `certificate_observations` schema
  proposals (revised in this design, will be replaced by the
  H-014 migration).
