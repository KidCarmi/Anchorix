package findings

import (
	"encoding/json"
	"time"
)

// Severity is the coarse classification surfaced to operators and
// used by GET /findings filtering. The schema CHECK in
// migrations/0001_init.sql admits info/low/medium/high/critical;
// v0.1's rules only emit low/medium/high. The other values are
// reserved for future rule additions and operator severity
// overrides (out of scope here).
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Status is the lifecycle of a finding.
//
// H-021 wrote only `open` / `resolved`. H-023 brings the two
// override values into active use via
// Service.AcknowledgeFinding and Service.SuppressFinding.
type Status string

const (
	StatusOpen         Status = "open"
	StatusResolved     Status = "resolved"
	StatusAcknowledged Status = "acknowledged"
	StatusSuppressed   Status = "suppressed"
)

// Finding is the canonical in-memory representation of a row in
// the findings table.
//
// Identity: (OrganizationID, CertificateID, RuleID) is unique
// (enforced by the migrations/0001 unique constraint). The
// composite FK on (OrganizationID, CertificateID) introduced in
// migration 0006 binds the row to the same organization as the
// referenced certificate.
//
// Timestamps:
//
//   - FirstSeenAt — the FIRST time the rule matched this
//     certificate, ever. Preserved across resolve → reopen
//     cycles (the existing row is UPDATEd, not replaced).
//     Stored in the SQL column `opened_at` whose 0001-era name
//     reflects "first opened"; the API exposes it as
//     `first_seen_at` per the H-021 contract.
//   - LastSeenAt — the most recent recompute that re-confirmed
//     the match. Bumped on every Recompute that finds the
//     finding still applies.
//   - ResolvedAt — set when the finding transitions
//     open → resolved (the rule no longer matches). Cleared
//     back to NULL on reopen.
//   - UpdatedAt — touched on any state change (open, update,
//     resolve, reopen). Distinct from LastSeenAt: a recompute
//     that re-confirms a match bumps both; a recompute that
//     resolves a finding bumps UpdatedAt and stamps ResolvedAt
//     but leaves LastSeenAt at the prior re-confirmation time.
//
// Certificate context (JOIN-populated, NOT stored on the
// findings row):
//
//   - FingerprintSHA256 — the referenced certificate's
//     fingerprint, populated by GetFinding / ListFindings via
//     a JOIN to the `certificates` table. Empty when the
//     finding is loaded by ListAllForOrg (recompute path) —
//     that path doesn't need cert context.
//   - Subject — same: JOIN-populated cert subject DN.
//
// These two are response-shaping context, not finding identity.
// The UpdateFinding / InsertFinding paths ignore them; only the
// scan paths that need to surface them to operators populate
// them.
//
// Override metadata (H-023):
//
//   - StatusReason / StatusActor / StatusChangedAt —
//     populated when an operator transitions the finding to
//     acknowledged or suppressed; cleared when recompute
//     auto-transitions OUT of an override (rule no longer
//     matches, suppression expired). NULL on findings that
//     have never been overridden.
//   - SuppressExpiresAt — set only when status=suppressed AND
//     the operator provided an expires_at. Recompute reopens
//     the finding to `open` when wall-clock time crosses this
//     and the rule still matches.
//
// The immutable history of override actions lives in
// audit_events (`finding.acknowledged` / `finding.suppressed`
// rows). These fields are denormalized current-state for the
// operator GET endpoints.
type Finding struct {
	ID                string
	OrganizationID    string
	CertificateID     string
	RuleID            string
	RuleVersion       int
	Severity          Severity
	Status            Status
	Title             string
	Evidence          json.RawMessage
	FirstSeenAt       time.Time
	LastSeenAt        time.Time
	ResolvedAt        *time.Time
	UpdatedAt         time.Time
	FingerprintSHA256 string
	Subject           string
	StatusReason      string
	StatusActor       string
	StatusChangedAt   *time.Time
	SuppressExpiresAt *time.Time
}

// RecomputeResult is the counter set returned by Service.Recompute.
// Counts are mutually exclusive — a finding ends up in exactly
// one bucket per run.
type RecomputeResult struct {
	EvaluatedCertificates int
	Opened                int
	Updated               int
	Resolved              int
	Unchanged             int
	RuleCount             int
}

// ListQuery captures the operator-facing filters for GET /findings.
// OrganizationID always comes from the authenticated session —
// never from a query parameter.
//
// StatusFilter == "" means "use default = open". The HTTP layer
// is responsible for translating an explicit ?status=all to the
// sentinel "all" before reaching the service.
//
// CursorLastSeenAt + CursorID are the storage-layer fields
// populated by the service after it decodes the opaque Cursor
// string. The repository reads those directly; it does NOT
// re-decode Cursor on its own.
type ListQuery struct {
	OrganizationID   string
	Status           StatusFilter
	Severity         Severity
	RuleID           string
	CertificateID    string
	Limit            int
	Cursor           string
	CursorLastSeenAt time.Time
	CursorID         string
}

// StatusFilter is the shape of the operator's `status` query
// parameter. Accepted wire values are mapped to the constants
// below; an empty filter is treated as `open` (the documented
// default).
type StatusFilter string

const (
	StatusFilterOpen         StatusFilter = "open"
	StatusFilterResolved     StatusFilter = "resolved"
	StatusFilterAcknowledged StatusFilter = "acknowledged"
	StatusFilterSuppressed   StatusFilter = "suppressed"
	StatusFilterAll          StatusFilter = "all"
)

// ListResult is the page returned by Service.ListFindings.
// NextCursor is empty when there is no further page.
type ListResult struct {
	Items      []Finding
	NextCursor string
}

// MaxOverrideReasonLength caps the operator-supplied `reason`
// field on acknowledge / suppress requests. Long enough for a
// "we filed CSCM-1234, expected fix Q2" sentence; short enough
// that a malicious operator can't blow out the audit_events
// JSONB column.
const MaxOverrideReasonLength = 1000

// AcknowledgeInput is the validated input to
// Service.AcknowledgeFinding. All four fields are required:
// OrganizationID and FindingID identify the target;
// ActorUserID identifies the operator (passed through to the
// audit row); Reason is the operator's note (also stored on
// the finding row as `status_reason`).
type AcknowledgeInput struct {
	OrganizationID string
	FindingID      string
	ActorUserID    string
	Reason         string
}

// SuppressInput is the validated input to
// Service.SuppressFinding. ExpiresAt is optional — when nil,
// the suppression has no expiry and the recompute logic
// treats it as "permanent until manually changed". When set,
// MUST be strictly in the future relative to the service's
// clock (the HTTP handler trims and validates before reaching
// the service, but the service re-checks defensively).
type SuppressInput struct {
	OrganizationID string
	FindingID      string
	ActorUserID    string
	Reason         string
	ExpiresAt      *time.Time
}
