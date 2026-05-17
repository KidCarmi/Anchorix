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
// v0.1 emits only `open` and `resolved`. The schema CHECK reserves
// `acknowledged` and `suppressed` for the future override surface
// — Service.Recompute never writes those values, and the GET
// endpoints filter the closed set (open/resolved) by default.
type Status string

const (
	StatusOpen     Status = "open"
	StatusResolved Status = "resolved"
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
type Finding struct {
	ID             string
	OrganizationID string
	CertificateID  string
	RuleID         string
	RuleVersion    int
	Severity       Severity
	Status         Status
	Title          string
	Evidence       json.RawMessage
	FirstSeenAt    time.Time
	LastSeenAt     time.Time
	ResolvedAt     *time.Time
	UpdatedAt      time.Time
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
// parameter. The three accepted wire values are mapped to the
// constants below; an empty filter is treated as `open` (the
// documented default).
type StatusFilter string

const (
	StatusFilterOpen     StatusFilter = "open"
	StatusFilterResolved StatusFilter = "resolved"
	StatusFilterAll      StatusFilter = "all"
)

// ListResult is the page returned by Service.ListFindings.
// NextCursor is empty when there is no further page.
type ListResult struct {
	Items      []Finding
	NextCursor string
}
