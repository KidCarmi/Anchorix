// Package risks evaluates rules against the certificate inventory and
// produces findings. Rules are deliberately small and pure: given a
// certificate (and optional context) they return zero or more findings.
package risks

import "time"

// Severity is a coarse classification used for filtering and dashboards.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Status is the lifecycle of a finding.
type Status string

const (
	StatusOpen         Status = "open"
	StatusAcknowledged Status = "acknowledged"
	StatusSuppressed   Status = "suppressed"
	StatusResolved     Status = "resolved"
)

// Finding represents a risk associated with a certificate.
type Finding struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	CertificateID  string    `json:"certificate_id"`
	RuleID         string    `json:"rule_id"`
	Severity       Severity  `json:"severity"`
	Status         Status    `json:"status"`
	Title          string    `json:"title"`
	Evidence       []byte    `json:"evidence"` // JSON-encoded; opaque to consumers
	OpenedAt       time.Time `json:"opened_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}
