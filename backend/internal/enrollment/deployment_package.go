package enrollment

import (
	"context"
	"errors"
	"time"
)

// PackageType is a controlled vocabulary that distinguishes between
// the rollout contexts an operator might want to track. It is
// metadata for the future GUI and for audit/policy decisions — the
// domain logic in v0.1 does not branch on package_type.
type PackageType string

const (
	// PackageTypeBaseline marks the currently-approved standard agent
	// version. Long expiry, generous max_uses.
	PackageTypeBaseline PackageType = "baseline"

	// PackageTypeBulkSCCM marks a package created for a fleet-management
	// tool (SCCM, Intune, GPO) to deploy silently across many endpoints.
	PackageTypeBulkSCCM PackageType = "bulk_sccm"

	// PackageTypeTechnician marks a small-batch operator-issued package
	// (e.g. a few hands-on installs by a technician on the floor).
	PackageTypeTechnician PackageType = "technician"

	// PackageTypeVIP marks a tightly scoped package for sensitive or
	// VIP installs. Low max_uses, short expiry.
	PackageTypeVIP PackageType = "vip"

	// PackageTypeLab marks a temporary lab/test package. Low max_uses,
	// short expiry.
	PackageTypeLab PackageType = "lab"
)

// Valid reports whether t is one of the recognized PackageType
// constants. The list is closed in v0.1; new types require a schema
// migration (the CHECK constraint on deployment_packages.package_type
// is the second line of defense) plus a corresponding constant.
func (t PackageType) Valid() bool {
	switch t {
	case PackageTypeBaseline, PackageTypeBulkSCCM, PackageTypeTechnician,
		PackageTypeVIP, PackageTypeLab:
		return true
	}
	return false
}

// DeploymentPackage is an enrollment artifact an admin creates so a
// fleet-management tool can deploy agents that auto-enroll on first
// run. The plaintext bootstrap secret lives only in the
// CreatePackageOutput; storage holds only its hash.
//
// Lifecycle: a package is active when ALL THREE of the following
// are true:
//
//   - not revoked (RevokedAt == nil)
//   - not expired (ExpiresAt is in the future)
//   - not exhausted (UsesCount < MaxUses)
//
// Each enrollment increments UsesCount atomically via the repository,
// so a fleet of devices racing to enroll cannot exceed MaxUses.
type DeploymentPackage struct {
	ID               string
	OrganizationID   string
	Name             string
	Description      string
	PackageType      PackageType
	AgentVersion     string
	MaxUses          int
	UsesCount        int
	ExpiresAt        time.Time
	RevokedAt        *time.Time
	RevokedByUserID  string
	RevokedReason    string
	CreatedByUserID  string
	CreatedAt        time.Time
	LastUsedAt       *time.Time
	DefaultGroupName string
	DefaultLabels    []string
}

// activeAt returns nil if the package is currently eligible to enroll
// a new agent, or one of ErrPackageRevoked / ErrPackageExpired /
// ErrPackageExhausted to identify the first failing precondition.
//
// Callers MUST NOT surface the specific error to the enrolling agent;
// see ErrEnrollmentRejected for the wire-safe wrapper. The specific
// reason is recorded server-side via an audit event so operators can
// diagnose rejected enrollments without leaking package state to the
// caller.
func (p *DeploymentPackage) activeAt(now time.Time) error {
	if p.RevokedAt != nil {
		return ErrPackageRevoked
	}
	if !now.Before(p.ExpiresAt) {
		return ErrPackageExpired
	}
	if p.UsesCount >= p.MaxUses {
		return ErrPackageExhausted
	}
	return nil
}

// DeploymentPackageRepository is the storage contract for deployment
// packages. The concrete implementation lives in
// internal/storage/postgres; this interface is owned by the consumer
// (CLAUDE.md §8.8).
type DeploymentPackageRepository interface {
	// Create inserts a new deployment package. The hash is the
	// SHA-256 of the plaintext bootstrap secret; no plaintext is
	// ever passed through this interface.
	Create(ctx context.Context, pkg *DeploymentPackage, bootstrapSecretHash []byte) error

	// GetByBootstrapHash looks up a package by the hash of its
	// bootstrap secret. Returns ErrPackageNotFound if no package
	// matches the hash.
	GetByBootstrapHash(ctx context.Context, hash []byte) (*DeploymentPackage, error)

	// IncrementUses atomically increments uses_count for the package
	// at the given timestamp. The implementation MUST only succeed
	// when the package is still active (not revoked, not expired,
	// not exhausted) at the moment of the SQL UPDATE — otherwise it
	// MUST return one of ErrPackageRevoked / ErrPackageExpired /
	// ErrPackageExhausted.
	//
	// This is the choke point that makes concurrent SCCM-style mass
	// enrollment safe under MaxUses.
	IncrementUses(ctx context.Context, id string, at time.Time) error
}

// Sentinel errors. Centralized so domain and storage agree on the
// vocabulary (CLAUDE.md §8.1).
var (
	// ErrPackageNotFound is returned by GetByBootstrapHash when no
	// package matches the supplied hash. Callers convert this to
	// ErrEnrollmentRejected before responding to the agent.
	ErrPackageNotFound = errors.New("enrollment: deployment package not found")

	// ErrPackageRevoked indicates the package has been revoked.
	ErrPackageRevoked = errors.New("enrollment: deployment package revoked")

	// ErrPackageExpired indicates the package's expires_at is in the past.
	ErrPackageExpired = errors.New("enrollment: deployment package expired")

	// ErrPackageExhausted indicates uses_count has reached max_uses.
	ErrPackageExhausted = errors.New("enrollment: deployment package usage exhausted")

	// ErrEnrollmentRejected is the wire-safe outer error returned to
	// any failed enrollment, regardless of internal reason. The
	// underlying reason is recorded as an audit event but never
	// echoed back to the agent (CLAUDE.md §6: deterministic auth
	// behavior — no enumeration via error code).
	ErrEnrollmentRejected = errors.New("enrollment: rejected")

	// ErrAgentAlreadyEnrolled indicates the install_id supplied by
	// the agent already corresponds to an enrolled agent in this
	// organization. v0.1 fails closed on this case rather than
	// re-issuing a credential without an explicit design.
	ErrAgentAlreadyEnrolled = errors.New("enrollment: agent already enrolled")

	// ErrInvalidPackageInput is returned by CreatePackage when the
	// caller-supplied input does not satisfy the documented rules
	// (missing required field, invalid PackageType, non-positive TTL
	// or MaxUses).
	ErrInvalidPackageInput = errors.New("enrollment: invalid package input")

	// ErrInvalidEnrollmentInput is returned by EnrollAgent when the
	// caller's input is malformed before we even consult the
	// package store (e.g. empty bootstrap secret / hostname). It is
	// folded into ErrEnrollmentRejected at the HTTP boundary so
	// callers cannot distinguish malformed input from a bad secret.
	ErrInvalidEnrollmentInput = errors.New("enrollment: invalid enrollment input")
)
