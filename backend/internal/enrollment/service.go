package enrollment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/kidcarmi/anchorix/backend/internal/audit"
	"github.com/kidcarmi/anchorix/backend/internal/clock"
	"github.com/kidcarmi/anchorix/backend/internal/ids"
)

// Transactor runs fn inside a single transaction. The implementation
// (storage/postgres.DB) binds a tx to the ctx so repository calls
// made with that ctx automatically participate. The enrollment
// service uses this to make package creation and agent enrollment
// atomic with their audit events across multiple repository writes
// without leaking pgx.Tx outside the storage layer (CLAUDE.md §8.6,
// §18). The interface shape is identical to auth.Transactor on
// purpose so the same *postgres.DB satisfies both.
type Transactor interface {
	WithTx(ctx context.Context, fn func(ctx context.Context) error) error
}

// Service is the enrollment domain entrypoint. HTTP handlers depend
// on this struct, never on the Repository / Transactor types
// directly (CLAUDE.md §8.6, §8.8).
type Service struct {
	packages DeploymentPackageRepository
	agents   AgentRepository
	audit    audit.Recorder
	tx       Transactor
	clock    clock.Clock
	rng      io.Reader // crypto/rand.Reader in prod; deterministic in tests
}

// NewService wires the service. Constructor-based DI per CLAUDE.md
// §8.8. Returns a validation error if any dependency is missing —
// never panics (CLAUDE.md §18: no panic-driven business flow).
func NewService(
	packages DeploymentPackageRepository,
	agents AgentRepository,
	auditRec audit.Recorder,
	tx Transactor,
	clk clock.Clock,
	rng io.Reader,
) (*Service, error) {
	switch {
	case packages == nil:
		return nil, errors.New("enrollment.NewService: deployment package repository required")
	case agents == nil:
		return nil, errors.New("enrollment.NewService: agent repository required")
	case auditRec == nil:
		return nil, errors.New("enrollment.NewService: audit recorder required")
	case tx == nil:
		return nil, errors.New("enrollment.NewService: transactor required")
	case clk == nil:
		return nil, errors.New("enrollment.NewService: clock required")
	}
	if rng == nil {
		// crypto/rand.Reader is the production default; making it
		// explicit keeps tests honest (a missing-rng test will
		// still be deterministic).
		return nil, errors.New("enrollment.NewService: rng required")
	}
	return &Service{
		packages: packages,
		agents:   agents,
		audit:    auditRec,
		tx:       tx,
		clock:    clk,
		rng:      rng,
	}, nil
}

// CreatePackageInput is what an operator supplies when creating a
// deployment package. All fields are validated by CreatePackage
// before any state changes.
type CreatePackageInput struct {
	OrganizationID   string
	CreatedByUserID  string
	Name             string
	Description      string
	PackageType      PackageType
	AgentVersion     string
	TTL              time.Duration // expires_at = clock.Now() + TTL
	MaxUses          int
	DefaultGroupName string
	DefaultLabels    []string
}

// CreatePackageOutput carries the freshly created package and the
// plaintext bootstrap secret. The plaintext appears in exactly one
// place in the application — this struct — and the HTTP handler
// echoes it back to the operator once before discarding it.
type CreatePackageOutput struct {
	Package         *DeploymentPackage
	BootstrapSecret string
}

// CreatePackage validates the input, generates a fresh high-entropy
// bootstrap secret, and writes the package + an audit event in a
// single transaction.
//
// Atomicity: the package row and the deployment_package.created
// audit event are committed together. An audit-write failure rolls
// the package insert back so the control plane can never reach a
// state where a package exists without a matching audit row
// (CLAUDE.md §9, §18). Proved by an integration test that injects
// a failing audit recorder.
func (s *Service) CreatePackage(ctx context.Context, in CreatePackageInput) (*CreatePackageOutput, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}

	plaintext, hash, err := generateBearerToken(s.rng)
	if err != nil {
		return nil, err
	}

	now := s.clock.Now()
	pkg := &DeploymentPackage{
		ID:               ids.New(),
		OrganizationID:   in.OrganizationID,
		Name:             strings.TrimSpace(in.Name),
		Description:      in.Description,
		PackageType:      in.PackageType,
		AgentVersion:     in.AgentVersion,
		MaxUses:          in.MaxUses,
		UsesCount:        0,
		ExpiresAt:        now.Add(in.TTL),
		CreatedByUserID:  in.CreatedByUserID,
		CreatedAt:        now,
		DefaultGroupName: in.DefaultGroupName,
		DefaultLabels:    append([]string(nil), in.DefaultLabels...),
	}

	if err := s.tx.WithTx(ctx, func(ctx context.Context) error {
		if err := s.packages.Create(ctx, pkg, hash); err != nil {
			return fmt.Errorf("enrollment: create package: %w", err)
		}
		// Audit metadata captures the operator-visible knobs of the
		// package but DELIBERATELY excludes the bootstrap secret and
		// its hash — those must never appear in audit_events
		// (CLAUDE.md §6.9). The hash is stored in the
		// deployment_packages row only.
		md, _ := json.Marshal(map[string]any{
			"package_type":  string(in.PackageType),
			"agent_version": in.AgentVersion,
			"max_uses":      in.MaxUses,
			"expires_at":    pkg.ExpiresAt.UTC().Format(time.RFC3339),
			"group_name":    in.DefaultGroupName,
			"label_count":   len(in.DefaultLabels),
		})
		return s.audit.Record(ctx, audit.Event{
			OrganizationID: in.OrganizationID,
			Actor:          in.CreatedByUserID,
			ActorType:      "user",
			Action:         "deployment_package.created",
			TargetType:     "deployment_package",
			TargetID:       pkg.ID,
			Metadata:       md,
		})
	}); err != nil {
		return nil, err
	}

	return &CreatePackageOutput{Package: pkg, BootstrapSecret: plaintext}, nil
}

// EnrollAgentInput is what a freshly installed agent supplies on
// its first call to /api/v1/agents/enroll. The bootstrap secret is
// the only credential; the rest are identity hints that help the
// operator UI recognize the endpoint later.
type EnrollAgentInput struct {
	BootstrapSecret    string
	Hostname           string
	AgentVersion       string
	MachineFingerprint string // raw fingerprint; hashed before storage
	InstallID          string
	RequestID          string // forwarded to the audit row for correlation
}

// EnrollAgentOutput is what the agent receives back. AgentCredential
// is the plaintext bearer credential — it appears in exactly one
// place in the application (this struct) and the HTTP handler
// echoes it back once.
type EnrollAgentOutput struct {
	Agent           *Agent
	AgentCredential string
	OrganizationID  string
}

// EnrollAgent verifies the bootstrap secret, increments the
// package's uses_count atomically, creates the agent row, and
// records an audit event — all in a single transaction.
//
// Atomicity: package usage, agent row, and audit event all commit
// together or all roll back. The atomic increment in
// IncrementUses() is the choke point that makes concurrent
// SCCM-style mass enrollment safe under MaxUses — if a thousand
// devices race to enroll through a package with max_uses=500, no
// more than 500 succeed.
//
// Rejection model: every failure mode (unknown secret, expired
// package, revoked package, exhausted package, malformed input,
// duplicate install_id) collapses to ErrEnrollmentRejected at the
// outer boundary. The internal reason is recorded as an audit
// event with severity:"security" so operators can diagnose
// rejections without leaking package state to the caller
// (CLAUDE.md §6: deterministic behavior; no enumeration).
func (s *Service) EnrollAgent(ctx context.Context, in EnrollAgentInput) (*EnrollAgentOutput, error) {
	if err := in.validate(); err != nil {
		// Don't audit input validation failures — the request never
		// even produced a package_id lookup, so there is nothing
		// for an operator to investigate. The HTTP layer rejects
		// the request with the same generic envelope as a bad
		// bootstrap secret.
		return nil, ErrEnrollmentRejected
	}

	hash := hashBearerToken(in.BootstrapSecret)
	pkg, err := s.packages.GetByBootstrapHash(ctx, hash)
	if err != nil {
		if errors.Is(err, ErrPackageNotFound) {
			// Bootstrap secret matched no package. We do not know
			// which organization this attempt belongs to (or if it
			// belongs to one at all), so the rejection is recorded
			// under the v0.1 single-tenant scope and the audit
			// write is best-effort: failing the response because of
			// an audit-side issue when we do not even have a
			// package id to attribute the rejection to would force
			// callers to retry against an unknown-secret path, and
			// that retry would itself be unauditable. Multi-tenant
			// will need a different policy (CLAUDE.md §4 —
			// multi-tenant org isolation is explicitly
			// v0.1-out-of-scope).
			_ = s.recordRejection(ctx, fallbackRejectionOrg, "", "bootstrap_secret_unknown", in)
			return nil, ErrEnrollmentRejected
		}
		return nil, fmt.Errorf("enrollment: lookup package: %w", err)
	}

	now := s.clock.Now()
	// Pre-check before opening the transaction. The authoritative
	// check is the conditional UPDATE inside IncrementUses below;
	// this early return saves us a tx round trip on the common
	// "already revoked" / "already expired" cases without weakening
	// the atomicity guarantee.
	if err := pkg.activeAt(now); err != nil {
		if auditErr := s.recordRejection(ctx, pkg.OrganizationID, pkg.ID, rejectionReason(err), in); auditErr != nil {
			// Known-package rejection: failing to audit the security
			// event is itself a security defect, surface as an
			// internal error rather than silently dropping the
			// rejection record (CLAUDE.md §9 — audit is not optional
			// on security-significant flows).
			return nil, fmt.Errorf("enrollment: record rejection: %w", auditErr)
		}
		return nil, ErrEnrollmentRejected
	}

	credPlain, credHash, err := generateBearerToken(s.rng)
	if err != nil {
		return nil, err
	}

	var fingerprintHash []byte
	if in.MachineFingerprint != "" {
		fingerprintHash = hashFingerprint(in.MachineFingerprint)
	}

	agent := &Agent{
		ID:                     ids.New(),
		OrganizationID:         pkg.OrganizationID,
		Hostname:               strings.TrimSpace(in.Hostname),
		DisplayName:            "",
		Status:                 AgentStatusActive,
		EnrolledAt:             now,
		LastSeenAt:             now,
		DeploymentPackageID:    pkg.ID,
		AgentVersion:           in.AgentVersion,
		MachineFingerprintHash: fingerprintHash,
		InstallID:              strings.TrimSpace(in.InstallID),
		GroupName:              pkg.DefaultGroupName,
		Labels:                 append([]string(nil), pkg.DefaultLabels...),
		UpdatedAt:              now,
	}

	if err := s.tx.WithTx(ctx, func(ctx context.Context) error {
		// Atomic guard against the three lifecycle bounds. If a
		// concurrent caller exhausts the package between our
		// pre-check above and this UPDATE, IncrementUses returns
		// ErrPackageExhausted (or ErrPackageRevoked / ErrPackageExpired)
		// and the entire transaction rolls back.
		if err := s.packages.IncrementUses(ctx, pkg.ID, now); err != nil {
			return err
		}
		if err := s.agents.Create(ctx, agent, credHash); err != nil {
			return err
		}
		md, _ := json.Marshal(map[string]any{
			"deployment_package_id": pkg.ID,
			"hostname":              agent.Hostname,
			"agent_version":         agent.AgentVersion,
			"group_name":            agent.GroupName,
			"label_count":           len(agent.Labels),
		})
		return s.audit.Record(ctx, audit.Event{
			OrganizationID: pkg.OrganizationID,
			Actor:          agent.ID,
			ActorType:      "agent",
			Action:         "agent.enrolled",
			TargetType:     "agent",
			TargetID:       agent.ID,
			RequestID:      in.RequestID,
			Metadata:       md,
		})
	}); err != nil {
		switch {
		case errors.Is(err, ErrPackageRevoked),
			errors.Is(err, ErrPackageExpired),
			errors.Is(err, ErrPackageExhausted):
			// Atomic-update race lost. The rejection MUST be audited
			// — failure to audit a security event is itself a
			// security defect (CLAUDE.md §9). Surface audit failure
			// as an internal error rather than swallowing it.
			if auditErr := s.recordRejection(ctx, pkg.OrganizationID, pkg.ID, rejectionReason(err), in); auditErr != nil {
				return nil, fmt.Errorf("enrollment: record rejection: %w", auditErr)
			}
			return nil, ErrEnrollmentRejected
		case errors.Is(err, ErrAgentAlreadyEnrolled):
			if auditErr := s.recordRejection(ctx, pkg.OrganizationID, pkg.ID, "install_id_already_enrolled", in); auditErr != nil {
				return nil, fmt.Errorf("enrollment: record rejection: %w", auditErr)
			}
			return nil, ErrEnrollmentRejected
		case errors.Is(err, ErrPackageNotFound):
			// IncrementUses returns ErrPackageNotFound when the
			// package row disappeared between the conditional
			// UPDATE and the follow-up classification SELECT —
			// almost always a concurrent operator hard-delete of
			// the package. The agent must still see the standard
			// generic rejection envelope (CLAUDE.md §6: no
			// enumeration via error code), so map this case to
			// ErrEnrollmentRejected rather than letting it fall
			// through to a 500.
			//
			// pkg.OrganizationID is the org we resolved BEFORE the
			// transaction, so we can still scope the audit row
			// correctly even though the package row itself is
			// gone.
			if auditErr := s.recordRejection(ctx, pkg.OrganizationID, pkg.ID, "package_concurrently_deleted", in); auditErr != nil {
				return nil, fmt.Errorf("enrollment: record rejection: %w", auditErr)
			}
			return nil, ErrEnrollmentRejected
		}
		return nil, err
	}

	return &EnrollAgentOutput{
		Agent:           agent,
		AgentCredential: credPlain,
		OrganizationID:  pkg.OrganizationID,
	}, nil
}

// AuthenticateAgentInput is what the agent-auth middleware passes
// to the service when validating an Authorization: Bearer header.
// Plaintext credential is hashed inside this method; the value
// never reaches the repository or any storage layer.
//
// Vocabulary note: AgentCredential is the post-enrollment bearer
// credential the control plane issued in
// EnrollAgentOutput.AgentCredential — NOT the bootstrap secret
// attached to the deployment package. The two have different
// lifecycles (one-per-package vs. one-per-agent) and different
// trust boundaries; do not conflate them.
//
// HeaderRejection is the middleware's signal that the
// Authorization header itself was unusable before any credential
// was extracted (missing entirely, wrong scheme, or empty token).
// When non-empty, the service short-circuits the credential
// lookup and records the rejection so probing patterns show up
// in the security audit feed alongside unknown-credential and
// disabled-agent failures (CLAUDE.md §9 — every auth failure
// is auditable).
type AuthenticateAgentInput struct {
	AgentCredential string // the agent_credential issued at enrollment
	HeaderRejection string // non-empty signals a pre-credential header failure
	RequestID       string // for audit correlation on failure
	RemoteAddr      string // for audit metadata only; never persisted as-is
}

// AuthenticateAgent verifies an agent's bearer credential and
// returns a narrow AuthenticatedAgent principal on success. Every
// failure mode collapses to ErrAgentAuthenticationFailed at the
// outer boundary; the internal reason is recorded as an
// agent.authentication_failed audit event tagged
// severity:"security" so operators can diagnose attempts without
// the caller being able to enumerate state.
//
// We do NOT update last_seen_at here. last_seen_at is the
// heartbeat-endpoint's responsibility (Phase 3); writing it on
// every authenticated read would generate one row-update per
// authenticated request, which is the wrong cost model.
func (s *Service) AuthenticateAgent(ctx context.Context, in AuthenticateAgentInput) (*AuthenticatedAgent, error) {
	if in.HeaderRejection != "" {
		// Middleware classified the Authorization header itself as
		// unusable. Audit the rejection so probing patterns
		// (missing header, wrong scheme, empty token) are visible
		// in the security feed, then surface the same
		// ErrAgentAuthenticationFailed sentinel as any other
		// failure mode (CLAUDE.md §6 deterministic auth).
		s.recordAuthFailure(ctx, "", "", in.HeaderRejection, in)
		return nil, ErrAgentAuthenticationFailed
	}
	if strings.TrimSpace(in.AgentCredential) == "" {
		s.recordAuthFailure(ctx, "", "", "credential_empty", in)
		return nil, ErrAgentAuthenticationFailed
	}

	hash := hashBearerToken(in.AgentCredential)
	agent, err := s.agents.FindByCredentialHash(ctx, hash)
	if err != nil {
		if errors.Is(err, ErrAgentNotFound) {
			s.recordAuthFailure(ctx, "", "", "credential_unknown", in)
			return nil, ErrAgentAuthenticationFailed
		}
		return nil, fmt.Errorf("enrollment: lookup agent by credential: %w", err)
	}

	if agent.Status != AgentStatusActive {
		// status "disabled" or "revoked": fail closed, audit the
		// rejection so operators can see attempted use of a
		// disabled agent's credential.
		s.recordAuthFailure(ctx, agent.OrganizationID, agent.ID, "agent_status_"+string(agent.Status), in)
		return nil, ErrAgentAuthenticationFailed
	}

	return &AuthenticatedAgent{
		AgentID:             agent.ID,
		OrganizationID:      agent.OrganizationID,
		Status:              agent.Status,
		DeploymentPackageID: agent.DeploymentPackageID,
		AgentVersion:        agent.AgentVersion,
		GroupName:           agent.GroupName,
		Labels:              append([]string(nil), agent.Labels...),
	}, nil
}

// recordAuthFailure writes an audit row for a failed agent-auth
// attempt. Best-effort (error ignored): failing the
// authentication response because the audit write failed would
// let an attacker DOS agent-side connectivity by probing
// audit-storage failures. The redaction allow-list +
// audit-metadata structure guarantee that the plaintext credential
// is never recorded.
//
// For unknown-credential failures we have no org context except
// the v0.1 single-tenant fallback ("anchorix") — same convention
// as auth.login_failed and the enrollment-rejection audit path.
func (s *Service) recordAuthFailure(ctx context.Context, orgID, agentID, reason string, in AuthenticateAgentInput) {
	if orgID == "" {
		orgID = fallbackRejectionOrg
	}
	md, _ := json.Marshal(map[string]any{
		"reason":      reason,
		"severity":    "security",
		"agent_id":    agentID,
		"remote_addr": in.RemoteAddr,
	})
	_ = s.audit.Record(ctx, audit.Event{
		OrganizationID: orgID,
		Actor:          agentID,
		ActorType:      "agent",
		Action:         "agent.authentication_failed",
		TargetType:     "agent",
		TargetID:       agentID,
		RequestID:      in.RequestID,
		Metadata:       md,
	})
}

// ListAgents returns the agents enrolled in the organization. The
// scoping check is the caller's responsibility — the HTTP handler
// passes the authenticated operator's organization id, and the
// repository's SQL is keyed by organization_id.
func (s *Service) ListAgents(ctx context.Context, organizationID string) ([]Agent, error) {
	if strings.TrimSpace(organizationID) == "" {
		return nil, errors.New("enrollment: list agents: organization id required")
	}
	return s.agents.List(ctx, organizationID)
}

// RevokePackageInput carries the operator's revoke request. The
// org id MUST be the authenticated admin's org (the HTTP handler
// derives it from the session). PackageID is the URL path
// parameter. RevokedByUserID is the admin's user id. Reason is
// optional operator-supplied text.
type RevokePackageInput struct {
	OrganizationID  string
	PackageID       string
	RevokedByUserID string
	Reason          string
}

// RevokePackageOutput is what the service returns after a
// revocation attempt. Package always carries the row's current
// state (with revoked_at populated). AlreadyRevoked is true when
// this call did NOT change the revoked state — the operator was
// re-revoking a package that was already revoked, and we returned
// the idempotent 200 path without a duplicate audit row.
type RevokePackageOutput struct {
	Package        *DeploymentPackage
	AlreadyRevoked bool
}

// RevokePackage marks a deployment package as revoked. Future
// enrollments through this package's bootstrap secret are
// rejected by IncrementUses (revoked_at IS NULL is part of the
// conditional UPDATE — see CLAUDE.md §6 + AGENT_ENROLLMENT.md
// "Package lifecycle"). Already enrolled agents are unaffected.
//
// Idempotency: revoking an already-revoked package is a no-op
// success. The current row is returned, the audit event is NOT
// re-emitted (the original revoke's audit row is the source of
// truth), and the HTTP layer responds 200 with AlreadyRevoked: true
// in the model. The contract is documented in REST_API.md +
// AGENT_ENROLLMENT.md.
//
// Atomicity: the UPDATE and the deployment_package.revoked audit
// row commit together. An audit-write failure rolls the UPDATE
// back so the control plane can never reach a state where a
// package is marked revoked without a matching audit row
// (CLAUDE.md §9).
//
// Org scoping: the package MUST belong to in.OrganizationID. A
// cross-org id returns ErrPackageNotFound — the same envelope a
// truly-missing id would produce, so admins cannot enumerate
// packages in neighboring tenants.
func (s *Service) RevokePackage(ctx context.Context, in RevokePackageInput) (*RevokePackageOutput, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}

	var (
		current        *DeploymentPackage
		alreadyRevoked bool
	)
	if err := s.tx.WithTx(ctx, func(ctx context.Context) error {
		pkg, err := s.packages.GetByIDAndOrg(ctx, in.PackageID, in.OrganizationID)
		if err != nil {
			return err
		}
		if pkg.RevokedAt != nil {
			// Idempotent path. No UPDATE, no audit. The original
			// revoke's audit row is already in the trail; emitting
			// a second one for a no-op would only add noise.
			current = pkg
			alreadyRevoked = true
			return nil
		}

		now := s.clock.Now()
		if err := s.packages.Revoke(ctx, pkg.ID, in.OrganizationID, in.RevokedByUserID, in.Reason, now); err != nil {
			// Concurrent revoke race: another admin revoked between
			// our GetByIDAndOrg and our UPDATE. Treat as idempotent.
			if errors.Is(err, ErrPackageAlreadyRevoked) {
				// Re-read for the current revoked metadata so the
				// response reflects the actual revoker.
				latest, getErr := s.packages.GetByIDAndOrg(ctx, in.PackageID, in.OrganizationID)
				if getErr != nil {
					return getErr
				}
				current = latest
				alreadyRevoked = true
				return nil
			}
			return err
		}

		// Mutate the in-memory copy so the response reflects the
		// new state without a follow-up SELECT.
		pkg.RevokedAt = &now
		pkg.RevokedByUserID = in.RevokedByUserID
		pkg.RevokedReason = in.Reason
		current = pkg

		md, _ := json.Marshal(map[string]any{
			"package_type":  string(pkg.PackageType),
			"agent_version": pkg.AgentVersion,
			"uses_count":    pkg.UsesCount,
			"max_uses":      pkg.MaxUses,
			"has_reason":    in.Reason != "",
			"reason_length": len(in.Reason),
		})
		return s.audit.Record(ctx, audit.Event{
			OrganizationID: in.OrganizationID,
			Actor:          in.RevokedByUserID,
			ActorType:      "user",
			Action:         "deployment_package.revoked",
			TargetType:     "deployment_package",
			TargetID:       pkg.ID,
			Metadata:       md,
		})
	}); err != nil {
		return nil, err
	}
	return &RevokePackageOutput{Package: current, AlreadyRevoked: alreadyRevoked}, nil
}

func (in RevokePackageInput) validate() error {
	if strings.TrimSpace(in.OrganizationID) == "" {
		return fmt.Errorf("%w: organization id required", ErrInvalidPackageInput)
	}
	if strings.TrimSpace(in.PackageID) == "" {
		return fmt.Errorf("%w: package id required", ErrInvalidPackageInput)
	}
	if strings.TrimSpace(in.RevokedByUserID) == "" {
		return fmt.Errorf("%w: revoking user id required", ErrInvalidPackageInput)
	}
	return nil
}

// fallbackRejectionOrg is the v0.1 single-tenant organization scope
// used for audit rows where the rejection happened before we could
// identify the operator's organization (e.g. an unknown bootstrap
// secret). Mirrors the convention used by auth.Service for
// auth.login_failed when the email did not resolve to a user.
const fallbackRejectionOrg = "anchorix"

// recordRejection writes an audit row for a failed enrollment and
// returns the audit-writer's error so callers can decide whether
// to surface it.
//
// Policy split (callers enforce, not this function):
//
//   - Known-package rejections (revoked / expired / exhausted /
//     duplicate install_id): the caller propagates a non-nil error
//     as an internal-error response. Failing to audit a security
//     event is itself a security defect (CLAUDE.md §9 — audit is
//     not optional on security-significant flows).
//   - Unknown-bootstrap-secret rejections: the caller discards the
//     returned error and proceeds with ErrEnrollmentRejected.
//     Without a package id we have no org context except the v0.1
//     single-tenant fallback, and forcing the response to fail
//     when audit cannot write would let attackers DOS the agent
//     enrollment endpoint indirectly via audit-storage problems.
//
// Metadata never carries the bootstrap secret or any agent
// credential.
func (s *Service) recordRejection(ctx context.Context, orgID, packageID, reason string, in EnrollAgentInput) error {
	md, _ := json.Marshal(map[string]any{
		"reason":                reason,
		"severity":              "security",
		"deployment_package_id": packageID,
		"hostname":              strings.TrimSpace(in.Hostname),
		"agent_version":         in.AgentVersion,
		"has_install_id":        in.InstallID != "",
		"has_machine_fp":        in.MachineFingerprint != "",
	})
	return s.audit.Record(ctx, audit.Event{
		OrganizationID: orgID,
		Actor:          "unknown_agent",
		ActorType:      "agent",
		Action:         "agent.enrollment_rejected",
		TargetType:     "deployment_package",
		TargetID:       packageID,
		RequestID:      in.RequestID,
		Metadata:       md,
	})
}

// rejectionReason maps the internal lifecycle errors to short
// machine-stable strings used in audit metadata. These strings are
// stable across releases — operators may grep them.
func rejectionReason(err error) string {
	switch {
	case errors.Is(err, ErrPackageRevoked):
		return "package_revoked"
	case errors.Is(err, ErrPackageExpired):
		return "package_expired"
	case errors.Is(err, ErrPackageExhausted):
		return "package_exhausted"
	}
	return "unknown"
}

// validate is the input-validation helper for CreatePackage. It
// returns ErrInvalidPackageInput wrapped with a short reason so
// tests can assert on errors.Is(err, ErrInvalidPackageInput) while
// developers see the specific cause in the wrapped message.
func (in CreatePackageInput) validate() error {
	if strings.TrimSpace(in.OrganizationID) == "" {
		return fmt.Errorf("%w: organization id required", ErrInvalidPackageInput)
	}
	if strings.TrimSpace(in.CreatedByUserID) == "" {
		return fmt.Errorf("%w: creator user id required", ErrInvalidPackageInput)
	}
	if strings.TrimSpace(in.Name) == "" {
		return fmt.Errorf("%w: name required", ErrInvalidPackageInput)
	}
	if !in.PackageType.Valid() {
		return fmt.Errorf("%w: package_type %q invalid", ErrInvalidPackageInput, in.PackageType)
	}
	if in.TTL <= 0 {
		return fmt.Errorf("%w: ttl must be positive", ErrInvalidPackageInput)
	}
	if in.MaxUses <= 0 {
		return fmt.Errorf("%w: max_uses must be positive", ErrInvalidPackageInput)
	}
	return nil
}

func (in EnrollAgentInput) validate() error {
	if strings.TrimSpace(in.BootstrapSecret) == "" {
		return ErrInvalidEnrollmentInput
	}
	if strings.TrimSpace(in.Hostname) == "" {
		return ErrInvalidEnrollmentInput
	}
	return nil
}
