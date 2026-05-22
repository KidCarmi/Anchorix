package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/kidcarmi/anchorix/backend/internal/audit"
	"github.com/kidcarmi/anchorix/backend/internal/clock"
	"github.com/kidcarmi/anchorix/backend/internal/ids"
)

// Transactor runs fn inside a single database transaction so
// the state-change repository call and the audit row commit
// atomically. Failures (in either path) roll the whole tx
// back. Owned by the consumer (CLAUDE.md §8.8).
type Transactor interface {
	WithTx(ctx context.Context, fn func(ctx context.Context) error) error
}

// TargetResolver is the consumer-owned interface used to
// validate polymorphic tag_assignments and memberships. The
// composition root stitches it together from the inventory +
// agents repositories.
//
// All methods return (true, nil) when the row exists in
// organizationID, (false, nil) when it does not, and an error
// only for repository-level failures (which the service
// surfaces to the caller verbatim).
type TargetResolver interface {
	CertificateExists(ctx context.Context, organizationID, certificateID string) (bool, error)
	AgentExists(ctx context.Context, organizationID, agentID string) (bool, error)
}

// Service is the identity-domain entrypoint. The HTTP layer
// depends on Service, never on Repository directly (CLAUDE.md
// §8.6, §8.8). Service owns:
//
//   - slug / key / value validation,
//   - polymorphic tag_assignments target validation,
//   - service_group parent cycle detection,
//   - disable preflight (tag_in_use, service_in_use,
//     service_group_has_children),
//   - audit recording for every state change inside the same
//     transaction as the state-change repo call.
type Service struct {
	repo     Repository
	tx       Transactor
	audit    audit.Recorder
	resolver TargetResolver
	clock    clock.Clock
}

// NewService wires the service.
func NewService(
	repo Repository,
	tx Transactor,
	auditRec audit.Recorder,
	resolver TargetResolver,
	clk clock.Clock,
) (*Service, error) {
	switch {
	case repo == nil:
		return nil, errors.New("identity.NewService: repository required")
	case tx == nil:
		return nil, errors.New("identity.NewService: transactor required")
	case auditRec == nil:
		return nil, errors.New("identity.NewService: audit recorder required")
	case resolver == nil:
		return nil, errors.New("identity.NewService: target resolver required")
	case clk == nil:
		return nil, errors.New("identity.NewService: clock required")
	}
	return &Service{
		repo:     repo,
		tx:       tx,
		audit:    auditRec,
		resolver: resolver,
		clock:    clk,
	}, nil
}

// ----- shared helpers -----

func requireOrg(s string) error {
	if strings.TrimSpace(s) == "" {
		return fmt.Errorf("%w: organization id required", ErrInvalidInput)
	}
	return nil
}

func requireActor(s string) error {
	if strings.TrimSpace(s) == "" {
		return fmt.Errorf("%w: actor user id required", ErrInvalidInput)
	}
	return nil
}

// mustMarshalSecurityMetadata serializes the metadata map plus
// the mandatory `severity: "security"` field that every
// governance audit row carries per CLAUDE.md §9. Marshal
// failure on a map[string]any with documented value types is
// effectively unreachable, so the helper deliberately ignores
// the error path — a real failure would be a programmer bug
// caught at unit-test time.
func mustMarshalSecurityMetadata(extra map[string]any) []byte {
	combined := make(map[string]any, len(extra)+1)
	combined["severity"] = "security"
	for k, v := range extra {
		combined[k] = v
	}
	b, _ := json.Marshal(combined)
	return b
}

// recordAudit centralizes the audit.Recorder call so any
// failure wraps to ErrInternalAudit. State-changing methods
// invoke this inside their WithTx callback; an audit failure
// rolls the whole tx back, taking the state change with it.
func (s *Service) recordAudit(ctx context.Context, e audit.Event) error {
	if err := s.audit.Record(ctx, e); err != nil {
		return fmt.Errorf("%w: %v", ErrInternalAudit, err)
	}
	return nil
}

// targetExists dispatches the polymorphic target lookup. The
// service-layer (rather than DB-FK) check returns
// ErrTagAssignmentTargetInvalid; a DB-side FK violation would
// surface as a generic 500 — the service version produces a
// clean 400 with the actual cause.
func (s *Service) targetExists(
	ctx context.Context,
	organizationID string,
	targetType TagTargetType,
	targetID string,
) (bool, error) {
	switch targetType {
	case TagTargetCertificate:
		return s.resolver.CertificateExists(ctx, organizationID, targetID)
	case TagTargetAgent:
		return s.resolver.AgentExists(ctx, organizationID, targetID)
	case TagTargetService:
		_, err := s.repo.GetService(ctx, organizationID, targetID)
		if err != nil {
			if errors.Is(err, ErrServiceNotFound) {
				return false, nil
			}
			return false, err
		}
		return true, nil
	case TagTargetServiceGroup:
		_, err := s.repo.GetServiceGroup(ctx, organizationID, targetID)
		if err != nil {
			if errors.Is(err, ErrServiceGroupNotFound) {
				return false, nil
			}
			return false, err
		}
		return true, nil
	case TagTargetAgentGroup:
		_, err := s.repo.GetAgentGroup(ctx, organizationID, targetID)
		if err != nil {
			if errors.Is(err, ErrAgentGroupNotFound) {
				return false, nil
			}
			return false, err
		}
		return true, nil
	}
	return false, fmt.Errorf("%w: unknown target_type %q", ErrInvalidInput, targetType)
}

// ----- Tag CRUD -----

// CreateTagInput is the validated input to CreateTag.
type CreateTagInput struct {
	OrganizationID string
	Key            string
	Value          string
	Description    string
	ActorUserID    string
}

func (s *Service) CreateTag(ctx context.Context, in CreateTagInput) (*Tag, error) {
	in.Key = strings.TrimSpace(in.Key)
	in.Value = strings.TrimSpace(in.Value)
	in.Description = strings.TrimSpace(in.Description)
	if err := requireOrg(in.OrganizationID); err != nil {
		return nil, err
	}
	if err := requireActor(in.ActorUserID); err != nil {
		return nil, err
	}
	if err := validateTagKey(in.Key); err != nil {
		return nil, err
	}
	if err := validateTagValue(in.Value); err != nil {
		return nil, err
	}
	if err := validateBounded("description", in.Description, maxDescriptionLen); err != nil {
		return nil, err
	}

	now := s.clock.Now()
	tag := &Tag{
		ID:             ids.New(),
		OrganizationID: in.OrganizationID,
		Key:            in.Key,
		Value:          in.Value,
		Description:    in.Description,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := s.tx.WithTx(ctx, func(ctx context.Context) error {
		if err := s.repo.CreateTag(ctx, tag); err != nil {
			return fmt.Errorf("identity: create tag: %w", err)
		}
		return s.recordAudit(ctx, audit.Event{
			OrganizationID: in.OrganizationID,
			OccurredAt:     now,
			Actor:          in.ActorUserID,
			ActorType:      "user",
			Action:         "tag.created",
			TargetType:     "tag",
			TargetID:       tag.ID,
			Metadata: mustMarshalSecurityMetadata(map[string]any{
				"key":   tag.Key,
				"value": tag.Value,
			}),
		})
	}); err != nil {
		return nil, err
	}
	return tag, nil
}

func (s *Service) GetTag(ctx context.Context, organizationID, tagID string) (*Tag, error) {
	if err := requireOrg(organizationID); err != nil {
		return nil, err
	}
	if tagID == "" {
		return nil, fmt.Errorf("%w: tag id required", ErrInvalidInput)
	}
	return s.repo.GetTag(ctx, organizationID, tagID)
}

func (s *Service) ListTags(ctx context.Context, organizationID string, activeOnly bool) ([]Tag, error) {
	if err := requireOrg(organizationID); err != nil {
		return nil, err
	}
	return s.repo.ListTags(ctx, organizationID, activeOnly)
}

// UpdateTagDescriptionInput is the validated input to
// UpdateTagDescription. Tag identity (key, value) is
// IMMUTABLE — see ErrTagIdentityImmutable. The HTTP handler
// rejects PATCH payloads with `key` / `value` fields before
// reaching the service.
type UpdateTagDescriptionInput struct {
	OrganizationID string
	TagID          string
	Description    string
	ActorUserID    string
}

func (s *Service) UpdateTagDescription(ctx context.Context, in UpdateTagDescriptionInput) error {
	if err := requireOrg(in.OrganizationID); err != nil {
		return err
	}
	if err := requireActor(in.ActorUserID); err != nil {
		return err
	}
	if in.TagID == "" {
		return fmt.Errorf("%w: tag id required", ErrInvalidInput)
	}
	if err := validateBounded("description", in.Description, maxDescriptionLen); err != nil {
		return err
	}
	now := s.clock.Now()
	return s.tx.WithTx(ctx, func(ctx context.Context) error {
		if err := s.repo.UpdateTagDescription(ctx, in.OrganizationID, in.TagID, strings.TrimSpace(in.Description)); err != nil {
			return err
		}
		return s.recordAudit(ctx, audit.Event{
			OrganizationID: in.OrganizationID,
			OccurredAt:     now,
			Actor:          in.ActorUserID,
			ActorType:      "user",
			Action:         "tag.updated",
			TargetType:     "tag",
			TargetID:       in.TagID,
			Metadata:       mustMarshalSecurityMetadata(map[string]any{}),
		})
	})
}

// DisableTagInput / EnableTagInput are validated inputs to the
// soft-delete cycle. The operator must supply a reason on
// disable (recorded in audit metadata).
type DisableTagInput struct {
	OrganizationID string
	TagID          string
	Reason         string
	ActorUserID    string
}

func (s *Service) DisableTag(ctx context.Context, in DisableTagInput) error {
	if err := requireOrg(in.OrganizationID); err != nil {
		return err
	}
	if err := requireActor(in.ActorUserID); err != nil {
		return err
	}
	if in.TagID == "" {
		return fmt.Errorf("%w: tag id required", ErrInvalidInput)
	}
	if err := validateReason("reason", in.Reason); err != nil {
		return err
	}
	now := s.clock.Now()
	return s.tx.WithTx(ctx, func(ctx context.Context) error {
		assignments, err := s.repo.ListTagAssignmentsForTag(ctx, in.OrganizationID, in.TagID)
		if err != nil {
			return fmt.Errorf("identity: tag-in-use preflight: %w", err)
		}
		if len(assignments) > 0 {
			return ErrTagInUse
		}
		if err := s.repo.DisableTag(ctx, in.OrganizationID, in.TagID); err != nil {
			return err
		}
		return s.recordAudit(ctx, audit.Event{
			OrganizationID: in.OrganizationID,
			OccurredAt:     now,
			Actor:          in.ActorUserID,
			ActorType:      "user",
			Action:         "tag.disabled",
			TargetType:     "tag",
			TargetID:       in.TagID,
			Metadata: mustMarshalSecurityMetadata(map[string]any{
				"reason": strings.TrimSpace(in.Reason),
			}),
		})
	})
}

type EnableTagInput struct {
	OrganizationID string
	TagID          string
	ActorUserID    string
}

func (s *Service) EnableTag(ctx context.Context, in EnableTagInput) error {
	if err := requireOrg(in.OrganizationID); err != nil {
		return err
	}
	if err := requireActor(in.ActorUserID); err != nil {
		return err
	}
	if in.TagID == "" {
		return fmt.Errorf("%w: tag id required", ErrInvalidInput)
	}
	now := s.clock.Now()
	return s.tx.WithTx(ctx, func(ctx context.Context) error {
		if err := s.repo.EnableTag(ctx, in.OrganizationID, in.TagID); err != nil {
			return err
		}
		return s.recordAudit(ctx, audit.Event{
			OrganizationID: in.OrganizationID,
			OccurredAt:     now,
			Actor:          in.ActorUserID,
			ActorType:      "user",
			Action:         "tag.enabled",
			TargetType:     "tag",
			TargetID:       in.TagID,
			Metadata:       mustMarshalSecurityMetadata(map[string]any{}),
		})
	})
}

// ----- TagAssignment CRUD -----

type AssignTagInput struct {
	OrganizationID string
	TagID          string
	TargetType     TagTargetType
	TargetID       string
	ActorUserID    string
}

func (s *Service) AssignTag(ctx context.Context, in AssignTagInput) (*TagAssignment, error) {
	if err := requireOrg(in.OrganizationID); err != nil {
		return nil, err
	}
	if err := requireActor(in.ActorUserID); err != nil {
		return nil, err
	}
	if in.TagID == "" {
		return nil, fmt.Errorf("%w: tag id required", ErrInvalidInput)
	}
	if err := validateTargetType(in.TargetType); err != nil {
		return nil, err
	}
	if err := validateTargetID(in.TargetID); err != nil {
		return nil, err
	}

	now := s.clock.Now()
	a := &TagAssignment{
		ID:             ids.New(),
		OrganizationID: in.OrganizationID,
		TagID:          in.TagID,
		TargetType:     in.TargetType,
		TargetID:       in.TargetID,
		AssignedBy:     in.ActorUserID,
		AssignedAt:     now,
	}
	if err := s.tx.WithTx(ctx, func(ctx context.Context) error {
		if _, err := s.repo.GetTag(ctx, in.OrganizationID, in.TagID); err != nil {
			return err
		}
		ok, err := s.targetExists(ctx, in.OrganizationID, in.TargetType, in.TargetID)
		if err != nil {
			return err
		}
		if !ok {
			return ErrTagAssignmentTargetInvalid
		}
		if err := s.repo.CreateTagAssignment(ctx, a); err != nil {
			return fmt.Errorf("identity: create tag assignment: %w", err)
		}
		return s.recordAudit(ctx, audit.Event{
			OrganizationID: in.OrganizationID,
			OccurredAt:     now,
			Actor:          in.ActorUserID,
			ActorType:      "user",
			Action:         "tag.assignment_created",
			TargetType:     "tag_assignment",
			TargetID:       a.ID,
			Metadata: mustMarshalSecurityMetadata(map[string]any{
				"tag_id":      in.TagID,
				"target_type": string(in.TargetType),
				"target_id":   in.TargetID,
			}),
		})
	}); err != nil {
		return nil, err
	}
	return a, nil
}

type UnassignTagInput struct {
	OrganizationID string
	TagID          string
	TargetType     TagTargetType
	TargetID       string
	ActorUserID    string
}

func (s *Service) UnassignTag(ctx context.Context, in UnassignTagInput) error {
	if err := requireOrg(in.OrganizationID); err != nil {
		return err
	}
	if err := requireActor(in.ActorUserID); err != nil {
		return err
	}
	if in.TagID == "" {
		return fmt.Errorf("%w: tag id required", ErrInvalidInput)
	}
	if err := validateTargetType(in.TargetType); err != nil {
		return err
	}
	if err := validateTargetID(in.TargetID); err != nil {
		return err
	}
	now := s.clock.Now()
	return s.tx.WithTx(ctx, func(ctx context.Context) error {
		if err := s.repo.DeleteTagAssignmentByTarget(
			ctx, in.OrganizationID, in.TagID, in.TargetType, in.TargetID,
		); err != nil {
			return err
		}
		return s.recordAudit(ctx, audit.Event{
			OrganizationID: in.OrganizationID,
			OccurredAt:     now,
			Actor:          in.ActorUserID,
			ActorType:      "user",
			Action:         "tag.assignment_deleted",
			TargetType:     "tag_assignment",
			TargetID:       in.TagID + ":" + string(in.TargetType) + ":" + in.TargetID,
			Metadata: mustMarshalSecurityMetadata(map[string]any{
				"tag_id":      in.TagID,
				"target_type": string(in.TargetType),
				"target_id":   in.TargetID,
			}),
		})
	})
}

func (s *Service) ListTagAssignmentsForTag(ctx context.Context, organizationID, tagID string) ([]TagAssignment, error) {
	if err := requireOrg(organizationID); err != nil {
		return nil, err
	}
	if tagID == "" {
		return nil, fmt.Errorf("%w: tag id required", ErrInvalidInput)
	}
	return s.repo.ListTagAssignmentsForTag(ctx, organizationID, tagID)
}

// ----- Service (the business entity) CRUD -----

type CreateServiceInput struct {
	OrganizationID string
	Slug           string
	DisplayName    string
	Description    string
	OwnerEmail     string
	OwnerTeam      string
	BusinessUnit   string
	ActorUserID    string
}

func (s *Service) CreateService(ctx context.Context, in CreateServiceInput) (*ServiceRecord, error) {
	in.Slug = strings.TrimSpace(in.Slug)
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	in.Description = strings.TrimSpace(in.Description)
	in.OwnerEmail = strings.TrimSpace(in.OwnerEmail)
	in.OwnerTeam = strings.TrimSpace(in.OwnerTeam)
	in.BusinessUnit = strings.TrimSpace(in.BusinessUnit)
	if err := requireOrg(in.OrganizationID); err != nil {
		return nil, err
	}
	if err := requireActor(in.ActorUserID); err != nil {
		return nil, err
	}
	if err := validateSlug("slug", in.Slug); err != nil {
		return nil, err
	}
	if err := validateNonEmptyBounded("display_name", in.DisplayName, maxDisplayNameLen); err != nil {
		return nil, err
	}
	if err := validateBounded("description", in.Description, maxDescriptionLen); err != nil {
		return nil, err
	}
	if err := validateBounded("owner_email", in.OwnerEmail, maxOwnerEmailLen); err != nil {
		return nil, err
	}
	if err := validateBounded("owner_team", in.OwnerTeam, maxOwnerTeamLen); err != nil {
		return nil, err
	}
	if err := validateBounded("business_unit", in.BusinessUnit, maxBusinessUnit); err != nil {
		return nil, err
	}

	now := s.clock.Now()
	svc := &ServiceRecord{
		ID:             ids.New(),
		OrganizationID: in.OrganizationID,
		Slug:           in.Slug,
		DisplayName:    in.DisplayName,
		Description:    in.Description,
		OwnerEmail:     in.OwnerEmail,
		OwnerTeam:      in.OwnerTeam,
		BusinessUnit:   in.BusinessUnit,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := s.tx.WithTx(ctx, func(ctx context.Context) error {
		if err := s.repo.CreateService(ctx, svc); err != nil {
			return fmt.Errorf("identity: create service: %w", err)
		}
		return s.recordAudit(ctx, audit.Event{
			OrganizationID: in.OrganizationID,
			OccurredAt:     now,
			Actor:          in.ActorUserID,
			ActorType:      "user",
			Action:         "service.created",
			TargetType:     "service",
			TargetID:       svc.ID,
			Metadata: mustMarshalSecurityMetadata(map[string]any{
				"slug": svc.Slug,
			}),
		})
	}); err != nil {
		return nil, err
	}
	return svc, nil
}

func (s *Service) GetService(ctx context.Context, organizationID, serviceID string) (*ServiceRecord, error) {
	if err := requireOrg(organizationID); err != nil {
		return nil, err
	}
	if serviceID == "" {
		return nil, fmt.Errorf("%w: service id required", ErrInvalidInput)
	}
	return s.repo.GetService(ctx, organizationID, serviceID)
}

func (s *Service) ListServices(ctx context.Context, organizationID string, activeOnly bool) ([]ServiceRecord, error) {
	if err := requireOrg(organizationID); err != nil {
		return nil, err
	}
	return s.repo.ListServices(ctx, organizationID, activeOnly)
}

type UpdateServiceInput struct {
	OrganizationID string
	ServiceID      string
	DisplayName    string
	Description    string
	OwnerEmail     string
	OwnerTeam      string
	BusinessUnit   string
	ActorUserID    string
}

func (s *Service) UpdateService(ctx context.Context, in UpdateServiceInput) error {
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	in.Description = strings.TrimSpace(in.Description)
	in.OwnerEmail = strings.TrimSpace(in.OwnerEmail)
	in.OwnerTeam = strings.TrimSpace(in.OwnerTeam)
	in.BusinessUnit = strings.TrimSpace(in.BusinessUnit)
	if err := requireOrg(in.OrganizationID); err != nil {
		return err
	}
	if err := requireActor(in.ActorUserID); err != nil {
		return err
	}
	if in.ServiceID == "" {
		return fmt.Errorf("%w: service id required", ErrInvalidInput)
	}
	if err := validateNonEmptyBounded("display_name", in.DisplayName, maxDisplayNameLen); err != nil {
		return err
	}
	if err := validateBounded("description", in.Description, maxDescriptionLen); err != nil {
		return err
	}
	if err := validateBounded("owner_email", in.OwnerEmail, maxOwnerEmailLen); err != nil {
		return err
	}
	if err := validateBounded("owner_team", in.OwnerTeam, maxOwnerTeamLen); err != nil {
		return err
	}
	if err := validateBounded("business_unit", in.BusinessUnit, maxBusinessUnit); err != nil {
		return err
	}
	now := s.clock.Now()
	return s.tx.WithTx(ctx, func(ctx context.Context) error {
		if err := s.repo.UpdateServiceMetadata(
			ctx, in.OrganizationID, in.ServiceID,
			in.DisplayName, in.Description, in.OwnerEmail, in.OwnerTeam, in.BusinessUnit,
		); err != nil {
			return err
		}
		return s.recordAudit(ctx, audit.Event{
			OrganizationID: in.OrganizationID,
			OccurredAt:     now,
			Actor:          in.ActorUserID,
			ActorType:      "user",
			Action:         "service.updated",
			TargetType:     "service",
			TargetID:       in.ServiceID,
			Metadata:       mustMarshalSecurityMetadata(map[string]any{}),
		})
	})
}

type DisableServiceInput struct {
	OrganizationID string
	ServiceID      string
	Reason         string
	ActorUserID    string
}

// DisableService rejects the call if the service is still
// referenced by ownership rules. Cert-ownership / override
// references are out-of-package; the H-026B engine will own
// its own preflight when it activates. v0.x considers an
// ownership-rule reference the only blocking signal.
func (s *Service) DisableService(ctx context.Context, in DisableServiceInput) error {
	if err := requireOrg(in.OrganizationID); err != nil {
		return err
	}
	if err := requireActor(in.ActorUserID); err != nil {
		return err
	}
	if in.ServiceID == "" {
		return fmt.Errorf("%w: service id required", ErrInvalidInput)
	}
	if err := validateReason("reason", in.Reason); err != nil {
		return err
	}
	now := s.clock.Now()
	return s.tx.WithTx(ctx, func(ctx context.Context) error {
		// preflight: any ownership_rule points at this service?
		// Defer to H-026B for richer cert/ownership preflight.
		rules, err := s.governanceRulesForService(ctx, in.OrganizationID, in.ServiceID)
		if err != nil {
			return err
		}
		if rules > 0 {
			return ErrServiceInUse
		}
		if err := s.repo.DisableService(ctx, in.OrganizationID, in.ServiceID); err != nil {
			return err
		}
		return s.recordAudit(ctx, audit.Event{
			OrganizationID: in.OrganizationID,
			OccurredAt:     now,
			Actor:          in.ActorUserID,
			ActorType:      "user",
			Action:         "service.disabled",
			TargetType:     "service",
			TargetID:       in.ServiceID,
			Metadata: mustMarshalSecurityMetadata(map[string]any{
				"reason": strings.TrimSpace(in.Reason),
			}),
		})
	})
}

// governanceRulesForService is a hole the H-026A2 service layer
// punches into the governance.OwnershipRepository to count
// rules referencing a service. We deliberately do not import
// the governance package (CLAUDE.md §8.6: identity → governance
// is the forbidden direction). The OwnershipRulesProbe
// interface inverts the dependency: governance implements the
// probe, identity consumes it.
//
// Wired via the service constructor as a future addition once
// H-026B lands. For H-026A2, the probe is OPTIONAL — when nil
// the preflight short-circuits to 0 (no blocking rules).
//
// Recording this here as a forward-compatible seam: the
// disable preflight is not bypassable in production once the
// engine exists; in the current H-026A2 build the seam is
// inactive so disabling a service always succeeds at the
// identity layer (the schema's ON DELETE RESTRICT FKs are the
// ultimate guard for physical deletion).
func (s *Service) governanceRulesForService(ctx context.Context, organizationID, serviceID string) (int, error) {
	// Intentional no-op until the probe is wired in H-026B.
	// Returning 0 keeps the disable path operational at the
	// identity layer; ownership rules pointing at the service
	// will block delete via the DB FK once H-026B is live.
	_ = ctx
	_ = organizationID
	_ = serviceID
	return 0, nil
}

type EnableServiceInput struct {
	OrganizationID string
	ServiceID      string
	ActorUserID    string
}

func (s *Service) EnableService(ctx context.Context, in EnableServiceInput) error {
	if err := requireOrg(in.OrganizationID); err != nil {
		return err
	}
	if err := requireActor(in.ActorUserID); err != nil {
		return err
	}
	if in.ServiceID == "" {
		return fmt.Errorf("%w: service id required", ErrInvalidInput)
	}
	now := s.clock.Now()
	return s.tx.WithTx(ctx, func(ctx context.Context) error {
		if err := s.repo.EnableService(ctx, in.OrganizationID, in.ServiceID); err != nil {
			return err
		}
		return s.recordAudit(ctx, audit.Event{
			OrganizationID: in.OrganizationID,
			OccurredAt:     now,
			Actor:          in.ActorUserID,
			ActorType:      "user",
			Action:         "service.enabled",
			TargetType:     "service",
			TargetID:       in.ServiceID,
			Metadata:       mustMarshalSecurityMetadata(map[string]any{}),
		})
	})
}

// ----- Service group CRUD -----

type CreateServiceGroupInput struct {
	OrganizationID string
	Slug           string
	DisplayName    string
	Description    string
	ParentID       *string
	ActorUserID    string
}

func (s *Service) CreateServiceGroup(ctx context.Context, in CreateServiceGroupInput) (*ServiceGroup, error) {
	in.Slug = strings.TrimSpace(in.Slug)
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	in.Description = strings.TrimSpace(in.Description)
	if err := requireOrg(in.OrganizationID); err != nil {
		return nil, err
	}
	if err := requireActor(in.ActorUserID); err != nil {
		return nil, err
	}
	if err := validateSlug("slug", in.Slug); err != nil {
		return nil, err
	}
	if err := validateNonEmptyBounded("display_name", in.DisplayName, maxDisplayNameLen); err != nil {
		return nil, err
	}
	if err := validateBounded("description", in.Description, maxDescriptionLen); err != nil {
		return nil, err
	}
	now := s.clock.Now()
	g := &ServiceGroup{
		ID:             ids.New(),
		OrganizationID: in.OrganizationID,
		Slug:           in.Slug,
		DisplayName:    in.DisplayName,
		Description:    in.Description,
		ParentID:       in.ParentID,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := s.tx.WithTx(ctx, func(ctx context.Context) error {
		if in.ParentID != nil {
			// Parent must exist in the same org. The
			// composite FK would also reject, but the
			// explicit check returns ErrServiceGroupNotFound
			// rather than a generic SQL error.
			if _, err := s.repo.GetServiceGroup(ctx, in.OrganizationID, *in.ParentID); err != nil {
				return err
			}
			// Cycle check: at create time the new group's
			// id is fresh, so it can't yet be an ancestor of
			// the proposed parent. The walk is purely
			// defense-in-depth against an id collision (with
			// 128-bit ids effectively unreachable) and to
			// share the helper with UpdateServiceGroupParent.
			if err := s.checkNoCycle(ctx, in.OrganizationID, g.ID, *in.ParentID); err != nil {
				return err
			}
		}
		if err := s.repo.CreateServiceGroup(ctx, g); err != nil {
			return fmt.Errorf("identity: create service group: %w", err)
		}
		return s.recordAudit(ctx, audit.Event{
			OrganizationID: in.OrganizationID,
			OccurredAt:     now,
			Actor:          in.ActorUserID,
			ActorType:      "user",
			Action:         "service_group.created",
			TargetType:     "service_group",
			TargetID:       g.ID,
			Metadata: mustMarshalSecurityMetadata(map[string]any{
				"slug": g.Slug,
			}),
		})
	}); err != nil {
		return nil, err
	}
	return g, nil
}

func (s *Service) GetServiceGroup(ctx context.Context, organizationID, groupID string) (*ServiceGroup, error) {
	if err := requireOrg(organizationID); err != nil {
		return nil, err
	}
	if groupID == "" {
		return nil, fmt.Errorf("%w: service group id required", ErrInvalidInput)
	}
	return s.repo.GetServiceGroup(ctx, organizationID, groupID)
}

func (s *Service) ListServiceGroups(ctx context.Context, organizationID string, activeOnly bool) ([]ServiceGroup, error) {
	if err := requireOrg(organizationID); err != nil {
		return nil, err
	}
	return s.repo.ListServiceGroups(ctx, organizationID, activeOnly)
}

type UpdateServiceGroupParentInput struct {
	OrganizationID string
	GroupID        string
	ParentID       *string // nil means "make root"
	ActorUserID    string
}

// UpdateServiceGroupParent walks the ancestor chain of the
// proposed parent to verify the group itself is not (already
// or transitively) an ancestor of the proposed parent. Returns
// ErrServiceGroupCycle on cycle detection.
func (s *Service) UpdateServiceGroupParent(ctx context.Context, in UpdateServiceGroupParentInput) error {
	if err := requireOrg(in.OrganizationID); err != nil {
		return err
	}
	if err := requireActor(in.ActorUserID); err != nil {
		return err
	}
	if in.GroupID == "" {
		return fmt.Errorf("%w: service group id required", ErrInvalidInput)
	}
	now := s.clock.Now()
	return s.tx.WithTx(ctx, func(ctx context.Context) error {
		if _, err := s.repo.GetServiceGroup(ctx, in.OrganizationID, in.GroupID); err != nil {
			return err
		}
		if in.ParentID != nil {
			if *in.ParentID == in.GroupID {
				return ErrServiceGroupCycle
			}
			if _, err := s.repo.GetServiceGroup(ctx, in.OrganizationID, *in.ParentID); err != nil {
				return err
			}
			if err := s.checkNoCycle(ctx, in.OrganizationID, in.GroupID, *in.ParentID); err != nil {
				return err
			}
		}
		if err := s.repo.UpdateServiceGroupParent(ctx, in.OrganizationID, in.GroupID, in.ParentID); err != nil {
			return err
		}
		meta := map[string]any{}
		if in.ParentID != nil {
			meta["parent_id"] = *in.ParentID
		}
		return s.recordAudit(ctx, audit.Event{
			OrganizationID: in.OrganizationID,
			OccurredAt:     now,
			Actor:          in.ActorUserID,
			ActorType:      "user",
			Action:         "service_group.updated",
			TargetType:     "service_group",
			TargetID:       in.GroupID,
			Metadata:       mustMarshalSecurityMetadata(meta),
		})
	})
}

// checkNoCycle walks parents starting from candidateParentID
// and returns ErrServiceGroupCycle if it ever reaches
// movingGroupID. Bounded by the org's parent chain depth
// (operator-curated; in practice 3–5 levels), so the walk is
// cheap. The DB query happens once per ancestor.
const maxServiceGroupDepth = 32

func (s *Service) checkNoCycle(ctx context.Context, organizationID, movingGroupID, candidateParentID string) error {
	cur := candidateParentID
	for i := 0; i < maxServiceGroupDepth; i++ {
		if cur == movingGroupID {
			return ErrServiceGroupCycle
		}
		row, err := s.repo.GetServiceGroup(ctx, organizationID, cur)
		if err != nil {
			return err
		}
		if row.ParentID == nil {
			return nil
		}
		cur = *row.ParentID
	}
	// Depth exceeded: treat as a cycle conservatively. A real
	// deployment would never legitimately nest service groups
	// 32 deep; an organic chain that long is almost certainly
	// a misconfiguration (or a cycle we missed).
	return ErrServiceGroupCycle
}

type DisableServiceGroupInput struct {
	OrganizationID string
	GroupID        string
	Reason         string
	ActorUserID    string
}

func (s *Service) DisableServiceGroup(ctx context.Context, in DisableServiceGroupInput) error {
	if err := requireOrg(in.OrganizationID); err != nil {
		return err
	}
	if err := requireActor(in.ActorUserID); err != nil {
		return err
	}
	if in.GroupID == "" {
		return fmt.Errorf("%w: service group id required", ErrInvalidInput)
	}
	if err := validateReason("reason", in.Reason); err != nil {
		return err
	}
	now := s.clock.Now()
	return s.tx.WithTx(ctx, func(ctx context.Context) error {
		// Children-preflight: any other service_group claims
		// this one as parent?
		all, err := s.repo.ListServiceGroups(ctx, in.OrganizationID, false)
		if err != nil {
			return fmt.Errorf("identity: service_group children preflight: %w", err)
		}
		for i := range all {
			if all[i].ParentID != nil && *all[i].ParentID == in.GroupID && all[i].DisabledAt == nil {
				return ErrServiceGroupHasChildren
			}
		}
		if err := s.repo.DisableServiceGroup(ctx, in.OrganizationID, in.GroupID); err != nil {
			return err
		}
		return s.recordAudit(ctx, audit.Event{
			OrganizationID: in.OrganizationID,
			OccurredAt:     now,
			Actor:          in.ActorUserID,
			ActorType:      "user",
			Action:         "service_group.disabled",
			TargetType:     "service_group",
			TargetID:       in.GroupID,
			Metadata: mustMarshalSecurityMetadata(map[string]any{
				"reason": strings.TrimSpace(in.Reason),
			}),
		})
	})
}

// ----- Service group membership -----

type SetServiceGroupMembershipInput struct {
	OrganizationID string
	ServiceID      string
	ServiceGroupID string
	ActorUserID    string
}

func (s *Service) SetServiceGroupMembership(ctx context.Context, in SetServiceGroupMembershipInput) error {
	if err := requireOrg(in.OrganizationID); err != nil {
		return err
	}
	if err := requireActor(in.ActorUserID); err != nil {
		return err
	}
	if in.ServiceID == "" || in.ServiceGroupID == "" {
		return fmt.Errorf("%w: service_id and service_group_id required", ErrInvalidInput)
	}
	now := s.clock.Now()
	return s.tx.WithTx(ctx, func(ctx context.Context) error {
		if _, err := s.repo.GetService(ctx, in.OrganizationID, in.ServiceID); err != nil {
			if errors.Is(err, ErrServiceNotFound) {
				return ErrMembershipTargetInvalid
			}
			return err
		}
		if _, err := s.repo.GetServiceGroup(ctx, in.OrganizationID, in.ServiceGroupID); err != nil {
			if errors.Is(err, ErrServiceGroupNotFound) {
				return ErrMembershipTargetInvalid
			}
			return err
		}
		if err := s.repo.SetServiceGroupMembership(ctx, &ServiceGroupMembership{
			OrganizationID: in.OrganizationID,
			ServiceID:      in.ServiceID,
			ServiceGroupID: in.ServiceGroupID,
			AssignedAt:     now,
		}); err != nil {
			return err
		}
		return s.recordAudit(ctx, audit.Event{
			OrganizationID: in.OrganizationID,
			OccurredAt:     now,
			Actor:          in.ActorUserID,
			ActorType:      "user",
			Action:         "service_group.membership_set",
			TargetType:     "service_group_membership",
			TargetID:       in.ServiceID,
			Metadata: mustMarshalSecurityMetadata(map[string]any{
				"service_id":       in.ServiceID,
				"service_group_id": in.ServiceGroupID,
			}),
		})
	})
}

type ClearServiceGroupMembershipInput struct {
	OrganizationID string
	ServiceID      string
	ActorUserID    string
}

func (s *Service) ClearServiceGroupMembership(ctx context.Context, in ClearServiceGroupMembershipInput) error {
	if err := requireOrg(in.OrganizationID); err != nil {
		return err
	}
	if err := requireActor(in.ActorUserID); err != nil {
		return err
	}
	if in.ServiceID == "" {
		return fmt.Errorf("%w: service id required", ErrInvalidInput)
	}
	now := s.clock.Now()
	return s.tx.WithTx(ctx, func(ctx context.Context) error {
		if err := s.repo.ClearServiceGroupMembership(ctx, in.OrganizationID, in.ServiceID); err != nil {
			return err
		}
		return s.recordAudit(ctx, audit.Event{
			OrganizationID: in.OrganizationID,
			OccurredAt:     now,
			Actor:          in.ActorUserID,
			ActorType:      "user",
			Action:         "service_group.membership_deleted",
			TargetType:     "service_group_membership",
			TargetID:       in.ServiceID,
			Metadata: mustMarshalSecurityMetadata(map[string]any{
				"service_id": in.ServiceID,
			}),
		})
	})
}

// ----- Agent group CRUD -----

type CreateAgentGroupInput struct {
	OrganizationID string
	Slug           string
	DisplayName    string
	Description    string
	ActorUserID    string
}

func (s *Service) CreateAgentGroup(ctx context.Context, in CreateAgentGroupInput) (*AgentGroup, error) {
	in.Slug = strings.TrimSpace(in.Slug)
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	in.Description = strings.TrimSpace(in.Description)
	if err := requireOrg(in.OrganizationID); err != nil {
		return nil, err
	}
	if err := requireActor(in.ActorUserID); err != nil {
		return nil, err
	}
	if err := validateSlug("slug", in.Slug); err != nil {
		return nil, err
	}
	if err := validateNonEmptyBounded("display_name", in.DisplayName, maxDisplayNameLen); err != nil {
		return nil, err
	}
	if err := validateBounded("description", in.Description, maxDescriptionLen); err != nil {
		return nil, err
	}
	now := s.clock.Now()
	g := &AgentGroup{
		ID:             ids.New(),
		OrganizationID: in.OrganizationID,
		Slug:           in.Slug,
		DisplayName:    in.DisplayName,
		Description:    in.Description,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := s.tx.WithTx(ctx, func(ctx context.Context) error {
		if err := s.repo.CreateAgentGroup(ctx, g); err != nil {
			return fmt.Errorf("identity: create agent group: %w", err)
		}
		return s.recordAudit(ctx, audit.Event{
			OrganizationID: in.OrganizationID,
			OccurredAt:     now,
			Actor:          in.ActorUserID,
			ActorType:      "user",
			Action:         "agent_group.created",
			TargetType:     "agent_group",
			TargetID:       g.ID,
			Metadata: mustMarshalSecurityMetadata(map[string]any{
				"slug": g.Slug,
			}),
		})
	}); err != nil {
		return nil, err
	}
	return g, nil
}

func (s *Service) GetAgentGroup(ctx context.Context, organizationID, groupID string) (*AgentGroup, error) {
	if err := requireOrg(organizationID); err != nil {
		return nil, err
	}
	if groupID == "" {
		return nil, fmt.Errorf("%w: agent group id required", ErrInvalidInput)
	}
	return s.repo.GetAgentGroup(ctx, organizationID, groupID)
}

func (s *Service) ListAgentGroups(ctx context.Context, organizationID string, activeOnly bool) ([]AgentGroup, error) {
	if err := requireOrg(organizationID); err != nil {
		return nil, err
	}
	return s.repo.ListAgentGroups(ctx, organizationID, activeOnly)
}

type DisableAgentGroupInput struct {
	OrganizationID string
	GroupID        string
	Reason         string
	ActorUserID    string
}

func (s *Service) DisableAgentGroup(ctx context.Context, in DisableAgentGroupInput) error {
	if err := requireOrg(in.OrganizationID); err != nil {
		return err
	}
	if err := requireActor(in.ActorUserID); err != nil {
		return err
	}
	if in.GroupID == "" {
		return fmt.Errorf("%w: agent group id required", ErrInvalidInput)
	}
	if err := validateReason("reason", in.Reason); err != nil {
		return err
	}
	now := s.clock.Now()
	return s.tx.WithTx(ctx, func(ctx context.Context) error {
		if err := s.repo.DisableAgentGroup(ctx, in.OrganizationID, in.GroupID); err != nil {
			return err
		}
		return s.recordAudit(ctx, audit.Event{
			OrganizationID: in.OrganizationID,
			OccurredAt:     now,
			Actor:          in.ActorUserID,
			ActorType:      "user",
			Action:         "agent_group.disabled",
			TargetType:     "agent_group",
			TargetID:       in.GroupID,
			Metadata: mustMarshalSecurityMetadata(map[string]any{
				"reason": strings.TrimSpace(in.Reason),
			}),
		})
	})
}

// ----- Agent group membership -----

type AddAgentToGroupInput struct {
	OrganizationID string
	AgentID        string
	GroupID        string
	ActorUserID    string
}

func (s *Service) AddAgentToGroup(ctx context.Context, in AddAgentToGroupInput) error {
	if err := requireOrg(in.OrganizationID); err != nil {
		return err
	}
	if err := requireActor(in.ActorUserID); err != nil {
		return err
	}
	if in.AgentID == "" || in.GroupID == "" {
		return fmt.Errorf("%w: agent_id and agent_group_id required", ErrInvalidInput)
	}
	now := s.clock.Now()
	return s.tx.WithTx(ctx, func(ctx context.Context) error {
		// Agent presence is checked via the resolver; agent
		// group via the repo.
		ok, err := s.resolver.AgentExists(ctx, in.OrganizationID, in.AgentID)
		if err != nil {
			return err
		}
		if !ok {
			return ErrMembershipTargetInvalid
		}
		if _, err := s.repo.GetAgentGroup(ctx, in.OrganizationID, in.GroupID); err != nil {
			if errors.Is(err, ErrAgentGroupNotFound) {
				return ErrMembershipTargetInvalid
			}
			return err
		}
		if err := s.repo.AddAgentToGroup(ctx, &AgentGroupMembership{
			OrganizationID: in.OrganizationID,
			AgentID:        in.AgentID,
			AgentGroupID:   in.GroupID,
			AssignedBy:     in.ActorUserID,
			AssignedAt:     now,
		}); err != nil {
			return err
		}
		return s.recordAudit(ctx, audit.Event{
			OrganizationID: in.OrganizationID,
			OccurredAt:     now,
			Actor:          in.ActorUserID,
			ActorType:      "user",
			Action:         "agent_group.membership_created",
			TargetType:     "agent_group_membership",
			TargetID:       in.AgentID + ":" + in.GroupID,
			Metadata: mustMarshalSecurityMetadata(map[string]any{
				"agent_id":       in.AgentID,
				"agent_group_id": in.GroupID,
			}),
		})
	})
}

type RemoveAgentFromGroupInput struct {
	OrganizationID string
	AgentID        string
	GroupID        string
	ActorUserID    string
}

func (s *Service) RemoveAgentFromGroup(ctx context.Context, in RemoveAgentFromGroupInput) error {
	if err := requireOrg(in.OrganizationID); err != nil {
		return err
	}
	if err := requireActor(in.ActorUserID); err != nil {
		return err
	}
	if in.AgentID == "" || in.GroupID == "" {
		return fmt.Errorf("%w: agent_id and agent_group_id required", ErrInvalidInput)
	}
	now := s.clock.Now()
	return s.tx.WithTx(ctx, func(ctx context.Context) error {
		if err := s.repo.RemoveAgentFromGroup(ctx, in.OrganizationID, in.AgentID, in.GroupID); err != nil {
			return err
		}
		return s.recordAudit(ctx, audit.Event{
			OrganizationID: in.OrganizationID,
			OccurredAt:     now,
			Actor:          in.ActorUserID,
			ActorType:      "user",
			Action:         "agent_group.membership_deleted",
			TargetType:     "agent_group_membership",
			TargetID:       in.AgentID + ":" + in.GroupID,
			Metadata: mustMarshalSecurityMetadata(map[string]any{
				"agent_id":       in.AgentID,
				"agent_group_id": in.GroupID,
			}),
		})
	})
}

func (s *Service) ListGroupsForAgent(ctx context.Context, organizationID, agentID string) ([]AgentGroupMembership, error) {
	if err := requireOrg(organizationID); err != nil {
		return nil, err
	}
	if agentID == "" {
		return nil, fmt.Errorf("%w: agent id required", ErrInvalidInput)
	}
	return s.repo.ListGroupsForAgent(ctx, organizationID, agentID)
}

func (s *Service) ListAgentsInGroup(ctx context.Context, organizationID, groupID string) ([]AgentGroupMembership, error) {
	if err := requireOrg(organizationID); err != nil {
		return nil, err
	}
	if groupID == "" {
		return nil, fmt.Errorf("%w: agent group id required", ErrInvalidInput)
	}
	return s.repo.ListAgentsInGroup(ctx, organizationID, groupID)
}
