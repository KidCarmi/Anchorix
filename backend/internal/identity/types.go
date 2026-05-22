package identity

import "time"

// Tag is the canonical representation of a row in the `tags`
// table. A tag is a (key, value) pair scoped to one organization.
// The value may be the empty string, in which case the tag acts
// as a boolean flag (e.g. key="pci-in-scope", value="").
//
// Renames are intentionally restricted in H-026 — the service
// layer (H-026A2) rejects PATCH attempts that change `Key` or
// `Value` with the tag_identity_immutable error, since both are
// part of the unique identity that `TagAssignment` rows point
// at.
type Tag struct {
	ID             string
	OrganizationID string
	Key            string
	Value          string
	Description    string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	DisabledAt     *time.Time
}

// TagTargetType is the polymorphic discriminator on
// `tag_assignments.target_type`. The DB CHECK constraint bounds
// the same set of strings; the engine-facing constants below are
// the only values the service layer accepts.
type TagTargetType string

const (
	TagTargetCertificate  TagTargetType = "certificate"
	TagTargetAgent        TagTargetType = "agent"
	TagTargetService      TagTargetType = "service"
	TagTargetServiceGroup TagTargetType = "service_group"
	TagTargetAgentGroup   TagTargetType = "agent_group"
)

// TagAssignment is one attachment of a tag to one target. The
// (tag_id, target_type, target_id) tuple is unique per
// organization (enforced by the DB unique constraint).
type TagAssignment struct {
	ID             string
	OrganizationID string
	TagID          string
	TargetType     TagTargetType
	TargetID       string
	AssignedBy     string
	AssignedAt     time.Time
}

// Service is the named ownership unit. It represents the thing
// that gets paged when a cert expires. owner_email / owner_team
// are descriptive — v0.x has no notification routing yet.
type Service struct {
	ID             string
	OrganizationID string
	Slug           string
	DisplayName    string
	Description    string
	OwnerEmail     string
	OwnerTeam      string
	BusinessUnit   string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	DisabledAt     *time.Time
}

// ServiceGroup is a hierarchical container for services. ParentID
// is nullable — a NULL parent means the group is a root. Cycle
// prevention is the service-layer's responsibility (the DB
// cannot express an acyclic constraint for self-references).
type ServiceGroup struct {
	ID             string
	OrganizationID string
	Slug           string
	DisplayName    string
	ParentID       *string
	Description    string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	DisabledAt     *time.Time
}

// ServiceGroupMembership records the direct group a service
// belongs to. H-026A allows exactly ONE direct group per service
// (enforced by the table's PRIMARY KEY on (organization_id,
// service_id)). Multi-parent membership is deferred.
type ServiceGroupMembership struct {
	OrganizationID string
	ServiceID      string
	ServiceGroupID string
	AssignedAt     time.Time
}

// AgentGroup is an operational grouping of agents (e.g. "Domain
// Controllers", "PCI Web Tier"). Distinct from
// agents.group_name, which is the deployment-package hint set
// at install time; agent_groups carry operator-curated
// memberships.
type AgentGroup struct {
	ID             string
	OrganizationID string
	Slug           string
	DisplayName    string
	Description    string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	DisabledAt     *time.Time
}

// AgentGroupMembership records that one agent is a member of
// one agent group. An agent may be in many groups; the PK is
// (organization_id, agent_id, agent_group_id).
type AgentGroupMembership struct {
	OrganizationID string
	AgentID        string
	AgentGroupID   string
	AssignedBy     string
	AssignedAt     time.Time
}
