package governance

import (
	"encoding/json"
	"time"
)

// PrecedenceTier names the ladder of ownership rule strengths the
// H-026B engine walks per certificate. The constants here MUST
// match the CHECK constraint in
// backend/migrations/0010_governance_ownership.sql exactly —
// they are the wire form of the enum on the SQL side.
//
// Order (highest precedence first):
//
//  1. Explicit         — operator override (always wins)
//  2. ServiceMember    — direct service membership (reserved; unused in H-026A1)
//  3. AgentGroup       — cert observed by an agent in a named group
//  4. SANPattern       — SAN glob/regex match
//  5. SubjectPattern   — subject CN glob match
//  6. Tag              — cert/agent carries a named tag
//  7. IssuerStore      — coarse issuer-DN / store-location rule
//  8. Fallback         — org default
type PrecedenceTier string

const (
	PrecedenceExplicit       PrecedenceTier = "explicit"
	PrecedenceServiceMember  PrecedenceTier = "service_member"
	PrecedenceAgentGroup     PrecedenceTier = "agent_group"
	PrecedenceSANPattern     PrecedenceTier = "san_pattern"
	PrecedenceSubjectPattern PrecedenceTier = "subject_pattern"
	PrecedenceTag            PrecedenceTier = "tag"
	PrecedenceIssuerStore    PrecedenceTier = "issuer_store"
	PrecedenceFallback       PrecedenceTier = "fallback"
)

// MatchKind names the shape of the ownership rule's match
// predicate. Bounded by a CHECK constraint in migration 0010.
type MatchKind string

const (
	MatchSANGlob       MatchKind = "san_glob"
	MatchSANRegex      MatchKind = "san_regex"
	MatchSubjectCNGlob MatchKind = "subject_cn_glob"
	MatchAgentGroup    MatchKind = "agent_group"
	MatchIssuerDN      MatchKind = "issuer_dn"
	MatchStoreLocation MatchKind = "store_location"
	MatchTag           MatchKind = "tag"
	MatchFallback      MatchKind = "fallback"
)

// Decision is the four-way classification the H-026B engine
// writes per certificate. Bounded by a CHECK in migration 0010.
type Decision string

const (
	DecisionMatched    Decision = "matched"
	DecisionOverridden Decision = "overridden"
	DecisionUnowned    Decision = "unowned"
	DecisionAmbiguous  Decision = "ambiguous"
)

// Confidence is the coarse label derived from the winning
// precedence tier. Bounded by a CHECK in migration 0010.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// OwnershipRule is one operator-authored pattern → service rule.
// The engine evaluates rules in deterministic (tier, priority,
// created_at, id) order; the first match wins.
type OwnershipRule struct {
	ID             string
	OrganizationID string
	Name           string
	Description    string
	ServiceID      string
	PrecedenceTier PrecedenceTier
	Priority       int
	MatchKind      MatchKind
	MatchValue     string
	Enabled        bool
	CreatedAt      time.Time
	UpdatedAt      time.Time
	CreatedBy      string
	DisabledAt     *time.Time
}

// CertificateOwnership is the engine's derived current ownership
// row for one certificate. One row per (organization_id,
// certificate_id) — denormalized for fast operator reads.
//
// ServiceID is NULL for unowned. WinningRuleID is NULL when the
// decision is overridden or unowned. OverrideID is NULL except
// when decision = overridden. ExplanationID always points at
// the latest explanation row for the cert.
type CertificateOwnership struct {
	OrganizationID  string
	CertificateID   string
	ServiceID       *string
	Decision        Decision
	WinningRuleID   *string
	OverrideID      *string
	ExplanationID   string
	Confidence      Confidence
	FirstAssignedAt time.Time
	LastEvaluatedAt time.Time
	LastChangedAt   time.Time
}

// CertificateOwnershipOverride is an operator pin that always
// wins (precedence tier "explicit"). Soft-deleted via
// (cleared_at, cleared_by, cleared_reason). At most one ACTIVE
// override per cert; the active partial unique index enforces
// this.
//
// ExpiresAt is optional; when non-NULL, the H-026B engine
// auto-clears the override at the first recompute pass after
// expiry with cleared_by = 'system', cleared_reason =
// 'auto-expired'.
type CertificateOwnershipOverride struct {
	ID             string
	OrganizationID string
	CertificateID  string
	ServiceID      string
	Reason         string
	SetBy          string
	SetAt          time.Time
	ExpiresAt      *time.Time
	ClearedAt      *time.Time
	ClearedBy      *string
	ClearedReason  *string
}

// OwnershipMatchExplanation is a snapshot of the engine's
// reasoning for one (cert, decision-change) pair. Recomputes
// that re-confirm an existing decision do not write a new
// explanation — they bump certificate_ownership.last_evaluated_at
// only, capping cardinality.
//
// LosingRules is a bounded JSONB array (K ≤ 8) of {rule_id,
// tier, priority, reason_not_chosen}. SignalsSeen captures the
// inputs the engine considered. Both are raw JSON in H-026A1
// since the engine that defines their concrete shape lives in
// H-026B.
type OwnershipMatchExplanation struct {
	ID               string
	OrganizationID   string
	CertificateID    string
	DecidedAt        time.Time
	DecidedDecision  Decision
	DecidedServiceID *string
	WinningRuleID    *string
	LosingRules      json.RawMessage
	SignalsSeen      json.RawMessage
	EngineVersion    int
}

// TagPair is one (key, value) classification tag as seen by the
// ownership signal reader. It is the storage-read projection of a
// tags row reached through a tag_assignments edge; the engine
// (H-026B) consumes it as a match signal. Distinct from the
// operator-curated identity.Tag — this carries only the two fields
// the engine matches on.
type TagPair struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// CertificateSignals is the flat, per-certificate bundle of inputs
// the H-026B ownership engine evaluates rules against. It is produced
// by OwnershipRepository.ListCertificateSignalsPaged as a single
// paged SQL join over certificates + certificate_observations +
// agent_group_memberships + tag_assignments, so the engine makes ZERO
// per-cert follow-up queries.
//
// This is a governance-owned value type on purpose: it lets the
// engine read inventory + identity signals WITHOUT importing those
// packages (H026B plan §3.1 / §2.2 boundary rule). The storage layer
// owns the SQL that assembles it.
//
// Field provenance:
//
//   - Subject / Issuer / SANs are intrinsic certificate metadata and
//     are populated regardless of observation state.
//   - StoreLocations / ObservingAgentIDs / ObservingAgentGroupIDs /
//     AgentTags are derived ONLY from ACTIVE observations
//     (certificate_observations.removed_at IS NULL): a cert no longer
//     present on a host must not be owned via that host's signals.
//   - ObservingAgentGroupIDs excludes disabled agent groups
//     (agent_groups.disabled_at IS NULL): a retired grouping is not a
//     live signal.
//   - CertTags are active (tags.disabled_at IS NULL) tag_assignments
//     with target_type = 'certificate'.
//   - AgentTags are active tag_assignments with target_type = 'agent'
//     for the cert's actively-observing agents; disabled tags are
//     excluded.
//
// Every slice is DISTINCT and deterministically ordered by the read
// path (text sets ascending; tag sets by key then value), so the
// engine's explanation snapshot is byte-stable.
//
// Subject and Issuer carry the raw DN strings; CN parsing is an
// engine concern (H-026B), not a storage one.
type CertificateSignals struct {
	CertificateID          string
	Subject                string
	Issuer                 string
	SANs                   []string
	StoreLocations         []string
	ObservingAgentIDs      []string
	ObservingAgentGroupIDs []string
	CertTags               []TagPair
	AgentTags              []TagPair
}

// ----- Policy types -----

// PolicyDefinition is a versioned bundle of policy rules. Two
// version columns:
//
//   - Version is the operator-facing per-slug counter; bumps
//     when an operator publishes new rule contents under the
//     same slug. Older (slug, version) rows stay for explanation
//     history.
//   - SchemaVersion is the engine-side JSONB-shape version;
//     bumps only when the H-026D engine learns a new rule kind
//     or changes a param shape.
type PolicyDefinition struct {
	ID             string
	OrganizationID string
	Slug           string
	DisplayName    string
	Description    string
	Rules          json.RawMessage
	SchemaVersion  int
	Version        int
	CreatedAt      time.Time
	UpdatedAt      time.Time
	CreatedBy      string
	DisabledAt     *time.Time
}

// PolicyScopeKind names the scope a policy assignment / waiver
// targets. Bounded by a CHECK in migration 0011.
type PolicyScopeKind string

const (
	PolicyScopeOrganization PolicyScopeKind = "organization"
	PolicyScopeServiceGroup PolicyScopeKind = "service_group"
	PolicyScopeService      PolicyScopeKind = "service"
	PolicyScopeCertificate  PolicyScopeKind = "certificate"
)

// PolicyAssignment binds one policy definition to one scope.
// Soft-deleted via (cleared_at, cleared_by). At most one ACTIVE
// assignment per (definition, scope); enforced by the active
// partial unique index.
type PolicyAssignment struct {
	ID                 string
	OrganizationID     string
	PolicyDefinitionID string
	ScopeKind          PolicyScopeKind
	ScopeID            string
	AssignedBy         string
	AssignedAt         time.Time
	ClearedAt          *time.Time
	ClearedBy          *string
}

// PolicyWaiver is a time-bounded exception for one
// (PolicyDefinitionID, PolicyRuleLocalID) tuple within one
// scope. ExpiresAt is NOT NULL — the DB CHECK
// `policy_waivers_expires_after_granted` also refuses
// past-or-now expiries. Active uniqueness is enforced by the
// active partial unique index.
type PolicyWaiver struct {
	ID                 string
	OrganizationID     string
	PolicyDefinitionID string
	PolicyRuleLocalID  string
	ScopeKind          PolicyScopeKind
	ScopeID            string
	Reason             string
	GrantedBy          string
	GrantedAt          time.Time
	ExpiresAt          time.Time
	ClearedAt          *time.Time
	ClearedBy          *string
}

// ----- Recompute runs -----

// RecomputeKind names the recompute family the run belongs to.
// Bounded by a CHECK in migration 0011.
type RecomputeKind string

const (
	RecomputeKindOwnership RecomputeKind = "ownership"
	RecomputeKindPolicy    RecomputeKind = "policy"
)

// RecomputeActorKind names the trigger source for a run.
// Bounded by a CHECK in migration 0011.
type RecomputeActorKind string

const (
	RecomputeActorUser    RecomputeActorKind = "user"
	RecomputeActorSystem  RecomputeActorKind = "system"
	RecomputeActorPreview RecomputeActorKind = "preview"
)

// GovernanceRecomputeRun is one row in
// governance_recompute_runs — a per-pass operational record
// complementary to audit_events. The H-026B engine writes one
// row at the start of each pass (with Succeeded == nil) and
// updates the row with the final outcome on commit.
type GovernanceRecomputeRun struct {
	ID                 string
	OrganizationID     string
	Kind               RecomputeKind
	StartedAt          time.Time
	FinishedAt         *time.Time
	Actor              string
	ActorKind          RecomputeActorKind
	Succeeded          *bool
	ErrorClass         string
	EvaluatedCount     int
	ChangedCount       int
	UnchangedCount     int
	BecameOwnedCount   int
	BecameUnownedCount int
	FlippedOwnerCount  int
	EngineVersion      int
}
