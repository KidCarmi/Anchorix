package governance

import "errors"

// Sentinel errors for the governance storage layer. Callers
// (the future H-026B engine and H-026C operator handlers) use
// errors.Is to map them to the canonical envelope.

// ErrOwnershipRuleNotFound is returned by lookups when no
// ownership_rules row matches (organization_id, id). Cross-org
// id lookups collapse to this sentinel.
var ErrOwnershipRuleNotFound = errors.New("governance: ownership rule not found")

// ErrCertificateOwnershipNotFound surfaces a missing
// certificate_ownership row. Engine paths call this distinct
// from "cert has decision=unowned" — the latter is a row that
// exists with NULL service_id.
var ErrCertificateOwnershipNotFound = errors.New("governance: certificate ownership not found")

// ErrOwnershipOverrideNotFound surfaces a missing
// certificate_ownership_overrides row. The "no active override
// for this cert" case is a successful read of zero rows from
// GetActiveOverride and is NOT this sentinel — this sentinel is
// for the by-id lookup.
var ErrOwnershipOverrideNotFound = errors.New("governance: ownership override not found")

// ErrOwnershipExplanationNotFound surfaces a missing
// ownership_match_explanations row.
var ErrOwnershipExplanationNotFound = errors.New("governance: ownership explanation not found")

// ErrPolicyDefinitionNotFound surfaces a missing policy
// definition row.
var ErrPolicyDefinitionNotFound = errors.New("governance: policy definition not found")

// ErrPolicyAssignmentNotFound surfaces a missing policy
// assignment row.
var ErrPolicyAssignmentNotFound = errors.New("governance: policy assignment not found")

// ErrPolicyWaiverNotFound surfaces a missing policy waiver row.
var ErrPolicyWaiverNotFound = errors.New("governance: policy waiver not found")

// ErrGovernanceRecomputeRunNotFound surfaces a missing
// governance_recompute_runs row.
var ErrGovernanceRecomputeRunNotFound = errors.New("governance: recompute run not found")
