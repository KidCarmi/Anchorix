package ownership

import "errors"

// Sentinel errors for the ownership engine. The recompute path
// returns these (wrapped) so a caller can errors.Is them; the
// structural-drift ones are deliberately fatal to a pass
// (fail-closed) rather than silently degraded.

// ErrUnknownPrecedenceTier is returned by rule compilation when a
// rule carries a precedence_tier outside the §4.2 ladder. The
// migration 0010 CHECK constraint makes this unreachable in a healthy
// database; if it ever drifts, the engine aborts the recompute loudly
// rather than evaluating an unrecognized tier in an undefined
// position. CLAUDE.md §6.12 fail-closed.
var ErrUnknownPrecedenceTier = errors.New("ownership: unknown precedence tier")

// ErrUnknownMatchKind is returned by rule compilation when a rule
// carries a match_kind the engine does not implement. Same
// fail-closed posture as ErrUnknownPrecedenceTier: a structurally
// corrupt rule aborts the pass instead of being silently skipped.
var ErrUnknownMatchKind = errors.New("ownership: unknown match kind")

// ErrIncompleteService is returned by NewService when a required
// dependency is missing.
var ErrIncompleteService = errors.New("ownership: incomplete service dependencies")

// ErrRecomputeInProgress is returned by RecomputeNoWait when the
// per-org advisory lock is already held by another recompute. The
// H-026B3A handler maps this to `409 ownership_recompute_in_progress`
// when the operator passed `?nowait=true`.
var ErrRecomputeInProgress = errors.New("ownership: recompute already in progress")

// --- H-026B3B rule-mutation sentinels ---------------------------------

// ErrInvalidRule is returned by the rule-mutation validators for any
// malformed input the operator can fix: empty/oversized name, unknown
// tier or match_kind, tier/kind mismatch, invalid or oversized regex,
// empty match_value where one is required, out-of-range priority. The
// handler maps it to 400 bad_request. Wrap with %w so callers can
// errors.Is it while still surfacing the specific reason in the
// message.
var ErrInvalidRule = errors.New("ownership: invalid rule")

// ErrServiceMemberReserved is returned when a mutation tries to create
// or imply the reserved `service_member` precedence tier. The tier is
// reserved in H-026B (governance plan §5.4 / OQ-1); the engine already
// treats it as inert, and rule creation rejects it loudly at the API.
// Distinct from ErrInvalidRule so the handler can return a specific
// `ownership_rule_tier_reserved` code.
var ErrServiceMemberReserved = errors.New("ownership: service_member tier is reserved")

// ErrRuleServiceNotFound is returned when the rule's target service
// does not exist (or is disabled) in the organization. Handler → 400
// ownership_rule_service_not_found (the service is operator-supplied
// input, not a path resource, so 400 not 404).
var ErrRuleServiceNotFound = errors.New("ownership: rule target service not found")

// ErrRuleTargetNotFound is returned when a rule whose match_value
// references another governance object (currently only agent_group
// rules, whose value is an agent_group id) names a target that does
// not exist or is disabled. Handler → 400 ownership_rule_target_not_found.
var ErrRuleTargetNotFound = errors.New("ownership: rule match target not found")
