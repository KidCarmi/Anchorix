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
