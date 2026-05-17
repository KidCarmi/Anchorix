package findings

import "errors"

// ErrFindingNotFound is returned by Repository.GetFinding /
// Service.GetFinding when no finding row matches the
// (organization_id, finding_id) pair. Cross-org id lookups also
// surface as this sentinel — the WHERE clause filters on
// organization_id, so a cross-org id is indistinguishable from a
// truly-missing one (CLAUDE.md §6 deterministic auth, no
// enumeration via error code). HTTP handler maps to 404 not_found.
var ErrFindingNotFound = errors.New("findings: finding not found")

// ErrInvalidListInput is returned by Service.ListFindings when the
// caller-supplied filter is structurally invalid (empty
// organization id, limit out of bounds, malformed cursor,
// unrecognized status/severity value). HTTP handler maps to 400
// bad_request.
var ErrInvalidListInput = errors.New("findings: invalid list input")

// ErrInvalidRecomputeInput is returned by Service.Recompute when
// the input is structurally invalid (empty organization id).
// HTTP handler maps to 400 bad_request.
var ErrInvalidRecomputeInput = errors.New("findings: invalid recompute input")

// ErrInternalAudit is returned by Service.Recompute when the
// audit recording inside the recompute transaction fails. The
// transaction rolls back; no finding state changes persist. HTTP
// handler maps to 500 internal_error. Matches the
// inventory.ErrInternalAudit pattern for consistency.
var ErrInternalAudit = errors.New("findings: audit write failed")
