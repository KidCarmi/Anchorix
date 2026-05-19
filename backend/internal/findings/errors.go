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

// ErrUnsupportedFindingStatus is returned by Service.Recompute
// when an existing finding row carries a status the recompute
// engine doesn't know how to transition. v0.1 only writes
// `open` / `resolved`; the schema CHECK reserves
// `acknowledged` and `suppressed` for the H-023 override
// workflow.
//
// Failing loudly here is deliberate: an earlier draft used a
// `default:` arm that silently treated any non-open status as
// "resolved → reopen", which would have flipped a future
// suppressed/acknowledged finding back to `open` on every
// recompute, defeating the override workflow's purpose. When
// H-023 introduces the override surface, it MUST extend the
// switch in Service.runDiff (the comment on the default arm
// points at this sentinel as the breadcrumb).
//
// HTTP handler maps to 500 internal_error.
var ErrUnsupportedFindingStatus = errors.New("findings: unsupported finding status for recompute")
