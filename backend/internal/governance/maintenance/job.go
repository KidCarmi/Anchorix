package maintenance

import "context"

// PageLimits are the per-page bounds the runner passes into a Job. A Job
// MUST treat PageSize as an upper bound on the work it does in one
// RunPage call; the runner separately enforces the per-run page count
// and wall-clock budget around the call (see JobRunner).
type PageLimits struct {
	// PageSize is the maximum number of items the page may process. It
	// is validated/clamped by config (B4 design §6.2 / §9) before
	// reaching the Job; the Job passes it to the underlying primitive.
	PageSize int
}

// PageResult is the outcome of a single bounded page.
//
// Cursor semantics are owned by the Job: NextCursor is opaque to the
// runner, which stores and replays it verbatim. The runner advances the
// persisted cursor to NextCursor only after a page returns without
// error (cursor-on-success; B4 design §6.1).
type PageResult struct {
	// NextCursor is the resume token for the next page. It is opaque to
	// the runner. On a Done result it is still recorded, but the run is
	// complete and the next cycle restarts from the job's start sentinel
	// per the re-arm policy.
	NextCursor string
	// Done reports that this org's eligible work for the job is fully
	// drained (no more pages). Done=false means a page boundary was
	// reached with work remaining.
	Done bool
	// ItemsScanned / ItemsChanged are observational only (structured
	// logging / future metrics). They carry no control-flow meaning;
	// the runner never branches on them.
	ItemsScanned int
	ItemsChanged int
}

// Job is one bounded, paged, per-organization governance maintenance
// behavior. A real Job (PR-3+) wraps exactly one dormant primitive
// (H-029 sweep, H-027 prune) and owns no mutable state. In PR-2 only
// test fakes implement this interface — no real Job is registered.
type Job interface {
	// Name is the stable registry / config / cursor key (e.g.
	// "expired_override_sweep"). It must be domain-explicit
	// (CLAUDE.md §8.4) and stable across releases — it keys the
	// persisted scheduler-state row.
	Name() string

	// RunPage executes exactly one bounded page for a single
	// organization, starting from cursor, within the supplied limits.
	//
	// Contract:
	//   - It is per-org: it must bind organizationID on every read/write
	//     and never touch another org's data.
	//   - It is self-contained: one RunPage call is one atomic unit (a
	//     real adapter runs it inside the primitive's own
	//     WithTxLockedOwnership transaction). There is no loop-spanning
	//     transaction held by the runner.
	//   - It MUST be idempotent w.r.t. re-running the same page after a
	//     crash that occurred before the cursor was persisted.
	//   - On error it returns a non-nil error and the runner does NOT
	//     advance the cursor (the page is retried from where it was).
	RunPage(ctx context.Context, organizationID, cursor string, limits PageLimits) (PageResult, error)
}
