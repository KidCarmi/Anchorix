# Hardening Backlog

This file tracks **real** follow-up engineering items surfaced during
the post-PR-002 hardening pass (PR-005). Each entry is small enough
to land in a focused PR but was deferred from PR-005 to keep that PR
documentation-only.

**This is not a TODO list.** Per CLAUDE.md §19, TODO-driven
architecture is forbidden. Each entry below has a clear scope, a
recommended PR title, and a rationale for why it wasn't fixed in
PR-005. New items get added only when the work is real, scoped, and
justifiable.

**Source of truth for rules:** [`CLAUDE.md`](../../CLAUDE.md). If
this file and CLAUDE.md disagree, CLAUDE.md wins.

## Open Items

_No open items._

The last open item, H-004 (cross-tab session synchronization),
shipped in `src/lib/session.ts` via `publishSessionEvent` +
`useCrossTabSessionSync`. New items get added here only when a
deferred follow-up has clear scope, real risk, and a recommended
PR shape — see the rules below.

## How items get added or removed

- **Added** when a deferred follow-up has clear scope, a real risk,
  and a recommended PR shape. "We might want to look at X someday"
  is not an entry; design speculation lives in
  `docs/architecture/EVOLUTION.md`.
- **Removed** when the recommended PR has merged. Crossing the entry
  out is not enough — delete it. The merge commit + this file's git
  history are the audit trail.
- **Promoted** to a CLAUDE.md amendment if the item turns out to
  encode a binding rule. CLAUDE.md is the constitution; this file is
  the punch list.
