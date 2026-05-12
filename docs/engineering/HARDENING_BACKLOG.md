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

### H-004 — Cross-tab session synchronization

- **Title:** `feat(frontend): cross-tab logout/login propagation via BroadcastChannel`
- **Risk:** low. If the operator has the SPA open in multiple tabs
  and signs out in tab A, tabs B+ keep showing AppShell until their
  next `/me` refetch (mount, invalidation by the H-003 401 handler,
  or window focus — the PR-009 focus refetch will catch it the
  moment they switch tabs). Conversely, signing in on tab A leaves
  tab B on LoginPage until it is brought to the foreground. No new
  API access is granted — subsequent API calls fail with 401 — but
  another tab may continue showing stale cached UI until the session
  query is invalidated. The UX is jarring; the security boundary is
  intact.
- **Scope:** small. Add a `BroadcastChannel("anchorix-session")` (or
  `storage` event fallback) to `src/lib/session.ts`. On
  `useLogout.onSettled` post a `"logout"` message; on
  `useMutation(api.login).onSuccess` post a `"login"` message. A
  module-level listener invalidates the session query when either
  message arrives. Add a test using two `<QueryClientProvider>`
  instances sharing the channel.
- **Recommended PR:** `feat(frontend): cross-tab session sync (H-004)`
- **Reason not fixed now:** the immediate UX gap was closed by
  H-003 (any 401 from a navigation request invalidates the session
  query). H-004 layers on top of that — when tab B issues any API
  call after tab A's logout, the 401 invalidates its session. H-004
  proactively notifies tab B without waiting for the next API call;
  ergonomic, but not on the critical path now that H-003 has
  shipped.
- **References:** CLAUDE.md §6, §8.3 (typed API client owns the
  boundary).

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
