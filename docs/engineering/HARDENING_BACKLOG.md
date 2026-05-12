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

### H-003 — Global 401 handler for expired-session navigation

- **Title:** `feat(frontend): treat 401 from any API call as session-expired`
- **Risk:** medium-low (UX, not security). If the operator keeps the
  SPA open past the server-side session idle timeout (8h default) or
  the cookie is revoked server-side, the next page-level API call
  returns 401, but `AuthGate` does not know — it only re-probes `/me`
  on mount, invalidation, or window focus (which PR-009 wired). The
  user sees a broken AppShell instead of being returned to the
  sign-in screen.
- **Scope:** small but non-trivial. Add a global "on 401" hook to
  `src/lib/api.ts` (single hook registry, set once in `main.tsx`)
  that invalidates the session query when any non-`/auth/me` request
  returns 401. The `/auth/me` exemption is required to avoid an
  infinite invalidate → refetch → 401 → invalidate loop. Add an
  integration test in `src/App.test.tsx` that simulates an expired
  session: load AppShell, mock the next `/api/v1/*` call to return
  401, click into a page, assert the gate flips to LoginPage.
- **Recommended PR:** `feat(frontend): expired-session handling (H-003)`
- **Reason not fixed now:** PR-009 is a hardening review pass. The
  refetch-on-focus change in PR-009 already catches the most common
  case (operator returns to the tab after expiry). H-003 closes the
  remaining gap where the operator is actively clicking through the
  app at expiry time. The fix touches two files and needs careful
  loop-avoidance design; it deserves a focused PR rather than being
  bundled into a review.
- **References:** CLAUDE.md §6 (deterministic auth), §17 (canonical
  error envelope).

### H-004 — Cross-tab session synchronization

- **Title:** `feat(frontend): cross-tab logout/login propagation via BroadcastChannel`
- **Risk:** low. If the operator has the SPA open in multiple tabs
  and signs out in tab A, tabs B+ keep showing AppShell until their
  next `/me` refetch (mount, invalidate, or window focus — the
  PR-009 focus refetch will catch it the moment they switch tabs).
  Conversely, signing in on tab A leaves tab B on LoginPage until it
  is brought to the foreground. No new API access is granted —
  subsequent API calls fail with 401 — but another tab may continue
  showing stale cached UI until the session query is invalidated.
  The UX is jarring; the security boundary is intact.
- **Scope:** small. Add a `BroadcastChannel("anchorix-session")` (or
  `storage` event fallback) to `src/lib/session.ts`. On
  `useLogout.onSettled` post a `"logout"` message; on
  `useMutation(api.login).onSuccess` post a `"login"` message. A
  module-level listener invalidates the session query when either
  message arrives. Add a test using two `<QueryClientProvider>`
  instances sharing the channel.
- **Recommended PR:** `feat(frontend): cross-tab session sync (H-004)`
- **Reason not fixed now:** depends on H-003's "on 401 invalidate
  session" mechanism for clean composition (otherwise a tab in the
  middle of a long-running query might race with the channel
  message). Better to land H-003 first, then layer H-004 on top.
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
