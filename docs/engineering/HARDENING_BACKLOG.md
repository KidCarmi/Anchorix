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

### H-001 — Full-flow log-redaction sweep test

- **Title:** `test(integration): assert no plaintext secrets appear in logs across a full auth flow`
- **Risk:** medium. CLAUDE.md §6.9 / §9 require that no credential
  material ends up in structured logs. The redaction allow-list is
  unit-tested in `internal/logger/redact_test.go`, and PR-002 added a
  spot-check on `auth.login_failed` metadata
  (`audit_test.go` line 108). The gap is a full-flow assertion that
  walks every captured log line emitted during a login → /me → logout
  cycle and asserts that none contain the plaintext password,
  session key, or session cookie value. Today this would catch a
  regression where a new handler logs a request body or a panic stack
  prints secrets.
- **Scope:** add a Tier-2 integration test under
  `backend/test/integration/redaction_test.go` that wires the test
  server with a capturing logger sink, runs the existing
  `TestLoginMeLogoutRoundTrip` flow, and asserts no captured line
  contains the test password / session id substrings. Reuse
  `internal/logger`'s redaction helpers — do not introduce a parallel
  redaction list.
- **Recommended PR:** `test(integration): full-flow log redaction sweep (H-001)`
- **Reason not fixed now:** the metadata-level assertion already
  covers the most common regression vector (a developer adding the
  password to an audit event). The fuller sweep requires a
  capturing-logger fixture that doesn't exist yet; adding it would
  expand PR-005's scope beyond doc alignment. The current redaction
  unit tests + the metadata spot-check together protect the §6.9
  invariant; H-001 is the belt-and-braces follow-up.
- **References:** CLAUDE.md §6.9, §9; `docs/engineering/TESTING_STRATEGY.md`
  ("Audit & Logging Tests").

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
