# Anchorix Auth Foundation

Checkpoint reference for the operator authentication, session, and
frontend behavior that landed in PRs #4 → #11. This is the
end-of-Phase-1 contract: agent enrollment (Phase 2) will build on
top of it without changing it.

**Source of truth for rules:** [`CLAUDE.md`](../../CLAUDE.md). If
this file and CLAUDE.md disagree, CLAUDE.md wins.

## Auth flow

```
Operator                Frontend (SPA)              Backend (control plane)
   │                         │                              │
   │  visits /               │                              │
   │ ──────────────────────► │  GET /api/v1/auth/me ─────► │
   │                         │ ◄──────── 401/unauthorized ──│   (no cookie or expired)
   │                         │                              │
   │ ◄─ LoginPage rendered ──│                              │
   │  submits creds          │                              │
   │ ──────────────────────► │  POST /api/v1/auth/login ───►│
   │                         │ ◄── 200 + Set-Cookie ────────│   (HttpOnly session cookie)
   │                         │                              │
   │                         │  GET /api/v1/auth/me ───────►│
   │                         │ ◄── 200 + User profile ──────│
   │                         │                              │
   │ ◄─ AppShell rendered ───│                              │
   │  navigates / uses app   │                              │
   │ ──────────────────────► │  (each request carries the   │
   │                         │   HttpOnly cookie via the     │
   │                         │   `credentials: "include"`    │
   │                         │   default in api.ts)          │
   │                         │                              │
   │  clicks Sign out        │                              │
   │ ──────────────────────► │  POST /auth/logout ─────────►│
   │                         │ ◄── 204 ─────────────────────│
   │                         │  (broadcasts "logout" to     │
   │                         │   other tabs; evicts         │
   │                         │   page-level cache;          │
   │                         │   refetches /me)             │
   │                         │  GET /me ───────────────────►│
   │                         │ ◄── 401 ─────────────────────│
   │ ◄─ LoginPage rendered ──│                              │
```

Endpoints, request/response shapes, error codes, and cookie
attributes are specified in [`docs/api/REST_API.md`](../api/REST_API.md).

## Session model

- **Storage.** Sessions live in the `sessions` table in
  PostgreSQL, owned by the storage layer
  (`backend/internal/storage/postgres/sessions_repository.go`).
  The session row is the source of truth; the cookie value is an
  opaque, signed reference to the row's id.
- **Cookie.** `anchorix_session` (overridable via
  `ANCHORIX_SESSION_COOKIE_NAME`). Attributes:
  - `HttpOnly` — JavaScript cannot read it.
  - `SameSite=Lax` — cross-origin POSTs do not carry the cookie.
  - `Secure` — emitted whenever
    `ANCHORIX_TLS_TERMINATION` is anything other than `disabled_dev`
    (so production, staging, and reverse-proxy postures all get
    Secure cookies — see CLAUDE.md §6.4).
- **Signing.** The cookie value is HMAC-SHA256 signed with
  `ANCHORIX_SESSION_KEY` (32-byte minimum, validated at startup),
  base64-url-encoded with strict alphabet — see
  `backend/internal/auth/cookies.go`.
- **Sliding expiry.** Each authenticated request extends the
  session's `expires_at` to
  `min(now + idle, created_at + absolute)`. Defaults: 8h idle, 24h
  absolute, both configurable via
  `ANCHORIX_SESSION_IDLE_LIFETIME` and
  `ANCHORIX_SESSION_ABSOLUTE_LIFETIME`.
- **Revocation.** `POST /auth/logout` revokes the row server-side
  (`revoked_at` timestamp) before clearing the cookie. Any later
  request carrying the same cookie value reads the revoked row and
  is treated as 401.
- **Atomicity.** Login, logout, and `admin create` wrap all
  state-changing repository calls plus their audit event in a single
  `auth.Service` transaction via the storage-layer `Transactor`.
  An audit-write failure rolls back the session/user insert, so the
  control plane can never reach a state where a session exists
  without a matching audit row (CLAUDE.md §9, §18). Proved by
  `backend/test/integration/atomicity_test.go`.

## Frontend `/me` bootstrap

- `useSession()` in `frontend/src/lib/session.ts` is a React Query
  observer keyed by `sessionQueryKey = ["session"]`. The observer
  is mounted at the composition root (`AuthGate`) and is the single
  source of truth for "is this operator signed in?".
- `AuthGate` (`frontend/src/components/AuthGate.tsx`) renders one
  of three things based on `useSession()` state:
  - `LoadingSplash` while the probe is in flight (first paint only;
    keeps protected content from flashing for users with an
    invalid cookie).
  - `LoginPage` on error of any kind, including a deterministic 401.
  - The authenticated children (`AppShell` + routes) otherwise.
- `useSession` overrides the global React Query
  `refetchOnWindowFocus: false` default just for itself — returning
  to the tab after the 8h idle timeout surfaces the 401 immediately
  without waiting for the next API call.
- The session-cookie value never appears in JavaScript. The browser
  attaches it automatically because `api.ts` uses
  `credentials: "include"` on every request.

## Logout behavior

`useLogout()` in `frontend/src/lib/session.ts` runs the following
in `onSettled` (so the cleanup happens whether `/logout` returned
204 or errored):

1. **Cache cleanup with a session-key-skipping predicate.**
   `queryClient.removeQueries({ predicate: q => !isSessionQuery(q.queryKey) })`
   evicts every page-level query (no stale data for the next
   operator) while preserving the session entry — `clear()` would
   remove the session slot too, desynchronizing `AuthGate`'s
   mounted observer so the subsequent refetch never re-renders the
   gate.
2. **Deterministic refetch.**
   `await queryClient.refetchQueries({ queryKey: sessionQueryKey })`
   awaits the next `/me` round trip. By the time the mutation
   promise settles, the gate has already received and rendered the
   new state — no second refresh trigger needed in the logging-out
   tab.
3. **Cross-tab broadcast.** `publishSessionEvent("logout")` posts
   on `BroadcastChannel("anchorix-session")` so other tabs flip on
   the next event-loop tick.

Logout determinism is covered by three integration tests:
- 204 success → same tab flips to LoginPage.
- 500 failure → same tab still flips (next `/me` is authoritative).
- Page-level cached query (`["agents","list"]`) is evicted, AND
  the session observer keeps working.

## Global 401 behavior (H-003)

`src/lib/api.ts` exposes
`registerUnauthorizedHandler(cb: (path: string) => void)`. The
session layer's `useGlobalUnauthorizedHandler()` registers a single
callback at App-mount time that invalidates `sessionQueryKey` when
fired. `request()` calls the registered callback whenever a fetch
response is 401 and the request path is **not** in the
`unauthorizedExemptPaths` set.

Exempt paths:

- `/auth/me` — the gate's own probe. A 401 from `/me` is the gate's
  trigger; invalidating in response would loop indefinitely.
- `/auth/login` — `invalid_credentials` is the deterministic
  failure mode of the login form, not an expired session. The
  LoginPage handles its own error UX; firing the global handler
  would force an extra `/me` refetch with the wrong UX framing.

All other paths fire the handler. The session refetch produces the
right outcome: if the cookie is still valid, `/me` returns 200 and
the gate stays on AppShell; if it is gone, `/me` returns 401 and
the gate flips to LoginPage. By construction the recovery path
cannot loop, because the `/me` refetch itself is exempt.

## Cross-tab behavior (H-004)

Same channel name, same vocabulary, in both directions:

| Trigger              | Action                                   |
| -------------------- | ---------------------------------------- |
| Login success        | `publishSessionEvent("login")`           |
| Logout settled       | `publishSessionEvent("logout")`          |
| `"login"` received   | other tab invalidates `sessionQueryKey`  |
| `"logout"` received  | other tab invalidates `sessionQueryKey`  |

The listener channel is held by `useEffect` (one per React tree),
closed on cleanup. The publisher opens a one-shot channel, posts,
then closes; browsers (and Node's polyfill, used only in tests)
still deliver the message to all other channels with the same name
before honoring the close.

The cross-tab notification composes with H-003: when tab A signs
out, tab B receives the broadcast immediately. Even if the
broadcast were lost (e.g. a browser that disabled
BroadcastChannel), tab B's next API call would return 401 and the
H-003 reactive path would flip the gate within one round trip.

## Security properties

These are **invariants** of the auth foundation. Anything that
would violate them is a security defect and must be reverted or
fixed before merge.

- **HttpOnly cookie.** The session value is never accessible to
  JavaScript.
- **No token storage in JavaScript.** There are zero
  `localStorage` / `sessionStorage` / `document.cookie` reads or
  writes in `frontend/src/`. Verified by grep on every PR.
- **Safe login errors.** `LoginPage` collapses all 401 / 400
  responses to one deterministic message ("Invalid email or
  password.") and everything else to a generic message ("Could not
  sign in."). Backend error-message text never reaches the
  operator. Asserted by unit and integration tests.
- **No backend error-message leak.** `err.message` /
  `error.message` is never rendered in any component
  (grep-verified, see `frontend/src/`).
- **No user/session/token broadcast over BroadcastChannel.** The
  cross-tab payload is the bare string `"login"` or `"logout"`.
  Asserted by a dedicated test that scans every captured
  `postMessage` payload for `User` fields and forbidden substrings
  (`password`, `session`, `cookie`, `token`, `secret`,
  `authorization`).
- **Cache cleanup on logout.** Every authenticated page-level
  query is evicted before the next operator can land on the
  Login screen.
- **`/auth/me` loop avoidance.** The exempt-paths set inside
  `api.ts` makes the recovery path provably loop-free, not by
  convention.
- **Audit trail.** Every state-changing auth operation
  (`admin_created`, `login_succeeded`, `login_failed`, `logout`)
  writes an `audit_events` row in the same transaction as the
  state change. Failed login attempts carry
  `severity: "security"` metadata. Append-only at the DB level via
  trigger; even an SQL-injected `DELETE` would be rejected.
- **No plaintext secrets in logs.** Enforced at three layers:
  (a) the `internal/logger` redaction allow-list,
  (b) `auth.login_failed` metadata never carries the submitted
  password, and
  (c) a full-flow integration sweep
  (`backend/test/integration/redaction_test.go`) inspects the raw
  log stream during a complete login → `/me` → logout cycle and
  asserts no password, no session cookie value, no raw session id,
  no session-key material, no bcrypt hash, and no sentinel
  Authorization bearer token appears anywhere.

## Known non-goals (Phase 1 boundary)

Anything in this list is **deliberately not implemented** at the
Phase-1 boundary. Each is reserved for a later phase or is out of
scope for v0.1; building any of them on top of the current
foundation requires either a roadmap revision or a CLAUDE.md
amendment.

- **RBAC UI.** Roles exist (`admin`, `operator`); the UI does not
  yet branch on role. The `User.role` field is plumbed end-to-end
  for the future.
- **SSO (SAML / OIDC).** Local password authentication only.
  Explicitly out of v0.1 (CLAUDE.md §4).
- **Password reset.** No `anchorix admin reset-password` exists.
  Bootstrap-only password creation today; operators rotate by
  re-running `admin create` for a new identity.
- **MFA / TOTP / WebAuthn.** Out of v0.1.
- **Agent enrollment.** Phase 2. The agent code paths and
  enrollment-token APIs are stubs; nothing in the current
  foundation depends on or enables an agent identity yet.
- **Inventory ingestion.** Phase 3. No certificate observations
  are accepted yet.
- **Findings.** Phase 4. No risk-rule evaluation runs yet.
- **CSRF middleware.** The session cookie's `HttpOnly` +
  `SameSite=Lax` combination is the current CSRF mitigation.
  Explicit CSRF tokens are sensible defense-in-depth and will
  arrive alongside the first non-`/auth/login` form-driven
  mutation.

## References

- [`docs/api/REST_API.md`](../api/REST_API.md) — endpoint
  contracts.
- [`docs/BOOTSTRAP.md`](../BOOTSTRAP.md) — first-operator flow.
- [`docs/engineering/TESTING_STRATEGY.md`](./TESTING_STRATEGY.md)
  — unit / integration / smoke tier model.
- [`docs/engineering/HARDENING_BACKLOG.md`](./HARDENING_BACKLOG.md)
  — currently "No open items"; H-001 through H-004 have all
  shipped.
- [`backend/internal/auth/`](../../backend/internal/auth/),
  [`backend/internal/httpapi/middleware/auth.go`](../../backend/internal/httpapi/middleware/auth.go),
  [`frontend/src/lib/session.ts`](../../frontend/src/lib/session.ts),
  [`frontend/src/components/AuthGate.tsx`](../../frontend/src/components/AuthGate.tsx)
  — the code this document describes.
