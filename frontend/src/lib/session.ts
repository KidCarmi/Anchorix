// Session state lives in the server. The frontend derives "is the
// operator signed in" by calling GET /api/v1/auth/me and reading
// the result.
//
// Mandatory: we never read or write the session value in JavaScript.
// The session cookie is HttpOnly + server-issued; this module only
// works in terms of the User payload the backend returns.
//
// CLAUDE.md §6 + §8.3: source of truth is the server session.

import { useEffect } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { UseQueryResult } from "@tanstack/react-query";

import { ApiError, api, registerUnauthorizedHandler, type User } from "./api";

// sessionQueryKey is a constant so tests, hooks, and the AuthGate all
// agree on which cache slot represents the current operator. A typo
// here would silently fail a cache invalidation.
export const sessionQueryKey = ["session"] as const;

// isSessionQuery returns true if a given React Query queryKey matches
// the session query exactly. Used by useLogout's cache eviction so
// the active session observer's subscription survives the cleanup —
// queryClient.clear() removes the session entry too, and removing
// the slot a mounted observer is subscribed to desynchronizes it so
// the subsequent invalidate-driven refetch never re-renders the
// gate. Excluding sessionQueryKey is what keeps logout deterministic
// in the tab that initiated it.
function isSessionQuery(queryKey: readonly unknown[]): boolean {
  if (queryKey.length !== sessionQueryKey.length) return false;
  for (let i = 0; i < queryKey.length; i += 1) {
    if (queryKey[i] !== sessionQueryKey[i]) return false;
  }
  return true;
}

// useSession queries /auth/me on mount.
//
//   - data        → authenticated User
//   - error 401   → anonymous (handled by AuthGate as "show login")
//   - error 5xx/network → render the same anonymous path; logging in
//     is the operator's safest next step.
//
// retry:false avoids the React Query default of one retry on error:
// for an authoritative 401 we don't want to wait an extra round trip
// before showing the login form.
export function useSession(): UseQueryResult<User, ApiError> {
  return useQuery<User, ApiError>({
    queryKey: sessionQueryKey,
    queryFn: () => api.me(),
    retry: false,
    // The session probe is the gate; treat it as always-fresh so
    // route transitions don't show a stale "logged in" cache after
    // the cookie was revoked server-side.
    staleTime: 0,
    gcTime: 0,
    // Re-probe /me when the user returns to the tab. If the cookie
    // expired server-side (sliding-session idle timeout, server-side
    // revocation, operator restart), the next focus surfaces it and
    // the gate flips to LoginPage. Overrides the global
    // refetchOnWindowFocus:false in main.tsx for the session query
    // only — page-level data queries keep the cheaper default.
    refetchOnWindowFocus: true,
  });
}

// SessionEvent is the union of cross-tab session-state messages.
// Intentionally tiny: only the event type travels. Posting a user
// object, an email, a role, or any cookie/session/token material
// would violate CLAUDE.md §6.9 — secrets and identifying data must
// not leak into channels the application does not own. Receivers
// only need to know "session state changed; refetch /me".
type SessionEvent = "login" | "logout";

const sessionChannelName = "anchorix-session";

// publishSessionEvent broadcasts to every other browsing context
// (tab, window, iframe) sharing this origin. It is a no-op when the
// browser lacks BroadcastChannel — the H-003 reactive 401 path
// catches the same state change on the next API call, so missing
// proactive notification is graceful degradation, not a defect.
export function publishSessionEvent(event: SessionEvent): void {
  if (typeof BroadcastChannel === "undefined") return;
  // One-shot channel per publish. Persistent channels exist for the
  // listener; the publisher does not need to hold one, and creating
  // per-call avoids keeping a writable handle around the auth code
  // path.
  const channel = new BroadcastChannel(sessionChannelName);
  try {
    channel.postMessage(event);
  } finally {
    channel.close();
  }
}

// useCrossTabSessionSync subscribes the current React tree to
// "login"/"logout" messages from other tabs and invalidates the
// session query when either arrives. AuthGate then flips on the
// next /me refetch — to LoginPage on "logout", to AppShell on
// "login".
//
// Mounted exactly once at the composition root (App). The effect
// owns the channel; the cleanup closes it so tests that mount and
// unmount do not leak BroadcastChannel instances.
//
// Composes cleanly with H-003: this hook is the proactive path
// (other tabs notify us), and the api.ts 401 dispatcher is the
// reactive path (next API call notices). Both invalidate the same
// query; invalidating twice in quick succession is a React Query
// no-op once the refetch has resolved.
export function useCrossTabSessionSync(): void {
  const queryClient = useQueryClient();
  useEffect(() => {
    if (typeof BroadcastChannel === "undefined") return;
    const channel = new BroadcastChannel(sessionChannelName);
    // addEventListener is the cross-realm-portable API. The
    // `onmessage` property has subtle differences across runtimes
    // (especially the Node worker_threads variant used in tests);
    // addEventListener behaves identically everywhere.
    const onMessage = (event: MessageEvent) => {
      const data = (event as { data?: unknown }).data;
      // Defensive narrowing: only known event types trigger a
      // refetch. A future message we don't understand is ignored,
      // not treated as a session change.
      if (data !== "login" && data !== "logout") return;
      void queryClient.invalidateQueries({ queryKey: sessionQueryKey });
    };
    channel.addEventListener("message", onMessage as EventListener);
    return () => {
      channel.removeEventListener("message", onMessage as EventListener);
      channel.close();
    };
  }, [queryClient]);
}

// useGlobalUnauthorizedHandler installs the api.ts 401 dispatcher
// onto this React tree's QueryClient. Mounted once at the
// composition root (App), it makes "any non-/me API call returning
// 401" invalidate the session query, which causes AuthGate to flip
// to LoginPage on the next /me round trip.
//
// The /auth/me exemption lives inside api.ts; the handler itself
// just needs to invalidate. Loop avoidance is by construction: a
// /me 401 cannot fire this handler, so the handler cannot recurse.
export function useGlobalUnauthorizedHandler(): void {
  const queryClient = useQueryClient();
  useEffect(() => {
    registerUnauthorizedHandler(() => {
      void queryClient.invalidateQueries({ queryKey: sessionQueryKey });
    });
    return () => {
      registerUnauthorizedHandler(null);
    };
  }, [queryClient]);
}

// useLogout is a mutation so callers get a stable, typed handle. On
// success or failure it forces /me to refetch — on success the cookie
// is gone and /me returns 401, on transport failure we surface the
// same anonymous path rather than leaving stale "logged in" cache.
// Also publishes a "logout" event so other tabs flip their gate
// (H-004) without waiting for their next API call (H-003's reactive
// path).
export function useLogout() {
  const queryClient = useQueryClient();
  return useMutation<void, ApiError>({
    mutationFn: () => api.logout(),
    onSettled: async () => {
      // Drop every cached PAGE-LEVEL query — the next operator must
      // not inherit cached data — but preserve the session query
      // itself. queryClient.clear() would remove the session entry
      // too, which desynchronizes AuthGate's mounted observer (the
      // subscription target disappears, so the subsequent
      // invalidate-driven refetch never re-renders the gate). The
      // predicate keeps the session observer wired while evicting
      // everything else.
      queryClient.removeQueries({
        predicate: (query) => !isSessionQuery(query.queryKey),
      });
      // refetchQueries gives deterministic timing: invalidateQueries
      // is fire-and-forget, while refetchQueries awaits the next /me
      // round trip. The logging-out tab's gate flips on this same
      // promise.
      await queryClient.refetchQueries({ queryKey: sessionQueryKey });
      publishSessionEvent("logout");
    },
  });
}
