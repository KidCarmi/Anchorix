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
export function useLogout() {
  const queryClient = useQueryClient();
  return useMutation<void, ApiError>({
    mutationFn: () => api.logout(),
    onSettled: async () => {
      // Drop every cached query: any page-level data fetched while
      // authenticated is no longer the next operator's to see.
      queryClient.clear();
      await queryClient.invalidateQueries({ queryKey: sessionQueryKey });
    },
  });
}
