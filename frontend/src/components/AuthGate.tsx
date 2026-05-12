import { type ReactNode } from "react";

import { useSession } from "../lib/session";
import { LoginPage } from "../pages/LoginPage";

// AuthGate is the single decision point for "show login vs. show app".
// It calls /auth/me via useSession and renders one of three things:
//
//   - the loading splash while the session probe is in flight (first
//     paint only — keeps protected content from flashing for users
//     whose cookie is invalid)
//   - LoginPage if the probe returns an error of any kind, including
//     a deterministic 401 from the backend
//   - the authenticated children otherwise
//
// CLAUDE.md §6 / §8.3: the server session is the source of truth.
// There is no localStorage / sessionStorage path here, no dev bypass,
// no fake admin mode.
export function AuthGate({ children }: { children: ReactNode }) {
  const session = useSession();

  if (session.isPending) {
    return <LoadingSplash />;
  }
  if (session.isError || !session.data) {
    return <LoginPage />;
  }
  return <>{children}</>;
}

function LoadingSplash() {
  return (
    <div
      className="flex min-h-full items-center justify-center bg-anchor-50"
      role="status"
      aria-label="Checking session"
    >
      <span className="text-sm text-anchor-700">Loading…</span>
    </div>
  );
}
