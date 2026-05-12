import { NavLink, Outlet } from "react-router-dom";

import { useLogout, useSession } from "../lib/session";

const navLinks = [
  { to: "/dashboard", label: "Dashboard" },
  { to: "/certificates", label: "Certificates" },
  { to: "/findings", label: "Findings" },
  { to: "/agents", label: "Agents" },
  { to: "/providers", label: "Providers" },
  { to: "/audit", label: "Audit" },
];

export function AppShell() {
  const session = useSession();
  const logout = useLogout();

  // When AppShell is rendered, AuthGate has confirmed session.data
  // is present. The fallback is defensive — a refetch can briefly
  // return undefined while the cookie was invalidated server-side.
  const displayName = session.data?.display_name ?? session.data?.email ?? "";
  const role = session.data?.role ?? "";

  return (
    <div className="flex min-h-full bg-anchor-50">
      <aside className="w-60 bg-anchor-900 text-anchor-50 flex flex-col">
        <div className="px-4 py-5 text-lg font-semibold tracking-wide">Anchorix</div>
        <nav className="flex-1 px-2 space-y-1">
          {navLinks.map((link) => (
            <NavLink
              key={link.to}
              to={link.to}
              className={({ isActive }) =>
                `block rounded px-3 py-2 text-sm ${
                  isActive ? "bg-anchor-700 text-white" : "text-anchor-100 hover:bg-anchor-700/60"
                }`
              }
            >
              {link.label}
            </NavLink>
          ))}
        </nav>
        <div className="border-t border-anchor-700/60 px-4 py-3 text-xs text-anchor-100/80">
          {displayName && (
            <div className="mb-2">
              <div className="font-medium text-anchor-50">{displayName}</div>
              {role && <div className="text-anchor-100/60">{role}</div>}
            </div>
          )}
          <button
            type="button"
            onClick={() => logout.mutate()}
            disabled={logout.isPending}
            className="w-full rounded border border-anchor-700/80 px-2 py-1 text-anchor-50 hover:bg-anchor-700/60 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {logout.isPending ? "Signing out…" : "Sign out"}
          </button>
        </div>
      </aside>
      <main className="flex-1 p-8 overflow-auto">
        <Outlet />
      </main>
    </div>
  );
}
