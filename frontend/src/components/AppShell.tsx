import { NavLink, Outlet } from "react-router-dom";

const navLinks = [
  { to: "/dashboard", label: "Dashboard" },
  { to: "/certificates", label: "Certificates" },
  { to: "/findings", label: "Findings" },
  { to: "/agents", label: "Agents" },
  { to: "/providers", label: "Providers" },
  { to: "/audit", label: "Audit" },
];

export function AppShell() {
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
        <div className="px-4 py-3 text-xs text-anchor-100/70">v0.1 — visibility before automation</div>
      </aside>
      <main className="flex-1 p-8 overflow-auto">
        <Outlet />
      </main>
    </div>
  );
}
