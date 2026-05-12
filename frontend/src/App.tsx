import { Navigate, Route, Routes } from "react-router-dom";

import { AppShell } from "./components/AppShell";
import { AuthGate } from "./components/AuthGate";
import { useCrossTabSessionSync, useGlobalUnauthorizedHandler } from "./lib/session";
import { AgentsPage } from "./pages/AgentsPage";
import { AuditPage } from "./pages/AuditPage";
import { CertificatesPage } from "./pages/CertificatesPage";
import { DashboardPage } from "./pages/DashboardPage";
import { FindingsPage } from "./pages/FindingsPage";
import { ProvidersPage } from "./pages/ProvidersPage";

// App routing: anonymous users see LoginPage (rendered directly by
// AuthGate, no route entry needed); authenticated users see the
// AppShell + nested pages. There is no /login route — the gate
// chooses which tree to mount based on the server session, so a
// signed-in operator can't accidentally land on a duplicate login
// form, and a signed-out operator can't accidentally see protected
// content even if they paste a deep link.
//
// App also wires the api.ts global 401 dispatcher to this tree's
// QueryClient (H-003). Component code never implements its own 401
// handling — when any non-/me request returns 401, the session
// query is invalidated and AuthGate flips automatically.
//
// App also subscribes the tree to cross-tab session events (H-004):
// when another tab logs in or out, this tab invalidates its session
// query and flips on the next /me round trip without waiting for
// its next page-level API call.
export function App() {
  useGlobalUnauthorizedHandler();
  useCrossTabSessionSync();
  return (
    <AuthGate>
      <Routes>
        <Route element={<AppShell />}>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/agents" element={<AgentsPage />} />
          <Route path="/certificates" element={<CertificatesPage />} />
          <Route path="/findings" element={<FindingsPage />} />
          <Route path="/providers" element={<ProvidersPage />} />
          <Route path="/audit" element={<AuditPage />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AuthGate>
  );
}
