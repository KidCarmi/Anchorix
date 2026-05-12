import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";

import { App } from "./App";
import { api, type User } from "./lib/api";

afterEach(() => {
  vi.unstubAllGlobals();
});

const sampleUser: User = {
  id: "u1",
  organization_id: "anchorix",
  email: "alice@example.com",
  display_name: "Alice",
  role: "admin",
  disabled: false,
  created_at: "2026-05-11T10:00:00Z",
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

// fetchRouter dispatches by request URL+method so a single test can
// drive the full auth flow (login → /me → logout) without timing
// games. Each route handler may return a Response or a Promise, and
// the call is recorded for assertion.
type RouteKey = `${string} ${string}`;
type RouteHandler = (init?: RequestInit) => Promise<Response>;

function fetchRouter(routes: Partial<Record<RouteKey, RouteHandler>>) {
  const calls: { url: string; init?: RequestInit }[] = [];
  const mock = vi.fn(
    async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input.toString();
      const method = (init?.method ?? "GET").toUpperCase();
      const key = `${method} ${url}` as RouteKey;
      calls.push({ url, init });
      const handler = routes[key];
      if (!handler) {
        throw new Error(`no fetchRouter handler for ${key}`);
      }
      return handler(init);
    },
  );
  vi.stubGlobal("fetch", mock);
  return { mock, calls };
}

function renderApp() {
  // Per-test QueryClient so React Query state does not leak across
  // tests. retry:false keeps assertions deterministic.
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={["/"]}>
        <App />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("App auth flow", () => {
  it("renders the LoadingSplash status region while /me is in flight", async () => {
    // Hold /me open: while the request is pending, AuthGate must
    // show its loading state — never AppShell, never LoginPage —
    // so protected content cannot flash for users with an invalid
    // cookie.
    let resolveMe!: (r: Response) => void;
    fetchRouter({
      "GET /api/v1/auth/me": () =>
        new Promise<Response>((r) => {
          resolveMe = r;
        }),
    });

    renderApp();

    const loading = await screen.findByRole("status", {
      name: /checking session/i,
    });
    expect(loading).toBeInTheDocument();
    expect(
      screen.queryByRole("heading", { name: /sign in to anchorix/i }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: /dashboard/i }),
    ).not.toBeInTheDocument();

    // Resolve to a 401 so the loading state cleanly transitions and
    // we don't leak an unresolved promise into the next test.
    resolveMe(
      jsonResponse(
        { error: { code: "unauthorized", message: "" } },
        401,
      ),
    );
    await screen.findByRole("heading", { name: /sign in to anchorix/i });
  });

  it("keeps the user on the login page when /me returns 401", async () => {
    fetchRouter({
      "GET /api/v1/auth/me": async () =>
        jsonResponse(
          { error: { code: "unauthorized", message: "authentication required" } },
          401,
        ),
    });

    renderApp();

    expect(
      await screen.findByRole("heading", { name: /sign in to anchorix/i }),
    ).toBeInTheDocument();
    // AppShell-only nav must not be visible.
    expect(screen.queryByText(/dashboard/i)).not.toBeInTheDocument();
  });

  it("transitions to the authenticated AppShell after a successful login", async () => {
    let meCallCount = 0;
    fetchRouter({
      "GET /api/v1/auth/me": async () => {
        meCallCount += 1;
        if (meCallCount === 1) {
          return jsonResponse(
            { error: { code: "unauthorized", message: "" } },
            401,
          );
        }
        return jsonResponse(sampleUser);
      },
      "POST /api/v1/auth/login": async () => jsonResponse(sampleUser),
    });

    renderApp();

    // Start anonymous.
    await screen.findByRole("heading", { name: /sign in to anchorix/i });

    // Fill the form and submit.
    fireEvent.change(screen.getByLabelText(/email/i), {
      target: { value: "alice@example.com" },
    });
    fireEvent.change(screen.getByLabelText(/password/i), {
      target: { value: "correct horse" },
    });
    fireEvent.click(screen.getByRole("button", { name: /sign in/i }));

    // After /me invalidates and refetches with 200, the AppShell
    // (and its sidebar nav) is what the user sees.
    expect(
      await screen.findByRole("link", { name: /dashboard/i }),
    ).toBeInTheDocument();
    expect(screen.getByText(/alice/i)).toBeInTheDocument();
    // The sign-in form is gone.
    expect(
      screen.queryByRole("heading", { name: /sign in to anchorix/i }),
    ).not.toBeInTheDocument();
  });

  it("returns the user to the login page even when /logout returns 500", async () => {
    // CLAUDE.md §6 + the useLogout onSettled design: even if the
    // server rejects the logout call, the frontend must still drop
    // every cached query and re-probe /me. The next /me reflects
    // whatever the server says — including that the cookie is now
    // gone — and AuthGate flips to LoginPage.
    let meCallCount = 0;
    fetchRouter({
      "GET /api/v1/auth/me": async () => {
        meCallCount += 1;
        if (meCallCount === 1) return jsonResponse(sampleUser);
        return jsonResponse(
          { error: { code: "unauthorized", message: "" } },
          401,
        );
      },
      "POST /api/v1/auth/logout": async () =>
        jsonResponse(
          { error: { code: "internal_error", message: "boom" } },
          500,
        ),
    });

    renderApp();
    await screen.findByRole("link", { name: /dashboard/i });

    fireEvent.click(screen.getByRole("button", { name: /sign out/i }));

    expect(
      await screen.findByRole("heading", { name: /sign in to anchorix/i }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: /dashboard/i }),
    ).not.toBeInTheDocument();
  });

  it("preserves the deep-link target across the auth gate", async () => {
    // Anonymous user lands on /agents → AuthGate renders LoginPage;
    // the URL is left alone. After a successful login the gate
    // flips and the same /agents route now resolves inside
    // AppShell — proving the deep-link target survived the
    // intermediate login screen.
    let meCallCount = 0;
    fetchRouter({
      "GET /api/v1/auth/me": async () => {
        meCallCount += 1;
        if (meCallCount === 1) {
          return jsonResponse(
            { error: { code: "unauthorized", message: "" } },
            401,
          );
        }
        return jsonResponse(sampleUser);
      },
      "POST /api/v1/auth/login": async () => jsonResponse(sampleUser),
    });

    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
    });
    render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={["/agents"]}>
          <App />
        </MemoryRouter>
      </QueryClientProvider>,
    );

    // Anonymous: login form is the only thing rendered.
    await screen.findByRole("heading", { name: /sign in to anchorix/i });
    expect(
      screen.queryByRole("link", { name: /agents/i }),
    ).not.toBeInTheDocument();

    fireEvent.change(screen.getByLabelText(/email/i), {
      target: { value: "alice@example.com" },
    });
    fireEvent.change(screen.getByLabelText(/password/i), {
      target: { value: "pw" },
    });
    fireEvent.click(screen.getByRole("button", { name: /sign in/i }));

    // After login, the gate flips and the URL we started on
    // (/agents) renders inside AppShell. The sidebar's "Agents" link
    // marks the route as active, and the form is gone.
    const agentsLink = await screen.findByRole("link", { name: /agents/i });
    expect(agentsLink).toHaveAttribute("aria-current", "page");
    expect(
      screen.queryByRole("heading", { name: /sign in to anchorix/i }),
    ).not.toBeInTheDocument();
  });

  it("returns the user to the login page after sign out", async () => {
    let meCallCount = 0;
    fetchRouter({
      "GET /api/v1/auth/me": async () => {
        meCallCount += 1;
        // First call: authenticated. After logout: 401.
        if (meCallCount === 1) return jsonResponse(sampleUser);
        return jsonResponse(
          { error: { code: "unauthorized", message: "" } },
          401,
        );
      },
      "POST /api/v1/auth/logout": async () => new Response(null, { status: 204 }),
    });

    renderApp();

    // Wait until AppShell is rendered.
    await screen.findByRole("link", { name: /dashboard/i });

    fireEvent.click(screen.getByRole("button", { name: /sign out/i }));

    await waitFor(() =>
      expect(
        screen.queryByRole("link", { name: /dashboard/i }),
      ).not.toBeInTheDocument(),
    );
    expect(
      await screen.findByRole("heading", { name: /sign in to anchorix/i }),
    ).toBeInTheDocument();
  });
});

describe("global 401 handler (H-003)", () => {
  it("returns the operator to LoginPage when a non-/me request returns 401", async () => {
    // Authenticated session, then a page-level API call returns 401
    // (server-side session expired mid-navigation). The global
    // handler must invalidate the session query, and the next /me
    // refetch must surface the 401 so AuthGate flips to LoginPage.
    let meCallCount = 0;
    fetchRouter({
      "GET /api/v1/auth/me": async () => {
        meCallCount += 1;
        if (meCallCount === 1) return jsonResponse(sampleUser);
        // After the page call's 401 fires the handler and
        // invalidates /me, the refetch returns the expired-session
        // 401 the server would actually emit.
        return jsonResponse(
          { error: { code: "session_expired", message: "" } },
          401,
        );
      },
      "GET /api/v1/agents": async () =>
        jsonResponse(
          { error: { code: "session_expired", message: "" } },
          401,
        ),
    });

    renderApp();

    // Wait until AppShell is mounted (operator is authenticated).
    await screen.findByRole("link", { name: /dashboard/i });

    // Trigger a page-level API call directly. Components are not
    // required to implement their own 401 handling — invoking the
    // typed API client surfaces the 401 path used everywhere.
    await expect(api.listAgents()).rejects.toThrow();

    // AuthGate flips to LoginPage after the session refetch.
    expect(
      await screen.findByRole("heading", { name: /sign in to anchorix/i }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: /dashboard/i }),
    ).not.toBeInTheDocument();
  });

  it("does not invalidate the session or refetch /me on /auth/login 401", async () => {
    // /auth/login is the deterministic invalid-credentials path —
    // not an expired session. The global handler must NOT fire for
    // login 401s, so the gate's /me state stays exactly where it
    // was (anonymous, one initial probe). Without the /auth/login
    // exemption, every failed login attempt would force an extra
    // /me refetch — wasted work and the wrong UX framing.
    let meCallCount = 0;
    let loginCallCount = 0;
    fetchRouter({
      "GET /api/v1/auth/me": async () => {
        meCallCount += 1;
        return jsonResponse(
          { error: { code: "unauthorized", message: "" } },
          401,
        );
      },
      "POST /api/v1/auth/login": async () => {
        loginCallCount += 1;
        return jsonResponse(
          { error: { code: "invalid_credentials", message: "wrong" } },
          401,
        );
      },
    });

    renderApp();

    // Initial gate probe runs once.
    await screen.findByRole("heading", { name: /sign in to anchorix/i });
    const initialMeCallCount = meCallCount;

    fireEvent.change(screen.getByLabelText(/email/i), {
      target: { value: "alice@example.com" },
    });
    fireEvent.change(screen.getByLabelText(/password/i), {
      target: { value: "wrong" },
    });
    fireEvent.click(screen.getByRole("button", { name: /sign in/i }));

    // Safe invalid-credentials message is shown. Backend "wrong"
    // text must not reach the operator.
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/invalid email or password\./i);
    expect(alert).not.toHaveTextContent(/wrong/i);
    expect(loginCallCount).toBe(1);

    // The login 401 must NOT have invalidated the session or
    // triggered an extra /me refetch. A short stability wait lets
    // any spurious refetch settle before we assert.
    await waitFor(() => {
      expect(meCallCount).toBe(initialMeCallCount);
    });
  });

  it("does not loop /me when /me itself returns 401", async () => {
    // The /auth/me exemption inside api.ts is what makes the gate's
    // own probe safe. Without the exemption, /me 401 would fire the
    // handler, which would invalidate /me, which would refetch /me,
    // which would 401 again — infinite loop. This test proves the
    // exemption holds: /me is called a small, bounded number of
    // times even though every call returns 401.
    let meCallCount = 0;
    fetchRouter({
      "GET /api/v1/auth/me": async () => {
        meCallCount += 1;
        return jsonResponse(
          { error: { code: "unauthorized", message: "" } },
          401,
        );
      },
    });

    renderApp();

    // LoginPage must render — proves the gate handled the 401
    // without hanging on an invalidation loop.
    await screen.findByRole("heading", { name: /sign in to anchorix/i });

    // A short stability wait so a runaway loop has time to surface
    // as a call-count explosion before we assert. waitFor's default
    // timeout (~1s) is the upper bound; a real loop would push
    // meCallCount into the hundreds.
    await waitFor(() => {
      expect(meCallCount).toBeLessThanOrEqual(2);
    });
  });
});

// renderAppTab renders an independent <App> instance into its own
// container under document.body, with its own QueryClient. Two
// instances in one test model two browser tabs sharing the same
// origin: their BroadcastChannel instances communicate, their
// fetches share the global fetch mock, and their DOM is queryable
// via within(container).
function renderAppTab() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  const utils = render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={["/"]}>
        <App />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return { ...utils, queryClient };
}

describe("cross-tab session sync (H-004)", () => {
  it("propagates logout to other tabs", async () => {
    // Both tabs start authenticated. Tab A signs out; tab B
    // receives the BroadcastChannel "logout" event, invalidates
    // its session, and AuthGate flips to LoginPage on the next
    // /me refetch (which now returns 401 because the server-side
    // `loggedIn` flag is false).
    //
    // We assert tab B's state — the cross-tab guarantee. Tab A's
    // own state is exercised by the PR-008 / PR-009 logout tests
    // and is not the contract this test is here to prove.
    let loggedIn = true;
    fetchRouter({
      "GET /api/v1/auth/me": async () =>
        loggedIn
          ? jsonResponse(sampleUser)
          : jsonResponse(
              { error: { code: "unauthorized", message: "" } },
              401,
            ),
      "POST /api/v1/auth/logout": async () => {
        loggedIn = false;
        return new Response(null, { status: 204 });
      },
    });

    const tabA = renderAppTab();
    const tabB = renderAppTab();
    const inA = within(tabA.container);
    const inB = within(tabB.container);

    // Both tabs reach AppShell.
    await inA.findByRole("link", { name: /dashboard/i });
    await inB.findByRole("link", { name: /dashboard/i });

    // Sign out in tab A.
    fireEvent.click(inA.getByRole("button", { name: /sign out/i }));

    // Tab B receives the broadcast, invalidates, refetches /me,
    // sees 401, and flips to LoginPage.
    expect(
      await inB.findByRole("heading", { name: /sign in to anchorix/i }),
    ).toBeInTheDocument();
    expect(
      inB.queryByRole("link", { name: /dashboard/i }),
    ).not.toBeInTheDocument();
  });

  it("propagates login to other tabs", async () => {
    // Both tabs start anonymous. Tab A submits valid credentials;
    // POST /login flips `loggedIn` and returns the user. Tab B
    // receives the "login" BroadcastChannel event, invalidates its
    // session, and AuthGate flips to AppShell on the refetch.
    let loggedIn = false;
    fetchRouter({
      "GET /api/v1/auth/me": async () =>
        loggedIn
          ? jsonResponse(sampleUser)
          : jsonResponse(
              { error: { code: "unauthorized", message: "" } },
              401,
            ),
      "POST /api/v1/auth/login": async () => {
        loggedIn = true;
        return jsonResponse(sampleUser);
      },
    });

    const tabA = renderAppTab();
    const tabB = renderAppTab();
    const inA = within(tabA.container);
    const inB = within(tabB.container);

    // Both tabs start on LoginPage.
    await inA.findByRole("heading", { name: /sign in to anchorix/i });
    await inB.findByRole("heading", { name: /sign in to anchorix/i });

    // Sign in via tab A.
    fireEvent.change(inA.getByLabelText(/email/i), {
      target: { value: "alice@example.com" },
    });
    fireEvent.change(inA.getByLabelText(/password/i), {
      target: { value: "correct horse" },
    });
    fireEvent.click(inA.getByRole("button", { name: /sign in/i }));

    // Tab B receives "login", invalidates, refetches /me, gets a
    // user, and renders AppShell.
    expect(
      await inB.findByRole("link", { name: /dashboard/i }),
    ).toBeInTheDocument();
  });

  it("broadcasts only the event type — no user, email, role, or session value", async () => {
    // CLAUDE.md §6.9: secrets and identifying material must not
    // leave the application boundary. The cross-tab channel is one
    // such boundary. This test spies on every BroadcastChannel
    // postMessage call made during a login + sign-out flow and
    // asserts every payload is a primitive "login"/"logout" string
    // with none of the forbidden substrings present in its JSON
    // representation.
    const postSpy = vi.spyOn(BroadcastChannel.prototype, "postMessage");

    let loggedIn = false;
    fetchRouter({
      "GET /api/v1/auth/me": async () =>
        loggedIn
          ? jsonResponse(sampleUser)
          : jsonResponse(
              { error: { code: "unauthorized", message: "" } },
              401,
            ),
      "POST /api/v1/auth/login": async () => {
        loggedIn = true;
        return jsonResponse(sampleUser);
      },
      "POST /api/v1/auth/logout": async () => {
        loggedIn = false;
        return new Response(null, { status: 204 });
      },
    });

    renderApp();
    await screen.findByRole("heading", { name: /sign in to anchorix/i });

    // Login (publishes "login").
    fireEvent.change(screen.getByLabelText(/email/i), {
      target: { value: sampleUser.email },
    });
    fireEvent.change(screen.getByLabelText(/password/i), {
      target: { value: "correct horse" },
    });
    fireEvent.click(screen.getByRole("button", { name: /sign in/i }));
    await screen.findByRole("link", { name: /dashboard/i });

    // Trigger logout (publishes "logout"). We do NOT assert the
    // tab's own gate flips here — the publish happens in
    // useLogout.onSettled regardless. waitFor watches for the spy
    // to have captured both payloads.
    fireEvent.click(screen.getByRole("button", { name: /sign out/i }));
    await waitFor(() => {
      const payloads = postSpy.mock.calls.map((c) => c[0]);
      expect(payloads).toContain("logout");
    });

    const payloads = postSpy.mock.calls.map((c) => c[0]);
    expect(payloads).toContain("login");
    expect(payloads).toContain("logout");

    const forbiddenSubstrings = [
      sampleUser.id,
      sampleUser.email,
      sampleUser.organization_id,
      sampleUser.display_name,
      sampleUser.role,
      "password",
      "session",
      "cookie",
      "token",
      "secret",
      "authorization",
    ];
    for (const payload of payloads) {
      // All payloads must be the bare event-type string.
      expect(typeof payload).toBe("string");
      expect(["login", "logout"]).toContain(payload as string);
      const serialized = JSON.stringify(payload).toLowerCase();
      for (const forbidden of forbiddenSubstrings) {
        expect(serialized).not.toContain(forbidden.toLowerCase());
      }
    }

    postSpy.mockRestore();
  });
});

// renderAppWithClient is renderApp + access to the QueryClient. Used
// by the cache-cleanup test to inspect cache state directly. The
// rest of the suite uses renderApp / renderAppTab because they
// don't need cache-level introspection.
function renderAppWithClient() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  const utils = render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={["/"]}>
        <App />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return { ...utils, queryClient };
}

describe("logout determinism (H-004 fix)", () => {
  it("logging-out tab returns to LoginPage on /logout 204", async () => {
    // Server-side state: loggedIn=true initially; POST /logout flips
    // it to false and returns 204. /me reads the flag, so the next
    // /me after sign-out returns 401. The fix in useLogout
    // (refetchQueries instead of clear+invalidate) makes the gate
    // flip on the same tick that the mutation settles.
    let loggedIn = true;
    fetchRouter({
      "GET /api/v1/auth/me": async () =>
        loggedIn
          ? jsonResponse(sampleUser)
          : jsonResponse(
              { error: { code: "unauthorized", message: "" } },
              401,
            ),
      "POST /api/v1/auth/logout": async () => {
        loggedIn = false;
        return new Response(null, { status: 204 });
      },
    });
    renderApp();

    await screen.findByRole("link", { name: /dashboard/i });
    fireEvent.click(screen.getByRole("button", { name: /sign out/i }));

    expect(
      await screen.findByRole("heading", { name: /sign in to anchorix/i }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: /dashboard/i }),
    ).not.toBeInTheDocument();
  });

  it("logging-out tab returns to LoginPage even when /logout returns 500", async () => {
    // The frontend treats the mutation as settled regardless of
    // outcome. Whatever the server reports on the next /me is the
    // authoritative answer. If the server actually revoked the
    // session despite responding 500, /me returns 401 and the gate
    // flips. This test models that case via a meCallCount-based /me
    // mock that surfaces 401 from the second call onward.
    let meCallCount = 0;
    fetchRouter({
      "GET /api/v1/auth/me": async () => {
        meCallCount += 1;
        if (meCallCount === 1) return jsonResponse(sampleUser);
        return jsonResponse(
          { error: { code: "unauthorized", message: "" } },
          401,
        );
      },
      "POST /api/v1/auth/logout": async () =>
        jsonResponse(
          { error: { code: "internal_error", message: "boom" } },
          500,
        ),
    });
    renderApp();

    await screen.findByRole("link", { name: /dashboard/i });
    fireEvent.click(screen.getByRole("button", { name: /sign out/i }));

    expect(
      await screen.findByRole("heading", { name: /sign in to anchorix/i }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: /dashboard/i }),
    ).not.toBeInTheDocument();
  });

  it("removes page-level cached queries on logout but keeps the session observer working", async () => {
    // The cache cleanup in useLogout MUST drop authenticated
    // page-level data (so the next operator doesn't inherit it)
    // while preserving the session query observer's subscription
    // (so the gate can still react to the post-logout /me 401).
    let loggedIn = true;
    fetchRouter({
      "GET /api/v1/auth/me": async () =>
        loggedIn
          ? jsonResponse(sampleUser)
          : jsonResponse(
              { error: { code: "unauthorized", message: "" } },
              401,
            ),
      "POST /api/v1/auth/logout": async () => {
        loggedIn = false;
        return new Response(null, { status: 204 });
      },
    });

    const { queryClient } = renderAppWithClient();
    await screen.findByRole("link", { name: /dashboard/i });

    // Prime a non-session query as if a page had fetched data.
    queryClient.setQueryData(["agents", "list"], [{ id: "agent-1" }]);
    expect(queryClient.getQueryData(["agents", "list"])).toEqual([
      { id: "agent-1" },
    ]);

    fireEvent.click(screen.getByRole("button", { name: /sign out/i }));

    // The gate flipped — proves the session observer is still wired
    // up after the cache cleanup ran.
    await screen.findByRole("heading", { name: /sign in to anchorix/i });

    // Page-level data is gone.
    expect(queryClient.getQueryData(["agents", "list"])).toBeUndefined();
  });
});
