import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";

import { App } from "./App";
import type { User } from "./lib/api";

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
