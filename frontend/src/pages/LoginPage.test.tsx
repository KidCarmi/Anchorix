import { afterEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";

import { LoginPage } from "./LoginPage";

afterEach(() => {
  vi.unstubAllGlobals();
});

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function renderLoginPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <LoginPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("LoginPage", () => {
  it("renders the email + password fields and the submit button", () => {
    renderLoginPage();
    expect(screen.getByRole("form", { name: /sign in/i })).toBeInTheDocument();
    expect(screen.getByLabelText(/email/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/password/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /sign in/i })).toBeInTheDocument();
  });

  it("shows the safe invalid-credentials message on 401", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse(
        { error: { code: "invalid_credentials", message: "wrong" } },
        401,
      ),
    );
    vi.stubGlobal("fetch", fetchMock);

    renderLoginPage();
    fireEvent.change(screen.getByLabelText(/email/i), {
      target: { value: "alice@example.com" },
    });
    fireEvent.change(screen.getByLabelText(/password/i), {
      target: { value: "wrong" },
    });
    fireEvent.click(screen.getByRole("button", { name: /sign in/i }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/invalid email or password\./i);
    // Underlying server message text must NOT leak through to the UI.
    expect(alert).not.toHaveTextContent(/wrong/i);
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("shows a generic safe message on a 500 server error", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse(
        { error: { code: "internal_error", message: "boom" } },
        500,
      ),
    );
    vi.stubGlobal("fetch", fetchMock);

    renderLoginPage();
    fireEvent.change(screen.getByLabelText(/email/i), {
      target: { value: "alice@example.com" },
    });
    fireEvent.change(screen.getByLabelText(/password/i), {
      target: { value: "pw" },
    });
    fireEvent.click(screen.getByRole("button", { name: /sign in/i }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/could not sign in/i);
    expect(alert).not.toHaveTextContent(/boom/i);
  });

  it("disables the submit button while the request is pending", async () => {
    // Resolve the fetch only when we say so, so we can observe the
    // pending state without timing assumptions.
    let resolveFetch!: (r: Response) => void;
    const pendingFetch = new Promise<Response>((r) => {
      resolveFetch = r;
    });
    vi.stubGlobal("fetch", vi.fn(async () => pendingFetch));

    renderLoginPage();
    fireEvent.change(screen.getByLabelText(/email/i), {
      target: { value: "alice@example.com" },
    });
    fireEvent.change(screen.getByLabelText(/password/i), {
      target: { value: "pw" },
    });
    fireEvent.click(screen.getByRole("button", { name: /sign in/i }));

    const submitButton = await screen.findByRole("button", {
      name: /signing in/i,
    });
    expect(submitButton).toBeDisabled();

    resolveFetch(
      jsonResponse({
        id: "u1",
        organization_id: "anchorix",
        email: "alice@example.com",
        display_name: "Alice",
        role: "admin",
        disabled: false,
        created_at: "2026-05-11T10:00:00Z",
      }),
    );
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: /sign in/i }),
      ).not.toBeDisabled(),
    );
  });
});
