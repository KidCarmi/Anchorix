import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError, api, type User } from "./api";

afterEach(() => {
  vi.unstubAllGlobals();
});

// sampleUser mirrors the User shape backend/internal/auth/auth.go
// returns from /auth/login and /auth/me.
function sampleUser(): User {
  return {
    id: "u1",
    organization_id: "anchorix",
    email: "alice@example.com",
    display_name: "Alice",
    role: "admin",
    disabled: false,
    created_at: "2026-05-11T10:00:00Z",
  };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("ApiError", () => {
  it("captures status and code", () => {
    const err = new ApiError(401, "unauthorized", "unauthorized");
    expect(err.status).toBe(401);
    expect(err.code).toBe("unauthorized");
    expect(err.message).toBe("unauthorized");
  });

  it("is a real Error", () => {
    const err = new ApiError(500, "boom");
    expect(err).toBeInstanceOf(Error);
  });
});

describe("api auth methods", () => {
  it("login sends credentials:include, POSTs JSON, returns the User payload", async () => {
    const user = sampleUser();
    const fetchMock = vi.fn(async () => jsonResponse(user));
    vi.stubGlobal("fetch", fetchMock);

    const got = await api.login("alice@example.com", "correct horse");

    expect(got).toEqual(user);
    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("/api/v1/auth/login");
    expect(init.credentials).toBe("include");
    expect(init.method).toBe("POST");
    expect(init.body).toBe(
      JSON.stringify({ email: "alice@example.com", password: "correct horse" }),
    );
    const headers = init.headers as Record<string, string>;
    expect(headers["Content-Type"]).toBe("application/json");
  });

  it("logout sends credentials:include, returns void on 204", async () => {
    // 204 disallows a body per the Fetch spec; pass null.
    const fetchMock = vi.fn(async () => new Response(null, { status: 204 }));
    vi.stubGlobal("fetch", fetchMock);

    await api.logout();

    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("/api/v1/auth/logout");
    expect(init.credentials).toBe("include");
    expect(init.method).toBe("POST");
  });

  it("me sends credentials:include and returns the User payload", async () => {
    const user = sampleUser();
    const fetchMock = vi.fn(async () => jsonResponse(user));
    vi.stubGlobal("fetch", fetchMock);

    const got = await api.me();

    expect(got).toEqual(user);
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("/api/v1/auth/me");
    expect(init.credentials).toBe("include");
  });

  it("throws ApiError with status and code on 401 invalid_credentials", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse(
        { error: { code: "invalid_credentials", message: "wrong" } },
        401,
      ),
    );
    vi.stubGlobal("fetch", fetchMock);

    let captured: unknown;
    try {
      await api.login("a@example.com", "nope");
    } catch (err) {
      captured = err;
    }
    expect(captured).toBeInstanceOf(ApiError);
    const apiErr = captured as ApiError;
    expect(apiErr.status).toBe(401);
    expect(apiErr.code).toBe("invalid_credentials");
  });
});
