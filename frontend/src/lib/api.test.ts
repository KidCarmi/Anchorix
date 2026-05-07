import { describe, expect, it, vi } from "vitest";

import { ApiError } from "./api";

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

  it("does not break when fetch is mocked", () => {
    // Sanity check that vi.fn is usable in the test environment.
    const f = vi.fn();
    f();
    expect(f).toHaveBeenCalledOnce();
  });
});
