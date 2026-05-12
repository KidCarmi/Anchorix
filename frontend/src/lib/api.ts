// Single typed API client. UI code never crafts URLs by hand
// (CLAUDE.md §8.3).

const baseURL = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? "/api/v1";

export class ApiError extends Error {
  readonly status: number;
  readonly code?: string;
  constructor(status: number, message: string, code?: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

// UnauthorizedHandler is invoked once per 401 response from any
// non-exempt endpoint, BEFORE the ApiError is thrown to the caller.
// The session layer wires a handler that invalidates the session
// query; AuthGate then flips to LoginPage on the next /me refetch.
type UnauthorizedHandler = (path: string) => void;

// unauthorizedExemptPaths lists request paths whose 401 must NOT
// trigger the global handler. /auth/me is the gate's own probe —
// invalidating the session query in response to its 401 would create
// an infinite invalidate → refetch → 401 → invalidate loop.
//
// Everything else (page-level data, future state-changing endpoints)
// uses the handler so an expired or revoked session surfaces in the
// gate within one /me round trip.
const unauthorizedExemptPaths: ReadonlySet<string> = new Set(["/auth/me"]);

// Single-slot registry. The composition root (src/lib/session.ts
// via useGlobalUnauthorizedHandler) sets this exactly once. We
// deliberately use a module-level slot rather than an event bus or
// pub/sub: there is exactly one consumer (the session layer), and
// exposing a list of subscribers would invite scope creep
// (CLAUDE.md §8.5 anti-patterns).
let unauthorizedHandler: UnauthorizedHandler | null = null;

// registerUnauthorizedHandler installs the global 401 callback.
// Pass null to clear (used by test cleanup). Last writer wins —
// re-registering replaces the previous handler.
export function registerUnauthorizedHandler(handler: UnauthorizedHandler | null): void {
  unauthorizedHandler = handler;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${baseURL}${path}`, {
    ...init,
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
  });

  if (!res.ok) {
    // Dispatch the global 401 callback BEFORE reading the body so a
    // handler that triggers a session refetch can race the response
    // body parse without affecting either path. The handler is
    // called at most once per response and never for /auth/me, which
    // is the gate's own probe and would loop on its own 401.
    if (res.status === 401 && unauthorizedHandler && !unauthorizedExemptPaths.has(path)) {
      unauthorizedHandler(path);
    }
    let code: string | undefined;
    let message = res.statusText;
    try {
      const body = (await res.json()) as { error?: { code?: string; message?: string } };
      code = body.error?.code;
      message = body.error?.message ?? message;
    } catch {
      // non-JSON response; keep the statusText
    }
    throw new ApiError(res.status, message, code);
  }

  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export const api = {
  // --- Auth ---
  //
  // Login, logout, and /me round-trip the HttpOnly session cookie
  // owned by the backend (CLAUDE.md §6: session value never reaches
  // JavaScript). The shared request() helper sets
  // `credentials: "include"` so the browser attaches the cookie on
  // every API call.
  login: (email: string, password: string) =>
    request<User>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),
  logout: () => request<void>("/auth/logout", { method: "POST" }),
  me: () => request<User>("/auth/me"),

  // --- Agents ---
  listAgents: () => request<{ items: Agent[]; next_cursor: string | null }>("/agents"),

  // --- Certificates ---
  listCertificates: (params: { q?: string; cursor?: string; limit?: number } = {}) => {
    const qs = new URLSearchParams();
    if (params.q) qs.set("q", params.q);
    if (params.cursor) qs.set("cursor", params.cursor);
    if (params.limit) qs.set("limit", String(params.limit));
    const suffix = qs.toString() ? `?${qs.toString()}` : "";
    return request<{ items: Certificate[]; next_cursor: string | null }>(`/certificates${suffix}`);
  },

  // --- Findings ---
  listFindings: () => request<{ items: Finding[]; next_cursor: string | null }>("/findings"),

  // --- Providers ---
  listProviders: () => request<{ items: Provider[] }>("/providers"),

  // --- Audit ---
  listAuditEvents: () => request<{ items: AuditEvent[]; next_cursor: string | null }>("/audit/events"),
};

// --- Types (kept thin; richer types arrive when each phase lands) ---

// User mirrors backend/internal/auth/auth.go User. `last_login_at`
// is JSON-omitempty on the server, so it may be missing or null on
// the first login.
export type User = {
  id: string;
  organization_id: string;
  email: string;
  display_name: string;
  role: "admin" | "operator";
  disabled: boolean;
  created_at: string;
  last_login_at?: string | null;
};

export type Agent = {
  id: string;
  hostname: string;
  status: "pending_enrollment" | "active" | "disabled" | "revoked";
  enrolled_at: string;
  last_seen_at: string;
};

export type Certificate = {
  id: string;
  subject: string;
  issuer: string;
  not_before: string;
  not_after: string;
  fingerprint_sha256: string;
};

export type Finding = {
  id: string;
  certificate_id: string;
  rule_id: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  status: "open" | "acknowledged" | "suppressed" | "resolved";
  title: string;
  opened_at: string;
};

export type Provider = {
  id: string;
  kind: string;
  display_name: string;
  capabilities: string[];
};

export type AuditEvent = {
  id: string;
  occurred_at: string;
  actor: string;
  actor_type: "user" | "agent" | "system";
  action: string;
  target_type: string;
  target_id: string;
};
