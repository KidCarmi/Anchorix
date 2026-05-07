import { useState } from "react";

export function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    // Wired in Phase 1. For now this is a static page.
    setError("Login backend lands in Phase 1.");
  }

  return (
    <div className="flex min-h-full items-center justify-center bg-anchor-50">
      <form
        onSubmit={onSubmit}
        className="w-full max-w-sm rounded-md border border-anchor-100 bg-white p-6 shadow-sm"
      >
        <h1 className="mb-1 text-xl font-semibold text-anchor-900">Sign in to Anchorix</h1>
        <p className="mb-4 text-sm text-anchor-700">Operator console — v0.1.</p>

        <label className="mb-3 block text-sm">
          <span className="text-anchor-900">Email</span>
          <input
            type="email"
            autoComplete="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="mt-1 block w-full rounded border border-anchor-100 px-3 py-2 text-sm"
          />
        </label>

        <label className="mb-4 block text-sm">
          <span className="text-anchor-900">Password</span>
          <input
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="mt-1 block w-full rounded border border-anchor-100 px-3 py-2 text-sm"
          />
        </label>

        {error && <p className="mb-3 text-sm text-red-600">{error}</p>}

        <button
          type="submit"
          className="w-full rounded bg-anchor-700 px-3 py-2 text-sm font-medium text-white hover:bg-anchor-900"
        >
          Sign in
        </button>
      </form>
    </div>
  );
}
