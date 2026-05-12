import { useState, type FormEvent } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";

import { ApiError, api } from "../lib/api";
import { publishSessionEvent, sessionQueryKey } from "../lib/session";

// Backend returns `invalid_credentials` for every failed-login mode
// (no user / wrong password / disabled user). The UI mirrors that
// determinism by collapsing those cases to one safe message — leaking
// "user not found" vs "wrong password" would help an attacker
// enumerate accounts (CLAUDE.md §6).
const invalidCredentialsMessage = "Invalid email or password.";

// genericFailureMessage is shown on transport errors, 5xx responses,
// or anything else we don't have a specific safe message for. It
// intentionally does not surface the underlying error to the operator
// — internal error text could carry hostnames, stack traces, or other
// detail that doesn't help them sign in.
const genericFailureMessage =
  "Could not sign in. Please check your network and try again.";

export function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const queryClient = useQueryClient();

  const loginMutation = useMutation({
    mutationFn: ({ email, password }: { email: string; password: string }) =>
      api.login(email, password),
    onSuccess: async () => {
      // The auth cookie is now set HttpOnly by the server. Force the
      // session query to refetch so AuthGate flips to the AppShell.
      // Also notify other tabs (H-004) so a tab sitting on LoginPage
      // can transition without waiting for its next /me probe.
      await queryClient.invalidateQueries({ queryKey: sessionQueryKey });
      publishSessionEvent("login");
    },
    onError: (err: unknown) => {
      if (err instanceof ApiError) {
        if (err.status === 401 || err.code === "invalid_credentials") {
          setErrorMessage(invalidCredentialsMessage);
          return;
        }
        if (err.status === 400) {
          setErrorMessage(invalidCredentialsMessage);
          return;
        }
      }
      setErrorMessage(genericFailureMessage);
    },
  });

  function onSubmit(e: FormEvent) {
    e.preventDefault();
    setErrorMessage(null);
    loginMutation.mutate({ email: email.trim(), password });
  }

  const isPending = loginMutation.isPending;

  return (
    <div className="flex min-h-full items-center justify-center bg-anchor-50">
      <form
        onSubmit={onSubmit}
        className="w-full max-w-sm rounded-md border border-anchor-100 bg-white p-6 shadow-sm"
        aria-label="Sign in"
      >
        <h1 className="mb-1 text-xl font-semibold text-anchor-900">Sign in to Anchorix</h1>
        <p className="mb-4 text-sm text-anchor-700">Operator console — v0.1.</p>

        <label className="mb-3 block text-sm">
          <span className="text-anchor-900">Email</span>
          <input
            type="email"
            autoComplete="email"
            required
            disabled={isPending}
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
            disabled={isPending}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="mt-1 block w-full rounded border border-anchor-100 px-3 py-2 text-sm"
          />
        </label>

        {errorMessage && (
          <p role="alert" className="mb-3 text-sm text-red-600">
            {errorMessage}
          </p>
        )}

        <button
          type="submit"
          disabled={isPending}
          className="w-full rounded bg-anchor-700 px-3 py-2 text-sm font-medium text-white hover:bg-anchor-900 disabled:cursor-not-allowed disabled:bg-anchor-700/60"
        >
          {isPending ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </div>
  );
}
