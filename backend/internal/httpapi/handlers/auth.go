package handlers

import "net/http"

// AuthLogin authenticates an operator and starts a session.
// Implementation lands in Phase 1 (CLAUDE.md §6.5; ROADMAP.md Phase 1).
func AuthLogin(w http.ResponseWriter, _ *http.Request) { notImplemented(w) }

// AuthLogout terminates the current session.
func AuthLogout(w http.ResponseWriter, _ *http.Request) { notImplemented(w) }

// AuthMe returns the currently authenticated operator profile.
func AuthMe(w http.ResponseWriter, _ *http.Request) { notImplemented(w) }
