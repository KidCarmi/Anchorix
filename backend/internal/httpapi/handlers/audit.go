package handlers

import "net/http"

// AuditList returns audit events filtered by actor / action / target.
// Audit events are insert-only (CLAUDE.md §9).
func AuditList(w http.ResponseWriter, _ *http.Request) { notImplemented(w) }
