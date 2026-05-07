package handlers

import "net/http"

// FindingsList returns risk findings filtered by severity, status, etc.
func FindingsList(w http.ResponseWriter, _ *http.Request) { notImplemented(w) }

// FindingsGet returns a single finding with its evidence payload.
func FindingsGet(w http.ResponseWriter, _ *http.Request) { notImplemented(w) }

// FindingsAcknowledge marks a finding as acknowledged. A reason is required
// and is recorded in the audit log.
func FindingsAcknowledge(w http.ResponseWriter, _ *http.Request) { notImplemented(w) }

// FindingsSuppress hides a finding from default views with an expiry and a
// required reason. Suppressions are visible in the audit log.
func FindingsSuppress(w http.ResponseWriter, _ *http.Request) { notImplemented(w) }
