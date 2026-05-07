package handlers

import "net/http"

// CertificatesList returns a paginated, filterable list of certificates.
func CertificatesList(w http.ResponseWriter, _ *http.Request) { notImplemented(w) }

// CertificatesGet returns a single certificate by id, including all known
// observation locations (host + store).
func CertificatesGet(w http.ResponseWriter, _ *http.Request) { notImplemented(w) }
