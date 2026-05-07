package handlers

import "net/http"

// ProvidersList returns the registered PKI / secret / transport providers.
// In v0.1 this surface is read-only.
func ProvidersList(w http.ResponseWriter, _ *http.Request) { notImplemented(w) }

// ProvidersGet returns a single provider's status and capability descriptor.
func ProvidersGet(w http.ResponseWriter, _ *http.Request) { notImplemented(w) }
