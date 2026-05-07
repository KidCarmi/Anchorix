package handlers

import "net/http"

// AgentsList returns the registered agents for the operator's organization.
func AgentsList(w http.ResponseWriter, _ *http.Request) { notImplemented(w) }

// AgentsGet returns a single agent by id.
func AgentsGet(w http.ResponseWriter, _ *http.Request) { notImplemented(w) }

// AgentsEnroll consumes a single-use enrollment token and records a new
// agent identity. Tokens are never logged (CLAUDE.md §6.5, §6.9).
func AgentsEnroll(w http.ResponseWriter, _ *http.Request) { notImplemented(w) }

// AgentsHeartbeat records that an agent is alive and updates last-seen.
func AgentsHeartbeat(w http.ResponseWriter, _ *http.Request) { notImplemented(w) }

// AgentsInventory ingests a batch of certificate descriptors from an agent.
// The control plane must reject any payload that contains private key
// material (CLAUDE.md §6.2).
func AgentsInventory(w http.ResponseWriter, _ *http.Request) { notImplemented(w) }

// AgentsCreateEnrollmentToken issues a short-lived enrollment token to an
// authenticated operator.
func AgentsCreateEnrollmentToken(w http.ResponseWriter, _ *http.Request) { notImplemented(w) }
