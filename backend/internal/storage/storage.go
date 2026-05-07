// Package storage aggregates the repository interfaces consumed by domain
// modules. Concrete implementations live under storage/postgres.
//
// Domain modules depend only on these interfaces — never on a specific
// driver — so the storage backend can evolve without rippling changes
// through the codebase.
package storage

import (
	"github.com/kidcarmi/anchorix/backend/internal/agents"
	"github.com/kidcarmi/anchorix/backend/internal/audit"
	"github.com/kidcarmi/anchorix/backend/internal/auth"
	"github.com/kidcarmi/anchorix/backend/internal/inventory"
)

// Repositories groups every domain repository the control plane needs.
// The composition root constructs one Repositories value at startup and
// passes the relevant fields to each domain service.
//
// The type is named Repositories rather than Stores to avoid colliding
// with the platform's domain term "certificate store" (Windows store
// locations such as LocalMachine\My).
type Repositories struct {
	Auth      auth.Repository
	Agents    agents.Repository
	Inventory inventory.Repository
	Audit     audit.Recorder
}
