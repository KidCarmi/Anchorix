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

// Stores groups all repository interfaces. The composition root constructs
// one Stores value at startup and passes the relevant fields to each domain
// service.
type Stores struct {
	Auth      auth.Repository
	Agents    agents.Repository
	Inventory inventory.Repository
	Audit     audit.Recorder
}
