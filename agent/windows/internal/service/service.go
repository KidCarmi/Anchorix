// Package service is the agent's runtime loop.
//
// On Windows it will register with the Service Control Manager (Phase 6);
// today it simply runs heartbeat + inventory loops driven by ticker.
package service

import (
	"context"
	"time"

	"github.com/kidcarmi/anchorix/agent/windows/internal/config"
	"github.com/kidcarmi/anchorix/agent/windows/internal/logger"
)

// Run starts the agent's main loops. It returns when ctx is cancelled.
func Run(ctx context.Context, cfg *config.Config, log *logger.Logger) error {
	log.Info("agent starting",
		"control_plane_url", cfg.ControlPlaneURL,
		"discovery_mode", cfg.DiscoveryMode,
		"heartbeat_interval", cfg.HeartbeatInterval.String(),
		"inventory_interval", cfg.InventoryInterval.String(),
	)

	heartbeat := time.NewTicker(cfg.HeartbeatInterval)
	defer heartbeat.Stop()
	inventory := time.NewTicker(cfg.InventoryInterval)
	defer inventory.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("agent shutting down")
			return nil
		case <-heartbeat.C:
			log.Debug("heartbeat tick (no-op until Phase 3)")
		case <-inventory.C:
			log.Debug("inventory tick (no-op until Phase 3)")
		}
	}
}
