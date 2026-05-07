//go:build !windows

package config

import (
	"os"
	"path/filepath"
)

func defaultIdentityPath() string {
	if v := os.Getenv("XDG_STATE_HOME"); v != "" {
		return filepath.Join(v, "anchorix", "agent", "identity.json")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "/var/lib/anchorix/agent/identity.json"
	}
	return filepath.Join(home, ".anchorix", "agent", "identity.json")
}
