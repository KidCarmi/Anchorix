// Package logger provides a tiny structured logger for the agent.
package logger

import (
	"log/slog"
	"os"
	"strings"
)

// Logger wraps slog.Logger so we can swap formats later (Windows event log
// integration arrives in Phase 6).
type Logger struct {
	*slog.Logger
}

// New constructs a Logger writing JSON to stdout.
func New(level string) *Logger {
	opts := &slog.HandlerOptions{Level: parseLevel(level)}
	return &Logger{Logger: slog.New(slog.NewJSONHandler(os.Stdout, opts))}
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
