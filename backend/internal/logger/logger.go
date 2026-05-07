// Package logger provides structured logging for the control plane.
//
// All log output is JSON to stdout. A small redaction allow-list ensures
// known sensitive field names never appear in logs (CLAUDE.md §6.9, §9).
package logger

import (
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/kidcarmi/anchorix/backend/internal/config"
)

// Logger is a thin wrapper around slog.Logger that enforces redaction.
type Logger struct {
	*slog.Logger
}

// New constructs a Logger with the configured level and environment-aware
// formatting.
func New(level string, env config.Env) *Logger {
	return newWithWriter(level, env, os.Stdout)
}

func newWithWriter(level string, env config.Env, w io.Writer) *Logger {
	opts := &slog.HandlerOptions{
		Level:       parseLevel(level),
		ReplaceAttr: redactAttr,
	}
	var handler slog.Handler
	if env == config.EnvDevelopment {
		handler = slog.NewTextHandler(w, opts)
	} else {
		handler = slog.NewJSONHandler(w, opts)
	}
	return &Logger{Logger: slog.New(handler)}
}

// With returns a child logger with the given key/value pairs attached.
func (l *Logger) With(args ...any) *Logger {
	return &Logger{Logger: l.Logger.With(args...)}
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
