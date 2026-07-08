// Package logging is tamayo's structured logging seam, built entirely on the
// standard library's log/slog — no third-party dependency, and it
// cross-compiles for GOOS=tamago unchanged.
//
// The design goal is that library packages stay logger-agnostic: they accept
// an optional *slog.Logger and treat nil as "log nothing" (Nop). Only the
// runtime binary (cmd/tamayo) picks a concrete handler. This keeps the
// crypto and token packages free of logging policy while giving the service
// real, structured, level-filtered logs.
package logging

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

// Nop returns a logger that discards everything. Library code uses this as
// the default when the caller passes no logger, so a nil *slog.Logger never
// has to be nil-checked at each call site.
func Nop() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// Or returns l if non-nil, else Nop(). Call it once at the top of a
// constructor so the rest of the type can log unconditionally.
func Or(l *slog.Logger) *slog.Logger {
	if l == nil {
		return Nop()
	}
	return l
}

// Options configures a host logger.
type Options struct {
	// Level is the minimum level emitted (default Info).
	Level slog.Level
	// JSON selects the JSON handler instead of the text handler.
	JSON bool
	// Out is the destination (default os.Stderr).
	Out io.Writer
}

// New builds a host logger (text by default, JSON on request) writing to
// Out. On tamago, prefer NewConsole — this handler pulls in slog's text/JSON
// formatting which is available but heavier than a bare console line.
func New(opts Options) *slog.Logger {
	out := opts.Out
	if out == nil {
		out = os.Stderr
	}
	ho := &slog.HandlerOptions{Level: opts.Level}
	var h slog.Handler
	if opts.JSON {
		h = slog.NewJSONHandler(out, ho)
	} else {
		h = slog.NewTextHandler(out, ho)
	}
	return slog.New(h)
}

// ParseLevel maps the usual level names (case-insensitive) to slog levels;
// anything unrecognized is Info. Handy for a -log-level flag.
func ParseLevel(s string) slog.Level {
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
