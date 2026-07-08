package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestNopDiscards(t *testing.T) {
	l := Nop()
	// Must not panic and must produce no output anywhere.
	l.Info("nothing", "k", "v")
	if Or(nil) == nil {
		t.Fatal("Or(nil) must return a usable logger")
	}
	custom := New(Options{})
	if Or(custom) != custom {
		t.Fatal("Or must pass through a non-nil logger")
	}
}

func TestConsoleLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	l := NewConsole(&buf, ConsoleOptions{Level: slog.LevelWarn})
	l.Debug("dbg")
	l.Info("inf")
	l.Warn("wrn", "code", 429)
	l.Error("err", "reason", "boom")

	out := buf.String()
	if strings.Contains(out, "dbg") || strings.Contains(out, "inf") {
		t.Fatalf("below-threshold lines leaked:\n%s", out)
	}
	if !strings.Contains(out, "WRN wrn code=429") {
		t.Fatalf("warn line/format wrong:\n%s", out)
	}
	if !strings.Contains(out, `ERR err reason="boom"`) {
		t.Fatalf("error line/format wrong:\n%s", out)
	}
}

func TestConsoleStructuredFieldsAndGroups(t *testing.T) {
	var buf bytes.Buffer
	l := NewConsole(&buf, ConsoleOptions{Level: slog.LevelInfo})
	l = l.With("issuer", "kv1").WithGroup("mint")
	l.Info("blind-sign", "family", "burn", "count", 3, "ok", true)

	out := strings.TrimSpace(buf.String())
	for _, want := range []string{"INF blind-sign", `issuer="kv1"`, `mint.family="burn"`, "mint.count=3", "mint.ok=true"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
}

func TestConsoleNoTimestampByDefault(t *testing.T) {
	var buf bytes.Buffer
	NewConsole(&buf, ConsoleOptions{}).Info("x")
	if !strings.HasPrefix(buf.String(), "INF x") {
		t.Fatalf("expected no leading timestamp, got %q", buf.String())
	}
}

func TestParseLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"debug": slog.LevelDebug, "DEBUG": slog.LevelDebug,
		"warn": slog.LevelWarn, "warning": slog.LevelWarn,
		"error": slog.LevelError, "info": slog.LevelInfo,
		"nonsense": slog.LevelInfo, "": slog.LevelInfo,
	}
	for in, want := range cases {
		if got := ParseLevel(in); got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestNewJSON(t *testing.T) {
	var buf bytes.Buffer
	New(Options{JSON: true, Out: &buf}).Info("hello", "n", 1)
	out := buf.String()
	if !strings.Contains(out, `"msg":"hello"`) || !strings.Contains(out, `"n":1`) {
		t.Fatalf("json output wrong: %s", out)
	}
}
