package logging

import (
	"context"
	"io"
	"log/slog"
	"strconv"
	"sync"
)

// ConsoleHandler is a minimal, synchronous slog.Handler that writes one
// compact line per record: "LEVEL msg key=val key=val". It spawns no
// goroutines and, by default, omits the timestamp — which is the right
// choice on bare-metal tamago where there is no wall clock early in boot and
// the UART is the console. It is fully portable (identical on host and
// tamago); cmd/tamayo uses it for embedded-style output and the richer
// slog text/JSON handlers (New) for host services.
type ConsoleHandler struct {
	mu     *sync.Mutex
	out    io.Writer
	level  slog.Leveler
	time   bool   // include a timestamp
	prefix string // accumulated WithAttrs/WithGroup, pre-rendered
	groups string // current group path as a dotted key prefix
}

// ConsoleOptions configures a ConsoleHandler.
type ConsoleOptions struct {
	Level slog.Leveler // minimum level (default Info)
	Time  bool         // include RFC3339 timestamps (off by default)
}

// NewConsole builds a console logger writing to out.
func NewConsole(out io.Writer, opts ConsoleOptions) *slog.Logger {
	var lvl slog.Leveler = slog.LevelInfo
	if opts.Level != nil {
		lvl = opts.Level
	}
	return slog.New(&ConsoleHandler{mu: &sync.Mutex{}, out: out, level: lvl, time: opts.Time})
}

func (h *ConsoleHandler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= h.level.Level()
}

func (h *ConsoleHandler) Handle(_ context.Context, r slog.Record) error {
	var b []byte
	if h.time && !r.Time.IsZero() {
		b = r.Time.AppendFormat(b, "15:04:05.000 ")
	}
	b = append(b, levelString(r.Level)...)
	b = append(b, ' ')
	b = append(b, r.Message...)
	b = append(b, h.prefix...)
	r.Attrs(func(a slog.Attr) bool {
		b = appendAttr(b, h.groups, a)
		return true
	})
	b = append(b, '\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := h.out.Write(b)
	return err
}

func (h *ConsoleHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	nh := *h
	var b []byte
	for _, a := range attrs {
		b = appendAttr(b, h.groups, a)
	}
	nh.prefix = h.prefix + string(b)
	return &nh
}

func (h *ConsoleHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	nh := *h
	nh.groups = h.groups + name + "."
	return &nh
}

func levelString(l slog.Level) string {
	switch {
	case l < slog.LevelInfo:
		return "DBG"
	case l < slog.LevelWarn:
		return "INF"
	case l < slog.LevelError:
		return "WRN"
	default:
		return "ERR"
	}
}

func appendAttr(b []byte, group string, a slog.Attr) []byte {
	a.Value = a.Value.Resolve()
	if a.Equal(slog.Attr{}) {
		return b
	}
	if a.Value.Kind() == slog.KindGroup {
		gs := a.Value.Group()
		if len(gs) == 0 {
			return b
		}
		ng := group
		if a.Key != "" {
			ng = group + a.Key + "."
		}
		for _, ga := range gs {
			b = appendAttr(b, ng, ga)
		}
		return b
	}
	b = append(b, ' ')
	b = append(b, group...)
	b = append(b, a.Key...)
	b = append(b, '=')
	switch a.Value.Kind() {
	case slog.KindString:
		b = strconv.AppendQuote(b, a.Value.String())
	case slog.KindInt64:
		b = strconv.AppendInt(b, a.Value.Int64(), 10)
	case slog.KindUint64:
		b = strconv.AppendUint(b, a.Value.Uint64(), 10)
	case slog.KindBool:
		b = strconv.AppendBool(b, a.Value.Bool())
	default:
		b = strconv.AppendQuote(b, a.Value.String())
	}
	return b
}
