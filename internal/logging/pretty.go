package logging

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ANSI colors
const (
	colReset  = "\x1b[0m"
	colGray   = "\x1b[90m"
	colRed    = "\x1b[31m"
	colGreen  = "\x1b[32m"
	colYellow = "\x1b[33m"
	colBlue   = "\x1b[34m"
)

// PrettyHandler is a minimal slog handler that prints human-friendly,
// colorized lines without key names for time/level/msg/source.
// Example:
//
//	12:34:56.789 INFO src/file.go:123 message k=v k2=v2
type PrettyHandler struct {
	mu     sync.Mutex
	w      io.Writer
	opts   slog.HandlerOptions
	attrs  []slog.Attr
	groups []string
}

// NewPrettyHandler constructs a PrettyHandler.
func NewPrettyHandler(w io.Writer, opts *slog.HandlerOptions) *PrettyHandler {
	if w == nil {
		w = os.Stderr
	}
	var o slog.HandlerOptions
	if opts != nil {
		o = *opts
	}
	return &PrettyHandler{w: w, opts: o}
}

func (h *PrettyHandler) Enabled(_ context.Context, level slog.Level) bool {
	// Respect configured level if provided.
	if h.opts.Level != nil {
		return level >= h.opts.Level.Level()
	}
	return true
}

func (h *PrettyHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	var buf bytes.Buffer

	// time (gray)
	ts := r.Time
	if ts.IsZero() {
		ts = time.Now()
	}
	buf.WriteString(colGray)
	buf.WriteString(ts.Local().Format("15:04:05.000"))
	buf.WriteString(colReset)
	buf.WriteByte(' ')

	// level (colored)
	lvlColor := colorForLevel(r.Level)
	buf.WriteString(lvlColor)
	buf.WriteString(strings.ToUpper(r.Level.String()))
	buf.WriteString(colReset)
	buf.WriteByte(' ')

	// source (trim to last 25 chars)
	targetSize := 25
	if len(r.Level.String()) < 5 {
		targetSize = 26
	}
	src := ""
	if r.PC != 0 && h.opts.AddSource {
		frs := runtime.CallersFrames([]uintptr{r.PC})
		fr, _ := frs.Next()
		if fr.File != "" {
			src = fmt.Sprintf("%s:%d", fr.File, fr.Line)
		}
	}
	if src != "" {
		if len(src) > targetSize {
			src = src[len(src)-targetSize:]
		}
		buf.WriteString(colGray)
		buf.WriteString(src)
		buf.WriteString(colReset)
		buf.WriteByte(' ')
	}

	// message (no quotes)
	buf.WriteString(r.Message)

	// attributes (handler + record), flattened with group prefixes
	// handler-level attrs first
	var writeAttrs func(prefix string, as []slog.Attr)
	writeAttrs = func(prefix string, as []slog.Attr) {
		for _, a := range as {
			key := a.Key
			if prefix != "" {
				key = prefix + "." + key
			}
			val := a.Value
			// For groups, flatten one level deep
			if val.Kind() == slog.KindGroup {
				writeAttrs(key, val.Group())
				continue
			}
			buf.WriteByte(' ')
			buf.WriteString(key)
			buf.WriteByte('=')
			buf.WriteString(fmt.Sprint(val))
		}
	}
	prefix := strings.Join(h.groups, ".")
	writeAttrs(prefix, h.attrs)
	r.Attrs(func(a slog.Attr) bool {
		writeAttrs(prefix, []slog.Attr{a})
		return true
	})

	buf.WriteByte('\n')
	_, err := h.w.Write(buf.Bytes())
	if err != nil {
		return fmt.Errorf("pretty handler write: %w", err)
	}
	return nil
}

func (h *PrettyHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	nh := &PrettyHandler{
		w:      h.w,
		opts:   h.opts,
		attrs:  append(append([]slog.Attr{}, h.attrs...), attrs...),
		groups: append([]string{}, h.groups...),
	}
	return nh
}

func (h *PrettyHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	nh := &PrettyHandler{
		w:      h.w,
		opts:   h.opts,
		attrs:  append([]slog.Attr{}, h.attrs...),
		groups: append(append([]string{}, h.groups...), name),
	}
	return nh
}

func colorForLevel(l slog.Level) string {
	switch {
	case l >= slog.LevelError:
		return colRed
	case l >= slog.LevelWarn:
		return colYellow
	case l >= slog.LevelInfo:
		return colGreen
	default:
		return colBlue
	}
}
