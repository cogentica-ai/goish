package slog

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"testing"
)

// The package-level functions are how slog is normally used, and they
// all go through one default Logger whose handler is NOT a TextHandler:
// it writes "LEVEL message key=value…" through the log package, so the
// log package's own prefix and flags apply. That is a different output
// shape from either built-in handler, and a port that wires the default
// to a TextHandler answers differently for every `slog.Info` call.
func TestGoishRef(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetFlags(0) // no timestamp, so the vectors are deterministic

	shot := func(tag string, f func()) {
		buf.Reset()
		f()
		fmt.Printf("%-22s %q\n", tag, buf.String())
	}

	shot("info", func() { Info("hello") })
	shot("info-attrs", func() { Info("hello", "k", "v", "n", 7) })
	shot("debug-default-off", func() { Debug("hidden") })
	shot("warn", func() { Warn("careful", "why", "reasons") })
	shot("error", func() { Error("bad", "err", fmt.Errorf("boom")) })
	shot("odd-args", func() { odd := []any{"dangling"}; Info("m", odd...) })
	shot("attr-arg", func() { Info("m", String("k", "v")) })
	shot("log-explicit", func() { Log(context.Background(), LevelWarn, "m", "k", "v") })
	shot("logattrs", func() { LogAttrs(context.Background(), LevelError, "m", String("k", "v")) })
	shot("context-variants", func() { InfoContext(context.Background(), "m", "k", "v") })
	shot("level-offset", func() { Log(context.Background(), LevelInfo+2, "m") })
	shot("group-attr", func() { Info("m", Group("g", String("a", "1"))) })
	shot("with", func() { With("svc", "api").Info("m", "k", "v") })

	// SetLogLoggerLevel changes what the DEFAULT handler lets through,
	// and returns the previous level.
	old := SetLogLoggerLevel(LevelDebug)
	fmt.Printf("setlevel old=%q\n", old.String())
	shot("debug-after-enable", func() { Debug("now visible", "k", "v") })
	old2 := SetLogLoggerLevel(old)
	fmt.Printf("setlevel back=%q\n", old2.String())
	shot("debug-off-again", func() { Debug("hidden again") })

	// Default().Enabled reflects it too.
	fmt.Printf("enabled debug=%v info=%v warn=%v\n",
		Default().Enabled(context.Background(), LevelDebug),
		Default().Enabled(context.Background(), LevelInfo),
		Default().Enabled(context.Background(), LevelWarn))

	// SetDefault swaps the logger the package functions use.
	var jbuf bytes.Buffer
	SetDefault(New(NewJSONHandler(&jbuf, &HandlerOptions{
		ReplaceAttr: func(g []string, a Attr) Attr {
			if len(g) == 0 && a.Key == TimeKey {
				return Attr{}
			}
			return a
		},
	})))
	jbuf.Reset()
	Info("through json", "k", "v")
	fmt.Printf("%-22s %q\n", "after-setdefault", jbuf.String())
}
