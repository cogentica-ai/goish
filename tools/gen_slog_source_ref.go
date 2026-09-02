package slog

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

// AddSource puts the call site in the output, and the two handlers
// render it differently: text flattens it to "file:line" while JSON
// nests it as an object with function/file/line. An EMPTY Source — the
// case where the Record has no PC — is elided entirely rather than
// printed as ":0" or "{}".
//
// The actual file and line differ between a Go build and a goish one,
// so ReplaceAttr substitutes a FIXED Source here. That leaves the
// handler's own conversion — the part being ported — as the only thing
// under test, and makes the expected bytes identical on both sides.
func TestGoishRef(t *testing.T) {
	fixed := time.Date(2024, 1, 2, 3, 4, 5, 123456789, time.UTC)

	pin := func(src *Source) *HandlerOptions {
		return &HandlerOptions{
			AddSource: true,
			ReplaceAttr: func(g []string, a Attr) Attr {
				if len(g) == 0 && a.Key == SourceKey {
					if src == nil {
						return Attr{}
					}
					a.Value = AnyValue(src)
				}
				return a
			},
		}
	}

	run := func(tag string, opts *HandlerOptions, r Record) {
		for _, kind := range []string{"text", "json"} {
			var buf bytes.Buffer
			var h Handler
			if kind == "text" {
				h = NewTextHandler(&buf, opts)
			} else {
				h = NewJSONHandler(&buf, opts)
			}
			_ = h.Handle(nil, r)
			fmt.Printf("%-18s %-4s %q\n", tag, kind, buf.String())
		}
	}

	rec := func(pc uintptr) Record {
		return NewRecord(fixed, LevelInfo, "m", pc)
	}

	run("full", pin(&Source{Function: "pkg.Fn", File: "a.go", Line: 42}), rec(1))
	run("no-function", pin(&Source{File: "a.go", Line: 42}), rec(1))
	run("file-only", pin(&Source{File: "a.go"}), rec(1))
	run("line-only", pin(&Source{Line: 42}), rec(1))
	run("empty-source", pin(&Source{}), rec(1))
	run("dropped", pin(nil), rec(1))

	// With AddSource on and a zero PC, Record.Source() is nil, Go
	// substitutes &Source{}, and the empty check elides it — so the
	// output carries no source key at all.
	run("zero-pc", &HandlerOptions{AddSource: true}, rec(0))

	// AddSource off: no source key even with a PC.
	run("addsource-off", &HandlerOptions{}, rec(1))
}
