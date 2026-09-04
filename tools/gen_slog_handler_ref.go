package slog

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

// The built-in handlers ARE slog's output. Everything about them is a
// formatting decision that a port either reproduces byte for byte or
// silently changes: which keys come first, when a key or value gets
// quoted, how groups become dotted prefixes in text and nested objects
// in JSON, that an EMPTY group is elided entirely, and what
// ReplaceAttr is allowed to see and rewrite.
//
// Every record below uses a fixed time so the output is deterministic.
func TestGoishRef(t *testing.T) {
	fixed := time.Date(2024, 1, 2, 3, 4, 5, 123456789, time.UTC)

	run := func(tag string, opts *HandlerOptions, mk func(h Handler) Handler, r Record) {
		for _, kind := range []string{"text", "json"} {
			var buf bytes.Buffer
			var h Handler
			if kind == "text" {
				h = NewTextHandler(&buf, opts)
			} else {
				h = NewJSONHandler(&buf, opts)
			}
			if mk != nil {
				h = mk(h)
			}
			if err := h.Handle(nil, r); err != nil {
				fmt.Printf("%-22s %-4s err=%v\n", tag, kind, err)
				continue
			}
			fmt.Printf("%-22s %-4s %q\n", tag, kind, buf.String())
		}
	}

	rec := func(msg string, level Level, attrs ...Attr) Record {
		r := NewRecord(fixed, level, msg, 0)
		r.AddAttrs(attrs...)
		return r
	}

	run("plain", nil, nil, rec("hello", LevelInfo))
	run("levels-warn", nil, nil, rec("m", LevelWarn))
	run("level-offset", nil, nil, rec("m", LevelInfo+2))
	run("attrs-basic", nil, nil, rec("m", LevelInfo,
		String("s", "v"), Int("n", 7), Bool("b", true)))
	run("attrs-float", nil, nil, rec("m", LevelInfo,
		Float64("f", 1.5), Float64("neg", -0.25)))
	run("attrs-dur-time", nil, nil, rec("m", LevelInfo,
		Duration("d", 1500*time.Millisecond), Time("t", fixed)))
	run("value-quoting", nil, nil, rec("m", LevelInfo,
		String("plain", "abc"), String("space", "a b"), String("empty", ""),
		String("quote", `he said "hi"`), String("eq", "a=b")))
	run("key-quoting", nil, nil, rec("m", LevelInfo,
		String("has space", "v"), String("has=eq", "v")))
	run("msg-quoting", nil, nil, rec("needs quoting", LevelInfo))
	run("newline", nil, nil, rec("m", LevelInfo, String("nl", "a\nb"), String("tab", "a\tb")))
	run("unicode", nil, nil, rec("m", LevelInfo, String("u", "Jörg"), String("emoji", "x")))
	run("nil-any", nil, nil, rec("m", LevelInfo, Any("a", nil)))
	run("err-any", nil, nil, rec("m", LevelInfo, Any("e", fmt.Errorf("boom"))))

	run("group-attr", nil, nil, rec("m", LevelInfo,
		Group("g", String("a", "1"), Int("b", 2))))
	run("group-empty", nil, nil, rec("m", LevelInfo, Group("g")))
	run("group-nested", nil, nil, rec("m", LevelInfo,
		Group("g", Group("h", String("a", "1")))))

	run("with-attrs", nil, func(h Handler) Handler {
		return h.WithAttrs([]Attr{String("svc", "api"), Int("v", 1)})
	}, rec("m", LevelInfo, String("k", "v")))

	run("with-group", nil, func(h Handler) Handler {
		return h.WithGroup("req")
	}, rec("m", LevelInfo, String("id", "7"), Int("n", 1)))

	run("with-group-attrs", nil, func(h Handler) Handler {
		return h.WithGroup("req").WithAttrs([]Attr{String("id", "7")})
	}, rec("m", LevelInfo, String("k", "v")))

	run("with-group-twice", nil, func(h Handler) Handler {
		return h.WithGroup("a").WithGroup("b")
	}, rec("m", LevelInfo, String("k", "v")))

	// A group with no attrs after it must be elided, even via WithGroup.
	run("with-group-none", nil, func(h Handler) Handler {
		return h.WithGroup("empty")
	}, rec("m", LevelInfo))

	run("opts-level-warn", &HandlerOptions{Level: LevelWarn}, nil, rec("m", LevelInfo))

	// ReplaceAttr sees the built-ins too, with an empty group path.
	dropTime := &HandlerOptions{ReplaceAttr: func(g []string, a Attr) Attr {
		if len(g) == 0 && a.Key == TimeKey {
			return Attr{}
		}
		return a
	}}
	run("replace-drop-time", dropTime, nil, rec("m", LevelInfo, String("k", "v")))

	upper := &HandlerOptions{ReplaceAttr: func(g []string, a Attr) Attr {
		if a.Key == "k" {
			a.Value = StringValue("REPLACED")
		}
		return a
	}}
	run("replace-value", upper, nil, rec("m", LevelInfo, String("k", "v")))

	rename := &HandlerOptions{ReplaceAttr: func(g []string, a Attr) Attr {
		if len(g) == 0 && a.Key == LevelKey {
			a.Key = "sev"
		}
		return a
	}}
	run("replace-level-key", rename, nil, rec("m", LevelInfo))

	// The group path ReplaceAttr receives inside a group.
	seeGroups := &HandlerOptions{ReplaceAttr: func(g []string, a Attr) Attr {
		if a.Key == "a" {
			a.Value = StringValue(fmt.Sprintf("groups=%v", g))
		}
		return a
	}}
	run("replace-sees-groups", seeGroups, nil, rec("m", LevelInfo,
		Group("g", String("a", "1"))))

	// Empty-key attrs are dropped; empty-value ones are not.
	run("empty-key", nil, nil, rec("m", LevelInfo, String("", "v"), String("k", "")))

	// An empty message still prints the key.
	run("empty-msg", nil, nil, rec("", LevelInfo))
}
