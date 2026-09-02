package slog

import (
	"fmt"
	"testing"
)

// slog.Level is an int whose String is NOT a lookup table: it renders
// the nearest named level plus a signed offset, so Level(1) is "INFO+1"
// and Level(-2) is "DEBUG+2" — not "INFO-3". ParseLevel reads that
// syntax back. A port that treats these as a fixed set of four names
// answers differently for every level a caller actually chooses, and
// silently, because the common levels all land on names.
func TestGoishRef(t *testing.T) {
	for _, l := range []Level{
		LevelDebug, LevelInfo, LevelWarn, LevelError,
		-8, -5, -4, -3, -1, 0, 1, 2, 3, 4, 5, 7, 8, 9, 12, 20, -20,
	} {
		txt, _ := l.MarshalText()
		js, _ := l.MarshalJSON()
		fmt.Printf("lvl %-5d str=%-10q text=%-10q json=%s\n", int(l), l.String(), string(txt), js)
	}

	for _, s := range []string{
		"DEBUG", "INFO", "WARN", "ERROR",
		"debug", "info", "warn", "error",
		"Debug", "INFO+2", "INFO-2", "DEBUG+3", "ERROR+4", "WARN-1",
		"INFO+0", "info+2", "", "NOPE", "INFO+", "INFO+x", "+2", "INFO++2",
	} {
		var l Level
		err := l.UnmarshalText([]byte(s))
		if err != nil {
			fmt.Printf("parse %-10q err=%v\n", s, err)
			continue
		}
		fmt.Printf("parse %-10q -> %d (%q)\n", s, int(l), l.String())
	}

	// LevelVar is a Leveler whose String is bracketed.
	var v LevelVar
	fmt.Printf("var  zero=%q level=%d\n", v.String(), int(v.Level()))
	v.Set(LevelWarn)
	txt, _ := v.MarshalText()
	fmt.Printf("var  warn=%q level=%d text=%q\n", v.String(), int(v.Level()), string(txt))
	if err := v.UnmarshalText([]byte("ERROR+2")); err != nil {
		fmt.Printf("var  unmarshal err=%v\n", err)
	} else {
		fmt.Printf("var  after=%q level=%d\n", v.String(), int(v.Level()))
	}
}
