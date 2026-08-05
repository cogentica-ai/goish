// gen_regexpfold_ref — reference generator for examples/regexpfold_ref.txt.
//
// Runs a corpus of `(?i)`-bearing patterns through the REAL Go regexp
// package and prints one row per (pattern, input) for MatchString and
// FindStringSubmatch, then a second corpus through the successive-match
// scan (FindAllString / FindAllStringIndex / FindAllStringSubmatch /
// Split) at several `n` values. examples/regexp_fold_diff.rs replays the same
// corpus against goish's engine and byte-compares.
//
// Regenerate:  go run tools/gen_regexpfold_ref.go > examples/regexpfold_ref.txt
//
// Every pattern here must stay inside the documented goish subset
// (no lookaround, no lazy quantifiers, no named groups) — the point is
// the `i` flag, not the parts of RE2 goish deliberately omits.
package main

import (
	"fmt"
	"regexp"
	"strings"
)

var patterns = []string{
	// The five patterns internal/semver actually compiles.
	`(?i)^(0|[1-9]\d*)(?:\.(0|[1-9]\d*)(?:\.(0|[1-9]\d*)(?:-([a-z0-9-.]+))?(?:\+([a-z0-9-.]+))?)?)?$`,
	`(?i)^(?:0|[1-9]\d*|[a-z-][a-z0-9-]*)(?:\.(?:0|[1-9]\d*|[a-zA-Z-][a-zA-Z0-9-]*))*$`,
	`(?i)^(?:0|[1-9]\d*|[a-z-][a-z0-9-]*)$`,
	`(?i)^[a-z0-9-]+(?:\.[a-z0-9-]+)*$`,
	`(?i)^[a-z0-9-]+$`,
	// Scope: the flag runs to the end of the ENCLOSING group and no
	// further. `b` folds, the trailing `c` does not.
	`^a(?i)b$`,
	`^(a(?i)b)c$`,
	`^(?:a(?i)b)c$`,
	// `(?i:...)` — group-local.
	`^a(?i:b)c$`,
	`^(?i:ab)c$`,
	// Turning it back off.
	`^(?i)a(?-i)b$`,
	`^(?i)(?-i:a)b$`,
	// Persistence across alternation branches within a group.
	`^(?i)ab|cd$`,
	`^((?i)ab|cd)$`,
	// Classes: plain, ranged, negated, and mixed with digits.
	`^(?i)[a-f]+$`,
	`^(?i)[^a-f]+$`,
	`^(?i)[a-fA-F0-9]+$`,
	`^(?i)[^0-9]$`,
	`^(?i)[z]$`,
	`^(?i)[a-]$`,
	// A range that straddles the letter runs, so the fold must clip.
	`^(?i)[Z-a]+$`,
	// Predefined classes are NOT folded by the flag.
	`^(?i)\w+$`,
	`^(?i)\d+$`,
	`^(?i)\W$`,
	// Escaped metas have no case; `\.` must stay a literal dot.
	// (Go rejects `\q` outright — an unknown-escape divergence goish
	// has independently of the `i` flag, so it is not swept here.)
	`^(?i)a\.b$`,
	// Non-letters are untouched.
	`^(?i)_-1$`,
	// Quantified folded atoms.
	`^(?i)a*b+c?$`,
	`^(?i)(ab)+$`,
	// The flag setter as the only content.
	`(?i)`,
	`^(?i)$`,
}

var inputs = []string{
	"", "a", "A", "b", "B", "ab", "aB", "Ab", "AB", "abc", "ABC", "aBc",
	"c", "C", "cd", "CD", "Cd", "z", "Z", "q", "Q", "_", "-", "_-1",
	"0", "9", "0.0.0", "1.2.3", "1.2.3-Alpha.1", "1.2.3-ALPHA.1+Build.5",
	"1.2.3+BUILD", "01", "1.2.3-", "abcdef", "ABCDEF", "aBcDeF", "gG",
	"abC", "aBC", "AbC", "abcD", "aBcD", "[", "]", "^", "a.b", "aXb", "a*b", "\\", "1", "12", "aab", "aaB",
}

func esc(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x21 && c < 0x7f && c != '\\' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, `\x%02x`, c)
		}
	}
	if b.Len() == 0 {
		return "-"
	}
	return b.String()
}

// The successive-match scan (Go's allMatches) has empty-match rules
// that a single-match sweep cannot reach at all: an empty match
// colliding with the previous match's end is DROPPED, and the scan
// steps one RUNE past an empty match. These patterns and inputs exist
// to hit exactly those, plus Split's own two special cases (n == 0,
// and an empty subject against a non-empty pattern).
var allPatterns = []string{
	`a*`, `a`, `,`, `\s+`, `\|\|`, `x*`, `(a)(b)?`, `(?i)a+`, `(?i)[a-c]`,
	// `.` is deliberately absent: Go's `.` matches one RUNE and
	// goish's matches one BYTE (documented in src/regexp/mod.rs), an
	// unrelated gap that would swamp this sweep on the UTF-8 inputs.
	`^`, `$`, ``,
}

var allInputs = []string{
	"", "a", "abaabaccadaaae", "a,b,,c", "  a  b ", "a||b||c", "a|b",
	",a,", ",,", "banana", "AaBbCc", "héllo", "日本語", "aé a",
}

var allCounts = []int{-1, 0, 1, 2, 3, 5}

func main() {
	for pi, p := range patterns {
		re := regexp.MustCompile(p)
		fmt.Printf("P %d %s\n", pi, esc(p))
		for ii, in := range inputs {
			fmt.Printf("M %d %d %v\n", pi, ii, re.MatchString(in))
			m := re.FindStringSubmatch(in)
			if m == nil {
				fmt.Printf("S %d %d nil\n", pi, ii)
				continue
			}
			parts := make([]string, len(m))
			for i, s := range m {
				parts[i] = esc(s)
			}
			fmt.Printf("S %d %d %d %s\n", pi, ii, len(m), strings.Join(parts, " "))
		}
	}

	for pi, p := range allPatterns {
		re := regexp.MustCompile(p)
		fmt.Printf("Q %d %s\n", pi, esc(p))
		for ii, in := range allInputs {
			for _, n := range allCounts {
				fmt.Printf("FA %d %d %d %s\n", pi, ii, n, qs(re.FindAllString(in, n)))
				fmt.Printf("FI %d %d %d %s\n", pi, ii, n, qi(re.FindAllStringIndex(in, n)))
				fmt.Printf("FS %d %d %d %s\n", pi, ii, n, qss(re.FindAllStringSubmatch(in, n)))
				fmt.Printf("SP %d %d %d %s\n", pi, ii, n, qs(re.Split(in, n)))
			}
		}
	}
}

// nil and empty are DIFFERENT here: Go returns nil for no matches and
// Split(s, 0) returns nil, while `[]string{}` can never occur — so a
// port that models nil as empty would still have to print "nil".
func qs(ss []string) string {
	if ss == nil {
		return "nil"
	}
	parts := make([]string, len(ss))
	for i, s := range ss {
		parts[i] = esc(s)
	}
	return "[" + strings.Join(parts, " ") + "]"
}

func qi(xs [][]int) string {
	if xs == nil {
		return "nil"
	}
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = fmt.Sprintf("%d:%d", x[0], x[1])
	}
	return "[" + strings.Join(parts, " ") + "]"
}

func qss(xs [][]string) string {
	if xs == nil {
		return "nil"
	}
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = qs(x)
	}
	return "[" + strings.Join(parts, " ") + "]"
}
