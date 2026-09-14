package syntax

import (
	"fmt"
	"strconv"
	"testing"
)

// The corpus: Go's own parse_test.go tables, plus the error cases.
var zzpats = []string{
	"a", "a.", "a.b", "ab", "a.b.c", "abc", "a|^", "a|b", "(a)", "(a)|b",
	"a*", "a+", "a?", "a{2}", "a{2,3}", "a{2,}", "a**", "a*+",
	"a|b|c", "a|b|c|d", "abc|abd", "abc|abd|aef|bcx|bcy",
	"(?i)a", "(?i)abc", "(?i)[a-z]", "(?i)K", "(?i)K",
	"(?s).", "(?m)^", "(?m)$", "^", "$", "\\A", "\\z", "\\b", "\\B",
	"[a-z]", "[^a-z]", "[a-]", "[-a]", "[]a]", "[a^]", "[[:alpha:]]",
	"[[:^alpha:]]", "[\\d]", "[\\D]", "[\\s\\w]", "\\d", "\\D", "\\s", "\\w", "\\W",
	"[a-b-c]", "[\\-]", "[a-c-e]",
	"(?:a)", "(?:a|b)", "(?P<name>a)", "(?<name>a)", "(?P<name>a)(?P<x>b)",
	"(?i:a)b", "(?i)a(?-i)b", "((a))", "(a)(b)",
	"x{0}", "x{0,}", "x{1,}", "x{1,2}", "x{1000}",
	"\\Qab+\\E", "\\Q\\E", "\\Qa", "\\.", "\\*", "\\x41", "\\x{4e00}",
	"\\101", "\\0", "\\012", "\\n", "\\t", "\\a", "\\f", "\\v", "\\r",
	// \pN and \pZ are NOT here: they need unicode.Categories, which
	// goish does not have. They are asserted as an explicit gap in the
	// smoke instead, with Go's answer recorded beside goish's.
	"\\p{Any}", "\\p{ASCII}", "(?i)\\p{ASCII}", "\\P{Any}",
	"", "()", "(?:)", "a**b", "|", "|a", "a|", "||",
	".*", ".+", "[^\\n]", "(?s)[^\\n]", "(?i)[k]",
	"a{2}{3}", "(a{2}){3}", "\\Qa{2}\\E",
	// Errors.
	"(", ")", "(a", "a)", "[", "[a", "[z-a]", "a{2,1}", "a{1001}",
	"\\", "\\q", "\\C", "\\x", "\\xg", "\\x{}", "\\x{110000}",
	"(?", "(?i", "(?P", "(?P<", "(?P<>a)", "(?P<a b>x)", "(?<>a)",
	"[[:nope:]]", "\\p{Nope}", "(?P<name>a", "*", "+", "?", "{1}",
	"a{2,1000000}", "((((((((((x{2}){2}){2}){2}){2}){2}){2}){2}){2}){2})",
	// parseInt refuses a leading zero, so `{01}` is not a repeat at all
	// and the braces are literal.
	"a{01}", "a{0,01}", "x{00}", "a{1,02}", "a{0}", "a{00,1}",
	// and clamps at 1e8 rather than wrapping.
	"a{99999999999}", "a{1,99999999999}", "a{100000000}", "a{999999999}",
	// Negated classes: the \n inserted under POSIX so the later
	// negation does the right thing.
	"[^a]", "[^-a]", "[^a-]", "[^\\d]", "[^[:alpha:]]", "[^\\n\\r]",
	"(?i)[^k]", "(?s)[^a]", "[a-z-]", "[^^]", "[^]a]",
	// A count long enough that an unclamped accumulator would OVERFLOW
	// rather than merely exceed 1000. Without parseInt's clamp this is
	// where a wrapped value could land back inside the limit and parse.
	"a{999999999999999999999999}", "a{1,999999999999999999999999}",
	"a{99999999999999999999999999999999}",
	// \p{^Name} == \P{Name} and \P{^Name} == \p{Name}: the caret
	// flips the sign a SECOND time.
	"\\p{^Any}", "\\P{^Any}", "\\p{^ASCII}", "\\P{^ASCII}",
	"(?i)\\p{^ASCII}", "\\p{}", "\\p{^}",
}

func TestGoishRef(t *testing.T) {
	for i, pat := range zzpats {
		for _, fl := range []struct {
			name string
			f    Flags
		}{{"perl", Perl}, {"posix", POSIX}, {"lit", Literal}} {
			re, err := Parse(pat, fl.f)
			if err != nil {
				fmt.Printf("%3d %-5s %-20s err=%s\n", i, fl.name, strconv.Quote(pat), strconv.Quote(err.Error()))
				continue
			}
			fmt.Printf("%3d %-5s %-20s %s | cap=%d\n", i, fl.name, strconv.Quote(pat),
				strconv.Quote(re.String()), re.MaxCap())
		}
	}
}
