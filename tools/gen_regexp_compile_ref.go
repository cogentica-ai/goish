package syntax

import (
	"fmt"
	"strconv"
	"testing"
)

var zzcpats = []string{
	"a", "ab", "abc", "a|b", "a|b|c", "(a)", "(a)(b)", "(?:a)",
	"a*", "a+", "a?", "a*?", "a+?", "a??",
	"a{2}", "a{2,3}", "a{2,}", "a{0,3}", "a{0,}", "a{1,}", "a{0}", "a{1}",
	"(a){2}", "(a){1,2}", "(a|b){2}",
	"(?:a+)+", "(?:a*)*", "(?:a?)?", "(?:a+)*", "(?:a*)+",
	"(a*)*", "(a*)+", "(a?)*",
	".", "(?s).", "^", "$", "(?m)^", "(?m)$", `\A`, `\z`, `\b`, `\B`,
	"[a-z]", "[^a-z]", "[ab]", "[a]", "(?i)a", "(?i)k", "(?i)[a-z]",
	"", "(?:)", "()",
	"abc|abd", "abc|abd|aef|bcx|bcy",
	"a(b|c)d", "(a|b)*c",
	`\d`, `\D`, `\s`, `\w`, "[[:alpha:]]",
	"x{2,5}", "x{3,}", "x{10}",
	"(?i)abc", "(?i)a|b",
	"a\nb", `\x{4e00}`, "\U0001F600",
	"(a)(b)(c)", "(?P<x>a)(?P<y>b)",
	"a**b",
	// rune() keeps FoldCase only when the rune HAS a fold orbit, and
	// InstRune1 is chosen only once it is gone. Both sides of that.
	"(?i)1", "(?i)_", "(?i)-", "(?i)[0-9]", "(?i)\\d", "(?i)aa", "(?i)ab",
	"(?i).", "(?i)[a]", "(?i)[k]", "(?i)\u017f", "(?i)\u212a", "(?i)\u00e9",
	"1", "[0-9]", "[a]", "[aa]",
	// star of a nullable body compiles as (f1+)?; of a non-nullable
	// body, as a bare loop. Several shapes of each.
	"(a|)*", "(|a)*", "((a)?)*", "(a{0,1})*", "(?:){0,}", "(a*b*)*",
	"(abc)*", "([a-z])*", "(\\b)*", "(^)*", "(?:a|b)*",
	// quest puts the body in Out when greedy and in Arg when not, and
	// leaves the OTHER as the hole. That swap is the whole of the
	// priority order, so every shape that reaches quest wants both.
	"(a|b)??", "[a-z]??", "(?:ab)??", "(a)??", "a{0,1}?", "a{2,3}?",
	"a{0,3}?", "(a|b)?", "[a-z]?", "(?:ab)?", "(a)?",
	"(a*)??", "(a+)??", "a*?b", "(?:a|b)*?", "(?:a|b)+?",
	"x{2,5}?", "x{3,}?",
}

func TestGoishRef(t *testing.T) {
	for i, pat := range zzcpats {
		re, err := Parse(pat, Perl)
		if err != nil {
			fmt.Printf("%3d %-22s parse-error %s\n", i, strconv.Quote(pat), strconv.Quote(err.Error()))
			continue
		}
		fmt.Printf("%3d %-22s parsed   %s\n", i, strconv.Quote(pat), strconv.Quote(re.String()))
		sre := re.Simplify()
		fmt.Printf("%3d %-22s simple   %s\n", i, strconv.Quote(pat), strconv.Quote(sre.String()))
		prog, err := Compile(sre)
		if err != nil {
			fmt.Printf("%3d %-22s compile-error %s\n", i, strconv.Quote(pat), strconv.Quote(err.Error()))
			continue
		}
		fmt.Printf("%3d %-22s numcap=%d start=%d ninst=%d\n", i, strconv.Quote(pat), prog.NumCap, prog.Start, len(prog.Inst))
		pre, complete := prog.Prefix()
		fmt.Printf("%3d %-22s prefix=%s complete=%v startcond=%d\n", i, strconv.Quote(pat), strconv.Quote(pre), complete, uint8(prog.StartCond()))
		fmt.Printf("%3d %-22s prog     %s\n", i, strconv.Quote(pat), strconv.Quote(prog.String()))
	}
}
