package regexp_test

import (
	"fmt"
	"regexp"
	"testing"
)

// The regexp package is one place where "compiles and returns something
// plausible" is indistinguishable from correct without a reference. The
// cases below are the ones a hand-written engine gets wrong: the
// leftmost-FIRST (not longest) rule Go inherits from Perl, the
// advance-by-one rule for empty matches in the FindAll/Split/ReplaceAll
// family, and $-expansion in a replacement template.
func TestGoishRef(t *testing.T) {
	type C struct{ pat, in string }
	cases := []C{
		{`a+`, "aaa"},
		{`a|ab`, "ab"},
		{`ab|a`, "ab"},
		{`a*`, "baaac"},
		{`a*`, ""},
		{`(a)(b)?`, "a"},
		{`(a+)(b+)?`, "aabbb"},
		{`\b\w+\b`, "hi there"},
		{`[^a]+`, "xxaxx"},
		{`(?i)AB`, "xxabxx"},
		{`^a`, "abc"},
		{`c$`, "abc"},
		{`(?m)^b`, "a\nb\nc"},
		{`(?s).+`, "a\nb"},
		{`(?P<w>\w+)@(?P<d>\w+)`, "me@host"},
		{`x*`, "abc"},
		{`\d+`, "a12b345"},
		{`.`, "héllo"},
		{`日+`, "a日日b"},
		{`(|a)`, "aa"},
	}
	for _, c := range cases {
		re, err := regexp.Compile(c.pat)
		if err != nil {
			fmt.Printf("compile %-24q err=%v\n", c.pat, err)
			continue
		}
		fmt.Printf("m   %-24q in=%-10q match=%v find=%q idx=%v sub=%q\n",
			c.pat, c.in, re.MatchString(c.in), re.FindString(c.in),
			re.FindStringIndex(c.in), re.FindStringSubmatch(c.in))
		fmt.Printf("all %-24q in=%-10q n=-1 %q idx=%v subs=%q\n",
			c.pat, c.in, re.FindAllString(c.in, -1),
			re.FindAllStringIndex(c.in, -1), re.FindAllStringSubmatch(c.in, -1))
		fmt.Printf("n   %-24q in=%-10q n=1 %q n=2 %q\n",
			c.pat, c.in, re.FindAllString(c.in, 1), re.FindAllString(c.in, 2))
		fmt.Printf("spl %-24q in=%-10q n=-1 %q n=2 %q\n",
			c.pat, c.in, re.Split(c.in, -1), re.Split(c.in, 2))
	}

	// $-expansion in a replacement template.
	type R struct{ pat, in, repl string }
	reps := []R{
		{`(a)(b)`, "ab", "$2$1"},
		{`(a)(b)`, "ab", "${2}${1}"},
		{`(a)(b)`, "ab", "$0!"},
		{`(a)(b)`, "ab", "$3"},
		{`(a)(b)`, "ab", "x$"},
		{`(a)(b)`, "ab", "$$"},
		{`(?P<x>a)(?P<y>b)`, "ab", "$y-$x"},
		{`(?P<x>a)(?P<y>b)`, "ab", "${y}${x}"},
		{`(a)`, "aa", "[$1]"},
		{`a*`, "bab", "-"},
		{`x*`, "abc", "-"},
		{`\d`, "a1b2", "<$0>"},
		{`(a)b`, "ab", "$1c"},
	}
	for _, r := range reps {
		re := regexp.MustCompile(r.pat)
		fmt.Printf("rep %-20q in=%-6q repl=%-10q -> %q lit=%q\n",
			r.pat, r.in, r.repl, re.ReplaceAllString(r.in, r.repl),
			re.ReplaceAllLiteralString(r.in, r.repl))
	}

	// Subexpression metadata.
	for _, p := range []string{`(a)(b)`, `(?P<x>a)(?P<y>b)`, `a`, `(a(b))`} {
		re := regexp.MustCompile(p)
		fmt.Printf("sub %-20q n=%d names=%q idx_y=%d str=%q\n",
			p, re.NumSubexp(), re.SubexpNames(), re.SubexpIndex("y"), re.String())
	}

	// QuoteMeta.
	for _, s := range []string{``, `a`, `a.b`, `+?*()[]{}^$|\`, `héllo`, "a\nb"} {
		fmt.Printf("quote %-16q -> %q\n", s, regexp.QuoteMeta(s))
	}

	// Compile errors.
	for _, p := range []string{`(`, `a**`, `[z-a]`, `(?P<>a)`, `\`, `a{2,1}`} {
		_, err := regexp.Compile(p)
		fmt.Printf("err %-10q %v\n", p, err)
	}
}
