package syntax

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// dump writes a node as an s-expression a generator can read back.
//   (op flags min max cap "name" [runes...] sub...)
func zzdump(b *strings.Builder, re *Regexp) {
	fmt.Fprintf(b, "(%d %d %d %d %d %s [", uint8(re.Op), uint16(re.Flags), re.Min, re.Max, re.Cap, strconv.Quote(re.Name))
	for i, r := range re.Rune {
		if i > 0 {
			b.WriteString(" ")
		}
		fmt.Fprintf(b, "%d", r)
	}
	b.WriteString("]")
	for _, s := range re.Sub {
		b.WriteString(" ")
		zzdump(b, s)
	}
	b.WriteString(")")
}

var pats = []struct {
	pat   string
	flags Flags
}{
	{"abc", Perl},
	{"a|b", Perl},
	{"(a)(b)", Perl},
	{"(?P<x>a)(?P<y>b)", Perl},
	{"a*", Perl}, {"a+?", Perl}, {"a??", Perl},
	{"a{2,5}", Perl}, {"a{2,}", Perl}, {"a{3}", Perl},
	{"(?i)abc", Perl}, {"(?i)k", Perl}, {"(?i)[a-z]", Perl},
	{"[a-z]", Perl}, {"[^a-z]", Perl}, {"[[:alpha:]]", Perl},
	{"[-a]", Perl}, {"[a-]", Perl}, {"[]a]", POSIX},
	{".", Perl}, {"(?s).", Perl}, {"(?m)^$", Perl}, {"^$", Perl},
	{`\A\z`, Perl}, {`\b\B`, Perl}, {"$", Perl},
	{"", Perl}, {"()", Perl}, {"(?:)", Perl},
	{"a(b|c)d", Perl}, {"(a|b)*", Perl}, {"(a+)+", Perl},
	{"\n\t\x07", Perl}, {`\x{4e00}`, Perl}, {`\.`, Perl},
	{"[\\x00-\\x{10FFFF}]", Perl},
	{"(?i)a|(?-i)b", Perl},
	{"(?i)(?:a(?-i)b)", Perl},
	{"[^\\n]", Perl},
	{"x{0,}", Perl}, {"x{1,}", Perl},
	{`\pL`, Perl}, {`\PL`, Perl},
	{"(a)|b", Perl},
	{"(?:ab)+", Perl},
	{"ab+", Perl},
	{`\Q+|*\E`, Perl},
	// Precedence: a quantifier binds to the node BELOW it, and
	// writeRegexp decides on `sub.Op > OpCapture`. Every Op either side
	// of that boundary, quantified, so the comparison is actually
	// tested rather than brushed past.
	{"(a)*", Perl}, {"(a)+", Perl}, {"(a)?", Perl}, {"(a){2,3}", Perl},
	{"(?P<n>a)*", Perl},
	{"a*", Perl}, {"ab*", Perl}, {"(ab)*", Perl}, {"[a]*", Perl},
	{"[ab]*", Perl}, {".*", Perl}, {"(?s).*", Perl},
	{"^*", POSIX}, {"(a|b)+", Perl}, {"(?:a|b)?", Perl},
	{"(ab|cd)*", Perl}, {"(a(b))*", Perl},
	{`\b*`, Perl}, {`\A*`, Perl}, {"$*", Perl},
	// Flag spans: calcFlags has to find each conflict and wrap only
	// the span that needs it.
	{"(?i)a(?-i)b(?i)c", Perl},
	{"(?s).(?-s).", Perl},
	{"(?m)^(?-m)^", Perl},
	{"(?i)(?s)a.b", Perl},
	{"(?i)abc(?-i)def", Perl},
	{"(?i)k(?-i)k", Perl},
	{"a(?i)b", Perl},
	{"(?i:a)b", Perl},
	{"(?i)(a(?-i)b)c", Perl},
	{"(?i)a|b|(?-i)c", Perl},
	{"(?im)^a$", Perl},
	{"(?i)[k]", Perl}, {"(?i)[kK]", Perl}, {"(?i)[a-zA-Z]", Perl},
	{`[\x{212A}]`, Perl},
	{"(?i)ſ", Perl},
	// The conflict test is `must&subCant || subMust&cant` — TWO halves,
	// and only the first fires when the must comes before the cant.
	// These put the cant first so the second half is tested too.
	{"k(?i)k", Perl},
	{".(?s).", Perl},
	{"$(?m)$", Perl},
	{"abc(?i)def", Perl},
	{"a(?i)b(?-i)c(?i)d", Perl},
	{"(?-s).(?s).(?-s).", Perl},
	{"k|(?i)k", Perl},
	{"(k)(?i)(k)", Perl},
}

func TestGoishRef(t *testing.T) {
	// ── Op.String, including out of range and the pseudo-op ─────────
	for _, i := range []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 127, 128, 129, 255} {
		fmt.Printf("Op.String %3d %s\n", i, strconv.Quote(Op(i).String()))
	}

	for n, p := range pats {
		re, err := Parse(p.pat, p.flags)
		if err != nil {
			fmt.Printf("Pat %2d %s parse-error %s\n", n, strconv.Quote(p.pat), strconv.Quote(err.Error()))
			continue
		}
		var b strings.Builder
		zzdump(&b, re)
		// TREE lines are consumed by the generator, not compared.
		fmt.Printf("TREE %2d %s\n", n, b.String())
		fmt.Printf("Pat %2d src %s\n", n, strconv.Quote(p.pat))
		fmt.Printf("Pat %2d String %s\n", n, strconv.Quote(re.String()))
		fmt.Printf("Pat %2d MaxCap %d\n", n, re.MaxCap())
		names := re.CapNames()
		qs := make([]string, len(names))
		for i, s := range names {
			qs[i] = strconv.Quote(s)
		}
		fmt.Printf("Pat %2d CapNames [%s]\n", n, strings.Join(qs, " "))
		fmt.Printf("Pat %2d Equal-self %v\n", n, re.Equal(re))
	}

	// ── Equal across pairs, including the flag-sensitive cases ──────
	type pair struct{ a, b string }
	pairs := []pair{
		{"abc", "abc"}, {"abc", "abd"},
		{"$", `\z`}, {`\z`, `\z`}, {"$", "$"},
		{"a*", "a*?"}, {"a*?", "a*?"},
		{"a{2,3}", "a{2,4}"}, {"a{2,3}", "a{2,3}"},
		{"(a)", "(a)"}, {"(?P<x>a)", "(?P<y>a)"}, {"(?P<x>a)", "(?P<x>a)"},
		{"(a)(b)", "(a)(b)"},
		{"[a-c]", "[a-c]"}, {"[a-c]", "[a-d]"},
		{"a|b", "a|b"}, {"a|b", "a|c"}, {"a|b", "a|b|c"},
		{"(?i)k", "k"},
	}
	for n, pp := range pairs {
		x, e1 := Parse(pp.a, Perl)
		y, e2 := Parse(pp.b, Perl)
		if e1 != nil || e2 != nil {
			fmt.Printf("Equal %2d error\n", n)
			continue
		}
		var bx, by strings.Builder
		zzdump(&bx, x)
		zzdump(&by, y)
		fmt.Printf("EQTREE %2d %s %s\n", n, bx.String(), by.String())
		fmt.Printf("Equal %2d %s %s %v\n", n, strconv.Quote(pp.a), strconv.Quote(pp.b), x.Equal(y))
	}
}
