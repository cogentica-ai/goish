package regexp_test

import (
	"fmt"
	"regexp"
	"testing"
)

// goish ships a hand-written backtracking matcher for a documented
// subset of RE2. This walks a corpus of patterns against a corpus of
// inputs and records exactly what Go does with each pair - including
// which patterns fail to COMPILE, which is half the contract.
func TestGoishRef(t *testing.T) {
	pats := []string{
		"a",
		"abc",
		"a|b",
		"a*",
		"a+",
		"a?",
		"a{2}",
		"a{2,}",
		"a{2,3}",
		"^abc$",
		"^a",
		"c$",
		".",
		"a.c",
		"a.*c",
		"[abc]",
		"[^abc]",
		"[a-z]",
		"[a-zA-Z0-9_]",
		"\\d",
		"\\D",
		"\\w",
		"\\W",
		"\\s",
		"\\S",
		"(a)(b)",
		"(?:ab)+",
		"(ab|cd)+",
		"(a+)(b+)",
		"(?i)abc",
		"(?i)[a-z]+",
		"a(?i:bc)",
		"(?i)ABC",
		"\\.",
		"\\\\",
		"\\$",
		"a\\|b",
		"^$",
		"",
		"x*",
		"(a*)*b",
		"[[:alpha:]]",
		"[[:digit:]]",
		"\\b",
		"\\bfoo\\b",
		"\\Bfoo",
		"(?s).",
		"(?m)^b",
		"a*?",
		"a+?",
		"(?P<x>a)",
		"foo(?=bar)",
		"[]]",
		"[^]]",
		"[a\\]b]",
		"[-a]",
		"[a-]",
		"\\p{L}",
		"\\pL",
		"\u65e5\u672c",
		"[\u3042-\u3093]",
		".\u3002",
		"(a)|(b)",
		"(|a)",
		"a{0}",
		"a{,3}",
		"\\x41",
		"\\101",
		"\\t",
		"\\n",
	}
	inputs := []string{
		"",
		"a",
		"abc",
		"ABC",
		"aaa",
		"aabbb",
		"xyz",
		"a\nb",
		"abcabc",
		"hello world",
		"foo bar",
		"foobar",
		"123",
		"a1b2",
		"_x9",
		"\u65e5\u672c\u8a9e",
		"a\u3042b",
		"a.c",
		"a|b",
		"a\\b",
		"  ",
		"\t\n",
		"]",
		"a]b",
		"-a",
		"A",
		"A",
		"b",
		"ab",
		"cd",
		"abcd",
	}
	for pi, p := range pats {
		re, err := regexp.Compile(p)
		if err != nil {
			fmt.Printf("compile %d ERR %q\n", pi, err.Error())
			continue
		}
		fmt.Printf("compile %d OK\n", pi)
		for si, s := range inputs {
			g := re.FindStringSubmatch(s)
			if g == nil {
				fmt.Printf("m %d %d nil\n", pi, si)
			} else {
				fmt.Printf("m %d %d %d", pi, si, len(g))
				for _, x := range g {
					fmt.Printf(" %q", x)
				}
				fmt.Printf("\n")
			}
		}
	}
	for pi, p := range pats {
		fmt.Printf("pat %d %q\n", pi, p)
	}
	for si, s := range inputs {
		fmt.Printf("in %d %q\n", si, s)
	}
}
