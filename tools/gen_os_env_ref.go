package os_test

import (
	"fmt"
	"os"
	"testing"
)

// os.Expand's rules are shell rules, and they are not what a
// hand-written scanner guesses. `$` is a SPECIAL VARIABLE, so `$$`
// expands `mapping("$")` rather than escaping to a literal dollar;
// so are `*`, `#`, `@`, `!`, `?`, `-` and the digits. An unterminated
// `${` is eaten as bad syntax rather than treated as a name running
// to the end of the string.
func TestGoishRef(t *testing.T) {
	mapping := func(k string) string {
		switch k {
		case "FOO":
			return "<foo>"
		case "BAR":
			return "<bar>"
		case "FOO_BAR":
			return "<fb>"
		case "A_B_1":
			return "<ab1>"
		case "_":
			return "<us>"
		case "foo":
			return "<lower>"
		}
		return "<" + k + ">"
	}
	cases := []string{
		"",
		"no vars",
		"$",
		"$$",
		"$$$",
		"a$$b",
		"$FOO",
		"${FOO}",
		"$FOO bar",
		"${FOO}bar",
		"$FOO$BAR",
		"${FOO}${BAR}",
		"$UNSET",
		"${UNSET}",
		"${}",
		"${",
		"${FOO",
		"$}",
		"a${",
		"a${b",
		"x${FOO}y${",
		"$1",
		"$9",
		"$0",
		"$*",
		"$#",
		"$@",
		"$!",
		"$?",
		"$-",
		"${*}",
		"${#}",
		"${1}",
		"${-}",
		"$FOO_BAR",
		"$FOO-BAR",
		"$FOO.BAR",
		"$_",
		"${_}",
		"$ FOO",
		"a$",
		"$$FOO",
		"${FOO}}",
		"$${FOO}",
		"\\$FOO",
		"$foo",
		"${a b}",
		"${A_B_1}",
	}
	for i, c := range cases {
		fmt.Printf("expand %d %q %q\n", i, c, os.Expand(c, mapping))
	}

	// ExpandEnv over the real environment.
	os.Setenv("GOISH_T1", "v1")
	os.Unsetenv("GOISH_T2")
	fmt.Printf("env1 %q\n", os.ExpandEnv("a $GOISH_T1 b ${GOISH_T1} c $GOISH_T2 d"))
	v, ok := os.LookupEnv("GOISH_T1")
	fmt.Printf("lookup1 %q %v\n", v, ok)
	v, ok = os.LookupEnv("GOISH_T2")
	fmt.Printf("lookup2 %q %v\n", v, ok)
	fmt.Printf("getenv %q\n", os.Getenv("GOISH_T2"))
	os.Setenv("GOISH_T2", "")
	v, ok = os.LookupEnv("GOISH_T2")
	fmt.Printf("lookup3 %q %v\n", v, ok)
	fmt.Printf("seterr %v\n", os.Setenv("BAD=KEY", "x") != nil)
	fmt.Printf("seterr2 %v\n", os.Setenv("", "x") != nil)
}
