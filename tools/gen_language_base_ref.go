// gen_language_base_ref — dump every base-language subtag that
// golang.org/x/text/language accepts, with its canonical form.
//
// x/text is NOT in GOROOT, so this cannot run under scripts/goref.sh.
// The recipe:
//
//	mkdir /tmp/xtextprobe && cd /tmp/xtextprobe
//	go mod init xtextprobe
//	go mod edit -require=golang.org/x/text@v0.38.0
//	cp <goish>/tools/gen_language_base_ref.go main.go
//	go mod tidy && go run main.go > /tmp/xtext_accepted.tsv
//	python3 <goish>/scripts/gen_language_tables.py /tmp/xtext_accepted.tsv
//
// The domain is exactly aa..zz and aaa..zzz: every key in goish's table
// is lowercase alpha of length 2 or 3, and x/text rejects a 1-letter or
// 4-or-more-letter first subtag before any table lookup.
//
// Measured with x/text v0.38.0: 190 two-letter and 8794 three-letter
// inputs are accepted, 314 of which canonicalise to something else.
package main

import (
	"bufio"
	"fmt"
	"os"

	"golang.org/x/text/language"
)

func main() {
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	emit := func(s string) {
		t, err := language.Parse(s)
		if err == nil {
			fmt.Fprintf(w, "%s\t%s\n", s, t)
		}
	}
	for a := 'a'; a <= 'z'; a++ {
		for b := 'a'; b <= 'z'; b++ {
			emit(string([]rune{a, b}))
			for c := 'a'; c <= 'z'; c++ {
				emit(string([]rune{a, b, c}))
			}
		}
	}
}
