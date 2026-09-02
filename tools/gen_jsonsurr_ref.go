package json_test

import (
	"encoding/json"
	"fmt"
	"testing"
)

// Go's unquoteBytes never fails on a surrogate: an unpaired one becomes
// U+FFFD and the lookahead is not consumed, so whatever follows is read
// as itself. That matters because real-world JSON carries lone
// surrogates and Go accepts the whole document.
func TestGoishRef(t *testing.T) {
	for _, in := range []string{
		`"\uD800"`,           // lone high surrogate
		`"\uDC00"`,           // lone low surrogate
		`"\uD800\uD800"`,     // two highs
		`"😀"`,     // a valid pair: U+1F600
		`"a\uD800b"`,         // lone high with text either side
		`"\uD800x"`,          // lone high then a plain char
		`"A"`,           // plain BMP
		`"é"`,           // plain BMP, non-ASCII
		`"\uDC00\uD800"`,     // low then high — neither pairs
		`"\uD800A"`,     // high then a non-surrogate escape
	} {
		var v string
		err := json.Unmarshal([]byte(in), &v)
		if err != nil {
			fmt.Printf("%-20s err=%v\n", in, err)
			continue
		}
		fmt.Printf("%-20s ok bytes=%v\n", in, []byte(v))
	}
}
