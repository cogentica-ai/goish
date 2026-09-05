// Real Go 1.25.5 base64.Decode destination-state oracle.
// go run tools/gen_base64decode_ref.go > examples/base64decode_ref.txt
package main

import (
	"encoding/base64"
	"fmt"
)

func row(input string) {
	for _, extra := range []int{0, 1, 4, 9} {
		dst := make([]byte, base64.StdEncoding.DecodedLen(len(input))+extra)
		for i := range dst { dst[i] = byte(91+i) }
		n, err := base64.StdEncoding.Decode(dst, []byte(input))
		fmt.Printf("%d|%s|%d|%t|%x\n", len(dst), input, n, err == nil, dst)
	}
}

func main() {
	for n := 0; n <= 16; n++ {
		value := make([]byte, n)
		for i := range value { value[i] = byte(1+i*37) }
		input := base64.StdEncoding.EncodeToString(value)
		row(input)
		for i := range input { row(input[:i]+"!"+input[i+1:]) }
	}
	for _, input := range []string{"!", "AQ", "AQ==!", "ASZL!A==", "ASZL!!!!", "AQ===", "====", "A==="} { row(input) }
}
