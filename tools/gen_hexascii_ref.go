package hex

import (
	"fmt"
	"testing"
)

func TestGoishRef(t *testing.T) {
	mk := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte((i*7 + 3) % 256)
		}
		return b
	}
	for _, n := range []int{0, 1, 7, 15, 16, 17, 31, 32, 33} {
		fmt.Printf("dump %-3d %q\n", n, Dump(mk(n)))
	}
	fmt.Printf("printable %q\n", Dump([]byte("Hello, world! ~\x7f\x00\x1f")))
	// Decode error shapes.
	for _, s := range []string{"", "0", "00", "0g", "g0", "0011", "001"} {
		b, err := DecodeString(s)
		fmt.Printf("dec %-6q %x err=%v\n", s, b, err)
	}
}
