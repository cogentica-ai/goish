package flate

import (
	"bytes"
	"fmt"
	"testing"
)

// Streams chosen to drive dict_decoder.go's paths: dist < length (the
// overlapping run-length copy), a long single-byte run, a repeat that
// crosses the 32 KiB window so writeCopy's wrap branch runs, and a
// dictionary preload.
func TestGoishRef(t *testing.T) {
	mk := func(n int, f func(i int) byte) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = f(i)
		}
		return b
	}
	cases := []struct {
		name string
		in   []byte
	}{
		{"run1000", bytes.Repeat([]byte("a"), 1000)},
		{"ab5000", bytes.Repeat([]byte("ab"), 2500)},
		{"abc3", bytes.Repeat([]byte("abc"), 3)},
		{"period7", mk(40000, func(i int) byte { return byte('a' + i%7) })},
		{"window", append(bytes.Repeat([]byte("xyz"), 20000), bytes.Repeat([]byte("xyz"), 20000)...)},
		{"mixed", mk(70000, func(i int) byte { return byte((i * 7 % 251) & 0x7f) })},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		w, _ := NewWriter(&buf, 6)
		w.Write(c.in)
		w.Close()
		sum := 0
		for _, b := range c.in {
			sum = (sum*31 + int(b)) & 0xffffff
		}
		fmt.Printf("%-10s inlen=%-6d complen=%-6d sum=%06x comp=%x\n",
			c.name, len(c.in), buf.Len(), sum, buf.Bytes())
	}
}
