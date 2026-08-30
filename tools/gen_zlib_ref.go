package zlib

import (
	"bytes"
	"fmt"
	"testing"
)

// The zlib header is two bytes plus an optional 4-byte dictionary id,
// and its FCHECK bits depend on the level. These are all of them.
func TestGoishRef(t *testing.T) {
	in := []byte("hello, hello, hello, zlib world")
	for _, lvl := range []int{0, 1, 6, 9, -2} {
		var buf bytes.Buffer
		w, _ := NewWriterLevel(&buf, lvl)
		w.Write(in)
		w.Close()
		fmt.Println("lvl", lvl, fmt.Sprintf("%x", buf.Bytes()))
	}
	dict := []byte("hello, zlib")
	for _, lvl := range []int{1, 6, 9} {
		var buf bytes.Buffer
		w, _ := NewWriterLevelDict(&buf, lvl, dict)
		w.Write(in)
		w.Close()
		fmt.Println("dict", lvl, fmt.Sprintf("%x", buf.Bytes()))
	}
}
