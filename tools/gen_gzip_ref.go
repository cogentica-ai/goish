package gzip

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

// The gzip header is ten bytes plus optional NUL-terminated name and
// comment and a length-prefixed extra field, and the trailer is CRC-32
// then length mod 2^32. All of it round-trips through a reader that
// makes the same mistakes, so these are Go's exact bytes.
func TestGoishRef(t *testing.T) {
	in := []byte("hello, hello, hello, gzip world")
	for _, lvl := range []int{0, 1, 6, 9, -2} {
		var buf bytes.Buffer
		w, _ := NewWriterLevel(&buf, lvl)
		w.Write(in)
		w.Close()
		fmt.Println("lvl", lvl, fmt.Sprintf("%x", buf.Bytes()))
	}
	// Header fields: name, comment, extra, mtime, OS.
	var buf bytes.Buffer
	w, _ := NewWriterLevel(&buf, 6)
	w.Name = "file.txt"
	w.Comment = "a comment"
	w.Extra = []byte{1, 2, 3}
	w.ModTime = time.Unix(1234567890, 0)
	w.OS = 3
	w.Write(in)
	w.Close()
	fmt.Println("hdr 0", fmt.Sprintf("%x", buf.Bytes()))
}
