package adler32

import (
	"encoding"
	"fmt"
	"hash"
	"testing"
)

func TestGoishRef(t *testing.T) {
	mk := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte((i*7 + 3) % 251)
		}
		return b
	}
	// Straddle the nmax=5552 block boundary and the 4-byte unrolled step.
	for _, n := range []int{0, 1, 3, 4, 5, 5551, 5552, 5553, 11104, 11105} {
		fmt.Printf("len=%-6d adler=%08x\n", n, Checksum(mk(n)))
	}

	h := New()
	h.Write([]byte("hello world"))
	st, err := h.(encoding.BinaryMarshaler).MarshalBinary()
	fmt.Printf("marshal err=%v state=%x sum=%08x\n", err, st, h.(hash.Hash32).Sum32())

	h2 := New()
	if err := h2.(encoding.BinaryUnmarshaler).UnmarshalBinary(st); err != nil {
		t.Fatal(err)
	}
	h2.Write([]byte("!!"))
	h.Write([]byte("!!"))
	fmt.Printf("roundtrip resumed=%08x direct=%08x\n", h2.(hash.Hash32).Sum32(), h.(hash.Hash32).Sum32())

	h3 := New()
	bad := append([]byte(nil), st...)
	bad[0] = 'x'
	fmt.Printf("bad-magic err=%v\n", h3.(encoding.BinaryUnmarshaler).UnmarshalBinary(bad))
	fmt.Printf("bad-size  err=%v\n", h3.(encoding.BinaryUnmarshaler).UnmarshalBinary(st[:3]))
	fmt.Printf("bad-size2 err=%v\n", h3.(encoding.BinaryUnmarshaler).UnmarshalBinary(append(st, 0)))

	h4 := New()
	h4.Write([]byte("abc"))
	c, _ := h4.(hash.Cloner).Clone()
	h4.Write([]byte("def"))
	fmt.Printf("clone=%08x orig=%08x\n", c.(hash.Hash32).Sum32(), h4.(hash.Hash32).Sum32())
	fmt.Printf("blocksize=%d size=%d\n", h4.BlockSize(), h4.Size())
}
