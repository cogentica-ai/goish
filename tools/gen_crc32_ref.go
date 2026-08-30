package crc32

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
	ieee := MakeTable(IEEE)
	cast := MakeTable(Castagnoli)
	koop := MakeTable(Koopman)
	// Straddle slicing8Cutoff = 16 and the 8-byte inner loop.
	for _, n := range []int{0, 1, 8, 9, 15, 16, 17, 64, 1000} {
		p := mk(n)
		fmt.Printf("len=%-5d IEEE=%08x CAST=%08x KOOP=%08x\n",
			n, Checksum(p, ieee), Checksum(p, cast), Checksum(p, koop))
	}

	h := New(ieee)
	h.Write([]byte("hello world"))
	st, err := h.(encoding.BinaryMarshaler).MarshalBinary()
	fmt.Printf("ieee marshal err=%v state=%x sum=%08x\n", err, st, h.(hash.Hash32).Sum32())

	hc := New(cast)
	hc.Write([]byte("hello world"))
	stc, _ := hc.(encoding.BinaryMarshaler).MarshalBinary()
	fmt.Printf("cast marshal state=%x sum=%08x\n", stc, hc.(hash.Hash32).Sum32())

	h2 := New(ieee)
	if err := h2.(encoding.BinaryUnmarshaler).UnmarshalBinary(st); err != nil {
		t.Fatal(err)
	}
	h2.Write([]byte("!!"))
	h.Write([]byte("!!"))
	fmt.Printf("roundtrip resumed=%08x direct=%08x\n", h2.(hash.Hash32).Sum32(), h.(hash.Hash32).Sum32())

	h3 := New(cast)
	fmt.Printf("cross-table err=%v\n", h3.(encoding.BinaryUnmarshaler).UnmarshalBinary(st))
	bad := append([]byte(nil), st...)
	bad[0] = 'x'
	fmt.Printf("bad-magic err=%v\n", h3.(encoding.BinaryUnmarshaler).UnmarshalBinary(bad))
	fmt.Printf("bad-size  err=%v\n", h3.(encoding.BinaryUnmarshaler).UnmarshalBinary(st[:11]))

	h4 := NewIEEE()
	h4.Write([]byte("abc"))
	c, _ := h4.(hash.Cloner).Clone()
	h4.Write([]byte("def"))
	fmt.Printf("clone=%08x orig=%08x\n", c.(hash.Hash32).Sum32(), h4.(hash.Hash32).Sum32())

	fmt.Printf("tableSum(IEEE)=%08x tableSum(CAST)=%08x tableSum(KOOP)=%08x\n",
		tableSum(ieee), tableSum(cast), tableSum(koop))
	fmt.Printf("ChecksumIEEE(hello world)=%08x\n", ChecksumIEEE([]byte("hello world")))
}
