package crc64

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
	iso := MakeTable(ISO)
	ecma := MakeTable(ECMA)
	custom := MakeTable(0x000000000000001B)

	for _, n := range []int{0, 1, 63, 64, 100, 2047, 2048, 4096} {
		p := mk(n)
		fmt.Printf("len=%-5d ISO=%016x ECMA=%016x CUSTOM=%016x\n",
			n, Checksum(p, iso), Checksum(p, ecma), Checksum(p, custom))
	}

	h := New(ecma)
	h.Write([]byte("hello world"))
	st, err := h.(encoding.BinaryMarshaler).MarshalBinary()
	fmt.Printf("ecma marshal err=%v state=%x\n", err, st)

	hi := New(iso)
	hi.Write([]byte("hello world"))
	sti, _ := hi.(encoding.BinaryMarshaler).MarshalBinary()
	fmt.Printf("iso  marshal state=%x\n", sti)

	h2 := New(ecma)
	if err := h2.(encoding.BinaryUnmarshaler).UnmarshalBinary(st); err != nil {
		t.Fatal(err)
	}
	h2.Write([]byte("!!"))
	h.Write([]byte("!!"))
	fmt.Printf("roundtrip resumed=%016x direct=%016x\n", h2.(hash.Hash64).Sum64(), h.(hash.Hash64).Sum64())

	h3 := New(iso)
	fmt.Printf("cross-table err=%v\n", h3.(encoding.BinaryUnmarshaler).UnmarshalBinary(st))
	bad := append([]byte(nil), st...)
	bad[0] = 'x'
	fmt.Printf("bad-magic err=%v\n", h3.(encoding.BinaryUnmarshaler).UnmarshalBinary(bad))
	fmt.Printf("bad-size  err=%v\n", h3.(encoding.BinaryUnmarshaler).UnmarshalBinary(st[:19]))

	h4 := New(ecma)
	h4.Write([]byte("abc"))
	c, _ := h4.(hash.Cloner).Clone()
	h4.Write([]byte("def"))
	fmt.Printf("clone=%016x orig=%016x\n", c.(hash.Hash64).Sum64(), h4.(hash.Hash64).Sum64())

	fmt.Printf("tableSum(ISO)=%016x tableSum(ECMA)=%016x tableSum(custom)=%016x\n",
		tableSum(iso), tableSum(ecma), tableSum(custom))
	fmt.Printf("tableSum(nil)=%016x\n", tableSum(nil))
}
