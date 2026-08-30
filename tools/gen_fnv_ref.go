package fnv

import (
	"encoding"
	"fmt"
	"hash"
	"testing"
)

func TestGoishRef(t *testing.T) {
	inputs := []string{"", "a", "ab", "abc", "hello world", "The quick brown fox jumps over the lazy dog"}
	for _, in := range inputs {
		h128, h128a := New128(), New128a()
		h128.Write([]byte(in))
		h128a.Write([]byte(in))
		fmt.Printf("in=%-45q 128=%x 128a=%x\n", in, h128.Sum(nil), h128a.Sum(nil))
	}

	news := []struct {
		name string
		h    hash.Hash
	}{
		{"32", New32()}, {"32a", New32a()},
		{"64", New64()}, {"64a", New64a()},
		{"128", New128()}, {"128a", New128a()},
	}
	for _, n := range news {
		n.h.Write([]byte("hello world"))
		st, err := n.h.(encoding.BinaryMarshaler).MarshalBinary()
		fmt.Printf("new%-5s marshal err=%v state=%x sum=%x size=%d blocksize=%d\n",
			n.name, err, st, n.h.Sum(nil), n.h.Size(), n.h.BlockSize())
	}

	// Round trip + rejections on sum128a.
	h := New128a()
	h.Write([]byte("hello world"))
	st, _ := h.(encoding.BinaryMarshaler).MarshalBinary()
	h2 := New128a()
	if err := h2.(encoding.BinaryUnmarshaler).UnmarshalBinary(st); err != nil {
		t.Fatal(err)
	}
	h2.Write([]byte("!!"))
	h.Write([]byte("!!"))
	fmt.Printf("roundtrip resumed=%x direct=%x\n", h2.Sum(nil), h.Sum(nil))

	h3 := New128a()
	bad := append([]byte(nil), st...)
	bad[3] = 0x09
	fmt.Printf("bad-magic err=%v\n", h3.(encoding.BinaryUnmarshaler).UnmarshalBinary(bad))
	fmt.Printf("bad-size  err=%v\n", h3.(encoding.BinaryUnmarshaler).UnmarshalBinary(st[:19]))
	// A 32-bit state fed to a 64-bit digest: wrong magic.
	h32 := New32()
	h32.Write([]byte("x"))
	st32, _ := h32.(encoding.BinaryMarshaler).MarshalBinary()
	h64 := New64()
	fmt.Printf("cross err=%v\n", h64.(encoding.BinaryUnmarshaler).UnmarshalBinary(st32))

	// Clone independence on every type.
	for _, n := range []struct {
		name string
		h    hash.Hash
	}{
		{"32", New32()}, {"32a", New32a()},
		{"64", New64()}, {"64a", New64a()},
		{"128", New128()}, {"128a", New128a()},
	} {
		n.h.Write([]byte("abc"))
		c, _ := n.h.(hash.Cloner).Clone()
		n.h.Write([]byte("def"))
		fmt.Printf("clone%-5s clone=%x orig=%x\n", n.name, c.Sum(nil), n.h.Sum(nil))
	}
}
