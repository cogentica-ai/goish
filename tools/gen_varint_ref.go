package binary

import (
	"bytes"
	"fmt"
	"io"
	"testing"
)

func TestGoishRef(t *testing.T) {
	us := []uint64{0, 1, 127, 128, 255, 256, 16383, 16384, 1 << 32, 1<<64 - 1}
	for _, u := range us {
		fmt.Printf("Uvarint %-20d enc=%x\n", u, AppendUvarint(nil, u))
	}
	is := []int64{0, 1, -1, 63, -64, 64, -65, 1 << 31, -(1 << 31), 1<<63 - 1, -1 << 63}
	for _, i := range is {
		fmt.Printf("Varint  %-21d enc=%x\n", i, AppendVarint(nil, i))
	}

	// Decode edge cases: truncated, overflowing, and the 11th-byte guard.
	cases := [][]byte{
		{},
		{0x80},
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02}, // 10th byte > 1
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}, // max
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}, // 11 bytes
	}
	for _, c := range cases {
		v, n := Uvarint(c)
		sv, sn := Varint(c)
		fmt.Printf("decode %-24x u=(%d,%d) s=(%d,%d)\n", c, v, n, sv, sn)
	}

	// ReadUvarint / ReadVarint error shapes.
	rd := func(b []byte) (uint64, string) {
		v, err := ReadUvarint(bytes.NewReader(b))
		if err == nil {
			return v, "<nil>"
		}
		if err == io.EOF {
			return v, "EOF"
		}
		if err == io.ErrUnexpectedEOF {
			return v, "ErrUnexpectedEOF"
		}
		return v, err.Error()
	}
	for _, b := range [][]byte{
		{}, {0x00}, {0x80}, {0xac, 0x02},
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01},
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02},
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01},
	} {
		v, e := rd(b)
		fmt.Printf("ReadUvarint %-24x v=%d err=%s\n", b, v, e)
	}
	v, err := ReadVarint(bytes.NewReader([]byte{0xac, 0x02}))
	fmt.Printf("ReadVarint ac02 v=%d err=%v\n", v, err)
	v2, err2 := ReadVarint(bytes.NewReader([]byte{0x80}))
	fmt.Printf("ReadVarint 80 v=%d err=%v\n", v2, err2)
}
