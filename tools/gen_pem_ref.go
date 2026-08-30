package pem

import (
	"fmt"
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
	// Encode at lengths that straddle the 64-column line breaker: 48
	// base64 chars per 36 raw bytes, so 48/47/49 raw bytes land on,
	// just under and just over a line boundary.
	for _, n := range []int{0, 1, 47, 48, 49, 96, 100} {
		b := &Block{Type: "TEST", Bytes: mk(n)}
		out := EncodeToMemory(b)
		fmt.Printf("len=%-4d enc=%q\n", n, string(out))
	}

	// Headers: Proc-Type first, then sorted.
	b := &Block{
		Type:    "RSA PRIVATE KEY",
		Headers: map[string]string{"Zeta": "z", "Alpha": "a", "Proc-Type": "4,ENCRYPTED", "DEK-Info": "DES-EDE3-CBC,0102"},
		Bytes:   mk(10),
	}
	fmt.Printf("hdr=%q\n", string(EncodeToMemory(b)))

	// A colon in a key is rejected.
	bad := &Block{Type: "X", Headers: map[string]string{"a:b": "c"}, Bytes: nil}
	fmt.Printf("badhdr=%q nil=%v\n", string(EncodeToMemory(bad)), EncodeToMemory(bad) == nil)

	// Decode round trip, and the trailing-data case.
	enc := EncodeToMemory(&Block{Type: "TEST", Bytes: mk(50)})
	trailing := append(append([]byte("leading junk\n"), enc...), []byte("trailing junk\n")...)
	p, rest := Decode(trailing)
	fmt.Printf("decode type=%q bytes=%x rest=%q\n", p.Type, p.Bytes, string(rest))

	// Unterminated BEGIN before a good block.
	multi := []byte("-----BEGIN BOGUS-----\n" + string(enc))
	p2, _ := Decode(multi)
	fmt.Printf("skip-bogus type=%q len=%d\n", p2.Type, len(p2.Bytes))

	// Headers round trip.
	hb := EncodeToMemory(b)
	p3, _ := Decode(hb)
	fmt.Printf("hdr-decode type=%q proc=%q dek=%q alpha=%q n=%d\n",
		p3.Type, p3.Headers["Proc-Type"], p3.Headers["DEK-Info"], p3.Headers["Alpha"], len(p3.Headers))

	// No PEM at all.
	p4, rest4 := Decode([]byte("no pem here\n"))
	fmt.Printf("nopem nil=%v rest=%q\n", p4 == nil, string(rest4))
}
