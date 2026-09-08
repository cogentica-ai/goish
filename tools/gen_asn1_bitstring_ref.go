package asn1_test

// Reference bytes for examples/asn1_bitstring_ref_smoke.rs.
//
// parseBitString is unexported, so this drives it through the exported
// Unmarshal into an asn1.BitString: tag 0x03 (BIT STRING), one length
// byte, then the payload whose FIRST byte is the padding-bit count.
//
// The rows that matter are the ones with a padding count above 7.
// Go rejects them with SyntaxError from the first clause of a
// short-circuiting ||, so it never evaluates the `1<<bytes[0]` in the
// third clause. A port that computes that mask eagerly shifts a u32 by
// 32 or more and panics in a debug build.

import (
	"encoding/asn1"
	"fmt"
	"testing"
)

func TestGoishRef(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte
	}{
		{"empty-contents", []byte{}},
		{"pad0-one-byte", []byte{0x00, 0xff}},
		{"pad1-clear", []byte{0x01, 0xfe}},
		{"pad1-set", []byte{0x01, 0xff}},
		{"pad7-clear", []byte{0x07, 0x80}},
		{"pad7-set", []byte{0x07, 0xff}},
		{"pad8", []byte{0x08, 0xff}},
		{"pad31", []byte{0x1f, 0xff}},
		{"pad32", []byte{0x20, 0xff}},
		{"pad33", []byte{0x21, 0xff}},
		{"pad64", []byte{0x40, 0xff}},
		{"pad255", []byte{0xff, 0xff}},
		{"pad-only-nonzero", []byte{0x01}},
		{"pad-only-zero", []byte{0x00}},
	}
	for _, c := range cases {
		der := append([]byte{0x03, byte(len(c.payload))}, c.payload...)
		var bs asn1.BitString
		_, err := asn1.Unmarshal(der, &bs)
		if err != nil {
			fmt.Printf("GOREF %s err=%s\n", c.name, err.Error())
			continue
		}
		fmt.Printf("GOREF %s ok bitlen=%d bytes=%x\n", c.name, bs.BitLength, bs.Bytes)
	}
}
