package base64

import (
	"fmt"
	"testing"
)

// The encodings differ only in alphabet and padding, and the decoder's
// awkward cases are all in decodeQuantum: embedded newlines, short or
// missing padding, trailing garbage, and strict mode's requirement that
// discarded low bits be zero.
func TestGoishRef(t *testing.T) {
	encs := []struct {
		name string
		e    *Encoding
	}{{"std", StdEncoding}, {"url", URLEncoding}, {"rawstd", RawStdEncoding}, {"rawurl", RawURLEncoding}}
	inputs := []string{"", "f", "fo", "foo", "foob", "fooba", "foobar", "\x00\xff\xfe\x01", "sure.~?"}
	for _, en := range encs {
		for _, in := range inputs {
			fmt.Printf("enc %-6s %-10q %q\n", en.name, in, en.e.EncodeToString([]byte(in)))
		}
	}
	// Custom alphabet + custom padding.
	c := NewEncoding("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_").WithPadding('@')
	fmt.Printf("custom %q\n", c.EncodeToString([]byte("foobar!")))
	d, err := c.DecodeString(c.EncodeToString([]byte("foobar!")))
	fmt.Printf("custom-rt %q err=%v\n", string(d), err)

	dec := []struct {
		name string
		e    *Encoding
		in   string
	}{
		{"std", StdEncoding, "Zm9vYmFy"},
		{"newlines", StdEncoding, "Zm9v\nYmFy\n"},
		{"crlf", StdEncoding, "Zm9v\r\nYmFy"},
		{"onepad", StdEncoding, "Zm9vYmE="},
		{"twopad", StdEncoding, "Zm9vYg=="},
		{"missingpad", StdEncoding, "Zm9vYg="},
		{"nopad-on-padded", StdEncoding, "Zm9vYg"},
		{"trailing", StdEncoding, "Zm9vYg==X"},
		{"badchar", StdEncoding, "Zm9v*mFy"},
		{"short", StdEncoding, "Z"},
		{"raw-ok", RawStdEncoding, "Zm9vYg"},
		{"raw-with-pad", RawStdEncoding, "Zm9vYg=="},
		{"nonzero-tail", StdEncoding, "aGk="},
		{"nonzero-tail2", StdEncoding, "aGl="},
	}
	for _, c := range dec {
		b, err := c.e.DecodeString(c.in)
		fmt.Printf("dec %-16s %-12q %x err=%v\n", c.name, c.in, b, err)
	}
	// Strict mode rejects non-zero padding bits.
	for _, in := range []string{"aGk=", "aGl="} {
		b, err := StdEncoding.Strict().DecodeString(in)
		fmt.Printf("strict %-6q %x err=%v\n", in, b, err)
	}
}
