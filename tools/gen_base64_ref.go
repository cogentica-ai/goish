package base64_test

import (
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"testing"
)

// base64 and base32 decode data that arrived from somewhere else —
// a URL, a cookie, a JWT, a PEM body — so what they REFUSE matters as
// much as what they accept, and Go says exactly where the input went
// wrong: CorruptInputError carries the byte OFFSET.
//
// The rules a plausible port gets wrong while every round trip still
// works:
//
//   * Padding is part of the encoding, not decoration. StdEncoding
//     REQUIRES it and refuses a short final quantum; RawStdEncoding
//     refuses it if present. The two are not interchangeable, and a
//     decoder that tolerates both accepts strings Go rejects.
//   * The non-strict decoders IGNORE \r and \n anywhere, including in
//     the middle of a quantum — that is what makes PEM work — but
//     ignore nothing else. Strict() additionally refuses a final
//     quantum whose unused trailing bits are not zero, which is the
//     canonicality check that stops two encodings of one value.
//   * The error OFFSET is the index of the offending byte, and for a
//     truncated input it is the length, which is a different answer
//     from "the last valid index".
//   * DecodedLen and EncodedLen differ between the padded and unpadded
//     encodings, and are exact, not upper bounds, for the padded ones.
func TestGoishRef(t *testing.T) {
	encs := []struct {
		name string
		e    *base64.Encoding
	}{
		{"std", base64.StdEncoding},
		{"url", base64.URLEncoding},
		{"rawstd", base64.RawStdEncoding},
		{"rawurl", base64.RawURLEncoding},
	}

	// 1. Encode: padding, and the URL alphabet's two different bytes.
	for _, e := range encs {
		for _, in := range []string{"", "f", "fo", "foo", "foob", "fooba", "foobar",
			"\xff\xef\xfe", "\x00\x00\x00", "sure."} {
			out := e.e.EncodeToString([]byte(in))
			fmt.Printf("enc %-7s %-9q -> %-14q elen=%d dlen=%d\n",
				e.name, in, out, e.e.EncodedLen(len(in)), e.e.DecodedLen(len(out)))
		}
	}

	// 2. Decode: the refusals, with their offsets.
	for _, e := range encs {
		for _, in := range []string{
			"Zg==", "Zm8=", "Zm9v", "Zg", "Zm8", "", "=", "==", "===",
			"Z", "Zm9vYg==", "Zg=Z", "Z===", "Zm9v!", "Zm 9v", "Zm\n9v",
			"Zm\r\n9v", "-_8=", "+/8=", "Zm9vYmFy",
		} {
			out, err := e.e.DecodeString(in)
			if err != nil {
				fmt.Printf("dec %-7s %-10q -> err=%q\n", e.name, in, err.Error())
				continue
			}
			fmt.Printf("dec %-7s %-10q -> %q\n", e.name, in, out)
		}
	}

	// 3. Strict(): the trailing-bits canonicality check.
	strict := base64.StdEncoding.Strict()
	for _, in := range []string{"Zg==", "Zh==", "Zm8=", "Zm9=", "Zm9v", "Zm\n9v"} {
		out, err := base64.StdEncoding.DecodeString(in)
		sout, serr := strict.DecodeString(in)
		fmt.Printf("strict %-8q -> lax=%-6q laxerr=%-28v strict=%-6q stricterr=%v\n",
			in, out, errText(err), sout, errText(serr))
	}

	// 4. A custom alphabet and a custom pad byte.
	{
		custom := base64.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
		fmt.Printf("custom enc=%q\n", custom.EncodeToString([]byte("\xff\xef\xfe")))
		withPad := base64.StdEncoding.WithPadding('.')
		fmt.Printf("withpad enc=%q\n", withPad.EncodeToString([]byte("f")))
		out, err := withPad.DecodeString("Zg..")
		fmt.Printf("withpad dec=%q err=%v\n", out, errText(err))
		nopad := base64.StdEncoding.WithPadding(base64.NoPadding)
		fmt.Printf("nopad enc=%q\n", nopad.EncodeToString([]byte("f")))
	}

	// 5. Lengths across the quantum boundaries.
	for _, n := range []int{0, 1, 2, 3, 4, 5, 6, 7, 8} {
		fmt.Printf("len n=%d std-enc=%d std-dec=%d raw-enc=%d raw-dec=%d\n", n,
			base64.StdEncoding.EncodedLen(n), base64.StdEncoding.DecodedLen(n),
			base64.RawStdEncoding.EncodedLen(n), base64.RawStdEncoding.DecodedLen(n))
	}

	// 6. base32, which has the same shape and a longer quantum.
	b32 := []struct {
		name string
		e    *base32.Encoding
	}{
		{"std", base32.StdEncoding},
		{"hex", base32.HexEncoding},
		{"rawstd", base32.StdEncoding.WithPadding(base32.NoPadding)},
	}
	for _, e := range b32 {
		for _, in := range []string{"", "f", "fo", "foo", "foob", "fooba", "foobar"} {
			out := e.e.EncodeToString([]byte(in))
			fmt.Printf("b32enc %-7s %-8q -> %-16q elen=%d\n",
				e.name, in, out, e.e.EncodedLen(len(in)))
		}
	}
	for _, e := range b32 {
		for _, in := range []string{
			"MY======", "MZXQ====", "MZXW6===", "MY", "MZXQ", "", "=",
			"MY=====", "MZXW6YTB", "MY======X", "M1======", "MZ\nXQ====",
		} {
			out, err := e.e.DecodeString(in)
			if err != nil {
				fmt.Printf("b32dec %-7s %-11q -> err=%q\n", e.name, in, err.Error())
				continue
			}
			fmt.Printf("b32dec %-7s %-11q -> %q\n", e.name, in, out)
		}
	}
}

func errText(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}
