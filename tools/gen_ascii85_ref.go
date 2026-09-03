package ascii85_test

import (
	"bytes"
	"encoding/ascii85"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"testing"
)

// ascii85 decodes bytes somebody else produced — it is the encoding
// inside PDF streams and Adobe's toolchain — so its refusals are the
// half that matters, and they are unusually specific.
//
// The rules that are not guessable from "base85 of four bytes at a
// time":
//
//   * 'z' is a shorthand for four ZERO bytes, but ONLY at the start of
//     a group. In the middle of one it is a corrupt-input error, so a
//     decoder that treats it positionally is wrong in a way that only
//     shows on data it did not produce.
//   * 'y' is Adobe's shorthand for four SPACES and Go does NOT accept
//     it, which a port copying another implementation would.
//   * Whitespace is skipped ANYWHERE, including inside a group.
//   * A group of five characters must not exceed 2^32-1 when decoded,
//     and one that does is corrupt rather than wrapped.
//   * A trailing partial group is padded with 'u' and yields fewer
//     bytes; a partial group of exactly ONE character is invalid,
//     because no single character encodes any byte.
//   * Encode does NOT emit the <~ ~> delimiters Adobe uses. Go leaves
//     framing to the caller, and a decoder handed them fails.
func TestGoishRef(t *testing.T) {
	inputs := []struct{ name, data string }{
		{"empty", ""},
		{"one", "a"},
		{"two", "ab"},
		{"three", "abc"},
		{"four", "abcd"},
		{"five", "abcde"},
		{"eight", "abcdefgh"},
		{"zeros-4", "\x00\x00\x00\x00"},
		{"zeros-8", "\x00\x00\x00\x00\x00\x00\x00\x00"},
		{"zeros-partial", "\x00\x00"},
		{"spaces-4", "    "},
		{"high", "\xff\xff\xff\xff"},
		{"text", "the quick brown fox"},
		{"binary", "\x00\x01\x02\xfd\xfe\xff"},
		{"long", strings.Repeat("Man ", 20)},
	}
	for _, in := range inputs {
		dst := make([]byte, ascii85.MaxEncodedLen(len(in.data)))
		n := ascii85.Encode(dst, []byte(in.data))
		enc := string(dst[:n])
		fmt.Printf("enc %-14s maxlen=%-4d n=%-4d out=%q\n",
			in.name, ascii85.MaxEncodedLen(len(in.data)), n, enc)
		// Round trip through Decode.
		out := make([]byte, len(in.data)+16)
		ndst, nsrc, err := ascii85.Decode(out, []byte(enc), true)
		fmt.Printf("dec %-14s ndst=%-4d nsrc=%-4d same=%-5v err=%s\n",
			in.name, ndst, nsrc, string(out[:ndst]) == in.data, errText(err))
		// And through the streaming pair.
		var buf bytes.Buffer
		w := ascii85.NewEncoder(&buf)
		w.Write([]byte(in.data))
		w.Close()
		fmt.Printf("stream %-11s enc=%q same-as-Encode=%v\n",
			in.name, buf.String(), buf.String() == enc)
		rd, rerr := io.ReadAll(ascii85.NewDecoder(strings.NewReader(buf.String())))
		fmt.Printf("stream %-11s dec-same=%-5v err=%s\n",
			in.name, string(rd) == in.data, errText(rerr))
	}

	// Decoding what a hostile or foreign encoder might send.
	for _, c := range []struct{ name, enc string }{
		{"z-alone", "z"},
		{"z-twice", "zz"},
		{"z-then-group", "z87cURD]"},
		{"z-mid-group", "8z7cURD]"},
		{"y-alone", "y"},
		{"y-mid", "8y7cURD]"},
		{"space-between", "87cURD] i,pu"},
		{"space-inside", "87c URD]"},
		{"newline-inside", "87c\nURD]"},
		{"tab-inside", "87c\tURD]"},
		{"crlf-inside", "87c\r\nURD]"},
		{"adobe-delims", "<~87cURD]~>"},
		{"trailing-delim", "87cURD]~>"},
		{"one-char", "8"},
		{"two-chars", "87"},
		{"four-chars", "87cU"},
		{"overflow", "sssss"},
		{"just-under", "s8W-!"},
		{"below-range", "!!!!!"},
		{"invalid-char", "87c\x01RD]"},
		{"tilde-only", "~"},
		{"high-byte", "87c\xffD]"},
		{"empty", ""},
		{"all-spaces", "     "},
		{"null-byte", "\x00"},
	} {
		out := make([]byte, 64)
		ndst, nsrc, err := ascii85.Decode(out, []byte(c.enc), true)
		fmt.Printf("bad %-16s -> ndst=%-3d nsrc=%-3d out=%-12s err=%s\n",
			c.name, ndst, nsrc, hex.EncodeToString(out[:ndst]), errText(err))
		// The same input through the streaming reader, which frames
		// differently and can stop in a different place.
		rd, rerr := io.ReadAll(ascii85.NewDecoder(strings.NewReader(c.enc)))
		fmt.Printf("badr %-15s -> n=%-3d out=%-12s err=%s\n",
			c.name, len(rd), hex.EncodeToString(rd), errText(rerr))
	}

	// flush=false leaves a partial group for the next call, which is
	// how the streaming decoder is built and where an off-by-one lives.
	{
		enc := "87cURD]i,\"Ebo80"
		for _, n := range []int{0, 1, 4, 5, 6, 9, 10, len(enc)} {
			out := make([]byte, 64)
			ndst, nsrc, err := ascii85.Decode(out, []byte(enc[:n]), false)
			fmt.Printf("noflush %-3d -> ndst=%-3d nsrc=%-3d out=%-10s err=%s\n",
				n, ndst, nsrc, hex.EncodeToString(out[:ndst]), errText(err))
		}
	}
}

func errText(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}
