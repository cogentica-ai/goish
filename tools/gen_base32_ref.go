package base32

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
)

// The streaming halves are what this reference is for. `encoder` buffers
// five bytes at a time and only `Close` flushes the trailing quantum, so
// a Write split across quantum boundaries must still produce exactly the
// one-shot encoding. `decoder` is the harder side: it reads through
// `readEncodedData`, which turns a short read at EOF into
// `io.ErrUnexpectedEOF` — but only for a padded encoding.
func TestGoishRef(t *testing.T) {
	encs := []struct {
		name string
		e    *Encoding
	}{
		{"std", StdEncoding},
		{"hex", HexEncoding},
		{"rawstd", StdEncoding.WithPadding(NoPadding)},
		{"dot", StdEncoding.WithPadding('.')},
	}
	inputs := []string{"", "f", "fo", "foo", "foob", "fooba", "foobar", "\x00\xff\xfe\x01", "sure.~?"}

	for _, en := range encs {
		for _, in := range inputs {
			fmt.Printf("enc %-6s %-10q %q\n", en.name, in, en.e.EncodeToString([]byte(in)))
		}
	}

	// EncodedLen / DecodedLen across a quantum.
	for _, en := range encs {
		for n := 0; n <= 11; n++ {
			fmt.Printf("len %-6s n=%-2d enc=%d dec=%d\n", en.name, n, en.e.EncodedLen(n), en.e.DecodedLen(n))
		}
	}

	// Streaming encoder: one Write per byte, so every quantum boundary
	// is crossed mid-Write.
	for _, en := range encs {
		for _, in := range inputs {
			var buf bytes.Buffer
			w := NewEncoder(en.e, &buf)
			for i := 0; i < len(in); i++ {
				w.Write([]byte(in[i : i+1]))
			}
			w.Close()
			fmt.Printf("stream-enc %-6s %-10q %q\n", en.name, in, buf.String())
		}
	}

	// Streaming decoder, read into a small buffer so the outbuf
	// staging path is exercised.
	for _, en := range encs {
		for _, in := range inputs {
			s := en.e.EncodeToString([]byte(in))
			r := NewDecoder(en.e, strings.NewReader(s))
			out, err := io.ReadAll(r)
			fmt.Printf("stream-dec %-6s %-10q %q err=%v\n", en.name, in, string(out), err)
		}
	}

	// Decoder with newlines interleaved in the encoded text.
	{
		s := StdEncoding.EncodeToString([]byte("foobar"))
		var wrapped strings.Builder
		for i, c := range []byte(s) {
			if i > 0 && i%3 == 0 {
				wrapped.WriteString("\r\n")
			}
			wrapped.WriteByte(c)
		}
		r := NewDecoder(StdEncoding, strings.NewReader(wrapped.String()))
		out, err := io.ReadAll(r)
		fmt.Printf("stream-dec-nl %q -> %q err=%v\n", wrapped.String(), string(out), err)
	}

	// Truncated input: padded encodings must report ErrUnexpectedEOF.
	for _, tc := range []string{"MZXW6YTBOI=====", "MZX", "MZXW6YTB"} {
		r := NewDecoder(StdEncoding, strings.NewReader(tc))
		out, err := io.ReadAll(r)
		fmt.Printf("trunc %-18q -> %q err=%v\n", tc, string(out), err)
	}

	// Corrupt input offsets.
	for _, tc := range []string{"M!XW6===", "MZXW6YTBOI======A", "MY=====", "MZX=====", "AAAAAAAA!"} {
		out, err := StdEncoding.DecodeString(tc)
		fmt.Printf("corrupt %-20q -> %q err=%v\n", tc, string(out), err)
	}

	// AppendEncode / AppendDecode keep the prefix.
	{
		got := StdEncoding.AppendEncode([]byte("PRE:"), []byte("foobar"))
		fmt.Printf("append-enc %q\n", string(got))
		dec, err := StdEncoding.AppendDecode([]byte("PRE:"), []byte("MZXW6YTBOI======"))
		fmt.Printf("append-dec %q err=%v\n", string(dec), err)
	}

	// CorruptInputError message text.
	fmt.Printf("errtext %q\n", CorruptInputError(7).Error())
}
