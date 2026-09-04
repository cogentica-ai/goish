package flate_test

import (
	"bytes"
	"compress/flate"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"testing"
)

// compress/flate is a decompressor fed by whoever produced the stream,
// which for anything that accepts gzip means the far end of a
// connection. Its refusals matter for the same reason a parser's do,
// and one of them is unusual: a stream can be well-formed for a while
// and then wrong, so the reader has to fail PART WAY THROUGH and say
// how far it got.
//
// The compressor half is measured too, byte for byte, because Go's
// flate is deterministic: the same input at the same level gives the
// same bytes. A port whose output merely "decompresses correctly" is
// not the same thing — it means every stored artifact differs, so
// anything that hashes or caches compressed output disagrees between
// the two.
//
// The stream bytes are printed as hex so the goish side inflates the
// SAME bytes rather than bytes its own compressor produced.
func TestGoishRef(t *testing.T) {
	inputs := []struct {
		name string
		data string
	}{
		{"empty", ""},
		{"one-byte", "a"},
		{"repeat", strings.Repeat("ab", 100)},
		{"text", "the quick brown fox jumps over the lazy dog"},
		{"incompressible", "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b"},
		{"long-run", strings.Repeat("x", 300)},
		{"binary", string([]byte{0xff, 0xfe, 0x00, 0x01, 0xff, 0xfe, 0x00, 0x01})},
	}
	levels := []struct {
		name  string
		level int
	}{
		{"default", flate.DefaultCompression},
		{"none", flate.NoCompression},
		{"speed", flate.BestSpeed},
		{"best", flate.BestCompression},
		{"huffman", flate.HuffmanOnly},
	}
	for _, lv := range levels {
		for _, in := range inputs {
			var buf bytes.Buffer
			w, err := flate.NewWriter(&buf, lv.level)
			if err != nil {
				fmt.Printf("deflate %-8s %-15s -> newwriter-err=%q\n",
					lv.name, in.name, err.Error())
				continue
			}
			w.Write([]byte(in.data))
			w.Close()
			enc := buf.Bytes()
			fmt.Printf("deflate %-8s %-15s -> len=%-5d hex=%s\n",
				lv.name, in.name, len(enc), hex.EncodeToString(enc))
			// Round trip through the reader.
			out, rerr := io.ReadAll(flate.NewReader(bytes.NewReader(enc)))
			re := "<nil>"
			if rerr != nil {
				re = rerr.Error()
			}
			fmt.Printf("inflate %-8s %-15s -> same=%-5v err=%s\n",
				lv.name, in.name, string(out) == in.data, re)
		}
	}

	// Levels that must be refused.
	for _, l := range []int{-3, 10, 100} {
		_, err := flate.NewWriter(io.Discard, l)
		if err != nil {
			fmt.Printf("level %-5d -> err=%q\n", l, err.Error())
			continue
		}
		fmt.Printf("level %-5d -> ok\n", l)
	}

	// Malformed streams: where the reader stops and what it says.
	{
		var good bytes.Buffer
		w, _ := flate.NewWriter(&good, flate.DefaultCompression)
		w.Write([]byte(strings.Repeat("hello world ", 20)))
		w.Close()
		g := good.Bytes()
		for _, c := range []struct {
			name string
			data []byte
		}{
			{"empty", nil},
			{"one-byte", g[:1]},
			{"truncated-half", g[:len(g)/2]},
			{"truncated-last", g[:len(g)-1]},
			{"trailing-junk", append(append([]byte(nil), g...), 0xff, 0xff)},
			{"all-ff", bytes.Repeat([]byte{0xff}, 16)},
			{"all-zero", make([]byte, 16)},
			{"flipped-bit", flipAt(g, len(g)/2)},
		} {
			out, err := io.ReadAll(flate.NewReader(bytes.NewReader(c.data)))
			re := "<nil>"
			if err != nil {
				re = err.Error()
			}
			fmt.Printf("bad %-16s -> n=%-4d err=%s\n", c.name, len(out), re)
		}
		fmt.Printf("bad-source hex=%s\n", hex.EncodeToString(g))
	}

	// A stored (uncompressed) block, which NoCompression produces and
	// which a decompressor must handle without any Huffman tables.
	{
		var buf bytes.Buffer
		w, _ := flate.NewWriter(&buf, flate.NoCompression)
		w.Write([]byte("stored block contents"))
		w.Close()
		fmt.Printf("stored hex=%s\n", hex.EncodeToString(buf.Bytes()))
		out, err := io.ReadAll(flate.NewReader(bytes.NewReader(buf.Bytes())))
		re := "<nil>"
		if err != nil {
			re = err.Error()
		}
		fmt.Printf("stored out=%q err=%s\n", out, re)
	}
}

func flipAt(b []byte, i int) []byte {
	out := append([]byte(nil), b...)
	if i < len(out) {
		out[i] ^= 0x40
	}
	return out
}
