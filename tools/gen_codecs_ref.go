package flate_test

import (
	"bytes"
	"compress/bzip2"
	"compress/lzw"
	"compress/zlib"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"testing"
)

// The three compress codecs that had smokes but had never been diffed:
// lzw, zlib and bzip2. All three decompress data somebody else
// produced, and each carries a rule the others do not:
//
//   * zlib wraps DEFLATE in a header AND an Adler-32 checksum, so
//     corruption IS detected — the opposite of raw flate, where a
//     flipped bit can decode to different bytes with no error at all.
//     The dictionary case is pinned too, because a stream compressed
//     with a dictionary is undecodable without it and Go says so with a
//     specific error.
//   * lzw's Order and litWidth are part of the format, not options: the
//     same bytes read LSB-first and MSB-first are different streams,
//     and a litWidth outside 2..8 is refused.
//   * bzip2 is decompress-only in Go, so the streams here come from the
//     system bzip2, which is the point: they are bytes this code did
//     not produce.
func TestGoishRef(t *testing.T) {
	inputs := []struct{ name, data string }{
		{"empty", ""},
		{"one", "a"},
		{"text", "the quick brown fox jumps over the lazy dog"},
		{"repeat", strings.Repeat("ab", 100)},
		{"binary", string([]byte{0, 1, 2, 0xfe, 0xff, 0, 1, 2})},
	}

	// 1. zlib: byte-for-byte output at each level, and the round trip.
	for _, lv := range []struct {
		name  string
		level int
	}{{"default", zlib.DefaultCompression}, {"none", zlib.NoCompression},
		{"speed", zlib.BestSpeed}, {"best", zlib.BestCompression}} {
		for _, in := range inputs {
			var buf bytes.Buffer
			w, err := zlib.NewWriterLevel(&buf, lv.level)
			if err != nil {
				fmt.Printf("zlib %-8s %-8s -> newwriter-err=%q\n", lv.name, in.name, err.Error())
				continue
			}
			w.Write([]byte(in.data))
			w.Close()
			enc := buf.Bytes()
			fmt.Printf("zlib %-8s %-8s -> len=%-4d hex=%s\n",
				lv.name, in.name, len(enc), hex.EncodeToString(enc))
			r, err := zlib.NewReader(bytes.NewReader(enc))
			if err != nil {
				fmt.Printf("zlibr %-8s %-8s -> newreader-err=%q\n", lv.name, in.name, err.Error())
				continue
			}
			out, rerr := io.ReadAll(r)
			fmt.Printf("zlibr %-8s %-8s -> same=%-5v err=%s\n",
				lv.name, in.name, string(out) == in.data, errText(rerr))
		}
	}

	// 2. zlib's checksum and header, which raw flate does not have.
	{
		var buf bytes.Buffer
		w := zlib.NewWriter(&buf)
		w.Write([]byte(strings.Repeat("checksummed ", 20)))
		w.Close()
		g := buf.Bytes()
		fmt.Printf("zlib-source hex=%s\n", hex.EncodeToString(g))
		for _, c := range []struct {
			name string
			data []byte
		}{
			{"empty", nil},
			{"header-only", g[:2]},
			{"bad-header", []byte{0x00, 0x00, 0x03, 0x00}},
			{"truncated", g[:len(g)-2]},
			{"corrupt-checksum", flipLast(g)},
			{"corrupt-body", flipAt(g, len(g)/2)},
			{"trailing-junk", append(append([]byte(nil), g...), 0xde, 0xad)},
		} {
			r, err := zlib.NewReader(bytes.NewReader(c.data))
			if err != nil {
				fmt.Printf("zlibbad %-17s -> newreader-err=%q\n", c.name, err.Error())
				continue
			}
			out, rerr := io.ReadAll(r)
			fmt.Printf("zlibbad %-17s -> n=%-4d err=%s\n", c.name, len(out), errText(rerr))
		}
	}

	// 3. zlib with a dictionary: undecodable without it.
	{
		dict := []byte("the quick brown fox")
		var buf bytes.Buffer
		w, _ := zlib.NewWriterLevelDict(&buf, zlib.DefaultCompression, dict)
		w.Write([]byte("the quick brown fox jumps"))
		w.Close()
		enc := buf.Bytes()
		fmt.Printf("zlibdict hex=%s\n", hex.EncodeToString(enc))
		_, err := zlib.NewReader(bytes.NewReader(enc))
		fmt.Printf("zlibdict no-dict-err=%s\n", errText(err))
		r, err := zlib.NewReaderDict(bytes.NewReader(enc), dict)
		if err != nil {
			fmt.Printf("zlibdict with-dict-err=%s\n", errText(err))
		} else {
			out, rerr := io.ReadAll(r)
			fmt.Printf("zlibdict out=%q err=%s\n", out, errText(rerr))
		}
	}

	// 4. lzw: the two orders and the litWidth range.
	for _, ord := range []struct {
		name string
		o    lzw.Order
	}{{"lsb", lzw.LSB}, {"msb", lzw.MSB}} {
		for _, in := range inputs {
			var buf bytes.Buffer
			w := lzw.NewWriter(&buf, ord.o, 8)
			w.Write([]byte(in.data))
			w.Close()
			enc := buf.Bytes()
			fmt.Printf("lzw %-4s %-8s -> len=%-4d hex=%s\n",
				ord.name, in.name, len(enc), hex.EncodeToString(enc))
			out, rerr := io.ReadAll(lzw.NewReader(bytes.NewReader(enc), ord.o, 8))
			fmt.Printf("lzwr %-4s %-8s -> same=%-5v err=%s\n",
				ord.name, in.name, string(out) == in.data, errText(rerr))
		}
	}
	// Reading an LSB stream as MSB: the format is part of the contract.
	{
		var buf bytes.Buffer
		w := lzw.NewWriter(&buf, lzw.LSB, 8)
		w.Write([]byte("mismatch me"))
		w.Close()
		out, err := io.ReadAll(lzw.NewReader(bytes.NewReader(buf.Bytes()), lzw.MSB, 8))
		fmt.Printf("lzw-mismatch n=%d err=%s\n", len(out), errText(err))
	}
	for _, lw := range []int{1, 2, 8, 9} {
		var buf bytes.Buffer
		out, err := io.ReadAll(lzw.NewReader(bytes.NewReader(buf.Bytes()), lzw.LSB, lw))
		fmt.Printf("lzw-litwidth %-2d -> n=%d err=%s\n", lw, len(out), errText(err))
	}

	// 5. bzip2: streams from the system bzip2, which this code did not
	//    produce — the whole point of a decompressor test.
	for _, c := range []struct{ name, hexs, want string }{
		{"hello", "425a6839314159265359579eb9560000069980400010001664d09020003100d0005541a01a6d17710e36c5e5e759252f3497c5dc914e142415e7ae5580",
			"hello bzip2 world hello bzip2 world"},
		{"empty", "425a683917724538509000000000", ""},
	} {
		data, _ := hex.DecodeString(c.hexs)
		out, err := io.ReadAll(bzip2.NewReader(bytes.NewReader(data)))
		fmt.Printf("bzip2 %-6s -> same=%-5v n=%-3d err=%s\n",
			c.name, string(out) == c.want, len(out), errText(err))
	}
	{
		data, _ := hex.DecodeString("425a6839314159265359579eb9560000069980400010001664d09020003100d0005541a01a6d17710e36c5e5e759252f3497c5dc914e142415e7ae5580")
		for _, c := range []struct {
			name string
			data []byte
		}{
			{"empty", nil},
			{"magic-only", data[:3]},
			{"bad-magic", []byte("XYZ98abcdefgh")},
			{"truncated", data[:len(data)/2]},
			{"corrupt-crc", flipLast(data)},
			{"trailing-junk", append(append([]byte(nil), data...), 0, 0)},
		} {
			out, err := io.ReadAll(bzip2.NewReader(bytes.NewReader(c.data)))
			fmt.Printf("bzip2bad %-14s -> n=%-3d err=%s\n", c.name, len(out), errText(err))
		}
	}
}

func flipAt(b []byte, i int) []byte {
	out := append([]byte(nil), b...)
	if i < len(out) {
		out[i] ^= 0x40
	}
	return out
}

func flipLast(b []byte) []byte {
	out := append([]byte(nil), b...)
	if len(out) > 0 {
		out[len(out)-1] ^= 0x01
	}
	return out
}

func errText(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}
