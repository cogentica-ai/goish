package crc32_test

import (
	"encoding/hex"
	"fmt"
	"hash/adler32"
	"hash/crc32"
	"hash/fnv"
	"strings"
	"testing"
)

// A checksum has one job and no interesting behaviour except its
// VALUE. Every artifact that stores one — a gzip trailer, a zip
// directory, a zlib stream, a protocol frame — becomes unreadable to
// the other side if the two implementations disagree by a bit, and the
// failure surfaces as "corrupt data" a long way from the cause.
//
// So this is byte-for-byte, and the cases that separate a real
// implementation from a plausible one are the boundaries: the empty
// input (which is NOT zero for every algorithm), a single zero byte
// (which is different again), inputs that cross the table-lookup
// stride, and the incremental path where a hash is fed in pieces and
// must equal the one-shot answer.
//
// The three polynomials matter because only IEEE is exercised by
// gzip/zlib. Castagnoli and Koopman have no other user in the tree, so
// nothing else would notice if their tables were wrong.
func TestGoishRef(t *testing.T) {
	inputs := []struct{ name, data string }{
		{"empty", ""},
		{"zero-byte", "\x00"},
		{"one", "a"},
		{"abc", "abc"},
		{"check", "123456789"},
		{"eight", "abcdefgh"},
		{"fifteen", "abcdefghijklmno"},
		{"sixteen", "abcdefghijklmnop"},
		{"seventeen", "abcdefghijklmnopq"},
		{"thirtyone", strings.Repeat("x", 31)},
		{"thirtytwo", strings.Repeat("x", 32)},
		{"thirtythree", strings.Repeat("x", 33)},
		{"long", strings.Repeat("The quick brown fox. ", 50)},
		{"binary", "\x00\x01\x02\xfd\xfe\xff"},
		{"high-bytes", strings.Repeat("\xff", 64)},
	}

	tables := []struct {
		name string
		poly uint32
	}{
		{"IEEE", crc32.IEEE},
		{"Castagnoli", crc32.Castagnoli},
		{"Koopman", crc32.Koopman},
		{"custom-1", 0x00000001},
		{"custom-ffffffff", 0xffffffff},
	}

	for _, tb := range tables {
		tbl := crc32.MakeTable(tb.poly)
		for _, in := range inputs {
			sum := crc32.Checksum([]byte(in.data), tbl)
			fmt.Printf("crc32 %-12s %-12s -> %08x\n", tb.name, in.name, sum)
		}
		// Update from a non-zero seed, which is how a caller chains
		// across buffers.
		fmt.Printf("crc32 %-12s update-seeded -> %08x\n", tb.name,
			crc32.Update(0xdeadbeef, tbl, []byte("abc")))
	}

	// ChecksumIEEE and the streaming Hash32 must agree with each other
	// and with the table form.
	for _, in := range inputs {
		one := crc32.ChecksumIEEE([]byte(in.data))
		h := crc32.NewIEEE()
		h.Write([]byte(in.data))
		streamed := h.Sum32()
		// Fed one byte at a time.
		h2 := crc32.NewIEEE()
		for i := 0; i < len(in.data); i++ {
			h2.Write([]byte{in.data[i]})
		}
		fmt.Printf("ieee %-12s -> %08x stream=%v bytewise=%v size=%d blocksize=%d\n",
			in.name, one, streamed == one, h2.Sum32() == one, h.Size(), h.BlockSize())
	}

	// Sum appends to the given slice rather than replacing it — a
	// detail every hash shares and callers get wrong.
	{
		h := crc32.NewIEEE()
		h.Write([]byte("abc"))
		fmt.Printf("sum-append prefix=%s\n", hex.EncodeToString(h.Sum([]byte{0xaa, 0xbb})))
		h.Reset()
		fmt.Printf("after-reset=%08x\n", h.Sum32())
	}

	// adler32, whose empty value is 1 rather than 0 — the single most
	// commonly mis-ported constant in this family.
	for _, in := range inputs {
		one := adler32.Checksum([]byte(in.data))
		h := adler32.New()
		h.Write([]byte(in.data))
		fmt.Printf("adler32 %-12s -> %08x stream=%v size=%d\n",
			in.name, one, h.Sum32() == one, h.Size())
	}

	// fnv, all four widths, whose OFFSET BASIS is what an empty input
	// returns — not zero either.
	for _, in := range inputs {
		h32, h32a := fnv.New32(), fnv.New32a()
		h64, h64a := fnv.New64(), fnv.New64a()
		h32.Write([]byte(in.data))
		h32a.Write([]byte(in.data))
		h64.Write([]byte(in.data))
		h64a.Write([]byte(in.data))
		fmt.Printf("fnv %-12s -> 32=%08x 32a=%08x 64=%016x 64a=%016x\n",
			in.name, h32.Sum32(), h32a.Sum32(), h64.Sum64(), h64a.Sum64())
	}
	{
		h := fnv.New128()
		ha := fnv.New128a()
		h.Write([]byte("abc"))
		ha.Write([]byte("abc"))
		fmt.Printf("fnv128 abc -> %s / %s size=%d\n",
			hex.EncodeToString(h.Sum(nil)), hex.EncodeToString(ha.Sum(nil)), h.Size())
	}
}
