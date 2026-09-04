package crc64_test

import (
	"encoding/hex"
	"fmt"
	"hash/crc64"
	"hash/maphash"
	"strings"
	"testing"
)

// Two hashes with opposite contracts, which is why they are measured
// together.
//
// crc64 is a CHECKSUM: its value is the whole contract, it must be
// identical everywhere, and an artifact carrying one is unreadable if
// two implementations disagree by a bit. So it is pinned byte for byte,
// across both polynomials — ISO and ECMA are different tables and only
// one of them being right is a bug nothing else in the tree would
// catch, since crc64 has no other user here.
//
// maphash is the opposite: its value is deliberately NOT stable. Every
// process picks a random seed, so the same bytes hash differently
// between runs and a caller must never persist or transmit a value. A
// port whose maphash was stable across processes would look more useful
// and would be wrong — code would come to depend on it, and the
// hash-flooding resistance the random seed exists to provide would be
// gone.
//
// What CAN be pinned about maphash is therefore its INVARIANTS, and
// those are what this measures: the same seed gives the same answer,
// different seeds give different answers, and every way of feeding the
// same bytes agrees.
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
		{"long", strings.Repeat("The quick brown fox. ", 50)},
		{"binary", "\x00\x01\x02\xfd\xfe\xff"},
		{"high-bytes", strings.Repeat("\xff", 64)},
	}

	for _, tb := range []struct {
		name string
		poly uint64
	}{
		{"ISO", crc64.ISO},
		{"ECMA", crc64.ECMA},
		{"custom-1", 0x0000000000000001},
		{"custom-max", 0xffffffffffffffff},
	} {
		tbl := crc64.MakeTable(tb.poly)
		for _, in := range inputs {
			fmt.Printf("crc64 %-11s %-12s -> %016x\n",
				tb.name, in.name, crc64.Checksum([]byte(in.data), tbl))
		}
		fmt.Printf("crc64 %-11s update-seeded -> %016x\n", tb.name,
			crc64.Update(0xdeadbeefcafebabe, tbl, []byte("abc")))
	}

	// The streaming path must agree with the one-shot, including when
	// fed a byte at a time, and Sum appends.
	{
		tbl := crc64.MakeTable(crc64.ECMA)
		for _, in := range inputs {
			one := crc64.Checksum([]byte(in.data), tbl)
			h := crc64.New(tbl)
			h.Write([]byte(in.data))
			h2 := crc64.New(tbl)
			for i := 0; i < len(in.data); i++ {
				h2.Write([]byte{in.data[i]})
			}
			fmt.Printf("crc64r %-12s -> stream=%v bytewise=%v size=%d blocksize=%d\n",
				in.name, h.Sum64() == one, h2.Sum64() == one, h.Size(), h.BlockSize())
		}
		h := crc64.New(tbl)
		h.Write([]byte("abc"))
		fmt.Printf("crc64 sum-append=%s\n", hex.EncodeToString(h.Sum([]byte{0xaa})))
		h.Reset()
		fmt.Printf("crc64 after-reset=%016x\n", h.Sum64())
	}

	// maphash: invariants only, because the seed is random per process.
	{
		s1 := maphash.MakeSeed()
		s2 := maphash.MakeSeed()
		for _, in := range inputs {
			a := maphash.String(s1, in.data)
			b := maphash.String(s1, in.data)
			c := maphash.String(s2, in.data)
			d := maphash.Bytes(s1, []byte(in.data))
			fmt.Printf("maphash %-12s -> stable=%-5v seed-differs=%-5v bytes-eq-string=%v\n",
				in.name, a == b, a != c, a == d)
		}
		// The streaming Hash must agree with the one-shot for the same
		// seed, however the bytes are fed in.
		for _, in := range inputs {
			want := maphash.String(s1, in.data)
			var h maphash.Hash
			h.SetSeed(s1)
			h.WriteString(in.data)
			var h2 maphash.Hash
			h2.SetSeed(s1)
			for i := 0; i < len(in.data); i++ {
				h2.WriteByte(in.data[i])
			}
			var h3 maphash.Hash
			h3.SetSeed(s1)
			h3.Write([]byte(in.data))
			fmt.Printf("maphashr %-11s -> writestring=%-5v bytewise=%-5v write=%-5v size=%d\n",
				in.name, h.Sum64() == want, h2.Sum64() == want, h3.Sum64() == want, h.Size())
		}
		// A Hash with no seed set gets one of its own, and Reset keeps
		// it — so two Resets of the same Hash agree with each other and
		// not with a fresh one.
		var h maphash.Hash
		h.WriteString("abc")
		first := h.Sum64()
		h.Reset()
		h.WriteString("abc")
		second := h.Sum64()
		var other maphash.Hash
		other.WriteString("abc")
		fmt.Printf("maphash reset-stable=%v fresh-differs=%v seed-nonzero=%v\n",
			first == second, first != other.Sum64(), h.Seed() != maphash.Seed{})
		// Comparable is what a caller actually needs from a Seed.
		fmt.Printf("maphash seed-self-eq=%v seed-differs=%v\n", s1 == s1, s1 != s2)
	}
}
