package hkdf_test

import (
	"crypto/hkdf"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"strings"
	"testing"
)

// A KDF has no interesting behaviour except its OUTPUT. Two
// implementations that both "derive a key" and disagree by one byte
// produce systems that cannot talk to each other, and the failure
// surfaces as a decryption error somewhere far away. So this is a
// byte-for-byte measurement, and the awkward inputs are the point:
// empty salts, empty info, zero-length and maximum-length outputs, and
// the boundary where Expand refuses.
//
// The rules that are not obvious from "it hashes things":
//
//   * An EMPTY salt is not the same as no salt in principle, but HKDF
//     defines it to be: Extract substitutes a string of HashLen zeros.
//     A port that skipped that step derives different keys from the
//     same inputs.
//   * Expand's output is capped at 255*HashLen, and one byte past it
//     is an ERROR rather than a truncated answer.
//   * Zero-length output is allowed and returns nothing, rather than
//     being treated as "give me the default".
//   * The one-shot Key() must equal Extract-then-Expand exactly.
func TestGoishRef(t *testing.T) {
	hashes := []struct {
		name string
		h    func() hash.Hash
		size int
	}{
		{"sha256", sha256.New, 32},
		{"sha512", sha512.New, 64},
		{"sha1", sha1.New, 20},
	}
	secrets := []struct{ name, val string }{
		{"empty", ""},
		{"short", "secret"},
		{"long", strings.Repeat("k", 200)},
		{"binary", "\x00\x01\xfe\xff"},
	}
	salts := []struct{ name, val string }{
		{"none", ""},
		{"short", "salt"},
		{"long", strings.Repeat("s", 100)},
	}
	infos := []struct{ name, val string }{
		{"none", ""},
		{"label", "goish reference"},
		{"binary", "\x00\xff"},
	}

	for _, hh := range hashes {
		for _, sec := range secrets {
			for _, salt := range salts {
				prk, err := hkdf.Extract(hh.h, []byte(sec.val), []byte(salt.val))
				if err != nil {
					fmt.Printf("extract %-6s %-6s %-5s -> err=%q\n",
						hh.name, sec.name, salt.name, err.Error())
					continue
				}
				fmt.Printf("extract %-6s %-6s %-5s -> prk=%s\n",
					hh.name, sec.name, salt.name, hex.EncodeToString(prk))
				for _, info := range infos {
					out, err := hkdf.Expand(hh.h, prk, info.val, hh.size)
					if err != nil {
						fmt.Printf("expand  %-6s %-6s %-5s %-5s -> err=%q\n",
							hh.name, sec.name, salt.name, info.name, err.Error())
						continue
					}
					fmt.Printf("expand  %-6s %-6s %-5s %-5s -> out=%s\n",
						hh.name, sec.name, salt.name, info.name, hex.EncodeToString(out))
					// The one-shot must agree with the two-step.
					k, kerr := hkdf.Key(hh.h, []byte(sec.val), []byte(salt.val), info.val, hh.size)
					fmt.Printf("key     %-6s %-6s %-5s %-5s -> same=%v err=%s\n",
						hh.name, sec.name, salt.name, info.name,
						hex.EncodeToString(k) == hex.EncodeToString(out), errText(kerr))
				}
			}
		}
	}

	// Output lengths, including the two boundaries.
	{
		prk, _ := hkdf.Extract(sha256.New, []byte("secret"), []byte("salt"))
		// A NEGATIVE length panics rather than erroring — it reaches
		// make([]byte, n) — so it is not measured here; goish cannot
		// recover a panic in-process to compare against.
		for _, n := range []int{0, 1, 31, 32, 33, 64, 255 * 32, 255*32 + 1} {
			out, err := hkdf.Expand(sha256.New, prk, "info", n)
			if err != nil {
				fmt.Printf("len %-8d -> err=%q\n", n, err.Error())
				continue
			}
			shown := hex.EncodeToString(out)
			if len(shown) > 64 {
				shown = shown[:64] + "…"
			}
			fmt.Printf("len %-8d -> n=%-6d out=%s\n", n, len(out), shown)
		}
	}

	// A PRK shorter than HashLen is refused: Expand's security rests on
	// the PRK being a full-length pseudorandom key.
	{
		for _, n := range []int{0, 1, 31, 32, 33, 64} {
			prk := []byte(strings.Repeat("p", n))
			out, err := hkdf.Expand(sha256.New, prk, "info", 32)
			if err != nil {
				fmt.Printf("prklen %-4d -> err=%q\n", n, err.Error())
				continue
			}
			fmt.Printf("prklen %-4d -> out=%s\n", n, hex.EncodeToString(out))
		}
	}

	// RFC 5869 test vectors, so this is anchored to the standard and
	// not merely to Go.
	{
		type vec struct{ name, ikm, salt, info string; n int }
		for _, v := range []vec{
			{"rfc-a1", "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
				"000102030405060708090a0b0c", "f0f1f2f3f4f5f6f7f8f9", 42},
			{"rfc-a2",
				"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
				"606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
				"b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
				82},
			{"rfc-a3", "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "", "", 42},
		} {
			ikm, _ := hex.DecodeString(v.ikm)
			salt, _ := hex.DecodeString(v.salt)
			info, _ := hex.DecodeString(v.info)
			prk, _ := hkdf.Extract(sha256.New, ikm, salt)
			okm, err := hkdf.Expand(sha256.New, prk, string(info), v.n)
			fmt.Printf("%s prk=%s\n", v.name, hex.EncodeToString(prk))
			fmt.Printf("%s okm=%s err=%s\n", v.name, hex.EncodeToString(okm), errText(err))
		}
	}
}

func errText(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}
