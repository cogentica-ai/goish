package ecdh_test

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"fmt"
	"testing"
)

// ECDH is where accepting a bad public key can leak the private one.
// The peer's key is the one input a caller does not control, so every
// rule about which byte strings are ACCEPTED is a rule about whether
// the shared secret means anything.
//
// The NIST curves and X25519 answer differently on purpose, and the
// difference is the interesting part:
//
//   * A NIST public key is a point, and NewPublicKey REJECTS anything
//     that is not on the curve — including the compressed and infinity
//     encodings, which Go does not accept at all. An implementation
//     that skipped the on-curve check could be fed a point on a weaker
//     twist and made to reveal the private scalar, one bit at a time.
//   * X25519 accepts ANY 32 bytes as a public key, because every
//     string is a valid u-coordinate. The check happens later:
//     ECDH refuses when the result is the all-zero point, which is
//     what a small-order input produces. The low-order points below
//     are the concrete inputs that trigger it.
//
// Keys come from fixed bytes rather than GenerateKey, so both sides
// compute the same secrets and the secrets themselves are compared,
// not merely their agreement.
func TestGoishRef(t *testing.T) {
	curves := []struct {
		name string
		c    ecdh.Curve
		size int
	}{
		{"P256", ecdh.P256(), 32},
		{"P384", ecdh.P384(), 48},
		{"P521", ecdh.P521(), 66},
		{"X25519", ecdh.X25519(), 32},
	}

	for _, cv := range curves {
		// Two private keys from fixed scalars.
		a := fixedScalar(cv.size, 0x11)
		b := fixedScalar(cv.size, 0x22)
		ka, err := cv.c.NewPrivateKey(a)
		if err != nil {
			fmt.Printf("%-6s privA-err=%q\n", cv.name, err.Error())
			continue
		}
		kb, err := cv.c.NewPrivateKey(b)
		if err != nil {
			fmt.Printf("%-6s privB-err=%q\n", cv.name, err.Error())
			continue
		}
		pa, pb := ka.PublicKey(), kb.PublicKey()
		fmt.Printf("%-6s pubA=%s\n", cv.name, hex.EncodeToString(pa.Bytes()))
		fmt.Printf("%-6s pubB=%s\n", cv.name, hex.EncodeToString(pb.Bytes()))
		s1, e1 := ka.ECDH(pb)
		s2, e2 := kb.ECDH(pa)
		fmt.Printf("%-6s shared=%s agree=%v e1=%s e2=%s\n", cv.name,
			hex.EncodeToString(s1), bytes.Equal(s1, s2), errText(e1), errText(e2))
		fmt.Printf("%-6s privBytes=%s pubEqual=%v selfEqual=%v\n", cv.name,
			hex.EncodeToString(ka.Bytes()), pa.Equal(pb), pa.Equal(pa))

		// Private keys that must be refused.
		for _, c := range []struct {
			name string
			key  []byte
		}{
			{"nil", nil},
			{"empty", []byte{}},
			{"short", a[:len(a)-1]},
			{"long", append(append([]byte(nil), a...), 0)},
			{"all-zero", make([]byte, cv.size)},
			{"all-ff", bytesRepeat(0xff, cv.size)},
			{"one", oneAt(cv.size)},
		} {
			_, err := cv.c.NewPrivateKey(c.key)
			fmt.Printf("%-6s priv %-10s -> err=%s\n", cv.name, c.name, errText(err))
		}

		// Public keys that must be refused — the on-curve question.
		pub := pa.Bytes()
		for _, c := range []struct {
			name string
			key  []byte
		}{
			{"nil", nil},
			{"empty", []byte{}},
			{"short", pub[:len(pub)-1]},
			{"long", append(append([]byte(nil), pub...), 0)},
			{"all-zero", make([]byte, len(pub))},
			{"all-ff", bytesRepeat(0xff, len(pub))},
			{"flip-first", flip(pub, 0)},
			{"flip-last", flip(pub, len(pub)-1)},
			{"infinity", []byte{0x00}},
			{"compressed", compressed(pub)},
			{"bad-prefix", withPrefix(pub, 0x05)},
		} {
			_, err := cv.c.NewPublicKey(c.key)
			fmt.Printf("%-6s pub  %-10s -> err=%s\n", cv.name, c.name, errText(err))
		}
	}

	// X25519's low-order points: accepted as keys, refused at ECDH,
	// which is where the check belongs for this curve.
	{
		x := ecdh.X25519()
		k, _ := x.NewPrivateKey(fixedScalar(32, 0x33))
		for _, c := range []struct{ name, hexs string }{
			{"zero", "0000000000000000000000000000000000000000000000000000000000000000"},
			{"one", "0100000000000000000000000000000000000000000000000000000000000000"},
			{"order-8-a", "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"},
			{"order-8-b", "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"},
			{"p-minus-1", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
			{"p", "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
			{"p-plus-1", "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"},
			{"high-bit-set", "00000000000000000000000000000000000000000000000000000000000000ff"},
		} {
			raw, _ := hex.DecodeString(c.hexs)
			p, err := x.NewPublicKey(raw)
			if err != nil {
				fmt.Printf("x25519 low %-14s -> newpub-err=%q\n", c.name, err.Error())
				continue
			}
			sh, err := k.ECDH(p)
			fmt.Printf("x25519 low %-14s -> shared=%-64s err=%s\n",
				c.name, hex.EncodeToString(sh), errText(err))
		}
	}

	// A key from one curve offered to another must not be accepted.
	{
		p256 := ecdh.P256()
		p384 := ecdh.P384()
		k256, _ := p256.NewPrivateKey(fixedScalar(32, 0x44))
		k384, _ := p384.NewPrivateKey(fixedScalar(48, 0x44))
		_, err := p384.NewPublicKey(k256.PublicKey().Bytes())
		fmt.Printf("cross p384-accepts-p256-pub err=%s\n", errText(err))
		_, err = k384.ECDH(k256.PublicKey())
		fmt.Printf("cross p384-ecdh-p256-pub err=%s\n", errText(err))
		x := ecdh.X25519()
		kx, _ := x.NewPrivateKey(fixedScalar(32, 0x44))
		_, err = kx.ECDH(k256.PublicKey())
		fmt.Printf("cross x25519-ecdh-p256-pub err=%s\n", errText(err))
		fmt.Printf("cross curve-names p256=%v p384=%v x25519=%v\n",
			p256.(fmt.Stringer) != nil, p384 != nil, x != nil)
	}
}

func fixedScalar(n int, b byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	// Keep it comfortably below any group order.
	out[0] = 0x01
	return out
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func oneAt(n int) []byte {
	out := make([]byte, n)
	out[n-1] = 1
	return out
}

func flip(b []byte, i int) []byte {
	out := append([]byte(nil), b...)
	out[i] ^= 0x01
	return out
}

func compressed(uncompressed []byte) []byte {
	if len(uncompressed) < 2 || uncompressed[0] != 0x04 {
		return []byte{0x02}
	}
	n := (len(uncompressed) - 1) / 2
	out := make([]byte, 1+n)
	out[0] = 0x02
	copy(out[1:], uncompressed[1:1+n])
	return out
}

func withPrefix(b []byte, p byte) []byte {
	out := append([]byte(nil), b...)
	if len(out) > 0 {
		out[0] = p
	}
	return out
}

func errText(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}
