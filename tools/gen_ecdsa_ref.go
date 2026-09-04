package ecdsa_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
)

// ECDSA verification is where a "does it round-trip" test is least
// informative: signing and verifying with the same code agrees with
// itself no matter what the rules are. What decides whether a caller is
// safe is which HOSTILE inputs come back false, and there are two
// distinct families of them — signatures that are well-formed DER but
// mathematically out of range, and byte strings that are not valid DER
// at all.
//
// The out-of-range family is the one that has produced real CVEs in
// other stacks: r or s equal to ZERO, or equal to or above the group
// order n. Those are trivially constructible and a verifier that
// forgets the range check can be talked into accepting them.
//
// The malleability answer is pinned deliberately in the other
// direction: for any valid (r, s), the pair (r, n-s) is ALSO valid, and
// Go accepts both. There is no low-S rule in ECDSA itself — that is a
// Bitcoin consensus rule layered on top — so a port that "helpfully"
// rejected high-S would reject signatures every Go peer produces about
// half the time. Anything that needs a unique signature per message
// must enforce that itself, above this layer.
//
// Signatures are not compared byte for byte: Go's nonce derivation is
// its own business and a port is not obliged to reproduce it. What IS
// compared is every verification decision, over signatures this test
// constructs itself.
func TestGoishRef(t *testing.T) {
	// A key with a FIXED D, so both sides hold the same key.
	curve := elliptic.P256()
	n := curve.Params().N
	d := new(big.Int)
	d.SetString("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", 16)
	d.Mod(d, n)
	priv := new(ecdsa.PrivateKey)
	priv.Curve = curve
	priv.D = d
	priv.X, priv.Y = curve.ScalarBaseMult(d.Bytes())
	pub := &priv.PublicKey
	fmt.Printf("key d=%s x=%s y=%s\n", d.Text(16), pub.X.Text(16), pub.Y.Text(16))
	fmt.Printf("key onCurve=%v bitsize=%d\n", curve.IsOnCurve(pub.X, pub.Y), curve.Params().BitSize)

	digest := sha256.Sum256([]byte("ecdsa reference message"))
	hash := digest[:]
	fmt.Printf("hash %s\n", hex.EncodeToString(hash))

	// One signature made here, used as the base for every mutation.
	sig, err := ecdsa.SignASN1(rand.Reader, priv, hash)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(sig, &parsed); err != nil {
		t.Fatal(err)
	}
	r, s := parsed.R, parsed.S
	fmt.Printf("roundtrip verify=%v r-in-range=%v s-in-range=%v\n",
		ecdsa.VerifyASN1(pub, hash, sig),
		r.Sign() > 0 && r.Cmp(n) < 0, s.Sign() > 0 && s.Cmp(n) < 0)

	mk := func(r, s *big.Int) []byte {
		b, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
		if err != nil {
			return nil
		}
		return b
	}

	// 1. The mathematically out-of-range family.
	zero := big.NewInt(0)
	one := big.NewInt(1)
	nMinusS := new(big.Int).Sub(n, s)
	for _, c := range []struct {
		name string
		r, s *big.Int
	}{
		{"valid", r, s},
		{"malleable-n-minus-s", r, nMinusS},
		{"r-zero", zero, s},
		{"s-zero", r, zero},
		{"both-zero", zero, zero},
		{"r-n", n, s},
		{"s-n", r, n},
		{"r-n-plus-1", new(big.Int).Add(n, one), s},
		{"s-n-plus-1", r, new(big.Int).Add(n, one)},
		{"r-negative", new(big.Int).Neg(r), s},
		{"s-negative", r, new(big.Int).Neg(s)},
		{"r-one", one, s},
		{"s-one", r, one},
		{"swapped", s, r},
		{"r-plus-n", new(big.Int).Add(r, n), s},
		{"s-plus-n", r, new(big.Int).Add(s, n)},
	} {
		b := mk(c.r, c.s)
		if b == nil {
			fmt.Printf("range %-20s -> marshal-failed\n", c.name)
			continue
		}
		fmt.Printf("range %-20s -> verify=%v\n", c.name, ecdsa.VerifyASN1(pub, hash, b))
	}

	// 2. The not-valid-DER family. A verifier must refuse these before
	//    it does any arithmetic, and refuse them as FALSE rather than
	//    by panicking on a hostile length.
	for _, c := range []struct {
		name string
		sig  []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"truncated-half", sig[:len(sig)/2]},
		{"truncated-last", sig[:len(sig)-1]},
		{"trailing-byte", append(append([]byte(nil), sig...), 0x00)},
		{"trailing-junk", append(append([]byte(nil), sig...), 0xde, 0xad)},
		{"wrong-outer-tag", retag(sig, 0x31)},
		{"raw-concat", append(padTo(r.Bytes(), 32), padTo(s.Bytes(), 32)...)},
		{"all-zero-70", make([]byte, 70)},
		{"just-sequence", []byte{0x30, 0x00}},
		{"one-integer", []byte{0x30, 0x03, 0x02, 0x01, 0x01}},
		{"three-integers", []byte{0x30, 0x09, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03}},
		{"indefinite-length", append([]byte{0x30, 0x80}, sig[2:]...)},
		{"non-minimal-length", nonMinimalLen(sig)},
	} {
		fmt.Printf("der %-20s -> verify=%v\n", c.name, ecdsa.VerifyASN1(pub, hash, c.sig))
	}

	// 3. The hash argument. A hash longer than the curve order is
	//    TRUNCATED rather than refused, and a shorter one is used as
	//    given — so two different messages can share a verification
	//    result if a caller passes the wrong digest length. Pinned so
	//    nobody has to guess which end is truncated.
	for _, c := range []struct {
		name string
		h    []byte
	}{
		{"exact-32", hash},
		{"short-16", hash[:16]},
		{"short-1", hash[:1]},
		{"empty", []byte{}},
		{"long-48", append(append([]byte(nil), hash...), hash[:16]...)},
		{"long-64", append(append([]byte(nil), hash...), hash...)},
		{"prefix-match-33", append(append([]byte(nil), hash...), 0x00)},
	} {
		fmt.Printf("hash %-14s -> verify=%v len=%d\n",
			c.name, ecdsa.VerifyASN1(pub, c.h, sig), len(c.h))
	}
	// A signature made over a TRUNCATED hash verifies against the full
	// hash when the truncation is on the right, which is the concrete
	// consequence of the rule above.
	{
		long := append(append([]byte(nil), hash...), 0xff)
		s2, err := ecdsa.SignASN1(rand.Reader, priv, long)
		if err != nil {
			fmt.Printf("trunc sign-err=%q\n", err.Error())
		} else {
			fmt.Printf("trunc long-sig-verifies-short=%v\n",
				ecdsa.VerifyASN1(pub, hash, s2))
		}
	}

	// 4. Wrong key: same signature, a different public key on the same
	//    curve, and a point that is not on the curve at all.
	{
		d2 := new(big.Int).Add(d, big.NewInt(1))
		p2 := new(ecdsa.PublicKey)
		p2.Curve = curve
		p2.X, p2.Y = curve.ScalarBaseMult(d2.Bytes())
		fmt.Printf("key wrong-key-verify=%v\n", ecdsa.VerifyASN1(p2, hash, sig))
		off := new(ecdsa.PublicKey)
		off.Curve = curve
		off.X = new(big.Int).Add(pub.X, one)
		off.Y = pub.Y
		fmt.Printf("key off-curve=%v off-curve-verify=%v\n",
			curve.IsOnCurve(off.X, off.Y), ecdsa.VerifyASN1(off, hash, sig))
	}

	// 5. Determinism is NOT expected: two signatures over the same
	//    message differ, and both verify.
	{
		a, _ := ecdsa.SignASN1(rand.Reader, priv, hash)
		b, _ := ecdsa.SignASN1(rand.Reader, priv, hash)
		fmt.Printf("nonce differ=%v both-verify=%v\n",
			hex.EncodeToString(a) != hex.EncodeToString(b),
			ecdsa.VerifyASN1(pub, hash, a) && ecdsa.VerifyASN1(pub, hash, b))
	}

	// 6. Every curve, so a port cannot be right on P-256 alone.
	for _, c := range []struct {
		name string
		crv  elliptic.Curve
	}{
		{"P224", elliptic.P224()}, {"P256", elliptic.P256()},
		{"P384", elliptic.P384()}, {"P521", elliptic.P521()},
	} {
		k, err := ecdsa.GenerateKey(c.crv, rand.Reader)
		if err != nil {
			fmt.Printf("curve %-5s -> genkey-err=%q\n", c.name, err.Error())
			continue
		}
		sg, err := ecdsa.SignASN1(rand.Reader, k, hash)
		if err != nil {
			fmt.Printf("curve %-5s -> sign-err=%q\n", c.name, err.Error())
			continue
		}
		bad := append(append([]byte(nil), sg...), 0x00)
		fmt.Printf("curve %-5s -> bits=%-3d verify=%v tampered=%v\n",
			c.name, c.crv.Params().BitSize, ecdsa.VerifyASN1(&k.PublicKey, hash, sg),
			ecdsa.VerifyASN1(&k.PublicKey, hash, bad))
	}
}

func retag(b []byte, tag byte) []byte {
	out := append([]byte(nil), b...)
	out[0] = tag
	return out
}

func nonMinimalLen(b []byte) []byte {
	// Re-encode the outer length in long form when short form suffices.
	body := b[2:]
	out := []byte{0x30, 0x81, byte(len(body))}
	return append(out, body...)
}

func padTo(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}
