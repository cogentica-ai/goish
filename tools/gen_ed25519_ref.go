package ed25519_test

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// A signature verifier that accepts something it should not is the
// worst defect a crypto port can have, because nothing downstream will
// ever notice: the caller's answer is "valid", and every check built on
// it agrees. So the interesting inputs here are the near-misses, and
// what is being pinned is mostly REJECTIONS.
//
// Ed25519's rejections are unusually specific, and none of them fall
// out of "does the maths work":
//
//   * The scalar S must be CANONICAL — strictly less than the group
//     order L. A signature with S+L in place of S verifies under a
//     naive implementation and is a different byte string for the same
//     message, which is signature malleability: two distinct valid
//     signatures where a protocol assumed one.
//   * The high three bits of S[31] are therefore always clear in a
//     real signature, and Go checks them explicitly before doing any
//     work.
//   * Go does NOT reject small-order public keys or non-canonical R
//     encodings, which some other implementations do. That is a
//     compatibility decision, and a port that "hardens" it disagrees
//     with every Go peer.
//
// Keys are derived from a FIXED seed rather than generated, so both
// sides sign the same bytes and the signature itself can be compared,
// not merely its acceptance.
func TestGoishRef(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i * 7)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	fmt.Printf("key seed=%s pub=%s privlen=%d publen=%d\n",
		hex.EncodeToString(seed), hex.EncodeToString(pub), len(priv), len(pub))
	fmt.Printf("key seed-roundtrip=%v public-equal=%v\n",
		bytes.Equal(priv.Seed(), seed), pub.Equal(priv.Public()))

	msgs := []struct{ name, msg string }{
		{"empty", ""},
		{"short", "a"},
		{"text", "the quick brown fox jumps over the lazy dog"},
		{"nul", "\x00"},
		{"long", strings.Repeat("x", 1000)},
		{"binary", "\xff\xfe\x00\x01\x80"},
	}
	sigs := map[string][]byte{}
	for _, m := range msgs {
		sig := ed25519.Sign(priv, []byte(m.msg))
		sigs[m.name] = sig
		fmt.Printf("sign %-8s len=%d sig=%s verify=%v\n",
			m.name, len(sig), hex.EncodeToString(sig), ed25519.Verify(pub, []byte(m.msg), sig))
	}

	// Cross-checks: the same signature under a different message, and
	// the same message under a different key, must both fail.
	good := sigs["text"]
	msg := []byte("the quick brown fox jumps over the lazy dog")
	otherSeed := make([]byte, ed25519.SeedSize)
	otherSeed[0] = 1
	otherPub := ed25519.NewKeyFromSeed(otherSeed).Public().(ed25519.PublicKey)
	fmt.Printf("cross wrong-message=%v\n", ed25519.Verify(pub, []byte("other"), good))
	fmt.Printf("cross wrong-key=%v\n", ed25519.Verify(otherPub, msg, good))
	fmt.Printf("cross empty-message=%v\n", ed25519.Verify(pub, nil, good))

	// Malformed signatures. Every one of these is a byte string a
	// hostile peer can send, and every answer must be false.
	bad := []struct {
		name string
		sig  []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"short-63", good[:63]},
		{"long-65", append(append([]byte(nil), good...), 0)},
		{"all-zero", make([]byte, 64)},
		{"all-ff", bytes.Repeat([]byte{0xff}, 64)},
		{"flip-first", flip(good, 0)},
		{"flip-r-last", flip(good, 31)},
		{"flip-s-first", flip(good, 32)},
		{"flip-s-last", flip(good, 63)},
		{"s-high-bit", setBit(good, 63, 0x80)},
		{"s-bit-254", setBit(good, 63, 0x40)},
		{"s-bit-253", setBit(good, 63, 0x20)},
		{"s-plus-order", addOrder(good)},
		{"r-zero", zeroRange(good, 0, 32)},
		{"s-zero", zeroRange(good, 32, 64)},
		{"swapped-halves", swapHalves(good)},
	}
	for _, b := range bad {
		ok := ed25519.Verify(pub, msg, b.sig)
		err := ed25519.VerifyWithOptions(pub, msg, b.sig, &ed25519.Options{})
		fmt.Printf("bad %-16s -> verify=%-5v err=%s\n", b.name, ok, errText(err))
	}

	// Small-order and identity public keys: Go ACCEPTS a signature
	// under them if the maths works out. Pinned because it is a
	// compatibility decision, not an oversight.
	{
		zero := make([]byte, ed25519.PublicKeySize)
		fmt.Printf("edge zero-pubkey-verify=%v\n",
			ed25519.Verify(ed25519.PublicKey(zero), msg, good))
		one := make([]byte, ed25519.PublicKeySize)
		one[0] = 1
		fmt.Printf("edge one-pubkey-verify=%v\n",
			ed25519.Verify(ed25519.PublicKey(one), msg, good))
	}

	// Ed25519ph: a PREHASHED variant with a different domain, so a
	// signature from one mode never verifies in the other. That
	// separation is the point of the domain prefix.
	{
		h := sha512.Sum512(msg)
		phSig, err := priv.Sign(nil, h[:], crypto.SHA512)
		if err != nil {
			fmt.Printf("ph sign-err=%q\n", err.Error())
		} else {
			fmt.Printf("ph sig=%s\n", hex.EncodeToString(phSig))
			fmt.Printf("ph verify-ph=%s\n", errText(ed25519.VerifyWithOptions(
				pub, h[:], phSig, &ed25519.Options{Hash: crypto.SHA512})))
			fmt.Printf("ph verify-pure=%s\n", errText(ed25519.VerifyWithOptions(
				pub, h[:], phSig, &ed25519.Options{})))
			fmt.Printf("ph pure-sig-as-ph=%s\n", errText(ed25519.VerifyWithOptions(
				pub, h[:], good, &ed25519.Options{Hash: crypto.SHA512})))
		}
		// A prehash of the wrong length is refused before any maths.
		_, err = priv.Sign(nil, h[:31], crypto.SHA512)
		fmt.Printf("ph short-digest-sign-err=%s\n", errText(err))
		fmt.Printf("ph short-digest-verify-err=%s\n", errText(ed25519.VerifyWithOptions(
			pub, h[:31], good, &ed25519.Options{Hash: crypto.SHA512})))
	}

	// Ed25519ctx: a context string, also domain-separating.
	{
		ctxSig, err := priv.Sign(nil, msg, &ed25519.Options{Context: "ctx-one"})
		if err != nil {
			fmt.Printf("ctx sign-err=%q\n", err.Error())
		} else {
			fmt.Printf("ctx sig=%s\n", hex.EncodeToString(ctxSig))
			fmt.Printf("ctx same=%s\n", errText(ed25519.VerifyWithOptions(
				pub, msg, ctxSig, &ed25519.Options{Context: "ctx-one"})))
			fmt.Printf("ctx different=%s\n", errText(ed25519.VerifyWithOptions(
				pub, msg, ctxSig, &ed25519.Options{Context: "ctx-two"})))
			fmt.Printf("ctx absent=%s\n", errText(ed25519.VerifyWithOptions(
				pub, msg, ctxSig, &ed25519.Options{})))
		}
		long := strings.Repeat("c", 256)
		_, err = priv.Sign(nil, msg, &ed25519.Options{Context: long})
		fmt.Printf("ctx too-long-err=%s\n", errText(err))
	}

	// Determinism: Ed25519 signatures carry no randomness, so signing
	// the same message twice must produce the SAME bytes. A port that
	// leaked randomness in here would pass every verification test and
	// still be wrong.
	{
		a := ed25519.Sign(priv, msg)
		b := ed25519.Sign(priv, msg)
		fmt.Printf("determinism same=%v\n", bytes.Equal(a, b))
	}

	// NewKeyFromSeed's expansion, and the private key layout: the
	// second half of a private key IS the public key.
	{
		fmt.Printf("layout priv-tail-is-pub=%v\n",
			bytes.Equal(priv[32:], pub))
	}
}

func flip(b []byte, i int) []byte {
	out := append([]byte(nil), b...)
	out[i] ^= 0x01
	return out
}

func setBit(b []byte, i int, mask byte) []byte {
	out := append([]byte(nil), b...)
	out[i] |= mask
	return out
}

func zeroRange(b []byte, lo, hi int) []byte {
	out := append([]byte(nil), b...)
	for i := lo; i < hi; i++ {
		out[i] = 0
	}
	return out
}

func swapHalves(b []byte) []byte {
	out := make([]byte, 64)
	copy(out[:32], b[32:])
	copy(out[32:], b[:32])
	return out
}

// addOrder adds the group order L to the scalar S, little-endian. The
// result is a DIFFERENT byte string that satisfies the same equation,
// which is exactly what canonicality checking exists to refuse.
func addOrder(sig []byte) []byte {
	l := []byte{
		0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
		0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
	}
	out := append([]byte(nil), sig...)
	carry := 0
	for i := 0; i < 32; i++ {
		v := int(out[32+i]) + int(l[i]) + carry
		out[32+i] = byte(v)
		carry = v >> 8
	}
	return out
}

func errText(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}
