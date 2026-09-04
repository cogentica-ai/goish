package rsa_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
)

// RSA signature verification is the classic home of "accepts a forgery"
// bugs, because a PKCS#1 v1.5 signature is CHECKED by rebuilding the
// expected padding and comparing — and an implementation that instead
// PARSES the padding, looking for the hash somewhere inside it, accepts
// signatures nobody holding the private key produced. That is
// Bleichenbacher's 2006 attack, and it is still found in new code.
//
// So the shape of this measurement is: one fixed key, one deterministic
// v1.5 signature compared BYTE FOR BYTE, and then a long list of
// near-miss byte strings that must each come back as an error.
//
// The key is emitted as PKCS#1 DER hex so the goish side loads the SAME
// key rather than one of its own — a verifier tested only against
// signatures it made itself cannot fail this kind of test.
//
// PSS and OAEP are randomised, so only their DECISIONS are compared,
// never their bytes. What is pinned there is the salt-length rules,
// which decide interoperability, and the label binding in OAEP, which
// decides whether a ciphertext can be replayed into a different
// context.
func TestGoishRef(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	fmt.Printf("key der=%s\n", hex.EncodeToString(der))
	fmt.Printf("key bits=%d size=%d e=%d\n", key.N.BitLen(), key.Size(), key.E)

	msg := []byte("rsa reference message")
	d256 := sha256.Sum256(msg)
	h256 := d256[:]
	d512 := sha512.Sum512(msg)
	h512 := d512[:]

	// 1. PKCS#1 v1.5 is DETERMINISTIC, so the bytes themselves are the
	//    expectation, not merely "it verifies".
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h256)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("v15 sig=%s\n", hex.EncodeToString(sig))
	sig2, _ := rsa.SignPKCS1v15(nil, key, crypto.SHA256, h256)
	fmt.Printf("v15 deterministic=%v nil-rand-ok=%v\n",
		hex.EncodeToString(sig) == hex.EncodeToString(sig2), sig2 != nil)
	fmt.Printf("v15 verify=%s\n",
		errText(rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, h256, sig)))

	// Every one of these is a byte string a hostile peer can send.
	nBytes := key.N.Bytes()
	for _, c := range []struct {
		name string
		sig  []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"short-by-one", sig[:len(sig)-1]},
		{"long-by-one", append(append([]byte(nil), sig...), 0)},
		{"all-zero", make([]byte, len(sig))},
		{"all-ff", bytesRepeat(0xff, len(sig))},
		{"one", oneAt(len(sig))},
		{"modulus", nBytes},
		{"modulus-minus-1", modMinus(key.N)},
		{"flip-first", flip(sig, 0)},
		{"flip-last", flip(sig, len(sig)-1)},
		{"flip-middle", flip(sig, len(sig)/2)},
		{"leading-zero-shift", shiftRight(sig)},
	} {
		fmt.Printf("v15bad %-20s -> err=%s\n", c.name,
			errText(rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, h256, c.sig)))
	}

	// Hash/digest mismatches: the algorithm identifier is part of what
	// is signed, so a SHA-256 signature must not verify as SHA-512, and
	// a digest of the wrong length must be refused before any maths.
	for _, c := range []struct {
		name string
		h    crypto.Hash
		d    []byte
	}{
		{"right", crypto.SHA256, h256},
		{"wrong-alg-sha512", crypto.SHA512, h512},
		{"wrong-alg-sha512-256d", crypto.SHA512, h256},
		{"sha256-short-digest", crypto.SHA256, h256[:31]},
		{"sha256-long-digest", crypto.SHA256, append(append([]byte(nil), h256...), 0)},
		{"sha256-empty-digest", crypto.SHA256, nil},
		{"hash-zero", crypto.Hash(0), h256},
		{"hash-zero-empty", crypto.Hash(0), nil},
	} {
		fmt.Printf("v15hash %-22s -> err=%s\n", c.name,
			errText(rsa.VerifyPKCS1v15(&key.PublicKey, c.h, c.d, sig)))
	}

	// 2. PSS. Randomised, so only decisions are compared. The salt
	//    length rules are the interoperability surface.
	for _, c := range []struct {
		name string
		opts *rsa.PSSOptions
	}{
		{"auto", &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA256}},
		{"equals-hash", &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}},
		{"explicit-0", &rsa.PSSOptions{SaltLength: 0, Hash: crypto.SHA256}},
		{"explicit-32", &rsa.PSSOptions{SaltLength: 32, Hash: crypto.SHA256}},
		{"explicit-222", &rsa.PSSOptions{SaltLength: 222, Hash: crypto.SHA256}},
		{"explicit-223", &rsa.PSSOptions{SaltLength: 223, Hash: crypto.SHA256}},
		{"explicit-1000", &rsa.PSSOptions{SaltLength: 1000, Hash: crypto.SHA256}},
	} {
		ps, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, h256, c.opts)
		if err != nil {
			fmt.Printf("pss %-14s -> sign-err=%s\n", c.name, errText(err))
			continue
		}
		// Verified back with AUTO, which accepts any salt length, and
		// with EqualsHash, which does not.
		vAuto := rsa.VerifyPSS(&key.PublicKey, crypto.SHA256, h256, ps,
			&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA256})
		vEq := rsa.VerifyPSS(&key.PublicKey, crypto.SHA256, h256, ps,
			&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
		fmt.Printf("pss %-14s -> len=%d auto=%s equals=%s\n",
			c.name, len(ps), errText(vAuto), errText(vEq))
	}
	{
		ps, _ := rsa.SignPSS(rand.Reader, key, crypto.SHA256, h256, nil)
		fmt.Printf("pss nil-opts -> len=%d verify=%s\n", len(ps),
			errText(rsa.VerifyPSS(&key.PublicKey, crypto.SHA256, h256, ps, nil)))
		for _, c := range []struct {
			name string
			sig  []byte
		}{
			{"nil", nil},
			{"empty", []byte{}},
			{"flip-first", flip(ps, 0)},
			{"flip-last", flip(ps, len(ps)-1)},
			{"short", ps[:len(ps)-1]},
			{"long", append(append([]byte(nil), ps...), 0)},
			{"all-zero", make([]byte, len(ps))},
			{"v15-sig-as-pss", sig},
		} {
			fmt.Printf("pssbad %-16s -> err=%s\n", c.name,
				errText(rsa.VerifyPSS(&key.PublicKey, crypto.SHA256, h256, c.sig, nil)))
		}
		// A PSS signature must not verify as PKCS#1 v1.5, and the
		// reverse was covered above.
		fmt.Printf("pss as-v15=%s\n",
			errText(rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, h256, ps)))
	}

	// 3. OAEP. The label is BOUND into the ciphertext, so a ciphertext
	//    encrypted for one label must not decrypt under another — that
	//    is what stops a ciphertext being replayed into a different
	//    context.
	plain := []byte("oaep secret payload")
	for _, c := range []struct{ name, label string }{
		{"no-label", ""},
		{"label-a", "context-a"},
	} {
		ct, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &key.PublicKey, plain, []byte(c.label))
		if err != nil {
			fmt.Printf("oaep %-10s -> encrypt-err=%s\n", c.name, errText(err))
			continue
		}
		pt, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, ct, []byte(c.label))
		fmt.Printf("oaep %-10s -> ctlen=%d same=%v err=%s\n",
			c.name, len(ct), string(pt) == string(plain), errText(err))
		other, oerr := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, ct, []byte("context-b"))
		fmt.Printf("oaep %-10s -> wrong-label n=%d err=%s\n", c.name, len(other), errText(oerr))
		for _, b := range []struct {
			name string
			ct   []byte
		}{
			{"flip-first", flip(ct, 0)},
			{"flip-last", flip(ct, len(ct)-1)},
			{"short", ct[:len(ct)-1]},
			{"long", append(append([]byte(nil), ct...), 0)},
			{"all-zero", make([]byte, len(ct))},
		} {
			_, e := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, b.ct, []byte(c.label))
			fmt.Printf("oaepbad %-8s %-12s -> err=%s\n", c.name, b.name, errText(e))
		}
	}
	// A message too long for the modulus is refused rather than
	// truncated.
	{
		big := make([]byte, 512)
		_, e := rsa.EncryptOAEP(sha256.New(), rand.Reader, &key.PublicKey, big, nil)
		fmt.Printf("oaep too-long-err=%s\n", errText(e))
		maxLen := key.Size() - 2*sha256.Size - 2
		exact := make([]byte, maxLen)
		ct, e2 := rsa.EncryptOAEP(sha256.New(), rand.Reader, &key.PublicKey, exact, nil)
		fmt.Printf("oaep max-len=%d err=%s ctlen=%d\n", maxLen, errText(e2), len(ct))
		over := make([]byte, maxLen+1)
		_, e3 := rsa.EncryptOAEP(sha256.New(), rand.Reader, &key.PublicKey, over, nil)
		fmt.Printf("oaep max-plus-1-err=%s\n", errText(e3))
	}

	// 4. Public keys that are not usable. Note what is NOT measured
	//    here: `Validate` on a mutated copy of a generated key returns
	//    nil, because it short-circuits on `Precomputed.fips != nil` —
	//    the key was validated when it was built and the early-out
	//    never looks at the mutated field. That measures Go's cache,
	//    not Go's rules, so the rules are reached through Verify
	//    instead, which every hostile input arrives at anyway.
	{
		fmt.Printf("valid ok=%s\n", errText(key.Validate()))
		for _, c := range []struct {
			name string
			e    int
			n    *big.Int
		}{
			{"e-one", 1, key.N},
			{"e-zero", 0, key.N},
			{"e-negative", -3, key.N},
			{"e-even", 4, key.N},
			{"e-three", 3, key.N},
			{"e-huge", 1 << 30, key.N},
			{"n-tiny", 65537, big.NewInt(3)},
			{"n-zero", 65537, big.NewInt(0)},
			{"n-one", 65537, big.NewInt(1)},
		} {
			p := &rsa.PublicKey{N: c.n, E: c.e}
			fmt.Printf("pubkey %-12s -> verify=%s\n", c.name,
				errText(rsa.VerifyPKCS1v15(p, crypto.SHA256, h256, sig)))
		}
	}
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

func modMinus(n *big.Int) []byte {
	m := new(big.Int).Sub(n, big.NewInt(1))
	return m.Bytes()
}

func flip(b []byte, i int) []byte {
	out := append([]byte(nil), b...)
	out[i] ^= 0x01
	return out
}

func shiftRight(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out[1:], b[:len(b)-1])
	return out
}

func errText(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}
