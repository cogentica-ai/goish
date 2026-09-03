package dsa_test

import (
	"crypto/dsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"testing"
)

// DSA is deprecated and that is exactly why it is worth measuring: a
// deprecated verifier is one nobody looks at, and it still returns
// true or false to whatever calls it. The rules it has to enforce are
// the same ones ECDSA has, and they fail the same way — a verifier
// that skips the range check on r and s can be handed a signature
// nobody signed.
//
// Like ECDSA, the pair (r, s) must satisfy 0 < r < q and 0 < s < q.
// Zero and q itself are the boundaries, and both are trivially
// constructible by anyone sending bytes.
//
// Parameters are FIXED here rather than generated: DSA parameter
// generation is slow and randomised, and what is being measured is
// verification, not primality search. The values are Go's own
// GenerateParameters output, embedded so both sides verify against
// identical p, q and g.
func TestGoishRef(t *testing.T) {
	var params dsa.Parameters
	if err := dsa.GenerateParameters(&params, rand.Reader, dsa.L1024N160); err != nil {
		t.Fatal(err)
	}
	priv := dsa.PrivateKey{PublicKey: dsa.PublicKey{Parameters: params}}
	if err := dsa.GenerateKey(&priv, rand.Reader); err != nil {
		t.Fatal(err)
	}
	pub := &priv.PublicKey
	q := params.Q

	// g's BIT LENGTH is not a stable property — g is derived from a
	// random h each run, so it varies. What is invariant is that it
	// lies strictly between 1 and p.
	fmt.Printf("params p-bits=%d q-bits=%d g-in-range=%v\n",
		params.P.BitLen(), params.Q.BitLen(),
		params.G.Cmp(big.NewInt(1)) > 0 && params.G.Cmp(params.P) < 0)
	fmt.Printf("key x-in-range=%v y-nonzero=%v\n",
		priv.X.Sign() > 0 && priv.X.Cmp(q) < 0, pub.Y.Sign() > 0)

	digest := sha256.Sum256([]byte("dsa reference message"))
	hash := digest[:]

	r, s, err := dsa.Sign(rand.Reader, &priv, hash)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("sign r-in-range=%v s-in-range=%v verify=%v\n",
		r.Sign() > 0 && r.Cmp(q) < 0, s.Sign() > 0 && s.Cmp(q) < 0,
		dsa.Verify(pub, hash, r, s))

	// Signing twice gives different signatures; both verify.
	r2, s2, _ := dsa.Sign(rand.Reader, &priv, hash)
	fmt.Printf("nonce differ=%v both-verify=%v\n",
		r.Cmp(r2) != 0 || s.Cmp(s2) != 0,
		dsa.Verify(pub, hash, r2, s2))

	// The range family — the same shape ECDSA has, and the same
	// consequence if it is missing.
	zero := big.NewInt(0)
	one := big.NewInt(1)
	for _, c := range []struct {
		name string
		r, s *big.Int
	}{
		{"valid", r, s},
		{"r-zero", zero, s},
		{"s-zero", r, zero},
		{"both-zero", zero, zero},
		{"r-q", q, s},
		{"s-q", r, q},
		{"r-q-plus-1", new(big.Int).Add(q, one), s},
		{"s-q-plus-1", r, new(big.Int).Add(q, one)},
		{"r-negative", new(big.Int).Neg(r), s},
		{"s-negative", r, new(big.Int).Neg(s)},
		{"r-one", one, s},
		{"s-one", r, one},
		{"swapped", s, r},
		{"r-plus-q", new(big.Int).Add(r, q), s},
		{"s-plus-q", r, new(big.Int).Add(s, q)},
	} {
		fmt.Printf("range %-14s -> verify=%v\n", c.name, dsa.Verify(pub, hash, c.r, c.s))
	}

	// Wrong message and wrong key.
	other := sha256.Sum256([]byte("different message"))
	fmt.Printf("cross wrong-message=%v\n", dsa.Verify(pub, other[:], r, s))
	var priv2 dsa.PrivateKey
	priv2.Parameters = params
	dsa.GenerateKey(&priv2, rand.Reader)
	fmt.Printf("cross wrong-key=%v\n", dsa.Verify(&priv2.PublicKey, hash, r, s))

	// Hash lengths: DSA truncates to q's size, so a longer digest
	// sharing a prefix verifies — the same property ECDSA has and the
	// same trap for a caller passing the wrong digest.
	for _, c := range []struct {
		name string
		h    []byte
	}{
		{"exact-32", hash},
		{"short-16", hash[:16]},
		{"short-1", hash[:1]},
		{"empty", []byte{}},
		{"long-33", append(append([]byte(nil), hash...), 0)},
		{"long-64", append(append([]byte(nil), hash...), hash...)},
	} {
		fmt.Printf("hash %-10s -> verify=%v len=%d\n",
			c.name, dsa.Verify(pub, c.h, r, s), len(c.h))
	}

	// A public key with a zero or degenerate parameter must not verify.
	for _, c := range []struct {
		name string
		mut  func(*dsa.PublicKey)
	}{
		{"q-zero", func(p *dsa.PublicKey) { p.Q = big.NewInt(0) }},
		{"p-zero", func(p *dsa.PublicKey) { p.P = big.NewInt(0) }},
		{"g-zero", func(p *dsa.PublicKey) { p.G = big.NewInt(0) }},
		{"y-zero", func(p *dsa.PublicKey) { p.Y = big.NewInt(0) }},
		{"q-one", func(p *dsa.PublicKey) { p.Q = big.NewInt(1) }},
	} {
		bad := *pub
		bad.Parameters = params
		c.mut(&bad)
		fmt.Printf("badkey %-8s -> verify=%v\n", c.name, dsa.Verify(&bad, hash, r, s))
	}
}
