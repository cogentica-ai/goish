package chacha20

import (
	"encoding/hex"
	"fmt"
	"testing"

	"golang.org/x/crypto/internal/poly1305"
)

// ChaCha20 and Poly1305 are the two halves of the AEAD that TLS 1.3
// negotiates whenever AES hardware is absent, and goish had 740 lines
// of them with NO test of any kind — not a vector, not a smoke.
//
// A stream cipher that is subtly wrong does not fail loudly: it
// produces ciphertext, and the peer produces plaintext that is not what
// was sent. A MAC that is subtly wrong is worse, because the failure it
// hides is authentication. Neither has a self-check; the only way to
// know is to compare against a reference.
//
// The parts worth pinning, beyond the published test vectors:
//
//   * The counter starts at 0 and SetCounter moves it, so a caller can
//     resume a stream mid-message — which is exactly what the AEAD does
//     when it reserves block 0 for the Poly1305 key and starts the
//     payload at block 1.
//   * XORKeyStream is incremental: encrypting in two calls must give
//     the same bytes as one, including across a 64-byte block boundary,
//     because that is how a streaming writer uses it.
//   * HChaCha20 is the key-derivation step XChaCha20 needs, and its
//     output is a KEY, so a wrong one is silently a different cipher.
//   * Poly1305 is not a hash: it is one-time authentication over a
//     16-byte-padded message, and the padding rule at each 16-byte
//     boundary is where an implementation goes wrong without failing
//     any round trip it performs against itself.
func TestGoishRef(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	nonce := []byte{0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0}

	// 1. RFC 8439 Section 2.4.2's vector, and the keystream itself.
	{
		c, err := NewUnauthenticatedCipher(key, nonce)
		if err != nil {
			t.Fatal(err)
		}
		c.SetCounter(1)
		pt := []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
		ct := make([]byte, len(pt))
		c.XORKeyStream(ct, pt)
		fmt.Printf("rfc8439 ct=%s\n", hex.EncodeToString(ct))
	}

	// 2. The raw keystream at several counters, which is what a wrong
	//    counter or a wrong block function shows up in first.
	for _, ctr := range []uint32{0, 1, 2, 0xffffffff} {
		c, _ := NewUnauthenticatedCipher(key, nonce)
		c.SetCounter(ctr)
		out := make([]byte, 64)
		c.XORKeyStream(out, out)
		fmt.Printf("keystream ctr=%-10d %s\n", ctr, hex.EncodeToString(out))
	}

	// 3. Incremental use must equal the single-shot: split at every
	//    interesting offset around a block boundary.
	for _, split := range []int{0, 1, 31, 63, 64, 65, 100} {
		src := make([]byte, 128)
		for i := range src {
			src[i] = byte(i * 7)
		}
		one, _ := NewUnauthenticatedCipher(key, nonce)
		a := make([]byte, len(src))
		one.XORKeyStream(a, src)

		two, _ := NewUnauthenticatedCipher(key, nonce)
		b := make([]byte, len(src))
		two.XORKeyStream(b[:split], src[:split])
		two.XORKeyStream(b[split:], src[split:])
		fmt.Printf("split %-4d same=%-5v head=%s\n", split,
			string(a) == string(b), hex.EncodeToString(b[:16]))
	}

	// 4. Zero-length and one-byte calls.
	{
		c, _ := NewUnauthenticatedCipher(key, nonce)
		c.XORKeyStream(nil, nil)
		one := make([]byte, 1)
		c.XORKeyStream(one, one)
		fmt.Printf("tiny after-empty=%s\n", hex.EncodeToString(one))
	}

	// 5. Key and nonce sizes that must be refused.
	for _, c := range []struct{ k, n int }{
		{32, 12}, {32, 24}, {31, 12}, {33, 12}, {32, 11}, {32, 13}, {0, 0},
	} {
		_, err := NewUnauthenticatedCipher(make([]byte, c.k), make([]byte, c.n))
		fmt.Printf("newcipher k=%-3d n=%-3d -> err=%v\n", c.k, c.n, errText(err))
	}

	// 6. HChaCha20 — the XChaCha20 key-derivation step.
	for _, n := range [][]byte{
		make([]byte, 16),
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	} {
		out, err := HChaCha20(key, n)
		fmt.Printf("hchacha nonce=%s -> %s err=%v\n",
			hex.EncodeToString(n), hex.EncodeToString(out), errText(err))
	}
	for _, c := range []struct{ k, n int }{{32, 15}, {32, 17}, {31, 16}} {
		_, err := HChaCha20(make([]byte, c.k), make([]byte, c.n))
		fmt.Printf("hchacha k=%-3d n=%-3d -> err=%v\n", c.k, c.n, errText(err))
	}

	// 7. Poly1305 over the lengths where the 16-byte padding rule bites.
	var pkey [32]byte
	for i := range pkey {
		pkey[i] = byte(i + 1)
	}
	for _, n := range []int{0, 1, 15, 16, 17, 31, 32, 33, 64, 100} {
		msg := make([]byte, n)
		for i := range msg {
			msg[i] = byte(i * 3)
		}
		var tag [16]byte
		poly1305.Sum(&tag, msg, &pkey)
		fmt.Printf("poly1305 len=%-4d tag=%s verify=%v\n",
			n, hex.EncodeToString(tag[:]), poly1305.Verify(&tag, msg, &pkey))
	}
	// A tampered tag must not verify.
	{
		msg := []byte("authenticated")
		var tag [16]byte
		poly1305.Sum(&tag, msg, &pkey)
		bad := tag
		bad[0] ^= 1
		fmt.Printf("poly1305 tamper-tag verify=%v\n", poly1305.Verify(&bad, msg, &pkey))
		fmt.Printf("poly1305 tamper-msg verify=%v\n",
			poly1305.Verify(&tag, []byte("authenticatee"), &pkey))
	}
	// The incremental MAC must equal the single-shot.
	{
		msg := make([]byte, 100)
		for i := range msg {
			msg[i] = byte(i)
		}
		var want [16]byte
		poly1305.Sum(&want, msg, &pkey)
		for _, split := range []int{0, 1, 15, 16, 17, 64} {
			m := poly1305.New(&pkey)
			m.Write(msg[:split])
			m.Write(msg[split:])
			got := m.Sum(nil)
			fmt.Printf("poly1305 split=%-3d same=%v\n", split,
				hex.EncodeToString(got) == hex.EncodeToString(want[:]))
		}
	}
	// RFC 8439 Section 2.5.2's vector.
	{
		var k [32]byte
		copy(k[:], mustHex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"))
		msg := []byte("Cryptographic Forum Research Group")
		var tag [16]byte
		poly1305.Sum(&tag, msg, &k)
		fmt.Printf("poly1305 rfc8439 tag=%s\n", hex.EncodeToString(tag[:]))
	}
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func errText(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}
