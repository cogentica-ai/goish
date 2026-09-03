package mlkem_test

import (
	"bytes"
	"crypto/mlkem"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// ML-KEM is a key ENCAPSULATION mechanism: one side produces a
// ciphertext and a shared secret, the other recovers the secret from
// the ciphertext. Everything a caller does afterwards is keyed on that
// secret, so the rule that decides whether any of it is safe is what
// Decapsulate does with a ciphertext it did not expect.
//
// The answer is the part people get wrong, because it is not "return
// an error". ML-KEM uses IMPLICIT REJECTION: a ciphertext of the right
// LENGTH that decrypts to nothing meaningful yields a shared secret
// that is pseudorandom and DIFFERENT from the sender's — no error, no
// signal, just a secret the two sides do not share. That is
// deliberate: an error would be an oracle, and the Fujisaki-Okamoto
// transform's security argument depends on there being no oracle. A
// port that "helpfully" returned an error for a corrupt ciphertext
// would leak exactly what the design spends effort hiding.
//
// The only inputs that DO error are the ones with the wrong length,
// because a length check reveals nothing an attacker did not already
// choose.
//
// Keys are derived from a FIXED seed rather than generated, so both
// sides hold the same key and the secrets themselves are compared, not
// merely the fact that two ends agreed with each other.
func TestGoishRef(t *testing.T) {
	// 768.
	{
		seed := make([]byte, mlkem.SeedSize)
		for i := range seed {
			seed[i] = byte(i * 3)
		}
		dk, err := mlkem.NewDecapsulationKey768(seed)
		if err != nil {
			t.Fatal(err)
		}
		ek := dk.EncapsulationKey()
		fmt.Printf("768 seedsize=%d ek-size=%d dk-bytes=%d\n",
			mlkem.SeedSize, len(ek.Bytes()), len(dk.Bytes()))
		fmt.Printf("768 ek=%s\n", hex.EncodeToString(ek.Bytes())[:96])
		fmt.Printf("768 dk-roundtrip=%v\n", bytes.Equal(dk.Bytes(), seed))

		// Encapsulate is randomised, so the ciphertext differs each
		// time — what must hold is that BOTH sides derive the same
		// secret, and that two encapsulations differ.
		sec1, ct1 := ek.Encapsulate()
		sec2, ct2 := ek.Encapsulate()
		fmt.Printf("768 ct-size=%d secret-size=%d ct-differs=%v secret-differs=%v\n",
			len(ct1), len(sec1), !bytes.Equal(ct1, ct2), !bytes.Equal(sec1, sec2))
		got, err := dk.Decapsulate(ct1)
		fmt.Printf("768 decap-agrees=%v err=%s\n", bytes.Equal(got, sec1), errText(err))
		got2, err := dk.Decapsulate(ct2)
		fmt.Printf("768 decap2-agrees=%v err=%s\n", bytes.Equal(got2, sec2), errText(err))

		// A DIFFERENT key must not recover the secret, and must not
		// error either.
		seed2 := make([]byte, mlkem.SeedSize)
		seed2[0] = 1
		dk2, _ := mlkem.NewDecapsulationKey768(seed2)
		other, err := dk2.Decapsulate(ct1)
		fmt.Printf("768 wrong-key agrees=%v len=%d err=%s\n",
			bytes.Equal(other, sec1), len(other), errText(err))

		// Implicit rejection: right length, wrong contents.
		for _, c := range []struct {
			name string
			ct   []byte
		}{
			{"flip-first", flip(ct1, 0)},
			{"flip-last", flip(ct1, len(ct1)-1)},
			{"flip-middle", flip(ct1, len(ct1)/2)},
			{"all-zero", make([]byte, len(ct1))},
			{"all-ff", bytesRepeat(0xff, len(ct1))},
		} {
			s, err := dk.Decapsulate(c.ct)
			fmt.Printf("768 reject %-12s -> err=%-6s len=%d agrees=%v deterministic=%v\n",
				c.name, errText(err), len(s), bytes.Equal(s, sec1), sameTwice(dk, c.ct))
		}

		// Wrong LENGTH is the one thing that errors.
		for _, c := range []struct {
			name string
			ct   []byte
		}{
			{"nil", nil},
			{"empty", []byte{}},
			{"short-by-one", ct1[:len(ct1)-1]},
			{"long-by-one", append(append([]byte(nil), ct1...), 0)},
			{"half", ct1[:len(ct1)/2]},
			{"one-byte", ct1[:1]},
		} {
			s, err := dk.Decapsulate(c.ct)
			fmt.Printf("768 badlen %-12s -> err=%q len=%d\n", c.name, errText(err), len(s))
		}

		// Malformed keys.
		for _, c := range []struct {
			name string
			b    []byte
		}{
			{"nil", nil},
			{"empty", []byte{}},
			{"short", seed[:len(seed)-1]},
			{"long", append(append([]byte(nil), seed...), 0)},
			{"all-zero", make([]byte, mlkem.SeedSize)},
		} {
			_, err := mlkem.NewDecapsulationKey768(c.b)
			fmt.Printf("768 badseed %-10s -> err=%q\n", c.name, errText(err))
		}
		ekb := ek.Bytes()
		for _, c := range []struct {
			name string
			b    []byte
		}{
			{"nil", nil},
			{"empty", []byte{}},
			{"short", ekb[:len(ekb)-1]},
			{"long", append(append([]byte(nil), ekb...), 0)},
			{"all-zero", make([]byte, len(ekb))},
			{"all-ff", bytesRepeat(0xff, len(ekb))},
			{"flip-first", flip(ekb, 0)},
		} {
			_, err := mlkem.NewEncapsulationKey768(c.b)
			fmt.Printf("768 badek %-12s -> err=%q\n", c.name, errText(err))
		}
		// A re-parsed encapsulation key encapsulates to the same
		// decapsulation key.
		ek2, err := mlkem.NewEncapsulationKey768(ekb)
		if err == nil {
			s3, c3 := ek2.Encapsulate()
			r3, _ := dk.Decapsulate(c3)
			fmt.Printf("768 reparsed-ek agrees=%v\n", bytes.Equal(r3, s3))
		}
	}

	// 1024, so a port cannot be right at one size only.
	{
		seed := make([]byte, mlkem.SeedSize)
		for i := range seed {
			seed[i] = byte(255 - i)
		}
		dk, err := mlkem.NewDecapsulationKey1024(seed)
		if err != nil {
			t.Fatal(err)
		}
		ek := dk.EncapsulationKey()
		sec, ct := ek.Encapsulate()
		got, derr := dk.Decapsulate(ct)
		fmt.Printf("1024 ek-size=%d ct-size=%d secret-size=%d agrees=%v err=%s\n",
			len(ek.Bytes()), len(ct), len(sec), bytes.Equal(got, sec), errText(derr))
		bad, berr := dk.Decapsulate(flip(ct, 0))
		fmt.Printf("1024 reject flip-first -> err=%-6s agrees=%v\n",
			errText(berr), bytes.Equal(bad, sec))
		_, xerr := dk.Decapsulate(ct[:len(ct)-1])
		fmt.Printf("1024 badlen short -> err=%q\n", errText(xerr))
		// A 768 ciphertext offered to a 1024 key is a length error.
		seed768 := make([]byte, mlkem.SeedSize)
		dk768, _ := mlkem.NewDecapsulationKey768(seed768)
		_, ct768 := dk768.EncapsulationKey().Encapsulate()
		_, cerr := dk.Decapsulate(ct768)
		fmt.Printf("1024 cross-size-768-ct -> err=%q\n", errText(cerr))
		_, kerr := mlkem.NewEncapsulationKey1024(dk768.EncapsulationKey().Bytes())
		fmt.Printf("1024 cross-size-768-ek -> err=%q\n", errText(kerr))
	}

	// GenerateKey must produce a working, distinct pair each time.
	{
		a, err1 := mlkem.GenerateKey768()
		b, err2 := mlkem.GenerateKey768()
		fmt.Printf("gen err1=%s err2=%s distinct=%v\n",
			errText(err1), errText(err2), !bytes.Equal(a.Bytes(), b.Bytes()))
		s, c := a.EncapsulationKey().Encapsulate()
		r, _ := a.Decapsulate(c)
		fmt.Printf("gen roundtrip=%v\n", bytes.Equal(r, s))
		cross, cerr := b.Decapsulate(c)
		fmt.Printf("gen cross-key agrees=%v err=%s\n", bytes.Equal(cross, s), errText(cerr))
	}
	_ = strings.Repeat
}

// sameTwice reports whether decapsulating the same bad ciphertext
// twice gives the same answer — implicit rejection has to be a
// FUNCTION of the key and the ciphertext, not fresh randomness, or a
// retry would leak that the first attempt was rejected.
func sameTwice(dk *mlkem.DecapsulationKey768, ct []byte) bool {
	a, err1 := dk.Decapsulate(ct)
	b, err2 := dk.Decapsulate(ct)
	if err1 != nil || err2 != nil {
		return false
	}
	return bytes.Equal(a, b)
}

func flip(b []byte, i int) []byte {
	out := append([]byte(nil), b...)
	out[i] ^= 0x01
	return out
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func errText(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}
