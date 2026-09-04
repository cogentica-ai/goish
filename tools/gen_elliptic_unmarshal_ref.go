package elliptic_test

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"
)

func TestGoishRef(t *testing.T) {
	c := elliptic.P256()
	priv, x, y, err := elliptic.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = priv
	good := elliptic.Marshal(c, x, y)

	show := func(tag string, b []byte) {
		gx, gy := elliptic.Unmarshal(c, b)
		ok := gx != nil && gy != nil
		onCurve := ok && c.IsOnCurve(gx, gy)
		fmt.Printf("%-18s ok=%-5v onCurve=%v\n", tag, ok, onCurve)
	}

	show("valid", good)

	// Flip a byte in X: almost certainly no longer on the curve.
	bad := append([]byte(nil), good...)
	bad[1] ^= 0x01
	show("off-curve", bad)

	// Truncated.
	show("short", good[:len(good)-1])

	// Wrong prefix (compressed form marker).
	comp := append([]byte(nil), good...)
	comp[0] = 0x02
	show("compressed-tag", comp)

	// All-zero body with the uncompressed tag.
	z := make([]byte, len(good))
	z[0] = 4
	show("zero-point", z)
}
