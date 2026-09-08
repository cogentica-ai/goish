package hmac_test

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/sha3"
	"encoding/hex"
	"fmt"
	"hash"
	"testing"
)

func TestGoishRef(t *testing.T) {
	cases := []struct {
		name string
		fn   func() hash.Hash
	}{
		{"sha256", sha256.New},
		{"sha224", sha256.New224},
		{"sha512", sha512.New},
		{"sha384", sha512.New384},
		{"sha512_224", sha512.New512_224},
		{"sha512_256", sha512.New512_256},
		{"sha1", sha1.New},
		{"md5", md5.New},
		{"sha3-224", func() hash.Hash { return sha3.New224() }},
		{"sha3-256", func() hash.Hash { return sha3.New256() }},
		{"sha3-384", func() hash.Hash { return sha3.New384() }},
		{"sha3-512", func() hash.Hash { return sha3.New512() }},
	}
	key := []byte("key-for-hmac")
	msg := []byte("Hi There")
	for _, c := range cases {
		h := hmac.New(c.fn, key)
		// First Reset is where Go caches the marshaled ipad/opad state.
		h.Reset()
		h.Write([]byte("garbage"))
		// Second Reset takes the marshaled branch.
		h.Reset()
		h.Write(msg)
		mac1 := h.Sum(nil)
		// Sum again after another Reset, to exercise the cached path twice.
		h.Reset()
		h.Write(msg)
		mac2 := h.Sum(nil)
		fresh := hmac.New(c.fn, key)
		fresh.Write(msg)
		want := fresh.Sum(nil)
		fmt.Printf("%-11s mac=%s stable=%v matches-fresh=%v size=%d\n",
			c.name, hex.EncodeToString(mac1),
			hex.EncodeToString(mac1) == hex.EncodeToString(mac2),
			hex.EncodeToString(mac1) == hex.EncodeToString(want),
			h.Size())
	}
}
