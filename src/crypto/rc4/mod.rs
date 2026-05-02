// crypto/rc4 — RC4 stream cipher.
//
// Reference: /share/go/src/crypto/rc4/rc4.go (85 LOC).
//
// RC4 is cryptographically broken; ported for completeness and to
// validate the `cipher::Stream` trait surface (declared in
// `src/crypto/cipher/mod.rs`).
//
// Slim deviations:
//   * `NewCipher` returns `(Option<Cipher>, error)`. Go returns
//     `(*Cipher, error)`. Goish doesn't have nullable pointers; an
//     `Option<Cipher>` carrying the value (or `None` on error) is the
//     idiomatic shape.
//   * No `crypto/internal/fips140only.Enabled` branch — goish has no
//     FIPS service-indicator infrastructure.
//   * No `alias.InexactOverlap` panic — goish slices don't expose
//     pointer arithmetic for the overlap check. Callers must respect
//     "dst and src must overlap entirely or not at all" by contract.
//   * `Cipher` is a value type (not heap-allocated). The `cipher::Stream`
//     trait uses `&mut self`, so callers hold the Cipher by value and
//     mutate it via the trait method.

#![allow(non_snake_case)]

extern crate alloc;

use crate::crypto::cipher::Stream;
use crate::errors::{ErrorTrait, Wrap, error, nil};
use crate::goslice::slice;
use crate::gostring::string;
use crate::strconv;
use crate::types::{byte, int};

// Go: rc4.go:20
//   type Cipher struct {
//       s    [256]uint32
//       i, j uint8
//   }
/// `rc4.Cipher` — an instance of RC4 using a particular key.
#[derive(Clone)]
pub struct Cipher {
    s: [u32; 256],
    i: u8,
    j: u8,
}

// Go: rc4.go:25
//   type KeySizeError int
//
//   func (k KeySizeError) Error() string {
//       return "crypto/rc4: invalid key size " + strconv.Itoa(int(k))
//   }
/// `rc4.KeySizeError` — error returned by `NewCipher` when the key
/// length is outside `[1, 256]`.
#[derive(Clone)]
pub struct KeySizeError(pub int);

impl ErrorTrait for KeySizeError {
    fn Error(&self) -> string {
        // Go: "crypto/rc4: invalid key size " + strconv.Itoa(int(k))
        let mut s = string::from_static("crypto/rc4: invalid key size ");
        s = s + strconv::Itoa(self.0);
        s
    }
}

// Go: rc4.go:33
//   func NewCipher(key []byte) (*Cipher, error)
/// `rc4.NewCipher(key)` — create and return a new `Cipher`. The key
/// argument should be the RC4 key, at least 1 byte and at most 256 bytes.
///
/// On success returns `(Some(cipher), nil)`. On error returns
/// `(None, KeySizeError)` for invalid key lengths.
pub fn NewCipher(key: slice<byte>) -> (Option<Cipher>, error) {
    // Go: k := len(key)
    let k = key.Len();
    // Go: if k < 1 || k > 256 { return nil, KeySizeError(k) }
    if k < 1 || k > 256 {
        return (None, Wrap(KeySizeError(k)));
    }
    // Go: var c Cipher
    let mut c = Cipher { s: [0u32; 256], i: 0, j: 0 };
    // Go: for i := 0; i < 256; i++ { c.s[i] = uint32(i) }
    let mut i: int = 0;
    while i < 256 {
        c.s[i as usize] = i as u32;
        i += 1;
    }
    // Go: var j uint8 = 0
    //     for i := 0; i < 256; i++ {
    //         j += uint8(c.s[i]) + key[i%k]
    //         c.s[i], c.s[j] = c.s[j], c.s[i]
    //     }
    let mut j: u8 = 0;
    let mut i: int = 0;
    while i < 256 {
        // u8 wrapping add — Go's uint8 arithmetic wraps modulo 256.
        j = j
            .wrapping_add(c.s[i as usize] as u8)
            .wrapping_add(key[i % k]);
        let ii = i as usize;
        let jj = j as usize;
        let tmp = c.s[ii];
        c.s[ii] = c.s[jj];
        c.s[jj] = tmp;
        i += 1;
    }
    (Some(c), nil)
}

impl Cipher {
    // Go: rc4.go:57
    //   func (c *Cipher) Reset() {
    //       for i := range c.s { c.s[i] = 0 }
    //       c.i, c.j = 0, 0
    //   }
    /// `Reset` zeros the key data and makes the `Cipher` unusable.
    ///
    /// Deprecated: Reset can't guarantee that the key will be entirely
    /// removed from the process's memory.
    pub fn Reset(&mut self) {
        // Go: for i := range c.s { c.s[i] = 0 }
        let mut i: int = 0;
        while i < 256 {
            self.s[i as usize] = 0;
            i += 1;
        }
        // Go: c.i, c.j = 0, 0
        self.i = 0;
        self.j = 0;
    }
}

// Go: rc4.go:66
//   func (c *Cipher) XORKeyStream(dst, src []byte)
//
// Implements `cipher::Stream` so `rc4::Cipher` can be used wherever
// the trait is required.
impl Stream for Cipher {
    fn XORKeyStream(&mut self, dst: &mut slice<byte>, src: slice<byte>) {
        // Go: if len(src) == 0 { return }
        if src.Len() == 0 {
            return;
        }
        // Go: if alias.InexactOverlap(dst[:len(src)], src) { panic(...) }
        // — omitted, see module-level deviation note.
        //
        // Go: i, j := c.i, c.j
        let mut i = self.i;
        let mut j = self.j;
        // Go: _ = dst[len(src)-1]
        // — Go's bounds-check hint; goish slice<T> indexing already
        //   panics on out-of-bounds, so we skip the synthetic touch.
        //
        // Go: dst = dst[:len(src)]
        //     for k, v := range src { ... }
        let n = src.Len();
        let mut k: int = 0;
        while k < n {
            let v = src[k];
            // Go: i += 1
            i = i.wrapping_add(1);
            // Go: x := c.s[i]
            let x = self.s[i as usize];
            // Go: j += uint8(x)
            j = j.wrapping_add(x as u8);
            // Go: y := c.s[j]
            let y = self.s[j as usize];
            // Go: c.s[i], c.s[j] = y, x
            self.s[i as usize] = y;
            self.s[j as usize] = x;
            // Go: dst[k] = v ^ uint8(c.s[uint8(x+y)])
            let idx = (x as u8).wrapping_add(y as u8) as usize;
            dst[k] = v ^ self.s[idx] as u8;
            k += 1;
        }
        // Go: c.i, c.j = i, j
        self.i = i;
        self.j = j;
    }
}
