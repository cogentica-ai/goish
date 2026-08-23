// go: file crypto/rc4/rc4.go decls: KeySizeError.Error, NewCipher, Cipher.Reset, Cipher.XORKeyStream
//
// crypto/rc4 — RC4 stream cipher. Verbatim port of rc4.go @ Go 1.25.5.
//
// RC4 is cryptographically broken; ported for completeness and to
// validate the `cipher::Stream` trait surface.
//
// Deviations from upstream, each deliberate and load-bearing:
//
//   * `NewCipher` returns `(Option<Cipher>, error)` where Go returns
//     `(*Cipher, error)`. Goish has no nullable pointer; `Option<Cipher>`
//     carrying the value (or `None` on error) is the equivalent shape.
//   * No `fips140only.Enabled` branch — goish has no FIPS 140-3
//     service-indicator infrastructure, so the guard has no state to read.
//   * No `alias.InexactOverlap` panic — goish `slice<T>` does not expose
//     the pointer arithmetic that check needs. Callers must respect
//     "dst and src must overlap entirely or not at all" by contract.
//   * `Cipher` is a value type; `cipher::Stream` takes `&mut self`, which
//     matches Go's `*Cipher` receiver.

#![allow(non_snake_case)]

extern crate alloc;

use crate::convert::{uint32, uint8};
use crate::crypto::cipher::Stream;
use crate::errors::{error, nil, ErrorTrait, Wrap};
use crate::goslice::slice;
use crate::gostring::string;
use crate::strconv;
use crate::types::{byte, int};

// go: sdk 1.25.5 crypto/rc4/rc4.go:20-23 Cipher
//
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

// go: sdk 1.25.5 crypto/rc4/rc4.go:25 KeySizeError
//
//   type KeySizeError int
/// `rc4.KeySizeError` — error returned by `NewCipher` when the key
/// length is outside `[1, 256]`.
#[derive(Clone)]
pub struct KeySizeError(pub int);

impl ErrorTrait for KeySizeError {
    // go: sdk 1.25.5 crypto/rc4/rc4.go:27-29 KeySizeError.Error
    //
    //   func (k KeySizeError) Error() string {
    //       return "crypto/rc4: invalid key size " + strconv.Itoa(int(k))
    //   }
    fn Error(&self) -> string {
        let mut s = string::from_static("crypto/rc4: invalid key size ");
        s = s + strconv::Itoa(self.0);
        return s;
    }
}

// go: sdk 1.25.5 crypto/rc4/rc4.go:33-51 NewCipher
//
//   func NewCipher(key []byte) (*Cipher, error)
/// `rc4.NewCipher(key)` — create and return a new `Cipher`. The key
/// argument should be the RC4 key, at least 1 byte and at most 256 bytes.
///
/// On success returns `(Some(cipher), nil)`; on error `(None, KeySizeError)`.
pub fn NewCipher(key: slice<byte>) -> (Option<Cipher>, error) {
    // Go: k := len(key)
    let k = key.Len();
    // Go: if k < 1 || k > 256 { return nil, KeySizeError(k) }
    if k < 1 || k > 256 {
        return (None, Wrap(KeySizeError(k)));
    }
    // Go: var c Cipher
    let mut c = Cipher {
        s: [0u32; 256],
        i: 0,
        j: 0,
    };
    // Go: for i := 0; i < 256; i++ { c.s[i] = uint32(i) }
    let mut i: int = 0;
    while i < 256 {
        c.s[i as usize] = uint32(i);
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
            .wrapping_add(uint8(c.s[i as usize]))
            .wrapping_add(key[i % k]);
        let ii = i as usize;
        let jj = j as usize;
        let tmp = c.s[ii];
        c.s[ii] = c.s[jj];
        c.s[jj] = tmp;
        i += 1;
    }
    // Go: return &c, nil
    return (Some(c), nil);
}

impl Cipher {
    // go: sdk 1.25.5 crypto/rc4/rc4.go:57-62 Cipher.Reset
    //
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

// Implements `cipher::Stream` so `rc4::Cipher` works wherever the trait
// is required (Go: `*Cipher` satisfies `cipher.Stream` structurally).
impl Stream for Cipher {
    // go: sdk 1.25.5 crypto/rc4/rc4.go:66-85 Cipher.XORKeyStream
    //
    //   func (c *Cipher) XORKeyStream(dst, src []byte)
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
        //   panics on out-of-bounds, so the synthetic touch is dropped.
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
            j = j.wrapping_add(uint8(x));
            // Go: y := c.s[j]
            let y = self.s[j as usize];
            // Go: c.s[i], c.s[j] = y, x
            self.s[i as usize] = y;
            self.s[j as usize] = x;
            // Go: dst[k] = v ^ uint8(c.s[uint8(x+y)])
            let idx = uint8(x).wrapping_add(uint8(y)) as usize;
            dst[k] = v ^ uint8(self.s[idx]);
            k += 1;
        }
        // Go: c.i, c.j = i, j
        self.i = i;
        self.j = j;
    }
}
