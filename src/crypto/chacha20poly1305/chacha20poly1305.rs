// go: file vendor/golang.org/x/crypto/chacha20poly1305/chacha20poly1305.go decls: New, chacha20poly1305.NonceSize, chacha20poly1305.Overhead, chacha20poly1305.Seal, chacha20poly1305.Open
// goishlint:ignore GOISH018 sliceForAppend — Go's Seal/Open carve the
//     output with sliceForAppend, which returns two slices, the second
//     aliasing into the first. goish cannot hand out two live views of
//     one buffer; Seal and Open build the output vector directly. The
//     same divergence is recorded, with the same reason, on the
//     sliceForAppend port in fips140/aes/gcm.
// goishlint:ignore GOISH021 NonceSizeX — the 24-byte XChaCha20 nonce.
//     It is declared in this Go file but belongs to xchacha20poly1305.go,
//     which goish does not port: NewX and the HChaCha20 derivation are
//     both absent, so a constant naming their nonce width would be the
//     only trace of a cipher that is not here.
// goishlint:ignore GOISH021 chacha20poly1305 — Go's unexported struct is
//     spelled `ChaCha20Poly1305` here, because goish returns the
//     concrete type where Go returns the `cipher.AEAD` interface.
//
// crypto/chacha20poly1305 — ChaCha20-Poly1305 AEAD, RFC 8439.
//
// The exported half: key sizes, the AEAD type, New, and the four
// cipher.AEAD methods. The generic seal/open bodies those methods
// delegate to are in `chacha20poly1305_generic.rs`, one `.rs` per
// `.go` as Go splits them.
//
// Slim deviations:
//   * `New` returns `(Option<ChaCha20Poly1305>, error)` where Go
//     returns `(cipher.AEAD, error)` — goish hands back the concrete
//     type.
//   * `Seal`/`Open` take and return `slice<byte>`; the generic bodies
//     work on `&[byte]`/`Vec<byte>` internally.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;
use alloc::vec::Vec;

use crate::crypto::cipher::AEAD as AEADTrait;
use crate::errors::{self, error};
use crate::goslice::slice;
use crate::types::{byte, int};

/// KeySize is the size of the key, in bytes.
pub const KeySize: usize = 32;
/// NonceSize is the size of the nonce, in bytes.
pub const NonceSize: usize = 12;
/// Overhead is the Poly1305 tag size — the difference between ciphertext and plaintext lengths.
pub const Overhead: usize = 16;

/// `chacha20poly1305.ChaCha20Poly1305` — AEAD cipher.
#[derive(Clone)]
pub struct ChaCha20Poly1305 {
    // `pub(super)` so the generic seal/open bodies, which Go keeps in
    // their own file too, can read it.
    pub(super) key: [byte; KeySize],
}

// go: none — goish idiom: Go declares `var errOpen = errors.New(…)` as a
// package-level sentinel and returns it from both the short-ciphertext
// and failed-authentication paths. goish built the message inline at
// each of those two sites, so the two errors were distinct values and
// neither could ever match the other by identity; `errors::Is` compares
// by Arc pointer. Same shape, and same fix, as gcm.rs's errOpen.
// Go: `var errOpen = errors.New("chacha20poly1305: message authentication failed")`
// (a plain `//`, not `///`: var! notes that per-entry rustdoc inside
// the block is dropped and rustc warns on it.)
crate::var! {
    pub(crate) errOpen: error = "chacha20poly1305: message authentication failed";
}

// go: sdk 1.25.5 vendor/golang.org/x/crypto/chacha20poly1305/chacha20poly1305.go:40-47 New
pub fn New(key: slice<byte>) -> (Option<ChaCha20Poly1305>, error) {
    let v = key.__into_vec();
    if v.len() != KeySize {
        return (None, errors::New("chacha20poly1305: bad key length"));
    }
    let mut k = [0u8; KeySize];
    k.copy_from_slice(&v);
    return (Some(ChaCha20Poly1305 { key: k }), errors::nil);
}

// Implement cipher::AEAD for ChaCha20Poly1305
impl AEADTrait for ChaCha20Poly1305 {
    // go: sdk 1.25.5 vendor/golang.org/x/crypto/chacha20poly1305/chacha20poly1305.go:49-51 chacha20poly1305.NonceSize
    fn NonceSize(&self) -> int {
        return crate::int(NonceSize);
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/chacha20poly1305/chacha20poly1305.go:53-55 chacha20poly1305.Overhead
    fn Overhead(&self) -> int {
        return crate::int(Overhead);
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/chacha20poly1305/chacha20poly1305.go:57-67 chacha20poly1305.Seal
    fn Seal(
        &self,
        dst: slice<byte>,
        nonce: slice<byte>,
        plaintext: slice<byte>,
        additional_data: slice<byte>,
    ) -> slice<byte> {
        let nonce_v = nonce.__into_vec();
        let plaintext_v = plaintext.__into_vec();
        let aad_v = additional_data.__into_vec();
        let dst_v = dst.__into_vec();

        if nonce_v.len() != NonceSize {
            panic!("chacha20poly1305: bad nonce length passed to Seal");
        }

        return self.seal_generic(&dst_v, &nonce_v, &plaintext_v, &aad_v);
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/chacha20poly1305/chacha20poly1305.go:71-83 chacha20poly1305.Open
    fn Open(
        &self,
        dst: slice<byte>,
        nonce: slice<byte>,
        ciphertext: slice<byte>,
        additional_data: slice<byte>,
    ) -> (slice<byte>, error) {
        let nonce_v = nonce.__into_vec();
        let ciphertext_v = ciphertext.__into_vec();
        let aad_v = additional_data.__into_vec();
        let dst_v = dst.__into_vec();

        if nonce_v.len() != NonceSize {
            panic!("chacha20poly1305: bad nonce length passed to Open");
        }
        if ciphertext_v.len() < 16 {
            // Go: return nil, errOpen
            return (slice::<byte>::__from_vec(Vec::new()), errOpen.into());
        }

        return self.open_generic(&dst_v, &nonce_v, &ciphertext_v, &aad_v);
    }
}
