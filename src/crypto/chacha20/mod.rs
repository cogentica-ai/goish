// crypto/chacha20 — ChaCha20 stream cipher.
//
// Port of:
//   vendor/golang.org/x/crypto/chacha20/chacha_generic.go  (399 LOC)
//   vendor/golang.org/x/crypto/chacha20/xor.go             (42 LOC)
//
// Generic (portable) implementation only — no architecture-specific asm.
// Implements the cipher.Stream interface.
//
// Slim deviations from upstream:
//   * `NewUnauthenticatedCipher` returns `(Option<Cipher>, error)`.
//   * No alias.InexactOverlap check (goish slice semantics).
//   * `bufSize` fixed at 64 bytes (single-block) for no_std simplicity.
//   * No precomputed-first-round optimization (correctness over perf in this port).

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use crate::errors::{ErrorTrait, error};
use crate::goslice::slice;
use crate::types::byte;

// KeySize is the size of the key used by this cipher, in bytes.
pub const KeySize: usize = 32;
// NonceSize is the size of the nonce used with the standard variant of this cipher.
pub const NonceSize: usize = 12;
// NonceSizeX is the size of the nonce used with the XChaCha20 variant.
pub const NonceSizeX: usize = 24;

const blockSize: usize = 64;

// The constant first 4 words of the ChaCha20 state.
const j0: u32 = 0x61707865; // "expa"
const j1: u32 = 0x3320646e; // "nd 3"
const j2: u32 = 0x79622d32; // "2-by"
const j3: u32 = 0x6b206574; // "te k"

/// ChaCha20 stream cipher. Implements `cipher::Stream`.
pub struct Cipher {
    key: [u32; 8],
    counter: u32,
    nonce: [u32; 3],
    // Buffered key stream bytes from a previous XORKeyStream call.
    // buf[bufSize - len .. bufSize] are valid.
    buf: [byte; blockSize],
    buf_len: usize,
    overflow: bool,
}

#[inline(always)]
fn quarterRound(a: u32, b: u32, c: u32, d: u32) -> (u32, u32, u32, u32) {
    let a = a.wrapping_add(b); let d = d ^ a; let d = d.rotate_left(16);
    let c = c.wrapping_add(d); let b = b ^ c; let b = b.rotate_left(12);
    let a = a.wrapping_add(b); let d = d ^ a; let d = d.rotate_left(8);
    let c = c.wrapping_add(d); let b = b ^ c; let b = b.rotate_left(7);
    (a, b, c, d)
}

/// Read a little-endian u32 from 4 bytes.
#[inline(always)]
fn read_u32_le(b: &[byte]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// XOR `src` 4-byte chunk with (a+b) and write little-endian to `dst`.
#[inline(always)]
fn addXor(dst: &mut [byte], src: &[byte], a: u32, b: u32) {
    let v = read_u32_le(&src[..4]) ^ a.wrapping_add(b);
    dst[..4].copy_from_slice(&v.to_le_bytes());
}

impl Cipher {
    /// Generate one 64-byte block of key stream into `out`,
    /// using the current counter value.
    fn generate_block(&self, out: &mut [byte; blockSize]) {
        let (c0, c1, c2, c3) = (j0, j1, j2, j3);
        let (c4, c5, c6, c7) = (self.key[0], self.key[1], self.key[2], self.key[3]);
        let (c8, c9, c10, c11) = (self.key[4], self.key[5], self.key[6], self.key[7]);
        let (c12, c13, c14, c15) = (self.counter, self.nonce[0], self.nonce[1], self.nonce[2]);

        let (mut x0, mut x1, mut x2, mut x3) = (c0, c1, c2, c3);
        let (mut x4, mut x5, mut x6, mut x7) = (c4, c5, c6, c7);
        let (mut x8, mut x9, mut x10, mut x11) = (c8, c9, c10, c11);
        let (mut x12, mut x13, mut x14, mut x15) = (c12, c13, c14, c15);

        for _ in 0..10 {
            // Column rounds
            let (a, b, c, d) = quarterRound(x0, x4, x8, x12);   x0=a; x4=b; x8=c; x12=d;
            let (a, b, c, d) = quarterRound(x1, x5, x9, x13);   x1=a; x5=b; x9=c; x13=d;
            let (a, b, c, d) = quarterRound(x2, x6, x10, x14);  x2=a; x6=b; x10=c; x14=d;
            let (a, b, c, d) = quarterRound(x3, x7, x11, x15);  x3=a; x7=b; x11=c; x15=d;
            // Diagonal rounds
            let (a, b, c, d) = quarterRound(x0, x5, x10, x15);  x0=a; x5=b; x10=c; x15=d;
            let (a, b, c, d) = quarterRound(x1, x6, x11, x12);  x1=a; x6=b; x11=c; x12=d;
            let (a, b, c, d) = quarterRound(x2, x7, x8, x13);   x2=a; x7=b; x8=c; x13=d;
            let (a, b, c, d) = quarterRound(x3, x4, x9, x14);   x3=a; x4=b; x9=c; x14=d;
        }

        // Add initial state back
        let buf_ptr = out.as_mut_ptr();
        // safety: out is 64 bytes; we write all 64 bytes below
        macro_rules! write_word {
            ($offset:expr, $val:expr, $initial:expr) => {
                let v = ($val.wrapping_add($initial)).to_le_bytes();
                unsafe {
                    core::ptr::write(buf_ptr.add($offset * 4 + 0), v[0]);
                    core::ptr::write(buf_ptr.add($offset * 4 + 1), v[1]);
                    core::ptr::write(buf_ptr.add($offset * 4 + 2), v[2]);
                    core::ptr::write(buf_ptr.add($offset * 4 + 3), v[3]);
                }
            }
        }
        write_word!(0, x0, c0);
        write_word!(1, x1, c1);
        write_word!(2, x2, c2);
        write_word!(3, x3, c3);
        write_word!(4, x4, c4);
        write_word!(5, x5, c5);
        write_word!(6, x6, c6);
        write_word!(7, x7, c7);
        write_word!(8, x8, c8);
        write_word!(9, x9, c9);
        write_word!(10, x10, c10);
        write_word!(11, x11, c11);
        write_word!(12, x12, c12);
        write_word!(13, x13, c13);
        write_word!(14, x14, c14);
        write_word!(15, x15, c15);
    }

    /// XOR key stream into dst/src.
    pub fn XORKeyStream(&mut self, dst: &mut [byte], src: &[byte]) {
        if src.is_empty() { return; }
        if dst.len() < src.len() {
            panic!("chacha20: output smaller than input");
        }

        let mut pos = 0usize;

        // Drain buffered keystream first
        if self.buf_len > 0 {
            let avail = self.buf_len;
            let take = if avail < src.len() { avail } else { src.len() };
            let buf_start = blockSize - self.buf_len;
            for i in 0..take {
                dst[pos + i] = src[pos + i] ^ self.buf[buf_start + i];
            }
            self.buf_len -= take;
            pos += take;
            if pos >= src.len() { return; }
        }

        // Full blocks
        while pos + blockSize <= src.len() {
            if self.overflow { panic!("chacha20: counter overflow"); }
            let mut block = [0u8; blockSize];
            self.generate_block(&mut block);
            for i in 0..blockSize {
                dst[pos + i] = src[pos + i] ^ block[i];
            }
            self.counter = self.counter.wrapping_add(1);
            if self.counter == 0 { self.overflow = true; }
            pos += blockSize;
        }

        // Partial block — fill buffer
        // Matches Go's layout: unused bytes live at buf[blockSize-buf_len..] (high indices).
        if pos < src.len() {
            if self.overflow { panic!("chacha20: counter overflow"); }
            let mut block = [0u8; blockSize];
            self.generate_block(&mut block);
            self.buf = block;
            self.counter = self.counter.wrapping_add(1);
            if self.counter == 0 { self.overflow = true; }
            let rem = src.len() - pos;
            for i in 0..rem {
                dst[pos + i] = src[pos + i] ^ self.buf[i];
            }
            // Leave unused bytes in place at buf[rem..blockSize].
            // The drain code reads from buf[blockSize - buf_len..] = buf[rem..].
            self.buf_len = blockSize - rem;
        }
    }

    /// SetCounter changes the counter. Panics if counter < current output counter.
    pub fn SetCounter(&mut self, counter: u32) {
        if self.overflow || counter < self.counter {
            panic!("chacha20: SetCounter attempted to rollback counter");
        }
        self.counter = counter;
        self.buf_len = 0;
    }
}

/// `chacha20.NewUnauthenticatedCipher` — creates a new ChaCha20 cipher.
/// Returns `(Option<Cipher>, error)`.
///
/// Accepts a 12-byte (standard) or 24-byte (XChaCha20) nonce.
pub fn NewUnauthenticatedCipher(key: slice<byte>, nonce: slice<byte>) -> (Option<Cipher>, error) {
    let key_v = key.__into_vec();
    let nonce_v = nonce.__into_vec();
    new_cipher_inner(&key_v, &nonce_v)
}

/// Same but from raw slices — used internally.
pub fn new_from_bytes(key: &[byte], nonce: &[byte]) -> (Option<Cipher>, error) {
    new_cipher_inner(key, nonce)
}

fn new_cipher_inner(key: &[byte], nonce: &[byte]) -> (Option<Cipher>, error) {
    if key.len() != KeySize {
        return (None, crate::errors::New("chacha20: wrong key size"));
    }

    let (actual_key, actual_nonce): (alloc::vec::Vec<byte>, alloc::vec::Vec<byte>);

    if nonce.len() == NonceSizeX {
        // XChaCha20: derive subkey via HChaCha20
        let (subkey, err) = hchacha20(key, &nonce[..16]);
        if !err.IsNil() {
            return (None, err);
        }
        actual_key = subkey;
        let mut cn = alloc::vec![0u8; NonceSize];
        cn[4..12].copy_from_slice(&nonce[16..24]);
        actual_nonce = cn;
    } else if nonce.len() == NonceSize {
        actual_key = key.to_vec();
        actual_nonce = nonce.to_vec();
    } else {
        return (None, crate::errors::New("chacha20: wrong nonce size"));
    }

    let c = Cipher {
        key: [
            read_u32_le(&actual_key[0..4]),
            read_u32_le(&actual_key[4..8]),
            read_u32_le(&actual_key[8..12]),
            read_u32_le(&actual_key[12..16]),
            read_u32_le(&actual_key[16..20]),
            read_u32_le(&actual_key[20..24]),
            read_u32_le(&actual_key[24..28]),
            read_u32_le(&actual_key[28..32]),
        ],
        counter: 0,
        nonce: [
            read_u32_le(&actual_nonce[0..4]),
            read_u32_le(&actual_nonce[4..8]),
            read_u32_le(&actual_nonce[8..12]),
        ],
        buf: [0u8; blockSize],
        buf_len: 0,
        overflow: false,
    };
    (Some(c), crate::errors::nil)
}

/// `HChaCha20` — derives a 32-byte key from a 32-byte key and 16-byte nonce.
/// Used to build XChaCha20.
pub fn HChaCha20(key: slice<byte>, nonce: slice<byte>) -> (slice<byte>, error) {
    let k = key.__into_vec();
    let n = nonce.__into_vec();
    let (out, err) = hchacha20(&k, &n);
    (slice::<byte>::__from_vec(out), err)
}

fn hchacha20(key: &[byte], nonce: &[byte]) -> (alloc::vec::Vec<byte>, error) {
    if key.len() != KeySize {
        return (alloc::vec![], crate::errors::New("chacha20: wrong HChaCha20 key size"));
    }
    if nonce.len() != 16 {
        return (alloc::vec![], crate::errors::New("chacha20: wrong HChaCha20 nonce size"));
    }

    let (mut x0, mut x1, mut x2, mut x3) = (j0, j1, j2, j3);
    let mut x4  = read_u32_le(&key[0..4]);
    let mut x5  = read_u32_le(&key[4..8]);
    let mut x6  = read_u32_le(&key[8..12]);
    let mut x7  = read_u32_le(&key[12..16]);
    let mut x8  = read_u32_le(&key[16..20]);
    let mut x9  = read_u32_le(&key[20..24]);
    let mut x10 = read_u32_le(&key[24..28]);
    let mut x11 = read_u32_le(&key[28..32]);
    let mut x12 = read_u32_le(&nonce[0..4]);
    let mut x13 = read_u32_le(&nonce[4..8]);
    let mut x14 = read_u32_le(&nonce[8..12]);
    let mut x15 = read_u32_le(&nonce[12..16]);

    for _ in 0..10 {
        // Column rounds
        let (a,b,c,d) = quarterRound(x0,x4,x8,x12);   x0=a;x4=b;x8=c;x12=d;
        let (a,b,c,d) = quarterRound(x1,x5,x9,x13);   x1=a;x5=b;x9=c;x13=d;
        let (a,b,c,d) = quarterRound(x2,x6,x10,x14);  x2=a;x6=b;x10=c;x14=d;
        let (a,b,c,d) = quarterRound(x3,x7,x11,x15);  x3=a;x7=b;x11=c;x15=d;
        // Diagonal rounds
        let (a,b,c,d) = quarterRound(x0,x5,x10,x15);  x0=a;x5=b;x10=c;x15=d;
        let (a,b,c,d) = quarterRound(x1,x6,x11,x12);  x1=a;x6=b;x11=c;x12=d;
        let (a,b,c,d) = quarterRound(x2,x7,x8,x13);   x2=a;x7=b;x8=c;x13=d;
        let (a,b,c,d) = quarterRound(x3,x4,x9,x14);   x3=a;x4=b;x9=c;x14=d;
    }

    let mut out = alloc::vec![0u8; 32];
    out[0..4].copy_from_slice(&x0.to_le_bytes());
    out[4..8].copy_from_slice(&x1.to_le_bytes());
    out[8..12].copy_from_slice(&x2.to_le_bytes());
    out[12..16].copy_from_slice(&x3.to_le_bytes());
    out[16..20].copy_from_slice(&x12.to_le_bytes());
    out[20..24].copy_from_slice(&x13.to_le_bytes());
    out[24..28].copy_from_slice(&x14.to_le_bytes());
    out[28..32].copy_from_slice(&x15.to_le_bytes());
    (out, crate::errors::nil)
}
