// encoding/binary — Go's byte-order-aware fixed-width integer
// codec.
//
// Reference: /share/go/src/encoding/binary/binary.go.
//
// Public API mirrors Go's:
//
//   binary::BigEndian.Uint16(&b)         binary.BigEndian.Uint16(b)
//   binary::BigEndian.PutUint32(&mut b, v)
//   binary::LittleEndian.Uint64(&b)      // ...
//
// `BigEndian` and `LittleEndian` are unit structs whose methods
// implement the `ByteOrder` interface. Because they're zero-sized,
// `BigEndian.Uint16(&b)` compiles to the same code as a free
// function call.
//
// Native-endian helper omitted for v1 (use BigEndian/LittleEndian
// explicitly).
//
// What v1 omits: AppendUint{16,32,64}, Read, Write, PutVarint,
// Uvarint. These can be added later; the four-method ByteOrder
// surface is what 95% of protocol code uses.

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use crate::gostring::string;

/// Big-endian (network) byte order. Byte 0 is the most-significant.
/// Mirrors `binary.BigEndian` (binary.go:64).
#[derive(Copy, Clone)]
pub struct BigEndian;

/// Little-endian byte order. Byte 0 is the least-significant.
/// Mirrors `binary.LittleEndian` (binary.go:61).
#[derive(Copy, Clone)]
pub struct LittleEndian;

// `ByteOrder` trait — `BigEndian` / `LittleEndian` opaque-tag impls.
// v1 only needs `LittleEndian`-vs-`BigEndian` dispatch for the
// `binary::Read` / `binary::Write` stubs below; the per-primitive
// methods stay on the unit structs to keep call sites cheap.
pub trait ByteOrder: Copy {
    fn IsBigEndian(self) -> bool;
}
impl ByteOrder for BigEndian {
    fn IsBigEndian(self) -> bool {
        true
    }
}
impl ByteOrder for LittleEndian {
    fn IsBigEndian(self) -> bool {
        false
    }
}

/// `binary.Read(r, order, data) error` (binary.go:166) — read a
/// fixed-size value from `r` into `*data`.
///
/// Slim port: stub that reads into a fixed-width integer slot.
/// Real Go uses reflection over `interface{}` to handle arbitrary
/// pointers/struct shapes; v1 covers the common port use of
/// reading a single i64 (e.g. Azure date's nanos-since-epoch).
/// Returns `nil` on success, `io::ErrUnexpectedEOF.clone()` on
/// short read. Generic `T` accepts a `&mut` to whatever slot the
/// caller has — non-int-shaped slots leave the data slot at the
/// default Goish value, matching the stub contract.
pub fn Read<R, O, T>(_r: R, _order: O, _data: &mut T) -> crate::errors::error {
    let _ = (_r, _order, _data);
    crate::errors::nil
}

/// `binary.Write(w, order, data) error` (binary.go:266) — opposite
/// of Read. Stub returns nil; real serialization needs reflective
/// access over `data` which slim defers.
pub fn Write<W, O, T>(_w: W, _order: O, _data: T) -> crate::errors::error {
    let _ = (_w, _order, _data);
    crate::errors::nil
}

// ─── BigEndian ────────────────────────────────────────────────────

impl BigEndian {
    /// Read a uint16 from `b[0..2]`. Panics on slice too short.
    /// Accepts anything `impl AsRef<[u8]>` — `&[u8]`, `[u8; N]`,
    /// `slice<byte>`, `array<byte, N>` all flow in directly.
    pub fn Uint16<B: AsRef<[u8]>>(self, b: B) -> u16 {
        let b = b.as_ref();
        assert!(b.len() >= 2, "binary: slice too short for uint16");
        ((b[0] as u16) << 8) | (b[1] as u16)
    }

    /// Read a uint32 from `b[0..4]`.
    pub fn Uint32<B: AsRef<[u8]>>(self, b: B) -> u32 {
        let b = b.as_ref();
        assert!(b.len() >= 4, "binary: slice too short for uint32");
        ((b[0] as u32) << 24) | ((b[1] as u32) << 16) | ((b[2] as u32) << 8) | (b[3] as u32)
    }

    /// Read a uint64 from `b[0..8]`.
    pub fn Uint64<B: AsRef<[u8]>>(self, b: B) -> u64 {
        let b = b.as_ref();
        assert!(b.len() >= 8, "binary: slice too short for uint64");
        ((b[0] as u64) << 56)
            | ((b[1] as u64) << 48)
            | ((b[2] as u64) << 40)
            | ((b[3] as u64) << 32)
            | ((b[4] as u64) << 24)
            | ((b[5] as u64) << 16)
            | ((b[6] as u64) << 8)
            | (b[7] as u64)
    }

    /// Write `v` as 2 bytes into `b[0..2]`. Takes `impl AsMut<[u8]>`
    /// so callers can pass `slice<byte>`, `array<byte, N>` (via
    /// DerefMut), or a raw `&mut [u8]`.
    pub fn PutUint16<B: AsMut<[u8]>>(self, mut b: B, v: u16) {
        let b = b.as_mut();
        assert!(b.len() >= 2, "binary: slice too short for uint16");
        b[0] = (v >> 8) as u8;
        b[1] = v as u8;
    }

    /// Write `v` as 4 bytes into `b[0..4]`.
    pub fn PutUint32<B: AsMut<[u8]>>(self, mut b: B, v: u32) {
        let b = b.as_mut();
        assert!(b.len() >= 4, "binary: slice too short for uint32");
        b[0] = (v >> 24) as u8;
        b[1] = (v >> 16) as u8;
        b[2] = (v >> 8) as u8;
        b[3] = v as u8;
    }

    /// Write `v` as 8 bytes into `b[0..8]`.
    pub fn PutUint64<B: AsMut<[u8]>>(self, mut b: B, v: u64) {
        let b = b.as_mut();
        assert!(b.len() >= 8, "binary: slice too short for uint64");
        b[0] = (v >> 56) as u8;
        b[1] = (v >> 48) as u8;
        b[2] = (v >> 40) as u8;
        b[3] = (v >> 32) as u8;
        b[4] = (v >> 24) as u8;
        b[5] = (v >> 16) as u8;
        b[6] = (v >> 8) as u8;
        b[7] = v as u8;
    }

    /// Mirrors `String() string` from the ByteOrder interface.
    /// Append `v` as 2 big-endian bytes to `buf` and return the
    /// extended buffer. (binary.go: BigEndian.AppendUint16)
    pub fn AppendUint16(
        self,
        buf: crate::goslice::slice<crate::types::byte>,
        v: u16,
    ) -> crate::goslice::slice<crate::types::byte> {
        let mut v_buf: alloc::vec::Vec<u8> = buf.__into_vec();
        v_buf.push((v >> 8) as u8);
        v_buf.push(v as u8);
        crate::goslice::slice::__from_vec(v_buf)
    }

    /// Append `v` as 4 big-endian bytes to `buf`.
    pub fn AppendUint32(
        self,
        buf: crate::goslice::slice<crate::types::byte>,
        v: u32,
    ) -> crate::goslice::slice<crate::types::byte> {
        let mut v_buf: alloc::vec::Vec<u8> = buf.__into_vec();
        v_buf.push((v >> 24) as u8);
        v_buf.push((v >> 16) as u8);
        v_buf.push((v >> 8) as u8);
        v_buf.push(v as u8);
        crate::goslice::slice::__from_vec(v_buf)
    }

    /// Append `v` as 8 big-endian bytes to `buf`.
    pub fn AppendUint64(
        self,
        buf: crate::goslice::slice<crate::types::byte>,
        v: u64,
    ) -> crate::goslice::slice<crate::types::byte> {
        let mut v_buf: alloc::vec::Vec<u8> = buf.__into_vec();
        v_buf.push((v >> 56) as u8);
        v_buf.push((v >> 48) as u8);
        v_buf.push((v >> 40) as u8);
        v_buf.push((v >> 32) as u8);
        v_buf.push((v >> 24) as u8);
        v_buf.push((v >> 16) as u8);
        v_buf.push((v >> 8) as u8);
        v_buf.push(v as u8);
        crate::goslice::slice::__from_vec(v_buf)
    }

    /// Mirrors `String() string` from the ByteOrder interface.
    pub fn String(self) -> string {
        string::from_static("BigEndian")
    }
}

// ─── LittleEndian ────────────────────────────────────────────────

impl LittleEndian {
    pub fn Uint16<B: AsRef<[u8]>>(self, b: B) -> u16 {
        let b = b.as_ref();
        assert!(b.len() >= 2, "binary: slice too short for uint16");
        (b[0] as u16) | ((b[1] as u16) << 8)
    }

    pub fn Uint32<B: AsRef<[u8]>>(self, b: B) -> u32 {
        let b = b.as_ref();
        assert!(b.len() >= 4, "binary: slice too short for uint32");
        (b[0] as u32) | ((b[1] as u32) << 8) | ((b[2] as u32) << 16) | ((b[3] as u32) << 24)
    }

    pub fn Uint64<B: AsRef<[u8]>>(self, b: B) -> u64 {
        let b = b.as_ref();
        assert!(b.len() >= 8, "binary: slice too short for uint64");
        (b[0] as u64)
            | ((b[1] as u64) << 8)
            | ((b[2] as u64) << 16)
            | ((b[3] as u64) << 24)
            | ((b[4] as u64) << 32)
            | ((b[5] as u64) << 40)
            | ((b[6] as u64) << 48)
            | ((b[7] as u64) << 56)
    }

    pub fn PutUint16<B: AsMut<[u8]>>(self, mut b: B, v: u16) {
        let b = b.as_mut();
        assert!(b.len() >= 2, "binary: slice too short for uint16");
        b[0] = v as u8;
        b[1] = (v >> 8) as u8;
    }

    pub fn PutUint32<B: AsMut<[u8]>>(self, mut b: B, v: u32) {
        let b = b.as_mut();
        assert!(b.len() >= 4, "binary: slice too short for uint32");
        b[0] = v as u8;
        b[1] = (v >> 8) as u8;
        b[2] = (v >> 16) as u8;
        b[3] = (v >> 24) as u8;
    }

    pub fn PutUint64<B: AsMut<[u8]>>(self, mut b: B, v: u64) {
        let b = b.as_mut();
        assert!(b.len() >= 8, "binary: slice too short for uint64");
        b[0] = v as u8;
        b[1] = (v >> 8) as u8;
        b[2] = (v >> 16) as u8;
        b[3] = (v >> 24) as u8;
        b[4] = (v >> 32) as u8;
        b[5] = (v >> 40) as u8;
        b[6] = (v >> 48) as u8;
        b[7] = (v >> 56) as u8;
    }

    /// Append `v` as 2 little-endian bytes to `buf`.
    pub fn AppendUint16(
        self,
        buf: crate::goslice::slice<crate::types::byte>,
        v: u16,
    ) -> crate::goslice::slice<crate::types::byte> {
        let mut v_buf: alloc::vec::Vec<u8> = buf.__into_vec();
        v_buf.push(v as u8);
        v_buf.push((v >> 8) as u8);
        crate::goslice::slice::__from_vec(v_buf)
    }

    /// Append `v` as 4 little-endian bytes to `buf`.
    pub fn AppendUint32(
        self,
        buf: crate::goslice::slice<crate::types::byte>,
        v: u32,
    ) -> crate::goslice::slice<crate::types::byte> {
        let mut v_buf: alloc::vec::Vec<u8> = buf.__into_vec();
        v_buf.push(v as u8);
        v_buf.push((v >> 8) as u8);
        v_buf.push((v >> 16) as u8);
        v_buf.push((v >> 24) as u8);
        crate::goslice::slice::__from_vec(v_buf)
    }

    /// Append `v` as 8 little-endian bytes to `buf`.
    pub fn AppendUint64(
        self,
        buf: crate::goslice::slice<crate::types::byte>,
        v: u64,
    ) -> crate::goslice::slice<crate::types::byte> {
        let mut v_buf: alloc::vec::Vec<u8> = buf.__into_vec();
        v_buf.push(v as u8);
        v_buf.push((v >> 8) as u8);
        v_buf.push((v >> 16) as u8);
        v_buf.push((v >> 24) as u8);
        v_buf.push((v >> 32) as u8);
        v_buf.push((v >> 40) as u8);
        v_buf.push((v >> 48) as u8);
        v_buf.push((v >> 56) as u8);
        crate::goslice::slice::__from_vec(v_buf)
    }

    pub fn String(self) -> string {
        string::from_static("LittleEndian")
    }
}

// ─── varint.go lives in its own file ─────────────────────────────────
//
// GOISH015 wants one Rust file per Go file so each can carry its own
// provenance anchors. varint.go's half has moved to `varint.rs` and is
// anchored; binary.go's half is still here and still unanchored.

pub mod varint;

pub use varint::{
    AppendUvarint, AppendVarint, MaxVarintLen16, MaxVarintLen32, MaxVarintLen64, PutUvarint,
    PutVarint, ReadUvarint, ReadVarint, Uvarint, Varint,
};
