// go: file encoding/binary/binary.go decls: bigEndian.Uint16, littleEndian.Uint16, bigEndian.Uint32, littleEndian.Uint32, bigEndian.Uint64, littleEndian.Uint64, bigEndian.PutUint16, littleEndian.PutUint16, bigEndian.PutUint32, littleEndian.PutUint32, bigEndian.PutUint64, littleEndian.PutUint64, bigEndian.AppendUint16, littleEndian.AppendUint16, bigEndian.AppendUint32, littleEndian.AppendUint32, bigEndian.AppendUint64, littleEndian.AppendUint64, bigEndian.String, littleEndian.String, Read, Write, Size, Append, Encode, Decode
// goishlint:ignore GOISH018 Decode.dataSize, Encode.dataSize, sizeof, dataSize, intDataSize, decodeFast, encodeFast, value, skip, GoString, ensure, bool, int8, uint8, int16, uint16, int32, uint32, int64, uint64 — Go's REFLECTIVE walk: `dataSize` decides a value's wire size at run time from its `reflect.Value`, and the `encoder`/`decoder` structs move the bytes the same way. goish decides at COMPILE time through the `Fixed` trait below, so an unsupported type is a build error where Go's is a run-time `errors.New("binary.Write: some values are not fixed-sized in type …")`. There is nothing to anchor those against. `GoString` is a fmt helper for the two order values, which goish's printer reaches through `String`.
// goishlint:ignore GOISH021 AppendByteOrder, coder, decoder, encoder, bigEndian, littleEndian, errBufferTooSmall, structSize — the same reflective machinery: `coder`/`encoder`/`decoder` are its state, `AppendByteOrder` is the append half of ByteOrder which goish folds into the inherent AppendUint* methods, `bigEndian`/`littleEndian` are Go's unexported carriers for the two exported values (goish names them BigEndian/LittleEndian directly), and `errBufferTooSmall` is built at its two call sites.
//
// binary.go — the ByteOrder interface, its two implementations, and
// the fixed-width Read/Write/Size/Append/Encode/Decode family.
//
// Reference: encoding/binary/binary.go.
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
// `Read` and `Write` were STUBS: generic over any `T`, doing nothing,
// returning nil. A caller writing a header with
// `binary.Write(w, binary.BigEndian, hdr)` got success and an empty
// stream, which is indistinguishable from a correct write of nothing.
// They are ported now, over a `Fixed` trait that stands in for Go's
// reflective `dataSize` walk.

use crate::gostring::string;

/// Big-endian (network) byte order. Byte 0 is the most-significant.
/// Mirrors `binary.BigEndian` (binary.go:64).
#[derive(Copy, Clone)]
pub struct BigEndian;

/// Little-endian byte order. Byte 0 is the least-significant.
/// Mirrors `binary.LittleEndian` (binary.go:61).
#[derive(Copy, Clone)]
pub struct LittleEndian;

// go: sdk 1.25.5 encoding/binary/binary.go:39-47 ByteOrder
/// Go's `ByteOrder` interface. goish's was a one-method tag —
/// `IsBigEndian() bool` — which no Go code can use and which the
/// `Read`/`Write` stubs did not consult either. This is Go's shape, so
/// a function can take an order as a parameter and call it.
///
/// The inherent methods on `BigEndian`/`LittleEndian` stay: they accept
/// anything `AsRef<[u8]>` where the trait must fix one type, and Rust
/// resolves an inherent method first, so existing call sites are
/// untouched.
pub trait ByteOrder: Copy {
    // go: none — goish idiom: forwards to the inherent method above, which carries the anchor.
    fn Uint16(self, b: &[crate::types::byte]) -> u16;
    // go: none — goish idiom: forwards to the inherent method above, which carries the anchor.
    fn Uint32(self, b: &[crate::types::byte]) -> u32;
    // go: none — goish idiom: forwards to the inherent method above, which carries the anchor.
    fn Uint64(self, b: &[crate::types::byte]) -> u64;
    // go: none — goish idiom: forwards to the inherent method above, which carries the anchor.
    fn PutUint16(self, b: &mut [crate::types::byte], v: u16);
    // go: none — goish idiom: forwards to the inherent method above, which carries the anchor.
    fn PutUint32(self, b: &mut [crate::types::byte], v: u32);
    // go: none — goish idiom: forwards to the inherent method above, which carries the anchor.
    fn PutUint64(self, b: &mut [crate::types::byte], v: u64);
    // go: none — goish idiom: forwards to the inherent method above, which carries the anchor.
    fn String(self) -> string;
    // go: none — goish idiom: kept from the tag trait this replaces, so
    //     the generic code below can branch without a downcast.
    fn IsBigEndian(self) -> bool;
}

impl ByteOrder for BigEndian {
    // go: none — goish idiom: forwards to the inherent method above, which carries the anchor.
    fn Uint16(self, b: &[crate::types::byte]) -> u16 {
        return BigEndian::Uint16(self, b);
    }
    // go: none — goish idiom: forwards to the inherent method above, which carries the anchor.
    fn Uint32(self, b: &[crate::types::byte]) -> u32 {
        return BigEndian::Uint32(self, b);
    }
    // go: none — goish idiom: forwards to the inherent method above, which carries the anchor.
    fn Uint64(self, b: &[crate::types::byte]) -> u64 {
        return BigEndian::Uint64(self, b);
    }
    // go: none — goish idiom: forwards to the inherent method above, which carries the anchor.
    fn PutUint16(self, b: &mut [crate::types::byte], v: u16) {
        BigEndian::PutUint16(self, b, v);
    }
    // go: none — goish idiom: forwards to the inherent method above, which carries the anchor.
    fn PutUint32(self, b: &mut [crate::types::byte], v: u32) {
        BigEndian::PutUint32(self, b, v);
    }
    // go: none — goish idiom: forwards to the inherent method above, which carries the anchor.
    fn PutUint64(self, b: &mut [crate::types::byte], v: u64) {
        BigEndian::PutUint64(self, b, v);
    }
    // go: none — goish idiom: forwards to the inherent method above, which carries the anchor.
    fn String(self) -> string {
        return BigEndian::String(self);
    }
    // go: none — goish idiom: forwards to the inherent method above, which carries the anchor.
    fn IsBigEndian(self) -> bool {
        return true;
    }
}

impl ByteOrder for LittleEndian {
    // go: none — goish idiom: forwards to the inherent method above, which carries the anchor.
    fn Uint16(self, b: &[crate::types::byte]) -> u16 {
        return LittleEndian::Uint16(self, b);
    }
    // go: none — goish idiom: forwards to the inherent method above, which carries the anchor.
    fn Uint32(self, b: &[crate::types::byte]) -> u32 {
        return LittleEndian::Uint32(self, b);
    }
    // go: none — goish idiom: forwards to the inherent method above, which carries the anchor.
    fn Uint64(self, b: &[crate::types::byte]) -> u64 {
        return LittleEndian::Uint64(self, b);
    }
    // go: none — goish idiom: forwards to the inherent method above, which carries the anchor.
    fn PutUint16(self, b: &mut [crate::types::byte], v: u16) {
        LittleEndian::PutUint16(self, b, v);
    }
    // go: none — goish idiom: forwards to the inherent method above, which carries the anchor.
    fn PutUint32(self, b: &mut [crate::types::byte], v: u32) {
        LittleEndian::PutUint32(self, b, v);
    }
    // go: none — goish idiom: forwards to the inherent method above, which carries the anchor.
    fn PutUint64(self, b: &mut [crate::types::byte], v: u64) {
        LittleEndian::PutUint64(self, b, v);
    }
    // go: none — goish idiom: forwards to the inherent method above, which carries the anchor.
    fn String(self) -> string {
        return LittleEndian::String(self);
    }
    // go: none — goish idiom: forwards to the inherent method above, which carries the anchor.
    fn IsBigEndian(self) -> bool {
        return false;
    }
}

// ─── BigEndian ────────────────────────────────────────────────────

impl BigEndian {
    // go: sdk 1.25.5 encoding/binary/binary.go:155-158 bigEndian.Uint16
    /// Read a uint16 from `b[0..2]`. Panics on slice too short.
    /// Accepts anything `impl AsRef<[u8]>` — `&[u8]`, `[u8; N]`,
    /// `slice<byte>`, `array<byte, N>` all flow in directly.
    pub fn Uint16<B: AsRef<[u8]>>(self, b: B) -> u16 {
        let b = b.as_ref();
        assert!(b.len() >= 2, "binary: slice too short for uint16");
        return ((b[0] as u16) << 8) | (b[1] as u16);
    }

    // go: sdk 1.25.5 encoding/binary/binary.go:176-179 bigEndian.Uint32
    /// Read a uint32 from `b[0..4]`.
    pub fn Uint32<B: AsRef<[u8]>>(self, b: B) -> u32 {
        let b = b.as_ref();
        assert!(b.len() >= 4, "binary: slice too short for uint32");
        return ((b[0] as u32) << 24)
            | ((b[1] as u32) << 16)
            | ((b[2] as u32) << 8)
            | (b[3] as u32);
    }

    // go: sdk 1.25.5 encoding/binary/binary.go:201-205 bigEndian.Uint64
    /// Read a uint64 from `b[0..8]`.
    pub fn Uint64<B: AsRef<[u8]>>(self, b: B) -> u64 {
        let b = b.as_ref();
        assert!(b.len() >= 8, "binary: slice too short for uint64");
        return ((b[0] as u64) << 56)
            | ((b[1] as u64) << 48)
            | ((b[2] as u64) << 40)
            | ((b[3] as u64) << 32)
            | ((b[4] as u64) << 24)
            | ((b[5] as u64) << 16)
            | ((b[6] as u64) << 8)
            | (b[7] as u64);
    }

    // go: sdk 1.25.5 encoding/binary/binary.go:161-165 bigEndian.PutUint16
    /// Write `v` as 2 bytes into `b[0..2]`. Takes `impl AsMut<[u8]>`
    /// so callers can pass `slice<byte>`, `array<byte, N>` (via
    /// DerefMut), or a raw `&mut [u8]`.
    pub fn PutUint16<B: AsMut<[u8]>>(self, mut b: B, v: u16) {
        let b = b.as_mut();
        assert!(b.len() >= 2, "binary: slice too short for uint16");
        b[0] = (v >> 8) as u8;
        b[1] = v as u8;
    }

    // go: sdk 1.25.5 encoding/binary/binary.go:182-188 bigEndian.PutUint32
    /// Write `v` as 4 bytes into `b[0..4]`.
    pub fn PutUint32<B: AsMut<[u8]>>(self, mut b: B, v: u32) {
        let b = b.as_mut();
        assert!(b.len() >= 4, "binary: slice too short for uint32");
        b[0] = (v >> 24) as u8;
        b[1] = (v >> 16) as u8;
        b[2] = (v >> 8) as u8;
        b[3] = v as u8;
    }

    // go: sdk 1.25.5 encoding/binary/binary.go:208-218 bigEndian.PutUint64
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

    // go: sdk 1.25.5 encoding/binary/binary.go:168-173 bigEndian.AppendUint16
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
        return crate::goslice::slice::__from_vec(v_buf);
    }

    // go: sdk 1.25.5 encoding/binary/binary.go:191-198 bigEndian.AppendUint32
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
        return crate::goslice::slice::__from_vec(v_buf);
    }

    // go: sdk 1.25.5 encoding/binary/binary.go:221-232 bigEndian.AppendUint64
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
        return crate::goslice::slice::__from_vec(v_buf);
    }

    // go: sdk 1.25.5 encoding/binary/binary.go:234-234 bigEndian.String
    /// Mirrors `String() string` from the ByteOrder interface.
    pub fn String(self) -> string {
        return string::from_static("BigEndian");
    }
}

// ─── LittleEndian ────────────────────────────────────────────────

impl LittleEndian {
    // go: sdk 1.25.5 encoding/binary/binary.go:69-72 littleEndian.Uint16
    pub fn Uint16<B: AsRef<[u8]>>(self, b: B) -> u16 {
        let b = b.as_ref();
        assert!(b.len() >= 2, "binary: slice too short for uint16");
        return (b[0] as u16) | ((b[1] as u16) << 8);
    }

    // go: sdk 1.25.5 encoding/binary/binary.go:90-93 littleEndian.Uint32
    pub fn Uint32<B: AsRef<[u8]>>(self, b: B) -> u32 {
        let b = b.as_ref();
        assert!(b.len() >= 4, "binary: slice too short for uint32");
        return (b[0] as u32)
            | ((b[1] as u32) << 8)
            | ((b[2] as u32) << 16)
            | ((b[3] as u32) << 24);
    }

    // go: sdk 1.25.5 encoding/binary/binary.go:115-119 littleEndian.Uint64
    pub fn Uint64<B: AsRef<[u8]>>(self, b: B) -> u64 {
        let b = b.as_ref();
        assert!(b.len() >= 8, "binary: slice too short for uint64");
        return (b[0] as u64)
            | ((b[1] as u64) << 8)
            | ((b[2] as u64) << 16)
            | ((b[3] as u64) << 24)
            | ((b[4] as u64) << 32)
            | ((b[5] as u64) << 40)
            | ((b[6] as u64) << 48)
            | ((b[7] as u64) << 56);
    }

    // go: sdk 1.25.5 encoding/binary/binary.go:75-79 littleEndian.PutUint16
    pub fn PutUint16<B: AsMut<[u8]>>(self, mut b: B, v: u16) {
        let b = b.as_mut();
        assert!(b.len() >= 2, "binary: slice too short for uint16");
        b[0] = v as u8;
        b[1] = (v >> 8) as u8;
    }

    // go: sdk 1.25.5 encoding/binary/binary.go:96-102 littleEndian.PutUint32
    pub fn PutUint32<B: AsMut<[u8]>>(self, mut b: B, v: u32) {
        let b = b.as_mut();
        assert!(b.len() >= 4, "binary: slice too short for uint32");
        b[0] = v as u8;
        b[1] = (v >> 8) as u8;
        b[2] = (v >> 16) as u8;
        b[3] = (v >> 24) as u8;
    }

    // go: sdk 1.25.5 encoding/binary/binary.go:122-132 littleEndian.PutUint64
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

    // go: sdk 1.25.5 encoding/binary/binary.go:82-87 littleEndian.AppendUint16
    /// Append `v` as 2 little-endian bytes to `buf`.
    pub fn AppendUint16(
        self,
        buf: crate::goslice::slice<crate::types::byte>,
        v: u16,
    ) -> crate::goslice::slice<crate::types::byte> {
        let mut v_buf: alloc::vec::Vec<u8> = buf.__into_vec();
        v_buf.push(v as u8);
        v_buf.push((v >> 8) as u8);
        return crate::goslice::slice::__from_vec(v_buf);
    }

    // go: sdk 1.25.5 encoding/binary/binary.go:105-112 littleEndian.AppendUint32
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
        return crate::goslice::slice::__from_vec(v_buf);
    }

    // go: sdk 1.25.5 encoding/binary/binary.go:135-146 littleEndian.AppendUint64
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
        return crate::goslice::slice::__from_vec(v_buf);
    }

    // go: sdk 1.25.5 encoding/binary/binary.go:148-148 littleEndian.String
    pub fn String(self) -> string {
        return string::from_static("LittleEndian");
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

extern crate alloc;

use alloc::vec::Vec;

use crate::convert::int as toint;
use crate::errors::{self, error, nil};
use crate::goslice::slice;
use crate::io;
use crate::types::{byte, float32, float64, int, int16, int32, int64, int8};
use crate::types::{uint16, uint32, uint64, uint8};

// go: none — goish idiom: Go's `dataSize` reflects over the value at
//     run time to find its wire size, and its `encoder`/`decoder`
//     structs then walk the same reflect.Value to move the bytes. goish
//     has no reflection at this layer, so the three questions — how
//     wide, how to write, how to read — are a trait, answered at
//     compile time.
//
//     The consequence is a better error than Go's: a type with no
//     fixed-width encoding does not compile, where Go returns
//     `binary.Write: some values are not fixed-sized in type T` at run
//     time. `binary.Size` of such a value is -1 in Go and unwritable
//     here for the same reason.
pub trait Fixed {
    /// Go's `Size` for this value: the number of bytes it occupies.
    fn __size(&self) -> int;
    /// Write `self` into `b`, which is exactly `__size()` long.
    fn __put(&self, order: &dyn ByteOrderDyn, b: &mut [byte]);
    /// Read `self` back out of `b`, which is exactly `__size()` long.
    fn __get(&mut self, order: &dyn ByteOrderDyn, b: &[byte]);
}

// go: none — goish idiom: `ByteOrder`'s methods take `self` by value so
//     the unit structs stay zero-sized, which makes the trait not
//     object-safe. `Fixed` needs a `&dyn` order to stay object-friendly
//     itself, so this is the same interface with `&self`.
pub trait ByteOrderDyn {
    // go: none — goish idiom: see `ByteOrderDyn` above.
    fn u16(&self, b: &[byte]) -> uint16;
    // go: none — goish idiom: see `ByteOrderDyn` above.
    fn u32(&self, b: &[byte]) -> uint32;
    // go: none — goish idiom: see `ByteOrderDyn` above.
    fn u64(&self, b: &[byte]) -> uint64;
    // go: none — goish idiom: see `ByteOrderDyn` above.
    fn put16(&self, b: &mut [byte], v: uint16);
    // go: none — goish idiom: see `ByteOrderDyn` above.
    fn put32(&self, b: &mut [byte], v: uint32);
    // go: none — goish idiom: see `ByteOrderDyn` above.
    fn put64(&self, b: &mut [byte], v: uint64);
}

impl<O: ByteOrder> ByteOrderDyn for O {
    // go: none — goish idiom: see `ByteOrderDyn` above.
    fn u16(&self, b: &[byte]) -> uint16 {
        return ByteOrder::Uint16(*self, b);
    }
    // go: none — goish idiom: see `ByteOrderDyn` above.
    fn u32(&self, b: &[byte]) -> uint32 {
        return ByteOrder::Uint32(*self, b);
    }
    // go: none — goish idiom: see `ByteOrderDyn` above.
    fn u64(&self, b: &[byte]) -> uint64 {
        return ByteOrder::Uint64(*self, b);
    }
    // go: none — goish idiom: see `ByteOrderDyn` above.
    fn put16(&self, b: &mut [byte], v: uint16) {
        ByteOrder::PutUint16(*self, b, v);
    }
    // go: none — goish idiom: see `ByteOrderDyn` above.
    fn put32(&self, b: &mut [byte], v: uint32) {
        ByteOrder::PutUint32(*self, b, v);
    }
    // go: none — goish idiom: see `ByteOrderDyn` above.
    fn put64(&self, b: &mut [byte], v: uint64) {
        ByteOrder::PutUint64(*self, b, v);
    }
}

// go: none — goish idiom: one `Fixed` impl per width, matching Go's
//     `encoder`/`decoder` per-kind methods. The signed types go through
//     the unsigned path on the same bit pattern, which is what Go's
//     `order.PutUint32(bs, uint32(v))` does.
macro_rules! fixed_1 {
    ($($t:ty),*) => { $(
        impl Fixed for $t {
            fn __size(&self) -> int { return 1; }
            fn __put(&self, _o: &dyn ByteOrderDyn, b: &mut [byte]) {
                b[0] = *self as byte; // goishlint:ignore GOISH005 - Go's `uint8(v)`: reinterpret the bit pattern at the wire width.
            }
            fn __get(&mut self, _o: &dyn ByteOrderDyn, b: &[byte]) {
                *self = b[0] as $t; // goishlint:ignore GOISH005 - see __put.
            }
        }
    )* };
}
fixed_1!(uint8, int8);

macro_rules! fixed_2 {
    ($($t:ty),*) => { $(
        impl Fixed for $t {
            fn __size(&self) -> int { return 2; }
            fn __put(&self, o: &dyn ByteOrderDyn, b: &mut [byte]) {
                o.put16(b, *self as uint16); // goishlint:ignore GOISH005 - Go's `order.PutUint16(bs, uint16(v))`.
            }
            fn __get(&mut self, o: &dyn ByteOrderDyn, b: &[byte]) {
                *self = o.u16(b) as $t; // goishlint:ignore GOISH005 - see __put.
            }
        }
    )* };
}
fixed_2!(uint16, int16);

macro_rules! fixed_4 {
    ($($t:ty),*) => { $(
        impl Fixed for $t {
            fn __size(&self) -> int { return 4; }
            fn __put(&self, o: &dyn ByteOrderDyn, b: &mut [byte]) {
                o.put32(b, *self as uint32); // goishlint:ignore GOISH005 - Go's `order.PutUint32(bs, uint32(v))`.
            }
            fn __get(&mut self, o: &dyn ByteOrderDyn, b: &[byte]) {
                *self = o.u32(b) as $t; // goishlint:ignore GOISH005 - see __put.
            }
        }
    )* };
}
fixed_4!(uint32, int32);

macro_rules! fixed_8 {
    ($($t:ty),*) => { $(
        impl Fixed for $t {
            fn __size(&self) -> int { return 8; }
            fn __put(&self, o: &dyn ByteOrderDyn, b: &mut [byte]) {
                o.put64(b, *self as uint64); // goishlint:ignore GOISH005 - Go's `order.PutUint64(bs, uint64(v))`.
            }
            fn __get(&mut self, o: &dyn ByteOrderDyn, b: &[byte]) {
                *self = o.u64(b) as $t; // goishlint:ignore GOISH005 - see __put.
            }
        }
    )* };
}
fixed_8!(uint64, int64);

// go: none — goish idiom: Go writes `math.Float32bits(v)` / `Float64bits`
//     and hands the result to the same PutUint path, so a float travels
//     as its IEEE-754 bit pattern and a NaN keeps whichever payload it
//     had.
impl Fixed for float32 {
    // go: none — goish idiom: forwards to the inherent method above, which carries the anchor.
    fn __size(&self) -> int {
        return 4;
    }
    // go: none — goish idiom: forwards to the inherent method above, which carries the anchor.
    fn __put(&self, o: &dyn ByteOrderDyn, b: &mut [byte]) {
        o.put32(b, self.to_bits());
    }
    // go: none — goish idiom: forwards to the inherent method above, which carries the anchor.
    fn __get(&mut self, o: &dyn ByteOrderDyn, b: &[byte]) {
        *self = float32::from_bits(o.u32(b));
    }
}

impl Fixed for float64 {
    // go: none — goish idiom: forwards to the inherent method above, which carries the anchor.
    fn __size(&self) -> int {
        return 8;
    }
    // go: none — goish idiom: forwards to the inherent method above, which carries the anchor.
    fn __put(&self, o: &dyn ByteOrderDyn, b: &mut [byte]) {
        o.put64(b, self.to_bits());
    }
    // go: none — goish idiom: forwards to the inherent method above, which carries the anchor.
    fn __get(&mut self, o: &dyn ByteOrderDyn, b: &[byte]) {
        *self = float64::from_bits(o.u64(b));
    }
}

// go: none — goish idiom: Go's `encoder.bool` writes 0 or 1 and its
//     `decoder.bool` reads "not zero", so any non-zero byte comes back
//     as true.
impl Fixed for bool {
    // go: none — goish idiom: forwards to the inherent method above, which carries the anchor.
    fn __size(&self) -> int {
        return 1;
    }
    // go: none — goish idiom: forwards to the inherent method above, which carries the anchor.
    fn __put(&self, _o: &dyn ByteOrderDyn, b: &mut [byte]) {
        b[0] = if *self { 1 } else { 0 };
    }
    // go: none — goish idiom: forwards to the inherent method above, which carries the anchor.
    fn __get(&mut self, _o: &dyn ByteOrderDyn, b: &[byte]) {
        *self = b[0] != 0;
    }
}

// go: none — goish idiom: Go's `dataSize` multiplies the element size
//     by the length for a slice or an array, and the encoder walks it.
impl<T: Fixed> Fixed for slice<T> {
    // go: none — goish idiom: forwards to the inherent method above, which carries the anchor.
    fn __size(&self) -> int {
        if self.len() == 0 {
            return 0;
        }
        return toint(self.len()) * self[0].__size();
    }
    // go: none — goish idiom: forwards to the inherent method above, which carries the anchor.
    fn __put(&self, o: &dyn ByteOrderDyn, b: &mut [byte]) {
        let mut off = 0usize;
        let mut i = 0usize;
        while i < self.len() {
            let w = self[i].__size() as usize;
            self[i].__put(o, &mut b[off..off + w]);
            off += w;
            i += 1;
        }
    }
    // go: none — goish idiom: forwards to the inherent method above, which carries the anchor.
    fn __get(&mut self, o: &dyn ByteOrderDyn, b: &[byte]) {
        let mut off = 0usize;
        let mut i = 0usize;
        while i < self.len() {
            let w = self[i].__size() as usize;
            self[i].__get(o, &b[off..off + w]);
            off += w;
            i += 1;
        }
    }
}

// go: sdk 1.25.5 encoding/binary/binary.go:597-690 Size
/// Go: "Size returns how many bytes Write would generate to encode the
/// value v … If v is neither of these, Size returns -1."
///
/// goish answers the second case at compile time instead: a type with no
/// `Fixed` impl cannot be passed here at all.
pub fn Size<T: Fixed + ?Sized>(v: &T) -> int {
    return v.__size();
}

// go: sdk 1.25.5 encoding/binary/binary.go:258-291 Read
/// Go: "Read reads structured binary data from r into data … Data read
/// from r is decoded using the specified byte order and written to
/// successive fields of the data."
///
/// goish's was a stub: generic over any `T`, ignoring all three
/// arguments and returning nil. Every caller got success and an
/// untouched destination.
pub fn Read<R: io::Reader, O: ByteOrder, T: Fixed + ?Sized>(
    r: &mut R,
    order: O,
    data: &mut T,
) -> error {
    let n = data.__size() as usize;
    let mut buf: slice<byte> = crate::goslice::slice::__from_vec(alloc::vec![0u8; n]);
    // Go: "if _, err := io.ReadFull(r, bs); err != nil { return err }"
    // — which is io.EOF when nothing was read and io.ErrUnexpectedEOF
    // when the read stopped part way.
    let (_, err) = io::ReadFull(r, &mut buf);
    if !err.IsNil() {
        return err;
    }
    let raw: &[byte] = &buf;
    data.__get(&order, raw);
    return nil;
}

// go: sdk 1.25.5 encoding/binary/binary.go:410-434 Write
/// Go: "Write writes the binary representation of data into w."
pub fn Write<W: io::Writer + ?Sized, O: ByteOrder, T: Fixed + ?Sized>(
    w: &mut W,
    order: O,
    data: &T,
) -> error {
    let n = data.__size() as usize;
    let mut v: Vec<byte> = alloc::vec![0u8; n];
    data.__put(&order, &mut v);
    let (_, err) = w.Write(crate::goslice::slice::__from_vec(v));
    return err;
}

// go: sdk 1.25.5 encoding/binary/binary.go:470-489 Append
/// Go: "Append appends the binary representation of data to buf."
pub fn Append<O: ByteOrder, T: Fixed + ?Sized>(
    buf: slice<byte>,
    order: O,
    data: &T,
) -> (slice<byte>, error) {
    let n = data.__size() as usize;
    let mut v: Vec<byte> = buf.__into_vec();
    let at = v.len();
    v.resize(at + n, 0);
    data.__put(&order, &mut v[at..]);
    return (crate::goslice::slice::__from_vec(v), nil);
}

// go: sdk 1.25.5 encoding/binary/binary.go:440-464 Encode
/// Go: "Encode encodes the binary representation of data into buf. If
/// buf is too small, Encode returns an error and does not write to buf."
pub fn Encode<O: ByteOrder, T: Fixed + ?Sized>(
    buf: &mut slice<byte>,
    order: O,
    data: &T,
) -> (int, error) {
    let n = data.__size() as usize;
    if buf.len() < n {
        // Go: errBufferTooSmall — "buffer too small", and n is 0.
        return (0, errors::New("buffer too small"));
    }
    let raw: &mut [byte] = buf;
    data.__put(&order, &mut raw[..n]);
    return (toint(n), nil);
}

// go: sdk 1.25.5 encoding/binary/binary.go:297-328 Decode
/// Go: "Decode decodes binary data from buf into data … If buf is
/// smaller than the size of data, Decode returns an error and does not
/// write to data."
pub fn Decode<O: ByteOrder, T: Fixed + ?Sized>(
    buf: &[byte],
    order: O,
    data: &mut T,
) -> (int, error) {
    let n = data.__size() as usize;
    if buf.len() < n {
        return (0, errors::New("buffer too small"));
    }
    data.__get(&order, &buf[..n]);
    return (toint(n), nil);
}
