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
        ((b[0] as u32) << 24)
            | ((b[1] as u32) << 16)
            | ((b[2] as u32) << 8)
            | (b[3] as u32)
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
    pub fn AppendUint16(self, buf: crate::goslice::slice<crate::types::byte>, v: u16) -> crate::goslice::slice<crate::types::byte> {
        let mut v_buf: alloc::vec::Vec<u8> = buf.__into_vec();
        v_buf.push((v >> 8) as u8);
        v_buf.push(v as u8);
        crate::goslice::slice::__from_vec(v_buf)
    }

    /// Append `v` as 4 big-endian bytes to `buf`.
    pub fn AppendUint32(self, buf: crate::goslice::slice<crate::types::byte>, v: u32) -> crate::goslice::slice<crate::types::byte> {
        let mut v_buf: alloc::vec::Vec<u8> = buf.__into_vec();
        v_buf.push((v >> 24) as u8);
        v_buf.push((v >> 16) as u8);
        v_buf.push((v >> 8) as u8);
        v_buf.push(v as u8);
        crate::goslice::slice::__from_vec(v_buf)
    }

    /// Append `v` as 8 big-endian bytes to `buf`.
    pub fn AppendUint64(self, buf: crate::goslice::slice<crate::types::byte>, v: u64) -> crate::goslice::slice<crate::types::byte> {
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
        (b[0] as u32)
            | ((b[1] as u32) << 8)
            | ((b[2] as u32) << 16)
            | ((b[3] as u32) << 24)
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
    pub fn AppendUint16(self, buf: crate::goslice::slice<crate::types::byte>, v: u16) -> crate::goslice::slice<crate::types::byte> {
        let mut v_buf: alloc::vec::Vec<u8> = buf.__into_vec();
        v_buf.push(v as u8);
        v_buf.push((v >> 8) as u8);
        crate::goslice::slice::__from_vec(v_buf)
    }

    /// Append `v` as 4 little-endian bytes to `buf`.
    pub fn AppendUint32(self, buf: crate::goslice::slice<crate::types::byte>, v: u32) -> crate::goslice::slice<crate::types::byte> {
        let mut v_buf: alloc::vec::Vec<u8> = buf.__into_vec();
        v_buf.push(v as u8);
        v_buf.push((v >> 8) as u8);
        v_buf.push((v >> 16) as u8);
        v_buf.push((v >> 24) as u8);
        crate::goslice::slice::__from_vec(v_buf)
    }

    /// Append `v` as 8 little-endian bytes to `buf`.
    pub fn AppendUint64(self, buf: crate::goslice::slice<crate::types::byte>, v: u64) -> crate::goslice::slice<crate::types::byte> {
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

// ─── Varint encoding (varint.go) ────────────────────────────────────

/// `MaxVarintLen16` (varint.go:34) — max bytes for a varint-16.
pub const MaxVarintLen16: crate::types::int = 3;
/// `MaxVarintLen32` (varint.go:35) — max bytes for a varint-32.
pub const MaxVarintLen32: crate::types::int = 5;
/// `MaxVarintLen64` (varint.go:36) — max bytes for a varint-64.
pub const MaxVarintLen64: crate::types::int = 10;

/// `binary.PutUvarint(buf, x)` (varint.go:23) — encode `x` into `buf`
/// in-place, returning the number of bytes written. Caller must ensure
/// `buf` is large enough (`MaxVarintLen64` is the worst case for u64).
/// Panics if `buf` is too small.
///
/// Takes `&mut slice<byte>` so the caller's buffer is mutated. Go's
/// slice header carries a pointer to a shared backing array, so a
/// by-value `[]byte` parameter still mutates the caller's data; goish's
/// `slice<byte>` owns its `Vec<u8>` and a by-value parameter would
/// only mutate a discarded copy.
pub fn PutUvarint(
    buf: &mut crate::goslice::slice<crate::types::byte>,
    mut x: crate::types::uint,
) -> crate::types::int {
    let mut i: crate::types::int = 0;
    while x >= 0x80 {
        buf[i] = ((x as u8) | 0x80) as crate::types::byte;
        x >>= 7;
        i += 1;
    }
    buf[i] = (x as u8) as crate::types::byte;
    i + 1
}

/// `binary.PutVarint(buf, x)` (varint.go:54) — zig-zag encode signed
/// `x` into `buf` in-place. Returns the number of bytes written.
pub fn PutVarint(
    buf: &mut crate::goslice::slice<crate::types::byte>,
    x: crate::types::int,
) -> crate::types::int {
    let mut ux = (x as u64).wrapping_shl(1);
    if x < 0 {
        ux = !ux;
    }
    PutUvarint(buf, ux as crate::types::uint)
}

/// `binary.AppendUvarint(buf, x)` (varint.go:41) — append the LEB128
/// varint encoding of `x` to `buf`. Each byte holds 7 bits; MSB=1 in
/// all but the last byte to mark continuation.
pub fn AppendUvarint(
    buf: crate::goslice::slice<crate::types::byte>,
    mut x: crate::types::uint,
) -> crate::goslice::slice<crate::types::byte> {
    let mut v_buf: alloc::vec::Vec<u8> = buf.__into_vec();
    // Go: for x >= 0x80 { buf = append(buf, byte(x)|0x80); x >>= 7 }
    while x >= 0x80 {
        v_buf.push((x as u8) | 0x80);
        x >>= 7;
    }
    // Go: return append(buf, byte(x))
    v_buf.push(x as u8);
    crate::goslice::slice::__from_vec(v_buf)
}

/// `binary.Uvarint(buf)` (varint.go:68) — decode a varint from `buf`.
/// Returns `(value, n)`:
///   * `n > 0` — number of bytes consumed.
///   * `n == 0` — buf too short.
///   * `n < 0`  — overflow; `-n` is the byte count read.
pub fn Uvarint(buf: crate::goslice::slice<crate::types::byte>) -> (crate::types::uint, crate::types::int) {
    let mut x: crate::types::uint = 0;
    let mut s: u32 = 0;
    let len = buf.Len();
    let mut i: crate::types::int = 0;
    // Go: for i, b := range buf { ... }
    while i < len {
        // Go: if i == MaxVarintLen64 { return 0, -(i+1) }
        if i == MaxVarintLen64 {
            return (0, -(i + 1));
        }
        let b = buf[i];
        // Go: if b < 0x80 { ... return x | uint64(b)<<s, i+1 }
        if b < 0x80 {
            // Overflow guard: at MaxVarintLen64-1, the top bits of
            // `b` would shift past bit 63.
            if i == MaxVarintLen64 - 1 && b > 1 {
                return (0, -(i + 1));
            }
            return (x | (b as crate::types::uint) << s, i + 1);
        }
        // Go: x |= uint64(b&0x7f) << s; s += 7
        x |= ((b & 0x7f) as crate::types::uint) << s;
        s += 7;
        i += 1;
    }
    // Go: return 0, 0  — buf too small.
    (0, 0)
}

/// `binary.AppendVarint(buf, x)` (varint.go:91) — append zig-zag
/// encoded varint of signed `x`.
pub fn AppendVarint(
    buf: crate::goslice::slice<crate::types::byte>,
    x: crate::types::int,
) -> crate::goslice::slice<crate::types::byte> {
    // Go: ux := uint64(x) << 1; if x < 0 { ux = ^ux }
    let mut ux = (x as u64).wrapping_shl(1);
    if x < 0 {
        ux = !ux;
    }
    AppendUvarint(buf, ux as crate::types::uint)
}

/// `binary.Varint(buf)` (varint.go:115) — decode zig-zag signed varint.
/// Returns `(value, n)` with the same conventions as `Uvarint`.
pub fn Varint(buf: crate::goslice::slice<crate::types::byte>) -> (crate::types::int, crate::types::int) {
    // Go: ux, n := Uvarint(buf)
    let (ux, n) = Uvarint(buf);
    // Go: x := int64(ux >> 1); if ux&1 != 0 { x = ^x }
    let mut x = (ux >> 1) as crate::types::int;
    if (ux & 1) != 0 {
        x = !x;
    }
    (x, n)
}
