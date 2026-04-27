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
    pub fn Uint16(self, b: &[u8]) -> u16 {
        assert!(b.len() >= 2, "binary: slice too short for uint16");
        ((b[0] as u16) << 8) | (b[1] as u16)
    }

    /// Read a uint32 from `b[0..4]`.
    pub fn Uint32(self, b: &[u8]) -> u32 {
        assert!(b.len() >= 4, "binary: slice too short for uint32");
        ((b[0] as u32) << 24)
            | ((b[1] as u32) << 16)
            | ((b[2] as u32) << 8)
            | (b[3] as u32)
    }

    /// Read a uint64 from `b[0..8]`.
    pub fn Uint64(self, b: &[u8]) -> u64 {
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

    /// Write `v` as 2 bytes into `b[0..2]`.
    pub fn PutUint16(self, b: &mut [u8], v: u16) {
        assert!(b.len() >= 2, "binary: slice too short for uint16");
        b[0] = (v >> 8) as u8;
        b[1] = v as u8;
    }

    /// Write `v` as 4 bytes into `b[0..4]`.
    pub fn PutUint32(self, b: &mut [u8], v: u32) {
        assert!(b.len() >= 4, "binary: slice too short for uint32");
        b[0] = (v >> 24) as u8;
        b[1] = (v >> 16) as u8;
        b[2] = (v >> 8) as u8;
        b[3] = v as u8;
    }

    /// Write `v` as 8 bytes into `b[0..8]`.
    pub fn PutUint64(self, b: &mut [u8], v: u64) {
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
    pub fn String(self) -> string {
        string::from_static("BigEndian")
    }
}

// ─── LittleEndian ────────────────────────────────────────────────

impl LittleEndian {
    pub fn Uint16(self, b: &[u8]) -> u16 {
        assert!(b.len() >= 2, "binary: slice too short for uint16");
        (b[0] as u16) | ((b[1] as u16) << 8)
    }

    pub fn Uint32(self, b: &[u8]) -> u32 {
        assert!(b.len() >= 4, "binary: slice too short for uint32");
        (b[0] as u32)
            | ((b[1] as u32) << 8)
            | ((b[2] as u32) << 16)
            | ((b[3] as u32) << 24)
    }

    pub fn Uint64(self, b: &[u8]) -> u64 {
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

    pub fn PutUint16(self, b: &mut [u8], v: u16) {
        assert!(b.len() >= 2, "binary: slice too short for uint16");
        b[0] = v as u8;
        b[1] = (v >> 8) as u8;
    }

    pub fn PutUint32(self, b: &mut [u8], v: u32) {
        assert!(b.len() >= 4, "binary: slice too short for uint32");
        b[0] = v as u8;
        b[1] = (v >> 8) as u8;
        b[2] = (v >> 16) as u8;
        b[3] = (v >> 24) as u8;
    }

    pub fn PutUint64(self, b: &mut [u8], v: u64) {
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

    pub fn String(self) -> string {
        string::from_static("LittleEndian")
    }
}
