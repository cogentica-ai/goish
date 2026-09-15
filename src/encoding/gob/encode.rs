// goishlint:ignore GOISH018 Encoder.newEncoderState, Encoder.freeEncoderState, encoderState.update, encIndirect, encBool, encInt, encUint, encFloat, encComplex, encUint8Array, encString, encStructTerminator, valid, Encoder.encodeSingle, Encoder.encodeStruct, Encoder.encodeArray, encodeReflectValue, Encoder.encodeMap, Encoder.encodeInterface, Encoder.encodeGobEncoder, encOpFor, Encoder.encode, buildEncEngine, compileEnc, getEncEngine, gobEncodeOpFor — the encOp ENGINE, ABSENT. Every one of them takes or returns a reflect.Value and the GobEncoder path needs `Implements`, which goish's reflect does not have. See the module banner in mod.rs and ROADMAP §2.
// goishlint:ignore GOISH021 encHelper, encOp, encInstr, encEngine, encBufferPool, encOpTable, singletonField — the engine's types and its dispatch table, absent with the engine above. encBufferPool is additionally a sync.Pool of encBuffers, which is a free list for the engine and has no caller here.
// goishlint:ignore GOISH019 encoderState — two fields absent, `enc` and `next`. `enc` is a back-pointer to the Encoder, which is not ported; `next` is the free-list link newEncoderState/freeEncoderState thread, and both of those are absent too.
// goishlint:ignore GOISH019 encBuffer — one field absent, `scratch [64]byte`. It is the inline array Go's `data` starts as a zero-length slice of, so a small message never allocates; goish's `data` is a Vec and has no separate backing array. `Reset` still drops the allocation past tooBig, which is the only part of the scratch field that is observable.
// go: file encoding/gob/encode.go decls: encBuffer.writeByte, encBuffer.Write, encBuffer.WriteString, encBuffer.Len, encBuffer.Bytes, encBuffer.Reset, encoderState.encodeUint, encoderState.encodeInt, floatBits
//
// encoding/gob/encode.go — the write side's wire primitives.
//
// The two integer encodings are the whole of gob's compactness and they
// are worth reading once: an unsigned value below 128 is ONE byte, and
// anything larger is a length byte carrying the NEGATED byte count
// followed by that many big-endian bytes. A signed value is folded into
// an unsigned one by shifting left and, when negative, complementing —
// note complementing and not negating, so -1 encodes as 1 and -2 as 3.

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

use crate::byte;
use crate::goslice::slice;
use crate::gostring::string;
use crate::int;
use crate::int64;
use crate::uint64;

// go: sdk 1.25.5 encoding/gob/encode.go:18-18 uint64Size
/// Go: `const uint64Size = 8`
pub const uint64Size: usize = 8;

// go: sdk 1.25.5 encoding/gob/encode.go:35-40 encBuffer
/// Go: "encBuffer is an extremely simple, fast implementation of a
/// write-only byte buffer. It never returns a non-nil error, but Write
/// returns an error value so it matches io.Writer."
///
/// Go's struct carries a `scratch [64]byte` that `data` starts as a
/// zero-length slice of, so a small message never allocates and `Reset`
/// can throw away a buffer that grew past `tooBig`. goish's `data` is a
/// `Vec`, so the scratch array is not a separate field — but `Reset`
/// still drops the allocation past `tooBig`, which is the part that is
/// observable (in memory held, not in any value this API returns).
#[derive(Clone, Default)]
pub struct encBuffer {
    pub data: Vec<byte>,
}

impl encBuffer {
    // go: none — goish idiom: Go's zero encBuffer is ready to use once
    // `data = scratch[0:0]`; a Rust Vec needs a constructor.
    pub fn new() -> Self {
        return encBuffer { data: Vec::new() };
    }

    // go: sdk 1.25.5 encoding/gob/encode.go:50-52 encBuffer.writeByte
    /// Go: `e.data = append(e.data, c)`
    pub fn writeByte(&mut self, c: byte) {
        self.data.push(c);
    }

    // go: sdk 1.25.5 encoding/gob/encode.go:54-57 encBuffer.Write
    /// Go: appends and reports `len(p), nil` — it never fails, and the
    /// error exists only so the type satisfies io.Writer.
    pub fn Write(&mut self, p: slice<byte>) -> (int, crate::error) {
        self.data.extend_from_slice(&p);
        return (p.Len(), crate::errors::nil);
    }

    // go: sdk 1.25.5 encoding/gob/encode.go:59-61 encBuffer.WriteString
    /// Go: `e.data = append(e.data, s...)`
    pub fn WriteString<S: Into<string>>(&mut self, s: S) {
        let s: string = s.into();
        self.data.extend_from_slice(s.as_bytes());
    }

    // go: sdk 1.25.5 encoding/gob/encode.go:63-65 encBuffer.Len
    /// Go: `len(e.data)`
    pub fn Len(&self) -> int {
        return crate::int(crate::int64(self.data.len()));
    }

    // go: sdk 1.25.5 encoding/gob/encode.go:67-69 encBuffer.Bytes
    /// Go: `e.data` — the live slice, so a caller sees later writes.
    /// goish returns a copy; nothing in this package writes through it.
    pub fn Bytes(&self) -> slice<byte> {
        return slice::__from_vec(self.data.clone());
    }

    // go: sdk 1.25.5 encoding/gob/encode.go:71-77 encBuffer.Reset
    /// Go: truncates, and throws the allocation away entirely once it
    /// has grown past `tooBig` so one huge message does not pin 8 GiB.
    pub fn Reset(&mut self) {
        if self.data.len() >= super::decoder::tooBig as usize {
            self.data = Vec::new();
        } else {
            self.data.clear();
        }
    }
}

impl crate::io::Writer for encBuffer {
    // go: none — goish idiom: Go's *encBuffer satisfies io.Writer by
    // having the method; Rust needs the trait impl spelled out.
    fn Write(&mut self, p: slice<byte>) -> (int, crate::error) {
        return encBuffer::Write(self, p);
    }
}

// go: sdk 1.25.5 encoding/gob/encode.go:26-33 encoderState
/// Go: "encoderState is the execution state of an instance of the
/// encoder. A new state is created for nested objects."
pub struct encoderState {
    pub b: encBuffer,
    /// Go: "encoding an array element or map key/value pair; send zero
    /// values"
    pub sendZero: bool,
    /// Go: "the last field number written."
    pub fieldnum: int,
    /// Go: "buffer used by the encoder; here to avoid allocation."
    pub buf: [byte; 1 + uint64Size],
}

impl encoderState {
    // go: none — goish idiom: Go builds this through newEncoderState,
    // which is part of the absent engine; the zero value is spelled out
    // here so the primitives can be driven on their own.
    pub fn new() -> Self {
        return encoderState {
            b: encBuffer::new(),
            sendZero: false,
            fieldnum: 0,
            buf: [0u8; 1 + uint64Size],
        };
    }

    // go: sdk 1.25.5 encoding/gob/encode.go:100-120 encoderState.encodeUint
    /// Go: "Unsigned integers have a two-state encoding. If the number
    /// is less than 128 (0 through 0x7F), its value is written
    /// directly. Otherwise the value is written in big-endian byte
    /// order preceded by the byte length, negated."
    pub fn encodeUint(&mut self, x: uint64) {
        if x <= 0x7F {
            self.b.writeByte(crate::byte(x));
            return;
        }

        crate::encoding::binary::BigEndian.PutUint64(&mut self.buf[1..], x);
        // Go: `bc := bits.LeadingZeros64(x) >> 3` — "8 - bytelen(x)"
        let bc = (crate::math::bits::LeadingZeros64(x) >> 3) as usize;
        // Go: "and then we subtract 8 to get -bytelen(x)"
        self.buf[bc] = crate::uint8(crate::int64(bc) - crate::int64(uint64Size));

        let tail: Vec<byte> = self.buf[bc..uint64Size + 1].to_vec();
        let _ = self.b.Write(slice::__from_vec(tail));
    }

    // go: sdk 1.25.5 encoding/gob/encode.go:122-131 encoderState.encodeInt
    /// Go: "The low bit of the encoding says whether to bit complement
    /// the (other bits of the) uint to recover the int."
    pub fn encodeInt(&mut self, i: int64) {
        let x: uint64;
        if i < 0 {
            x = crate::uint64(!i << 1) | 1;
        } else {
            x = crate::uint64(i << 1);
        }
        self.encodeUint(x);
    }
}

// go: sdk 1.25.5 encoding/gob/encode.go:206-213 floatBits
/// Go: "Floating-point numbers are transmitted as uint64s holding the
/// bits of the underlying representation. They are sent byte-reversed,
/// with the exponent end coming out first, so integer floating point
/// numbers (for example) transmit more compactly. This routine does the
/// swizzling."
pub fn floatBits(f: crate::float64) -> uint64 {
    let u = crate::math::Float64bits(f);
    return crate::math::bits::ReverseBytes64(u);
}
