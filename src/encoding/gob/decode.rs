// goishlint:ignore GOISH018 Decoder.newDecoderState, Decoder.freeDecoderState, decoderState.decodeUint, decoderState.decodeInt, decoderState.getLength, ignoreUint, ignoreTwoUints, decAlloc, decBool, decInt8, decUint8, decInt16, decUint16, decInt32, decUint32, decInt64, decUint64, decFloat32, decFloat64, decComplex64, decComplex128, decUint8Slice, decString, ignoreUint8Array, float32FromBits, Decoder.decodeSingle, Decoder.decodeStruct, Decoder.ignoreStruct, Decoder.ignoreSingle, Decoder.decodeArrayHelper, Decoder.decodeArray, decodeIntoValue, Decoder.decodeMap, Decoder.ignoreArrayHelper, Decoder.ignoreArray, Decoder.ignoreMap, Decoder.decodeSlice, Decoder.ignoreSlice, Decoder.decodeInterface, Decoder.ignoreInterface, Decoder.ignoreGobDecoder, Decoder.decodeGobDecoder, Decoder.decOpFor, Decoder.decIgnoreOpFor, Decoder.gobDecodeOpFor, Decoder.compatibleType, Decoder.compileSingle, Decoder.compileIgnoreSingle, Decoder.compileDec, Decoder.getDecEnginePtr, Decoder.getIgnoreEnginePtr, Decoder.decodeValue, Decoder.decodeIgnoredValue, Decoder.decodeTypeDefinition, Decoder.errorf, emptyStruct, allocValue, init, typeString — the decOp ENGINE, ABSENT. Every one of these takes a reflect.Value and most WRITE through it; goish's reflect::Value is a read-only deep clone. The `decodeUint`/`decodeInt`/`getLength`/`float32FromBits` four are additionally blocked on gob's panic-based error signalling: they call `error_`, which panics with a gobError that `catchError` recovers, and goish's `recover!()` observes a panic without stopping it. See the module banner in mod.rs and ROADMAP §2.
// goishlint:ignore GOISH021 decHelper, decoderState, decOp, decInstr, decEngine, emptyStruct, intBits, uintptrBits, decIgnoreOpMap, decOpTable, emptyStructType, maxIgnoreNestingDepth, noValue — the engine's types, its dispatch tables, and the two word-size constants the overflow checks use, absent with the engine above. decoderState in particular exists only to hold the free-list link and the field number the decOps thread between them.
// go: file encoding/gob/decode.go decls: errBadUint, errBadType, errRange, decBuffer.Read, decBuffer.Drop, decBuffer.ReadByte, decBuffer.Len, decBuffer.Bytes, decBuffer.SetBytes, decBuffer.Reset, overflow, decodeUintReader, float64FromBits
//
// encoding/gob/decode.go — the read side's wire primitives.
//
// `decodeUintReader` is the only length decoder the Decoder uses on the
// raw stream, and its error contract is finicky enough to be worth
// pinning: an empty reader gives `(0, 1, io.EOF)` because the width is
// set BEFORE the read; a truncated multi-byte value reports the number
// of bytes it managed to read as the width and `io.ErrUnexpectedEOF`;
// and a length byte claiming more than eight bytes is `errBadUint`
// rather than a short read.

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

use super::encode::uint64Size;
use crate::byte;
use crate::float64;
use crate::goslice::slice;
use crate::gostring::string;
use crate::int;
use crate::uint64;

// go: sdk 1.25.5 encoding/gob/decode.go:19-23 errBadUint
/// Go's `var (errBadUint; errBadType; errRange)` block.
///
/// Functions rather than statics because goish's `error` is not
/// const-constructible; each call returns a fresh value with the same
/// text, which is what every comparison in this package tests.
pub fn errBadUint() -> crate::error {
    return crate::errors::New("gob: encoded unsigned integer out of range");
}

// go: none — see errBadUint; Go declares all three in one var block.
pub fn errBadType() -> crate::error {
    return crate::errors::New("gob: unknown type id or corrupted data");
}

// go: none — see errBadUint.
pub fn errRange() -> crate::error {
    return crate::errors::New("gob: bad data: field numbers out of bounds");
}

// go: sdk 1.25.5 encoding/gob/decode.go:38-43 decBuffer
/// Go: "decBuffer is an extremely simple, fast implementation of a
/// read-only byte buffer. It is initialized by calling Size and then
/// copying the data into the slice returned by Bytes()."
#[derive(Clone, Default)]
pub struct decBuffer {
    pub data: Vec<byte>,
    /// Go: "Read offset."
    pub offset: usize,
}

impl decBuffer {
    // go: none — goish idiom: Go's zero decBuffer is ready to use.
    pub fn new() -> Self {
        return decBuffer {
            data: Vec::new(),
            offset: 0,
        };
    }

    // go: sdk 1.25.5 encoding/gob/decode.go:45-52 decBuffer.Read
    /// Go: copies what it can and reports `io.EOF` only when it copied
    /// NOTHING and the caller asked for something — so a zero-length
    /// read of an exhausted buffer is `(0, nil)`, not EOF.
    pub fn Read(&mut self, p: &mut [byte]) -> (int, crate::error) {
        let avail = &self.data[self.offset..];
        let n = core::cmp::min(p.len(), avail.len());
        p[..n].copy_from_slice(&avail[..n]);
        if n == 0 && p.len() != 0 {
            return (0, crate::io::EOF.into());
        }
        self.offset += n;
        return (crate::int(crate::int64(n)), crate::errors::nil);
    }

    // go: sdk 1.25.5 encoding/gob/decode.go:54-59 decBuffer.Drop
    /// Go: `if n > d.Len() { panic("drop") }` — and it is a panic, not
    /// an error, because every caller has already checked the length.
    pub fn Drop(&mut self, n: int) {
        if n > self.Len() {
            panic!("drop");
        }
        self.offset += n as usize;
    }

    // go: sdk 1.25.5 encoding/gob/decode.go:61-68 decBuffer.ReadByte
    /// Go: one byte, or `io.EOF`.
    pub fn ReadByte(&mut self) -> (byte, crate::error) {
        if self.offset >= self.data.len() {
            return (0, crate::io::EOF.into());
        }
        let c = self.data[self.offset];
        self.offset += 1;
        return (c, crate::errors::nil);
    }

    // go: sdk 1.25.5 encoding/gob/decode.go:70-72 decBuffer.Len
    /// Go: `len(d.data) - d.offset` — what is LEFT, not what was set.
    pub fn Len(&self) -> int {
        return crate::int(crate::int64(self.data.len() - self.offset));
    }

    // go: sdk 1.25.5 encoding/gob/decode.go:74-76 decBuffer.Bytes
    /// Go: `d.data[d.offset:]` — the unread tail.
    pub fn Bytes(&self) -> slice<byte> {
        return slice::__from_vec(self.data[self.offset..].to_vec());
    }

    // go: sdk 1.25.5 encoding/gob/decode.go:78-82 decBuffer.SetBytes
    /// Go: "SetBytes sets the buffer to the bytes, discarding any
    /// existing data."
    pub fn SetBytes(&mut self, data: slice<byte>) {
        self.data = data.to_vec();
        self.offset = 0;
    }

    // go: sdk 1.25.5 encoding/gob/decode.go:84-87 decBuffer.Reset
    /// Go: truncates the data AND rewinds the offset.
    pub fn Reset(&mut self) {
        self.data.clear();
        self.offset = 0;
    }
}

// go: sdk 1.25.5 encoding/gob/decode.go:108-110 overflow
/// Go: `errors.New(`value for "` + name + `" out of range`)`
pub fn overflow<S: Into<string>>(name: S) -> crate::error {
    let name: string = name.into();
    return crate::errors::New(
        string::from_static("value for \"") + name + string::from_static("\" out of range"),
    );
}

// go: sdk 1.25.5 encoding/gob/decode.go:112-144 decodeUintReader
/// Go: "decodeUintReader reads an encoded unsigned integer from an
/// io.Reader. Used only by the Decoder to read the message length."
///
/// Read the width returns carefully — they are not "bytes consumed" in
/// the obvious way. It is set to 1 before the first read, so an empty
/// reader reports width 1 with io.EOF; and on a truncated multi-byte
/// value it is overwritten with the SHORT count from the second read,
/// so three bytes of an eight-byte value reports width 3. Only the
/// success path adds the `+1` for the length byte.
pub fn decodeUintReader(
    r: &mut dyn crate::io::Reader,
    buf: &mut slice<byte>,
) -> (uint64, int, crate::error) {
    let mut x: uint64 = 0;
    let mut width: int = 1;
    let mut head = buf.slice(0, width);
    let (n, err) = crate::io::ReadFull(r, &mut head);
    if n == 0 {
        return (x, width, err);
    }
    let b = head[0];
    buf[0] = b;
    if b <= 0x7f {
        return (uint64(b), width, crate::errors::nil);
    }
    let n = -crate::int64(crate::int8(b));
    if n > crate::int64(uint64Size) {
        return (x, width, errBadUint());
    }
    let mut body = buf.slice(0, crate::int(n));
    let (rn, err) = crate::io::ReadFull(r, &mut body);
    width = rn;
    if err != crate::errors::nil {
        let err = if crate::errors::Is(err.clone(), crate::io::EOF) {
            crate::io::ErrUnexpectedEOF.into()
        } else {
            err
        };
        return (x, width, err);
    }
    // Go: "Could check that the high byte is zero but it's not worth it."
    let mut i: int = 0;
    while i < width {
        x = x << 8 | uint64(body[i]);
        i += 1;
    }
    // Go: "+1 for length byte"
    width += 1;
    return (x, width, crate::errors::nil);
}

// go: sdk 1.25.5 encoding/gob/decode.go:310-315 float64FromBits
/// Go: undoes `floatBits`' byte reversal. Note it is NOT an involution
/// on the BITS of a float — it is on the uint64 — so a NaN payload
/// survives it exactly.
pub fn float64FromBits(u: uint64) -> float64 {
    let v = crate::math::bits::ReverseBytes64(u);
    return crate::math::Float64frombits(v);
}
