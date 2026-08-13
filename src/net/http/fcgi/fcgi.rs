// net/http/fcgi/fcgi.go — the FastCGI wire protocol.
//
// Ported: the record type/status/role constants, the record header,
// the begin-request body, and the name/value pair size codec. These
// need nothing beyond encoding/binary and are exercisable on their
// own.
//
// NOT ported yet: conn, record, bufWriter, streamWriter and the
// writeRecord/writePairs path. Go's `conn` groups six fields under one
// sync.Mutex and its `streamWriter` is ALIASED — bufWriter holds the
// same *streamWriter both as its io.Closer and, inside a bufio.Writer,
// as its sink. Rust cannot alias that way, so the layer wants an
// Arc<conn> with a Clone streamWriter, which is a design decision
// rather than a transcription and is left for its own commit.

#![allow(non_snake_case)]

extern crate alloc;

use crate::encoding::binary;
use crate::errors::{self, error};
use crate::goslice::slice;
use crate::string;
use crate::types::{byte, int, uint16, uint32, uint8};

// go: sdk 1.25.5 net/http/fcgi/fcgi.go:25-27 recType
/// A record type, as defined by the FastCGI specification §8.
pub type recType = uint8;

// go: sdk 1.25.5 net/http/fcgi/fcgi.go:29-41 typeBeginRequest
pub const typeBeginRequest: recType = 1;
pub const typeAbortRequest: recType = 2;
pub const typeEndRequest: recType = 3;
pub const typeParams: recType = 4;
pub const typeStdin: recType = 5;
pub const typeStdout: recType = 6;
pub const typeStderr: recType = 7;
pub const typeData: recType = 8;
pub const typeGetValues: recType = 9;
pub const typeGetValuesResult: recType = 10;
pub const typeUnknownType: recType = 11;

// go: sdk 1.25.5 net/http/fcgi/fcgi.go:43-44 flagKeepConn
/// Keep the connection between web server and responder open after the
/// request.
pub const flagKeepConn: uint8 = 1;

// go: sdk 1.25.5 net/http/fcgi/fcgi.go:46-49 maxWrite
pub const maxWrite: int = 65535; // maximum record body
pub const maxPad: int = 255;

// go: sdk 1.25.5 net/http/fcgi/fcgi.go:51-55 roleResponder
pub const roleResponder: int = 1; // only Responders are implemented
pub const roleAuthorizer: int = 2;
pub const roleFilter: int = 3;

// go: sdk 1.25.5 net/http/fcgi/fcgi.go:57-62 statusRequestComplete
pub const statusRequestComplete: int = 0;
pub const statusCantMultiplex: int = 1;
pub const statusOverloaded: int = 2;
pub const statusUnknownRole: int = 3;

// go: sdk 1.25.5 net/http/fcgi/fcgi.go:64-71 header
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct header {
    pub Version: uint8,
    pub Type: recType,
    pub Id: uint16,
    pub ContentLength: uint16,
    pub PaddingLength: uint8,
    pub Reserved: uint8,
}

impl header {
    // go: sdk 1.25.5 net/http/fcgi/fcgi.go:92-99 header.init
    //
    // The padding rule is the subtle part: `-contentLength & 7` rounds
    // the body up to a multiple of 8 using two's-complement negation,
    // so a 0-length body pads 0 and a 1-length body pads 7. Written in
    // Rust as a wrapping negation on the byte, because `-` on an
    // unsigned type is not an operator here.
    pub fn init(&mut self, recType_: recType, reqId: uint16, contentLength: int) {
        self.Version = 1;
        self.Type = recType_;
        self.Id = reqId;
        self.ContentLength = crate::uint16(contentLength);
        self.PaddingLength = crate::uint8(contentLength).wrapping_neg() & 7;
    }
}

// go: sdk 1.25.5 net/http/fcgi/fcgi.go:73-77 beginRequest
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct beginRequest {
    pub role: uint16,
    pub flags: uint8,
    pub reserved: [uint8; 5],
}

impl beginRequest {
    // go: sdk 1.25.5 net/http/fcgi/fcgi.go:79-87 beginRequest.read
    pub fn read(&mut self, content: slice<byte>) -> error {
        if content.Len() != 8 {
            return errors::New(string("fcgi: invalid begin request record"));
        }
        self.role = binary::BigEndian.Uint16(content.as_ref());
        self.flags = content[2];
        return errors::nil;
    }
}

// go: sdk 1.25.5 net/http/fcgi/fcgi.go:196-210 readSize
//
/// Decode a FastCGI name/value length prefix, returning the value and
/// the number of bytes it occupied.
///
/// The high bit of the first byte selects the width: clear means a
/// one-byte length of 0..127, set means a four-byte big-endian length
/// with bit 31 masked off. A short buffer yields `(0, 0)` — the caller
/// distinguishes "nothing decoded" by the zero length, not an error.
pub fn readSize(s: slice<byte>) -> (uint32, int) {
    if s.Len() == 0 {
        return (0, 0);
    }
    let mut size = crate::uint32(s[0]);
    let mut n: int = 1;
    if size & (1 << 7) != 0 {
        if s.Len() < 4 {
            return (0, 0);
        }
        n = 4;
        size = binary::BigEndian.Uint32(s.as_ref());
        size &= !(1u32 << 31); // Go: size &^= 1 << 31
    }
    return (size, n);
}

// go: sdk 1.25.5 net/http/fcgi/fcgi.go:212-217 readString
//
/// Take the first `size` bytes of `s` as a string, or "" when `size`
/// overruns the buffer.
pub fn readString(s: slice<byte>, size: uint32) -> string {
    if size > crate::uint32(s.Len()) {
        return string("");
    }
    return string::from_bytes(&s.slice(0, crate::int(size)));
}

// go: sdk 1.25.5 net/http/fcgi/fcgi.go:219-227 encodeSize
//
/// Write a FastCGI length prefix into `b`, returning its width.
///
/// The inverse of [`readSize`]: 0..127 encodes in one byte, anything
/// larger takes four with bit 31 set as the wide-form marker.
pub fn encodeSize(b: &mut slice<byte>, size: uint32) -> int {
    if size > 127 {
        let wide = size | (1u32 << 31);
        binary::BigEndian.PutUint32(b.as_mut(), wide);
        return 4;
    }
    b[0] = crate::byte(size);
    return 1;
}
