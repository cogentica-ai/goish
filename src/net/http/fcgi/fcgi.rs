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
//
// goishlint:ignore GOISH019 conn, bufWriter — the two shapes named in
// the note above. `conn`'s six Go fields sit in one `st` behind the
// Mutex Go spells out field-by-field; `bufWriter` cannot hold the
// aliased *streamWriter twice, so it carries the sink only.

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

// go: none — goish-only. Go spells this `io.ReadWriteCloser` inline;
// core io declares ReadCloser and ReadSeeker but not this trio, so it
// is named here rather than adding a public trait for one user.
pub trait ReadWriteCloser: crate::io::Reader + crate::io::Writer + crate::io::Closer {}
impl<T: crate::io::Reader + crate::io::Writer + crate::io::Closer> ReadWriteCloser for T {}

// go: sdk 1.25.5 net/http/fcgi/fcgi.go:101-110 conn
//
/// A FastCGI connection: the record framing layer over a transport.
///
/// Go guards the transport with `sync.Mutex` and keeps `buf`/`h` as
/// fields "to avoid allocations". goish puts every mutable field
/// inside the mutex instead of beside it, which is the same
/// invariant — nothing here is reachable without the lock — expressed
/// so the compiler enforces it.
pub struct conn {
    st: crate::sync::Mutex<connState>,
}

struct connState {
    rwc: alloc::boxed::Box<dyn ReadWriteCloser + Send + Sync>,
    closeErr: error,
    closed: bool,
    // to avoid allocations
    buf: crate::bytes::Buffer,
    h: header,
}

// go: sdk 1.25.5 net/http/fcgi/fcgi.go:112-114 newConn
pub fn newConn(
    rwc: alloc::boxed::Box<dyn ReadWriteCloser + Send + Sync>,
) -> alloc::sync::Arc<conn> {
    return alloc::sync::Arc::new(conn {
        st: crate::sync::Mutex::new(connState {
            rwc,
            closeErr: errors::nil,
            closed: false,
            buf: crate::bytes::Buffer::new(),
            h: header::default(),
        }),
    });
}

impl conn {
    // go: none — goish-only: Go's serve loop reads the transport
    // directly as `rec.read(c.conn.rwc)`, WITHOUT taking the conn
    // mutex, which guards writes only. goish's `rwc` lives inside that
    // mutex, so the read is a method on conn and the lock is released
    // before the record is handled — see child::serve for why nothing
    // is writing while this is reading.
    pub fn __read_record(&self, rec: &mut record) -> error {
        let mut g = self.st.Lock();
        return rec.read(&mut *g.rwc);
    }

    // go: sdk 1.25.5 net/http/fcgi/fcgi.go:117-125 conn.Close
    //
    /// Closes the conn if it is not already closed.
    pub fn Close(&self) -> error {
        let mut g = self.st.Lock();
        if !g.closed {
            g.closeErr = g.rwc.Close();
            g.closed = true;
        }
        return g.closeErr.clone();
    }

    // go: sdk 1.25.5 net/http/fcgi/fcgi.go:151-167 conn.writeRecord
    //
    /// Writes and sends a single record.
    ///
    /// Go serialises the header with reflective
    /// `binary.Write(&c.buf, binary.BigEndian, c.h)`. goish has no
    /// reflective encoder, so the eight bytes are written by hand in
    /// the struct's field order — Version, Type, Id, ContentLength,
    /// PaddingLength, Reserved — which is exactly what Go's reflection
    /// produces for this layout.
    pub fn writeRecord(&self, recType_: recType, reqId: uint16, b: &slice<byte>) -> error {
        let mut g = self.st.Lock();
        g.buf.Reset();
        let n = crate::len(b);
        g.h.init(recType_, reqId, n);

        let mut hb = [0u8; 8];
        hb[0] = g.h.Version;
        hb[1] = g.h.Type;
        binary::BigEndian.PutUint16(&mut hb[2..4], g.h.Id);
        binary::BigEndian.PutUint16(&mut hb[4..6], g.h.ContentLength);
        hb[6] = g.h.PaddingLength;
        hb[7] = g.h.Reserved;
        g.buf.Write(slice::<byte>::__from_vec(hb.to_vec()));

        g.buf.Write(b.clone());
        let padLen = g.h.PaddingLength as usize;
        let zeros = [0u8; 8];
        g.buf
            .Write(slice::<byte>::__from_vec(zeros[..padLen].to_vec()));

        let out = g.buf.Bytes();
        let (_, err) = g.rwc.Write(out);
        return err;
    }

    // go: sdk 1.25.5 net/http/fcgi/fcgi.go:169-174 conn.writeEndRequest
    pub fn writeEndRequest(&self, reqId: uint16, appStatus: int, protocolStatus: uint8) -> error {
        let mut b = alloc::vec![0u8; 8];
        binary::BigEndian.PutUint32(&mut b[0..4], crate::uint32(appStatus));
        b[4] = protocolStatus;
        return self.writeRecord(typeEndRequest, reqId, &slice::<byte>::__from_vec(b));
    }
}

// go: sdk 1.25.5 net/http/fcgi/fcgi.go:176-194 conn.writePairs
//
/// Writes name/value pairs as a stream of `typeParams`-style records.
///
/// Free rather than a method because it needs an `Arc<conn>` to hand
/// to the stream writer, and Go's `c *conn` receiver is already a
/// pointer being shared exactly that way.
pub fn writePairs(
    c: &alloc::sync::Arc<conn>,
    recType_: recType,
    reqId: uint16,
    pairs: &crate::gomap::map<string, string>,
) -> error {
    let mut w = newWriter(c, recType_, reqId);
    let mut b = slice::<byte>::__from_vec(alloc::vec![0u8; 8]);
    let keys = pairs.Keys();
    for ki in 0..keys.len() {
        let k = keys[ki].clone();
        let (v, _) = pairs.Get(k.clone());
        let n = encodeSize(&mut b, crate::uint32(crate::len(&k)));
        let mut tail = slice::<byte>::__from_vec((&(&*b)[n as usize..]).to_vec());
        let n2 = encodeSize(&mut tail, crate::uint32(crate::len(&v)));
        for i in 0..n2 {
            b[n + i] = tail[i];
        }
        let total = n + n2;
        let head = slice::<byte>::__from_vec((&(&*b)[..total as usize]).to_vec());
        let (_, err) = w.Write(head);
        if err != errors::nil {
            return err;
        }
        let (_, err) = w.WriteString(k.clone());
        if err != errors::nil {
            return err;
        }
        let (_, err) = w.WriteString(v.clone());
        if err != errors::nil {
            return err;
        }
    }
    let _ = w.Close();
    return errors::nil;
}

// go: sdk 1.25.5 net/http/fcgi/fcgi.go:252-256 streamWriter
//
/// Abstracts out the separation of a stream into discrete records.
/// It only writes `maxWrite` bytes at a time.
#[derive(Clone)]
pub struct streamWriter {
    c: alloc::sync::Arc<conn>,
    recType: recType,
    reqId: uint16,
}

impl crate::io::Writer for streamWriter {
    // go: sdk 1.25.5 net/http/fcgi/fcgi.go:258-272 streamWriter.Write
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        let mut nn: int = 0;
        let mut off: usize = 0;
        let total = p.len();
        while off < total {
            let mut n = total - off;
            if n > maxWrite as usize {
                n = maxWrite as usize;
            }
            let chunk = slice::<byte>::__from_vec((&(&*p)[off..off + n]).to_vec());
            let err = self.c.writeRecord(self.recType, self.reqId, &chunk);
            if err != errors::nil {
                return (nn, err);
            }
            nn += crate::int(n);
            off += n;
        }
        return (nn, errors::nil);
    }
}

impl crate::io::Closer for streamWriter {
    // go: sdk 1.25.5 net/http/fcgi/fcgi.go:274-277 streamWriter.Close
    //
    /// Sends an empty record to close the stream.
    fn Close(&mut self) -> error {
        return self
            .c
            .writeRecord(self.recType, self.reqId, &slice::<byte>::new());
    }
}

// go: sdk 1.25.5 net/http/fcgi/fcgi.go:231-234 bufWriter
//
/// A buffered writer whose Close flushes and then closes the
/// underlying stream.
///
/// **This is the aliasing that was recorded as fcgi's blocker.** Go
/// holds ONE `*streamWriter` twice — as the `io.Closer` field and,
/// inside the embedded `*bufio.Writer`, as the sink. Rust cannot
/// alias a mutable value like that, but it does not need to: a
/// `streamWriter` is three small fields over an `Arc<conn>`, so two
/// CLONES share the one conn and behave identically. The lock lives
/// on the conn, which is where Go's is too.
pub struct bufWriter {
    closer: streamWriter,
    w: crate::bufio::Writer<streamWriter>,
}

// go: none — goish-only. Go's bufWriter EMBEDS `*bufio.Writer`, so it
// inherits Write/Flush/WriteString; Rust has no embedding, so the two
// the child response needs are forwarded explicitly.
impl crate::io::Writer for bufWriter {
    // go: none — forwards to the embedded bufio.Writer.
    fn Write(
        &mut self,
        p: crate::goslice::slice<crate::types::byte>,
    ) -> (crate::types::int, error) {
        return crate::io::Writer::Write(&mut self.w, p);
    }
}

impl bufWriter {
    // go: none — see the Writer impl above.
    pub fn Flush(&mut self) -> error {
        return self.w.Flush();
    }

    // go: sdk 1.25.5 net/http/fcgi/fcgi.go:236-242 bufWriter.Close
    pub fn Close(&mut self) -> error {
        let err = self.w.Flush();
        if err != errors::nil {
            let _ = crate::io::Closer::Close(&mut self.closer);
            return err;
        }
        return crate::io::Closer::Close(&mut self.closer);
    }

    // go: none — Go promotes Write/WriteString from the embedded
    // *bufio.Writer; Rust has no embedding, so they forward.
    pub fn Write(&mut self, p: slice<byte>) -> (int, error) {
        return self.w.Write(p);
    }

    // go: none — as Write above: promoted from the embedded
    // *bufio.Writer in Go.
    pub fn WriteString(&mut self, s: string) -> (int, error) {
        return self.w.WriteString(s);
    }
}

// go: sdk 1.25.5 net/http/fcgi/fcgi.go:244-248 newWriter
pub fn newWriter(c: &alloc::sync::Arc<conn>, recType_: recType, reqId: uint16) -> bufWriter {
    let s = streamWriter {
        c: c.clone(),
        recType: recType_,
        reqId: reqId,
    };
    let w = crate::bufio::NewWriterSize(s.clone(), maxWrite);
    return bufWriter { closer: s, w };
}

// go: sdk 1.25.5 net/http/fcgi/fcgi.go:127-130 record
//
/// One FastCGI record read off the wire: an 8-byte header plus a body
/// big enough for the largest legal content and padding.
pub struct record {
    pub h: header,
    pub buf: slice<byte>,
}

impl record {
    // go: none — goish-only. Go's `buf` is a fixed
    // `[maxWrite + maxPad]byte` array inside the struct; goish uses a
    // slice, which must be sized once rather than by declaration.
    pub fn new() -> record {
        return record {
            h: header::default(),
            buf: slice::<byte>::__from_vec(alloc::vec![0u8; (maxWrite + maxPad) as usize]),
        };
    }

    // go: sdk 1.25.5 net/http/fcgi/fcgi.go:132-144 record.read
    //
    /// Go reads the header with reflective `binary.Read`; goish parses
    /// the same eight bytes by hand, matching header's field order.
    pub fn read(&mut self, r: &mut dyn crate::io::Reader) -> error {
        let mut hb = slice::<byte>::__from_vec(alloc::vec![0u8; 8]);
        let (_, err) = crate::io::ReadFull(r, &mut hb);
        if err != errors::nil {
            return err;
        }
        self.h.Version = hb[0];
        self.h.Type = hb[1];
        self.h.Id = binary::BigEndian.Uint16(&(&*hb)[2..4]);
        self.h.ContentLength = binary::BigEndian.Uint16(&(&*hb)[4..6]);
        self.h.PaddingLength = hb[6];
        self.h.Reserved = hb[7];

        if self.h.Version != 1 {
            return errors::New(string("fcgi: invalid header version"));
        }
        let n = crate::int(self.h.ContentLength) + crate::int(self.h.PaddingLength);
        let mut body = slice::<byte>::__from_vec(alloc::vec![0u8; n as usize]);
        let (_, err) = crate::io::ReadFull(r, &mut body);
        if err != errors::nil {
            return err;
        }
        for i in 0..n {
            self.buf[i] = body[i];
        }
        return errors::nil;
    }

    // go: sdk 1.25.5 net/http/fcgi/fcgi.go:146-148 record.content
    pub fn content(&self) -> slice<byte> {
        let n = self.h.ContentLength as usize;
        return slice::<byte>::__from_vec((&(&*self.buf)[..n]).to_vec());
    }
}
