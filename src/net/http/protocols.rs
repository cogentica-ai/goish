// net/http/protocols — line-by-line port of Go 1.25 src/net/http/http.go
// (Protocols struct + NoBody value).
//
// Protocols is a Go 1.25 addition (issue 70811). We keep the
// HTTP1/HTTP2/UnencryptedHTTP2 surface; the rest of net/http only
// reads these flags and is unaware of bundled HTTP/2 in slim goish.
//
// NoBody is a public io.ReadCloser+WriterTo whose Read returns
// (0, io.EOF) and WriteTo returns (0, nil). Same shape as Go.

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use crate::gostring::string;
use crate::types::int;
use crate::{append, make};

// ─── Protocols ────────────────────────────────────────────────────

/// Bit constants. Mirror http.go:34-38 (proto* private const).
const protoHTTP1: u8 = 1 << 0;
const protoHTTP2: u8 = 1 << 1;
const protoUnencryptedHTTP2: u8 = 1 << 2;

/// Protocols is a set of HTTP protocols.
/// The zero value is an empty set of protocols.
///
/// Mirrors `Protocols` (http.go:30).
#[derive(Copy, Clone, Default, PartialEq, Eq)]
pub struct Protocols {
    bits: u8,
}

impl Protocols {
    /// Construct an empty Protocols set. Go uses zero value; this is
    /// a tiny ergonomic helper.
    pub fn new() -> Self {
        Protocols { bits: 0 }
    }

    /// HTTP1 reports whether p includes HTTP/1.
    pub fn HTTP1(self) -> bool {
        self.bits & protoHTTP1 != 0
    }

    /// SetHTTP1 adds or removes HTTP/1 from p.
    pub fn SetHTTP1(&mut self, ok: bool) {
        self.setBit(protoHTTP1, ok);
    }

    /// HTTP2 reports whether p includes HTTP/2.
    pub fn HTTP2(self) -> bool {
        self.bits & protoHTTP2 != 0
    }

    /// SetHTTP2 adds or removes HTTP/2 from p.
    pub fn SetHTTP2(&mut self, ok: bool) {
        self.setBit(protoHTTP2, ok);
    }

    /// UnencryptedHTTP2 reports whether p includes unencrypted HTTP/2.
    pub fn UnencryptedHTTP2(self) -> bool {
        self.bits & protoUnencryptedHTTP2 != 0
    }

    /// SetUnencryptedHTTP2 adds or removes unencrypted HTTP/2 from p.
    pub fn SetUnencryptedHTTP2(&mut self, ok: bool) {
        self.setBit(protoUnencryptedHTTP2, ok);
    }

    fn setBit(&mut self, bit: u8, ok: bool) {
        if ok {
            self.bits |= bit;
        } else {
            self.bits &= !bit;
        }
    }

    /// Mirrors `Protocols.String()` (http.go:66).
    pub fn String(self) -> string {
        let mut s: crate::slice<string> = make!([]string, 0);
        if self.HTTP1() {
            s = append!(s, string::from("HTTP1"));
        }
        if self.HTTP2() {
            s = append!(s, string::from("HTTP2"));
        }
        if self.UnencryptedHTTP2() {
            s = append!(s, string::from("UnencryptedHTTP2"));
        }
        let inner = crate::strings::Join(s, string::from(","));
        let mut out = string::from("{");
        out = out + inner;
        out + string::from("}")
    }
}

// ─── NoBody ──────────────────────────────────────────────────────

/// `http.NoBody` — an `io.ReadCloser` with no bytes. Read always
/// returns EOF and Close always returns nil. Mirrors http.go:177-189.
///
/// The Go API is a *value*: `var NoBody = noBody{}`. In goish we
/// expose `http::NoBody()` returning a fresh zero-sized value. Each
/// call yields the same observable behavior, so equality semantics
/// match.
pub fn NoBody() -> noBody {
    noBody {}
}

#[derive(Copy, Clone, Default)]
pub struct noBody {}

impl crate::io::Reader for noBody {
    fn Read(&mut self, _p: &mut crate::slice<crate::types::byte>) -> (int, crate::errors::error) {
        // Go: return 0, io.EOF
        (0, crate::io::EOF())
    }
}

impl crate::io::Closer for noBody {
    fn Close(&mut self) -> crate::errors::error {
        // Go: return nil
        crate::nil
    }
}

impl crate::io::WriterTo for noBody {
    fn WriteTo(&mut self, _w: &mut dyn crate::io::Writer) -> (i64, crate::errors::error) {
        // Go: return 0, nil
        (0, crate::nil)
    }
}
