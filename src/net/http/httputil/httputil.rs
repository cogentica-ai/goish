// net/http/httputil/httputil.go — the chunked reader/writer wrappers.
//
// Go's httputil.go is 41 lines: NewChunkedReader, NewChunkedWriter and
// ErrLineTooLong, all thin re-exports of net/http/internal. It needs
// only io and that package, which is why it splits out cleanly.

#![allow(non_snake_case)]
#![allow(dead_code)]

use crate::io::{Reader, Writer};

use super::super::internal::chunked::{ChunkedReader, ChunkedWriter};

// go: sdk 1.25.5 net/http/httputil/httputil.go:20-22 NewChunkedReader
/// `httputil.NewChunkedReader(r)` (httputil.go:21) — translate from
/// HTTP "chunked" format. Returns an `io.Reader` that yields the
/// dechunked body and signals EOF on the terminator. Thin wrapper
/// over the internal `chunked.NewChunkedReader`.
pub fn NewChunkedReader<R: Reader>(r: R) -> ChunkedReader<R> {
    return super::super::internal::chunked::NewChunkedReader(r);
}

// go: sdk 1.25.5 net/http/httputil/httputil.go:35-37 NewChunkedWriter
/// `httputil.NewChunkedWriter(w)` (httputil.go:36) — wrap `w` so
/// writes are emitted as HTTP "chunked" frames. Closing the writer
/// sends the terminating zero-length chunk but not the trailing CRLF
/// — callers writing trailers (or a final empty trailer) must emit
/// the closing CRLF themselves.
pub fn NewChunkedWriter<W: Writer>(w: W) -> ChunkedWriter<W> {
    return super::super::internal::chunked::NewChunkedWriter(w);
}

// goishlint:ignore GOISH021 ErrLineTooLong — Go writes
// `var ErrLineTooLong = internal.ErrLineTooLong`, an ALIAS of the
// internal sentinel, not a second one. goish spells that as a
// `pub use`, which GOISH021 does not see as a declaration. Declaring
// it locally instead would mint a SECOND error value and break
// `errors::Is(err, ErrLineTooLong)` for anything comparing against
// the internal one — goish's errors match by Arc::ptr_eq.
// go: sdk 1.25.5 net/http/httputil/httputil.go:41-41 ErrLineTooLong
/// `httputil.ErrLineTooLong` (httputil.go:43) — re-export of
/// `chunked::ErrLineTooLong`. Same Arc identity.
pub use super::super::internal::chunked::ErrLineTooLong;
