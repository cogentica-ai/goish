// net/http/transfer — message-framing rules shared by requests and
// responses: how many body bytes to expect, whether the connection
// closes afterwards, and which headers a status suppresses.
//
// Partial port of Go 1.25.5 net/http/transfer.go. The framing
// DECISIONS port verbatim and are the security-sensitive half (RFC
// 9112 request smuggling and response splitting both live here). The
// transferWriter MACHINERY (newTransferWriter through unwrapBody,
// with the 200ms body probe) is ported and wired into the client's
// request-write path — a streaming request body with unknown length
// goes out `Transfer-Encoding: chunked`.
//
// Not yet ported from transfer.go (readTransfer's read half):
//   readTransfer, body.Read/readLocked/readTrailer/Close/
//   unreadDataSizeLocked, bodyLocked, mergeSetHeader's caller side.

#![allow(non_snake_case, non_camel_case_types)]

extern crate alloc;

use alloc::vec::Vec;

use crate::errors::{self, error};
use crate::goslice::slice;
use crate::string;
use crate::types::byte;
use crate::{int, int64};

use super::header::{hasToken, CanonicalHeaderKey, Header};

// go: sdk 1.25.5 net/http/transfer.go:31 ErrLineTooLong
//
// Go writes `var ErrLineTooLong = internal.ErrLineTooLong`, an ALIAS.
// Re-export rather than redeclare so `errors::Is` (which matches by
// Arc::ptr_eq) still succeeds against the internal sentinel.
pub use super::internal::chunked::ErrLineTooLong;

crate::var! {
    // go: sdk 1.25.5 net/http/transfer.go:829 ErrBodyReadAfterClose
    pub ErrBodyReadAfterClose: error = "http: invalid Read on closed Body";
}

// ─── trivial readers ────────────────────────────────────────────────

// go: sdk 1.25.5 net/http/transfer.go:33-35 errorReader
/// A reader that fails every Read with a fixed error.
pub struct errorReader {
    pub err: error,
}

impl crate::io::Reader for errorReader {
    // go: sdk 1.25.5 net/http/transfer.go:37-39 errorReader.Read
    fn Read(&mut self, _p: &mut slice<byte>) -> (int, error) {
        return (0, self.err.clone());
    }
}

// go: sdk 1.25.5 net/http/transfer.go:41-44 byteReader
/// A reader yielding exactly one byte, then EOF. Go returns the byte
/// AND `io.EOF` from the same call, which callers rely on.
pub struct byteReader {
    pub b: byte,
    pub done: bool,
}

impl crate::io::Reader for byteReader {
    // go: sdk 1.25.5 net/http/transfer.go:46-55 byteReader.Read
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        if self.done {
            return (0, crate::io::EOF.into());
        }
        if p.Len() == 0 {
            return (0, errors::nil);
        }
        self.done = true;
        p[int(0)] = self.b;
        return (1, crate::io::EOF.into());
    }
}

// ─── transferReader ─────────────────────────────────────────────────

// go: sdk 1.25.5 net/http/transfer.go:440-453 transferReader
/// The inputs and outputs of reading a message's framing. Only the
/// header-derived half is populated today: `Body` waits on the Body
/// redesign, so `readTransfer` (which fills it) is not ported.
pub struct transferReader {
    // Input
    pub Header: Header,
    pub StatusCode: int,
    pub RequestMethod: string,
    pub ProtoMajor: int,
    pub ProtoMinor: int,
    // Output
    pub Body: Option<alloc::boxed::Box<dyn crate::io::ReadCloser>>,
    pub ContentLength: i64,
    pub Chunked: bool,
    pub Close: bool,
    pub Trailer: Header,
}

impl transferReader {
    // go: sdk 1.25.5 net/http/transfer.go:455-457 transferReader.protoAtLeast
    pub fn protoAtLeast(&self, m: int, n: int) -> bool {
        return self.ProtoMajor > m || (self.ProtoMajor == m && self.ProtoMinor >= n);
    }

    // go: sdk 1.25.5 net/http/transfer.go:631-658 transferReader.parseTransferEncoding
    /// Go: "parseTransferEncoding sets t.Chunked based on the
    /// Transfer-Encoding header."
    ///
    /// Go's comment is worth keeping verbatim: this is "one of the
    /// most security sensitive surfaces in HTTP/1.1 due to the risk of
    /// request smuggling, so we keep it strict and simple" — a single
    /// Transfer-Encoding header, and only if it is exactly `chunked`.
    pub fn parseTransferEncoding(&mut self) -> error {
        // Go: raw, present := t.Header["Transfer-Encoding"]
        if !self.Header.has(string("Transfer-Encoding")) {
            return errors::nil;
        }
        let raw = self.Header.Values(string("Transfer-Encoding"));
        self.Header.Del(string("Transfer-Encoding"));

        // Go: "Issue 12785; ignore Transfer-Encoding on HTTP/1.0
        // requests."
        if !self.protoAtLeast(1, 1) {
            return errors::nil;
        }

        if raw.Len() != 1 {
            return newUnsupportedTEError(crate::fmt::Sprintf!(
                "too many transfer encodings: %q",
                __quote_list(&raw)
            ));
        }
        if !super::internal::ascii::EqualFold(raw[int(0)].clone(), string("chunked")) {
            return newUnsupportedTEError(crate::fmt::Sprintf!(
                "unsupported transfer encoding: %q",
                raw[int(0)].clone()
            ));
        }

        self.Chunked = true;
        return errors::nil;
    }
}

// ─── transferWriter ─────────────────────────────────────────────────

use super::server::readResult;

// go: sdk 1.25.5 net/http/transfer.go:61-76 transferWriter
/// Go: "transferWriter inspects the fields of a user-supplied Request
/// or Response, sanitizes them without changing the user object and
/// provides methods for writing the respective header, body and
/// trailer in wire format."
///
/// Go splits Body (io.Reader) from BodyCloser (io.Closer) because the
/// probe may re-wrap Body while Close must still reach the original;
/// goish keeps the same split with `Body` handles (Arc-shared state,
/// so the re-wrap and the closer see one stream).
#[derive(Clone)]
pub struct transferWriter {
    pub Method: string,
    pub(crate) Body: Option<super::Body>,
    pub(crate) BodyCloser: Option<super::Body>,
    pub ResponseToHEAD: bool,
    pub ContentLength: i64,
    pub Close: bool,
    pub TransferEncoding: slice<string>,
    pub Header: Header,
    pub Trailer: Header,
    pub IsResponse: bool,
    pub(crate) bodyReadError: error,
    /// Go: "flush headers to network before body"
    pub FlushHeaders: bool,
    /// Go: "non-nil if probeRequestBody called"
    pub(crate) ByteReadCh: Option<crate::gochan::chan<readResult>>,
}

impl Default for transferWriter {
    // go: none — goish-only: Go zero-values the struct; Header has no
    // Default derive, so the zero value is written out.
    fn default() -> Self {
        return transferWriter {
            Method: string::new(),
            Body: None,
            BodyCloser: None,
            ResponseToHEAD: false,
            ContentLength: 0,
            Close: false,
            TransferEncoding: slice::<string>::__from_vec(Vec::new()),
            Header: Header::new(),
            Trailer: Header::new(),
            IsResponse: false,
            bodyReadError: errors::nil,
            FlushHeaders: false,
            ByteReadCh: None,
        };
    }
}

// go: none — goish-only: the two shapes Go passes to newTransferWriter
// as `any` and type-switches on.
pub(crate) enum TransferMsg<'a> {
    Req(&'a super::Request),
    Resp(&'a super::Response),
}

// go: sdk 1.25.5 net/http/transfer.go:78-150 newTransferWriter
/// Go: extract the transfer-relevant fields from a Request or
/// Response, then sanitize the (Body, ContentLength, TransferEncoding)
/// triple. The chunked-or-not decision for an outgoing request body
/// happens HERE (shouldSendChunkedRequestBody, possibly probing the
/// body), not at write time.
pub(crate) fn newTransferWriter(r: TransferMsg) -> (transferWriter, error) {
    let mut t = transferWriter::default();

    // Go: "Extract relevant fields"
    let atLeastHTTP11: bool;
    match r {
        TransferMsg::Req(rr) => {
            // Go: if rr.ContentLength != 0 && rr.Body == nil — an
            // exhausted in-memory Body is goish's nil.
            if rr.ContentLength != 0 && matches!(rr.Body.__eager_len(), Some(0)) {
                return (
                    t,
                    errors::New(crate::fmt::Sprintf!(
                        "http: Request.ContentLength=%d with nil Body",
                        int64(rr.ContentLength)
                    )),
                );
            }
            t.Method = super::request::valueOrDefault(rr.Method.clone(), "GET");
            t.Close = rr.Close;
            t.TransferEncoding = rr.TransferEncoding.clone();
            t.Header = rr.Header.clone();
            t.Trailer = rr.Trailer.clone();
            if !matches!(rr.Body.__eager_len(), Some(0)) {
                t.Body = Some(rr.Body.clone());
                t.BodyCloser = Some(rr.Body.clone());
            }
            t.ContentLength = rr.outgoingLength();
            if t.ContentLength < 0
                && t.TransferEncoding.Len() == 0
                && t.shouldSendChunkedRequestBody()
            {
                t.TransferEncoding = crate::make!([]string, 0);
                t.TransferEncoding = crate::append!(t.TransferEncoding, string("chunked"));
            }
            // Go: "If there's a body, conservatively flush the headers
            // to any bufio.Writer we're writing to, just in case the
            // server needs the headers early, before we copy the body
            // and possibly block. We make an exception for the common
            // standard library in-memory types" (Issue 22088).
            if t.ContentLength != 0 && !isKnownInMemoryReader(&t.Body) {
                t.FlushHeaders = true;
            }
            atLeastHTTP11 = true; // Go: "Transport requests are always 1.1 or 2.0"
        }
        TransferMsg::Resp(rr) => {
            t.IsResponse = true;
            if !rr.Request.IsNil() {
                t.Method = rr.Request.Must().Method.clone();
            }
            if !matches!(rr.Body.__eager_len(), Some(0)) {
                t.Body = Some(rr.Body.clone());
                t.BodyCloser = Some(rr.Body.clone());
            }
            t.ContentLength = int64(rr.ContentLength);
            t.Close = rr.Close;
            t.TransferEncoding = rr.TransferEncoding.clone();
            t.Header = rr.Header.clone();
            t.Trailer = rr.Trailer.clone();
            atLeastHTTP11 = rr.ProtoAtLeast(1, 1);
            t.ResponseToHEAD = noResponseBodyExpected(t.Method.clone());
        }
    }

    // Go: "Sanitize Body,ContentLength,TransferEncoding"
    if t.ResponseToHEAD {
        t.Body = None;
        if chunked(&t.TransferEncoding) {
            t.ContentLength = -1;
        }
    } else {
        if !atLeastHTTP11 || t.Body.is_none() {
            t.TransferEncoding = crate::make!([]string, 0);
        }
        if chunked(&t.TransferEncoding) {
            t.ContentLength = -1;
        } else if t.Body.is_none() {
            // Go: "no chunking, no body"
            t.ContentLength = 0;
        }
    }

    // Go: "Sanitize Trailer"
    if !chunked(&t.TransferEncoding) {
        t.Trailer = Header::new();
    }

    return (t, errors::nil);
}

impl transferWriter {
    // go: sdk 1.25.5 net/http/transfer.go:170-206 transferWriter.shouldSendChunkedRequestBody
    /// Go: "the case we really want to prevent is sending a GET or
    /// other typically-bodyless request to a server with a chunked
    /// body when the body has zero bytes, since GETs with bodies …
    /// are approximately never seen in the wild and confuse most
    /// servers" (Issue 18257). For those methods the body is PROBED;
    /// an empty one is dropped entirely.
    pub(crate) fn shouldSendChunkedRequestBody(&mut self) -> bool {
        // Go: "Note that t.ContentLength is the corrected content
        // length from rr.outgoingLength, so 0 actually means zero."
        if self.ContentLength >= 0 || self.Body.is_none() {
            return false; // Go: "redundant checks; caller did them"
        }
        if self.Method == "CONNECT" {
            return false;
        }
        if super::request::requestMethodUsuallyLacksBody(self.Method.clone()) {
            // Go: "Only probe the Request.Body for GET/HEAD/DELETE/etc
            // requests, because it's only those types of requests
            // that confuse servers."
            self.probeRequestBody(); // Go: "adjusts t.Body, t.ContentLength"
            return self.Body.is_some();
        }
        // Go: "For all other request types (PUT, POST, PATCH, or
        // anything made-up we've never heard of), assume it's normal."
        return true;
    }

    // go: sdk 1.25.5 net/http/transfer.go:208-248 transferWriter.probeRequestBody
    /// Go: "reads a byte from t.Body to see whether it's empty
    /// (returns io.EOF right away). But because we've had problems
    /// with this blocking users in the past (issue 17480) when the
    /// body is a pipe … we need to be careful and bound how long we
    /// wait for it" — 200ms, then assume chunked and read the probed
    /// byte back asynchronously (finishAsyncByteRead).
    pub(crate) fn probeRequestBody(&mut self) {
        let ch: crate::gochan::chan<readResult> = crate::make!(chan readResult, 1);
        self.ByteReadCh = Some(ch.clone());
        // Go: go func(body io.Reader) { … }(t.Body) — the goroutine
        // reads through a shared handle to the same stream.
        let body = self.Body.clone().unwrap();
        let ch_inner = ch.clone();
        crate::go!(stack(64 * crate::KB), move || {
            let mut body = body;
            let mut buf = crate::make!([]byte, 1);
            let mut rres = readResult::default();
            let (n, err) = crate::io::Reader::Read(&mut body, &mut buf);
            rres.n = n;
            rres.err = err;
            if rres.n == 1 {
                rres.b = buf[0];
            }
            let _ = ch_inner.Send(rres);
        });
        let timer = crate::time::NewTimer(crate::time::Duration(200 * 1_000_000));
        crate::select! {
            let rres = ch.Recv() => {
                timer.Stop();
                if rres.n == 0 && errors::Is(rres.err.clone(), crate::io::EOF) {
                    // Go: "It was empty."
                    self.Body = None;
                    self.ContentLength = 0;
                } else if rres.n == 1 {
                    // Go: io.MultiReader(&byteReader{b}, t.Body) — or,
                    // if the read also errored, the error replaces the
                    // rest of the stream.
                    let (inner, err_after) = if rres.err.IsNil() {
                        (self.Body.clone(), None)
                    } else {
                        (None, Some(errorReader { err: rres.err.clone() }))
                    };
                    self.Body = Some(super::Body::from_reader(alloc::boxed::Box::new(
                        probedBody {
                            pending: Some(byteReader { b: rres.b, done: false }),
                            wait: None,
                            inner,
                            err_after,
                        },
                    )));
                } else if !rres.err.IsNil() {
                    // Go: t.Body = errorReader{rres.err}
                    self.Body = Some(super::Body::from_reader(alloc::boxed::Box::new(
                        probedBody {
                            pending: None,
                            wait: None,
                            inner: None,
                            err_after: Some(errorReader { err: rres.err.clone() }),
                        },
                    )));
                }
            },
            let _ = (timer.C).Recv() => {
                // Go: "Too slow. Don't wait. Read it later, and keep
                // assuming that this is ContentLength == -1 (unknown),
                // which means we'll send a 'Transfer-Encoding: chunked'
                // header." The probed byte is collected on the body's
                // first Read (finishAsyncByteRead).
                self.Body = Some(super::Body::from_reader(alloc::boxed::Box::new(
                    probedBody {
                        pending: None,
                        wait: Some(finishAsyncByteRead { ch: ch.clone() }),
                        inner: self.Body.clone(),
                        err_after: None,
                    },
                )));
                // Go: "Request that Request.Write flush the headers to
                // the network before writing the body, since our body
                // may not become readable until it's seen the response
                // headers."
                self.FlushHeaders = true;
            },
        }
        return;
    }

    // go: sdk 1.25.5 net/http/transfer.go:278-335 transferWriter.writeHeader
    /// Emit the transfer-owned header lines: `Connection: close`,
    /// exactly one of Content-Length / `Transfer-Encoding: chunked`,
    /// and the `Trailer:` announcement. Everything else is the
    /// caller's (Request.write / response writer) job.
    pub(crate) fn writeHeader(
        &self,
        w: &mut dyn crate::io::Writer,
        trace: Option<&super::httptrace::ClientTrace>,
    ) -> error {
        if self.Close && !hasToken(self.Header.Get(string("Connection")), string("close")) {
            let (_, err) = w.Write(crate::convert::bytes("Connection: close\r\n"));
            if !err.IsNil() {
                return err;
            }
            if let Some(tr) = trace {
                if let Some(f) = &tr.WroteHeaderField {
                    let mut v = crate::make!([]string, 0);
                    v = crate::append!(v, string("close"));
                    f(string("Connection"), v);
                }
            }
        }

        // Go: "Write Content-Length and/or Transfer-Encoding whose
        // values are a function of the sanitized field triple (Body,
        // ContentLength, TransferEncoding)"
        if self.shouldSendContentLength() {
            let line = crate::fmt::Sprintf!("Content-Length: %d\r\n", self.ContentLength);
            let (_, err) = w.Write(crate::convert::bytes(line));
            if !err.IsNil() {
                return err;
            }
            if let Some(tr) = trace {
                if let Some(f) = &tr.WroteHeaderField {
                    let mut v = crate::make!([]string, 0);
                    v = crate::append!(v, crate::strconv::FormatInt(self.ContentLength, 10));
                    f(string("Content-Length"), v);
                }
            }
        } else if chunked(&self.TransferEncoding) {
            let (_, err) = w.Write(crate::convert::bytes("Transfer-Encoding: chunked\r\n"));
            if !err.IsNil() {
                return err;
            }
            if let Some(tr) = trace {
                if let Some(f) = &tr.WroteHeaderField {
                    let mut v = crate::make!([]string, 0);
                    v = crate::append!(v, string("chunked"));
                    f(string("Transfer-Encoding"), v);
                }
            }
        }

        // Go: "Write Trailer header"
        {
            let mut keys_v: Vec<string> = Vec::new();
            for (k, _) in crate::range!(&self.Trailer) {
                let k = CanonicalHeaderKey(k.clone());
                if k == "Transfer-Encoding" || k == "Trailer" || k == "Content-Length" {
                    return super::request::badStringError(string("invalid Trailer key"), k);
                }
                keys_v.push(k);
            }
            if !keys_v.is_empty() {
                // Go: slices.Sort(keys)
                keys_v.sort();
                let keys = slice::<string>::__from_vec(keys_v);
                let line = string("Trailer: ")
                    + crate::strings::Join(keys.clone(), string(","))
                    + string("\r\n");
                let (_, err) = w.Write(crate::convert::bytes(line));
                if !err.IsNil() {
                    return err;
                }
                if let Some(tr) = trace {
                    if let Some(f) = &tr.WroteHeaderField {
                        f(string("Trailer"), keys);
                    }
                }
            }
        }

        return errors::nil;
    }

    // go: sdk 1.25.5 net/http/transfer.go:338-407 transferWriter.writeBody
    /// Go: "always closes t.BodyCloser". Chunked-encodes when the
    /// sanitized TransferEncoding says so; with a known ContentLength
    /// it copies exactly that many bytes then DRAINS the rest, and a
    /// length mismatch is a hard error, not a silent short body.
    ///
    /// goish deviations, both about buffering: the FlushAfterChunkWriter
    /// wrap (Go applies it when w is a *bufio.Writer) and the CONNECT
    /// bufioFlushWriter wrap are skipped — the client hands writeBody
    /// the conn itself, unbuffered, so there is nothing to flush.
    pub(crate) fn writeBody(&mut self, w: &mut dyn crate::io::Writer) -> error {
        let mut err: error;
        let mut ncopy: i64 = 0;

        // Go: "Write body. We 'unwrap' the body first if it was
        // wrapped in a nopCloser or readTrackingBody."
        if !self.ResponseToHEAD && self.Body.is_some() {
            let mut body = self.unwrapBody();
            if chunked(&self.TransferEncoding) {
                let mut cw = super::internal::chunked::NewChunkedWriter(&mut *w);
                let (_, e) = self.doBodyCopy(&mut cw, &mut body);
                err = e;
                if err.IsNil() {
                    err = crate::io::Closer::Close(&mut cw);
                }
            } else if self.ContentLength == -1 {
                let (n, e) = self.doBodyCopy(w, &mut body);
                ncopy = n;
                err = e;
            } else {
                let mut lr = crate::io::LimitReader(body.clone(), self.ContentLength);
                let (n, e) = self.doBodyCopy(w, &mut lr);
                ncopy = n;
                err = e;
                if err.IsNil() {
                    // Go: nextra, err = t.doBodyCopy(io.Discard, body)
                    let mut disc = crate::io::DiscardWriter();
                    let (nextra, e2) = self.doBodyCopy(&mut disc, &mut body);
                    ncopy += nextra;
                    err = e2;
                }
            }
            if !err.IsNil() {
                // Go's deferred close of BodyCloser runs on this path.
                if let Some(bc) = &self.BodyCloser {
                    let _ = bc.__close_shared();
                }
                return err;
            }
        }
        if let Some(bc) = self.BodyCloser.take() {
            let cerr = bc.__close_shared();
            if !cerr.IsNil() {
                return cerr;
            }
        }

        if !self.ResponseToHEAD && self.ContentLength != -1 && self.ContentLength != ncopy {
            return errors::New(crate::fmt::Sprintf!(
                "http: ContentLength=%d with Body length %d",
                self.ContentLength,
                ncopy
            ));
        }

        if !self.ResponseToHEAD && chunked(&self.TransferEncoding) {
            // Go: "Write Trailer header" — Header::Write on an empty
            // Trailer emits nothing, which is Go's nil-Trailer branch.
            {
                let mut tb = crate::bytes::Buffer::new();
                let terr = self.Trailer.Write(&mut tb);
                if !terr.IsNil() {
                    return terr;
                }
                let (_, we) = w.Write(tb.Bytes());
                if !we.IsNil() {
                    return we;
                }
            }
            // Go: "Last chunk, empty trailer"
            let (_, e) = w.Write(crate::convert::bytes("\r\n"));
            return e;
        }
        return errors::nil;
    }

    // go: sdk 1.25.5 net/http/transfer.go:413-422 transferWriter.doBodyCopy
    /// Go: "wraps a copy operation, with any resulting error also
    /// being saved in bodyReadError. This function is only intended
    /// for use in writeBody."
    fn doBodyCopy(
        &mut self,
        dst: &mut dyn crate::io::Writer,
        src: &mut dyn crate::io::Reader,
    ) -> (i64, error) {
        let buf = super::server::getCopyBuf();
        let (n, err) = crate::io::CopyBuffer(dst, src, buf.clone());
        super::server::putCopyBuf(buf);
        if !err.IsNil() && !errors::Is(err.clone(), crate::io::EOF) {
            self.bodyReadError = err.clone();
        }
        return (n, err);
    }

    // go: sdk 1.25.5 net/http/transfer.go:429-438 transferWriter.unwrapBody
    /// Go strips a nopCloser/readTrackingBody wrapper so *os.File
    /// bodies keep their OS-level copy optimizations. goish's `Body`
    /// is a closed enum with no such wrappers to strip, so the unwrap
    /// is the identity — kept as the writeBody seam Go routes through.
    fn unwrapBody(&self) -> super::Body {
        return self.Body.clone().unwrap();
    }
}

// go: waived unwrapNopCloser — reflect.TypeOf against the two
// io.NopCloser shapes; goish's Body is a closed enum that carries no
// nopCloser wrapping to detect, so unwrapBody above is already the
// identity and there is nothing for this helper to strip.

// go: sdk 1.25.5 net/http/transfer.go:1113-1127 isKnownInMemoryReader
/// Go: "reports whether r is a type known to not block on Read
/// (*bytes.Reader, *bytes.Buffer, *strings.Reader). Its caller uses
/// this as an optional optimization to send fewer TCP packets." A
/// goish `Body` is known-in-memory exactly when it is Eager.
pub(crate) fn isKnownInMemoryReader(r: &Option<super::Body>) -> bool {
    let out = match r {
        Some(b) => b.__bytes_eager().is_some(),
        None => false,
    };
    return out;
}

// go: waived bufioFlushWriter — flushes after every Write IF the
// wrapped writer is a *bufio.Writer; goish's bufio::Writer<W> is
// generic, so a type-erased `dyn Writer` cannot be downcast to it,
// and the one call site (CONNECT bodies in writeBody) hands over the
// unbuffered conn where the flush is a no-op.

// goishlint:ignore GOISH019 — one finding, on `finishAsyncByteRead`
// below: Go's field is `tw *transferWriter`, used only as tw.ByteReadCh;
// goish stores that channel directly (`ch`) because the struct lives
// INSIDE the rewrapped Body the transferWriter owns — holding the
// whole writer back would be self-referential. This rule has no
// line-scoped form; the other structs in this file pass the field
// check today and stay covered by review.
// go: sdk 1.25.5 net/http/transfer.go:1074-1076 finishAsyncByteRead
/// Go: holds `tw *transferWriter` and reads tw.ByteReadCh; goish
/// borrows just the channel (the struct would otherwise be
/// self-referential inside the rewrapped Body).
pub(crate) struct finishAsyncByteRead {
    ch: crate::gochan::chan<readResult>,
}

impl crate::io::Reader for finishAsyncByteRead {
    // go: sdk 1.25.5 net/http/transfer.go:1078-1092 finishAsyncByteRead.Read
    /// Block until the probe goroutine's 1-byte read lands, then
    /// surface it exactly: the byte (if any) plus the error, with a
    /// nil error mapped to io.EOF (this reader has nothing more).
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        if p.Len() == 0 {
            return (0, errors::nil);
        }
        let (rres, _) = self.ch.Recv();
        let n = rres.n;
        let mut err = rres.err.clone();
        if n == 1 {
            p[0] = rres.b;
        }
        if err.IsNil() {
            err = crate::io::EOF.into();
        }
        return (n, err);
    }
}

// go: none — goish-only: Response.Write's zero-or-unknown probe
// re-chains its one probed byte exactly like Go's
// `struct { io.Reader; io.Closer }{ io.MultiReader(bytes.NewReader(
// buf[:1]), r.Body), r.Body }` (response.go:279-286). Same carrier as
// the request-probe path below.
pub(crate) fn __rechain_probed_byte(b: byte, rest: super::Body) -> super::Body {
    return super::Body::from_reader(alloc::boxed::Box::new(probedBody {
        pending: Some(byteReader { b, done: false }),
        wait: None,
        inner: Some(rest),
        err_after: None,
    }));
}

// go: none — goish-only carrier `probedBody`: Go re-chains the probed
// byte with io.MultiReader(&byteReader{b}, t.Body), or after a probe
// timeout with MultiReader(finishAsyncByteRead{t}, t.Body). goish's
// Body needs a single Send+Sync ReadCloser and the io::MultiReader
// port's boxes carry no Send bound, so the chain — byteReader stage,
// finishAsyncByteRead stage, inner body, errorReader stage — is
// composed here, each stage delegating to its ported reader above.
struct probedBody {
    /// byteReader: the probed byte, delivered before everything else.
    pending: Option<byteReader>,
    /// finishAsyncByteRead: the probe goroutine's pending result —
    /// blocks the first Read until the 1-byte probe lands.
    wait: Option<finishAsyncByteRead>,
    inner: Option<super::Body>,
    /// errorReader: surfaced once the earlier stages are exhausted.
    err_after: Option<errorReader>,
}

impl crate::io::Reader for probedBody {
    // go: none — goish-only: MultiReader-style advance through the
    // chain; each stage is one of the ported readers above.
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        if p.Len() == 0 {
            return (0, errors::nil);
        }
        if let Some(br) = &mut self.pending {
            let (n, e) = br.Read(p);
            if n > 0 {
                // byteReader answers (1, EOF); MultiReader semantics
                // convert that EOF into "advance to the next stage".
                self.pending = None;
                let _ = e;
                return (n, errors::nil);
            }
            self.pending = None;
        }
        if let Some(fr) = &mut self.wait {
            let (n, e) = fr.Read(p);
            self.wait = None;
            if !e.IsNil() && !errors::Is(e.clone(), crate::io::EOF) {
                self.inner = None;
                return (n, e);
            }
            if n > 0 {
                return (n, errors::nil);
            }
            // 0 bytes, clean EOF from the probe: fall through to the
            // inner body (which will answer EOF as well).
        }
        if let Some(b) = &mut self.inner {
            let (n, e) = crate::io::Reader::Read(b, p);
            return (n, e);
        }
        if let Some(er) = &mut self.err_after {
            return er.Read(p);
        }
        return (0, crate::io::EOF.into());
    }
}

impl crate::io::Closer for probedBody {
    // go: none — goish-only: Go's rewrapped body keeps rr.Body as the
    // BodyCloser; the inner handle here is that same shared stream.
    fn Close(&mut self) -> error {
        let out = match &self.inner {
            Some(b) => b.__close_shared(),
            None => errors::nil,
        };
        return out;
    }
}

impl transferWriter {
    // go: sdk 1.25.5 net/http/transfer.go:254-276 transferWriter.shouldSendContentLength
    /// Whether to emit a Content-Length header. Pure: it reads only
    /// Method, ContentLength and TransferEncoding.
    ///
    /// The last clause is the surprising one. With ContentLength == 0
    /// and NO Transfer-Encoding, POST/PUT/PATCH send `Content-Length:
    /// 0` (many servers expect it) but GET/HEAD/DELETE do not. Add an
    /// explicit `identity` encoding and DELETE flips to true, because
    /// only GET and HEAD are excluded in that branch. Verified against
    /// Go over 7 methods x 3 lengths x 3 encodings.
    pub fn shouldSendContentLength(&self) -> bool {
        if chunked(&self.TransferEncoding) {
            return false;
        }
        if self.ContentLength > 0 {
            return true;
        }
        if self.ContentLength < 0 {
            return false;
        }
        // Go: "Many servers expect a Content-Length for these methods"
        if self.Method == "POST" || self.Method == "PUT" || self.Method == "PATCH" {
            return true;
        }
        if self.ContentLength == 0 && isIdentity(&self.TransferEncoding) {
            if self.Method == "GET" || self.Method == "HEAD" {
                return false;
            }
            return true;
        }
        return false;
    }
}

// ─── body ───────────────────────────────────────────────────────────

// goishlint:ignore GOISH019 body — Go's struct carries src/hdr/r/
// closing/onHitEOF, the streaming half that needs io.ReadCloser. What
// lands are the flags its state accessors read.
// go: sdk 1.25.5 net/http/transfer.go:811-827 body
/// Go: "body turns a Reader into a ReadCloser. Close ensures that the
/// body has been fully read and then reads the trailer if necessary."
///
/// STAGED, same reason as transferWriter.
pub struct body {
    state: crate::sync::Mutex<bodyState>,
}

// go: none — goish-only: the payload of Go's `mu sync.Mutex` on body,
// restricted to the fields this slice ports.
struct bodyState {
    sawEOF: bool,
    /// Go: "true if Close called and we didn't read to the end of src"
    earlyClose: bool,
    onHitEOF: Option<alloc::boxed::Box<dyn Fn() + Send + Sync>>,
}

impl body {
    // go: none — goish-only: Go builds `body` inside readTransfer.
    pub fn __new() -> body {
        return body {
            state: crate::sync::Mutex::new(bodyState {
                sawEOF: false,
                earlyClose: false,
                onHitEOF: None,
            }),
        };
    }

    // go: sdk 1.25.5 net/http/transfer.go:1012-1016 body.didEarlyClose
    /// Whether Close was called before the source was drained. This is
    /// what `response.closedRequestBodyEarly` consults to refuse
    /// connection reuse — an undrained body would desync the next
    /// keep-alive request.
    pub fn didEarlyClose(&self) -> bool {
        return self.state.Lock().earlyClose;
    }

    // go: sdk 1.25.5 net/http/transfer.go:1018-1024 body.bodyRemains
    /// Go: "reports whether future Read calls might yield data."
    pub fn bodyRemains(&self) -> bool {
        return !self.state.Lock().sawEOF;
    }

    // go: sdk 1.25.5 net/http/transfer.go:1026-1030 body.registerOnHitEOF
    pub fn registerOnHitEOF(&self, fn_: alloc::boxed::Box<dyn Fn() + Send + Sync>) {
        self.state.Lock().onHitEOF = Some(fn_);
        return;
    }

    // go: none — goish-only: drives the flags the accessors read until
    // the streaming Read lands.
    pub fn __mark_eof(&self) {
        let cb = {
            let mut st = self.state.Lock();
            st.sawEOF = true;
            st.onHitEOF.take()
        };
        if let Some(f) = cb {
            f();
        }
        return;
    }

    // go: none — goish-only: same, for the early-close flag.
    pub fn __mark_early_close(&self) {
        self.state.Lock().earlyClose = true;
        return;
    }
}

// ─── status-driven rules ────────────────────────────────────────────

// go: sdk 1.25.5 net/http/transfer.go:250-252 noResponseBodyExpected
pub fn noResponseBodyExpected(requestMethod: string) -> bool {
    return requestMethod == "HEAD";
}

// go: sdk 1.25.5 net/http/transfer.go:459-471 bodyAllowedForStatus
/// Go: "bodyAllowedForStatus reports whether a given response status
/// code permits a body. See RFC 7230, section 3.3."
///
/// Note 99 and 205 DO permit a body — only 100..=199, 204 and 304 do
/// not. Verified against Go for 99/100/150/199/200/204/205/304/305/404.
pub fn bodyAllowedForStatus(status: int) -> bool {
    if status >= 100 && status <= 199 {
        return false;
    }
    if status == 204 {
        return false;
    }
    if status == 304 {
        return false;
    }
    return true;
}

// go: sdk 1.25.5 net/http/transfer.go:473-477 suppressedHeaders304
/// Go: RFC 7232 section 4.1 — a 304 must not carry these.
pub fn suppressedHeaders304() -> slice<string> {
    return slice::<string>::__from_vec(alloc::vec![
        string("Content-Type"),
        string("Content-Length"),
        string("Transfer-Encoding"),
    ]);
}

// go: sdk 1.25.5 net/http/transfer.go:473-477 suppressedHeadersNoBody
pub fn suppressedHeadersNoBody() -> slice<string> {
    return slice::<string>::__from_vec(alloc::vec![
        string("Content-Length"),
        string("Transfer-Encoding"),
    ]);
}

// go: sdk 1.25.5 net/http/transfer.go:473-477 excludedHeadersNoBody
pub fn excludedHeadersNoBody() -> crate::gomap::map<string, bool> {
    let mut m = crate::gomap::map::<string, bool>::new();
    m.Set(string("Content-Length"), true);
    m.Set(string("Transfer-Encoding"), true);
    return m;
}

// go: sdk 1.25.5 net/http/transfer.go:479-489 suppressedHeaders
/// Which headers must be dropped for `status`. Empty (Go's nil) when
/// the status permits a body.
pub fn suppressedHeaders(status: int) -> slice<string> {
    if status == 304 {
        // Go: RFC 7232 section 4.1
        return suppressedHeaders304();
    }
    if !bodyAllowedForStatus(status) {
        return suppressedHeadersNoBody();
    }
    return slice::<string>::new();
}

// ─── transfer-encoding predicates ───────────────────────────────────

// go: sdk 1.25.5 net/http/transfer.go:609 chunked
/// Go: "Checks whether chunked is part of the encodings stack."
///
/// Deliberately case-SENSITIVE and first-element-only, matching Go:
/// `["CHUNKED"]` is false, and so is `["gzip","chunked"]`.
pub fn chunked(te: &slice<string>) -> bool {
    return te.Len() > 0 && te[int(0)] == "chunked";
}

// go: sdk 1.25.5 net/http/transfer.go:612 isIdentity
/// Go: "Checks whether the encoding is explicitly \"identity\"."
pub fn isIdentity(te: &slice<string>) -> bool {
    return te.Len() == 1 && te[int(0)] == "identity";
}

// go: sdk 1.25.5 net/http/transfer.go:615-617 unsupportedTEError
//
// Go carries a distinct `*unsupportedTEError` struct so callers can
// type-assert it. goish's errors have no `errors::As`, so the port
// wraps a sentinel: `unsupportedTEError(msg)` builds an error whose
// Unwrap chain reaches `errUnsupportedTE`, and `isUnsupportedTEError`
// tests that with `errors::Is` — the shape recorded for typed errors
// generally.
crate::var! {
    pub(crate) errUnsupportedTE: error = "http: unsupported transfer encoding";
}

pub struct unsupportedTEError {
    pub err: string,
}

impl errors::ErrorTrait for unsupportedTEError {
    // go: sdk 1.25.5 net/http/transfer.go:619-621 unsupportedTEError.Error
    fn Error(&self) -> string {
        return self.err.clone();
    }
    // go: none — goish-only. Go type-asserts `*unsupportedTEError`;
    // goish has no errors::As, so the chain to a sentinel is what
    // `isUnsupportedTEError` matches on.
    fn Unwrap(&self) -> error {
        return errUnsupportedTE.into();
    }
}

// go: none — goish-only constructor: Go writes the composite literal
// `&unsupportedTEError{...}` inline, goish needs the errors::Wrap
// boxing step so it is named once here.
fn newUnsupportedTEError(msg: string) -> error {
    return errors::Wrap(unsupportedTEError { err: msg });
}

// go: sdk 1.25.5 net/http/transfer.go:625-628 isUnsupportedTEError
/// Go: "isUnsupportedTEError checks if the error is of type
/// unsupportedTEError. It is usually invoked with a non-nil err."
pub fn isUnsupportedTEError(err: error) -> bool {
    return errors::Is(err, errUnsupportedTE);
}

// ─── framing ────────────────────────────────────────────────────────

// go: sdk 1.25.5 net/http/transfer.go:661-743 fixLength
/// Go: "Determine the expected body length, using RFC 7230 Section
/// 3.3." Returns -1 for "read until EOF/end of chunks".
///
/// This is the request-smuggling hardening point. Two behaviours are
/// load-bearing and were checked against Go rather than inferred:
///   - duplicate Content-Length headers are an ERROR if they differ
///     after trimming, and are DEDUPLICATED if they agree
///     (`["5"," 5 "]` collapses to `["5"]`, n=5);
///   - when Transfer-Encoding is chunked, Content-Length is DELETED
///     from the header and -1 returned, so the two can never both be
///     honoured downstream (RFC 9112).
pub fn fixLength(
    isResponse: bool,
    status: int,
    requestMethod: string,
    header: &mut Header,
    chunked_: bool,
) -> (i64, error) {
    let isRequest = !isResponse;
    let mut contentLens = header.Values(string("Content-Length"));

    // Go: "Hardening against HTTP request smuggling"
    if contentLens.Len() > 1 {
        // Go: "Per RFC 7230 Section 3.3.2, prevent multiple
        // Content-Length headers if they differ in value. If there are
        // dups of the value, remove the dups. See Issue 16490."
        let first = crate::net::textproto::TrimString(contentLens[int(0)].clone());
        for i in 1..contentLens.Len() {
            let ct = crate::net::textproto::TrimString(contentLens[int(i)].clone());
            if first != ct {
                return (
                    0,
                    crate::fmt::Errorf!(
                        "http: message cannot contain multiple Content-Length headers; got %s",
                        __quote_list(&contentLens)
                    ),
                );
            }
        }

        // Go: deduplicate Content-Length
        header.Del(string("Content-Length"));
        header.Add(string("Content-Length"), first);

        contentLens = header.Values(string("Content-Length"));
    }

    // Go: "Reject requests with invalid Content-Length headers."
    let mut n: i64 = 0;
    if contentLens.Len() > 0 {
        let (parsed, err) = parseContentLength(&contentLens);
        if !err.IsNil() {
            return (-1, err);
        }
        n = parsed;
    }

    // Go: "Logic based on response type or status"
    if isResponse && noResponseBodyExpected(requestMethod) {
        return (0, errors::nil);
    }
    if status / 100 == 1 {
        return (0, errors::nil);
    }
    if status == 204 || status == 304 {
        return (0, errors::nil);
    }

    // Go: RFC 9112 — "If a message is received with both a
    // Transfer-Encoding and a Content-Length header field, the
    // Transfer-Encoding overrides the Content-Length."
    if chunked_ {
        header.Del(string("Content-Length"));
        return (-1, errors::nil);
    }

    // Go: "Logic based on Content-Length"
    if contentLens.Len() > 0 {
        return (n, errors::nil);
    }

    header.Del(string("Content-Length"));

    if isRequest {
        // Go: "RFC 7230 neither explicitly permits nor forbids an
        // entity-body on a GET request so we permit one if declared,
        // but we default to 0 here (not -1 below) if there's no
        // mention of a body."
        return (0, errors::nil);
    }

    // Go: "Body-EOF logic based on other methods (like closing, or
    // chunked coding)"
    return (-1, errors::nil);
}

// go: sdk 1.25.5 net/http/transfer.go:745-765 shouldClose
/// Go: "Determine whether to hang up after sending a request and body,
/// or receiving a response and body."
///
/// Go calls `httpguts.HeaderValuesContainsToken`, which scans the FULL
/// value list case-insensitively. goish has no httpguts; `hasToken`
/// is the substitute and requires a LOWERCASE token, so the loop below
/// passes `"close"` / `"keep-alive"` and never the header spelling.
pub fn shouldClose(
    major: int,
    minor: int,
    header: &mut Header,
    removeCloseHeader: bool,
) -> bool {
    if major < 1 {
        return true;
    }

    let conv = header.Values(string("Connection"));
    let hasClose = __values_contain_token(&conv, "close");
    if major == 1 && minor == 0 {
        return hasClose || !__values_contain_token(&conv, "keep-alive");
    }

    if hasClose && removeCloseHeader {
        header.Del(string("Connection"));
    }

    return hasClose;
}

// go: sdk 1.25.5 net/http/transfer.go:767-805 fixTrailer
/// Go: "Parse the trailer header." Returns an empty Header (Go's nil)
/// when there is no usable trailer — including the `Trailer` present
/// but not chunked case, which Go deliberately does NOT treat as an
/// error (issue #27197).
pub fn fixTrailer(header: &mut Header, chunked_: bool) -> (Header, error) {
    if !header.has(string("Trailer")) {
        return (Header::new(), errors::nil);
    }
    let vv = header.Values(string("Trailer"));
    if !chunked_ {
        // Go: "Trailer and no chunking: this is an invalid use case
        // for trailer header. Nevertheless, no error will be returned
        // and we let users decide if this is a valid HTTP message."
        return (Header::new(), errors::nil);
    }
    header.Del(string("Trailer"));

    let mut trailer = Header::new();
    let mut err: error = errors::nil;
    for i in 0..vv.Len() {
        let v = vv[int(i)].clone();
        super::server::foreachHeaderElement(v, |key: string| {
            let key = CanonicalHeaderKey(key);
            if key == "Transfer-Encoding" || key == "Trailer" || key == "Content-Length" {
                // Go's guard reads `if err == nil { err = …; return }`,
                // so only the FIRST bad key is reported.
                if err.IsNil() {
                    err = super::request::badStringError("bad trailer key", key);
                    return;
                }
            }
            trailer.__set_values(key, slice::<string>::new());
        });
    }
    if !err.IsNil() {
        return (Header::new(), err);
    }
    if trailer.Len() == 0 {
        return (Header::new(), errors::nil);
    }
    return (trailer, errors::nil);
}

// go: sdk 1.25.5 net/http/transfer.go:953-960 mergeSetHeader
/// Go takes `dst *Header` and replaces it wholesale when nil. goish's
/// `Header` has no nil state, so an empty `dst` takes `src` entire —
/// the same observable result.
pub fn mergeSetHeader(dst: &mut Header, src: Header) {
    if dst.Len() == 0 {
        *dst = src;
        return;
    }
    for (k, v) in crate::range!(&src) {
        dst.__set_values(k.clone(), v.clone());
    }
    return;
}

// go: sdk 1.25.5 net/http/transfer.go:894-907 seeUpcomingDoubleCRLF
/// Go: peek forward until the buffer is full, looking for the blank
/// line that ends a trailer block.
pub fn seeUpcomingDoubleCRLF<R: crate::io::Reader>(
    r: &mut crate::bufio::Reader<R>,
) -> bool {
    let mut peekSize: int = 4;
    loop {
        // Go: "This loop stops when Peek returns an error, which it
        // does when r's buffer has been filled."
        let (buf, err) = r.Peek(peekSize);
        if crate::bytes::HasSuffix(buf.clone(), crate::convert::bytes("\r\n\r\n")) {
            return true;
        }
        if !err.IsNil() {
            break;
        }
        peekSize += 1;
    }
    return false;
}

// go: sdk 1.25.5 net/http/transfer.go:1046-1069 parseContentLength
/// Go: "parseContentLength checks that the header is valid and then
/// trims whitespace. It returns -1 if no value is set otherwise the
/// value if it's >= 0."
///
/// Only the FIRST value is consulted — `["1","2"]` yields 1, not an
/// error; `fixLength` is what rejects disagreeing duplicates. The
/// bound is `ParseUint(cl, 10, 63)`, so 2^63-1 parses and a negative
/// or non-numeric value does not. The `httplaxcontentlength` GODEBUG
/// escape hatch is not ported (goish has no godebug); goish always
/// takes Go's default branch and rejects an empty value.
pub fn parseContentLength(clHeaders: &slice<string>) -> (i64, error) {
    if clHeaders.Len() == 0 {
        return (-1, errors::nil);
    }
    let cl = crate::net::textproto::TrimString(clHeaders[int(0)].clone());

    // Go: "The Content-Length must be a valid numeric value."
    if cl == "" {
        return (
            0,
            super::request::badStringError("invalid empty Content-Length", cl),
        );
    }
    let (n, err) = crate::strconv::ParseUint(cl.clone(), 10, 63);
    if !err.IsNil() {
        return (0, super::request::badStringError("bad Content-Length", cl));
    }
    return (int64(n), errors::nil);
}

// ─── goish-only helpers ─────────────────────────────────────────────

// go: none — goish-only. Go gets `%q` on a []string for free from fmt;
// goish's Sprintf has no slice verb, so render Go's exact
// `["a" "b"]` spelling by hand for the two error messages that use it.
fn __quote_list(v: &slice<string>) -> string {
    let mut out: Vec<u8> = Vec::new();
    out.push(b'[');
    for i in 0..v.Len() {
        if i > 0 {
            out.push(b' ');
        }
        out.push(b'"');
        out.extend_from_slice(v[int(i)].as_bytes());
        out.push(b'"');
    }
    out.push(b']');
    return string::from_bytes(&out);
}

// go: none — goish-only. Stands in for
// `httpguts.HeaderValuesContainsToken(values, token)`: scan every
// entry of the header's value list, not just the joined first one.
// `token` MUST be lowercase — that is `hasToken`'s precondition.
fn __values_contain_token(values: &slice<string>, token: &'static str) -> bool {
    for i in 0..values.Len() {
        if hasToken(values[int(i)].clone(), string(token)) {
            return true;
        }
    }
    return false;
}
