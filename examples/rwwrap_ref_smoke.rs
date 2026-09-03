// rwwrap_ref_smoke — wrapping http.ResponseWriter, against a running Go.
// (net/http/server.go's optional ResponseWriter interfaces)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_rwwrap_ref.go` run in
// `package http_test` by `scripts/goref.sh`. goish matched Go on all 6
// lines.
//
// Middleware wraps http.ResponseWriter. That is the single most common
// thing anyone does with the type — logging, compression, status
// capture, timing — and it is where an interface silently disappears.
//
// ResponseWriter carries three methods. Everything else a handler may
// need is an OPTIONAL interface found by assertion: Flusher for
// streaming, Hijacker for protocol upgrades, CloseNotifier for
// disconnect detection. A wrapper that does not forward them makes them
// vanish, and nothing reports it — a streaming handler simply stops
// streaming and buffers until the response ends.
//
// The `stream` lines make that concrete rather than abstract: the same
// handler, writing the same three chunks, flushes three times through
// the bare writer and ZERO times through an opaque wrapper. The body is
// identical in both. Nothing in the response says the streaming was
// lost — which is exactly why it is worth a pinned test.
//
// GOISH NEEDS ONE STEP GO DOES NOT, and it is the reason this smoke
// exists. Go's `w.(http.Flusher)` is structural: a wrapper that
// declares Flush has it, full stop. goish resolves the assertion
// through a runtime registry plus a per-type `__goish_as_dyn_any`
// hook, so a wrapper must register its ResponseWriter impl AND
// override that hook — otherwise EVERY assertion misses, including the
// ones it does forward, and `forwards-flush` behaves like `opaque`.
// Both wrappers here do it, and the code says why. A middleware author
// who omits it gets a wrapper that silently loses interfaces it
// carefully implemented.
//
// Two cases are in the Go reference generator but not compared, because
// there is nothing on the goish side to compare them to:
//
//   * `embeds` — Go's `struct{ http.ResponseWriter }`. Rust has no
//     interface embedding. Its Go answer is the same as opaque's, and
//     the reason is the sharper half of the trap: embedding LOOKS like
//     it forwards everything and forwards only the three declared
//     methods.
//   * io.ReaderFrom and io.StringWriter, which goish's recorder does
//     not implement. Comparing them would measure the recorder rather
//     than the wrapping.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use alloc::sync::Arc;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::io;
use goish::net::http;
use goish::net::http::httptest;
use goish::net::http::{Flusher, HeaderHandle, Hijacker, ResponseWriter};
use goish::syscall;
use goish::types::{byte, int};
const GO: [&str; 6] = [
    "rw bare             -> flusher=true  hijacker=false code=201 body=\"body\" hdr=\"1\"",
    "rw opaque           -> flusher=false hijacker=false code=201 body=\"body\" hdr=\"1\"",
    "rw forwards-flush   -> flusher=true  hijacker=false code=201 body=\"body\" hdr=\"1\"",
    "stream bare             -> flushes=3 body=\"chunkchunkchunk\"",
    "stream opaque           -> flushes=0 body=\"chunkchunkchunk\"",
    "stream forwards-flush   -> flushes=3 body=\"chunkchunkchunk\"",
];

// Static counters: probeOne and streamOne are free functions, so
// threading them through would reshape the probe the reference was
// generated from.
static FAILED: goish::sync::Mutex<int> = goish::sync::Mutex::new(0);
static LN: goish::sync::Mutex<int> = goish::sync::Mutex::new(0);

fn chk(got: string) {
    let mut ln = LN.Lock();
    if *ln >= GO.len() as int {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln + 1, got);
        *FAILED.Lock() += 1;
        *ln += 1;
        return;
    }
    let want = s(GO[*ln as usize]);
    *ln += 1;
    if got == want {
        return;
    }
    fmt::Printf!("[!!] line %d FAIL\n  got  %q\n  want %q\n", *ln, got, want);
    *FAILED.Lock() += 1;
}

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}
// Implements ONLY ResponseWriter — every optional interface is lost,
// which is the default outcome of writing a wrapper.
struct OpaqueWriter(Arc<dyn ResponseWriter + Send + Sync>);
impl ResponseWriter for OpaqueWriter {
    fn Header(&self) -> HeaderHandle {
        return self.0.Header();
    }
    fn Write(&self, p: slice<byte>) -> (int, error0) {
        return self.0.Write(p);
    }
    fn WriteHeader(&self, c: int) {
        self.0.WriteHeader(c);
    }
    // goish resolves an interface assertion through a registry and this
    // hook; without it `cast!` cannot see past the trait object and
    // EVERY assertion misses, including ones the wrapper does forward.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}
// Forwards Flusher and nothing else.
struct FlushWriter(Arc<dyn ResponseWriter + Send + Sync>);
impl ResponseWriter for FlushWriter {
    fn Header(&self) -> HeaderHandle {
        return self.0.Header();
    }
    fn Write(&self, p: slice<byte>) -> (int, error0) {
        return self.0.Write(p);
    }
    fn WriteHeader(&self, c: int) {
        self.0.WriteHeader(c);
    }
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}
impl Flusher for FlushWriter {
    fn Flush(&self) {
        let (f, ok) = goish::cast!(&*self.0, Flusher);
        if ok {
            f.Flush();
        }
    }
}
use goish::errors::error as error0;
fn probeOne(
    label: &str,
    w: &(dyn ResponseWriter + Send + Sync + 'static),
    rec: &httptest::ResponseRecorder,
) {
    let (_, flusher) = goish::cast!(w, Flusher);
    let (_, hijacker) = goish::cast!(w, Hijacker);
    let seen = fmt::Sprintf!("flusher=%-5v hijacker=%-5v", flusher, hijacker);
    w.Header().Set(s("X-Probe"), s("1"));
    w.WriteHeader(201);
    let _ = w.Write(slice::__from_vec(b"body".to_vec()));
    chk(fmt::Sprintf!(
        "rw %-16s -> %s code=%d body=%q hdr=%q",
        s(label),
        seen,
        rec.Code(),
        string::from_bytes(&rec.Body().to_vec()),
        rec.HeaderMap().Get(s("X-Probe"))
    ));
}
fn streamOne(
    label: &str,
    w: &(dyn ResponseWriter + Send + Sync + 'static),
    rec: &httptest::ResponseRecorder,
) {
    let mut flushed: int = 0;
    for _ in 0..3 {
        let _ = w.Write(slice::__from_vec(b"chunk".to_vec()));
        let (f, ok) = goish::cast!(w, Flusher);
        if ok {
            f.Flush();
            flushed += 1;
        }
    }
    chk(fmt::Sprintf!(
        "stream %-16s -> flushes=%d body=%q",
        s(label),
        flushed,
        string::from_bytes(&rec.Body().to_vec())
    ));
}
#[goish::main]
fn main() {
    use goish::net::http::responsewriter as rww;
    rww::__goish_register_ResponseWriter_impl::<OpaqueWriter>();
    rww::__goish_register_ResponseWriter_impl::<FlushWriter>();
    rww::__goish_register_Flusher_impl::<FlushWriter>();
    {
        let rec = httptest::NewRecorder();
        probeOne("bare", &rec, &rec);
    }
    {
        let rec = Arc::new(httptest::NewRecorder());
        let w = OpaqueWriter(rec.clone());
        probeOne("opaque", &w, &rec);
    }
    {
        let rec = Arc::new(httptest::NewRecorder());
        let w = FlushWriter(rec.clone());
        probeOne("forwards-flush", &w, &rec);
    }
    {
        let rec = httptest::NewRecorder();
        streamOne("bare", &rec, &rec);
    }
    {
        let rec = Arc::new(httptest::NewRecorder());
        let w = OpaqueWriter(rec.clone());
        streamOne("opaque", &w, &rec);
    }
    {
        let rec = Arc::new(httptest::NewRecorder());
        let w = FlushWriter(rec.clone());
        streamOne("forwards-flush", &w, &rec);
    }
    let _ = io::EOF;
    let ln = *LN.Lock();
    let mut failed = *FAILED.Lock();
    if ln != GO.len() as int {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln, GO.len() as int);
        failed += 1;
    }
    if failed == 0 {
        fmt::Printf!("ok %d/%d\n", ln, ln);
        return;
    }
    fmt::Printf!("FAILED %d of %d\n", failed, ln);
    syscall::Exit(1);
}
