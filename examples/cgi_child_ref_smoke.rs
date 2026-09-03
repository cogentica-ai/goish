// cgi_child_ref_smoke — the CGI child's ResponseWriter, against a running Go.
// (net/http/cgi/child.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_cgichild_ref.go` run in
// `package cgi` by `scripts/goref.sh`.
//
// This is the writer a handler is handed INSIDE a CGI process. A CGI
// handler is an ordinary http.Handler, so it reaches for the same
// optional interfaces any handler does — and the one that matters for
// CGI in particular is Flusher. CGI is how a long-running script
// streams progress to a client; a handler that calls Flush and finds
// nothing there buffers its whole response instead, and the only
// symptom is that the output arrives all at once at the end. Nothing
// errors and nothing logs.
//
// ONE DEFECT, and it was invisible from inside the package. goish's
// cgi response HAD a Flush method — ported, anchored, correct — with no
// `Flusher` impl, no registration, and no `__goish_as_dyn_any` on its
// ResponseWriter impl. So `w.(http.Flusher)` missed and every CGI
// handler saw a writer that could not flush. The sibling fcgi response
// does all three and works, which is what made the omission visible:
// two implementations of the same thing, one of them wired up.
//
// The response is constructed directly rather than through Serve,
// which reads os.Stdin and writes os.Stdout. goish's os exposes those
// as functions rather than assignable variables, so there is no
// in-process redirection — and what is being measured is the WRITER's
// interface set and the bytes it produces, not the process plumbing.
//
// Also pinned, because CGI's response format is not HTTP's: the header
// block ends with "Status: 201 Created" rather than a status line, a
// handler that writes nothing still produces a full header block, and
// a Flush before any Write does not emit an empty body. The header
// field ORDER is map-iteration order in Go, so it is sorted before
// comparison — pinning it would pin something Go does not promise.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::io;
use goish::net::http;
use goish::net::http::cgi;
use goish::net::http::{Flusher, Hijacker, ResponseWriter};
use goish::sort;
use goish::strings;
use goish::syscall;
use goish::types::{byte, int};
const GO: [&str; 5] = [
    "cgi plain          -> flusher=true  hijacker=false out=\"Content-Type: text/plain; charset=utf-8|Status: 201 Created|X-From-Handler: 1||body\"",
    "cgi streaming      -> flusher=true  hijacker=false out=\"Content-Type: text/plain|Status: 200 OK||chunk-achunk-b\"",
    "cgi no-write       -> flusher=true  hijacker=false out=\"Content-Type: text/plain; charset=utf-8|Status: 200 OK|X-Empty: yes||\"",
    "cgi status-only    -> flusher=true  hijacker=false out=\"Content-Type: text/plain; charset=utf-8|Status: 404 Not Found||\"",
    "cgi flush-before-write -> flusher=true  hijacker=false out=\"Content-Type: text/plain; charset=utf-8|Status: 200 OK||after\"",
];

// Static counters: `probe` is a free function driving a whole
// response, so threading them through would reshape the probe the
// reference was generated from.
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
#[derive(Clone)]
struct Capture(Arc<goish::sync::Mutex<Vec<u8>>>);
impl io::Writer for Capture {
    fn Write(&mut self, p: slice<byte>) -> (int, goish::errors::error) {
        let mut g = self.0.Lock();
        for b in p.to_vec() {
            g.push(b);
        }
        return (p.Len(), goish::nil.into());
    }
}
// The header block's field order is map-iteration order, so it is
// sorted before comparison; the Status line and body are not.
fn normalize(x: string) -> string {
    let i = strings::Index(x.clone(), s("\r\n\r\n"));
    if i < 0 {
        return x;
    }
    let head = string::from_bytes(&x.as_bytes()[..i as usize]);
    let rest = string::from_bytes(&x.as_bytes()[(i as usize) + 4..]);
    let lines = strings::Split(head, s("\r\n"));
    let mut v: Vec<string> = Vec::new();
    for j in 0..lines.Len() {
        v.push(lines[j].clone());
    }
    let mut sl = slice::<string>::__from_vec(v);
    sort::Strings(&mut sl);
    let mut out = string::new();
    for j in 0..sl.Len() {
        if j > 0 {
            out = out + "|";
        }
        out = out + sl[j].clone();
    }
    return out + "||" + rest;
}
fn probe(label: &str, h: &dyn Fn(&(dyn ResponseWriter + Send + Sync + 'static))) {
    let buf = Capture(Arc::new(goish::sync::Mutex::new(Vec::new())));
    let (req, _) = http::NewRequest(s("GET"), s("http://example.test/p"), ());
    let rw = cgi::response::new(&req, Box::new(buf.clone()));
    let (_, flusher) = goish::cast!(
        &rw as &(dyn ResponseWriter + Send + Sync + 'static),
        Flusher
    );
    let (_, hijacker) = goish::cast!(
        &rw as &(dyn ResponseWriter + Send + Sync + 'static),
        Hijacker
    );
    h(&rw);
    let _ = ResponseWriter::Write(&rw, slice::<byte>::new());
    rw.Flush();
    let out = {
        let g = buf.0.Lock();
        string::from_bytes(&g[..])
    };
    chk(fmt::Sprintf!(
        "cgi %-14s -> flusher=%-5v hijacker=%-5v out=%q",
        s(label),
        flusher,
        hijacker,
        normalize(out)
    ));
}
#[goish::main]
fn main() {
    probe("plain", &|w: &(dyn ResponseWriter
                           + Send
                           + Sync
                           + 'static)| {
        w.Header().Set(s("X-From-Handler"), s("1"));
        w.WriteHeader(201);
        let _ = w.Write(slice::__from_vec(b"body".to_vec()));
    });
    probe("streaming", &|w: &(dyn ResponseWriter
                               + Send
                               + Sync
                               + 'static)| {
        w.Header().Set(s("Content-Type"), s("text/plain"));
        let _ = w.Write(slice::__from_vec(b"chunk-a".to_vec()));
        let (f, ok) = goish::cast!(w, Flusher);
        if ok {
            f.Flush();
        }
        let _ = w.Write(slice::__from_vec(b"chunk-b".to_vec()));
    });
    probe("no-write", &|w: &(dyn ResponseWriter
                              + Send
                              + Sync
                              + 'static)| {
        w.Header().Set(s("X-Empty"), s("yes"));
    });
    probe(
        "status-only",
        &|w: &(dyn ResponseWriter + Send + Sync + 'static)| {
            w.WriteHeader(404);
        },
    );
    probe(
        "flush-before-write",
        &|w: &(dyn ResponseWriter + Send + Sync + 'static)| {
            let (f, ok) = goish::cast!(w, Flusher);
            if ok {
                f.Flush();
            }
            let _ = w.Write(slice::__from_vec(b"after".to_vec()));
        },
    );
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
