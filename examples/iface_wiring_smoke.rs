// iface_wiring_smoke — every in-tree type that should satisfy an
// OPTIONAL interface actually does, when asked the way a caller asks.
//
// This is not a Go-reference smoke. It guards a goish-specific
// mechanism that Go has no equivalent of, and it exists because that
// mechanism has already produced a real defect.
//
// Go's `w.(http.Flusher)` is STRUCTURAL: a type with a Flush method
// has the interface, and there is nothing to forget. goish resolves
// the same assertion through a runtime registry plus a per-type
// `__goish_as_dyn_any` hook, so a concrete type needs THREE things —
// the trait impl, the registration, and the hook — and any one of them
// missing makes the assertion silently miss.
//
// net/http/cgi's response had the Flush METHOD and none of the three.
// Every CGI handler therefore saw a writer that could not flush, which
// turns a streaming script into a buffering one with no error, no log
// and identical bytes arriving all at once at the end. Nothing in the
// tree noticed, because nothing in the tree asserted Flusher on a CGI
// writer — the defect was found by comparing cgi's wiring against
// fcgi's, not by any test.
//
// So this asserts the wiring directly, for every optional interface a
// caller may reach for on an in-tree type. A new ResponseWriter or FS
// that forgets a step fails here rather than in someone's production
// stream.
//
// The expectations come from Go: a type is listed as satisfying an
// interface only where Go's corresponding type does. httptest's
// recorder and cgi's, fcgi's and the server's responses all have
// Flush in Go; os.DirFS and fstest.MapFS both implement ReadDirFS,
// StatFS and ReadFileFS; fs.Sub's result implements ReadDirFS and
// ReadFileFS. Where Go's type does NOT implement something — the
// recorder is not a Hijacker — the negative is asserted too, because a
// port that over-implements diverges just as surely.

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
use goish::io::fs;
use goish::net::http;
use goish::net::http::cgi;
use goish::net::http::httptest;
use goish::net::http::{Flusher, Hijacker, ResponseWriter};
use goish::testing::fstest;
use goish::types::{byte, int};
use goish::{syscall, time};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

static FAILED: goish::sync::Mutex<int> = goish::sync::Mutex::new(0);
static CHECKS: goish::sync::Mutex<int> = goish::sync::Mutex::new(0);

fn want(what: &str, got: bool, expect: bool) {
    *CHECKS.Lock() += 1;
    if got == expect {
        return;
    }
    fmt::Printf!("[!!] %s: cast %v, expected %v\n", s(what), got, expect);
    *FAILED.Lock() += 1;
}

#[derive(Clone)]
struct Sink(Arc<goish::sync::Mutex<Vec<u8>>>);
impl goish::io::Writer for Sink {
    fn Write(&mut self, p: slice<byte>) -> (int, goish::errors::error) {
        let mut g = self.0.Lock();
        for b in p.to_vec() {
            g.push(b);
        }
        return (p.Len(), goish::nil.into());
    }
}

fn mapfs() -> Arc<fstest::MapFS> {
    let mut m = fstest::MapFS::new();
    m.0.Set(
        s("a.txt"),
        Arc::new(fstest::MapFile {
            Data: slice::<byte>::__from_vec(b"alpha".to_vec()),
            Mode: fs::FileMode(0o644),
            ModTime: time::Time::default(),
            Sys: None,
        }),
    );
    m.0.Set(
        s("dir/b.txt"),
        Arc::new(fstest::MapFile {
            Data: slice::<byte>::__from_vec(b"bravo".to_vec()),
            Mode: fs::FileMode(0o644),
            ModTime: time::Time::default(),
            Sys: None,
        }),
    );
    return Arc::new(m);
}

#[goish::main]
fn main() {
    // ── ResponseWriters ──────────────────────────────────────────────
    //
    // Go: httptest.ResponseRecorder has Flush and no Hijack.
    {
        let rec = httptest::NewRecorder();
        let w: &(dyn ResponseWriter + Send + Sync + 'static) = &rec;
        want("recorder is Flusher", goish::cast!(w, Flusher).1, true);
        want(
            "recorder is not Hijacker",
            goish::cast!(w, Hijacker).1,
            false,
        );
    }
    // Go: cgi's response has Flush. This is the one that was broken.
    {
        let buf = Sink(Arc::new(goish::sync::Mutex::new(Vec::new())));
        let (req, _) = http::NewRequest(s("GET"), s("http://x/p"), ());
        let rw = cgi::response::new(&req, Box::new(buf));
        let w: &(dyn ResponseWriter + Send + Sync + 'static) = &rw;
        want("cgi response is Flusher", goish::cast!(w, Flusher).1, true);
    }

    // ── Filesystems ──────────────────────────────────────────────────
    //
    // Go: fstest.MapFS implements ReadDirFS, StatFS, ReadFileFS and
    // GlobFS. A missed assertion here does not fail loudly — fs.ReadDir
    // falls back to Open+ReadDir, which returns the same answer for a
    // correct FS and hides a wrong one, exactly as it did when this
    // mechanism was first investigated.
    {
        let m = mapfs();
        let f: &(dyn fs::FS + Send + Sync + 'static) = &*m;
        want("MapFS is ReadDirFS", goish::cast!(f, fs::ReadDirFS).1, true);
        want("MapFS is StatFS", goish::cast!(f, fs::StatFS).1, true);
        want(
            "MapFS is ReadFileFS",
            goish::cast!(f, fs::ReadFileFS).1,
            true,
        );
    }
    // Go: the FS returned by fs.Sub implements ReadDirFS and ReadFileFS.
    {
        let m: Arc<dyn fs::FS + Send + Sync> = mapfs();
        let (sub, err) = fs::Sub(m, s("dir"));
        if err != goish::nil {
            fmt::Printf!("[!!] fs::Sub failed: %q\n", err.Error());
            *FAILED.Lock() += 1;
        } else {
            let f: &(dyn fs::FS + Send + Sync + 'static) = &*sub;
            want("subFS is ReadDirFS", goish::cast!(f, fs::ReadDirFS).1, true);
            want(
                "subFS is ReadFileFS",
                goish::cast!(f, fs::ReadFileFS).1,
                true,
            );
        }
    }

    let checks = *CHECKS.Lock();
    let failed = *FAILED.Lock();
    if failed == 0 {
        fmt::Printf!("ok %d/%d\n", checks, checks);
        return;
    }
    fmt::Printf!("FAILED %d of %d\n", failed, checks);
    syscall::Exit(1);
}
