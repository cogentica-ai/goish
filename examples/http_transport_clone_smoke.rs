// http_transport_clone_smoke — Transport.Clone must produce an
// INDEPENDENT Transport. Go's contract is "a deep copy of t's
// exported fields"; the part that bites is the maps: a clone that
// shares the idle pool or the registered-protocol map lets a mutation
// on one Transport reach the other.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::net::http::filetransport::NewFileTransport;
use goish::net::http::transport::{connectMethod, persistConn};
use goish::net::http::{ParseURL, Transport};
use goish::{string, time};

static PASSED: AtomicUsize = AtomicUsize::new(0);
static FAILED: AtomicUsize = AtomicUsize::new(0);

fn check(name: &'static str, ok: bool, detail: goish::string) {
    if ok {
        PASSED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("PASS: %s\n", name);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("FAIL: %s — %s\n", name, detail);
    }
}

fn conn(host: &'static str) -> Arc<persistConn> {
    let (u, _) = ParseURL(fmt::Sprintf!("http://%s/", string(host)));
    let cm = connectMethod {
        proxyURL: None,
        targetScheme: string("http"),
        targetAddr: goish::net::http::transport::canonicalAddr(&u),
        onlyH1: false,
    };
    Arc::new(persistConn::__new(cm.key()))
}

#[goish::main]
fn main() {
    goish::go!(stack(512 * 1024), move || {
        run();
    });
    loop {
        goish::runtime::sched::Gosched();
    }
}

fn run() {
    // Scalar fields carry across.
    {
        let mut t = Transport::default();
        t.MaxIdleConns = 7;
        t.MaxIdleConnsPerHost = 3;
        t.DisableKeepAlives = true;
        t.MaxResponseHeaderBytes = 4096;
        t.IdleConnTimeout = time::Duration(5 * 1_000_000_000);
        let c = t.Clone();
        check(
            "scalar fields are copied",
            c.MaxIdleConns == 7
                && c.MaxIdleConnsPerHost == 3
                && c.DisableKeepAlives
                && c.MaxResponseHeaderBytes == 4096
                && c.IdleConnTimeout == time::Duration(5 * 1_000_000_000),
            string(""),
        );
    }

    // The idle pool is NOT shared.
    {
        let t = Transport::default();
        let _ = t.tryPutIdleConn(&conn("a.com"));
        let c = t.Clone();
        // The clone starts empty, so it can accept two of its own.
        let e1 = c.tryPutIdleConn(&conn("a.com"));
        let e2 = c.tryPutIdleConn(&conn("a.com"));
        // If the pool were shared, the original's entry would count
        // toward the per-host cap of 2 and e2 would be refused.
        check(
            "the clone gets a FRESH idle pool",
            e1.IsNil() && e2.IsNil(),
            fmt::Sprintf!("%v / %v", e1, e2),
        );
    }

    // Closing idle conns on the clone must not disturb the original.
    {
        let t = Transport::default();
        let pc = conn("a.com");
        let _ = t.tryPutIdleConn(&pc);
        let c = t.Clone();
        c.CloseIdleConnections();
        check(
            "CloseIdleConnections on the clone leaves the original's conn alone",
            !pc.isBroken(),
            string(""),
        );
    }

    // The registered-protocol map is copied, not shared.
    {
        let t = Transport::default();
        let dir = Arc::new(goish::net::http::fs::NewDir(string("/tmp")))
            as Arc<dyn goish::net::http::fs::FileSystem + Send + Sync>;
        t.RegisterProtocol(string("file"), NewFileTransport(dir.clone()));
        let c = t.Clone();
        let (req, _) =
            goish::net::http::NewRequest(string("GET"), string("file:///x"), goish::slice::new());
        check(
            "registered protocols carry across to the clone",
            c.alternateRoundTripper(&req).is_some(),
            string(""),
        );
        // And registering on the clone must not reach the original —
        // if the map were shared this would panic on double-register.
        c.RegisterProtocol(string("ftp"), NewFileTransport(dir));
        let (req2, _) =
            goish::net::http::NewRequest(string("GET"), string("ftp://h/x"), goish::slice::new());
        check(
            "but the clone's own registrations do not reach the original",
            c.alternateRoundTripper(&req2).is_some() && t.alternateRoundTripper(&req2).is_none(),
            string(""),
        );
    }

    let p = PASSED.load(Ordering::Relaxed);
    let f = FAILED.load(Ordering::Relaxed);
    fmt::Printf!("\n%d passed, %d failed\n", p as i64, f as i64);
    if f == 0 {
        fmt::Printf!("HTTP_TRANSPORT_CLONE_SMOKE_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("HTTP_TRANSPORT_CLONE_SMOKE_FAIL\n");
    goish::os::Exit(1);
}
