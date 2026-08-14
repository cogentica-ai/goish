// http_idlepool_smoke — transport.go's idle-connection pool.
//
// Staged: nothing puts a live conn in this pool yet. What is tested is
// the admission policy, because every rejection is a NAMED error and
// `putOrCloseIdleConn` closes exactly when tryPutIdleConn returns
// non-nil. A rejection that returned nil-with-no-insert would leak the
// connection instead of closing it.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::net::http::transport::{connectMethod, persistConn, wantConn};
use goish::net::http::{ParseURL, Transport};
use goish::{errors, string};

static PASSED: AtomicUsize = AtomicUsize::new(0);
static FAILED: AtomicUsize = AtomicUsize::new(0);

fn check(name: &'static str, ok: bool, detail: goish::string) {
    if ok { PASSED.fetch_add(1, Ordering::Relaxed); fmt::Printf!("PASS: %s\n", name); }
    else { FAILED.fetch_add(1, Ordering::Relaxed); fmt::Printf!("FAIL: %s — %s\n", name, detail); }
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
    goish::go!(stack(512 * 1024), move || { run(); });
    loop { goish::runtime::sched::Gosched(); }
}

fn run() {
    // A healthy conn is admitted, and admission marks it reused.
    {
        let t = Transport::default();
        let pc = conn("a.com");
        let e = t.tryPutIdleConn(&pc);
        check("a healthy conn is pooled and marked reused",
              e.IsNil() && pc.isReused(), fmt::Sprintf!("%v", e));
        check("and can then be removed", t.removeIdleConnLocked(&pc), string(""));
        check("removing it twice reports false the second time",
              !t.removeIdleConnLocked(&pc), string(""));
    }

    // Each rejection is a distinct named error.
    {
        let mut t = Transport::default();
        t.DisableKeepAlives = true;
        let e = t.tryPutIdleConn(&conn("a.com"));
        check("keep-alives disabled is rejected by name",
              !e.IsNil() && e.Error() == "http: putIdleConn: keep alives disabled", fmt::Sprintf!("%v", e));
    }
    {
        let mut t = Transport::default();
        t.MaxIdleConnsPerHost = -1;
        let e = t.tryPutIdleConn(&conn("a.com"));
        check("a NEGATIVE MaxIdleConnsPerHost means no pooling for that host",
              !e.IsNil() && e.Error() == "http: putIdleConn: keep alives disabled", fmt::Sprintf!("%v", e));
    }
    {
        let t = Transport::default();
        let pc = conn("a.com");
        pc.close(errors::New(string("boom")));
        let e = t.tryPutIdleConn(&pc);
        check("a broken conn is rejected by name",
              !e.IsNil() && e.Error() == "http: putIdleConn: connection is in bad state", fmt::Sprintf!("%v", e));
    }
    {
        // Default MaxIdleConnsPerHost is 2, so the third to the SAME
        // host is refused — and a different host is not.
        let t = Transport::default();
        let e1 = t.tryPutIdleConn(&conn("a.com"));
        let e2 = t.tryPutIdleConn(&conn("a.com"));
        let e3 = t.tryPutIdleConn(&conn("a.com"));
        let other = t.tryPutIdleConn(&conn("b.com"));
        check("per-host cap is 2, and it is PER HOST",
              e1.IsNil() && e2.IsNil()
                  && !e3.IsNil() && e3.Error() == "http: putIdleConn: too many idle connections for host"
                  && other.IsNil(),
              fmt::Sprintf!("%v/%v/%v/%v", e1, e2, e3, other));
    }
    {
        let t = Transport::default();
        let pc = conn("a.com");
        let _ = t.tryPutIdleConn(&pc);
        t.CloseIdleConnections();
        check("CloseIdleConnections closes what was pooled", pc.isBroken(), string(""));
        // closeIdle stays set: conns finishing AFTER the call are
        // closed rather than pooled.
        let e = t.tryPutIdleConn(&conn("a.com"));
        check("and newly idle conns are refused afterwards",
              !e.IsNil() && e.Error() == "http: putIdleConn: CloseIdleConnections was called", fmt::Sprintf!("%v", e));
    }

    // ── queueForIdleConn ──
    {
        let t = Transport::default();
        let pc = conn("a.com");
        let _ = t.tryPutIdleConn(&pc);
        let w = Arc::new(wantConn::__new());
        w.__set_key(pc.cacheKey.clone());
        let got = t.queueForIdleConn(&w);
        check("a waiter is satisfied from the idle pool",
              got && !w.waiting()
                  && w.__delivered().map(|d| Arc::ptr_eq(&d, &pc)).unwrap_or(false),
              string(""));
        // Delivered means REMOVED: a second waiter finds nothing and
        // is queued instead. Leaving it in the list would hand one
        // HTTP/1 conn to two requests.
        let w2 = Arc::new(wantConn::__new());
        w2.__set_key(pc.cacheKey.clone());
        check("the delivered conn is removed, so the next waiter queues",
              !t.queueForIdleConn(&w2) && w2.waiting(), string(""));
    }
    {
        // A BROKEN conn in the list is skipped, not handed out.
        let t = Transport::default();
        let bad = conn("a.com");
        let _ = t.tryPutIdleConn(&bad);
        bad.close(errors::New(string("readLoop marked it broken")));
        let w = Arc::new(wantConn::__new());
        w.__set_key(bad.cacheKey.clone());
        check("a broken idle conn is skipped rather than delivered",
              !t.queueForIdleConn(&w) && w.waiting(), string(""));
    }
    {
        // queueForIdleConn undoes CloseIdleConnections — Go: "we might
        // want one".
        let t = Transport::default();
        t.CloseIdleConnections();
        let w = Arc::new(wantConn::__new());
        let _ = t.queueForIdleConn(&w);
        let e = t.tryPutIdleConn(&conn("a.com"));
        check("queueForIdleConn clears closeIdle, so pooling resumes",
              e.IsNil(), fmt::Sprintf!("%v", e));
    }
    {
        // DisableKeepAlives short-circuits before touching the pool.
        let mut t = Transport::default();
        t.DisableKeepAlives = true;
        let w = Arc::new(wantConn::__new());
        check("DisableKeepAlives refuses without consulting the pool",
              !t.queueForIdleConn(&w) && w.waiting(), string(""));
    }

    // ── getConn ── the idle-HIT path, end to end, no dialing
    {
        let t = Transport::default();
        let pc = conn("a.com");
        let _ = t.tryPutIdleConn(&pc);
        let (u, _) = ParseURL(string("http://a.com/"));
        let cm = connectMethod {
            proxyURL: None,
            targetScheme: string("http"),
            targetAddr: goish::net::http::transport::canonicalAddr(&u),
            onlyH1: false,
        };
        let (r0, _) = goish::net::http::NewRequest(string("GET"), string("http://a.com/"), goish::slice::new());
        let (got, e) = t.getConn(&r0, &cm);
        check("getConn returns the pooled conn without dialing",
              e.IsNil() && got.map(|g| Arc::ptr_eq(&g, &pc)).unwrap_or(false),
              fmt::Sprintf!("%v", e));
        // Second call: pool is empty now, so it queues and reports
        // that no idle conn was available.
        let (got2, e2) = t.getConn(&r0, &cm);
        check("a second getConn finds nothing and queues instead",
              got2.is_none() && !e2.IsNil(), string(""));
        // The waiter really is queued: freeing a conn now satisfies it.
        let fresh = conn("a.com");
        let _ = t.tryPutIdleConn(&fresh);
        let (got3, e3) = t.getConn(&r0, &cm);
        check("and a newly pooled conn is handed out on the next call",
              e3.IsNil() && got3.is_some(), fmt::Sprintf!("%v", e3));
    }

    let p = PASSED.load(Ordering::Relaxed);
    let f = FAILED.load(Ordering::Relaxed);
    fmt::Printf!("\n%d passed, %d failed\n", p as i64, f as i64);
    if f == 0 { fmt::Printf!("HTTP_IDLEPOOL_SMOKE_OK\n"); goish::os::Exit(0); }
    fmt::Printf!("HTTP_IDLEPOOL_SMOKE_FAIL\n");
    goish::os::Exit(1);
}
