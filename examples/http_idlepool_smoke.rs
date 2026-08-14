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
use goish::net::http::transport::{connectMethod, persistConn};
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

    let p = PASSED.load(Ordering::Relaxed);
    let f = FAILED.load(Ordering::Relaxed);
    fmt::Printf!("\n%d passed, %d failed\n", p as i64, f as i64);
    if f == 0 { fmt::Printf!("HTTP_IDLEPOOL_SMOKE_OK\n"); goish::os::Exit(0); }
    fmt::Printf!("HTTP_IDLEPOOL_SMOKE_FAIL\n");
    goish::os::Exit(1);
}
