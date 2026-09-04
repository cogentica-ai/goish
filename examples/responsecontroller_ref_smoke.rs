// responsecontroller_ref_smoke — the capabilities the server's own
// writer offers.
//
// Reference: Go 1.25.5 net/http, measured by
// tools/gen_responsecontroller_ref.go from inside a handler. The GO[]
// line is Go's verbatim output.
//
// http_responsecontroller_smoke already covers the controller's WALK —
// try the capability, else Unwrap, else ErrNotSupported — and covers
// it well. Every writer it walks is hand-written for the test, so what
// it proves is that the walk works on writers the test wrote. It says
// nothing about the writer a handler is actually given.
//
// That writer supported none of these. `ReadDeadliner`,
// `WriteDeadliner`, `FullDuplexer` and `FlushErrorer` had ZERO
// implementations anywhere in the tree, so every probe missed and
// every method answered "feature not supported" on the server's own
// response — a handler asking for a read deadline was told the writer
// could not do that, while Go's answers nil and sets it.
//
// Found by sweeping assertion TARGETS against the registry: a trait
// that is asserted on but has no registered implementor is an
// assertion that can never fire. Four of the five here came back with
// zero.
//
// EnableFullDuplex answers nil rather than ErrNotSupported, and that
// is not a shortcut. Go needs telling because its default is to
// consume the request body before replying; goish reads the body
// eagerly BEFORE the handler runs, so there is never an unread body
// for a write to deadlock against. The property the flag buys is
// already unconditional, so nil is the honest answer and
// ErrNotSupported would be the false one.

#![no_std]
#![no_main]
extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use goish::fmt;
use goish::net;
use goish::net::http;
use goish::net::http::responsewriter::response;
use goish::{go, string, time};

// Go's verbatim output.
const GO: [&str; 1] = ["responsecontroller flush=nil setread=nil setwrite=nil fullduplex=nil"];

static FAILED: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static LN: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

fn chk(got: goish::string) {
    use core::sync::atomic::Ordering;
    let i = LN.fetch_add(1, Ordering::Relaxed);
    let g: &str = got.as_ref();
    if i >= GO.len() {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("[!!] extra line %d: %s\n", i as i64, got);
        return;
    }
    if g == GO[i] {
        fmt::Printf!("ok   %s\n", got);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!(
            "[!!] line %d\n  got:  %s\n  want: %s\n",
            i as i64,
            got,
            goish::string(GO[i])
        );
    }
}

fn err_str(e: goish::error) -> goish::string {
    if e.IsNil() {
        string("nil")
    } else {
        e.Error()
    }
}

#[goish::main]
fn main() {
    goish::go!(stack(1024 * 1024), move || {
        run();
    });
    loop {
        goish::runtime::sched::Gosched();
    }
}

fn run() {
    // A real server response over a real connection: the writer the
    // serve loop hands a handler, built the same way.
    let (ln, le) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    if !le.IsNil() {
        fmt::Printf!("listen: %v\n", le);
        goish::os::Exit(1);
    }
    let port = ln.Addr().Port;
    go!(stack(256 * 1024), move || {
        let (mut c, e) = ln.Accept();
        if e.IsNil() {
            time::Sleep(time::Duration(400_000_000));
            let _ = goish::io::Closer::Close(&mut c);
        }
    });
    time::Sleep(time::Duration(80_000_000));
    let addr = fmt::Sprintf!("127.0.0.1:%d", port as i64);
    let (conn, de) = net::Dial(string("tcp"), addr);
    if !de.IsNil() {
        fmt::Printf!("dial: %v\n", de);
        goish::os::Exit(1);
    }

    let w: Arc<dyn http::ResponseWriter + Send + Sync + 'static> = Arc::new(response::new(conn));
    let rc = http::NewResponseController(w);
    chk(fmt::Sprintf!(
        "responsecontroller flush=%v setread=%v setwrite=%v fullduplex=%v",
        err_str(rc.Flush()),
        err_str(rc.SetReadDeadline(time::Now().Add(time::Duration(60_000_000_000)))),
        err_str(rc.SetWriteDeadline(time::Now().Add(time::Duration(60_000_000_000)))),
        err_str(rc.EnableFullDuplex())
    ));

    use core::sync::atomic::Ordering;
    let f = FAILED.load(Ordering::Relaxed);
    let n = LN.load(Ordering::Relaxed);
    if f == 0 && n == GO.len() {
        fmt::Printf!("\nok %d/%d\n", n as i64, GO.len() as i64);
        goish::os::Exit(0);
    }
    fmt::Printf!(
        "\nFAILED %d of %d (%d lines)\n",
        f as i64,
        GO.len() as i64,
        n as i64
    );
    goish::os::Exit(1);
}
