// common_read_error_ref_smoke — which read errors the serve loop
// swallows.
//
// Reference: Go 1.25.5 net/http, measured by
// tools/gen_common_read_error_ref.go. Every GO[] line is Go's verbatim
// answer from isCommonNetReadError itself.
//
// This one function decides whether a connection dies in SILENCE or
// the client is told what was wrong: conn.serve closes without a word
// on an ordinary end-of-connection read, and answers 400 on anything
// else. Getting it wrong in one direction turns a diagnosable error
// into a bare reset; in the other it writes a response onto a
// connection that is already gone.
//
// goish used to answer by matching the error TEXT —
// `contains("i/o timeout")` and `starts_with("read")` — under a
// comment saying it had no typed net.Error/net.OpError to assert on.
// It has both, and both are registered, so the assertions Go writes
// are available: net.Error for the timeout arm, a concrete
// *net.OpError with Op == "read" for the other.
//
// The last two cases are why this is not merely tidier. They are
// ordinary errors whose MESSAGES happen to read like network ones:
//
//   "read: malformed chunk size"      — starts with "read"
//   "json: i/o timeout in field"      — contains "i/o timeout"
//
// The text version answered true to both. Go answers false, because
// neither is a *net.OpError and neither is a net.Error. A chunked-body
// parse error that begins with the word "read" is not hypothetical,
// and under the old rule it would have closed the connection in
// silence instead of returning the 400 it earns.
//
// The OpError rows pin the other half: Op == "read" qualifies, "write"
// and "dial" do not, and a read whose inner error is a deadline
// qualifies twice over.

#![no_std]
#![no_main]
extern crate alloc;
extern crate goish;

use goish::errors;
use goish::fmt;
use goish::net::http;
use goish::net::net as gnet;
use goish::string;

// Go's verbatim output.
const GO: [&str; 10] = [
    "eof                true",
    "nil-like           false",
    "deadline           true",
    "oper-read          true",
    "oper-write         false",
    "oper-dial          false",
    "oper-read-timeout  true",
    "text-read-prefix   false",
    "text-io-timeout    false",
    // The case hand-built errors cannot stand in for: a REAL socket
    // read deadline, with the error built by `net` the way production
    // builds it. Its absence is exactly why the typed rewrite in
    // 0773a9d measured 9/9 against Go while breaking idle-close on
    // every live connection — every typed input above happens to be a
    // type that IS registered, and goish's own deadline error was an
    // untyped string until f5f523c.
    "real-read-timeout  true",
];

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

fn oper(op: &str, inner: goish::error) -> goish::error {
    errors::Wrap(gnet::OpError {
        Op: goish::string::from_bytes(op.as_bytes()),
        Net: string("tcp"),
        Source: None,
        Addr: None,
        Err: inner,
    })
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
    let cases: [(&str, goish::error); 9] = [
        ("eof", goish::io::EOF.into()),
        ("nil-like", errors::New(string("boom"))),
        ("deadline", goish::os::ErrDeadlineExceeded.into()),
        ("oper-read", oper("read", errors::New(string("x")))),
        ("oper-write", oper("write", errors::New(string("x")))),
        ("oper-dial", oper("dial", errors::New(string("x")))),
        (
            "oper-read-timeout",
            oper("read", goish::os::ErrDeadlineExceeded.into()),
        ),
        (
            "text-read-prefix",
            errors::New(string("read: malformed chunk size")),
        ),
        (
            "text-io-timeout",
            errors::New(string("json: i/o timeout in field")),
        ),
    ];
    for (name, e) in cases.iter() {
        chk(fmt::Sprintf!(
            "%-18s %v",
            goish::string::from_bytes(name.as_bytes()),
            http::server::isCommonNetReadError(e.clone())
        ));
    }

    // A real socket read deadline: the error comes from `net`, not
    // from this file, which is the whole point of the case.
    let (ln, le) = goish::net::Listen(string("tcp"), string("127.0.0.1:0"));
    if !le.IsNil() {
        chk(fmt::Sprintf!(
            "%-18s listen error %v",
            string("real-read-timeout"),
            le
        ));
    } else {
        let port = ln.Addr().Port;
        goish::go!(stack(256 * 1024), move || {
            let (mut c, e) = ln.Accept();
            if e.IsNil() {
                goish::time::Sleep(goish::time::Duration(300_000_000));
                let _ = goish::io::Closer::Close(&mut c);
            }
        });
        goish::time::Sleep(goish::time::Duration(80_000_000));
        let addr = fmt::Sprintf!("127.0.0.1:%d", port as i64);
        let (mut c, de) = goish::net::Dial(string("tcp"), addr);
        if !de.IsNil() {
            chk(fmt::Sprintf!(
                "%-18s dial error %v",
                string("real-read-timeout"),
                de
            ));
        } else {
            let _ = c.SetReadDeadline(goish::time::Now().Add(goish::time::Duration(100_000_000)));
            let mut buf = goish::make!([]goish::byte, 16);
            let (_n, rerr) = goish::io::Reader::Read(&mut c, &mut buf);
            chk(fmt::Sprintf!(
                "%-18s %v",
                string("real-read-timeout"),
                http::server::isCommonNetReadError(rerr)
            ));
            let _ = goish::io::Closer::Close(&mut c);
        }
    }

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
