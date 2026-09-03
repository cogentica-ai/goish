// net_error_shape_ref_smoke — what a socket error IS, not just what it
// says.
//
// Reference: Go 1.25.5 net, measured by
// tools/gen_net_error_shape_ref.go against real sockets — a refused
// dial and a read that hits its deadline.
//
// Go returns `*net.OpError` for both, carrying the operation, the
// network, and the addresses, so a caller can ask WHICH operation
// failed and branch on `net.Error.Timeout()`. That structure is the
// public contract; the message is a rendering of it.
//
// goish matches on the read path and NOT on the dial path, and this
// smoke records the difference rather than leaving it to be
// rediscovered:
//
//   read  — typed since f5f523c, which composed Go's
//           OpError{Op:"read", Err: errTimeout}. opErr, netErr and
//           timeout all answer as Go's do.
//   dial  — still an `errors::New` string built by `errno_error`, so
//           `errors.As(err, &opErr)` and `err.(net.Error)` BOTH miss.
//           A caller cannot tell a refused connection from any other
//           failure except by matching on text.
//
// The message column is deliberately not pinned. Go renders the
// network and both addresses — "read tcp IP:58946->IP:44309: i/o
// timeout" — which carries ephemeral ports that change every run.
// goish renders neither. Pinning it would mean pinning a divergence
// that is really two divergences (missing Net, missing addresses) and
// a port number that is noise.
//
// KNOWN GAP, and the shape of the fix is known: `errno_error` should
// build `OpError{Op, Net, Source, Addr, Err: syscall.Errno}` as Go
// does. That was blocked until a198b33, because syscall's errno table
// was missing the nine socket errnos and switching to it would have
// rewritten every socket message to "errno". It is unblocked now. It
// changes the text of every socket error in the tree, so it wants its
// own commit, its own measurement, and a green CI on either side.

#![no_std]
#![no_main]
extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::errors;
use goish::fmt;
use goish::net;
use goish::net::net as gnet;
use goish::{go, string, time};

// goish's current shape columns; the Go reference is in the header
// above and in tools/gen_net_error_shape_ref.go.
const GO: [&str; 2] = [
    // dial: matches Go on every column, and on the message too —
    // "dial tcp IP:1: connect: connection refused", byte for byte.
    // Until this line was fixed goish returned an untyped string
    // carrying only Go's INNER half ("connect: connection refused"),
    // so errors.As(err, &opErr) and err.(net.Error) both missed.
    "dial-refused   opErr=true  op=\"dial\"   net=\"tcp\" netErr=true  timeout=false",
    // read: KNOWN GAP, narrower than dial's was. The type is right —
    // opErr, netErr and timeout all answer as Go's do — but Net is
    // empty where Go says "tcp", because `timeout_error` composes an
    // OpError without the network or the addresses. Go renders
    // "read tcp IP:55922->IP:37159: i/o timeout"; goish renders
    // "read: i/o timeout". Closing it means plumbing the conn's
    // addresses into the read path, which is the same work the other
    // errno_error sites (accept, close, dup, shutdown) still need.
    "read-timeout   opErr=true  op=\"read\"   net=\"\"    netErr=true  timeout=true ",
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

fn show(tag: &'static str, err: goish::error) {
    let oe = errors::AsConcrete::<gnet::OpError>(&err);
    let is_op = oe.is_some();
    let (op, nw) = match oe {
        Some(o) => (o.Op.clone(), o.Net.clone()),
        None => (string(""), string("")),
    };
    let (ne, is_net) = errors::AsIface::<goish::d!(gnet::Error)>(&err);
    let msg = if err.IsNil() {
        string("<nil>")
    } else {
        err.Error()
    };
    let m: &str = msg.as_ref();
    let normalised = m.replace("127.0.0.1", "IP");
    // The message is left OUT of the assertion: Go's carries ephemeral
    // ports. What is pinned is the shape a caller branches on.
    let _ = normalised;
    chk(fmt::Sprintf!(
        "%-14s opErr=%-5v op=%-8q net=%-5q netErr=%-5v timeout=%-5v",
        string(tag),
        is_op,
        op,
        nw,
        is_net,
        is_net && ne.Timeout()
    ));
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
    let (_c, e) = net::Dial(string("tcp"), string("127.0.0.1:1"));
    show("dial-refused", e);

    let (ln, le) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    if !le.IsNil() {
        fmt::Printf!("listen: %v\n", le);
        goish::os::Exit(1);
    }
    let port = ln.Addr().Port;
    go!(stack(256 * 1024), move || {
        let (mut c, e) = ln.Accept();
        if e.IsNil() {
            time::Sleep(time::Duration(300_000_000));
            let _ = goish::io::Closer::Close(&mut c);
        }
    });
    time::Sleep(time::Duration(80_000_000));
    let addr = fmt::Sprintf!("127.0.0.1:%d", port as i64);
    let (mut c, _de) = net::Dial(string("tcp"), addr);
    let _ = c.SetReadDeadline(time::Now().Add(time::Duration(80_000_000)));
    let mut buf = goish::make!([]goish::byte, 4);
    let (_n, rerr) = goish::io::Reader::Read(&mut c, &mut buf);
    show("read-timeout", rerr);
    let _ = goish::io::Closer::Close(&mut c);
    let _v: Vec<u8> = Vec::new();

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
