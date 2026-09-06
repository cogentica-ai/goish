// http_ctx_cause_ref_smoke — the error a cancelled request reports,
// against Go 1.25.5.
//
// When a request's context ends it, Go does not surface the raw I/O
// failure. readLoop and roundTrip both call
// `pc.cancelRequest(context.Cause(rc.treq.ctx))` (transport.go:2410,
// :2883), so what the caller sees is the context's CAUSE.
//
// goish cancels by expiring the conn's netpoll deadline instead
// (arm_cancel_watch), which unblocks the I/O but reported whatever
// that I/O returned. Two things were wrong before the client mapped
// the cause:
//
//   deadline  goish said `read tcp …: i/o timeout` where Go says
//             `context deadline exceeded`, so
//             `errors.Is(err, context.DeadlineExceeded)` — the
//             standard way to ask — answered FALSE.
//   cause     a WithCancelCause request reported plain "context
//             canceled" and lost the cause, which is the one thing
//             WithCancelCause exists to carry.
//
// The `plain` rows were already right and are kept because they are
// what distinguishes "map the cause" from "always say canceled".
//
// The errors.Is rows matter more than the strings: a caller branches
// on Is, not on text.
//
// The server URL is normalised to "URL" on both sides — the port is
// ephemeral. Reference: scripts/goref.sh net/http.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use alloc::sync::Arc;
use goish::gostring::string;
use goish::io::Writer;
use goish::net::http;
use goish::{context, errors, fmt, net, time};

const GO: [&str; 6] = [
    "cause     err=Get \"URL\": my custom cause",
    "cause     is-errMine=true is-Canceled=false",
    "plain     err=Get \"URL\": context canceled",
    "plain     is-Canceled=true",
    "deadline  err=Get \"URL\": context deadline exceeded",
    "deadline  is-DeadlineExceeded=true",
];

static mut BAD: usize = 0;

fn chk(ln: &mut usize, got: &string) {
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line: %q\n", got);
        unsafe { BAD += 1 };
        *ln += 1;
        return;
    }
    let want = string::from(GO[*ln]);
    if got.clone() == want {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        unsafe { BAD += 1 };
        fmt::Printf!("[!!] goish: %q\n", got);
        fmt::Printf!("     go   : %q\n", want);
    }
    *ln += 1;
}

#[goish::main]
fn main() {
    goish::go!(stack(1024 * 1024), move || { run(); });
    loop { goish::runtime::sched::Gosched(); }
}

/// The server URL carries an ephemeral port; replace it so the error
/// text can be pinned.
fn norm(e: &errors::error, url: &string) -> string {
    return goish::strings::ReplaceAll(e.Error(), url.clone(), string::from("URL"));
}

fn run() {
    let mut ln: usize = 0;
    let errMine = errors::New(string::from("my custom cause"));
    let mux = http::ServeMux::new();
    mux.HandleFunc(string::from("/"), |w, _r| {
        time::Sleep(time::Second * 2);
        let _ = w.Write(goish::convert::bytes(string::from("late")));
    });
    let mut srv = http::Server::default();
    srv.Handler = Arc::new(mux) as Arc<dyn http::Handler>;
    let srv = Arc::new(srv);
    let (l, _) = net::Listen(string::from("tcp"), string::from("127.0.0.1:0"));
    let addr = l.Addr().String();
    let s2 = srv.clone();
    goish::go!(stack(512 * 1024), move || { let _ = s2.Serve(l); });
    time::Sleep(time::Millisecond * 50);
    let url = string::from("http://") + addr + string::from("/");

    // 1. cancel with a cause
    let (ctx, cancel) = context::WithCancelCause(context::Background());
    let em = errMine.clone();
    goish::go!(stack(256 * 1024), move || {
        time::Sleep(time::Millisecond * 150);
        cancel(em);
    });
    let (req, _) = http::NewRequestWithContext(ctx, string::from("GET"), url.clone(),
        goish::slice::<goish::byte>::new());
    let c = http::Client::default();
    let (_, err) = c.Do(&req);
    chk(&mut ln, &fmt::Sprintf!("cause     err=%s", norm(&err, &url)));
    chk(&mut ln, &fmt::Sprintf!("cause     is-errMine=%v is-Canceled=%v",
        errors::Is(err.clone(), errMine.clone()),
        errors::Is(err.clone(), context::Canceled)));

    // 2. plain cancel
    let (ctx2, cancel2) = context::WithCancel(context::Background());
    goish::go!(stack(256 * 1024), move || {
        time::Sleep(time::Millisecond * 150);
        cancel2();
    });
    let (req2, _) = http::NewRequestWithContext(ctx2, string::from("GET"), url.clone(),
        goish::slice::<goish::byte>::new());
    let (_, err2) = c.Do(&req2);
    chk(&mut ln, &fmt::Sprintf!("plain     err=%s", norm(&err2, &url)));
    chk(&mut ln, &fmt::Sprintf!("plain     is-Canceled=%v",
        errors::Is(err2.clone(), context::Canceled)));

    // 3. deadline
    let (ctx3, _c3) = context::WithTimeout(context::Background(), time::Millisecond * 150);
    let (req3, _) = http::NewRequestWithContext(ctx3, string::from("GET"), url.clone(),
        goish::slice::<goish::byte>::new());
    let (_, err3) = c.Do(&req3);
    chk(&mut ln, &fmt::Sprintf!("deadline  err=%s", norm(&err3, &url)));
    chk(&mut ln, &fmt::Sprintf!("deadline  is-DeadlineExceeded=%v",
        errors::Is(err3.clone(), context::DeadlineExceeded)));

    let _ = srv.Close();
    if ln != GO.len() {
        fmt::Printf!("[!!] line count mismatch with the Go reference\n");
        unsafe { BAD += 1 };
    }
    let bad = unsafe { BAD };
    if bad != 0 {
        // e2e_runner.sh: "rc=0 wins regardless of stdout content",
        // so printing the mismatch is not enough to fail CI.
        fmt::Printf!("[!!] %d row(s) diverge from Go\n", bad as i64);
        goish::os::Exit(1);
    }
    goish::os::Exit(0);
}
