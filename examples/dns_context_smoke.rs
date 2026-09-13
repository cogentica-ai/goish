// dns_context_smoke — a DNS query must be bounded, by its own timeout
// and by the caller's context.
//
// THE FIRST ROW IS THE IMPORTANT ONE, and it is not about contexts at
// all. Against a resolver that never answers, goish's UDP query never
// timed out — not late, never. Measured on the commit before the fix:
// a config with `timeout_secs = 1` was still blocked after 60 seconds.
//
// `SO_RCVTIMEO` does not survive a signal. A `recvfrom` interrupted
// before any data arrives returns EINTR, and the retry restarts the
// timeout from zero. goish's scheduler preempts with signals far more
// often than any DNS timeout, so the receive was interrupted,
// restarted, interrupted — 1688 EINTRs in 20 seconds against a socket
// whose timeout was 100 ms, and not one EAGAIN. The loop retried on
// EINTR without re-checking the clock, which is an unbounded wait
// wearing a timeout's clothes.
//
// That is reachable without any attacker: a nameserver whose UDP/53 is
// firewalled to DROP rather than REJECT is ordinary, and it made every
// goish program that resolves a hostname hang forever.
//
// `net/lookup.rs` took a `context.Context` in nine Resolver methods and
// read none of it: no `Done()`, no `Err()`, no `Deadline()`. A caller
// who bounded a lookup with a one-second context got an unbounded one —
// `attempts x servers x timeout_secs`, which with the usual resolv.conf
// is 2 x 3 x 5 = up to 30 seconds. `#![allow(unused_variables)]` at the
// top of that file kept the compiler quiet about the dead parameters.
//
// THE RESOLVER HERE IS A BLACKHOLE THIS SMOKE OWNS: a UDP socket bound
// to 127.0.0.1 that is never read from. That matters for three reasons.
// It needs no network and no real DNS. It cannot race — pointing at a
// real resolver with a short deadline is a coin flip, and measured
// against Go 1.25.5 a 1 ms deadline on `LookupHost("example.com")`
// returned NIL, because the lookup beat it. And an unbound loopback
// port would not do: the kernel answers with ICMP port-unreachable, so
// the socket fails immediately and never waits, which is not the case
// under test.
//
// Go's shape, measured (`&net.Resolver{PreferGo: true}`):
//
//   cancelled ctx      Err="dial udp <ns>:53: operation was canceled"
//                      IsTimeout=false IsTemporary=true
//   expired deadline   Err="dial udp <ns>:53: i/o timeout"
//                      IsTimeout=true  IsTemporary=true

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use goish::net::dnsclient::{self, QueryBound};
use goish::net::dnsmessage as dns;
use goish::{context, fmt, int, string, syscall, time};

static mut FAILED: int = 0;

fn check(name: &'static str, ok: bool, detail: goish::string) {
    if ok {
        fmt::Printf!("[ok] %s\n", name);
    } else {
        unsafe { FAILED += 1 };
        fmt::Printf!("[!!] %s — %s\n", name, detail);
    }
}

/// A UDP socket bound to an ephemeral loopback port that nothing ever
/// reads. Returns "127.0.0.1:port".
fn blackhole() -> (i32, goish::string) {
    let fd = syscall::Socket(syscall::AF_INET, syscall::SOCK_DGRAM, syscall::IPPROTO_UDP);
    if fd < 0 {
        return (-1, string(""));
    }
    let addr = syscall::SockaddrIn::ipv4([127, 0, 0, 1], 0);
    if syscall::Bind(fd, &addr, core::mem::size_of::<syscall::SockaddrIn>() as u32) < 0 {
        return (-1, string(""));
    }
    // getsockname to learn the port the kernel picked.
    let mut got = syscall::SockaddrIn::ipv4([0, 0, 0, 0], 0);
    let mut len: u32 = core::mem::size_of::<syscall::SockaddrIn>() as u32;
    let r = unsafe {
        syscall::syscall3(
            syscall::SYS_GETSOCKNAME,
            fd as usize,
            &mut got as *mut syscall::SockaddrIn as usize,
            &mut len as *mut u32 as usize,
        )
    };
    if r < 0 {
        return (-1, string(""));
    }
    let port = u16::from_be(got.sin_port);
    return (fd, fmt::Sprintf!("127.0.0.1:%d", port as int));
}

#[goish::main]
fn main() {
    let (fd, server) = blackhole();
    check("bound a blackhole resolver", fd >= 0, string("socket/bind failed"));
    if fd < 0 {
        goish::os::Exit(1);
    }

    // A config that would take 2 x 1 x 5 = 10 seconds to give up.
    let mut cfg = dnsclient::get_system_dns_config();
    cfg.servers = alloc::vec![alloc::string::String::from(server.as_ref() as &str)];
    cfg.timeout_secs = 5;
    cfg.attempts = 2;
    cfg.search = alloc::vec::Vec::new();
    cfg.ndots = 1;
    cfg.use_tcp = false;

    // ── 1. the query times out AT ALL ───────────────────────────────
    //
    // Also the control for every row below: a bounded lookup returning
    // fast proves nothing unless an unbounded one is slow. Before the
    // fix this did not return, so an upper bound is as much the
    // assertion as the lower one.
    let t0 = time::Now();
    let (_p, _s, e0) = dnsclient::lookup_ctx(
        &cfg,
        "example.com",
        dns::TypeA,
        &QueryBound::none(),
    );
    let unbounded_ms = time::Since(t0).Milliseconds();
    check(
        "a query against a dead resolver TERMINATES, and takes its budget",
        !e0.IsNil() && unbounded_ms >= 9000 && unbounded_ms < 20000,
        fmt::Sprintf!("took %dms, want 9000..20000 (err=%v)", unbounded_ms, e0),
    );

    // ── 2. a 1-second context bounds it ─────────────────────────────
    let (ctx, cancel) = context::WithTimeout(context::Background(), time::Second);
    let t1 = time::Now();
    let (_p2, _s2, e1) = dnsclient::lookup_ctx(&cfg, "example.com", dns::TypeA, &QueryBound::of(&ctx));
    let bounded_ms = time::Since(t1).Milliseconds();
    cancel();
    check(
        "a 1s context bounds the lookup to about 1s",
        bounded_ms >= 900 && bounded_ms < 3000,
        fmt::Sprintf!("took %dms, want 900..3000", bounded_ms),
    );
    check(
        "and it fails rather than returning a bogus answer",
        !e1.IsNil(),
        string("expected an error"),
    );

    // ── 3. Go's error shape: a deadline is a TIMEOUT ────────────────
    let de = goish::errors::AsConcrete::<goish::net::net::DNSError>(&e1);
    match de {
        Some(d) => {
            check(
                "the deadline reports IsTimeout, per Go",
                d.IsTimeout && d.IsTemporary && !d.IsNotFound,
                fmt::Sprintf!(
                    "IsTimeout=%v IsTemporary=%v IsNotFound=%v",
                    d.IsTimeout,
                    d.IsTemporary,
                    d.IsNotFound
                ),
            );
            check(
                "and says i/o timeout, not \"context deadline exceeded\"",
                goish::strings::Contains(d.Err.clone(), string("i/o timeout")),
                d.Err.clone(),
            );
        }
        None => {
            check("the deadline produces a DNSError", false, e1.Error());
            check("and says i/o timeout", false, string("no DNSError"));
        }
    }

    // ── 4. an already-cancelled context is NOT a timeout ────────────
    let (ctx2, cancel2) = context::WithCancel(context::Background());
    cancel2();
    let t2 = time::Now();
    let (_p3, _s3, e2) = dnsclient::lookup_ctx(&cfg, "example.com", dns::TypeA, &QueryBound::of(&ctx2));
    let cancel_ms = time::Since(t2).Milliseconds();
    check(
        "a cancelled context stops the lookup promptly",
        cancel_ms < 1500,
        fmt::Sprintf!("took %dms, want <1500", cancel_ms),
    );
    match goish::errors::AsConcrete::<goish::net::net::DNSError>(&e2) {
        Some(d) => check(
            "cancellation is IsTimeout=false, IsTemporary=true, per Go",
            !d.IsTimeout && d.IsTemporary,
            fmt::Sprintf!("IsTimeout=%v IsTemporary=%v Err=%s", d.IsTimeout, d.IsTemporary, d.Err.clone()),
        ),
        None => check("cancellation produces a DNSError", false, e2.Error()),
    }

    unsafe {
        syscall::syscall1(syscall::SYS_CLOSE, fd as usize);
    }

    let f = unsafe { FAILED };
    if f == 0 {
        fmt::Printf!("\nok 8/8\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("\nFAIL %d\n", f);
    goish::os::Exit(1);
}
