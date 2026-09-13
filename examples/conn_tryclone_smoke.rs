// conn_tryclone_smoke — `TCPConn::TryClone` gives two independently
// owned handles on one socket (#28).
//
// Go hands a single `net.Conn` interface value to two goroutines and
// lets them share it. Rust ownership cannot: moving one connection into
// both a reader and a writer is impossible, and wrapping it in one
// `Arc<Mutex<_>>` is NOT equivalent — a blocking read holds the mutex
// and stops the writer, deadlocking any full-duplex protocol. That is
// the shape a JSON-RPC server needs, and it is why this exists.
//
// Four properties, one per acceptance criterion on the issue:
//
//   1. bidirectional traffic     write on one handle, read on the other
//   2. concurrent read + write   a handle BLOCKED in Read does not stop
//                                the other handle writing. This is the
//                                row a mutex-based sharing scheme fails.
//   3. independent close         closing one handle leaves the other
//                                usable; the socket dies with the last
//   4. the error path            TryClone of a closed conn returns a
//                                non-nil error and no usable conn
//
// Not a stress test: one listener, one connection, a few bytes.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use goish::io::{Closer, Reader, Writer};
use goish::net;
use goish::time;
use goish::{convert, fmt, go, make, string, syscall};

static FAILED: AtomicUsize = AtomicUsize::new(0);

fn check(name: &'static str, ok: bool, detail: goish::string) {
    if ok {
        fmt::Printf!("[ok] %s\n", name);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("[!!] %s — %s\n", name, detail);
    }
}

/// `Error()` on a nil error panics, and `check` evaluates its detail
/// eagerly, so every nil-error row has to go through this.
fn errtext(e: &goish::error) -> goish::string {
    if e.IsNil() {
        return string("");
    }
    return e.Error();
}

fn addr_for(port: u32) -> goish::string {
    let mut buf: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(24);
    buf.extend_from_slice(b"127.0.0.1:");
    let mut tmp = [0u8; 6];
    let mut i = tmp.len();
    let mut n = port;
    if n == 0 {
        i -= 1;
        tmp[i] = b'0';
    } else {
        while n > 0 {
            i -= 1;
            tmp[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
    }
    buf.extend_from_slice(&tmp[i..]);
    return string::from_bytes(&buf);
}

#[goish::main]
fn main() {
    let (ln, err) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    check("listen", err.IsNil(), errtext(&err));
    if !err.IsNil() {
        syscall::Exit(1);
    }
    let port = ln.Addr().Port;
    static CLIENT_PORT: AtomicI32 = AtomicI32::new(0);
    CLIENT_PORT.store(port as i32, Ordering::Release);

    // Echo server: read a line, write it back with a prefix, then send
    // a second unsolicited message so the client can read twice.
    go!(move || {
        let (mut c, e) = ln.Accept();
        if !e.IsNil() {
            return;
        }
        let mut buf = make!([]u8, 64);
        let (n, _) = c.Read(&mut buf);
        if n > 0 {
            let _ = c.Write(convert::bytes("echo:"));
            let _ = c.Write(buf.slice(0, n));
        }
        // The second reply is GATED on receiving a byte from the
        // client's other handle. That makes the next assertion causal
        // rather than timing-based: the client's Read cannot complete
        // until its sibling handle's Write has actually reached the
        // peer, so a passing row proves the two ran concurrently
        // instead of merely suggesting it.
        let mut gate = make!([]u8, 8);
        let (gn, _) = c.Read(&mut gate);
        if gn > 0 {
            let _ = c.Write(convert::bytes("late"));
        }
        time::Sleep(400 * time::Millisecond);
        let _ = c.Close();
    });

    let (mut conn, derr) = net::Dial(string("tcp"), addr_for(CLIENT_PORT.load(Ordering::Acquire) as u32));
    check("dial", derr.IsNil(), errtext(&derr));
    if !derr.IsNil() {
        syscall::Exit(1);
    }

    // ── 1. two owned handles, bidirectional ─────────────────────────
    let (mut w, terr) = conn.TryClone();
    check("TryClone succeeds on a live conn", terr.IsNil(), errtext(&terr));

    let (nw, werr) = w.Write(convert::bytes("ping"));
    check(
        "write on the DUPLICATE reaches the peer",
        werr.IsNil() && nw == 4,
        fmt::Sprintf!("n=%d err=%v", nw, werr),
    );

    // Read until the whole reply is in. The server writes "echo:" and
    // the payload as two calls, and TCP is free to deliver them as two
    // segments — a single Read returning 5 is correct behaviour, not a
    // failure. Draining fully also matters for the NEXT phase: any
    // bytes left buffered here would make that Read return immediately
    // instead of parking, and the property under test would not be
    // exercised at all.
    let mut got: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    let mut rerr = goish::errors::nil;
    while got.len() < 9 {
        let mut rb = make!([]u8, 64);
        let (nr, e) = conn.Read(&mut rb);
        if !e.IsNil() || nr == 0 {
            rerr = e;
            break;
        }
        got.extend_from_slice(&rb.slice(0, nr));
    }
    check(
        "read on the ORIGINAL sees the reply to the duplicate's write",
        rerr.IsNil() && got.len() == 9 && &got[..] == b"echo:ping",
        fmt::Sprintf!("got=%d bytes err=%v", got.len() as goish::int, rerr),
    );

    // ── 2. a blocked Read does not stop the other handle writing ────
    //
    // The reader parks on the netpoller for ~120 ms waiting for "late".
    // A mutex-shared conn would hold the lock across that park and the
    // write below could not run. Both handles must make progress.
    static WROTE: AtomicUsize = AtomicUsize::new(0);
    let (mut w2, e2) = conn.TryClone();
    check("second TryClone", e2.IsNil(), errtext(&e2));

    // Sleep only to get the reader parked FIRST; correctness does not
    // depend on the margin, because the server will not answer until
    // this write arrives. A deadline on the Read keeps a failure a
    // clean timeout rather than a hang.
    go!(move || {
        time::Sleep(40 * time::Millisecond);
        let (n, e) = w2.Write(convert::bytes("x"));
        if e.IsNil() && n == 1 {
            WROTE.store(1, Ordering::Release);
        }
        let _ = w2.Close();
    });

    let dl = time::Now().Add(3 * time::Second);
    check(
        "SetReadDeadline on the original",
        conn.SetReadDeadline(dl).IsNil(),
        string("SetReadDeadline failed"),
    );
    let mut lb = make!([]u8, 64);
    let (ln2, lerr) = conn.Read(&mut lb);
    check(
        "a Read parked on the netpoller is unblocked by the OTHER handle's Write",
        lerr.IsNil() && ln2 == 4 && &lb.slice(0, 4) as &[u8] == b"late",
        fmt::Sprintf!("n=%d err=%v", ln2, lerr),
    );
    check(
        "and that Write succeeded without a shared mutex",
        WROTE.load(Ordering::Acquire) == 1,
        string("the sibling handle's write never landed"),
    );
    // Clear the deadline so the later rows are not affected by it.
    let _ = conn.SetReadDeadline(time::Time::default());

    // ── 3. closing one handle leaves the other usable ───────────────
    let cerr = w.Close();
    check("closing the duplicate", cerr.IsNil(), errtext(&cerr));
    let (n3, w3err) = conn.Write(convert::bytes("still-here"));
    check(
        "the ORIGINAL still writes after the duplicate is closed",
        w3err.IsNil() && n3 == 10,
        fmt::Sprintf!("n=%d err=%v", n3, w3err),
    );

    // ── 3b. the same operation on a UNIX-DOMAIN connection ──────────
    //
    // The issue requires this, and alpha.13 represents both families as
    // `TCPConn`, so it is tempting to assert it from the type alone.
    // `TryClone` is an operation on the DESCRIPTOR, not on the address
    // family — but "it should work" is not a measurement, so it is
    // measured.
    {
        let (dir, derr2) = goish::os::MkdirTemp(string(""), string("goishdup"));
        if derr2.IsNil() {
            let sock = fmt::Sprintf!("%s/s.sock", dir);
            let (uln, ulerr) = net::Listen(string("unix"), sock.clone());
            check("unix listen", ulerr.IsNil(), errtext(&ulerr));
            if ulerr.IsNil() {
                go!(move || {
                    let (mut uc, e) = uln.Accept();
                    if e.IsNil() {
                        let mut b = make!([]u8, 16);
                        let (n, _) = uc.Read(&mut b);
                        if n > 0 {
                            let _ = uc.Write(convert::bytes("u-ok"));
                        }
                        let _ = uc.Close();
                    }
                });
                let (mut ucli, uderr) = net::Dial(string("unix"), sock.clone());
                check("unix dial", uderr.IsNil(), errtext(&uderr));
                if uderr.IsNil() {
                    let (mut uw, uterr) = ucli.TryClone();
                    check("TryClone on a unix conn", uterr.IsNil(), errtext(&uterr));
                    let (un, uwerr) = uw.Write(convert::bytes("hi"));
                    let mut ub = make!([]u8, 16);
                    let (urn, urerr) = ucli.Read(&mut ub);
                    check(
                        "unix: write on the duplicate, read on the original",
                        uwerr.IsNil() && un == 2 && urerr.IsNil() && urn == 4
                            && &ub.slice(0, 4) as &[u8] == b"u-ok",
                        fmt::Sprintf!("wn=%d rn=%d werr=%v rerr=%v", un, urn, uwerr, urerr),
                    );
                    let _ = uw.Close();
                    let _ = ucli.Close();
                }
            }
            // Leave nothing behind: a leftover socket in a temp dir is a
            // cleanup bug reporting itself.
            let _ = goish::os::RemoveAll(dir);
        }
    }

    // ── 4. the error path ───────────────────────────────────────────
    let _ = conn.Close();
    let (_dead, eerr) = conn.TryClone();
    check(
        "TryClone of a CLOSED conn returns a non-nil error",
        !eerr.IsNil(),
        string("expected an error, got nil"),
    );

    let f = FAILED.load(Ordering::Relaxed);
    if f == 0 {
        fmt::Printf!("\nok 16/16\n");
        syscall::Exit(0);
    }
    fmt::Printf!("\nFAIL %d\n", f as i64);
    syscall::Exit(1);
}
