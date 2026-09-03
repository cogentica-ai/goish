// timeout_iface_ref_smoke — does a deadline error report a timeout?
//
// Reference: Go 1.25.5 net, measured by tools/gen_timeout_iface_ref.go.
// Every GO[] line is Go's verbatim output.
//
// Go declares `interface{ Timeout() bool }` TWICE — once in os
// (error.go:41) and once in net (net.go:535) — and it costs nothing,
// because both are anonymous and satisfaction is structural: one type
// with one method satisfies both.
//
// goish cannot copy that. Its interfaces are satisfied by an explicit
// impl plus a registry entry keyed on the TRAIT'S identity, so two
// identically-shaped traits are two different keys and a type
// registered for one is invisible to the other. os had declared its
// own `timeout` and registered the deadline and errno errors against
// it; net's `OpError.Timeout` asked net's, and missed every one.
//
// The line that mattered is oper-deadline: a socket read that hits its
// deadline, wrapped in a net.OpError exactly as the net package wraps
// it, reported Timeout() == FALSE. That is the answer to the standard
// Go retry check —
//
//     if ne, ok := err.(net.Error); ok && ne.Timeout() { retry }
//
// — on the one error that check exists for. `os.IsTimeout` said false
// on it too, while saying true on the same error unwrapped, because
// the two paths asked different traits.
//
// There is now one trait, net's, re-exported by os. deadline-bare also
// needed net.Error itself: Go's os.ErrDeadlineExceeded satisfies it by
// having all three methods, and goish had no Temporary at all.
//
// oper-plain is the control: a net.OpError around an ordinary error IS
// a net.Error and is NOT a timeout, so a fix that made everything
// answer true would fail here.

#![no_std]
#![no_main]
extern crate alloc;
extern crate goish;

use goish::errors;
use goish::fmt;
use goish::net::net as gnet;
use goish::string;

// Go's verbatim output.
const GO: [&str; 4] = [
    "deadline-bare  iface-timeout=true  iface-temporary=true  net.Error=true  netTimeout=true  osIsTimeout=true",
    "oper-deadline  iface-timeout=true  iface-temporary=true  net.Error=true  netTimeout=true  osIsTimeout=true",
    "oper-plain     iface-timeout=false iface-temporary=false net.Error=true  netTimeout=false osIsTimeout=false",
    // A REAL socket read deadline. The three above are built by hand
    // in this file, which is precisely what let the same gap hide in
    // common_read_error_ref_smoke: a hand-built error uses a type that
    // IS registered, while goish's `net` produced an untyped string
    // until f5f523c and every assertion below missed it. This case
    // asks the two questions Go's own documentation tells a caller to
    // ask — os.IsTimeout and err.(net.Error).Timeout() — about the
    // error `net` actually returns.
    "real-read-timeout iface-timeout=true  iface-temporary=true  net.Error=true  netTimeout=true  osIsTimeout=true",
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
    let deadline: goish::error = goish::os::ErrDeadlineExceeded.into();
    let oper_deadline = errors::Wrap(gnet::OpError {
        Op: string("read"),
        Net: string("tcp"),
        Source: None,
        Addr: None,
        Err: deadline.clone(),
    });
    let oper_plain = errors::Wrap(gnet::OpError {
        Op: string("read"),
        Net: string("tcp"),
        Source: None,
        Addr: None,
        Err: errors::New(string("boom")),
    });

    let cases: [(&str, goish::error); 3] = [
        ("deadline-bare", deadline),
        ("oper-deadline", oper_deadline),
        ("oper-plain", oper_plain),
    ];
    // A real socket read deadline, so the error comes from `net`.
    let real_err: goish::error = {
        let (ln, le) = goish::net::Listen(string("tcp"), string("127.0.0.1:0"));
        if !le.IsNil() {
            le
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
                de
            } else {
                let _ =
                    c.SetReadDeadline(goish::time::Now().Add(goish::time::Duration(100_000_000)));
                let mut buf = goish::make!([]goish::byte, 16);
                let (_n, rerr) = goish::io::Reader::Read(&mut c, &mut buf);
                let _ = goish::io::Closer::Close(&mut c);
                rerr
            }
        }
    };
    let cases: [(&str, goish::error); 4] = [
        cases[0].clone(),
        cases[1].clone(),
        cases[2].clone(),
        ("real-read-timeout", real_err),
    ];

    for (name, e) in cases.iter() {
        let (t, okt) = errors::AsIface::<goish::d!(gnet::timeout)>(e);
        let (m, okm) = errors::AsIface::<goish::d!(gnet::temporary)>(e);
        let (ne, okn) = errors::AsIface::<goish::d!(gnet::Error)>(e);
        chk(fmt::Sprintf!(
            "%-14s iface-timeout=%-5v iface-temporary=%-5v net.Error=%-5v netTimeout=%-5v osIsTimeout=%v",
            goish::string::from_bytes(name.as_bytes()),
            okt && t.Timeout(),
            okm && m.Temporary(),
            okn,
            okn && ne.Timeout(),
            goish::os::IsTimeout(e.clone())
        ));
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
