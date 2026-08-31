// net_error_iface_smoke — net.Error assertions against a running Go.
// (net/net.go, errors/wrap.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_neterror_ref.go` run in `package
// net_test` by `scripts/goref.sh`.
//
// Go's error types satisfy `net.Error`, `interface{ Timeout() bool }`
// and `interface{ Temporary() bool }` STRUCTURALLY, by having the
// methods, and `OpError.Timeout()` asserts the second on the error it
// wraps. In goish an `error` is a HANDLE around `Arc<dyn ErrorTrait>`,
// and `cast!` downcasts whatever it is handed — handed an `error` it
// asks the registry for the HANDLE's type, which nothing registers.
//
// So the assertion missed. Silently, and for every error:
// `OpError::Timeout` had never once returned true, `OpError::Temporary`
// never for a wrapped temporary error, `io/fs::PathError::Timeout`
// never at all, and `newDNSError` built every DNSError with IsTimeout
// and IsTemporary false regardless of what it was given. Anchoring
// `context` is what surfaced it: DeadlineExceeded.Timeout() had to be
// reachable, and nothing could reach it.
//
// The fix is `errors::AsIface`, which reaches THROUGH the handle to the
// concrete error — the assertion Go writes — plus the seven impls and
// their registrations, which did not exist either.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::errors::{self, error, ErrorTrait};
use goish::gostring::string;
use goish::net::net::{self as netpkg, AddrError, DNSError, InvalidAddrError, OpError, ParseError};
use goish::types::int;
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

// go: none — goish idiom: the smokes print one PASS/FAIL line per
//     numbered check; this is that line, hoisted.
fn report(failed: &mut int, ok: bool, n: &str, what: &str) {
    if ok {
        fmt::Println!("[", n, "]", what, "PASS");
    } else {
        fmt::Println!("[", n, "]", what, "FAIL");
        *failed += 1;
    }
}

// go: none — goish idiom: the Go reference's `timeoutErr` — an error
//     that answers Timeout() true and nothing else. This is the shape
//     OpError wraps, and the one a handle-downcast can never see.
struct TimeoutErr;

impl ErrorTrait for TimeoutErr {
    fn Error(&self) -> string {
        return s("i/o timeout");
    }
}

impl netpkg::timeout for TimeoutErr {
    fn Timeout(&self) -> bool {
        return true;
    }
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

// go: none — goish idiom: the Go reference's `tempErr`.
struct TempErr;

impl ErrorTrait for TempErr {
    fn Error(&self) -> string {
        return s("temporary");
    }
}

impl netpkg::temporary for TempErr {
    fn Temporary(&self) -> bool {
        return true;
    }
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
}

// go: none — goish idiom: the Go reference's `plainErr` — no Timeout,
//     no Temporary, so both assertions must MISS.
struct PlainErr;

impl ErrorTrait for PlainErr {
    fn Error(&self) -> string {
        return s("plain");
    }
}

// go: none — goish idiom: an error with no Timeout of its own that
//     wraps one that has it. Nothing in Go's net needs this shape; it
//     is here to show that `AsIface` asserts on the head and leaves the
//     walking to `errors::Is`.
struct Wrapper {
    inner: error,
}

impl ErrorTrait for Wrapper {
    fn Error(&self) -> string {
        return self.inner.Error();
    }
    fn Unwrap(&self) -> error {
        return self.inner.clone();
    }
}

fn opErr(op: &str, err: error) -> OpError {
    return OpError {
        Op: s(op),
        Net: s("tcp"),
        Source: None,
        Addr: None,
        Err: err,
    };
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // The two test errors are declared here, outside goish, so the
    // registry has to be told about them — exactly as Go's linker would
    // have done for free.
    netpkg::__goish_register_timeout_impl::<TimeoutErr>();
    netpkg::__goish_register_temporary_impl::<TempErr>();

    // 1. OpError forwards Timeout and Temporary to the error it wraps,
    //    and answers false when that error has neither method. Every
    //    `true` below used to be a false.
    {
        let mut ok = true;
        // (wrapped, want_timeout, want_temporary)
        let cases: [(error, bool, bool); 5] = [
            (errors::Wrap(TimeoutErr), true, false),
            (errors::Wrap(TempErr), false, true),
            (errors::Wrap(PlainErr), false, false),
            (goish::context::DeadlineExceeded.into(), true, true),
            (goish::context::Canceled.into(), false, false),
        ];
        let mut i = 0;
        while i < cases.len() {
            let (ref e, want_t, want_p) = cases[i];
            let op = opErr("read", e.clone());
            if op.Timeout() != want_t || op.Temporary() != want_p {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 1", "OpError forwards to what it wraps");
    }

    // 2. The DeadlineExceeded row on its own, because it is the one
    //    that motivated the fix: a context deadline reaching a caller
    //    through an OpError has to read as a timeout, or code that
    //    retries on `netErr.Timeout()` silently stops retrying.
    {
        let de: error = goish::context::DeadlineExceeded.into();
        let op = opErr("read", de);
        let ok = op.Timeout() && op.Temporary();
        report(&mut failed, ok, " 2", "a context deadline IS a timeout");
    }

    // 3. Go: accept-case op=read temporary=false, op=accept
    //    temporary=false. The accept special case is for ECONNRESET and
    //    ECONNABORTED specifically, so a plain error is false either
    //    way — the op alone does not make it temporary.
    {
        let mut ok = true;
        for op in ["read", "accept"] {
            if opErr(op, errors::Wrap(PlainErr)).Temporary() {
                ok = false;
            }
        }
        report(&mut failed, ok, " 3", "accept alone is not temporary");
    }

    // 4. The net.Error assertion against each concrete type in the
    //    package. Before the impls existed, `ok` was false for all six.
    {
        let mut ok = true;
        let errs: [(error, bool, bool); 5] = [
            (
                errors::Wrap(opErr("dial", errors::Wrap(TimeoutErr))),
                true,
                false,
            ),
            (
                errors::Wrap(ParseError {
                    Type: s("IP address"),
                    Text: s("x"),
                }),
                false,
                false,
            ),
            (
                errors::Wrap(AddrError {
                    Err: s("bad"),
                    Addr: s("y"),
                }),
                false,
                false,
            ),
            (errors::Wrap(InvalidAddrError(s("zap"))), false, false),
            (
                errors::Wrap(DNSError {
                    UnwrapErr: errors::nil,
                    Err: s("no such host"),
                    Name: s("h"),
                    Server: s(""),
                    IsTimeout: true,
                    IsTemporary: true,
                    IsNotFound: false,
                }),
                true,
                true,
            ),
        ];
        let mut i = 0;
        while i < errs.len() {
            let (ref e, want_t, want_p) = errs[i];
            let (ne, hit) = errors::AsIface::<goish::d!(netpkg::Error)>(e);
            if !hit {
                ok = false;
            } else if ne.Timeout() != want_t || ne.Temporary() != want_p {
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 4", "every net error IS a net.Error");
    }

    // 5. A miss is still a miss: an error with no such method answers
    //    false, and the returned value is the nil sentinel rather than
    //    something wrong.
    {
        let mut ok = true;
        let (_, hit) = errors::AsIface::<goish::d!(netpkg::timeout)>(&errors::Wrap(PlainErr));
        if hit {
            ok = false;
        }
        let (_, hit2) = errors::AsIface::<goish::d!(netpkg::Error)>(&errors::New("bare"));
        if hit2 {
            ok = false;
        }
        // And nil is a miss, not a panic.
        let (_, hit3) = errors::AsIface::<goish::d!(netpkg::timeout)>(&errors::nil);
        if hit3 {
            ok = false;
        }
        report(&mut failed, ok, " 5", "AsIface misses cleanly");
    }

    // 6. AsIface asserts on the error ITSELF and does not walk the
    //    chain — Go's `err.(interface{ Timeout() bool })` behaves the
    //    same way, and `errors::As`/`errors::Is` are the walking ones.
    //
    //    `Wrapper` below has no Timeout of its own and wraps one that
    //    does, so the assertion must MISS while a walk would find it.
    {
        let mut ok = true;
        let inner = errors::Wrap(TimeoutErr);
        let wrapped = errors::Wrap(Wrapper {
            inner: inner.clone(),
        });
        let (_, hit) = errors::AsIface::<goish::d!(netpkg::timeout)>(&wrapped);
        if hit {
            ok = false;
        }
        // The walk does reach it — that is `errors::Is`' job, not this
        // one's.
        if !errors::Is(wrapped, inner) {
            ok = false;
        }
        // And an OpError, which HAS a Timeout of its own, hits at the
        // head as Go's does.
        let op = errors::Wrap(opErr("read", errors::Wrap(TimeoutErr)));
        let (_, hitOp) = errors::AsIface::<goish::d!(netpkg::timeout)>(&op);
        if !hitOp {
            ok = false;
        }
        report(&mut failed, ok, " 6", "AsIface asserts, it does not walk");
    }

    if failed == 0 {
        fmt::Println!("ok 6/6");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 6");
        syscall::Exit(1);
    }
}
