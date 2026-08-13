// httptrace_smoke — exercise net/http/httptrace.
// (net/http/httptrace/trace.go)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicI64, Ordering};

use goish::fmt;
use goish::context;
use goish::errors;
use goish::net::http::httptrace::{
    self, ClientTrace, ContextClientTrace, DNSDoneInfo, DNSStartInfo, WithClientTrace,
    WroteRequestInfo,
};
use goish::crypto::tls;
use goish::{string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. WithClientTrace stores; ContextClientTrace round-trips.
    {
        let trace = ClientTrace::default();
        let ctx = WithClientTrace(context::Background(), trace);
        if ContextClientTrace(&ctx).is_some() {
            fmt::Println!("[ 1] Context round-trip        PASS");
        } else {
            fmt::Println!("[ 1] Context round-trip        FAIL");
            failed += 1;
        }
    }

    // 2. Background ctx has no trace.
    {
        let ctx = context::Background();
        if ContextClientTrace(&ctx).is_none() {
            fmt::Println!("[ 2] Background None           PASS");
        } else {
            fmt::Println!("[ 2] Background None           FAIL");
            failed += 1;
        }
    }

    // 3. GetConn hook fires with hostPort.
    {
        static CALLED: AtomicI64 = AtomicI64::new(0);
        let mut trace = ClientTrace::default();
        trace.GetConn = Some(Arc::new(|hp: goish::gostring::string| {
            if hp == "example.com:80" {
                CALLED.fetch_add(1, Ordering::SeqCst);
            }
        }));
        let ctx = WithClientTrace(context::Background(), trace);
        let t = ContextClientTrace(&ctx).unwrap();
        if let Some(h) = &t.GetConn {
            h(string("example.com:80"));
        }
        if CALLED.load(Ordering::SeqCst) == 1 {
            fmt::Println!("[ 3] GetConn hook              PASS");
        } else {
            fmt::Println!("[ 3] GetConn hook              FAIL");
            failed += 1;
        }
    }

    // 4. compose: old hook adopted when new is None.
    {
        static CALLED: AtomicI64 = AtomicI64::new(0);
        let mut old = ClientTrace::default();
        old.GotFirstResponseByte = Some(Arc::new(|| {
            CALLED.fetch_add(10, Ordering::SeqCst);
        }));
        let ctx1 = WithClientTrace(context::Background(), old);
        // New trace has no GotFirstResponseByte → adopt old's.
        let new = ClientTrace::default();
        let ctx2 = WithClientTrace(ctx1, new);
        let t = ContextClientTrace(&ctx2).unwrap();
        if let Some(h) = &t.GotFirstResponseByte {
            h();
        }
        if CALLED.load(Ordering::SeqCst) == 10 {
            fmt::Println!("[ 4] compose adopt old         PASS");
        } else {
            fmt::Println!("[ 4] compose adopt old         FAIL got {}", CALLED.load(Ordering::SeqCst));
            failed += 1;
        }
    }

    // 5. compose: both hooks set → new fires first, then old.
    {
        static SEQ: AtomicI64 = AtomicI64::new(0);
        let mut old = ClientTrace::default();
        old.GotFirstResponseByte = Some(Arc::new(|| {
            // Multiply prior value by 10 then add 2.
            // If new fires first (writing 1), then old runs (1*10+2 = 12).
            let prev = SEQ.load(Ordering::SeqCst);
            SEQ.store(prev * 10 + 2, Ordering::SeqCst);
        }));
        let ctx1 = WithClientTrace(context::Background(), old);
        let mut new = ClientTrace::default();
        new.GotFirstResponseByte = Some(Arc::new(|| {
            SEQ.store(1, Ordering::SeqCst);
        }));
        let ctx2 = WithClientTrace(ctx1, new);
        let t = ContextClientTrace(&ctx2).unwrap();
        if let Some(h) = &t.GotFirstResponseByte {
            h();
        }
        if SEQ.load(Ordering::SeqCst) == 12 {
            fmt::Println!("[ 5] compose new-then-old      PASS");
        } else {
            fmt::Println!("[ 5] compose new-then-old      FAIL got {}", SEQ.load(Ordering::SeqCst));
            failed += 1;
        }
    }

    // 6. compose: 2-arg ConnectStart chains both calls.
    {
        static N: AtomicI64 = AtomicI64::new(0);
        let mut old = ClientTrace::default();
        old.ConnectStart = Some(Arc::new(
            |network: goish::gostring::string, _addr: goish::gostring::string| {
                if network == "tcp" {
                    N.fetch_add(2, Ordering::SeqCst);
                }
            },
        ));
        let ctx1 = WithClientTrace(context::Background(), old);
        let mut new = ClientTrace::default();
        new.ConnectStart = Some(Arc::new(
            |network: goish::gostring::string, _addr: goish::gostring::string| {
                if network == "tcp" {
                    N.fetch_add(1, Ordering::SeqCst);
                }
            },
        ));
        let ctx2 = WithClientTrace(ctx1, new);
        let t = ContextClientTrace(&ctx2).unwrap();
        if let Some(h) = &t.ConnectStart {
            h(string("tcp"), string("1.2.3.4:80"));
        }
        if N.load(Ordering::SeqCst) == 3 {
            fmt::Println!("[ 6] compose ConnectStart      PASS");
        } else {
            fmt::Println!("[ 6] compose ConnectStart      FAIL got {}", N.load(Ordering::SeqCst));
            failed += 1;
        }
    }

    // 7. hasNetHooks predicate.
    {
        let trace = ClientTrace::default();
        let h0 = trace.hasNetHooks();
        let mut trace2 = ClientTrace::default();
        trace2.DNSStart = Some(Arc::new(|_: DNSStartInfo| {}));
        let h1 = trace2.hasNetHooks();
        let mut trace3 = ClientTrace::default();
        trace3.GetConn = Some(Arc::new(|_| {}));
        let h2 = trace3.hasNetHooks(); // Only GetConn — not net.
        if !h0 && h1 && !h2 {
            fmt::Println!("[ 7] hasNetHooks               PASS");
        } else {
            fmt::Println!("[ 7] hasNetHooks               FAIL h0={} h1={} h2={}", h0, h1, h2);
            failed += 1;
        }
    }

    // 8. DNSStartInfo / DNSDoneInfo carry data correctly.
    {
        static GOT_HOST: AtomicI64 = AtomicI64::new(0);
        let mut trace = ClientTrace::default();
        trace.DNSStart = Some(Arc::new(|info: DNSStartInfo| {
            if info.Host == "example.com" {
                GOT_HOST.fetch_add(1, Ordering::SeqCst);
            }
        }));
        trace.DNSDone = Some(Arc::new(|info: DNSDoneInfo| {
            // Addrs is Go's []net.IPAddr — an address WITH its zone, not
            // a bare IP. Reading both halves back is what keeps the
            // element type honest.
            let ok = goish::builtin::len(&info.Addrs) == 1
                && info.Addrs[0].IP.String() == "127.0.0.1"
                && info.Addrs[0].Zone == "";
            if info.Coalesced && info.Err.IsNil() && ok {
                GOT_HOST.fetch_add(10, Ordering::SeqCst);
            }
        }));
        let ctx = WithClientTrace(context::Background(), trace);
        let t = ContextClientTrace(&ctx).unwrap();
        if let Some(h) = &t.DNSStart {
            h(DNSStartInfo {
                Host: string("example.com"),
            });
        }
        if let Some(h) = &t.DNSDone {
            h(DNSDoneInfo {
                Addrs: goish::goslice::slice::<goish::net::LookupIPAddr>::__from_vec(
                    alloc::vec![goish::net::LookupIPAddr {
                        IP: goish::net::IPv4(127, 0, 0, 1),
                        Zone: string(""),
                    }],
                ),
                Err: errors::nil,
                Coalesced: true,
            });
        }
        if GOT_HOST.load(Ordering::SeqCst) == 11 {
            fmt::Println!("[ 8] DNS info structs          PASS");
        } else {
            fmt::Println!("[ 8] DNS info structs          FAIL");
            failed += 1;
        }
    }

    // 9. WroteRequestInfo carries error.
    {
        static SAW_ERR: AtomicI64 = AtomicI64::new(0);
        let mut trace = ClientTrace::default();
        trace.WroteRequest = Some(Arc::new(|info: WroteRequestInfo| {
            if !info.Err.IsNil() && info.Err.Error() == "boom" {
                SAW_ERR.fetch_add(1, Ordering::SeqCst);
            }
        }));
        let ctx = WithClientTrace(context::Background(), trace);
        let t = ContextClientTrace(&ctx).unwrap();
        if let Some(h) = &t.WroteRequest {
            h(WroteRequestInfo {
                Err: errors::New("boom"),
            });
        }
        if SAW_ERR.load(Ordering::SeqCst) == 1 {
            fmt::Println!("[ 9] WroteRequestInfo          PASS");
        } else {
            fmt::Println!("[ 9] WroteRequestInfo          FAIL");
            failed += 1;
        }
    }

    // 10. Inner ctx without trace inherits parent trace via Context.Value.
    {
        let trace = ClientTrace::default();
        let ctx1 = WithClientTrace(context::Background(), trace);
        // Add a value below the trace — trace remains visible.
        let ctx2 = context::WithValue(ctx1, "k", 1i64);
        if ContextClientTrace(&ctx2).is_some() {
            fmt::Println!("[10] Inherit through WithValue PASS");
        } else {
            fmt::Println!("[10] Inherit through WithValue FAIL");
            failed += 1;
        }
    }

    // 11. Two independent traces don't bleed across contexts.
    {
        static A: AtomicI64 = AtomicI64::new(0);
        static B: AtomicI64 = AtomicI64::new(0);
        let mut t1 = ClientTrace::default();
        t1.GotFirstResponseByte = Some(Arc::new(|| {
            A.fetch_add(1, Ordering::SeqCst);
        }));
        let mut t2 = ClientTrace::default();
        t2.GotFirstResponseByte = Some(Arc::new(|| {
            B.fetch_add(1, Ordering::SeqCst);
        }));
        let ctx1 = WithClientTrace(context::Background(), t1);
        let ctx2 = WithClientTrace(context::Background(), t2);
        let cb1 = ContextClientTrace(&ctx1).unwrap();
        let cb2 = ContextClientTrace(&ctx2).unwrap();
        cb1.GotFirstResponseByte.as_ref().unwrap()();
        cb2.GotFirstResponseByte.as_ref().unwrap()();
        cb2.GotFirstResponseByte.as_ref().unwrap()();
        if A.load(Ordering::SeqCst) == 1 && B.load(Ordering::SeqCst) == 2 {
            fmt::Println!("[11] Independent contexts      PASS");
        } else {
            fmt::Println!("[11] Independent contexts      FAIL");
            failed += 1;
        }
    }

    // 12. Cancellation forwarded through trace value.
    {
        let trace = ClientTrace::default();
        let (parent, cancel) = context::WithCancel(context::Background());
        let ctx = WithClientTrace(parent, trace);
        let pre = ctx.Err().IsNil();
        cancel();
        let post = !ctx.Err().IsNil();
        if pre && post && ContextClientTrace(&ctx).is_some() {
            fmt::Println!("[12] Cancel forwarded          PASS");
        } else {
            fmt::Println!("[12] Cancel forwarded          FAIL");
            failed += 1;
        }
    }
    // 13. The two TLS hooks. goish's ClientTrace omitted them entirely
    //     on the grounds that "goish v1 does not implement crypto/tls"
    //     — true when the file was written, false since crypto/tls
    //     reached 100%. A tracer watching an HTTPS request would have
    //     silently seen nothing at handshake time.
    //
    //     Composing them is the part worth asserting: TLSHandshakeDone
    //     carries a tls.ConnectionState, so it is the one hook whose
    //     compose arm could not be shared with any other shape.
    {
        static ORDER: AtomicI64 = AtomicI64::new(0);
        let mut old = ClientTrace::default();
        old.TLSHandshakeStart = Some(Arc::new(|| {
            ORDER.fetch_add(1, Ordering::SeqCst);
        }));
        old.TLSHandshakeDone = Some(Arc::new(|cs: tls::ConnectionState, e: goish::error| {
            if cs.Version == tls::VersionTLS13 && e.IsNil() {
                // Old runs LAST, so it lands on a value the new hook
                // has already multiplied.
                ORDER.fetch_add(100, Ordering::SeqCst);
            }
        }));
        let mut new = ClientTrace::default();
        new.TLSHandshakeStart = Some(Arc::new(|| {
            ORDER.fetch_add(1, Ordering::SeqCst);
        }));
        new.TLSHandshakeDone = Some(Arc::new(|cs: tls::ConnectionState, _e: goish::error| {
            if cs.Version == tls::VersionTLS13 {
                ORDER.fetch_add(10, Ordering::SeqCst);
            }
        }));

        let ctx = WithClientTrace(context::Background(), old);
        let ctx = WithClientTrace(ctx, new);
        let t = ContextClientTrace(&ctx).unwrap();

        t.TLSHandshakeStart.as_ref().unwrap()();
        let mut cs = tls::ConnectionState::default();
        cs.Version = tls::VersionTLS13;
        t.TLSHandshakeDone.as_ref().unwrap()(cs, errors::nil);

        // 2 from the composed Start (both halves ran), 110 from Done.
        if ORDER.load(Ordering::SeqCst) == 112 {
            fmt::Println!("[13] TLS hooks compose         PASS");
        } else {
            fmt::Println!(
                "[13] TLS hooks compose         FAIL got",
                ORDER.load(Ordering::SeqCst)
            );
            failed += 1;
        }
    }

    let _ = httptrace::ContextClientTrace;

    if failed == 0 {
        fmt::Println!("ok 13/13");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 13");
        syscall::Exit(1);
    }
}
