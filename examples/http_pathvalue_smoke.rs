// Request.PathValue / SetPathValue against Go 1.25.5.
//
// Expected values from a goref run driving a real ServeMux.
//
// goish stores path values in a map<string,string>; Go keeps the
// matched pattern plus a positional []string and resolves names with
// the unexported patIndex. That is a deliberate data-structure
// divergence, so what matters is that the OBSERVABLE behaviour is
// identical — which is what this pins:
//
//   named wildcard      -> its matched segment
//   unknown name        -> ""
//   empty name          -> ""
//   multi wildcard {r...} -> the whole remaining path, slashes intact
//   {$} (end-of-path)   -> NOT addressable; PathValue("$") is ""
//   SetPathValue        -> readable back, even for a name not in the pattern
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicI32, Ordering};
use goish::net::http;
use goish::{fmt, string, syscall};

static BAD: AtomicI32 = AtomicI32::new(0);
static RAN: AtomicI32 = AtomicI32::new(0);

fn want(got: string, w: &str, what: &str) {
    if got != w {
        fmt::Println!("FAIL ", what, ": got ", got, " want ", w);
        BAD.fetch_add(1, Ordering::SeqCst);
    }
}

#[goish::main]
fn main() {
    goish::go!(stack(256 * 1024), move || {
        let mux = http::ServeMux::new();

        mux.HandleFunc(string("/a/{b}"), |_w, r| {
            want(r.PathValue(string("b")), "x", "single wildcard");
            want(r.PathValue(string("nope")), "", "unknown name");
            want(r.PathValue(string("")), "", "empty name");
            RAN.fetch_add(1, Ordering::SeqCst);
        });
        mux.HandleFunc(string("/m/{b}/c/{d}"), |_w, r| {
            want(r.PathValue(string("b")), "x", "multi-segment b");
            want(r.PathValue(string("d")), "y", "multi-segment d");
            RAN.fetch_add(1, Ordering::SeqCst);
        });
        mux.HandleFunc(string("/f/{rest...}"), |_w, r| {
            want(r.PathValue(string("rest")), "x/y/z", "multi wildcard");
            RAN.fetch_add(1, Ordering::SeqCst);
        });
        mux.HandleFunc(string("/only/{$}"), |_w, r| {
            // Go: {$} is an end-of-path marker, NOT a named wildcard.
            want(r.PathValue(string("$")), "", "{$} is not addressable");
            RAN.fetch_add(1, Ordering::SeqCst);
        });

        let mux: Arc<dyn http::Handler> = Arc::new(mux);
        for p in ["/a/x", "/m/x/c/y", "/f/x/y/z", "/only/"].iter() {
            let (req, err) =
                http::NewRequest(string("GET"), string("http://x") + string(*p), goish::nil);
            if err != goish::errors::nil {
                fmt::Println!("FAIL NewRequest ", *p, ": ", err.Error());
                BAD.fetch_add(1, Ordering::SeqCst);
                continue;
            }
            let rec = http::httptest::NewRecorder();
            mux.ServeHTTP(&rec, &req);
        }

        // SetPathValue works for a name the pattern never declared.
        {
            let (mut req, _) = http::NewRequest(string("GET"), string("http://x/a/x"), goish::nil);
            req.SetPathValue(string("injected"), string("zzz"));
            want(
                req.PathValue(string("injected")),
                "zzz",
                "SetPathValue round-trip",
            );
        }

        let ran = RAN.load(Ordering::SeqCst);
        if ran != 4 {
            fmt::Println!("FAIL handlers run: ", ran, " want 4");
            BAD.fetch_add(1, Ordering::SeqCst);
        }

        let bad = BAD.load(Ordering::SeqCst);
        if bad == 0 {
            fmt::Println!("PATHVALUE_OK 9/9");
            syscall::Exit(0);
        } else {
            fmt::Println!("FAILED ", bad);
            syscall::Exit(1);
        }
    });
    loop {
        goish::runtime::sched::Gosched();
    }
}
