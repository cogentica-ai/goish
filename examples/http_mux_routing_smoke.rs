// ServeMux routing against Go 1.25.5. Expected values from a goref run
// driving a real mux with eight patterns registered together.
//
// The cases that matter, beyond plain matching:
//   /m with GET      -> falls back to "/", NOT 405, because a bare "/"
//                       catch-all is registered
//   /a               -> 301 to "/a/", the trailing-slash redirect
//   //double         -> 301 to "/double", cleanPath collapsing slashes
//   /a/./b           -> 301 to "/a/b", dot-segment cleaning
//   /a/zzz           -> "/a/" subtree, not "/a/b"
//   /p/1/c           -> "/p/{x}/c" beats "/p/{x}" on specificity
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use goish::net::http;
use goish::net::http::httptest;
use goish::{fmt, string, syscall, types::int};

fn eq(got: string, want: &str, what: &str, bad: &mut i32) {
    if got != want {
        fmt::Println!("FAIL ", what, ": got ", got, " want ", want);
        *bad += 1;
    }
}

#[goish::main]
fn main() {
    goish::go!(stack(512 * 1024), move || {
        let mut bad = 0i32;
        let mux = http::ServeMux::new();
        for p in [
            "/", "/a/", "/a/b", "/p/{x}", "/p/{x}/c", "POST /m", "/exact",
            "/tree/{rest...}",
        ]
        .iter()
        {
            let pp = string(*p);
            mux.HandleFunc(string(*p), move |w, _r| {
                w.Header().Set(string("X-Pat"), pp.clone());
                w.WriteHeader(200);
            });
        }
        let mux: Arc<dyn http::Handler> = Arc::new(mux);

        // (method, path, code, pattern, location)
        let cases: [(&str, &str, int, &str, &str); 14] = [
            ("GET", "/", 200, "/", ""),
            ("GET", "/a/", 200, "/a/", ""),
            ("GET", "/a/b", 200, "/a/b", ""),
            ("GET", "/a/zzz", 200, "/a/", ""),
            ("GET", "/p/1", 200, "/p/{x}", ""),
            ("GET", "/p/1/c", 200, "/p/{x}/c", ""),
            ("GET", "/m", 200, "/", ""),
            ("POST", "/m", 200, "POST /m", ""),
            ("GET", "/exact", 200, "/exact", ""),
            ("GET", "/tree/x/y", 200, "/tree/{rest...}", ""),
            ("GET", "/nope", 200, "/", ""),
            ("GET", "/a", 301, "", "/a/"),
            ("GET", "//double", 301, "", "/double"),
            ("GET", "/a/./b", 301, "", "/a/b"),
        ];

        for (method, path, code, pat, loc) in cases.iter() {
            let (req, err) = http::NewRequest(
                string(*method),
                string("http://x") + string(*path),
                goish::nil,
            );
            if err != goish::errors::nil {
                fmt::Println!("FAIL NewRequest ", *path, ": ", err.Error());
                bad += 1;
                continue;
            }
            let rec = httptest::NewRecorder();
            mux.ServeHTTP(&rec, &req);
            let res = rec.Result();
            if res.StatusCode != *code {
                fmt::Println!("FAIL ", *method, " ", *path, ": code ", res.StatusCode, " want ", *code);
                bad += 1;
            }
            eq(res.Header.Get(string("X-Pat")), pat, *path, &mut bad);
            eq(res.Header.Get(string("Location")), loc, *path, &mut bad);
        }

        if bad == 0 {
            fmt::Println!("MUX_ROUTING_OK 14/14");
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
