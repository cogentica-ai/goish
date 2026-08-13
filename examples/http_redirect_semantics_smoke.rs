// Client redirect semantics against Go 1.25.5.
// Expected values from a goref run using real httptest servers.
//
//   POST + 301/302/303 -> GET, body DROPPED
//   POST + 307/308     -> POST, body PRESERVED
//   loop               -> 10 hops, then "stopped after 10 redirects"
//
// Go's rule for 301/302/303 is "any method that is not GET or HEAD
// becomes GET" (redirectBehavior). A port that special-cases only
// POST and PUT passes the common cases and leaves DELETE/PATCH
// unconverted, which is why DELETE is tested here explicitly.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use goish::net::http;
use goish::{errors, fmt, net, string, sync, syscall, types::int};

static METHOD: sync::Mutex<alloc::vec::Vec<u8>> = sync::Mutex::new(alloc::vec::Vec::new());
static BODY: sync::Mutex<alloc::vec::Vec<u8>> = sync::Mutex::new(alloc::vec::Vec::new());
static HOPS: sync::Mutex<int> = sync::Mutex::new(0);

fn serve(h: Arc<dyn http::Handler>) -> string {
    let (ln, e) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    if e != errors::nil {
        fmt::Println!("listen: ", e.Error());
        syscall::Exit(1);
    }
    let addr = ln.Addr().String();
    goish::go!(stack(512 * 1024), move || {
        let _ = http::Serve(ln, h);
    });
    return string("http://") + addr;
}

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
        mux.HandleFunc(string("/dst"), |_w, r| {
            *METHOD.Lock() = r.Method.as_bytes().to_vec();
            *BODY.Lock() = (&*r.Body).to_vec();
        });
        for code in [301, 302, 303, 307, 308].iter() {
            let c = *code;
            mux.HandleFunc(
                string("/src") + goish::fmt::Sprintf!("%d", c),
                move |w, r| {
                    http::Redirect(w, r, string("/dst"), c);
                },
            );
        }
        let url = serve(Arc::new(mux) as Arc<dyn http::Handler>);
        let cl = http::Client::default();

        // POST + each redirect code.
        let cases: [(int, &str, &str); 5] = [
            (301, "GET", ""),
            (302, "GET", ""),
            (303, "GET", ""),
            (307, "POST", "hello"),
            (308, "POST", "hello"),
        ];
        for (code, wantMethod, wantBody) in cases.iter() {
            *METHOD.Lock() = alloc::vec::Vec::new();
            *BODY.Lock() = alloc::vec::Vec::new();
            let (mut req, _) = http::NewRequest(
                string("POST"),
                url.clone() + string("/src") + goish::fmt::Sprintf!("%d", *code),
                goish::slice::<u8>::__from_vec(b"hello".to_vec()),
            );
            req.Header.Set(string("Content-Type"), string("text/plain"));
            let (_, err) = cl.Do(&req);
            if err != errors::nil {
                fmt::Println!("FAIL POST+", *code, ": ", err.Error());
                bad += 1;
                continue;
            }
            eq(string::from_bytes(&METHOD.Lock()[..]), wantMethod, "redirect method", &mut bad);
            eq(string::from_bytes(&BODY.Lock()[..]), wantBody, "redirect body", &mut bad);
        }

        // DELETE + 302 must also become GET.
        {
            *METHOD.Lock() = alloc::vec::Vec::new();
            let (req, _) = http::NewRequest(
                string("DELETE"),
                url.clone() + string("/src302"),
                goish::nil,
            );
            let (_, err) = cl.Do(&req);
            if err != errors::nil {
                fmt::Println!("FAIL DELETE+302: ", err.Error());
                bad += 1;
            }
            eq(
                string::from_bytes(&METHOD.Lock()[..]),
                "GET",
                "DELETE + 302 becomes GET",
                &mut bad,
            );
        }

        // Redirect loop: 10 hops, then an error.
        {
            let loopMux = http::ServeMux::new();
            loopMux.HandleFunc(string("/"), |w, r| {
                let mut h = HOPS.Lock();
                *h += 1;
                let n = *h;
                drop(h);
                http::Redirect(w, r, goish::fmt::Sprintf!("/%d", n), 302);
            });
            let lurl = serve(Arc::new(loopMux) as Arc<dyn http::Handler>);
            let (_, err) = cl.Get(lurl);
            if err == errors::nil {
                fmt::Println!("FAIL redirect loop: expected an error");
                bad += 1;
            }
            let hops = *HOPS.Lock();
            if hops != 10 {
                fmt::Println!("FAIL redirect loop hops: ", hops, " want 10");
                bad += 1;
            }
        }

        if bad == 0 {
            fmt::Println!("REDIRECT_SEMANTICS_OK 13/13");
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
