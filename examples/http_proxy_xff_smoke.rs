// The reverse proxy must APPEND the real peer to X-Forwarded-For.
//
// Expected values from a goref run against Go's
// NewSingleHostReverseProxy:
//
//   client sends nothing     -> "127.0.0.1"
//   client sends "1.2.3.4"   -> "1.2.3.4, 127.0.0.1"
//
// The second case is the point. goish previously copied the inbound
// header VERBATIM and appended nothing, so a client could claim any
// address and the backend saw exactly that. Go appends the real peer
// last, which is what makes the FINAL entry trustworthy regardless of
// what the client asserted.
//
// Plain listeners rather than httptest, so this isolates the proxy.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use goish::net::http;
use goish::net::http::httputil;
use goish::net::http::url;
use goish::{errors, fmt, net, string, sync, syscall};

static SEEN: sync::Mutex<alloc::vec::Vec<u8>> = sync::Mutex::new(alloc::vec::Vec::new());

struct Backend;
impl http::Handler for Backend {
    fn ServeHTTP(&self, w: &(dyn http::ResponseWriter + Send + Sync + 'static), r: &http::Request) {
        *SEEN.Lock() = r.Header.Get(string("X-Forwarded-For")).as_bytes().to_vec();
        let _ = w.Write(goish::slice::<u8>::__from_vec(b"ok".to_vec()));
    }
}

fn eq(got: string, want: &str, what: &str, bad: &mut i32) {
    if got != want {
        fmt::Println!("FAIL ", what, ": got ", got, " want ", want);
        *bad += 1;
    }
}

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

#[goish::main]
fn main() {
    goish::go!(stack(512 * 1024), move || {
        let mut bad = 0i32;

        let backURL = serve(Arc::new(Backend) as Arc<dyn http::Handler>);
        let (target, _) = url::Parse(backURL);
        let frontURL = serve(httputil::NewSingleHostReverseProxy(target));

        let c = http::Client::default();

        // 1. client sends no X-Forwarded-For.
        let (_, err) = c.Get(frontURL.clone() + string("/"));
        if err != errors::nil {
            fmt::Println!("FAIL plain GET: ", err.Error());
            bad += 1;
        }
        eq(
            string::from_bytes(&SEEN.Lock()[..]),
            "127.0.0.1",
            "no client XFF",
            &mut bad,
        );

        // 2. client SPOOFS an X-Forwarded-For — the real peer must
        //    still be appended after it.
        let (mut req, _) =
            http::NewRequest(string("GET"), frontURL.clone() + string("/"), goish::nil);
        req.Header.Set(string("X-Forwarded-For"), string("1.2.3.4"));
        let (_, err2) = c.Do(&req);
        if err2 != errors::nil {
            fmt::Println!("FAIL spoofed GET: ", err2.Error());
            bad += 1;
        }
        eq(
            string::from_bytes(&SEEN.Lock()[..]),
            "1.2.3.4, 127.0.0.1",
            "client spoofed XFF",
            &mut bad,
        );

        if bad == 0 {
            fmt::Println!("PROXY_XFF_OK 4/4");
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
