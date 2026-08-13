// Client.Jar against Go 1.25.5. Expected values from a goref run.
//
//   before login -> Cookie=""
//   after login  -> Cookie="sid=abc"
//   through 302  -> Cookie="sid=abc; hop=1"
//   no jar       -> Cookie=""
//
// The third case is the one worth having. A cookie set BY the 302
// response must be stored and then sent on the redirected request —
// that is what makes a login-then-redirect flow work at all, and it
// only happens if the jar is consulted on every hop rather than once
// per Do.
//
// goish's cookiejar package was fully ported and unreachable until
// Client grew a Jar field.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use goish::net::http;
use goish::net::http::cookiejar;
use goish::{errors, fmt, net, string, sync, syscall};

static SEEN: sync::Mutex<alloc::vec::Vec<u8>> = sync::Mutex::new(alloc::vec::Vec::new());

fn record(r: &http::Request) {
    *SEEN.Lock() = r.Header.Get(string("Cookie")).as_bytes().to_vec();
}

fn seen() -> string {
    return string::from_bytes(&SEEN.Lock()[..]);
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
        mux.HandleFunc(string("/login"), |w, _r| {
            let mut c = http::Cookie::default();
            c.Name = string("sid");
            c.Value = string("abc");
            c.Path = string("/");
            http::SetCookie(w, &c);
            w.WriteHeader(200);
        });
        mux.HandleFunc(string("/redir"), |w, r| {
            let mut c = http::Cookie::default();
            c.Name = string("hop");
            c.Value = string("1");
            c.Path = string("/");
            http::SetCookie(w, &c);
            http::Redirect(w, r, string("/after"), 302);
        });
        mux.HandleFunc(string("/after"), |_w, r| record(r));
        mux.HandleFunc(string("/check"), |_w, r| record(r));

        let (ln, e) = net::Listen(string("tcp"), string("127.0.0.1:0"));
        if e != errors::nil {
            fmt::Println!("listen: ", e.Error());
            syscall::Exit(1);
        }
        let url = string("http://") + ln.Addr().String();
        goish::go!(stack(512 * 1024), move || {
            let _ = http::Serve(ln, Arc::new(mux) as Arc<dyn http::Handler>);
        });

        let (jar, _) = cookiejar::New(None);
        let mut c = http::Client::default();
        c.Jar = Some(jar as Arc<dyn http::CookieJar>);

        let (_, _) = c.Get(url.clone() + string("/check"));
        eq(seen(), "", "before login", &mut bad);

        let (_, _) = c.Get(url.clone() + string("/login"));
        let (_, _) = c.Get(url.clone() + string("/check"));
        eq(seen(), "sid=abc", "after login", &mut bad);

        // A cookie set BY the 302 must reach the redirected request.
        let (_, _) = c.Get(url.clone() + string("/redir"));
        eq(seen(), "sid=abc; hop=1", "cookie set through a 302", &mut bad);

        // A client with no jar sends nothing.
        let c2 = http::Client::default();
        let (_, _) = c2.Get(url.clone() + string("/login"));
        let (_, _) = c2.Get(url.clone() + string("/check"));
        eq(seen(), "", "no jar", &mut bad);

        if bad == 0 {
            fmt::Println!("CLIENT_JAR_OK 4/4");
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
