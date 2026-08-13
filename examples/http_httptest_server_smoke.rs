// httptest.Server — the in-process end-to-end test server.
//
// Drives a real socket: NewServer picks a loopback port, Client()
// fetches Server.URL, and Close() blocks until the serve loop exits.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
use alloc::sync::Arc;
use goish::net::http;
use goish::net::http::httptest;
use goish::string;

struct H;
impl http::Handler for H {
    fn ServeHTTP(&self, w: &(dyn http::ResponseWriter + Send + Sync + 'static), r: &http::Request) {
        w.Header().Set(string("X-Echo"), r.URL.Path.clone());
        w.WriteHeader(http::StatusTeapot);
        let _ = w.Write(goish::slice::<u8>::__from_vec(b"hi from httptest".to_vec()));
    }
}

fn check(cond: bool, what: &str, n: &mut i32) {
    if cond {
        *n += 1;
    } else {
        goish::fmt::Println!("FAIL: ", what);
    }
}

#[goish::main]
fn main() {
    goish::go!(stack(256 * 1024), move || {
        let mut ok = 0i32;

        let ts = httptest::NewServer(Arc::new(H) as Arc<dyn http::Handler>);

        // Start assigned a loopback URL.
        let url = ts.URL();
        check(
            goish::strings::HasPrefix(url.clone(), string("http://127.0.0.1:")),
            "URL has loopback prefix",
            &mut ok,
        );

        // The server actually answers on it.
        let c = ts.Client();
        let (resp, err) = c.Get(goish::fmt::Sprintf!("%s/abc", url));
        check(err == goish::nil, "Get returned no error", &mut ok);
        if err == goish::nil {
            check(resp.StatusCode == http::StatusTeapot, "status 418", &mut ok);
            check(
                resp.Header.Get(string("X-Echo")) == "/abc",
                "handler saw the path",
                &mut ok,
            );
            check(
                {
                    let (b, _) = goish::io::ReadAll(&mut resp.Body.clone());
                    goish::string::from_bytes(&b) == "hi from httptest"
                },
                "body round-tripped",
                &mut ok,
            );
        }

        // Close is idempotent and returns.
        ts.clone().Close();
        ts.Close();
        ok += 1;

        goish::fmt::Println!("HTTPTEST_SERVER_OK ", ok, "/6");
        goish::syscall::Exit(if ok == 6 { 0 } else { 1 });
    });

    // Park main until the client goroutine has exited(0)/exited(1).
    loop {
        goish::runtime::sched::Gosched();
    }
}
