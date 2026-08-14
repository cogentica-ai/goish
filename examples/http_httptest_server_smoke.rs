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
    goish::go!(stack(4 * 1024 * 1024), move || {
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

        // ── NewTLSServer: a real HTTPS httptest server ──
        {
            let mux2 = goish::net::http::ServeMux::new();
            mux2.HandleFunc("/tls", |w, _r| {
                let _ = w.Write(goish::bytes("secure"));
            });
            let ts2 = goish::net::http::httptest::NewTLSServer(
                alloc::sync::Arc::new(mux2),
            );
            goish::time::Sleep(goish::time::Duration(200 * 1_000_000));
            let u = ts2.URL();
            let us: &str = u.as_ref();
            if us.starts_with("https://") && ts2.Certificate().is_some() {
                ok += 1;
            } else {
                goish::fmt::Println!("FAIL tls url/cert: ", u.clone());
            }
            let cfg = goish::crypto::tls::Config {
                InsecureSkipVerify: true,
                ServerName: goish::string("localhost"),
                ..Default::default()
            };
            let addr = goish::string::from_bytes(
                us.trim_start_matches("https://").as_bytes(),
            );
            let (mut c, e) = goish::crypto::tls::Dial(goish::string("tcp"), addr, &cfg);
            let mut got = goish::string("");
            if e.IsNil() {
                let _ = goish::io::Writer::Write(
                    &mut c,
                    goish::slice::<goish::byte>::__from_vec(
                        b"GET /tls HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                            .to_vec(),
                    ),
                );
                let mut buf = goish::make!([]goish::byte, 4096);
                let (n, _) = goish::io::Reader::Read(&mut c, &mut buf);
                let mut v: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
                for i in 0..n {
                    v.push(buf[i]);
                }
                got = goish::string::from_bytes(&v);
                let _ = goish::io::Closer::Close(&mut c);
            }
            let gs: &str = got.as_ref();
            if gs.contains("secure") {
                ok += 1;
            } else {
                goish::fmt::Println!("FAIL tls body: ", got.clone());
            }
            ts2.Close();
        }

        goish::fmt::Println!("HTTPTEST_SERVER_OK ", ok, "/8");
        goish::syscall::Exit(if ok == 8 { 0 } else { 1 });
    });

    // Park main until the client goroutine has exited(0)/exited(1).
    loop {
        goish::runtime::sched::Gosched();
    }
}
