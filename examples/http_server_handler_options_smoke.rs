// http_server_handler_options_smoke — serverHandler's "OPTIONS *"
// dispatch (net/http/server.go:3331) and the Request.RequestURI /
// Server.DisableGeneralOptionsHandler fields it reads.
//
// Values are Go 1.25.5 output via scripts/goref.sh net/http.
//
// The detail that makes this worth a test: the check reads
// `req.RequestURI`, NOT `req.URL.Path`. A request-target of "*" is not
// a path — it does not survive URL parsing — so a check written
// against URL.Path would never fire and every "OPTIONS *" would reach
// the user's handler. RequestURI exists precisely to keep the
// unmodified target, and goish had no such field before this.
//
// All three negative cases must reach the user handler: OPTIONS with a
// real path, GET with target "*", and OPTIONS * when the server has
// opted out via DisableGeneralOptionsHandler.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use goish::net::http;
use goish::net::http::httptest;
use goish::net::http::responsewriter::ResponseWriter;
use goish::net::http::server::{serverHandler, Handler, Server};
use goish::{convert, fmt, string, syscall};

fn mine(w: &(dyn ResponseWriter + Send + Sync + 'static), _r: &http::Request) {
    let _ = w.Write(convert::bytes(string("mine")));
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // (disable, method, requestURI, wantContentLength, wantBody)
    let cases: &[(bool, &'static str, &'static str, &str, &str)] = &[
        (false, "OPTIONS", "*", "0", ""),
        (true, "OPTIONS", "*", "", "mine"),
        (false, "OPTIONS", "/p", "", "mine"),
        (false, "GET", "*", "", "mine"),
    ];

    let mut bad = 0;
    for (disable, method, uri, wantCL, wantBody) in cases {
        let mut srv = Server::default();
        srv.Handler = Arc::new(http::HandlerFunc(mine)) as Arc<dyn Handler>;
        srv.DisableGeneralOptionsHandler = *disable;
        let sh = serverHandler { srv: Arc::new(srv) };

        let (mut req, _) = http::NewRequest(string(*method), string("http://e.com/"), goish::nil);
        req.RequestURI = string(*uri);

        let rec = httptest::NewRecorder();
        {
            let w: &(dyn ResponseWriter + Send + Sync + 'static) = &rec;
            Handler::ServeHTTP(&sh, w, &req);
        }
        let body = string::from_bytes(&rec.Body());
        let cl = rec.Header().Get(string("Content-Length"));
        if body != *wantBody || cl != *wantCL {
            fmt::Println!(
                "     disable=", *disable, " ", *method, " ", *uri,
                " -> cl=", cl, " body=", body
            );
            bad += 1;
        }
    }

    if bad == 0 {
        fmt::Println!("[1] OPTIONS * reads RequestURI, not URL.Path  PASS");
    } else {
        fmt::Println!("[1] serverHandler dispatch  FAIL");
        failed += 1;
    }

    if failed == 0 {
        fmt::Println!("ok 1/1");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL ", failed, " of 1");
        syscall::Exit(1);
    }
}
