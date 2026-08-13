// TimeoutHandler against Go 1.25.5. Expected values from a goref run.
//
// Three observables:
//   handler finishes in time -> its own status, headers and body pass through
//   handler overruns, empty msg -> 503 and Go's DEFAULT HTML body
//   handler overruns, custom msg -> 503 and that message
//
// The default body is a specific string Go hard-codes; a port that
// invented its own wording would look fine in a browser and differ on
// the wire.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::net::http;
use goish::net::http::httptest;
use goish::{fmt, string, syscall, time};

const DEFAULT_BODY: &str =
    "<html><head><title>Timeout</title></head><body><h1>Timeout</h1></body></html>";

struct Slow(time::Duration);

impl http::Handler for Slow {
    fn ServeHTTP(
        &self,
        w: &(dyn http::ResponseWriter + Send + Sync + 'static),
        _r: &http::Request,
    ) {
        if self.0 > time::Duration(0) {
            time::Sleep(self.0);
        }
        w.Header().Set(string("X-Inner"), string("yes"));
        w.WriteHeader(201);
        let _ = w.Write(goish::slice::<u8>::__from_vec(b"inner body".to_vec()));
    }
}

fn drive(dt: time::Duration, msg: &'static str, sleep: time::Duration) -> (goish::types::int, string) {
    let th = http::TimeoutHandler(Slow(sleep), dt, string(msg));
    let rec = httptest::NewRecorder();
    let (req, _) = http::NewRequest(string("GET"), string("http://x/"), goish::nil);
    th.ServeHTTP(&rec, &req);
    let res = rec.Result();
    return (res.StatusCode, string::from_bytes(&rec.Body()));
}

fn eq(got: (goish::types::int, string), code: goish::types::int, body: &str, what: &str, bad: &mut i32) {
    if got.0 != code || got.1 != body {
        fmt::Println!("FAIL ", what);
        fmt::Println!("  got  code=", got.0, " body=", got.1);
        fmt::Println!("  want code=", code, " body=", body);
        *bad += 1;
    }
}

#[goish::main]
fn main() {
    goish::go!(stack(512 * 1024), move || {
        let mut bad = 0i32;
        let ms = |n: i64| time::Duration(n * 1_000_000);

        eq(drive(ms(500), "", ms(0)), 201, "inner body", "fast passes through", &mut bad);
        eq(drive(ms(30), "", ms(300)), 503, DEFAULT_BODY, "timeout default body", &mut bad);
        eq(drive(ms(30), "too slow", ms(300)), 503, "too slow", "timeout custom msg", &mut bad);

        if bad == 0 {
            fmt::Println!("TIMEOUTHANDLER_OK 3/3");
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
