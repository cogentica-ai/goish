// httptest_recorder_smoke — net/http/httptest/recorder.go.
//
// httptest.rs said ResponseRecorder was "blocked on the ResponseWriter
// trait refactor". That refactor landed; this is the recorder.
//
// Every expectation below is a live go1.25.5 run of the same seven
// handlers through httptest.NewRecorder, not a reading of the docs:
//
//   plain          Code=200 Status="200 OK" CT="text/plain; charset=utf-8" CL=-1 Flushed=false Body="hello"
//   html-sniff     Code=200 CT="text/html; charset=utf-8"
//   explicit-ct    Code=201 Status="201 Created" CT="application/json"
//   no-write       Code=200 CT="" Body=""
//   flush          Code=200 Flushed=true
//   content-length CL=5
//   trailer        Trailer=map[X-Sum:[42]]
//
// The two that carry the most weight:
//
//   * `no-write` — a handler that writes NOTHING still reports 200 and
//     an EMPTY Content-Type. Sniffing on an empty body would give
//     "text/plain; charset=utf-8", and seeding Code to 0 would report
//     0; Go seeds 200 and only sniffs from writeHeader.
//   * `trailer` — "Authorization" is announced in the Trailer header
//     and is DROPPED from the result, while "X-Sum" survives. That is
//     RFC 7230 §4.1.2's forbidden-trailer list, which lives in
//     httpguts and is relocated into recorder.rs. A recorder that
//     copied every announced name would look right until someone
//     leaked a credential into a trailer.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::gostring::string as gostring;
use goish::net::http::httptest::NewRecorder;
use goish::net::http::responsewriter::{Flusher, ResponseWriter};
use goish::{string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;
    let mut n = 1;

    let mut check = |label: &'static str, ok: bool, got: gostring| {
        if ok {
            fmt::Println!("[", n, "] ", label, "  PASS");
        } else {
            fmt::Println!("[", n, "] ", label, "  FAIL got=", got);
            failed += 1;
        }
        n += 1;
    };

    // 1. A plain write: implicit 200, sniffed text/plain, unknown length.
    {
        let rec = NewRecorder();
        let _ = rec.Write(goish::convert::bytes(string("hello")));
        let res = rec.Result();
        let ct = res.Header.Get(string("Content-Type"));
        let ok = rec.Code() == 200
            && res.Status == "200 OK"
            && ct == "text/plain; charset=utf-8"
            && res.ContentLength == -1
            && !rec.Flushed()
            && rec.Body() == goish::convert::bytes(string("hello"));
        check("plain write", ok, ct);
    }

    // 2. Content-Type is SNIFFED from the body, not assumed.
    {
        let rec = NewRecorder();
        let _ = rec.Write(goish::convert::bytes(string("<html>hi</html>")));
        let ct = rec.Result().Header.Get(string("Content-Type"));
        check("html sniffed", ct == "text/html; charset=utf-8", ct);
    }

    // 3. An explicit Content-Type wins, and WriteHeader's code sticks.
    {
        let rec = NewRecorder();
        rec.Header()
            .Set(string("Content-Type"), string("application/json"));
        rec.WriteHeader(201);
        let _ = rec.Write(goish::convert::bytes(string("{\"a\":1}")));
        let res = rec.Result();
        let ct = res.Header.Get(string("Content-Type"));
        let ok = rec.Code() == 201 && res.Status == "201 Created" && ct == "application/json";
        check("explicit ct + 201", ok, res.Status.clone());
    }

    // 4. A handler that writes nothing: 200, and NO Content-Type.
    //    Sniffing an empty body would have produced text/plain.
    {
        let rec = NewRecorder();
        let res = rec.Result();
        let ct = res.Header.Get(string("Content-Type"));
        let ok = rec.Code() == 200
            && res.Status == "200 OK"
            && ct == ""
            && goish::builtin::len(&rec.Body()) == 0;
        check("no write -> 200, no ct", ok, ct);
    }

    // 5. Flush records itself and implies a 200.
    {
        let rec = NewRecorder();
        rec.Flush();
        let ok = rec.Flushed() && rec.Code() == 200;
        check("flush recorded", ok, string(""));
    }

    // 6. A Content-Length the handler set is parsed onto the Response.
    {
        let rec = NewRecorder();
        rec.Header().Set(string("Content-Length"), string("5"));
        let _ = rec.Write(goish::convert::bytes(string("abcde")));
        let cl = rec.Result().ContentLength;
        check("content-length parsed", cl == 5, string(""));
    }

    // 7. Announced trailers are filtered by RFC 7230's forbidden list:
    //    X-Sum survives, Authorization does not.
    {
        let rec = NewRecorder();
        rec.Header()
            .Set(string("Trailer"), string("X-Sum, Authorization"));
        let _ = rec.Write(goish::convert::bytes(string("body")));
        rec.Header().Set(string("X-Sum"), string("42"));
        rec.Header().Set(string("Authorization"), string("secret"));
        let res = rec.Result();
        let sum = res.Trailer.Get(string("X-Sum"));
        let auth = res.Trailer.Get(string("Authorization"));
        check("trailer filtered", sum == "42" && auth == "", sum.clone());
    }

    // 8. Result is cached — Go returns the same *Response on a second
    //    call, so a later header write must not change it.
    {
        let rec = NewRecorder();
        let _ = rec.Write(goish::convert::bytes(string("x")));
        let first = rec.Result();
        rec.Header().Set(string("X-Late"), string("nope"));
        let second = rec.Result();
        let ok = first.Status == second.Status && second.Header.Get(string("X-Late")) == "";
        check("Result is cached", ok, second.Header.Get(string("X-Late")));
    }

    drop(check);
    if failed == 0 {
        fmt::Println!("ok 8/8");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 8");
        syscall::Exit(1);
    }
}
