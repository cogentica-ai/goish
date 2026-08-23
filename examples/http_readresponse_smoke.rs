// ReadResponse — parsing a response off the wire, against Go 1.25.5.
// Expected values from a goref run of the real http.ReadResponse.
//
// Nine cases covering the framing decisions:
//   Content-Length body
//   204 / 304 — no body regardless of what follows
//   chunked   — ContentLength becomes -1, TransferEncoding [chunked]
//   HTTP/1.0 with no CL — body runs to EOF and Close is TRUE
//   Connection: close with a CL — Close true, CL still honoured
//   a non-standard status code keeps its reason phrase verbatim
//   a non-numeric status code is an ERROR, not a 0
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::net::http;
use goish::{bufio, bytes, errors, fmt, io, string, syscall};

fn parse(raw: &'static str) -> string {
    let mut br = bufio::NewReader(bytes::NewReader(goish::slice::<u8>::__from_vec(
        raw.as_bytes().to_vec(),
    )));
    let (mut resp, err) = http::ReadResponse(&mut br, None);
    if err != errors::nil {
        return string("err ") + err.Error();
    }
    let (body, _) = io::ReadAll(&mut resp.Body);
    let te = if resp.TransferEncoding.len() > 0 {
        resp.TransferEncoding[0].clone()
    } else {
        string("")
    };
    return fmt::Sprintf!(
        "%d %s proto=%s CL=%d close=%v te=%s body=%s ct=%s",
        resp.StatusCode,
        resp.Status.clone(),
        resp.Proto.clone(),
        resp.ContentLength,
        resp.Close,
        te,
        string::from_bytes(&body),
        resp.Header.Get(string("Content-Type"))
    );
}

fn eq(got: string, want: &str, what: &str, bad: &mut i32) {
    if got != want {
        fmt::Println!("FAIL ", what);
        fmt::Println!("  got  ", got);
        fmt::Println!("  want ", want);
        *bad += 1;
    }
}

#[goish::main]
fn main() {
    let mut bad = 0i32;

    eq(
        parse("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello"),
        "200 200 OK proto=HTTP/1.1 CL=5 close=false te= body=hello ct=text/plain",
        "simple Content-Length",
        &mut bad,
    );

    eq(
        parse("HTTP/1.1 204 No Content\r\n\r\n"),
        "204 204 No Content proto=HTTP/1.1 CL=0 close=false te= body= ct=",
        "204 has no body",
        &mut bad,
    );

    eq(
        parse("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"),
        "200 200 OK proto=HTTP/1.1 CL=-1 close=false te=chunked body=hello ct=",
        "chunked",
        &mut bad,
    );

    eq(
        parse("HTTP/1.0 200 OK\r\n\r\nbody-to-eof"),
        "200 200 OK proto=HTTP/1.0 CL=-1 close=true te= body=body-to-eof ct=",
        "HTTP/1.0 body to EOF",
        &mut bad,
    );

    eq(
        parse("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nhi"),
        "200 200 OK proto=HTTP/1.1 CL=2 close=true te= body=hi ct=",
        "Connection: close with CL",
        &mut bad,
    );

    eq(
        parse("HTTP/1.1 599 Weird Reason\r\nContent-Length: 0\r\n\r\n"),
        "599 599 Weird Reason proto=HTTP/1.1 CL=0 close=false te= body= ct=",
        "non-standard status keeps its reason",
        &mut bad,
    );

    eq(
        parse("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-A: 1\r\nX-A: 2\r\n\r\n"),
        "200 200 OK proto=HTTP/1.1 CL=0 close=false te= body= ct=",
        "duplicate headers",
        &mut bad,
    );

    eq(
        parse("HTTP/1.1 304 Not Modified\r\n\r\n"),
        "304 304 Not Modified proto=HTTP/1.1 CL=0 close=false te= body= ct=",
        "304 has no body",
        &mut bad,
    );

    // A non-numeric status code must be an error, not a silent 0.
    {
        let got = parse("HTTP/1.1 abc OK\r\n\r\n");
        if !goish::strings::HasPrefix(got.clone(), string("err ")) {
            fmt::Println!("FAIL bad status line: expected an error, got ", got);
            bad += 1;
        }
    }

    if bad == 0 {
        fmt::Println!("READRESPONSE_OK 9/9");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAILED ", bad);
        syscall::Exit(1);
    }
}
