// net/http/fcgi parameter decoding — request.parseParams and friends.
//
// Expected values are Go 1.25.5's, captured by calling the real
// unexported newRequest/parseParams/addFastCGIEnvToContext inside
// net/http/fcgi (goref).
//
// Two cases carry the interesting behaviour:
//
//   * "long key len" uses a 4-byte length prefix (high bit set on the
//     first byte), the branch a 1-byte-prefix test never reaches;
//   * "truncated" declares lengths past the end of the buffer, where
//     Go BAILS OUT SILENTLY and keeps whatever was parsed before —
//     it does not error and does not discard the earlier pairs.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gomap::map;
use goish::net::http::fcgi;
use goish::{fmt, slice, string, syscall};

fn parse(raw: &[u8]) -> map<string, string> {
    let mut r = fcgi::newRequest(1, 0);
    r.rawParams = slice::<u8>::__from_vec(raw.to_vec());
    r.parseParams();
    return r.params;
}

fn want(m: &map<string, string>, k: &'static str, v: &str, what: &str, bad: &mut i32) {
    let (got, ok) = m.Get(string(k));
    if !ok || got != v {
        fmt::Println!("FAIL ", what, ": ", k, " = ", got);
        *bad += 1;
    }
}

fn wantLen(m: &map<string, string>, n: goish::types::int, what: &str, bad: &mut i32) {
    if m.Len() != n {
        fmt::Println!("FAIL ", what, ": len = ", m.Len(), " want ", n);
        *bad += 1;
    }
}

fn wantBool(got: bool, w: bool, what: &str, bad: &mut i32) {
    if got != w {
        fmt::Println!("FAIL ", what);
        *bad += 1;
    }
}

#[goish::main]
fn main() {
    let mut bad = 0i32;

    // Two short pairs, 1-byte length prefixes.
    let m = parse(&[
        3, 5, b'K', b'E', b'Y', b'v', b'a', b'l', b'u', b'e', 4, 2, b'K', b'E', b'Y', b'2', b'h',
        b'i',
    ]);
    wantLen(&m, 2, "two pairs count", &mut bad);
    want(&m, "KEY", "value", "two pairs", &mut bad);
    want(&m, "KEY2", "hi", "two pairs", &mut bad);

    // 4-byte length prefix: high bit set on the first byte.
    let m = parse(&[0x80, 0x00, 0x00, 0x03, 0x01, b'A', b'B', b'C', b'x']);
    wantLen(&m, 1, "long key len count", &mut bad);
    want(&m, "ABC", "x", "long key len", &mut bad);

    // Truncated: Go keeps what it already parsed and stops.
    let m = parse(&[
        3, 5, b'K', b'E', b'Y', b'v', b'a', b'l', b'u', b'e', 9, 9, b'a',
    ]);
    wantLen(&m, 1, "truncated count", &mut bad);
    want(&m, "KEY", "value", "truncated", &mut bad);

    // Empty.
    wantLen(&parse(&[]), 0, "empty count", &mut bad);

    // keepConn comes from the low bit of flags.
    wantBool(
        fcgi::newRequest(1, 0).keepConn,
        false,
        "keepConn 0",
        &mut bad,
    );
    wantBool(
        fcgi::newRequest(1, 1).keepConn,
        true,
        "keepConn 1",
        &mut bad,
    );
    wantBool(
        fcgi::newRequest(1, 3).keepConn,
        true,
        "keepConn 3",
        &mut bad,
    );

    // The env predicate: net/http-native names and HTTP_* are excluded.
    let envCases: [(&str, bool); 6] = [
        ("CONTENT_LENGTH", false),
        ("HTTP_HOST", false),
        ("REMOTE_USER", true),
        ("SCRIPT_FILENAME", true),
        ("SERVER_PROTOCOL", false),
        ("DOCUMENT_ROOT", true),
    ];
    for (s, w) in envCases.iter() {
        wantBool(
            fcgi::addFastCGIEnvToContext(string(*s)),
            *w,
            "addFastCGIEnvToContext",
            &mut bad,
        );
    }

    // filterOutUsedEnvVars keeps exactly the included ones.
    let mut env: map<string, string> = map::new();
    env.Set(string("CONTENT_LENGTH"), string("5"));
    env.Set(string("HTTP_HOST"), string("x"));
    env.Set(string("DOCUMENT_ROOT"), string("/srv"));
    env.Set(string("REMOTE_USER"), string("bob"));
    let kept = fcgi::filterOutUsedEnvVars(&env);
    wantLen(&kept, 2, "filterOutUsedEnvVars count", &mut bad);
    want(&kept, "DOCUMENT_ROOT", "/srv", "filter kept", &mut bad);
    want(&kept, "REMOTE_USER", "bob", "filter kept", &mut bad);

    if bad == 0 {
        fmt::Println!("FCGI_PARAMS_OK 20/20");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAILED ", bad);
        syscall::Exit(1);
    }
}
