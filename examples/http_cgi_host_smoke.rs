// http_cgi_host_smoke — net/http/cgi/host.go's environment helpers.
// Values from scripts/goref.sh against the real cgi package.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::net::http::cgi::host::{removeLeadingDuplicates, upperCaseAndUnderscore};
use goish::{slice, string};

static PASSED: AtomicUsize = AtomicUsize::new(0);
static FAILED: AtomicUsize = AtomicUsize::new(0);

fn check(name: &'static str, ok: bool, detail: goish::string) {
    if ok {
        PASSED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("PASS: %s\n", name);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("FAIL: %s — %s\n", name, detail);
    }
}

fn strs(v: &[&'static str]) -> slice<string> {
    let mut o: alloc::vec::Vec<string> = alloc::vec::Vec::new();
    for s in v {
        o.push(string(*s));
    }
    slice::<string>::__from_vec(o)
}

fn joined(v: &slice<string>) -> goish::string {
    let mut out = string("");
    for i in 0..v.Len() {
        out = fmt::Sprintf!("%s%s,", out, v[i].clone());
    }
    out
}

#[goish::main]
fn main() {
    goish::go!(stack(512 * 1024), move || {
        run();
    });
    loop {
        goish::runtime::sched::Gosched();
    }
}

fn run() {
    {
        let cases: &[(char, char)] = &[
            ('a', 'A'),
            ('z', 'Z'),
            ('A', 'A'),
            ('Z', 'Z'),
            ('-', '_'),
            // `=` maps to `_` too: a header named X=Y would otherwise
            // inject a second '=' into the key=value env entry.
            ('=', '_'),
            ('_', '_'),
            ('0', '0'),
            ('é', 'é'), // non-ASCII passes through untouched
        ];
        let mut bad = string("");
        for (r, want) in cases {
            let got = upperCaseAndUnderscore(*r as goish::rune);
            if got != *want as goish::rune {
                bad = fmt::Sprintf!("%s -> %d", string("case"), got as i64);
            }
        }
        check(
            "upperCaseAndUnderscore over 9 runes (incl. '=' and non-ASCII)",
            bad.Len() == 0,
            bad,
        );
    }
    {
        // LAST occurrence wins — an environment is applied last-wins,
        // so keeping the first would hand the child the overridden value.
        let cases: &[(&[&'static str], &[&'static str])] = &[
            (&["A=1", "B=2"], &["A=1", "B=2"]),
            (&["A=1", "A=2"], &["A=2"]),
            (&["A=1", "A=2", "A=3"], &["A=3"]),
            // "PATH=" must not prefix-match "PATH_EXTRA=" — the '=' is
            // part of the compared key.
            (&["PATH=x", "PATH_EXTRA=y"], &["PATH=x", "PATH_EXTRA=y"]),
            // No '=' at all: never treated as a duplicate.
            (&["NOEQUALS", "NOEQUALS"], &["NOEQUALS", "NOEQUALS"]),
            (&["A=1", "B=2", "A=9", "B=8"], &["A=9", "B=8"]),
        ];
        let mut bad = string("");
        for (input, want) in cases {
            let got = removeLeadingDuplicates(strs(input));
            if joined(&got) != joined(&strs(want)) {
                bad = fmt::Sprintf!("got %s want %s", joined(&got), joined(&strs(want)));
            }
        }
        check(
            "removeLeadingDuplicates keeps the LAST of each key",
            bad.Len() == 0,
            bad,
        );
    }

    let p = PASSED.load(Ordering::Relaxed);
    let f = FAILED.load(Ordering::Relaxed);
    fmt::Printf!("\n%d passed, %d failed\n", p as i64, f as i64);
    if f == 0 {
        fmt::Printf!("HTTP_CGI_HOST_SMOKE_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("HTTP_CGI_HOST_SMOKE_FAIL\n");
    goish::os::Exit(1);
}
