// crypto/ssh: the client defaulted to NOT verifying host keys.
//
// goish's crypto/ssh is hand-written and unanchored — Go's standard
// library has no crypto/ssh, so no tier in this project can compare it
// to anything, and its own header says "Nothing here has been diffed
// for protocol conformance". §2b exists because that category is where
// the defects are.
//
// `ClientConfig::new()` set `HostKeyCallback: InsecureIgnoreHostKey()`.
// The handshake does verify the server's signature over the exchange
// hash — but that only proves the peer holds the private key for the
// host key it SENT. It says nothing about whether that host key is the
// one you meant to reach. Closing that gap is the callback's entire
// job, and the default threw it away silently.
//
// This is the shape of CVE-2017-3204, for which golang.org/x/crypto/ssh
// made HostKeyCallback a REQUIRED field: a nil one is an error there,
// not a permissive default. goish has no nil for a `Box<dyn Fn>`, so
// the same semantics are a default that fails.
//
// The rows below are the whole of the decision. Note the third: the
// insecure callback is still available, because a caller who means it
// should be able to say so — what changed is that they must.
#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;

use goish::crypto::ssh;
use goish::fmt;
use goish::gostring::string;
use goish::types::{byte, int};

static mut PASS: int = 0;
static mut FAIL: int = 0;

fn check(what: &'static str, ok: bool) {
    unsafe {
        if ok {
            PASS += 1;
        } else {
            FAIL += 1;
            fmt::Printf!("FAIL %s\n", what);
        }
    }
}

const KEY_A: &[byte] = b"\x00\x00\x00\x0bssh-ed25519AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const KEY_B: &[byte] = b"\x00\x00\x00\x0bssh-ed25519BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

#[goish::main]
fn main() {
    // ── the default must REFUSE ───────────────────────────────────
    let cfg = ssh::ClientConfig::new();
    let e = (cfg.HostKeyCallback)("host.example:22", KEY_A);
    check("the default HostKeyCallback refuses", !e.IsNil());
    // Guarded: if the row above failed, `e` is nil and `.Error()`
    // panics — which would exit 2 and take the remaining rows with it.
    // A smoke that dies on its own first failure reports one bit where
    // it could report eight.
    let msg = if e.IsNil() {
        string::from_static("<nil>")
    } else {
        e.Error()
    };
    check(
        "and says why, naming the escape hatches",
        goish::strings::Contains(
            msg.clone(),
            string::from_static("refusing to connect without host key verification"),
        ) && goish::strings::Contains(msg, string::from_static("InsecureIgnoreHostKey")),
    );
    // It must refuse EVERY key, not just an unknown-looking one — a
    // default that happened to accept some blob would be worse than one
    // that accepted all.
    let e2 = (cfg.HostKeyCallback)("other.example:22", KEY_B);
    check("the default refuses a second, different key too", !e2.IsNil());
    let e3 = (cfg.HostKeyCallback)("", &[]);
    check("the default refuses the empty key", !e3.IsNil());

    // ── FixedHostKey pins one key ─────────────────────────────────
    let fixed = ssh::FixedHostKey(goish::goslice::slice::<byte>::__from_vec(KEY_A.to_vec()));
    check(
        "FixedHostKey accepts the key it was given",
        fixed("host.example:22", KEY_A).IsNil(),
    );
    check(
        "FixedHostKey rejects a different key",
        !fixed("host.example:22", KEY_B).IsNil(),
    );
    check(
        "FixedHostKey rejects a truncated key",
        !fixed("host.example:22", &KEY_A[..KEY_A.len() - 1]).IsNil(),
    );
    check(
        "FixedHostKey rejects an empty key",
        !fixed("host.example:22", &[]).IsNil(),
    );

    // ── the escape hatch still exists, for callers who mean it ────
    let insecure = ssh::InsecureIgnoreHostKey();
    check(
        "InsecureIgnoreHostKey still accepts anything",
        insecure("host.example:22", KEY_B).IsNil(),
    );

    unsafe {
        let (pass, fail) = (PASS, FAIL);
        if pass + fail != 9 {
            fmt::Printf!("FAIL ran %v checks, expected 9\n", pass + fail);
            FAIL += 1;
        }
        let fail = FAIL;
        fmt::Printf!(
            "ssh_host_key_default_smoke: %v checks, %v failed\n",
            pass + fail,
            fail
        );
        if fail > 0 {
            goish::syscall::Exit(1);
        }
    }
}
