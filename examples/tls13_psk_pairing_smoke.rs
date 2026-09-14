// The PSK / cipher-suite pairing check the invented TLS 1.3 client
// did not have.
//
// Go's clientHandshakeStateTLS13.processServerHello
// (handshake_client_tls13.go:445-466) gates a server's PSK acceptance
// on three things. goish's invented client had none of them:
//
//   * selectedIdentity out of range — Go sends alertIllegalParameter
//     and ABORTS. goish logged "server selected unknown identity" and
//     continued with a full handshake, so a server naming identity 7
//     when one was offered got a connection instead of an error.
//   * a selected identity with nothing offered — Go's
//     alertInternalError arm.
//   * pskSuite.hash != suite.hash — Go aborts with "server selected an
//     invalid PSK and cipher suite pair". THIS WAS ABSENT, so a
//     SHA-256-bound resumption secret could be fed into a SHA-384 key
//     schedule.
//
// The last one fails closed two steps later, when the Finished MAC
// diverges, which is why it is a spec violation rather than an exploit.
// "Fails closed by accident, later" is not a guarantee, and Go does not
// rely on it.
//
// WHY THIS NEEDED EXTRACTING. The path is unreachable in any
// goish-only program — nothing under src/ writes the session cache the
// client reads from (see ROADMAP §1) — so a guard added inline here
// could never be driven, and a wrong one would look exactly like a
// right one. `psk_acceptance_decision` is the live decision; the
// handshake calls it and this drives the same function.
//
// The table asserts three DISTINCT refusal reasons, not three
// refusals. A decision that refused everything would otherwise pass.
#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;

use goish::crypto::tls;
use goish::fmt;
use goish::gostring::string;
use goish::types::int;

// The three TLS 1.3 suites, by hash: 0x1301 and 0x1303 are SHA-256,
// 0x1302 is SHA-384.
const AES128_SHA256: int = 0x1301;
const AES256_SHA384: int = 0x1302;
const CHACHA_SHA256: int = 0x1303;

static mut PASS: int = 0;
static mut FAIL: int = 0;

fn row(
    what: &'static str,
    selected: int,
    has_selected: bool,
    offered: int,
    server: int,
    want_msg: &'static str,
    want_ok: bool,
) {
    let (msg, ok) = tls::handshake_client_pskDecision(selected, has_selected, offered, server);
    unsafe {
        if ok == want_ok && msg == string::from_bytes(want_msg.as_bytes()) {
            PASS += 1;
        } else {
            FAIL += 1;
            fmt::Printf!(
                "FAIL %s: got (%s,%v) want (%s,%v)\n",
                what,
                msg.clone(),
                ok,
                want_msg,
                want_ok
            );
        }
    }
}

#[goish::main]
fn main() {
    // ── accepted: same hash on both sides ─────────────────────────
    row(
        "same suite accepts",
        0, true, AES128_SHA256, AES128_SHA256, "", true,
    );
    // Different suite, SAME hash — Go compares the hash, not the id,
    // so this must be ACCEPTED. A check written against suite_id
    // instead would refuse it.
    row(
        "different suite, same hash accepts",
        0, true, AES128_SHA256, CHACHA_SHA256, "", true,
    );
    row(
        "the SHA-384 suite accepts itself",
        0, true, AES256_SHA384, AES256_SHA384, "", true,
    );

    // ── the missing check ─────────────────────────────────────────
    row(
        "SHA-256 PSK with a SHA-384 suite is refused",
        0, true, AES128_SHA256, AES256_SHA384,
        "tls: server selected an invalid PSK and cipher suite pair", false,
    );
    row(
        "SHA-384 PSK with a SHA-256 suite is refused",
        0, true, AES256_SHA384, CHACHA_SHA256,
        "tls: server selected an invalid PSK and cipher suite pair", false,
    );

    // ── identity out of range ─────────────────────────────────────
    row(
        "identity 1 is refused (one was offered)",
        1, true, AES128_SHA256, AES128_SHA256,
        "tls: server selected an invalid PSK", false,
    );
    row(
        "identity 7 is refused",
        7, true, AES128_SHA256, AES128_SHA256,
        "tls: server selected an invalid PSK", false,
    );

    // ── a selection with nothing offered ──────────────────────────
    row(
        "selecting a PSK we never offered is refused",
        0, true, 0, AES128_SHA256,
        "tls: server selected a PSK we did not offer", false,
    );

    // ── unknown suites on either side ─────────────────────────────
    row(
        "an unknown cached suite is refused",
        0, true, 0x9999, AES128_SHA256,
        "tls: cached session has an unknown cipher suite", false,
    );
    row(
        "an unknown server suite is refused",
        0, true, AES128_SHA256, 0x9999,
        "tls: server selected an unknown cipher suite", false,
    );

    // ── no selection at all: a full handshake, not a refusal ──────
    row(
        "no selected_identity is not an error",
        0, false, AES128_SHA256, AES128_SHA256, "<none>", false,
    );
    row(
        "no selection and nothing offered is not an error",
        0, false, 0, AES128_SHA256, "<none>", false,
    );

    unsafe {
        let (pass, fail) = (PASS, FAIL);
        if pass + fail != 12 {
            fmt::Printf!("FAIL ran %v rows, expected 12\n", pass + fail);
            FAIL += 1;
        }
        let fail = FAIL;
        fmt::Printf!(
            "tls13_psk_pairing_smoke: %v checks, %v failed\n",
            pass + fail,
            fail
        );
        if fail > 0 {
            goish::syscall::Exit(1);
        }
    }
}
