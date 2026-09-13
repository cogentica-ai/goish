// tls13_certverify_refuse_smoke — a CertificateVerify that does not
// parse must be REFUSED, not skipped.
//
// CertificateVerify is the only thing in TLS 1.3 that binds the
// server's certificate to this connection. A man-in-the-middle already
// has the handshake secret — it ran its own key exchange — and a
// certificate is public, so if this step is skipped the MITM can
// present any server's certificate and be believed.
//
// The invented TLS 1.3 client skipped it on a parse failure:
//
//     None => {
//         // Continue — don't abort for parse failure
//         //            (shouldn't happen with well-formed servers)
//     }
//
// `parse_tls13_cert_verify` returns None for anything truncated, so a
// one-byte body was enough. "Shouldn't happen with well-formed
// servers" is true and beside the point: a hostile server is the case
// this code exists to survive. Go never reaches the decision at all —
// `readHandshake` fails to unmarshal and the handshake aborts.
//
// This is a sibling of the defect ROADMAP §1 fixed here already —
// `verify_cert_verify` returning success for an unlisted signature
// algorithm — and easier to trigger, needing no algorithm at all. That
// audit listed what it had checked clean; this path was in neither
// list, which is why the row below exists.
//
// Reachability: `tls::Dial` runs the PORTED clientHandshake, not this
// one. The invented family is public API from `crypto::tls::mod`, so a
// caller can reach it.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::crypto::tls::handshake_client_tls13 as hs13;
use goish::{fmt, int, string};

static mut FAILED: int = 0;

fn check(name: &'static str, ok: bool, detail: goish::string) {
    if ok {
        fmt::Printf!("[ok] %s\n", name);
    } else {
        unsafe { FAILED += 1 };
        fmt::Printf!("[!!] %s — %s\n", name, detail);
    }
}

/// A syntactically plausible CertificateVerify: type(1) len(3)
/// sig_alg(2) sig_len(2) sig(n).
fn cert_verify_msg(sig_alg: u16, sig: &[u8]) -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    let body_len = 4 + sig.len();
    v.push(15); // CertificateVerify
    v.push(((body_len >> 16) & 0xff) as u8);
    v.push(((body_len >> 8) & 0xff) as u8);
    v.push((body_len & 0xff) as u8);
    v.push((sig_alg >> 8) as u8);
    v.push((sig_alg & 0xff) as u8);
    v.push((sig.len() >> 8) as u8);
    v.push((sig.len() & 0xff) as u8);
    v.extend_from_slice(sig);
    return v;
}

#[goish::main]
fn main() {
    let th = [0x5au8; 32];
    // A Certificate message that will not parse — the handshake's own
    // fallback makes the key Unknown, which every arm refuses.
    let junk_cert: [u8; 8] = [11, 0, 0, 4, 0, 0, 0, 0];

    // ── the defect: a malformed CertificateVerify ───────────────────
    //
    // Each of these makes `parse_tls13_cert_verify` return None, which
    // used to mean "carry on without verifying".
    let malformed: [(&'static str, &[u8]); 4] = [
        ("empty", &[]),
        ("header only, no sig_alg", &[15, 0, 0, 0]),
        ("sig_alg but no length", &[15, 0, 0, 2, 0x08, 0x04]),
        (
            "length longer than the body",
            &[15, 0, 0, 6, 0x08, 0x04, 0xff, 0xf0, 0x01, 0x02],
        ),
    ];
    let mut msgs: Vec<goish::string> = Vec::new();
    for (label, body) in malformed.iter() {
        let e = hs13::__cert_verify_decision(&junk_cert, body, &th);
        check(
            "a malformed CertificateVerify is refused",
            !e.IsNil(),
            fmt::Sprintf!("%s was ACCEPTED", string::from_static(label)),
        );
        if !e.IsNil() {
            msgs.push(e.Error());
        }
    }

    // ── not vacuous ─────────────────────────────────────────────────
    //
    // Every row above asserts a refusal, so a decision function that
    // refused EVERYTHING would pass them all. These two rows are what
    // distinguish "refuses for the right reason" from "refuses": a
    // parse failure and a well-formed message must report DIFFERENT
    // causes, and the well-formed one must get as far as the signature.
    let well_formed_unknown_alg = cert_verify_msg(0xdead, &[0u8; 64]);
    let e_alg = hs13::__cert_verify_decision(&junk_cert, &well_formed_unknown_alg, &th);
    check(
        "a well-formed message with an unknown algorithm is also refused",
        !e_alg.IsNil(),
        string("accepted an unknown signature algorithm"),
    );
    check(
        "and it is refused for a DIFFERENT reason than a parse failure",
        !msgs.is_empty() && !e_alg.IsNil() && e_alg.Error() != msgs[0].clone(),
        fmt::Sprintf!(
            "parse=%s alg=%s — identical text means the decision is not discriminating",
            if msgs.is_empty() { string("<none>") } else { msgs[0].clone() },
            if e_alg.IsNil() { string("<nil>") } else { e_alg.Error() }
        ),
    );

    // A well-formed message naming a REAL algorithm reaches the key
    // check, and refuses because the junk certificate gave no key —
    // a third distinct cause, so the function is not collapsing.
    let well_formed_real_alg = cert_verify_msg(0x0804, &[0u8; 64]); // rsa_pss_rsae_sha256
    let e_key = hs13::__cert_verify_decision(&junk_cert, &well_formed_real_alg, &th);
    check(
        "a real algorithm against an unparseable certificate is refused",
        !e_key.IsNil(),
        string("accepted a signature with no certificate key"),
    );
    check(
        "with a third distinct cause",
        !e_key.IsNil() && !e_alg.IsNil() && e_key.Error() != e_alg.Error(),
        fmt::Sprintf!(
            "key=%s alg=%s",
            if e_key.IsNil() { string("<nil>") } else { e_key.Error() },
            if e_alg.IsNil() { string("<nil>") } else { e_alg.Error() }
        ),
    );

    let f = unsafe { FAILED };
    if f == 0 {
        fmt::Printf!("\nok 8/8\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("\nFAIL %d\n", f);
    goish::os::Exit(1);
}
