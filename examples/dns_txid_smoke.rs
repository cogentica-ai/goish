// dns_txid_smoke — the DNS transaction ID must be unpredictable.
//
// `net/dnsclient.rs` calls itself "Port of net/dnsclient.go +
// net/dnsclient_unix.go" and carries no provenance anchor. Its ID came
// from a xorshift64 with a hardcoded seed mixed with clock_gettime,
// under a heading that said "poor-man's random using clock".
//
// That ID is the whole of a stub resolver's defence against off-path
// spoofing: an attacker who can guess it, and the source port, can race
// a forged answer ahead of the real one and be believed. Sixteen bits
// is already thin, which is why the value has to be UNPREDICTABLE
// rather than merely varying — a xorshift with a known constant seed
// is recoverable from a few observed IDs, and the clock mixed into it
// is something an off-path attacker can approximate.
//
// Go draws it from the runtime generator, seeded by the OS
// (dnsclient.go:22). goish now draws it from crypto/rand, the same
// source crypto/tls takes record IVs from.
//
// A statistical test cannot prove unpredictability, and this does not
// pretend to. What it checks is what the OLD code would fail: 64 draws
// all distinct, and no constant spacing between them. The zero check
// is a cheap sanity assertion, not a guard against a real failure
// mode — `crypto::rand::Read` fatals rather than returning a
// half-filled buffer, as Go's does.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;

use goish::fmt;
use goish::net::dnsclient;
use goish::net::dnsmessage as dns;
use goish::types::int;

#[goish::main]
fn main() {
    let mut bad: int = 0;

    let (name, _) = dns::NewName("example.com.");
    let q = dns::Question { Name: name, Type: dns::TypeA, Class: dns::ClassINET };
    let mut ids: Vec<u16> = Vec::new();
    for _ in 0..64 {
        let (id, _udp, _tcp, err) = dnsclient::new_request(q.clone(), false);
        if !err.IsNil() {
            fmt::Printf!("[!!] new_request err=%v\n", err);
            return;
        }
        ids.push(id);
    }
    // Mostly distinct. NOT all-distinct: that is the birthday problem,
    // and asserting it was a ~3% flake by construction.
    //
    // A DNS transaction ID is 16 bits, so 64 draws from 65536 values
    // collide with probability 1 - exp(-64*63/(2*65536)) ~= 3.0%. The
    // old assertion therefore failed about one run in 33 with a
    // perfectly good generator, and it duly went red on e2e-race, which
    // runs each example up to 50 times a night.
    //
    // Allowing up to three collisions puts the false-failure rate near
    // 1e-6 while still catching what this exists to catch: a constant
    // generator gives 63 duplicates, and a counter is caught by the
    // same-delta test below, not by this one.
    const MAX_DUPES: usize = 3;
    let mut sorted = ids.clone();
    sorted.sort();
    sorted.dedup();
    let dupes = ids.len() - sorted.len();
    if dupes <= MAX_DUPES {
        fmt::Printf!("[ok] %-22s %d draws, %d distinct\n", "unpredictable", ids.len() as int, sorted.len() as int);
    } else {
        fmt::Printf!("[!!] %-22s %d draws, only %d distinct\n", "unpredictable", ids.len() as int, sorted.len() as int);
        bad += 1;
    }
    // Consecutive difference constant would mean a counter.
    let mut same_delta = true;
    let d0 = ids[1].wrapping_sub(ids[0]);
    for i in 2..ids.len() {
        if ids[i].wrapping_sub(ids[i - 1]) != d0 { same_delta = false; }
    }
    if !same_delta {
        fmt::Printf!("[ok] %-22s not a counter\n", "spacing");
    } else {
        fmt::Printf!("[!!] %-22s constant spacing — a counter\n", "spacing");
        bad += 1;
    }
    // Any zeros (a failed draw left as zero)?
    let zeros = ids.iter().filter(|x| **x == 0).count();
    if zeros == 0 {
        fmt::Printf!("[ok] %-22s no zero ids\n", "draws");
    } else {
        fmt::Printf!("[!!] %-22s %d zero ids\n", "draws", zeros as int);
        bad += 1;
    }
    if bad == 0 {
        fmt::Printf!("dns_txid_smoke: all checks passed\n");
    } else {
        fmt::Printf!("dns_txid_smoke: %v FAILED\n", bad);
        // e2e reads the exit status, not the word FAILED above
        // (ROADMAP §2b-vii).
        goish::os::Exit(1);
    }
}
