// tls_session_expiry_smoke — a cached TLS 1.3 ticket must expire, and
// the cache must be bounded.
//
// `session.rs` is the invented client-side session cache (ROADMAP.md
// §1). It stored `ticket_lifetime` and `received_at_ms` on every entry
// and read neither: a ticket stayed offerable for as long as the
// process ran. Its own comment on the lifetime field said "0 means not
// bound but we still try", which is the case RFC 8446 4.6.1 says is
// already unusable.
//
// Go drops an expired session rather than offering it
// (handshake_client.go:462, "Check that the session ticket is not
// expired") and caps its lruSessionCache at 64 entries
// (common.go:1623). Both are now enforced, plus the 7-day ceiling from
// common.go:941 that applies whatever lifetime the server claimed.
//
// What this costs when missing is not a compromise — the server
// rejects a stale ticket and the handshake falls back — but a ticket is
// a linkable identifier, and one kept past the lifetime its issuer set
// is offered to the network on every reconnect. The unbounded cache is
// the sharper half: the PEER decides how many tickets this process
// remembers, and every NewSessionTicket was appended.
//
// Measured against the commit before the fix, all four expiry cases
// came back resumable and all 200 tickets were kept.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;

use goish::crypto::tls::session;
use goish::fmt;
use goish::gostring::string;
use goish::types::{byte, int};


fn mk(lifetime: u32, received_at_ms: u64) -> session::cachedSession {
    let mut c = session::cachedSession::default();
    c.ticket = alloc::vec![1u8, 2, 3];
    c.resumption_psk = alloc::vec![4u8; 32];
    c.ticket_lifetime = lifetime;
    c.received_at_ms = received_at_ms;
    c.suite_id = 0x1301;
    c.hash_size = 32;
    return c;
}

const GO: [&str; 6] = [
    "fresh                    resumable=true",
    "past-lifetime            resumable=false",
    "zero-lifetime            resumable=false",
    "over-7-days              resumable=false",
    "capacity                 kept=64",
    "host-capacity            hosts<=64 kept=64",
];

fn chk(ln: &mut usize, got: &string) {
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln as int + 1, got);
        *ln += 1;
        return;
    }
    if got == GO[*ln] {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        fmt::Printf!("[!!] line %d\n  got  %q\n  want %q\n", *ln as int + 1, got, GO[*ln]);
    }
    *ln += 1;
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;

    let now = session::now_ms();

    // Fresh ticket: 1 hour lifetime, received now.
    session::put("fresh.example", mk(3600, now));
    let got = session::take("fresh.example");
    chk(&mut ln, &fmt::Sprintf!("%-24s resumable=%v", "fresh", got.is_some()));

    // Expired by the server's own lifetime: 60s, received 2 hours ago.
    session::put("stale.example", mk(60, now - 2 * 3600 * 1000));
    let got = session::take("stale.example");
    chk(&mut ln, &fmt::Sprintf!("%-24s resumable=%v", "past-lifetime", got.is_some()));

    // Lifetime 0 — unusable on arrival.
    session::put("zero.example", mk(0, now));
    let got = session::take("zero.example");
    chk(&mut ln, &fmt::Sprintf!("%-24s resumable=%v", "zero-lifetime", got.is_some()));

    // Server claims 30 days; the 7-day ceiling still applies.
    session::put("greedy.example", mk(30 * 24 * 3600, now - 8 * 24 * 3600 * 1000));
    let got = session::take("greedy.example");
    chk(&mut ln, &fmt::Sprintf!("%-24s resumable=%v", "over-7-days", got.is_some()));

    // Capacity: 200 tickets for one host must not all be kept.
    for i in 0..200u32 {
        session::put("many.example", mk(3600 + i, now));
    }
    chk(&mut ln, &fmt::Sprintf!("%-24s kept=%d", "capacity", session::len_total() as int));

    // Host capacity: 200 DISTINCT hosts must not all be kept either.
    //
    // The row above bounds tickets per host and passed long before this
    // one existed, which is exactly why the host dimension went
    // unnoticed: `put` capped the list it appends to and nothing capped
    // the number of lists. Go bounds KEYS — lruSessionCache holds at
    // most 64 and evicts the least-recently-used (common.go:1623) — so
    // an unbounded key count is the divergence, and a client that dials
    // many names and resumes none of them is the way to reach it.
    //
    // One ticket each, so `kept` is also the host count.
    {
        let mut m = session::CACHE.Lock();
        *m = goish::map::new_no_zero();
    }
    for i in 0..200u32 {
        let host = fmt::Sprintf!("h%d.example", i as int);
        session::put(host, mk(3600, now + i as u64));
    }
    chk(
        &mut ln,
        &fmt::Sprintf!(
            "%-24s hosts<=64 kept=%d",
            "host-capacity",
            session::len_total() as int
        ),
    );
    let _: byte = 0;
    if ln != GO.len() {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln as int, GO.len() as int);
    }
}
