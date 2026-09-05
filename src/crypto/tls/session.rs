// crypto/tls/session.rs — TLS 1.3 client-side session cache.
//
// goishlint:ignore GOISH015 — this file is INVENTED, not a port, as the
//     note below says: it anchors nothing. The `common.go` and
//     `handshake_client.go` citations are the Go RULES it now enforces,
//     quoted so the two can be compared, not a claim to port either.
//     ROADMAP.md §1 has it slated for deletion once the ported
//     ClientSessionCache path takes over.
//
// go: none — goish-only legacy: a hand-written global session cache
// predating the verbatim port. Go's equivalent surface is
// ClientSessionCache + lruSessionCache (common.go) with
// Conn.loadSession / saveSessionTicket, which are being ported; once
// the remaining client-handshake declarations land and the dial path
// moves onto them, this file is slated for deletion. Nothing in here
// corresponds to a Go declaration — names are goish-invented.
//
// Holds NewSessionTicket-derived resumption state keyed by server_name so
// that a subsequent Dial to the same host can resume via pre_shared_key.
//
// Reference: RFC 8446 §4.6.1 (NewSessionTicket) and §4.2.11 (pre_shared_key).

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use alloc::vec::Vec;

use crate::goslice::slice;
use crate::gostring::string;
use crate::lazy::Lazy;
use crate::sync;
use crate::types::byte;

/// `cachedSession` — one resumable session derived from a server-issued
/// NewSessionTicket.
///
/// Renamed out of the way of `tls::ClientSessionState`, which is now a
/// verbatim port of Go's type in ticket[rs]. This one is goish-only:
/// the flattened shape the live TLS 1.3 client holds, plus the
/// fields we need to recompute the obfuscated_ticket_age + binders.
#[derive(Clone)]
pub struct cachedSession {
    /// Opaque ticket bytes from the server (used as PskIdentity.identity).
    pub ticket: Vec<byte>,
    /// Server-chosen value XORed (well, added mod 2^32) into the obfuscated_ticket_age.
    pub ticket_age_add: u32,
    /// Ticket lifetime in seconds. 0 means "not bound" but we still try.
    pub ticket_lifetime: u32,
    /// Monotonic time the ticket was received, in milliseconds since epoch.
    /// `obfuscated_ticket_age = (now_ms - received_at_ms) + ticket_age_add` mod 2^32.
    pub received_at_ms: u64,
    /// PSK = HKDF-Expand-Label(resumption_master_secret, "resumption",
    ///                         ticket_nonce, hash_size).
    pub resumption_psk: Vec<byte>,
    /// Cipher suite the original session was negotiated with. The resumed
    /// session MUST use a suite with the same hash (RFC 8446 §4.2.11).
    pub suite_id: u16,
    /// Hash output size for the suite (32 = SHA-256, 48 = SHA-384).
    pub hash_size: u16,
}

impl Default for cachedSession {
    fn default() -> Self {
        cachedSession {
            ticket: Vec::new(),
            ticket_age_add: 0,
            ticket_lifetime: 0,
            received_at_ms: 0,
            resumption_psk: Vec::new(),
            suite_id: 0,
            hash_size: 0,
        }
    }
}

// ─── Process-wide cache ───────────────────────────────────────────────
//
// Go's tls.Config.ClientSessionCache is per-Config; for our single-binary
// no_std use case a process-wide cache keyed by server_name is sufficient.

/// Go: common.go:941 — `maxSessionTicketLifetime = 7 * 24 * time.Hour`.
/// RFC 8446 4.6.1: a server MUST NOT send a lifetime over 7 days, and a
/// client MUST NOT cache a ticket for longer than 7 days regardless of
/// what the server asked for.
const maxSessionTicketLifetimeMs: u64 = 7 * 24 * 60 * 60 * 1000;

/// Go: common.go:1623 — `defaultSessionCacheCapacity = 64`, the bound
/// on `lruSessionCache`. Without one the peer decides how much this
/// process remembers: a server may issue NewSessionTicket as often as
/// it likes, and every one was appended here.
const maxTicketsPerHost: usize = 64;

type CacheMap = crate::map<string, slice<cachedSession>>;

pub static CACHE: Lazy<sync::Mutex<CacheMap>> =
    Lazy::new(|| sync::Mutex::new(crate::map::new_no_zero()));

/// Append a session for `server_name`. Multiple tickets per host are kept
/// (servers commonly issue several so the client can resume in parallel).
pub fn put<S: Into<string>>(server_name: S, state: cachedSession) {
    let name = server_name.into();
    if name.Len() == 0 || state.ticket.is_empty() || state.resumption_psk.is_empty() {
        return;
    }
    let mut m = CACHE.Lock();
    let (cur_opt, _) = m.GetRef(name.clone());
    let mut list: slice<cachedSession> = match cur_opt {
        Some(s) => s.clone(),
        None => slice::<cachedSession>::__from_vec(Vec::new()),
    };
    let mut v = list.__into_vec();
    v.push(state);
    // Go's lruSessionCache evicts the least-recently-used entry past
    // its capacity; this list is per-host and ordered oldest-first, so
    // dropping from the front is the same discipline. Unbounded, a
    // server that issues a ticket per record grows this without limit.
    while v.len() > maxTicketsPerHost {
        v.remove(0);
    }
    list = slice::<cachedSession>::__from_vec(v);
    m.Set(name, list);
}

/// Pop the most-recently-stored session for `server_name`, or `None`.
/// Per RFC 8446 each ticket SHOULD be used only once (replay resistance),
/// so we remove the entry on get.
pub fn take<S: Into<string>>(server_name: S) -> Option<cachedSession> {
    let name = server_name.into();
    if name.Len() == 0 {
        return None;
    }
    let mut m = CACHE.Lock();
    let (cur_opt, _) = m.GetRef(name.clone());
    let list = match cur_opt {
        Some(s) => s.clone(),
        None => return None,
    };
    let mut v = list.__into_vec();
    if v.is_empty() {
        return None;
    }
    // Go: handshake_client.go:462 — "Check that the session ticket is
    // not expired", and it drops the entry rather than offering it.
    //
    // Nothing here checked. `ticket_lifetime` and `received_at_ms` were
    // both stored and neither was ever read, so a ticket stayed usable
    // for as long as the process ran: a stale resumption attempt the
    // server can only reject, and a linkable identifier kept long past
    // the lifetime its issuer set.
    let now = now_ms();
    let mut popped: Option<cachedSession> = None;
    while let Some(cand) = v.pop() {
        if !ticket_expired(&cand, now) {
            popped = Some(cand);
            break;
        }
        // Expired: drop it and keep looking. Go's cache does the same
        // — an expired entry is removed, not returned.
    }

    if v.is_empty() {
        // No tickets left — remove the entry.
        crate::delete!(m, name);
    } else {
        m.Set(name, slice::<cachedSession>::__from_vec(v));
    }
    popped
}

// go: none — goish-only: Go spreads this over `session.useBy`, set
//     when the ticket is stored, and the check at
//     handshake_client.go:463. This cache keeps the lifetime and the
//     arrival time instead, so the comparison lives in one predicate.
/// Whether `c` may no longer be offered for resumption.
///
/// Two bounds, both from Go. The server's own `ticket_lifetime` (RFC
/// 8446 4.6.1, seconds), and the 7-day ceiling that applies whatever
/// the server said. A lifetime of 0 means the ticket is already
/// unusable — this file used to note that case and "still try".
fn ticket_expired(c: &cachedSession, now: u64) -> bool {
    if now < c.received_at_ms {
        // Clock moved backwards; treat as expired rather than trusting
        // a negative age.
        return true;
    }
    let age_ms = now - c.received_at_ms;
    if age_ms >= maxSessionTicketLifetimeMs {
        return true;
    }
    return age_ms >= crate::convert::uint64(c.ticket_lifetime) * 1000;
}

/// Total ticket count across all hosts. Useful for tests.
pub fn len_total() -> usize {
    let m = CACHE.Lock();
    let mut total = 0usize;
    for (_, list) in crate::range!(&*m) {
        total += list.Len() as usize;
    }
    total
}

/// Wall-clock milliseconds for ticket-age math.
///
/// Falls back to `time::Now().UnixMilli()`. The PSK obfuscated_ticket_age
/// is mod 2^32 so even a coarse clock is fine.
pub fn now_ms() -> u64 {
    let t = crate::time::Now();
    let ns = t.UnixNano() as u64;
    ns / 1_000_000
}
