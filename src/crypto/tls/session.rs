// crypto/tls/session.rs — TLS 1.3 client-side session cache.
//
// Holds NewSessionTicket-derived resumption state keyed by server_name so
// that a subsequent Dial to the same host can resume via pre_shared_key.
//
// Reference: RFC 8446 §4.6.1 (NewSessionTicket) and §4.2.11 (pre_shared_key).

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use alloc::vec::Vec;

use crate::gostring::string;
use crate::goslice::slice;
use crate::lazy::Lazy;
use crate::sync;
use crate::types::byte;

/// `ClientSessionState` — one resumable session derived from a server-issued
/// NewSessionTicket. Mirrors Go's crypto/tls.ClientSessionState plus the
/// fields we need to recompute the obfuscated_ticket_age + binders.
#[derive(Clone)]
pub struct ClientSessionState {
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

impl Default for ClientSessionState {
    fn default() -> Self {
        ClientSessionState {
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

type CacheMap = crate::map<string, slice<ClientSessionState>>;

pub static CACHE: Lazy<sync::Mutex<CacheMap>> =
    Lazy::new(|| sync::Mutex::new(crate::map::new_no_zero()));

/// Append a session for `server_name`. Multiple tickets per host are kept
/// (servers commonly issue several so the client can resume in parallel).
pub fn put<S: Into<string>>(server_name: S, state: ClientSessionState) {
    let name = server_name.into();
    if name.Len() == 0 || state.ticket.is_empty() || state.resumption_psk.is_empty() {
        return;
    }
    let mut m = CACHE.Lock();
    let (cur_opt, _) = m.GetRef(name.clone());
    let mut list: slice<ClientSessionState> = match cur_opt {
        Some(s) => s.clone(),
        None => slice::<ClientSessionState>::__from_vec(Vec::new()),
    };
    let mut v = list.__into_vec();
    v.push(state);
    list = slice::<ClientSessionState>::__from_vec(v);
    m.Set(name, list);
}

/// Pop the most-recently-stored session for `server_name`, or `None`.
/// Per RFC 8446 each ticket SHOULD be used only once (replay resistance),
/// so we remove the entry on get.
pub fn take<S: Into<string>>(server_name: S) -> Option<ClientSessionState> {
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
    let popped = v.pop();
    if v.is_empty() {
        // No tickets left — remove the entry.
        crate::delete!(m, name);
    } else {
        m.Set(name, slice::<ClientSessionState>::__from_vec(v));
    }
    popped
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
