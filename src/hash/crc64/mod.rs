// hash/crc64 — Go's `hash/crc64`, ported (simple table algorithm).
//
// 64-bit cyclic redundancy check, polynomial in LSB-first form.
// (Go: hash/crc64/crc64.go)
//
// Slim deviations:
//   * Only the simple table algorithm; no slicing-by-8 fast path.
//     Go's update has a slicing-by-8 inner loop for blocks ≥64 bytes
//     that uses `[8]Table`; goish-v1 uses the byte-at-a-time inner
//     loop (the fallback path Go also uses for tails / small inputs).
//     ~5x slower for large inputs, but algorithmically equivalent.
//   * No MarshalBinary / UnmarshalBinary / Clone (cosmetic).
//   * `ISOTable()` / `ECMATable()` are functions returning `Arc<Table>`
//     produced by lazy `SpinLock<Option<Arc<Table>>>` (matches crc32
//     and io::pipe::ErrClosedPipe). Go has package-level `*Table`s.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::hash::{Hash, Hash64};
use crate::io;
use crate::runtime::spin::SpinLock;
use crate::types::{byte, int};

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

// ─── Constants (Go: crc64.go:18-27) ───────────────────────────────────

/// `crc64.Size` (crc64.go:18) — checksum length in bytes.
pub const Size: int = 8;

/// `crc64.ISO` (crc64.go:23) — ISO 3309 polynomial; used in HDLC.
pub const ISO: u64 = 0xD800000000000000;

/// `crc64.ECMA` (crc64.go:26) — ECMA 182 polynomial.
pub const ECMA: u64 = 0xC96C5795D7870F42;

// ─── Table (Go: crc64.go:30) ──────────────────────────────────────────

/// `crc64.Table` — 256-entry table representing the polynomial.
#[derive(Clone)]
pub struct Table {
    entries: [u64; 256],
}

impl Table {
    /// Index access matching Go's `t[i]`.
    pub fn at(&self, i: usize) -> u64 {
        self.entries[i]
    }
}

// Go: makeTable (crc64.go:58)
fn make_table(poly: u64) -> Table {
    let mut entries = [0u64; 256];
    // Go: for i := 0; i < 256; i++
    let mut i: usize = 0;
    while i < 256 {
        let mut crc = i as u64;
        // Go: for j := 0; j < 8; j++
        let mut j = 0;
        while j < 8 {
            if crc & 1 == 1 {
                crc = (crc >> 1) ^ poly;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        entries[i] = crc;
        i += 1;
    }
    Table { entries }
}

/// `crc64.MakeTable(poly)` (crc64.go:46) — return a Table for `poly`.
pub fn MakeTable(poly: u64) -> Table {
    // Slim: no slicing-by-8 helper construction; just makeTable.
    make_table(poly)
}

// ─── ISOTable / ECMATable singletons ──────────────────────────────────
//
// Go exposes `slicing8TableISO`/`slicing8TableECMA` as package-level
// `*[8]Table`s lazily filled by sync.OnceFunc; goish exposes
// `ISOTable()` / `ECMATable()` that return `Arc<Table>` (the simple
// 256-entry table; the slicing-by-8 helper layer isn't ported).

/// `crc64.ISOTable()` — return the lazily-built ISO polynomial table.
pub fn ISOTable() -> Arc<Table> {
    static SLOT: SpinLock<Option<Arc<Table>>> = SpinLock::new(None);
    let mut g = SLOT.lock();
    if g.is_none() {
        *g = Some(Arc::new(make_table(ISO)));
    }
    g.as_ref().unwrap().clone()
}

/// `crc64.ECMATable()` — return the lazily-built ECMA polynomial table.
pub fn ECMATable() -> Arc<Table> {
    static SLOT: SpinLock<Option<Arc<Table>>> = SpinLock::new(None);
    let mut g = SLOT.lock();
    if g.is_none() {
        *g = Some(Arc::new(make_table(ECMA)));
    }
    g.as_ref().unwrap().clone()
}

// ─── digest (Go: crc64.go:88) ─────────────────────────────────────────

/// `crc64` digest computing CRC-64 with a chosen polynomial Table.
pub struct Digest {
    crc: u64,
    tab: Arc<Table>,
}

/// `crc64.New(tab)` (crc64.go:98) — new digest with the given table.
pub fn New(tab: Arc<Table>) -> Digest {
    // Go: return &digest{0, tab}
    Digest { crc: 0, tab }
}

// Go: update (crc64.go:141), simple-table fallback path only.
fn simple_update(mut crc: u64, tab: &Table, p: &[byte]) -> u64 {
    // Go: crc = ^crc
    crc = !crc;
    // Slim: skip the slicing-by-8 inner loop.
    // Go: for _, v := range p { crc = tab[byte(crc)^v] ^ (crc >> 8) }
    for v in p.iter() {
        crc = tab.entries[((crc as byte) ^ *v) as usize] ^ (crc >> 8);
    }
    // Go: return ^crc
    !crc
}

/// `crc64.Update(crc, tab, p)` (crc64.go:181) — extend `crc` by hashing `p`.
pub fn Update(crc: u64, tab: &Table, p: slice<byte>) -> u64 {
    let raw: &[byte] = &p;
    simple_update(crc, tab, raw)
}

/// `crc64.Checksum(data, tab)` (crc64.go:199) — CRC-64 of `data`.
pub fn Checksum(data: slice<byte>, tab: &Table) -> u64 {
    Update(0, tab, data)
}

// ─── Hash trait impls for Digest (Go: crc64.go:100-195) ───────────────

impl io::Writer for Digest {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        // Go: d.crc = update(d.crc, d.tab, p); return len(p), nil
        let raw: &[byte] = &p;
        self.crc = simple_update(self.crc, &self.tab, raw);
        (raw.len() as int, nil)
    }
}

impl Hash for Digest {
    fn Sum(&self, b: slice<byte>) -> slice<byte> {
        // Go: append(in, byte(s>>56), byte(s>>48), byte(s>>40), byte(s>>32),
        //                  byte(s>>24), byte(s>>16), byte(s>>8),  byte(s))
        let s = self.crc;
        let mut out: Vec<byte> = b.__into_vec();
        out.push((s >> 56) as byte);
        out.push((s >> 48) as byte);
        out.push((s >> 40) as byte);
        out.push((s >> 32) as byte);
        out.push((s >> 24) as byte);
        out.push((s >> 16) as byte);
        out.push((s >> 8) as byte);
        out.push(s as byte);
        slice::__from_vec(out)
    }
    fn Reset(&mut self) {
        // Go: d.crc = 0
        self.crc = 0;
    }
    fn Size(&self) -> int {
        Size
    }
    fn BlockSize(&self) -> int {
        1
    }
}

impl Hash64 for Digest {
    fn Sum64(&self) -> u64 {
        self.crc
    }
}
