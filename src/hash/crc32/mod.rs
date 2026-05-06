// hash/crc32 — Go's `hash/crc32`, ported (simple table algorithm).
//
// 32-bit cyclic redundancy check, polynomial in LSB-first form.
// (Go: hash/crc32/crc32.go + crc32_generic.go)
//
// Slim deviations:
//   * Only the simple table algorithm (`simpleMakeTable` /
//     `simpleUpdate`); no slicing-by-8, no HW acceleration. Go's
//     IEEE/Castagnoli archUpdate paths use SSE 4.2 PCLMUL on amd64;
//     goish-v1 leaves that for a later optimization pass.
//   * No MarshalBinary / UnmarshalBinary / Clone (cosmetic state
//     save/restore; not needed for HTTP streaming hashes).
//   * `IEEETable` is a function `IEEETable()` that returns an `Arc<Table>`
//     produced by a one-shot `Once::Do`; Go exposes a package-level
//     `*Table`, but goish-v1 doesn't have package-level mutable
//     statics with no_std-safe lazy init except via Once.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::hash::{Hash, Hash32};
use crate::io;
use crate::runtime::spin::SpinLock;
use crate::types::{byte, int};

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

// ─── Constants (Go: crc32.go:24-41) ───────────────────────────────────

/// `crc32.Size` — checksum length in bytes.
pub const Size: int = 4;

/// `crc32.IEEE` (crc32.go:30) — used by Ethernet, gzip, zip, png, ...
pub const IEEE: u32 = 0xedb88320;

/// `crc32.Castagnoli` (crc32.go:35) — used in iSCSI; better error
/// detection than IEEE.
pub const Castagnoli: u32 = 0x82f63b78;

/// `crc32.Koopman` (crc32.go:40) — alternate polynomial with strong
/// error detection.
pub const Koopman: u32 = 0xeb31d82e;

// ─── Table (Go: crc32.go:44) ──────────────────────────────────────────

/// `crc32.Table` — 256-entry table representing the polynomial.
#[derive(Clone)]
pub struct Table {
    entries: [u32; 256],
}

impl Table {
    /// Index access matching Go's `t[i]`.
    pub fn at(&self, i: usize) -> u32 {
        self.entries[i]
    }
}

// Go: simpleMakeTable (crc32_generic.go:21) — allocates and populates.
fn simple_make_table(poly: u32) -> Table {
    let mut entries = [0u32; 256];
    // Go: for i := 0; i < 256; i++ { ... }
    let mut i: usize = 0;
    while i < 256 {
        let mut crc = i as u32;
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

/// `crc32.MakeTable(poly)` (crc32.go:122) — return a Table for `poly`.
pub fn MakeTable(poly: u32) -> Table {
    // Slim: no Castagnoli arch fast path; just simpleMakeTable for any poly.
    simple_make_table(poly)
}

// ─── IEEETable singleton ──────────────────────────────────────────────
//
// Go exposes `IEEETable` as a package-level `*Table`; goish exposes a
// function returning `Arc<Table>` (matches the cached-error idiom used
// in io::pipe::ErrClosedPipe). Lazy-built under SpinLock on first call.

/// `crc32.IEEETable()` — return the lazily-built IEEE polynomial table.
pub fn IEEETable() -> Arc<Table> {
    static SLOT: SpinLock<Option<Arc<Table>>> = SpinLock::new(None);
    let mut g = SLOT.lock();
    if g.is_none() {
        *g = Some(Arc::new(simple_make_table(IEEE)));
    }
    g.as_ref().unwrap().clone()
}

// ─── digest (Go: crc32.go:136) ────────────────────────────────────────

/// `crc32` digest computing CRC-32 with a chosen polynomial Table.
pub struct Digest {
    crc: u32,
    tab: Arc<Table>,
}

/// `crc32.New(tab)` (crc32.go:146) — new digest with the given table.
pub fn New(tab: Arc<Table>) -> Digest {
    // Go: return &digest{0, tab}
    Digest { crc: 0, tab }
}

/// `crc32.NewIEEE()` (crc32.go:158) — new digest with the IEEE table.
pub fn NewIEEE() -> Digest {
    New(IEEETable())
}

// Go: simpleUpdate (crc32_generic.go:40) — table-driven CRC update.
fn simple_update(mut crc: u32, tab: &Table, p: &[byte]) -> u32 {
    // Go: crc = ^crc
    crc = !crc;
    // Go: for _, v := range p { crc = tab[byte(crc)^v] ^ (crc >> 8) }
    for v in p.iter() {
        crc = tab.entries[((crc as byte) ^ *v) as usize] ^ (crc >> 8);
    }
    // Go: return ^crc
    !crc
}

/// `crc32.Update(crc, tab, p)` (crc32.go:217) — extend `crc` by hashing `p`.
pub fn Update(crc: u32, tab: &Table, p: slice<byte>) -> u32 {
    let raw: &[byte] = &p;
    simple_update(crc, tab, raw)
}

/// `crc32.Checksum(data, tab)` (crc32.go:239) — CRC-32 of `data`.
pub fn Checksum(data: slice<byte>, tab: &Table) -> u32 {
    Update(0, tab, data)
}

/// `crc32.ChecksumIEEE(data)` (crc32.go:243) — CRC-32-IEEE of `data`.
pub fn ChecksumIEEE(data: slice<byte>) -> u32 {
    let tab = IEEETable();
    Checksum(data, &tab)
}

// ─── Hash trait impls for Digest (Go: crc32.go:160-235) ───────────────

impl io::Writer for Digest {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        // Go: d.crc = update(d.crc, d.tab, p, false); return len(p), nil
        let raw: &[byte] = &p;
        self.crc = simple_update(self.crc, &self.tab, raw);
        (raw.len() as int, nil)
    }
}

impl Hash for Digest {
    fn Sum(&self, b: slice<byte>) -> slice<byte> {
        // Go: append(in, byte(s>>24), byte(s>>16), byte(s>>8), byte(s))
        let s = self.crc;
        let mut out: Vec<byte> = b.__into_vec();
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

impl Hash32 for Digest {
    fn Sum32(&self) -> u32 {
        self.crc
    }
}
