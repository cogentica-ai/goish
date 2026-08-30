// go: file hash/crc32/crc32_generic.go decls: simpleMakeTable, simplePopulateTable, simpleUpdate, slicingMakeTable, slicingUpdate
//
// The `decls:` manifest above lists crc32_generic.go's funcs only.
// GOISH017 matches a manifest entry against Rust `fn` items, so naming
// `slicing8Cutoff` or the `slicing8Table` type there would report both
// as dropped ports. They are not dropped — each carries its own
// `// go: sdk` anchor below.
//
// hash/crc32/crc32_generic.go — the CRC-32 algorithms that are not
// specific to any architecture and use no hardware acceleration.
//
// Two of them. The simple one is a byte-at-a-time table lookup over a
// 256-word table. The slicing-by-8 one reads eight input bytes at a
// time out of eight such tables, and is worth its 8 KiB only past
// `slicing8Cutoff`; below that `slicingUpdate` falls straight through
// to `simpleUpdate`, which is why the cutoff lives here rather than at
// the call sites.
//
// This is the whole of goish's CRC-32: crc32_amd64.go's SSE 4.2 and
// PCLMUL paths are assembly, so `crc32_otherarch.rs` — the `!amd64`
// half of Go's own build — is what goish ports for the `arch*`
// interface, and every update lands here.

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

use crate::convert::byte as tobyte;
use crate::types::{byte, uint32};

extern crate alloc;
use alloc::sync::Arc;

use super::crc32::Table;

// go: sdk 1.25.5 hash/crc32/crc32_generic.go:20-24 simpleMakeTable
/// `crc32.simpleMakeTable(poly)` — allocate and construct a [`Table`]
/// for `poly`, suitable for use with [`simpleUpdate`].
pub(super) fn simpleMakeTable(poly: uint32) -> Table {
    // Go: t := new(Table); simplePopulateTable(poly, t); return t
    let mut t = Table::__zero();
    simplePopulateTable(poly, &mut t);
    return t;
}

// go: sdk 1.25.5 hash/crc32/crc32_generic.go:28-40 simplePopulateTable
/// `crc32.simplePopulateTable(poly, t)` — fill `t` for `poly`.
pub(super) fn simplePopulateTable(poly: uint32, t: &mut Table) {
    // Go: for i := 0; i < 256; i++
    let mut i: usize = 0;
    while i < 256 {
        // Go: crc := uint32(i)
        let mut crc: uint32 = crate::convert::uint32(i);
        // Go: for j := 0; j < 8; j++
        let mut j: usize = 0;
        while j < 8 {
            if crc & 1 == 1 {
                crc = (crc >> 1) ^ poly;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        // Go: t[i] = crc
        t.__set(i, crc);
        i += 1;
    }
}

// go: sdk 1.25.5 hash/crc32/crc32_generic.go:44-50 simpleUpdate
/// `crc32.simpleUpdate(crc, tab, p)` — the simple algorithm, over a
/// table built by [`simpleMakeTable`].
///
/// Takes a borrowed `&[byte]`: the slicing-by-8 caller hands it the
/// tail of a cursor it is already walking, and re-wrapping a goish
/// slice there would allocate per call. It is unexported, so no goish
/// API surface sees the borrow.
pub(super) fn simpleUpdate(crc: uint32, tab: &Table, p: &[byte]) -> uint32 {
    // Go: crc = ^crc
    let mut crc = !crc;
    // Go: for _, v := range p { crc = tab[byte(crc)^v] ^ (crc >> 8) }
    let mut i: usize = 0;
    while i < p.len() {
        crc = tab.at(usize::from(tobyte(crc) ^ p[i])) ^ (crc >> 8);
        i += 1;
    }
    // Go: return ^crc
    return !crc;
}

// go: sdk 1.25.5 hash/crc32/crc32_generic.go:53-53 slicing8Cutoff
/// `crc32.slicing8Cutoff` — use slicing-by-8 when the payload is at
/// least this many bytes.
const slicing8Cutoff: usize = 16;

// go: sdk 1.25.5 hash/crc32/crc32_generic.go:56-56 slicing8Table
/// `crc32.slicing8Table` — an array of 8 [`Table`]s, used by the
/// slicing-by-8 algorithm.
pub(super) struct slicing8Table {
    tables: [Table; 8],
}

impl slicing8Table {
    // go: none — goish idiom: Go writes `tab[j][i]` on a `*slicing8Table`,
    //     which is an array type and indexes directly. `tables` is
    //     private, so goish exposes the read through a method.
    pub(super) fn at(&self, j: usize) -> &Table {
        return &self.tables[j];
    }
}

// go: sdk 1.25.5 hash/crc32/crc32_generic.go:60-71 slicingMakeTable
/// `crc32.slicingMakeTable(poly)` — construct a [`slicing8Table`] for
/// `poly`, suitable for use with [`slicingUpdate`].
pub(super) fn slicingMakeTable(poly: uint32) -> Arc<slicing8Table> {
    // Go: t := new(slicing8Table); simplePopulateTable(poly, &t[0])
    let mut tables: [Table; 8] = core::array::from_fn(|_| Table::__zero());
    simplePopulateTable(poly, &mut tables[0]);
    // Go: for i := 0; i < 256; i++
    let mut i: usize = 0;
    while i < 256 {
        // Go: crc := t[0][i]
        let mut crc = tables[0].at(i);
        // Go: for j := 1; j < 8; j++
        let mut j: usize = 1;
        while j < 8 {
            // Go: crc = t[0][crc&0xFF] ^ (crc >> 8)
            crc = tables[0].at(usize::from(tobyte(crc))) ^ (crc >> 8);
            // Go: t[j][i] = crc
            tables[j].__set(i, crc);
            j += 1;
        }
        i += 1;
    }
    return Arc::new(slicing8Table { tables });
}

// go: sdk 1.25.5 hash/crc32/crc32_generic.go:75-91 slicingUpdate
/// `crc32.slicingUpdate(crc, tab, p)` — the slicing-by-8 algorithm,
/// over a table built by [`slicingMakeTable`]. Falls through to
/// [`simpleUpdate`] for anything shorter than [`slicing8Cutoff`], and
/// for the tail the eight-byte loop leaves behind.
pub(super) fn slicingUpdate(crc: uint32, tab: &slicing8Table, p: &[byte]) -> uint32 {
    let mut crc = crc;
    let mut q: &[byte] = p;
    // Go: if len(p) >= slicing8Cutoff
    if q.len() >= slicing8Cutoff {
        // Go: crc = ^crc
        crc = !crc;
        // Go: for len(p) > 8
        while q.len() > 8 {
            // Go: crc ^= byteorder.LEUint32(p)
            let mut w: [byte; 4] = [0; 4];
            w.copy_from_slice(&q[..4]);
            crc ^= uint32::from_le_bytes(w);
            // Go: crc = tab[0][p[7]] ^ tab[1][p[6]] ^ tab[2][p[5]] ^ tab[3][p[4]] ^
            //            tab[4][crc>>24] ^ tab[5][(crc>>16)&0xFF] ^
            //            tab[6][(crc>>8)&0xFF] ^ tab[7][crc&0xFF]
            crc = tab.at(0).at(usize::from(q[7]))
                ^ tab.at(1).at(usize::from(q[6]))
                ^ tab.at(2).at(usize::from(q[5]))
                ^ tab.at(3).at(usize::from(q[4]))
                ^ tab.at(4).at(usize::from(tobyte(crc >> 24)))
                ^ tab.at(5).at(usize::from(tobyte(crc >> 16)))
                ^ tab.at(6).at(usize::from(tobyte(crc >> 8)))
                ^ tab.at(7).at(usize::from(tobyte(crc)));
            // Go: p = p[8:]
            q = &q[8..];
        }
        // Go: crc = ^crc
        crc = !crc;
    }
    // Go: if len(p) == 0 { return crc }
    if q.is_empty() {
        return crc;
    }
    // Go: return simpleUpdate(crc, &tab[0], p)
    return simpleUpdate(crc, tab.at(0), q);
}
