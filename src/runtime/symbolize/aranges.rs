// runtime::symbolize::aranges — DWARF .debug_aranges lookup table.
//
// .debug_aranges is a series of address-range descriptors, each of
// which says "Compilation Unit at debug_info offset X covers PC ranges
// [addr1, addr1+len1), [addr2, addr2+len2), ...". DWARF 2 layout:
//
//   unit_length      (4 / 12 bytes — initial length)
//   version          (2 bytes, always 2 in practice)
//   debug_info_off   (4 / 8 bytes per length form)
//   address_size     (1 byte, == 8 on amd64)
//   segment_size     (1 byte, == 0 on amd64)
//   <padding>        (so the first range is aligned to 2 * address_size)
//   ranges           (pairs of (address, length) until both zero)
//
// We pre-build a flat sorted Vec<(pc_lo, pc_hi, cu_off)> at init and
// binary-search at lookup time.

use alloc::vec::Vec;

use super::dwarf_util::{read_initial_length, read_u16, read_u32, read_u64, read_u8};

#[derive(Clone, Copy)]
pub struct ArangeEntry {
    pub pc_lo: u64,
    pub pc_hi: u64,
    pub cu_offset: u64,
}

/// Parse `.debug_aranges` into a sorted lookup table.
pub fn build(aranges: &[u8]) -> Vec<ArangeEntry> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < aranges.len() {
        let unit_start = off;
        let (length, is_64bit) = match read_initial_length(aranges, &mut off) {
            Some(v) => v,
            None => break,
        };
        let unit_end = off + length as usize;
        if unit_end > aranges.len() {
            break;
        }

        let _version = match read_u16(aranges, &mut off) {
            Some(v) => v,
            None => break,
        };
        let cu_offset = if is_64bit {
            match read_u64(aranges, &mut off) {
                Some(v) => v,
                None => break,
            }
        } else {
            match read_u32(aranges, &mut off) {
                Some(v) => v as u64,
                None => break,
            }
        };
        let address_size = match read_u8(aranges, &mut off) {
            Some(v) => v,
            None => break,
        };
        let _segment_size = match read_u8(aranges, &mut off) {
            Some(v) => v,
            None => break,
        };

        // Padding so first tuple aligns to 2*address_size from the
        // start of the unit (i.e., from `unit_start`, not from `off`).
        let align = (2 * address_size as usize).max(1);
        let from_unit = off - unit_start;
        let pad = (align - (from_unit % align)) % align;
        off += pad;

        // Tuples until (0, 0).
        if address_size != 8 {
            // Non-amd64 — skip this CU.
            off = unit_end;
            continue;
        }
        while off + 16 <= unit_end {
            let addr = match read_u64(aranges, &mut off) {
                Some(v) => v,
                None => break,
            };
            let len = match read_u64(aranges, &mut off) {
                Some(v) => v,
                None => break,
            };
            if addr == 0 && len == 0 {
                break;
            }
            if len == 0 {
                continue;
            }
            out.push(ArangeEntry {
                pc_lo: addr,
                pc_hi: addr.wrapping_add(len),
                cu_offset,
            });
        }
        off = unit_end;
    }
    out.sort_by_key(|e| e.pc_lo);
    out
}

/// Find the CU offset that owns `pc`, if any.
pub fn lookup(table: &[ArangeEntry], pc: u64) -> Option<u64> {
    // Binary search for the entry whose pc_lo is the largest ≤ pc.
    let mut lo = 0usize;
    let mut hi = table.len();
    while lo < hi {
        let mid = (lo + hi) / 2;
        if table[mid].pc_lo <= pc {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if lo == 0 {
        return None;
    }
    let e = &table[lo - 1];
    if pc < e.pc_hi {
        Some(e.cu_offset)
    } else {
        None
    }
}
