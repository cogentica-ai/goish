// runtime::symbolize::symtab — sorted view of `.symtab`/`.strtab`.
//
// Build a `Vec<SymRange>` of `(start, end, name_offset)` for every
// STT_FUNC in the symbol table, sorted by `start`. At lookup time,
// binary-search for the function whose range contains the PC.

use alloc::vec::Vec;

use super::elf::{st_type, Elf64Sym, STT_FUNC};

#[derive(Clone, Copy)]
pub struct SymRange {
    pub start: u64,
    pub end: u64,
    pub name_off: u32,
}

pub struct SymTable {
    pub ranges: Vec<SymRange>,
}

impl SymTable {
    pub fn build(symtab: &[Elf64Sym]) -> Self {
        let mut ranges: Vec<SymRange> = Vec::new();
        for s in symtab {
            if st_type(s.st_info) != STT_FUNC {
                continue;
            }
            if s.st_size == 0 || s.st_value == 0 {
                continue;
            }
            ranges.push(SymRange {
                start: s.st_value,
                end: s.st_value + s.st_size,
                name_off: s.st_name,
            });
        }
        ranges.sort_by_key(|r| r.start);
        SymTable { ranges }
    }

    pub fn lookup(&self, pc: u64) -> Option<SymRange> {
        if self.ranges.is_empty() {
            return None;
        }
        let mut lo = 0usize;
        let mut hi = self.ranges.len();
        while lo < hi {
            let mid = (lo + hi) / 2;
            if self.ranges[mid].start <= pc {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if lo == 0 {
            return None;
        }
        let r = self.ranges[lo - 1];
        if pc < r.end {
            Some(r)
        } else {
            None
        }
    }
}

/// Read a null-terminated symbol name from `.strtab`.
pub fn name_at<'a>(strtab: &'a [u8], off: u32) -> &'a [u8] {
    let start = off as usize;
    if start >= strtab.len() {
        return &[];
    }
    let mut end = start;
    while end < strtab.len() && strtab[end] != 0 {
        end += 1;
    }
    &strtab[start..end]
}
