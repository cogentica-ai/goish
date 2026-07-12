// runtime::symbolize::line — DWARF .debug_line decoder.
//
// Each Compilation Unit has a Line Number Program: a small VM that
// emits (address, file, line) "rows" mapping native PCs back to
// source locations. We pre-execute every CU's program at init,
// flatten the rows into one sorted Vec<LineRow>, and binary-search
// at lookup time. Per-program file/dir tables are kept on the side
// so we can resolve `(program_id, file_idx) → "dir/file"` later.
//
// Targets DWARF 4 (which is what current rustc emits). DWARF 2-3 line
// programs are an almost-strict subset and would also decode here;
// DWARF 5 changed the directory/file table format and would need a
// separate parser arm — out of scope for v1 since the binary uses 4.

use alloc::vec::Vec;

use super::dwarf_util::{
    read_cstr, read_initial_length, read_sleb, read_u16, read_u32,
    read_u64, read_u8, read_uleb,
};

#[derive(Clone, Copy)]
pub struct LineRow {
    pub pc: u64,
    pub line: u32,
    /// Index into `Programs::programs` identifying which CU this row
    /// belongs to. Needed to resolve `file_idx` against the right
    /// per-CU file table.
    pub program_id: u32,
    pub file_idx: u32,
}

pub struct FileEntry {
    pub dir_idx: usize,
    pub name: Vec<u8>,
}

pub struct Program {
    pub include_dirs: Vec<Vec<u8>>,
    /// File index 1..N per DWARF 4 spec (index 0 is reserved).
    /// We store entries 1..N, so file_idx of 1 maps to files[0].
    pub files: Vec<FileEntry>,
    pub comp_dir: Vec<u8>,
}

pub struct Programs {
    pub rows: Vec<LineRow>,
    pub programs: Vec<Program>,
}

impl Programs {
    /// Look up the row whose pc range contains `pc`.
    pub fn lookup(&self, pc: u64) -> Option<LineRow> {
        if self.rows.is_empty() {
            return None;
        }
        let mut lo = 0usize;
        let mut hi = self.rows.len();
        while lo < hi {
            let mid = (lo + hi) / 2;
            if self.rows[mid].pc <= pc {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if lo == 0 {
            return None;
        }
        Some(self.rows[lo - 1])
    }

    /// Resolve `(program_id, file_idx)` into a path written into `out`.
    /// Returns the number of bytes written (0 on miss).
    ///
    /// DWARF resolution rules:
    ///   - If filename is absolute, use it as-is.
    ///   - If `dir_idx == 0`, the directory is `comp_dir` (absolute).
    ///   - If `dir_idx > 0`, the directory is `include_dirs[dir_idx-1]`.
    ///     When that include_dir is relative, it's anchored at `comp_dir`,
    ///     so the resolved path is `comp_dir + "/" + include_dir + "/" + name`.
    ///     When it's absolute, comp_dir is skipped.
    pub fn resolve_file(&self, program_id: u32, file_idx: u32, out: &mut [u8]) -> usize {
        let prog = match self.programs.get(program_id as usize) {
            Some(p) => p,
            None => return 0,
        };
        if file_idx == 0 {
            return 0;
        }
        let f = match prog.files.get((file_idx - 1) as usize) {
            Some(f) => f,
            None => return 0,
        };

        let mut o = 0usize;

        // Filename absolute → ignore both comp_dir and include_dir.
        if f.name.first() == Some(&b'/') {
            return copy_into(out, &mut o, &f.name);
        }

        let dir: &[u8] = if f.dir_idx == 0 {
            &prog.comp_dir
        } else {
            match prog.include_dirs.get(f.dir_idx - 1) {
                Some(d) => d,
                None => &[],
            }
        };

        // If dir is relative AND we have a comp_dir AND we're not
        // already using comp_dir as `dir`, prefix it.
        let need_comp_prefix = f.dir_idx != 0
            && !dir.is_empty()
            && dir.first() != Some(&b'/')
            && !prog.comp_dir.is_empty();

        if need_comp_prefix {
            copy_into(out, &mut o, &prog.comp_dir);
            ensure_slash(out, &mut o);
        }
        if !dir.is_empty() {
            copy_into(out, &mut o, dir);
            ensure_slash(out, &mut o);
        } else if f.dir_idx == 0 && !prog.comp_dir.is_empty() {
            // dir_idx 0 with empty `dir` means we DID look at comp_dir
            // and it was empty. Already covered above, no-op here.
        }
        copy_into(out, &mut o, &f.name);
        o
    }
}

#[inline]
fn copy_into(out: &mut [u8], o: &mut usize, src: &[u8]) -> usize {
    let copy = src.len().min(out.len() - *o);
    out[*o..*o + copy].copy_from_slice(&src[..copy]);
    *o += copy;
    *o
}

#[inline]
fn ensure_slash(out: &mut [u8], o: &mut usize) {
    if *o == 0 {
        return;
    }
    if out[*o - 1] == b'/' {
        return;
    }
    if *o < out.len() {
        out[*o] = b'/';
        *o += 1;
    }
}

// ─── Compilation-directory map (built from .debug_info) ──────────────
//
// DWARF 4 line programs DO NOT carry the compilation directory in their
// header — that lives in the CU's `DW_AT_comp_dir`. To resolve
// directory index 0 to a real path we need to thread comp_dir from
// `.debug_info` into each line program. For the v1 symboliser we
// accept missing comp_dir (paths render relative); a follow-up walks
// `.debug_abbrev`/`.debug_info` to plumb it through.

/// Decode all line programs from `.debug_line` into a flat row table.
/// `comp_dirs` is an optional list of `(stmt_list_offset, comp_dir)`
/// pairs from `.debug_info` — caller may pass `&[]` to skip.
pub fn build(debug_line: &[u8], comp_dirs: &[(u64, Vec<u8>)]) -> Programs {
    let mut rows: Vec<LineRow> = Vec::new();
    let mut programs: Vec<Program> = Vec::new();
    let mut off = 0usize;
    while off < debug_line.len() {
        let prog_start = off;
        let (length, _is_64bit) = match read_initial_length(debug_line, &mut off) {
            Some(v) => v,
            None => break,
        };
        let prog_end = off + length as usize;
        if prog_end > debug_line.len() {
            break;
        }
        match decode_program(debug_line, &mut off, prog_end, prog_start, programs.len() as u32, &mut rows, comp_dirs) {
            Some(p) => programs.push(p),
            None => {}
        }
        off = prog_end;
    }
    rows.sort_by_key(|r| r.pc);
    Programs { rows, programs }
}

fn decode_program(
    buf: &[u8],
    off: &mut usize,
    end: usize,
    prog_start: usize,
    program_id: u32,
    rows: &mut Vec<LineRow>,
    comp_dirs: &[(u64, Vec<u8>)],
) -> Option<Program> {
    let header_start = *off;
    let version = read_u16(buf, off)?;
    if version < 2 || version > 4 {
        return None;
    }
    let header_length = read_u32(buf, off)? as usize;
    let opcode_base_off = *off + header_length; // start of opcodes
    let minimum_instruction_length = read_u8(buf, off)?;
    let _max_ops_per_instr = if version >= 4 {
        read_u8(buf, off)?
    } else {
        1
    };
    let default_is_stmt = read_u8(buf, off)?;
    let line_base = read_u8(buf, off)? as i8;
    let line_range = read_u8(buf, off)?;
    let opcode_base = read_u8(buf, off)?;

    if line_range == 0 {
        return None;
    }
    // standard_opcode_lengths: `opcode_base - 1` bytes.
    let mut std_lengths = [0u8; 16];
    for i in 0..(opcode_base.saturating_sub(1) as usize) {
        if i >= std_lengths.len() {
            return None;
        }
        std_lengths[i] = read_u8(buf, off)?;
    }

    // include_directories — null-terminated cstrs until empty cstr.
    let mut include_dirs: Vec<Vec<u8>> = Vec::new();
    loop {
        let s = read_cstr(buf, off)?;
        if s.is_empty() {
            break;
        }
        include_dirs.push(s.to_vec());
    }

    // file_names — entries until empty cstr.
    let mut files: Vec<FileEntry> = Vec::new();
    loop {
        let s = read_cstr(buf, off)?;
        if s.is_empty() {
            break;
        }
        let dir_idx = read_uleb(buf, off)? as usize;
        let _mtime = read_uleb(buf, off)?;
        let _len = read_uleb(buf, off)?;
        files.push(FileEntry {
            dir_idx,
            name: s.to_vec(),
        });
    }

    // Move to start of opcodes.
    *off = opcode_base_off;

    // Look up comp_dir by stmt_list offset (== prog_start).
    let mut comp_dir: Vec<u8> = Vec::new();
    for (so, cd) in comp_dirs {
        if *so as usize == prog_start {
            comp_dir = cd.clone();
            break;
        }
    }

    // Run the VM.
    let mut address: u64 = 0;
    let mut file: u64 = 1;
    let mut line: i64 = 1;
    let mut is_stmt = default_is_stmt != 0;
    let _ = is_stmt;
    let end_sequence = false;
    let _ = end_sequence;

    while *off < end {
        let opcode = read_u8(buf, off)?;
        if opcode == 0 {
            // Extended opcode.
            let ext_len = read_uleb(buf, off)? as usize;
            if ext_len == 0 {
                continue;
            }
            let ext_op = read_u8(buf, off)?;
            match ext_op {
                1 => {
                    // DW_LNE_end_sequence — Goish doesn't propagate this
                    // flag downstream yet; reset row state per DWARF spec.
                    address = 0;
                    file = 1;
                    line = 1;
                }
                2 => {
                    // DW_LNE_set_address — address-size byte value (8 on amd64).
                    address = read_u64(buf, off)?;
                }
                3 => {
                    // DW_LNE_define_file — name (cstr) + dir_idx + mtime + len.
                    let s = read_cstr(buf, off)?;
                    let dir_idx = read_uleb(buf, off)? as usize;
                    let _mt = read_uleb(buf, off)?;
                    let _ln = read_uleb(buf, off)?;
                    files.push(FileEntry {
                        dir_idx,
                        name: s.to_vec(),
                    });
                }
                4 => {
                    // DW_LNE_set_discriminator
                    let _ = read_uleb(buf, off)?;
                }
                _ => {
                    // Unknown — skip ext_len-1 bytes (we already read the op).
                    *off += ext_len.saturating_sub(1);
                }
            }
        } else if opcode < opcode_base {
            // Standard opcode.
            match opcode {
                1 => {
                    // DW_LNS_copy
                    if address != 0 {
                        rows.push(LineRow {
                            pc: address,
                            line: line.max(0) as u32,
                            program_id,
                            file_idx: file as u32,
                        });
                    }
                }
                2 => {
                    // DW_LNS_advance_pc
                    let adv = read_uleb(buf, off)?;
                    address = address.wrapping_add(adv * minimum_instruction_length as u64);
                }
                3 => {
                    // DW_LNS_advance_line
                    let adv = read_sleb(buf, off)?;
                    line = line.wrapping_add(adv);
                }
                4 => {
                    // DW_LNS_set_file
                    file = read_uleb(buf, off)?;
                }
                5 => {
                    // DW_LNS_set_column
                    let _ = read_uleb(buf, off)?;
                }
                6 => {
                    // DW_LNS_negate_stmt
                    is_stmt = !is_stmt;
                }
                7 => {
                    // DW_LNS_set_basic_block — no-op
                }
                8 => {
                    // DW_LNS_const_add_pc
                    let adjusted = 255u32 - opcode_base as u32;
                    let op_adv = adjusted / line_range as u32;
                    address = address.wrapping_add((op_adv as u64) * minimum_instruction_length as u64);
                }
                9 => {
                    // DW_LNS_fixed_advance_pc
                    let inc = read_u16(buf, off)?;
                    address = address.wrapping_add(inc as u64);
                }
                10 | 11 => {
                    // set_prologue_end / set_epilogue_begin — no-op
                }
                12 => {
                    // DW_LNS_set_isa
                    let _ = read_uleb(buf, off)?;
                }
                _ => {
                    // Unknown standard opcode — skip its declared args.
                    let n = std_lengths[(opcode as usize).saturating_sub(1)] as usize;
                    for _ in 0..n {
                        let _ = read_uleb(buf, off)?;
                    }
                }
            }
        } else {
            // Special opcode.
            let adjusted = (opcode - opcode_base) as u32;
            let op_adv = adjusted / line_range as u32;
            let line_inc = (line_base as i32) + (adjusted % line_range as u32) as i32;
            address = address.wrapping_add((op_adv as u64) * minimum_instruction_length as u64);
            line = line.wrapping_add(line_inc as i64);
            if address != 0 {
                rows.push(LineRow {
                    pc: address,
                    line: line.max(0) as u32,
                    program_id,
                    file_idx: file as u32,
                });
            }
        }
    }

    let _ = header_start;

    Some(Program {
        include_dirs,
        files,
        comp_dir,
    })
}
