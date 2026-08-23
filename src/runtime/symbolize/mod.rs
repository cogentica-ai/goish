// runtime::symbolize — in-process DWARF symboliser.
//
// At `__goish_rt0` startup we mmap `/proc/self/exe` read-only, parse
// out `.symtab`/`.strtab`/`.debug_info`/`.debug_abbrev`/`.debug_str`/
// `.debug_line`, and pre-build:
//   - sorted symbol-range table     (PC → mangled fn name + offset)
//   - per-CU comp_dir map            (so file paths are absolute)
//   - flat sorted line-row table     (PC → file_idx + line)
//   - per-program file/dir tables    (file_idx → "dir/name")
//
// Lookups are then a pair of binary searches with no allocation —
// safe to call from the SIGSEGV signal handler. The mmap stays for
// the process lifetime; .debug_* sections live on disk only (no LOAD
// segment maps them) so we have to read the file ourselves.

use alloc::vec::Vec;

use crate::runtime::spin::SpinLock;
use crate::syscall;

pub mod aranges;
pub mod demangle;
pub mod dwarf_util;
pub mod elf;
pub mod info;
pub mod line;
pub mod symtab;

use elf::{symtab_entries, ElfView};

/// Resolved symbol info for a single PC. Fields are owned (no
/// borrowing into mmap'd memory) so the value can outlive any lock.
pub struct SymInfo {
    pub fn_name: [u8; 256],
    pub fn_name_len: usize,
    pub fn_offset: u64,
    pub file: [u8; 512],
    pub file_len: usize,
    pub line: u32,
}

impl Default for SymInfo {
    fn default() -> Self {
        Self {
            fn_name: [0u8; 256],
            fn_name_len: 0,
            fn_offset: 0,
            file: [0u8; 512],
            file_len: 0,
            line: 0,
        }
    }
}

struct Tables {
    symtab: symtab::SymTable,
    strtab: &'static [u8],
    lines: line::Programs,
}

static TABLES: SpinLock<Option<Tables>> = SpinLock::new(None);

/// Initialise the symboliser. Call once at startup before any signal
/// handler that depends on it. Idempotent (subsequent calls no-op).
pub fn init() {
    {
        let g = TABLES.lock();
        if g.is_some() {
            return;
        }
    }

    // Open /proc/self/exe.
    let path = b"/proc/self/exe\0";
    let fd = syscall::Open(path.as_ptr(), syscall::O_RDONLY, 0);
    if fd < 0 {
        return;
    }

    // Stat for size.
    let mut st = syscall::Stat_t::default();
    let r = syscall::Fstat(fd, &mut st);
    if r != 0 || st.st_size <= 0 {
        syscall::Close(fd);
        return;
    }
    let size = st.st_size as usize;

    // mmap the whole file. Read-only, private. Lives for the process
    // lifetime — never munmap'd.
    let base = syscall::Mmap(
        core::ptr::null_mut(),
        size,
        syscall::PROT_READ,
        syscall::MAP_PRIVATE,
        fd,
        0,
    );
    syscall::Close(fd);
    if (base as isize) <= 0 {
        return;
    }
    let bytes: &'static [u8] = unsafe { core::slice::from_raw_parts(base, size) };

    let elf = match ElfView::open(bytes) {
        Some(v) => v,
        None => return,
    };

    // Pull sections.
    let symtab_bytes = match elf.section(b".symtab") {
        Some(b) => b,
        None => return,
    };
    let strtab_bytes = match elf.section(b".strtab") {
        Some(b) => b,
        None => return,
    };
    let debug_info = elf.section(b".debug_info").unwrap_or(&[]);
    let debug_abbrev = elf.section(b".debug_abbrev").unwrap_or(&[]);
    let debug_str = elf.section(b".debug_str").unwrap_or(&[]);
    let debug_line = elf.section(b".debug_line").unwrap_or(&[]);

    // Symbol table.
    let entries = symtab_entries(symtab_bytes);
    let symtab = symtab::SymTable::build(entries);

    // Comp_dir per CU (so line-program file paths get absolute prefix).
    let comp_dirs: Vec<(u64, Vec<u8>)> = if !debug_info.is_empty() && !debug_abbrev.is_empty() {
        info::collect_comp_dirs(debug_info, debug_abbrev, debug_str)
    } else {
        Vec::new()
    };

    // Line programs.
    let lines = if !debug_line.is_empty() {
        line::build(debug_line, &comp_dirs)
    } else {
        line::Programs {
            rows: Vec::new(),
            programs: Vec::new(),
        }
    };

    let mut g = TABLES.lock();
    *g = Some(Tables {
        symtab,
        strtab: strtab_bytes,
        lines,
    });

    // `aranges` module is currently unused but kept for a follow-up
    // that prefers .debug_aranges over walking the line table when
    // we just want CU bounds. Touch it so dead-code lint stays quiet.
    let _ = aranges::lookup;
}

/// Resolve `pc` to symbol info. Returns false if the symboliser
/// hasn't been initialised, the PC isn't in any function, or the
/// lookups all miss. Async-signal-safe: only acquires the SpinLock
/// briefly to read pointers, then drops it before doing any decoding.
pub fn symbolize(pc: u64, out: &mut SymInfo) -> bool {
    out.fn_name_len = 0;
    out.file_len = 0;
    out.line = 0;
    out.fn_offset = 0;

    // Lock-free-ish snapshot: take the SpinLock briefly, copy out the
    // raw refs we need, drop the lock. The Tables instance stays live
    // (it's behind `Option<Tables>` in a static — once set, never
    // cleared), so the borrow remains valid until the next init,
    // which never happens after startup.
    let (sym_ptr, str_bytes, lines_ptr) = {
        let g = TABLES.lock();
        match &*g {
            Some(t) => (
                &t.symtab as *const symtab::SymTable,
                t.strtab,
                &t.lines as *const line::Programs,
            ),
            None => return false,
        }
    };
    let sym = unsafe { &*sym_ptr };
    let lines = unsafe { &*lines_ptr };

    // Symbol name.
    if let Some(r) = sym.lookup(pc) {
        let raw = symtab::name_at(str_bytes, r.name_off);
        let n = demangle::demangle(raw, &mut out.fn_name);
        if n > 0 {
            out.fn_name_len = n;
        } else {
            // Fall back to raw symbol.
            let copy = raw.len().min(out.fn_name.len());
            out.fn_name[..copy].copy_from_slice(&raw[..copy]);
            out.fn_name_len = copy;
        }
        out.fn_offset = pc - r.start;
    }

    // File:line.
    if let Some(row) = lines.lookup(pc) {
        out.line = row.line;
        out.file_len = lines.resolve_file(row.program_id, row.file_idx, &mut out.file);
    }

    out.fn_name_len > 0 || out.file_len > 0
}
