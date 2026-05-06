// runtime::symbolize::elf — minimal ELF64 reader.
//
// Reads section headers and looks up sections by name. The full ELF
// spec is huge; we only need:
//   - the section header table (e_shoff / e_shentsize / e_shnum)
//   - the section-name string table (e_shstrndx)
//   - per-section: sh_offset, sh_size (so we can return a byte slice)
//
// Linux x86_64 binaries are always little-endian ELF64. We assume that
// and refuse anything else.

#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64Ehdr {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Elf64Shdr {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
}

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;

/// Borrowed view of a parsed ELF file. The underlying bytes must stay
/// alive for the lifetime of this view (in our case the file is
/// mmap'd for the lifetime of the process — see `symbolize::init`).
pub struct ElfView<'a> {
    bytes: &'a [u8],
    shoff: usize,
    shentsize: usize,
    shnum: usize,
    shstr: &'a [u8],
}

impl<'a> ElfView<'a> {
    /// Parse the ELF header. Returns `None` if the file isn't an
    /// ELF64 LSB executable that we can read.
    pub fn open(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() < core::mem::size_of::<Elf64Ehdr>() {
            return None;
        }
        if &bytes[0..4] != &ELF_MAGIC[..] {
            return None;
        }
        if bytes[4] != ELFCLASS64 || bytes[5] != ELFDATA2LSB {
            return None;
        }
        let ehdr = unsafe { *(bytes.as_ptr() as *const Elf64Ehdr) };
        let shoff = ehdr.e_shoff as usize;
        let shentsize = ehdr.e_shentsize as usize;
        let shnum = ehdr.e_shnum as usize;
        let shstrndx = ehdr.e_shstrndx as usize;

        if shentsize < core::mem::size_of::<Elf64Shdr>() || shnum == 0 {
            return None;
        }
        let table_end = shoff.checked_add(shentsize.checked_mul(shnum)?)?;
        if table_end > bytes.len() {
            return None;
        }

        // Section-name string table is the section at e_shstrndx.
        if shstrndx >= shnum {
            return None;
        }
        let shstr_hdr_off = shoff + shstrndx * shentsize;
        let shstr_hdr =
            unsafe { *(bytes.as_ptr().add(shstr_hdr_off) as *const Elf64Shdr) };
        let shstr_off = shstr_hdr.sh_offset as usize;
        let shstr_size = shstr_hdr.sh_size as usize;
        if shstr_off.checked_add(shstr_size)? > bytes.len() {
            return None;
        }
        let shstr = &bytes[shstr_off..shstr_off + shstr_size];

        Some(ElfView {
            bytes,
            shoff,
            shentsize,
            shnum,
            shstr,
        })
    }

    fn shdr(&self, i: usize) -> Elf64Shdr {
        let off = self.shoff + i * self.shentsize;
        unsafe { *(self.bytes.as_ptr().add(off) as *const Elf64Shdr) }
    }

    fn name_at(&self, off: u32) -> &'a [u8] {
        let start = off as usize;
        if start >= self.shstr.len() {
            return &[];
        }
        let mut end = start;
        while end < self.shstr.len() && self.shstr[end] != 0 {
            end += 1;
        }
        &self.shstr[start..end]
    }

    /// Look up a section by name. Returns its raw bytes from the file.
    pub fn section(&self, name: &[u8]) -> Option<&'a [u8]> {
        let mut i = 0;
        while i < self.shnum {
            let hdr = self.shdr(i);
            if self.name_at(hdr.sh_name) == name {
                let off = hdr.sh_offset as usize;
                let size = hdr.sh_size as usize;
                if off.checked_add(size)? <= self.bytes.len() {
                    return Some(&self.bytes[off..off + size]);
                }
                return None;
            }
            i += 1;
        }
        None
    }

    /// Find the section header index by name (needed when one section
    /// references another via sh_link).
    pub fn section_index(&self, name: &[u8]) -> Option<usize> {
        let mut i = 0;
        while i < self.shnum {
            let hdr = self.shdr(i);
            if self.name_at(hdr.sh_name) == name {
                return Some(i);
            }
            i += 1;
        }
        None
    }
}

// ─── ELF symbol table ────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Elf64Sym {
    pub st_name: u32,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u16,
    pub st_value: u64,
    pub st_size: u64,
}

/// Parse `.symtab` into an array view of `Elf64Sym` entries.
pub fn symtab_entries(symtab: &[u8]) -> &[Elf64Sym] {
    let n = symtab.len() / core::mem::size_of::<Elf64Sym>();
    unsafe { core::slice::from_raw_parts(symtab.as_ptr() as *const Elf64Sym, n) }
}

/// `STT_FUNC` — symbol is a function.
pub const STT_FUNC: u8 = 2;

#[inline]
pub fn st_type(info: u8) -> u8 {
    info & 0xf
}
