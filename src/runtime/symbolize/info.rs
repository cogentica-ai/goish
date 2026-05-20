// runtime::symbolize::info — minimal `.debug_info` + `.debug_abbrev`
// walker: just enough to extract `(stmt_list_offset, comp_dir)` for
// each Compilation Unit so the line decoder can build absolute paths.
//
// We DO NOT walk DIE children, function tables, type info, or any of
// the other DWARF machinery. The CU DIE is always the first DIE in
// each unit and carries everything we need at the top level.

use alloc::vec::Vec;

use super::dwarf_util::{
    read_initial_length, read_sleb, read_u16, read_u32, read_u64,
    read_u8, read_uleb,
};

// DW_AT_*
const DW_AT_NAME: u64 = 0x03;
const DW_AT_STMT_LIST: u64 = 0x10;
const DW_AT_COMP_DIR: u64 = 0x1b;

// DW_FORM_*
const DW_FORM_ADDR: u64 = 0x01;
const DW_FORM_BLOCK2: u64 = 0x03;
const DW_FORM_BLOCK4: u64 = 0x04;
const DW_FORM_DATA2: u64 = 0x05;
const DW_FORM_DATA4: u64 = 0x06;
const DW_FORM_DATA8: u64 = 0x07;
const DW_FORM_STRING: u64 = 0x08;
const DW_FORM_BLOCK: u64 = 0x09;
const DW_FORM_BLOCK1: u64 = 0x0a;
const DW_FORM_DATA1: u64 = 0x0b;
const DW_FORM_FLAG: u64 = 0x0c;
const DW_FORM_SDATA: u64 = 0x0d;
const DW_FORM_STRP: u64 = 0x0e;
const DW_FORM_UDATA: u64 = 0x0f;
const DW_FORM_REF_ADDR: u64 = 0x10;
const DW_FORM_REF1: u64 = 0x11;
const DW_FORM_REF2: u64 = 0x12;
const DW_FORM_REF4: u64 = 0x13;
const DW_FORM_REF8: u64 = 0x14;
const DW_FORM_REF_UDATA: u64 = 0x15;
const DW_FORM_INDIRECT: u64 = 0x16;
const DW_FORM_SEC_OFFSET: u64 = 0x17;
const DW_FORM_EXPRLOC: u64 = 0x18;
const DW_FORM_FLAG_PRESENT: u64 = 0x19;
const DW_FORM_REF_SIG8: u64 = 0x20;

#[derive(Clone)]
struct AbbrevAttr {
    name: u64,
    form: u64,
}

#[derive(Clone)]
struct Abbrev {
    code: u64,
    _tag: u64,
    _has_children: bool,
    attrs: Vec<AbbrevAttr>,
}

fn parse_abbrev_table(buf: &[u8], start: usize) -> Vec<Abbrev> {
    let mut out: Vec<Abbrev> = Vec::new();
    let mut off = start;
    loop {
        let code = match read_uleb(buf, &mut off) {
            Some(v) => v,
            None => break,
        };
        if code == 0 {
            break;
        }
        let tag = match read_uleb(buf, &mut off) {
            Some(v) => v,
            None => break,
        };
        let _has_children = match read_u8(buf, &mut off) {
            Some(v) => v != 0,
            None => break,
        };
        let mut attrs: Vec<AbbrevAttr> = Vec::new();
        loop {
            let name = match read_uleb(buf, &mut off) {
                Some(v) => v,
                None => return out,
            };
            let form = match read_uleb(buf, &mut off) {
                Some(v) => v,
                None => return out,
            };
            if name == 0 && form == 0 {
                break;
            }
            attrs.push(AbbrevAttr { name, form });
        }
        out.push(Abbrev {
            code,
            _tag: tag,
            _has_children,
            attrs,
        });
    }
    out
}

/// Skip a single attribute value of the given DWARF form. Returns true
/// on success. Used both when reading the CU DIE (for forms we don't
/// care about) and for skipping attributes wholesale.
fn skip_form(
    info: &[u8],
    off: &mut usize,
    form: u64,
    is_64bit: bool,
    addr_size: u8,
) -> bool {
    match form {
        DW_FORM_ADDR => *off += addr_size as usize,
        DW_FORM_DATA1 | DW_FORM_REF1 | DW_FORM_FLAG => *off += 1,
        DW_FORM_DATA2 | DW_FORM_REF2 => *off += 2,
        DW_FORM_DATA4 | DW_FORM_REF4 => *off += 4,
        DW_FORM_DATA8 | DW_FORM_REF8 | DW_FORM_REF_SIG8 => *off += 8,
        DW_FORM_SDATA => {
            let _ = read_sleb(info, off);
        }
        DW_FORM_UDATA | DW_FORM_REF_UDATA => {
            let _ = read_uleb(info, off);
        }
        DW_FORM_STRING => {
            // Null-terminated.
            while *off < info.len() && info[*off] != 0 {
                *off += 1;
            }
            *off += 1;
        }
        DW_FORM_STRP | DW_FORM_SEC_OFFSET | DW_FORM_REF_ADDR => {
            *off += if is_64bit { 8 } else { 4 };
        }
        DW_FORM_BLOCK1 => {
            let n = match read_u8(info, off) {
                Some(v) => v,
                None => return false,
            } as usize;
            *off += n;
        }
        DW_FORM_BLOCK2 => {
            let n = match read_u16(info, off) {
                Some(v) => v,
                None => return false,
            } as usize;
            *off += n;
        }
        DW_FORM_BLOCK4 => {
            let n = match read_u32(info, off) {
                Some(v) => v,
                None => return false,
            } as usize;
            *off += n;
        }
        DW_FORM_BLOCK | DW_FORM_EXPRLOC => {
            let n = match read_uleb(info, off) {
                Some(v) => v,
                None => return false,
            } as usize;
            *off += n;
        }
        DW_FORM_FLAG_PRESENT => {} // no bytes
        DW_FORM_INDIRECT => {
            // Form is itself a uleb followed by a value of that form.
            let inner = match read_uleb(info, off) {
                Some(v) => v,
                None => return false,
            };
            return skip_form(info, off, inner, is_64bit, addr_size);
        }
        _ => return false,
    }
    true
}

/// Read a strp into a slice of `.debug_str`. Returns `None` if the
/// offset is out of bounds.
fn read_strp_value<'a>(
    info: &[u8],
    off: &mut usize,
    is_64bit: bool,
    debug_str: &'a [u8],
) -> Option<&'a [u8]> {
    let so = if is_64bit {
        read_u64(info, off)? as usize
    } else {
        read_u32(info, off)? as usize
    };
    if so >= debug_str.len() {
        return None;
    }
    let mut end = so;
    while end < debug_str.len() && debug_str[end] != 0 {
        end += 1;
    }
    Some(&debug_str[so..end])
}

fn read_inline_str<'a>(info: &'a [u8], off: &mut usize) -> Option<&'a [u8]> {
    let start = *off;
    while *off < info.len() && info[*off] != 0 {
        *off += 1;
    }
    let s = &info[start..*off];
    if *off < info.len() {
        *off += 1;
    }
    Some(s)
}

fn read_sec_offset(info: &[u8], off: &mut usize, is_64bit: bool) -> Option<u64> {
    if is_64bit {
        read_u64(info, off)
    } else {
        Some(read_u32(info, off)? as u64)
    }
}

/// Walk every CU in `.debug_info`, returning `(stmt_list_offset,
/// comp_dir)` for each.
pub fn collect_comp_dirs(
    debug_info: &[u8],
    debug_abbrev: &[u8],
    debug_str: &[u8],
) -> Vec<(u64, Vec<u8>)> {
    let mut out: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut off = 0usize;

    while off < debug_info.len() {
        let unit_start = off;
        let (length, is_64bit) = match read_initial_length(debug_info, &mut off) {
            Some(v) => v,
            None => break,
        };
        let unit_end = off + length as usize;
        if unit_end > debug_info.len() {
            break;
        }
        let _version = match read_u16(debug_info, &mut off) {
            Some(v) => v,
            None => break,
        };
        let abbrev_offset = match read_sec_offset(debug_info, &mut off, is_64bit) {
            Some(v) => v as usize,
            None => break,
        };
        let addr_size = match read_u8(debug_info, &mut off) {
            Some(v) => v,
            None => break,
        };

        // First DIE — should be DW_TAG_compile_unit.
        let abbrev_code = match read_uleb(debug_info, &mut off) {
            Some(v) => v,
            None => {
                off = unit_end;
                continue;
            }
        };
        if abbrev_code == 0 {
            off = unit_end;
            continue;
        }

        let abbrevs = parse_abbrev_table(debug_abbrev, abbrev_offset);
        let abbrev = match abbrevs.iter().find(|a| a.code == abbrev_code) {
            Some(a) => a,
            None => {
                off = unit_end;
                continue;
            }
        };

        let mut stmt_list: Option<u64> = None;
        let mut comp_dir: Option<Vec<u8>> = None;

        for attr in &abbrev.attrs {
            // Resolve indirect form.
            let mut form = attr.form;
            if form == DW_FORM_INDIRECT {
                form = match read_uleb(debug_info, &mut off) {
                    Some(v) => v,
                    None => break,
                };
            }
            match attr.name {
                DW_AT_STMT_LIST => match form {
                    DW_FORM_SEC_OFFSET => {
                        if let Some(v) = read_sec_offset(debug_info, &mut off, is_64bit) {
                            stmt_list = Some(v);
                        } else {
                            break;
                        }
                    }
                    DW_FORM_DATA4 => {
                        if let Some(v) = read_u32(debug_info, &mut off) {
                            stmt_list = Some(v as u64);
                        } else {
                            break;
                        }
                    }
                    DW_FORM_DATA8 => {
                        if let Some(v) = read_u64(debug_info, &mut off) {
                            stmt_list = Some(v);
                        } else {
                            break;
                        }
                    }
                    _ => {
                        if !skip_form(debug_info, &mut off, form, is_64bit, addr_size) {
                            break;
                        }
                    }
                },
                DW_AT_COMP_DIR => match form {
                    DW_FORM_STRP => {
                        if let Some(s) = read_strp_value(debug_info, &mut off, is_64bit, debug_str) {
                            comp_dir = Some(s.to_vec());
                        } else {
                            break;
                        }
                    }
                    DW_FORM_STRING => {
                        if let Some(s) = read_inline_str(debug_info, &mut off) {
                            comp_dir = Some(s.to_vec());
                        } else {
                            break;
                        }
                    }
                    _ => {
                        if !skip_form(debug_info, &mut off, form, is_64bit, addr_size) {
                            break;
                        }
                    }
                },
                _ => {
                    if !skip_form(debug_info, &mut off, form, is_64bit, addr_size) {
                        break;
                    }
                }
            }
        }

        if let (Some(sl), Some(cd)) = (stmt_list, comp_dir) {
            out.push((sl, cd));
        }
        let _ = unit_start;
        off = unit_end;
    }
    let _ = DW_AT_NAME;
    out
}
