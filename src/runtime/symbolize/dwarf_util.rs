// runtime::symbolize::dwarf_util — byte reader + LEB128 decoders.
//
// All readers operate on a `&[u8]` cursor model: take an offset, return
// the value plus the new offset. No allocation, no panics on EOF
// (caller checks bounds). Used by every DWARF section parser.

/// Read a little-endian u8.
#[inline]
pub fn read_u8(buf: &[u8], off: &mut usize) -> Option<u8> {
    if *off >= buf.len() {
        return None;
    }
    let v = buf[*off];
    *off += 1;
    Some(v)
}

#[inline]
pub fn read_u16(buf: &[u8], off: &mut usize) -> Option<u16> {
    if *off + 2 > buf.len() {
        return None;
    }
    let v = u16::from_le_bytes([buf[*off], buf[*off + 1]]);
    *off += 2;
    Some(v)
}

#[inline]
pub fn read_u32(buf: &[u8], off: &mut usize) -> Option<u32> {
    if *off + 4 > buf.len() {
        return None;
    }
    let v = u32::from_le_bytes([
        buf[*off],
        buf[*off + 1],
        buf[*off + 2],
        buf[*off + 3],
    ]);
    *off += 4;
    Some(v)
}

#[inline]
pub fn read_u64(buf: &[u8], off: &mut usize) -> Option<u64> {
    if *off + 8 > buf.len() {
        return None;
    }
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&buf[*off..*off + 8]);
    *off += 8;
    Some(u64::from_le_bytes(bytes))
}

/// DWARF unsigned LEB128. Returns the decoded value and advances `off`.
pub fn read_uleb(buf: &[u8], off: &mut usize) -> Option<u64> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        if *off >= buf.len() {
            return None;
        }
        let b = buf[*off];
        *off += 1;
        result |= ((b & 0x7f) as u64) << shift;
        if (b & 0x80) == 0 {
            return Some(result);
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
}

/// DWARF signed LEB128.
pub fn read_sleb(buf: &[u8], off: &mut usize) -> Option<i64> {
    let mut result: i64 = 0;
    let mut shift: u32 = 0;
    let mut last: u8 = 0;
    loop {
        if *off >= buf.len() {
            return None;
        }
        let b = buf[*off];
        *off += 1;
        result |= ((b & 0x7f) as i64) << shift;
        shift += 7;
        last = b;
        if (b & 0x80) == 0 {
            break;
        }
        if shift >= 64 {
            return None;
        }
    }
    // Sign-extend: if the sign bit (bit 6 of last byte) is set, fill
    // the high bits with 1s.
    if shift < 64 && (last & 0x40) != 0 {
        result |= (-1i64) << shift;
    }
    Some(result)
}

/// Read a null-terminated C string starting at `off`. Advances `off`
/// past the terminator. Returns the string slice (without the NUL).
pub fn read_cstr<'a>(buf: &'a [u8], off: &mut usize) -> Option<&'a [u8]> {
    let start = *off;
    while *off < buf.len() {
        if buf[*off] == 0 {
            let s = &buf[start..*off];
            *off += 1;
            return Some(s);
        }
        *off += 1;
    }
    None
}

/// DWARF "initial length" — either a 4-byte length (DWARF32) or a
/// 12-byte form (0xffffffff sentinel + 8-byte length, DWARF64).
/// Returns `(length, is_64bit)`.
pub fn read_initial_length(buf: &[u8], off: &mut usize) -> Option<(u64, bool)> {
    let first = read_u32(buf, off)?;
    if first == 0xffffffff {
        let len = read_u64(buf, off)?;
        Some((len, true))
    } else if first >= 0xfffffff0 {
        // Reserved range — refuse.
        None
    } else {
        Some((first as u64, false))
    }
}
