// go: file encoding/binary/native_endian_little.go decls: nativeEndian.String
// goishlint:ignore GOISH021 nativeEndian, NativeEndian — Go declares
//     `type nativeEndian struct{ littleEndian }`, an embedding that
//     inherits every method; Rust has no embedding, so `NativeEndian`
//     is its own unit struct forwarding to `LittleEndian`.

use crate::gostring::string;

use super::{ByteOrder, LittleEndian};

/// Go: `binary.NativeEndian` — the byte order of the machine the
/// program is running on. goish targets x86-64, which is little-endian,
/// so this is `LittleEndian` under another name and another `String()`,
/// exactly as Go's `native_endian_little.go` declares it.
#[derive(Copy, Clone)]
pub struct NativeEndian;

impl ByteOrder for NativeEndian {
    // go: none — goish idiom: forwards to LittleEndian, which carries the anchor.
    fn Uint16(self, b: &[crate::types::byte]) -> u16 {
        return LittleEndian.Uint16(b);
    }
    // go: none — goish idiom: forwards to LittleEndian, which carries the anchor.
    fn Uint32(self, b: &[crate::types::byte]) -> u32 {
        return LittleEndian.Uint32(b);
    }
    // go: none — goish idiom: forwards to LittleEndian, which carries the anchor.
    fn Uint64(self, b: &[crate::types::byte]) -> u64 {
        return LittleEndian.Uint64(b);
    }
    // go: none — goish idiom: forwards to LittleEndian, which carries the anchor.
    fn PutUint16(self, b: &mut [crate::types::byte], v: u16) {
        LittleEndian::PutUint16(LittleEndian, b, v);
    }
    // go: none — goish idiom: forwards to LittleEndian, which carries the anchor.
    fn PutUint32(self, b: &mut [crate::types::byte], v: u32) {
        LittleEndian::PutUint32(LittleEndian, b, v);
    }
    // go: none — goish idiom: forwards to LittleEndian, which carries the anchor.
    fn PutUint64(self, b: &mut [crate::types::byte], v: u64) {
        LittleEndian::PutUint64(LittleEndian, b, v);
    }
    // go: none — goish idiom: forwards to LittleEndian, which carries the anchor.
    fn String(self) -> string {
        return string::from_static("NativeEndian");
    }
    // go: none — goish idiom: forwards to LittleEndian, which carries the anchor.
    fn IsBigEndian(self) -> bool {
        return false;
    }
}
