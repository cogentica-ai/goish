// goishlint:ignore GOISH018 NewWriter, Writer.SetOffset, Writer.Flush, Writer.SetComment, Writer.Close, Writer.Create, Writer.CreateHeader, Writer.prepare, Writer.CreateRaw, Writer.Copy, Writer.RegisterCompressor, Writer.AddFS, writeHeader, fileWriter.Write, fileWriter.close, dirWriter.Write, countWriter.Write, nopCloser.Close, writeBuf.uint8, writeBuf.uint16, writeBuf.uint32, writeBuf.uint64, header.FileHeader, compressor, writeDataDescriptor — the whole WRITER, absent from this slice. `detectUTF8` is here because `readDirectoryHeader` in reader.go calls it and Go declares it in this file; the writer itself is the next slice after reader.go, since reading an archive is the half that has to be right about a hostile input.
// goishlint:ignore GOISH021 Writer, header, fileWriter, dirWriter, countWriter, nopCloser, writeBuf, errLongName, errLongExtra — the writer's types and its two length-limit errors, absent with the writer above.
// go: file archive/zip/writer.go decls: detectUTF8
//
// archive/zip/writer.go — one function, for now.
//
// `detectUTF8` is the writer's, but the READER calls it: a central
// directory header's name and comment are raw bytes, and Go decides
// whether to set FileHeader.NonUTF8 by running exactly this test over
// them. It lives here because Go declares it here and GOISH015 maps
// one Go file to one `.rs`.

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(dead_code)]

extern crate alloc;

use crate::byte;

// go: sdk 1.25.5 archive/zip/writer.go:231-249 detectUTF8
/// Go: "Officially, ZIP uses CP-437, but many readers use the system's
/// local character encoding. Most encoding are compatible with a large
/// subset of CP-437, which itself is ASCII-like. Forbid 0x7e and 0x5c
/// since EUC-KR and Shift-JIS replace those characters with localized
/// currency and overline characters."
///
/// Returns `(valid, require)`: valid is false the moment a byte
/// sequence is not UTF-8 at all; require becomes true once some
/// character outside the safe CP-437 subset appears, which is what
/// tells the writer it must set the UTF-8 flag.
///
/// The parameter is BYTES, not `&str`. Go's `s` is a `string`, which is
/// arbitrary bytes, and deciding whether those bytes are valid UTF-8 is
/// the entire job — a `&str` cannot hold the failing input, and goish's
/// `string: AsRef<str>` would silently truncate it at the first invalid
/// byte. `readDirectoryHeader` feeds it a name read straight off the
/// wire.
pub fn detectUTF8(s: &[byte]) -> (bool, bool) {
    let mut require = false;
    let mut i: usize = 0;
    while i < s.len() {
        let (r, size) = crate::unicode::utf8::DecodeRune(&s[i..]);
        let size = size as usize;
        i += size;
        if r < 0x20 || r > 0x7d || r == 0x5c {
            if !crate::unicode::utf8::ValidRune(r)
                || (r == crate::unicode::utf8::RuneError && size == 1)
            {
                return (false, false);
            }
            require = true;
        }
    }
    return (true, require);
}
