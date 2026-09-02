// go: file math/big/intconv.go decls: Int.Text, Int.Append, Int.String
//
// math/big/intconv.go — the text side of Int: rendering to a base, and
// appending that rendering to a caller's buffer. Go keeps it separate
// from int.go, so goish does too (GOISH015). The scanning half of the
// same Go file (`scan`, `Scan`, `scanSign`, `byteReader`) and `Format`
// depend on `fmt.State` / `fmt.ScanState` and are not ported yet, so
// this file does not claim to be complete — the manifest above lists
// exactly what is here.
//
// The digit conversion itself lives in `itoa`, which is Go's and lives
// in natconv.go; it stays in the module root until that file is split
// out in turn.
//
// goishlint:ignore GOISH018 writeMultiple, Format, scan, Scan, scanSign, ReadByte, UnreadByte — the scanning and fmt.Formatter halves of intconv.go. Both are defined against interfaces goish has not ported: Format takes a fmt.State and Scan a fmt.ScanState, and scan/scanSign/byteReader exist only to feed Scan. Nothing in goish's crypto reaches them; they are a deliberate omission, not an oversight, and this list is the record of exactly what is missing.
// goishlint:ignore GOISH021 byteReader — the io.ByteScanner adapter that exists only for Scan; see the GOISH018 note above.

#![allow(non_snake_case)]

extern crate alloc;

use super::{itoa, Int, MAX_BASE};
use crate::types::int;

impl Int {
    // go: sdk 1.25.5 math/big/intconv.go:21-28 Int.Text
    /// `(*Int).Text(base)` — string representation of `self` in `base`.
    /// `base` must be between 2 and 62 inclusive; lower-case letters
    /// `a`..`z` cover digit values 10..35 and upper-case `A`..`Z` cover
    /// 36..61. No `0x`-style prefix is added. Negative values are
    /// prefixed with `-`.
    pub fn Text(&self, base: int) -> crate::string {
        if base < 2 || base > MAX_BASE {
            panic!("big::Int::Text: invalid base");
        }
        let buf = itoa(self.neg, &self.abs, base);
        return crate::gostring::string::from_bytes(&buf);
    }

    // go: sdk 1.25.5 math/big/intconv.go:30-36 Int.Append
    /// `(*Int).Append(buf, base)` — append the base-`base` text of
    /// `self` (as produced by `Text`) to `buf` and return the extended
    /// slice. `base` must be 2..=62.
    pub fn Append(
        &self,
        buf: crate::slice<crate::types::byte>,
        base: int,
    ) -> crate::slice<crate::types::byte> {
        if base < 2 || base > MAX_BASE {
            panic!("big::Int::Append: invalid base");
        }
        let mut out = buf.__into_vec();
        out.extend_from_slice(&itoa(self.neg, &self.abs, base));
        return crate::slice::<crate::types::byte>::__from_vec(out);
    }

    // go: sdk 1.25.5 math/big/intconv.go:39-41 Int.String
    /// Go: "String returns the decimal representation of x as generated
    /// by x.Text(10)."
    ///
    /// Go's `Text` answers "<nil>" for a nil `*Int`; goish takes
    /// `&self`, so there is no nil receiver to answer for.
    pub fn String(&self) -> crate::string {
        // Go: return x.Text(10)
        return self.Text(10);
    }
}
