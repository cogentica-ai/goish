// go: file strconv/atob.go decls: ParseBool, FormatBool, AppendBool
//
// atob.go — ParseBool, FormatBool, AppendBool.

extern crate alloc;

use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::gostring::string;
use crate::types::byte;

use super::*;

// ─── Bool ─────────────────────────────────────────────────────────────

// go: sdk 1.25.5 strconv/atob.go:10-18 ParseBool
pub fn ParseBool<S: Into<string>>(str_: S) -> (bool, error) {
    let s = str_.into();
    let b = s.as_bytes();
    return match b {
        b"1" | b"t" | b"T" | b"true" | b"TRUE" | b"True" => (true, nil),
        b"0" | b"f" | b"F" | b"false" | b"FALSE" | b"False" => (false, nil),
        _ => (false, syntaxError("ParseBool", s)),
    };
}

// go: sdk 1.25.5 strconv/atob.go:21-26 FormatBool
pub fn FormatBool(b: bool) -> string {
    return if b {
        string::from_static("true")
    } else {
        string::from_static("false")
    };
}

// go: sdk 1.25.5 strconv/atob.go:30-35 AppendBool
pub fn AppendBool(dst: slice<byte>, b: bool) -> slice<byte> {
    let mut v = dst.__into_vec();
    if b {
        v.extend_from_slice(b"true");
    } else {
        v.extend_from_slice(b"false");
    }
    return slice::__from_vec(v);
}
