// go: file strings/clone.go decls: Clone
//
// strings/clone.go — one function.

#![allow(non_snake_case)]

use crate::gostring::string;

// go: sdk 1.25.5 strings/clone.go:21-23 Clone
/// `strings.Clone(s)` — fresh, independent copy. For our `Arc<[u8]>`
/// backing this forces a non-shared allocation.
pub fn Clone<S: Into<string>>(s: S) -> string {
    let s = s.into();
    return string::from_bytes(s.as_bytes());
}
