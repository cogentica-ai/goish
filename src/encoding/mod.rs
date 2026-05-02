// encoding — Go's `encoding` package tree.
//
// v1 ships `encoding/json`, `encoding/binary`, `encoding/hex`,
// `encoding/base64`. Other subpackages (`encoding/csv`,
// `encoding/gob`, etc.) land later.

pub mod base32;
pub mod base64;
pub mod binary;
pub mod hex;
pub mod json;
