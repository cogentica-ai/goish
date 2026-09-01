// go: package cmp
//
// cmp — Go's `cmp` package (Go 1.21+), ported.
//
//   Go                                    goish
//   ───────────────────────────────────   ─────────────────────────────
//   ok := cmp.Less(a, b)                  let ok = cmp::Less(&a, &b);
//   c  := cmp.Compare(a, b)               let c  = cmp::Compare(&a, &b);
//   v  := cmp.Or(x, y, z)                 let v  = cmp::Or(&[x, y, z]);

#![allow(non_snake_case)]

#[path = "cmp.rs"]
mod cmp_go;
pub use cmp_go::*;
