// go — Goish carry of the `go/...` stdlib namespace (go/types, go/ast,
// go/constant, etc).
//
// These modules host the *trait surfaces* the reasoner cache shows
// goishc will emit `Arc<dyn ...>` against (146 + 66 + 50 = 262 call
// sites across stdlib). The traits are minimal scaffolding — concrete
// implementations live in the ports that need them. Adding a stub
// here is what makes `Arc<dyn go::types::Type>` compile at the call
// site; the implementing port type fills in the methods.

#![allow(non_camel_case_types, non_snake_case)]

pub mod ast;
pub mod constant;
pub mod types;
