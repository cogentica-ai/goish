// go/constant — minimal Goish surface for Go's go/constant package.
//
// 50 stdlib call sites carry `Arc<dyn go::constant::Value>`.
// Implementations (boolVal, intVal, floatVal, stringVal, …) live in
// the ports that need them.

#![allow(non_camel_case_types, non_snake_case)]

use crate::gostring::string;
use crate::types::int;

/// Go's `constant.Kind` — one of Bool / String / Int / Float /
/// Complex / Unknown.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Unknown,
    Bool,
    String,
    Int,
    Float,
    Complex,
}

/// Go's `constant.Value` — the carry trait for compile-time constant
/// values produced by the type-checker.
pub trait Value: Send + Sync {
    fn Kind(&self) -> Kind;
    fn String(&self) -> string;
    fn ExactString(&self) -> string {
        self.String()
    }
}

/// Match Go's `BoolVal`, `StringVal`, `Int64Val` etc as free functions
/// dispatching on the trait object.
pub fn BoolVal(v: &(dyn Value)) -> bool {
    matches!(v.Kind(), Kind::Bool)
}

pub fn StringVal(v: &(dyn Value)) -> string {
    if matches!(v.Kind(), Kind::String) {
        v.String()
    } else {
        string::default()
    }
}

pub fn Int64Val(v: &(dyn Value)) -> (int, bool) {
    let s = v.String();
    let ok = matches!(v.Kind(), Kind::Int);
    let txt: &str = AsRef::<str>::as_ref(&s);
    match txt.parse::<i64>() {
        Ok(n) if ok => (n as int, true),
        _ => (0, false),
    }
}
