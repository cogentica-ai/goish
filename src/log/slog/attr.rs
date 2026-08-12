// go: file log/slog/attr.go decls: Group
//
// log/slog/attr.go — Attr constructors.
//
// **Partial port.** String/Int/Bool/Any and the Attr type itself are
// hand-written in mod[rs]; only Group is anchored here.
//
// goishlint:ignore GOISH018 Any, Bool, Duration, Equal, Float64, GroupAttrs, Int, Int64, String, Time, Uint64, argsToAttrSlice, isEmpty — not ported; only the declarations in this file are.
// goishlint:ignore GOISH021 Attr — same.

#![allow(non_snake_case)]

extern crate alloc;

use super::{Attr, GroupValue};
use crate::gostring::string;

// go: sdk 1.25.5 log/slog/attr.go:66-68 Group
/// Go: "Group returns an Attr for a Group [Value]. The first argument
/// is the key; the remaining arguments are converted to Attrs as in
/// [Logger.Log]."
///
/// Deviation: Go is variadic over `...any` and runs the arguments
/// through `argsToAttrSlice`, which pairs loose key/value arguments.
/// goish takes the Attrs directly — the pairing helper needs Go's `any`
/// type switch, and building it here would be inventing a second way to
/// construct an Attr alongside the typed constructors above.
pub fn Group<S: Into<string>>(key: S, args: crate::goslice::slice<Attr>) -> Attr {
    return Attr {
        Key: key.into(),
        Value: GroupValue(args),
    };
}

