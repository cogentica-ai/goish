// go: file log/slog/attr.go decls: Group, Any, argsToAttrSlice
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
use crate::goslice::slice;
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


// go: sdk 1.25.5 log/slog/attr.go:93-95 Any
/// Go: "Any returns an Attr for the supplied value."
///
/// Corrects goish's earlier shape. This used to take an `error`, with a
/// note saying "logr only uses it with errors; widen if needed" — but
/// Go's takes `any`, and `argsToAttr` below depends on that: every
/// unpaired or non-string argument becomes `Any(badKey, x)`, which is
/// impossible to express if the value must be an error.
pub fn Any<S: Into<string>>(key: S, value: crate::goany::Any) -> Attr {
    return Attr {
        Key: key.into(),
        Value: super::AnyValue(value),
    };
}

// go: sdk 1.25.5 log/slog/attr.go:79-89 argsToAttrSlice
/// Go: consume a loose `...any` argument list into Attrs, pairing keys
/// with values.
pub fn argsToAttrSlice(args: crate::goslice::slice<crate::goany::Any>) -> slice<Attr> {
    let mut attrs: alloc::vec::Vec<Attr> = alloc::vec::Vec::new();
    let mut i: crate::types::int = 0;
    while i < args.Len() {
        let (attr, consumed) = super::argsToAttr(&args, i);
        attrs.push(attr);
        i += consumed;
    }
    return slice::__from_vec(attrs);
}
