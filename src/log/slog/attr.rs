// go: file log/slog/attr.go decls: Group, Any, argsToAttrSlice, Int64, Uint64, Float64, Duration, Time, Attr.String, Attr.Equal, Attr.isEmpty
//
// log/slog/attr.go — Attr constructors.
//
// String/Int/Bool and the Attr type itself are hand-written in the
// module root; the typed constructors, `Attr.String`, `Attr.Equal` and
// `Attr.isEmpty` are ported here.
//
// goishlint:ignore GOISH018 Bool, GroupAttrs, Int, String — `Bool`, `Int` and `String` are hand-written in the module root, where the Attr type itself lives; `GroupAttrs` takes a []Attr where goish's `Group` already does.
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

// ─── Typed Attr constructors (attr.go:26) ───────────────────────────

// go: sdk 1.25.5 log/slog/attr.go:23-25 Int64
/// Go: "Int64 returns an Attr for an int64."
pub fn Int64<S: Into<string>>(key: S, value: crate::types::int) -> Attr {
    return Attr {
        Key: key.into(),
        Value: super::Int64Value(value),
    };
}

// go: sdk 1.25.5 log/slog/attr.go:34-36 Uint64
/// Go: "Uint64 returns an Attr for a uint64."
pub fn Uint64<S: Into<string>>(key: S, v: u64) -> Attr {
    return Attr {
        Key: key.into(),
        Value: super::Uint64Value(v),
    };
}

// go: sdk 1.25.5 log/slog/attr.go:39-41 Float64
/// Go: "Float64 returns an Attr for a floating-point number."
pub fn Float64<S: Into<string>>(key: S, v: f64) -> Attr {
    return Attr {
        Key: key.into(),
        Value: super::Float64Value(v),
    };
}

// go: sdk 1.25.5 log/slog/attr.go:55-57 Duration
/// Go: "Duration returns an Attr for a [time.Duration]."
pub fn Duration<S: Into<string>>(key: S, v: crate::time::Duration) -> Attr {
    return Attr {
        Key: key.into(),
        Value: super::DurationValue(v),
    };
}

// go: sdk 1.25.5 log/slog/attr.go:50-52 Time
/// Go: "Time returns an Attr for a [time.Time]. It discards the
/// monotonic portion."
pub fn Time<S: Into<string>>(key: S, v: crate::time::Time) -> Attr {
    return Attr {
        Key: key.into(),
        Value: super::TimeValue(v),
    };
}

// ─── Attr methods (attr.go:79) ──────────────────────────────────────

impl Attr {
    // go: sdk 1.25.5 log/slog/attr.go:102-104 Attr.String
    /// Go: `return a.Key + "=" + a.Value.String()`
    pub fn String(&self) -> string {
        let mut b: alloc::vec::Vec<crate::types::byte> = alloc::vec::Vec::new();
        super::appendAttrString(self, &mut b);
        return string::__from_vec(b);
    }

    // go: sdk 1.25.5 log/slog/attr.go:98-100 Attr.Equal
    /// Go: "Equal reports whether a and b have equal keys and values."
    pub fn Equal(&self, b: &Attr) -> bool {
        return self.Key == b.Key && self.Value == b.Value;
    }

    // go: sdk 1.25.5 log/slog/attr.go:108-110 Attr.isEmpty
    /// Go: `return a.Key == "" && a.Value.num == 0 && a.Value.any == nil`
    ///
    /// Note this is NOT "the key is empty": an Attr with an empty key
    /// and a real value survives, and the handlers print it as `""=v`.
    pub fn isEmpty(&self) -> bool {
        return self.Key.Len() == 0
            && self.Value.Kind() == super::KindAny
            && self.Value.any.IsNil();
    }
}

// go: none — goish idiom: Go's `fmt` finds `String()` by structural
// assertion, so `%%v` and `%%s` on a value whose METHOD SET includes it
// print through it. goish's printer dispatches on `Format`, which a
// type reaches through `Stringer`, and these did not implement it —
// so `fmt.Printf("%%v", x)`, entirely ordinary Go, did not compile.
//
// Only VALUE-receiver String methods are bridged. Go puts a
// pointer-receiver String in the POINTER's method set only, so
// printing the value prints the struct instead; goish has no
// value/pointer distinction, and implementing Stringer for those types
// would print where Go does not. net.IPNet, url.URL, url.Userinfo,
// http.Cookie, mail.Address and regexp.Regexp are left alone for that
// reason.
impl crate::fmt::Stringer for Attr {
    // go: none — goish idiom: see the note above.
    fn String(&self) -> crate::gostring::string {
        let v = self;
        return Attr::String(v);
    }
}
