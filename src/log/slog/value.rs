// go: file log/slog/value.go decls: AnyValue, Value.Resolve, GroupValue, countEmptyGroups, Value.isEmptyGroup, StringValue, IntValue, Int64Value, Uint64Value, Float64Value, BoolValue, DurationValue, TimeValue, Kind.String, Value.String, Value.append
//
// log/slog/value.go — the group constructor and its emptiness pruning.
//
// **Partial port.** The typed Value constructors live in mod[rs] and
// predate this file; only the group path is anchored here.
//
// goishlint:ignore GOISH018 Any, Bool, BoolValue, Duration, DurationValue, Equal, Float64, Float64Value, Group, Int64, Int64Value, IntValue, Kind, LogValuer, String, StringValue, Time, TimeValue, Uint64, Uint64Value, append, bool, duration, float, group, stack, str, time — not ported; only the declarations in this file are.
// goishlint:ignore GOISH021 Kind, KindAny, KindBool, KindDuration, KindFloat64, KindGroup, KindInt64, KindLogValuer, KindString, KindTime, KindUint64, LogValuer, Value, kind, kindStrings, groupptr, stringptr, timeLocation, timeTime — same. The four
// pointer-shaped types are Go's unsafe packing of a Value's payload;
// goish carries the payload in `any` and has nothing to pack.

#![allow(non_snake_case)]

extern crate alloc;

use super::{Attr, GoishAny, KindGroup, Value};
use crate::types::int;

// ─── groups ──────────────────────────────────────────────────────────

// go: sdk 1.25.5 log/slog/value.go:446-454 Value.isEmptyGroup
/// Go: "We do not need to recursively examine the group's Attrs for
/// emptiness, because GroupValue removed them when the group was
/// constructed, and groups are immutable."
///
/// That invariant is the reason this is a shallow check, and it only
/// holds because `GroupValue` prunes on the way in. A `GroupValue` that
/// skipped the pruning would make this quietly wrong for nested groups.
pub fn isEmptyGroup(v: &Value) -> bool {
    if v.Kind() != KindGroup {
        return false;
    }
    return group_of(v).Len() == 0;
}

// go: sdk 1.25.5 log/slog/value.go:196-204 countEmptyGroups
/// Go: count how many of `as` are empty groups, so `GroupValue` can
/// size its replacement slice exactly once.
pub fn countEmptyGroups(as_: &crate::goslice::slice<Attr>) -> int {
    let mut n: int = 0;
    for i in 0..as_.Len() {
        if isEmptyGroup(&as_[i].Value) {
            n += 1;
        }
    }
    return n;
}

// go: sdk 1.25.5 log/slog/value.go:179-193 GroupValue
/// Go: "GroupValue returns a new Value for a list of Attrs. The caller
/// must not subsequently mutate the argument slice."
///
/// Go: "Remove empty groups. It is simpler overall to do this at
/// construction than to check each Group recursively for emptiness."
/// That pruning is load-bearing: `isEmptyGroup` above is a shallow
/// check precisely because this guarantees no empty group survives
/// construction.
///
/// Deviation: Go packs the group into `Value{num, any: groupptr(...)}`
/// with an unsafe slice pointer; goish's `Value` carries the slice
/// through its `any` field, so there is no pointer arithmetic and the
/// `num` count is `Len()`.
pub fn GroupValue(as_: crate::goslice::slice<Attr>) -> Value {
    let n = countEmptyGroups(&as_);
    let kept = if n > 0 {
        let mut out: alloc::vec::Vec<Attr> = alloc::vec::Vec::new();
        for i in 0..as_.Len() {
            if !isEmptyGroup(&as_[i].Value) {
                out.push(as_[i].clone());
            }
        }
        crate::goslice::slice::__from_vec(out)
    } else {
        as_
    };
    return Value {
        kind: KindGroup,
        any: GoishAny::new(kept),
    };
}

// go: none — goish idiom: Go reaches the backing array through
// `v.group()`, an unsafe slice reconstruction. goish downcasts the
// `any` payload instead, returning an empty slice for a Value that is
// not a group.
fn group_of(v: &Value) -> crate::goslice::slice<Attr> {
    return match v.any.As::<crate::goslice::slice<Attr>>() {
        Some(g) => g.clone(),
        None => crate::goslice::slice::new(),
    };
}

// go: sdk 1.25.5 log/slog/value.go:221-266 AnyValue
/// Go: "AnyValue returns a [Value] for the supplied value."
///
/// Go's body is a 20-arm type switch over `any`, mapping each concrete
/// type onto the Kind that represents it — every signed width to
/// KindInt64, every unsigned width to KindUint64, both float widths to
/// KindFloat64, and `[]Attr` to a group. The widening is the point: a
/// handler only ever sees the nine Kinds, never the twenty input types.
///
/// Deviation: Go dispatches on the dynamic type of an interface value;
/// goish downcasts `goany::Any` in the same order. The order matters
/// for the same reason it does in Go — `Value` and `Kind` are checked
/// before the fallthrough so an already-built Value is returned as-is
/// rather than being wrapped in another one.
///
/// The `default: return Value{any: v}` arm becomes KindAny holding the
/// original payload, which is what Go's untyped arm produces.
pub fn AnyValue(v: GoishAny) -> Value {
    // Go: case string: return StringValue(v)
    if let Some(x) = v.As::<crate::gostring::string>() {
        return Value {
            kind: super::KindString,
            any: GoishAny::new(x.clone()),
        };
    }
    // Go: case bool: return BoolValue(v)
    if let Some(x) = v.As::<bool>() {
        return Value {
            kind: super::KindBool,
            any: GoishAny::new(*x),
        };
    }
    // Go: every signed width folds to KindInt64.
    if let Some(x) = v.As::<crate::types::int>() {
        return Value {
            kind: super::KindInt64,
            any: GoishAny::new(*x),
        };
    }
    if let Some(x) = v.As::<i8>() {
        return Value {
            kind: super::KindInt64,
            any: GoishAny::new(crate::types::int::from(*x)),
        };
    }
    if let Some(x) = v.As::<i16>() {
        return Value {
            kind: super::KindInt64,
            any: GoishAny::new(crate::types::int::from(*x)),
        };
    }
    if let Some(x) = v.As::<i32>() {
        return Value {
            kind: super::KindInt64,
            any: GoishAny::new(crate::types::int::from(*x)),
        };
    }
    // Go: every unsigned width folds to KindUint64.
    if let Some(x) = v.As::<u8>() {
        return Value {
            kind: super::KindUint64,
            any: GoishAny::new(u64::from(*x)),
        };
    }
    if let Some(x) = v.As::<u16>() {
        return Value {
            kind: super::KindUint64,
            any: GoishAny::new(u64::from(*x)),
        };
    }
    if let Some(x) = v.As::<u32>() {
        return Value {
            kind: super::KindUint64,
            any: GoishAny::new(u64::from(*x)),
        };
    }
    if let Some(x) = v.As::<u64>() {
        return Value {
            kind: super::KindUint64,
            any: GoishAny::new(*x),
        };
    }
    // Go: both float widths fold to KindFloat64.
    if let Some(x) = v.As::<crate::types::float64>() {
        return Value {
            kind: super::KindFloat64,
            any: GoishAny::new(*x),
        };
    }
    if let Some(x) = v.As::<crate::types::float32>() {
        return Value {
            kind: super::KindFloat64,
            any: GoishAny::new(crate::types::float64::from(*x)),
        };
    }
    // Go: case time.Duration / time.Time
    if let Some(x) = v.As::<crate::time::Duration>() {
        return Value {
            kind: super::KindDuration,
            any: GoishAny::new(*x),
        };
    }
    if let Some(x) = v.As::<crate::time::Time>() {
        return Value {
            kind: super::KindTime,
            any: GoishAny::new(*x),
        };
    }
    // Go: case []Attr: return GroupValue(v...)
    if let Some(x) = v.As::<crate::goslice::slice<Attr>>() {
        return GroupValue(x.clone());
    }
    // Go: case Value: return v — an already-built Value passes through
    // rather than being wrapped again.
    if let Some(x) = v.As::<Value>() {
        return x.clone();
    }
    // Go: default: return Value{any: v}
    return Value {
        kind: super::KindAny,
        any: v,
    };
}

// go: sdk 1.25.5 log/slog/value.go:487-489 LogValuer
/// Go: "A LogValuer is any Go value that can convert itself into a
/// Value for logging. This mechanism may be used to defer expensive
/// operations until they are needed, or to expand a single value into a
/// sequence of components."
pub trait LogValuer: Send + Sync {
    fn LogValue(&self) -> Value;
}

// go: none — goish idiom: a `Value` of KindLogValuer carries its
// LogValuer through the `any` field, and `goany::Any` requires
// `PartialEq + Reflect` on its payload. A `dyn` trait object has
// neither, so this newtype supplies both — equality by pointer
// identity, which is the only equality a trait object can honestly
// claim.
#[derive(Clone)]
pub struct LogValuerBox(pub alloc::sync::Arc<dyn LogValuer>);

impl PartialEq for LogValuerBox {
    // go: none — goish idiom: pointer identity, the only equality a
    // trait object can honestly claim. Go never compares LogValuers.
    fn eq(&self, other: &Self) -> bool {
        return alloc::sync::Arc::ptr_eq(&self.0, &other.0);
    }
}

impl crate::reflect::Reflect for LogValuerBox {
    // go: none — goish idiom: minimal descriptor so the box can live in
    // a `goany::Any`, which requires Reflect. Nothing walks it.
    fn __reflect_type() -> crate::reflect::Type {
        return crate::reflect::Type::__new(crate::reflect::Kind::Struct, "LogValuerBox", &[]);
    }
    // go: none — goish idiom: as __reflect_type.
    fn __reflect_value(&self) -> crate::reflect::Value {
        return crate::reflect::Value::Struct {
            ty: <LogValuerBox as crate::reflect::Reflect>::__reflect_type(),
            fields: alloc::vec![],
        };
    }
}

// go: none — goish idiom: Go writes `AnyValue(x)` and lets the type
// switch notice a LogValuer. goish's `Any` cannot dispatch on an
// unsized trait, so a LogValuer-carrying Value is built explicitly.
pub fn LogValuerValue(v: alloc::sync::Arc<dyn LogValuer>) -> Value {
    return Value {
        kind: super::KindLogValuer,
        any: GoishAny::new(LogValuerBox(v)),
    };
}

// go: sdk 1.25.5 log/slog/value.go:491-491 maxLogValues
/// Go: `const maxLogValues = 100` — the cap on how many times Resolve
/// will follow a LogValuer chain.
pub const maxLogValues: crate::types::int = 100;

// go: sdk 1.25.5 log/slog/value.go:500-516 Value.Resolve
/// Go: "Resolve repeatedly calls LogValue on v while it implements
/// LogValuer, and returns the result. If v resolves to a group, the
/// group's attributes' values are not recursively resolved. If the
/// number of LogValue calls exceeds a threshold, a Value containing an
/// error is returned. Resolve's return value is guaranteed not to be of
/// Kind [KindLogValuer]."
///
/// The bound is the point. A LogValuer that returns itself — trivially,
/// or through a cycle two types long — would otherwise spin forever
/// inside a logging call. Go caps at 100 and returns an *error Value*
/// rather than panicking, because failing a log line is worse than
/// logging a bad one.
///
/// Deviation: Go wraps the loop in `defer recover()` so a LogValue that
/// panics becomes an error Value too. goish's `recover!()` observes a
/// panic but does not stop it propagating (panic = abort, no unwind
/// tables), so a panicking LogValue still takes down its goroutine.
/// The overflow guard below is unaffected.
pub fn Resolve(v: &Value) -> Value {
    let mut cur = v.clone();
    let mut i: crate::types::int = 0;
    while i < maxLogValues {
        if cur.Kind() != super::KindLogValuer {
            return cur;
        }
        let next = match cur.any.As::<LogValuerBox>() {
            Some(b) => b.0.LogValue(),
            // A Value tagged KindLogValuer whose payload is not one is
            // malformed; treat it as fully resolved rather than
            // looping on it.
            None => return cur,
        };
        cur = next;
        i += 1;
    }
    // Go: fmt.Errorf("LogValue called too many times on Value of type %T", …)
    return super::AnyValue(GoishAny::new(crate::errors::New(
        crate::gostring::string::from_static("LogValue called too many times on Value"),
    )));
}

// ─── Typed constructors (value.go:76) ───────────────────────────────
//
// Go packs a Value into a word plus a pointer and reads the Kind back
// out of the packing; goish stores the Kind alongside the payload, so
// each constructor sets it directly. The SET of constructors and the
// Kind each produces are Go's.

// go: sdk 1.25.5 log/slog/value.go:109-111 StringValue
/// Go: "StringValue returns a new [Value] for a string."
pub fn StringValue<S: Into<crate::gostring::string>>(value: S) -> Value {
    return Value {
        kind: super::KindString,
        any: GoishAny::new(value.into()),
    };
}

// go: sdk 1.25.5 log/slog/value.go:114-116 IntValue
/// Go: "IntValue returns a [Value] for an int."
pub fn IntValue(v: int) -> Value {
    return Int64Value(v);
}

// go: sdk 1.25.5 log/slog/value.go:119-121 Int64Value
/// Go: "Int64Value returns a [Value] for an int64."
pub fn Int64Value(v: int) -> Value {
    return Value {
        kind: super::KindInt64,
        any: GoishAny::new(v),
    };
}

// go: sdk 1.25.5 log/slog/value.go:124-126 Uint64Value
/// Go: "Uint64Value returns a [Value] for a uint64."
pub fn Uint64Value(v: u64) -> Value {
    return Value {
        kind: super::KindUint64,
        any: GoishAny::new(v),
    };
}

// go: sdk 1.25.5 log/slog/value.go:129-131 Float64Value
/// Go: "Float64Value returns a [Value] for a floating-point number."
pub fn Float64Value(v: f64) -> Value {
    return Value {
        kind: super::KindFloat64,
        any: GoishAny::new(v),
    };
}

// go: sdk 1.25.5 log/slog/value.go:134-140 BoolValue
/// Go: "BoolValue returns a [Value] for a bool."
pub fn BoolValue(v: bool) -> Value {
    return Value {
        kind: super::KindBool,
        any: GoishAny::new(v),
    };
}

// go: sdk 1.25.5 log/slog/value.go:173-175 DurationValue
/// Go: "DurationValue returns a [Value] for a [time.Duration]."
pub fn DurationValue(v: crate::time::Duration) -> Value {
    return Value {
        kind: super::KindDuration,
        any: GoishAny::new(v),
    };
}

// go: sdk 1.25.5 log/slog/value.go:153-170 TimeValue
/// Go: "TimeValue returns a [Value] for a [time.Time]."
pub fn TimeValue(v: crate::time::Time) -> Value {
    return Value {
        kind: super::KindTime,
        any: GoishAny::new(v),
    };
}

// ─── Kind.String (value.go:44) ──────────────────────────────────────

impl super::Kind {
    // go: sdk 1.25.5 log/slog/value.go:75-80 Kind.String
    /// Go: `func (k Kind) String() string` over the `kindStrings` table.
    pub fn String(self) -> crate::gostring::string {
        let k = self;
        // Go: var kindStrings = []string{…} indexed by the Kind.
        let names: [&str; 10] = [
            "Any",
            "Bool",
            "Duration",
            "Float64",
            "Int64",
            "String",
            "Time",
            "Uint64",
            "Group",
            "LogValuer",
        ];
        if k.0 >= 0 && k.0 < crate::int64(names.len()) {
            return crate::gostring::string::from_bytes(
                names[k.0.unsigned_abs() as usize].as_bytes(),
            );
        }
        // Go: "<unknown slog.Kind>"
        return crate::gostring::string::from_static("<unknown slog.Kind>");
    }
}

// ─── Value.String (value.go:180) ────────────────────────────────────

impl Value {
    // go: sdk 1.25.5 log/slog/value.go:304-310 Value.String
    /// Go: "String returns Value's value as a string, formatted like
    /// [fmt.Sprint]. Unlike the methods Int64, Float64, and so on, which
    /// panic if v is of the wrong kind, String never panics."
    ///
    /// This is the renderer every built-in handler leans on, and it is
    /// per-Kind rather than one formatter: an Int64 is decimal, a Float64
    /// is shortest-round-trip, a Duration is Go's duration syntax, a Time
    /// is `time.Time.String()` (NOT RFC 3339 — the handlers apply that
    /// themselves), and a Group is bracketed like a slice of Attrs.
    pub fn String(&self) -> crate::gostring::string {
        let v = self;
        let k = v.Kind();
        if k == super::KindString {
            return match v.any.As::<crate::gostring::string>() {
                Some(s) => s.clone(),
                None => crate::gostring::string::from_static(""),
            };
        }
        let mut buf: alloc::vec::Vec<crate::types::byte> = alloc::vec::Vec::new();
        v.append(&mut buf);
        return crate::gostring::string::__from_vec(buf);
    }

    // go: sdk 1.25.5 log/slog/value.go:458-481 Value.append
    /// Go: "append appends a text representation of v to dst. v is
    /// formatted as with fmt.Sprint."
    pub fn append(&self, dst: &mut alloc::vec::Vec<crate::types::byte>) {
        let v = self;
        let k = v.Kind();
        if k == super::KindString {
            if let Some(s) = v.any.As::<crate::gostring::string>() {
                dst.extend_from_slice(s.as_bytes());
            }
            return;
        }
        if k == super::KindInt64 {
            if let Some(x) = v.any.As::<int>() {
                dst.extend_from_slice(crate::strconv::FormatInt(*x, 10).as_bytes());
            }
            return;
        }
        if k == super::KindUint64 {
            if let Some(x) = v.any.As::<u64>() {
                dst.extend_from_slice(crate::strconv::FormatUint(*x, 10).as_bytes());
            }
            return;
        }
        if k == super::KindFloat64 {
            if let Some(x) = v.any.As::<f64>() {
                // Go: strconv.AppendFloat(dst, v.float(), 'g', -1, 64)
                dst.extend_from_slice(crate::strconv::FormatFloat(*x, b'g', -1, 64).as_bytes());
            }
            return;
        }
        if k == super::KindBool {
            if let Some(x) = v.any.As::<bool>() {
                dst.extend_from_slice(crate::strconv::FormatBool(*x).as_bytes());
            }
            return;
        }
        if k == super::KindDuration {
            if let Some(x) = v.any.As::<crate::time::Duration>() {
                dst.extend_from_slice(x.String().as_bytes());
            }
            return;
        }
        if k == super::KindTime {
            if let Some(x) = v.any.As::<crate::time::Time>() {
                dst.extend_from_slice(x.String().as_bytes());
            }
            return;
        }
        if k == super::KindGroup {
            // Go: return fmt.Append(dst, v.group()) — a []Attr prints as
            // "[a=1 b=2]", space-separated inside brackets.
            let g = group_of(v);
            dst.push(b'[');
            let mut i: int = 0;
            while i < g.Len() {
                if i > 0 {
                    dst.push(b' ');
                }
                appendAttrString(&g[i], dst);
                i += 1;
            }
            dst.push(b']');
            return;
        }
        if k == super::KindLogValuer || k == super::KindAny {
            // Go: return fmt.Append(dst, v.any) — the payload's own
            // rendering, which for an error is its Error() text and for a
            // nil `any` is "<nil>".
            dst.extend_from_slice(anyString(&v.any).as_bytes());
            return;
        }
    }
}

// go: none — goish idiom: Go renders a Group by handing the `[]Attr`
//     to `fmt.Append`, which reaches each Attr's own String method.
//     goish has no such reflection at this point, so the one-Attr
//     rendering is a shared helper that both `Attr::String` (attr.rs)
//     and the Group arm above call.
/// `a.Key + "=" + a.Value.String()`, appended.
pub fn appendAttrString(a: &Attr, dst: &mut alloc::vec::Vec<crate::types::byte>) {
    dst.extend_from_slice(a.Key.as_bytes());
    dst.push(b'=');
    a.Value.append(dst);
}

// go: none — goish idiom: Go's `fmt.Append(dst, v.any)` reflects over
//     the boxed `any` and calls its Error or String method if it has
//     one. goish's `GoishAny` is a typed box, so the same rendering is
//     a downcast ladder over the types slog can actually hold.
fn anyString(v: &GoishAny) -> crate::gostring::string {
    if v.IsNil() {
        return crate::gostring::string::from_static("<nil>");
    }
    if let Some(e) = v.As::<crate::errors::error>() {
        if e.IsNil() {
            return crate::gostring::string::from_static("<nil>");
        }
        return e.Error();
    }
    if let Some(s) = v.As::<crate::gostring::string>() {
        return s.clone();
    }
    if let Some(x) = v.As::<int>() {
        return crate::strconv::FormatInt(*x, 10);
    }
    if let Some(x) = v.As::<u64>() {
        return crate::strconv::FormatUint(*x, 10);
    }
    if let Some(x) = v.As::<bool>() {
        return crate::strconv::FormatBool(*x);
    }
    if let Some(x) = v.As::<f64>() {
        return crate::strconv::FormatFloat(*x, b'g', -1, 64);
    }
    return crate::gostring::string::from_static("<nil>");
}

// go: none — goish idiom: Go's `Value.Group()` unpacks the group out of
//     the packed representation; goish stores it whole, and the
//     handlers need it, so this is that accessor under a name that says
//     it is goish's rather than Go's `Group`.
pub fn __group_attrs(v: &Value) -> crate::goslice::slice<Attr> {
    return group_of(v);
}
