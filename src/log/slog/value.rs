// go: file log/slog/value.go decls: AnyValue, GroupValue, countEmptyGroups, Value.isEmptyGroup
//
// log/slog/value.go — the group constructor and its emptiness pruning.
//
// **Partial port.** The typed Value constructors live in mod[rs] and
// predate this file; only the group path is anchored here.
//
// goishlint:ignore GOISH018 Any, Bool, BoolValue, Duration, DurationValue, Equal, Float64, Float64Value, Group, Int64, Int64Value, IntValue, Kind, LogValuer, Resolve, String, StringValue, Time, TimeValue, Uint64, Uint64Value, append, bool, duration, float, group, stack, str, time — not ported; only the declarations in this file are.
// goishlint:ignore GOISH021 Kind, KindAny, KindBool, KindDuration, KindFloat64, KindGroup, KindInt64, KindLogValuer, KindString, KindTime, KindUint64, LogValuer, Value, kind, kindStrings, maxLogValues, groupptr, stringptr, timeLocation, timeTime — same. The four
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
        return Value { kind: super::KindString, any: GoishAny::new(x.clone()) };
    }
    // Go: case bool: return BoolValue(v)
    if let Some(x) = v.As::<bool>() {
        return Value { kind: super::KindBool, any: GoishAny::new(*x) };
    }
    // Go: every signed width folds to KindInt64.
    if let Some(x) = v.As::<crate::types::int>() {
        return Value { kind: super::KindInt64, any: GoishAny::new(*x) };
    }
    if let Some(x) = v.As::<i8>() {
        return Value { kind: super::KindInt64, any: GoishAny::new(crate::types::int::from(*x)) };
    }
    if let Some(x) = v.As::<i16>() {
        return Value { kind: super::KindInt64, any: GoishAny::new(crate::types::int::from(*x)) };
    }
    if let Some(x) = v.As::<i32>() {
        return Value { kind: super::KindInt64, any: GoishAny::new(crate::types::int::from(*x)) };
    }
    // Go: every unsigned width folds to KindUint64.
    if let Some(x) = v.As::<u8>() {
        return Value { kind: super::KindUint64, any: GoishAny::new(u64::from(*x)) };
    }
    if let Some(x) = v.As::<u16>() {
        return Value { kind: super::KindUint64, any: GoishAny::new(u64::from(*x)) };
    }
    if let Some(x) = v.As::<u32>() {
        return Value { kind: super::KindUint64, any: GoishAny::new(u64::from(*x)) };
    }
    if let Some(x) = v.As::<u64>() {
        return Value { kind: super::KindUint64, any: GoishAny::new(*x) };
    }
    // Go: both float widths fold to KindFloat64.
    if let Some(x) = v.As::<crate::types::float64>() {
        return Value { kind: super::KindFloat64, any: GoishAny::new(*x) };
    }
    if let Some(x) = v.As::<crate::types::float32>() {
        return Value {
            kind: super::KindFloat64,
            any: GoishAny::new(crate::types::float64::from(*x)),
        };
    }
    // Go: case time.Duration / time.Time
    if let Some(x) = v.As::<crate::time::Duration>() {
        return Value { kind: super::KindDuration, any: GoishAny::new(*x) };
    }
    if let Some(x) = v.As::<crate::time::Time>() {
        return Value { kind: super::KindTime, any: GoishAny::new(*x) };
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
    return Value { kind: super::KindAny, any: v };
}
