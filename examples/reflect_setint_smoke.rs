// reflect_setint_smoke — reflect::New + Value::SetInt vs Go 1.25.5.
//
// Values from `scripts/goref.sh reflect`. These two exist so that
// encoding/asn1's makeField can materialise an `asn1:"default:N"` value
// and DeepEqual it against a field — the last reflect capability the
// Marshal path was missing.
//
// The truncation rows are the point: Go's SetInt narrows rather than
// rejecting, so int8 <- 300 is 44, and getting that wrong would silently
// mis-compare defaults.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::reflect::{Kind, New, Reflect, TypeOfDyn, Value, Zero};

static FAILED: AtomicUsize = AtomicUsize::new(0);
static RAN: AtomicUsize = AtomicUsize::new(0);

fn check(ok: bool, what: &'static str) {
    RAN.fetch_add(1, Ordering::AcqRel);
    if ok {
        fmt::Printf!("PASS: %s\n", goish::string(what));
    } else {
        FAILED.fetch_add(1, Ordering::AcqRel);
        fmt::Printf!("FAIL: %s\n", goish::string(what));
    }
}

#[goish::main]
fn main() {
    // New(t).Elem() is a zero of t, and mutable.
    let ti = TypeOfDyn::<i64>();
    let mut v = New(ti).Elem();
    check(v.Kind() == Kind::Int, "New(int).Elem() has Kind::Int");
    check(v == Zero(ti), "New(int).Elem() starts equal to Zero");
    v.SetInt(42);
    check(v.Int() == 42, "SetInt(42) on int");
    check(v != Zero(ti), "after SetInt it differs from Zero");

    // Truncation, exactly as Go: int8 <- 300 is 44.
    let t8 = TypeOfDyn::<i8>();
    let mut v8 = New(t8).Elem();
    check(v8.Kind() == Kind::Int8, "New(int8).Elem() has Kind::Int8");
    v8.SetInt(42);
    check(v8.Int() == 42, "SetInt(42) on int8");
    let mut v8b = New(t8).Elem();
    v8b.SetInt(300);
    check(v8b.Int() == 44, "SetInt(300) on int8 truncates to 44 (Go)");

    let t16 = TypeOfDyn::<i16>();
    let mut v16 = New(t16).Elem();
    v16.SetInt(-5);
    check(v16.Int() == -5, "SetInt(-5) on int16");

    let t32 = TypeOfDyn::<i32>();
    let mut v32 = New(t32).Elem();
    v32.SetInt(70000);
    check(v32.Int() == 70000, "SetInt(70000) on int32");

    let mut v64 = New(ti).Elem();
    v64.SetInt(-9223372036854775808);
    check(v64.Int() == -9223372036854775808, "SetInt(int64 min)");

    // The asn1 makeField shape: build a typed default, compare to a field.
    let mut def = New(ti).Elem();
    def.SetInt(7);
    let field = Value::Int(7);
    check(def == field, "makeField shape: default == field");
    let other = Value::Int(8);
    check(def != other, "makeField shape: default != field");

    // ─── typed re-extraction, the makeBody prerequisite ───────────────
    //
    // makeBody does value.Interface().(T) for five types. goish's
    // Interface() boxes () for Struct/Slice, so recovery goes through the
    // Value's own fields instead. These assert that each of the five
    // carries enough to rebuild the original — which is what the encode
    // path needs, and what time::Time and big::Int previously discarded.
    use goish::encoding::asn1::{BitString, ObjectIdentifier, RawValue};
    use goish::goslice::slice;

    // ObjectIdentifier reflects as Named{Slice} — the name is what tells
    // makeBody it is an OID and not any other []int — so unwrap one level.
    let oid = ObjectIdentifier::New(slice::__from_vec(alloc::vec![1i64, 2, 840]));
    match oid.__reflect_value() {
        Value::Named { ty, inner } => match *inner {
            Value::Slice { items, .. } => {
                check(
                    ty.Name().as_bytes() == b"ObjectIdentifier"
                        && items.len() == 3
                        && items[0] == Value::Int(1)
                        && items[2] == Value::Int(840),
                    "ObjectIdentifier reflect value round-trips",
                );
            }
            _ => check(false, "ObjectIdentifier reflect value round-trips"),
        },
        _ => check(false, "ObjectIdentifier reflect value round-trips"),
    }

    let bs = BitString {
        Bytes: slice::__from_vec(alloc::vec![0xf0u8]),
        BitLength: 4,
    };
    match bs.__reflect_value() {
        Value::Struct { fields, .. } => {
            check(
                fields.len() == 2 && fields[1] == Value::Int(4),
                "BitString reflect value round-trips",
            );
        }
        _ => check(false, "BitString reflect value round-trips"),
    }

    let rv = RawValue {
        Class: 2,
        Tag: 7,
        IsCompound: true,
        Bytes: slice::__from_vec(alloc::vec![1u8, 2]),
        FullBytes: slice::__from_vec(alloc::vec![0xa7u8, 2, 1, 2]),
    };
    match rv.__reflect_value() {
        Value::Struct { fields, .. } => {
            check(
                fields.len() == 5
                    && fields[0] == Value::Int(2)
                    && fields[1] == Value::Int(7)
                    && fields[2] == Value::Bool(true),
                "RawValue reflect value round-trips",
            );
        }
        _ => check(false, "RawValue reflect value round-trips"),
    }

    let t = goish::time::Date(2024, 3, 7, 9, 5, 1, 0, goish::time::UTC);
    match t.__reflect_value() {
        Value::Struct { fields, .. } => {
            // The field carries the INTERNAL second count — seconds
            // from year 1, the frame `Time.sec` uses — not the Unix
            // one. That is what makes a reflected zero Time equal
            // `reflect::Zero(Time)`, which is how `encoding/asn1` omits
            // an OPTIONAL field; reflecting `Unix()` made the zero
            // unmatchable the moment `Time` stopped being anchored at
            // the epoch.
            check(
                fields.len() == 2 && fields[0] == Value::Int(t.Unix() + 62_135_596_800),
                "time::Time reflect value carries its instant",
            );
        }
        _ => check(false, "time::Time reflect value carries its instant"),
    }

    let mut n = goish::math::big::Int::default();
    n.SetString("-123456789012345678901234567890", 10);
    match n.__reflect_value() {
        Value::Struct { fields, .. } => {
            let signOK = fields.len() == 2 && fields[0] == Value::Int(-1);
            let magOK = match &fields[1] {
                Value::Slice { items, .. } => items.len() == n.Bytes().Len() as usize,
                _ => false,
            };
            check(
                signOK && magOK,
                "big::Int reflect value carries sign and magnitude",
            );
        }
        _ => check(false, "big::Int reflect value carries sign and magnitude"),
    }

    let failed = FAILED.load(Ordering::Acquire);
    let ran = RAN.load(Ordering::Acquire);
    if failed == 0 {
        fmt::Printf!("reflect_setint_smoke OK %d/%d\n", ran as i64, ran as i64);
    } else {
        fmt::Printf!(
            "reflect_setint_smoke FAILED %d of %d\n",
            failed as i64,
            ran as i64
        );
        goish::syscall::Exit(1);
    }
}
