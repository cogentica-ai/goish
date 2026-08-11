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
use goish::reflect::{Kind, New, TypeOfDyn, Value, Zero};

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

    let failed = FAILED.load(Ordering::Acquire);
    let ran = RAN.load(Ordering::Acquire);
    if failed == 0 {
        fmt::Printf!("reflect_setint_smoke OK %d/%d\n", ran as i64, ran as i64);
    } else {
        fmt::Printf!("reflect_setint_smoke FAILED %d of %d\n", failed as i64, ran as i64);
        goish::syscall::Exit(1);
    }
}
