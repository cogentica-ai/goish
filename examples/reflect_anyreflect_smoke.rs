// reflect_anyreflect_smoke — exercise reflect::AnyReflect, the
// supertrait that bundles `core::any::Any` (typeid downcast) with
// `goish::reflect::Reflect` (Value walking). Used by ports that
// accept arbitrary user values via `Arc<dyn AnyReflect + Send + Sync>`
// (Go's `interface{}` shape) and want to BOTH downcast to known types
// AND walk unknown ones via reflection.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use goish::{int, reflect, string, syscall};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

#[goish::reflect]
pub struct Profile {
    Name: string,
    Age: int,
}

#[goish::main]
fn main() {
    let p = Profile { Name: string("alice"), Age: 30 };

    // Coerce to the type-erased handle ports use for `interface{}`.
    let any_handle: Arc<dyn reflect::AnyReflect + Send + Sync> = Arc::new(p);

    // ─── Reflection round-trip ───────────────────────────────────────
    let val = any_handle.reflect_value();
    check(val.Kind() == reflect::Kind::Struct, b"any: Kind != Struct\n");
    let ty = any_handle.reflect_type();
    check(ty.Name() == "Profile", b"any: Type.Name\n");
    check(ty.NumField() == 2, b"any: NumField\n");

    // ─── Downcast still works through as_any() upcast ────────────────
    let recovered = any_handle.as_any().downcast_ref::<Profile>();
    check(recovered.is_some(), b"any: downcast_ref miss\n");
    let r = recovered.unwrap();
    check(r.Age == 30, b"any: downcast Age mismatch\n");

    // ─── Wrong-type downcast fails cleanly (returns None) ────────────
    let bad = any_handle.as_any().downcast_ref::<int>();
    check(bad.is_none(), b"any: wrong-type downcast should be None\n");

    let ok = b"ok 4/4\n";
    syscall::Write(syscall::STDOUT, ok.as_ptr(), ok.len());
}
