// gomap no-zero smoke — `map<K, V>::new_no_zero()` ctor for value
// types that don't impl `Default`. Mirrors Go's `map[K]Interface`
// where the value is a trait object held by `Box<dyn Trait + Send +
// Sync>`. Missing-key access panics; the user is expected to use
// `Has(k)` first OR rely on insert-only patterns (registries).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::boxed::Box;
use goish::{int, len, string, syscall};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond { die(msg); }
}

// User-defined trait — stands in for any Go interface used as a map
// value type. The `Default`-bounded `new()` ctor doesn't fit because
// `Box<dyn Hasher + Send + Sync>` isn't `Default`.
trait Hasher {
    fn name(&self) -> int;
}

struct H7;
impl Hasher for H7 {
    fn name(&self) -> int { 7 }
}

struct H42;
impl Hasher for H42 {
    fn name(&self) -> int { 42 }
}

#[goish::main]
fn main() {
    // Ctor — works without V: Default
    let mut hashers: goish::map<string, Box<dyn Hasher + Send + Sync>>
        = goish::map::new_no_zero();
    check(len(&hashers) == 0, b"no-zero map: initial len != 0\n");

    // Has() works — answer is false for any key when the map is empty
    check(!hashers.Has(string::from_static("seven")),
          b"no-zero map: Has(seven) wrong on empty\n");

    // Insert via Set (IndexMut still requires V: Default, so use Set
    // for non-Default V). Box<dyn Trait> is not Clone either, so the
    // existing `m["k"] = v` IndexMut path doesn't apply anyway.
    hashers.Set(string::from_static("seven"), Box::new(H7) as Box<dyn Hasher + Send + Sync>);
    hashers.Set(string::from_static("forty-two"), Box::new(H42) as Box<dyn Hasher + Send + Sync>);
    check(len(&hashers) == 2, b"no-zero map: len after 2 inserts != 2\n");

    // Has() — present
    check(hashers.Has(string::from_static("seven")),
          b"no-zero map: Has(seven) wrong\n");
    check(hashers.Has(string::from_static("forty-two")),
          b"no-zero map: Has(forty-two) wrong\n");

    // Read via Index (panics on missing — caller must Has() first)
    if hashers.Has(string::from_static("seven")) {
        let h = &hashers[string::from_static("seven")];
        check(h.name() == 7, b"no-zero map: H7.name() != 7\n");
    }
    if hashers.Has(string::from_static("forty-two")) {
        let h = &hashers[string::from_static("forty-two")];
        check(h.name() == 42, b"no-zero map: H42.name() != 42\n");
    }

    // GetRef — borrow-form comma-ok, no V: Clone / Default bounds.
    let (h_opt, ok) = hashers.GetRef(string::from_static("seven"));
    check(ok && h_opt.unwrap().name() == 7, b"no-zero map: GetRef(seven) wrong\n");

    let (_, ok2) = hashers.GetRef(string::from_static("missing"));
    check(!ok2, b"no-zero map: GetRef(missing) ok must be false\n");

    // Range! — iteration works, no Default required
    let mut count: int = 0;
    for (_, _) in goish::range!(hashers) {
        count += 1;
    }
    check(count == 2, b"no-zero map: range count != 2\n");

    const OK: &[u8] = b"gomap_no_zero: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
