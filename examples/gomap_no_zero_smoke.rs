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
    if !cond {
        die(msg);
    }
}

// User-defined trait — stands in for any Go interface used as a map
// value type. The `Default`-bounded `new()` ctor doesn't fit because
// `Box<dyn Hasher + Send + Sync>` isn't `Default`.
trait Hasher {
    fn name(&self) -> int;
}

struct H7;
impl Hasher for H7 {
    fn name(&self) -> int {
        7
    }
}

struct H42;
impl Hasher for H42 {
    fn name(&self) -> int {
        42
    }
}

/// Read one value out of an interface-typed map.
///
/// There is no owned read for a `Box<dyn Trait>` value: `Get` clones and
/// `Box<dyn Hasher>` is not Clone. `__try_for_each` hands the value out
/// by reference for the duration of the call and stops at the first
/// match, so it is the access path that survives the shared header
/// issue #7 is heading for — and, unlike the `Index` impl it replaces,
/// it never returns a reference the caller can outlive.
fn name_of(m: &goish::map<string, Box<dyn Hasher + Send + Sync>>, key: &'static str) -> Option<int> {
    return m.__try_for_each(|k, v| {
        use core::ops::ControlFlow;
        if k == &string::from_static(key) {
            return ControlFlow::Break(v.name());
        }
        return ControlFlow::Continue(());
    });
}

#[goish::main]
fn main() {
    // Ctor — works without V: Default
    let mut hashers: goish::map<string, Box<dyn Hasher + Send + Sync>> = goish::map::new_no_zero();
    check(len(&hashers) == 0, b"no-zero map: initial len != 0\n");

    // Has() works — answer is false for any key when the map is empty
    check(
        !hashers.Has(string::from_static("seven")),
        b"no-zero map: Has(seven) wrong on empty\n",
    );

    // Insert via Set — the only write form since the `IndexMut` impl
    // that spelled `m["k"] = v` was removed (it returned `&mut V`,
    // which a shared header cannot hand out; ROADMAP §2u).
    hashers.Set(
        string::from_static("seven"),
        Box::new(H7) as Box<dyn Hasher + Send + Sync>,
    );
    hashers.Set(
        string::from_static("forty-two"),
        Box::new(H42) as Box<dyn Hasher + Send + Sync>,
    );
    check(
        len(&hashers) == 2,
        b"no-zero map: len after 2 inserts != 2\n",
    );

    // Has() — present
    check(
        hashers.Has(string::from_static("seven")),
        b"no-zero map: Has(seven) wrong\n",
    );
    check(
        hashers.Has(string::from_static("forty-two")),
        b"no-zero map: Has(forty-two) wrong\n",
    );

    // Reading the VALUE, which `Get` cannot do here: it clones, and
    // `Box<dyn Hasher>` is not Clone. `Index` used to serve this and is
    // gone — it returned `&V`, which a shared header cannot hand back.
    // The guard-scoped closure is what remains, and what will still
    // work once the header lands.
    check(
        name_of(&hashers, "seven") == Some(7),
        b"no-zero map: H7.name() != 7\n",
    );
    check(
        name_of(&hashers, "forty-two") == Some(42),
        b"no-zero map: H42.name() != 42\n",
    );
    check(
        name_of(&hashers, "missing") == None,
        b"no-zero map: read of a missing key must be None\n",
    );

    // Iteration. `range!` is NOT available here: it yields owned
    // `(K, V)` the way Go's `range` yields copies, which needs
    // `V: Clone`, and `Box<dyn Hasher>` is not. Go has no equivalent
    // problem — an interface value is a copyable two-word pair — so
    // this is a goish limit, and the guard-scoped walk is the answer
    // to it, as it is for reading a single value above.
    let mut count: int = 0;
    hashers.__for_each(|_, _| count += 1);
    check(count == 2, b"no-zero map: __for_each count != 2\n");

    const OK: &[u8] = b"gomap_no_zero: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
