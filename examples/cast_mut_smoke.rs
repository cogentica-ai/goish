// cast_mut_smoke — `cast!(&mut x, J)` is the mutable interface assertion
// (Go's `if m, ok := x.(Mover); ok { m.Step() }` where Step mutates).
// Proves: starting from a `&mut dyn Animal` carrier, we recover `&mut dyn
// Mover` through the per-trait registry and the mutation persists in the
// concrete value. Also checks the miss case returns None.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::any::Any as CoreAny;

use goish::fmt;
use goish::gostring::string;
use goish::{cast, d, syscall};

// Carrier interface — the static type we hold a `&mut` to.
#[goish::interface]
pub trait Animal {
    fn Name(&self) -> string;
}

// Target interface with a `&mut self` method — the whole point of the test.
#[goish::interface]
pub trait Mover {
    fn Step(&mut self) -> i64;
}

#[derive(PartialEq)]
struct Dog {
    steps: i64,
}

impl Animal for Dog {
    fn Name(&self) -> string {
        string::from_static("dog")
    }
    // Impl-site overrides (what goishc emits at every `impl Trait for C`):
    // expose the concrete value as a `&dyn Any` / `&mut dyn Any` so the
    // registry can re-view it as another interface.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn CoreAny + Send + Sync)> {
        Some(self)
    }
    fn __goish_as_dyn_any_mut(&mut self) -> Option<&mut (dyn CoreAny + Send + Sync)> {
        Some(self)
    }
}

impl Mover for Dog {
    fn Step(&mut self) -> i64 {
        self.steps += 1;
        self.steps
    }
}

// A second Animal that does NOT implement Mover — the miss case.
#[derive(PartialEq)]
struct Rock;

impl Animal for Rock {
    fn Name(&self) -> string {
        string::from_static("rock")
    }
    fn __goish_as_dyn_any(&self) -> Option<&(dyn CoreAny + Send + Sync)> {
        Some(self)
    }
    fn __goish_as_dyn_any_mut(&mut self) -> Option<&mut (dyn CoreAny + Send + Sync)> {
        Some(self)
    }
}

#[goish::main]
fn main() {
    // Register Dog as a Mover (Go's link-time itab; here the explicit init).
    __goish_register_Mover_impl::<Dog>();

    let mut bad = 0i32;

    // Hold the value behind its carrier interface, mutably.
    let mut dog = Dog { steps: 0 };
    let animal: &mut d!(Animal) = &mut dog;

    // cast!(&mut carrier, Mover) → Option<&mut dyn Mover>.
    match cast!(&mut *animal, Mover) {
        Some(m) => {
            let a = m.Step(); // 1
            let b = m.Step(); // 2
            if a != 1 || b != 2 {
                bad += 1;
            }
        }
        None => {
            bad += 1; // should have hit
        }
    }

    // Mutation must persist in the concrete `dog`.
    if dog.steps != 2 {
        bad += 1;
    }

    // Miss case: Rock is an Animal but not a registered Mover.
    let mut rock = Rock;
    let ra: &mut d!(Animal) = &mut rock;
    if cast!(&mut *ra, Mover).is_some() {
        bad += 1; // should have missed
    }

    if bad == 0 {
        fmt::Println!(string::from_static(
            "PASS: cast!(&mut x, J) mutable interface assertion works"
        ));
        syscall::Exit(0);
    } else {
        fmt::Println!(string::from_static("FAIL"));
        syscall::Exit(1);
    }
}
