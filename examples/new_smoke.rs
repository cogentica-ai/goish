// new!(T) smoke test — verbatim Go `new(T)` mapping.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate goish;

use goish::fmt;
use goish::{int, new, string, syscall};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

#[derive(Default)]
struct Counter {
    value: int,
}

impl Counter {
    fn Increment(&mut self) { self.value += 1; }
    fn Get(&self) -> int { self.value }
}

#[goish::main]
fn main() {
    // 1. new!(Counter) — non-nil nilable<Counter>. Method access goes
    //    through Must / MustMut narrowing (no auto-deref).
    let mut p = new!(Counter);
    {
        let p = p.Must();
        check(p.Get() == 0, b"new: Counter not zero\n");
    }
    {
        let p = p.MustMut();
        p.Increment();
        p.Increment();
        p.Increment();
        check(p.Get() == 3, b"new: Counter increments wrong\n");
    }

    // 2. new!(int) — nilable<int> with zero inside.
    let n = new!(int);
    check(*n.Must() == 0, b"new: int not zero\n");

    // 3. new!(string) — nilable<string> wrapping empty.
    let s = new!(string);
    check(s.Must().Len() == 0, b"new: string not empty\n");

    fmt::Println!("new: ok");
}
