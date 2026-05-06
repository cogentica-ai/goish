// stringer_ref_smoke — verifies the auto-emitted StringerRef from
// the #[goish::interface]-decorated `fmt::Stringer` works as a
// drop-in interface value: Default→nil, From<concrete>, Deref-to-dyn,
// PartialEq<Nil>.

#![no_std]
#![no_main]

extern crate alloc;

use goish::{int, nil, string, syscall};
use goish::fmt::{Stringer, StringerRef};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond { die(msg); }
}

struct Greeting(int);
impl Stringer for Greeting {
    fn String(&self) -> string {
        if self.0 == 1 { string::from_static("hello") }
        else { string::from_static("world") }
    }
}

#[derive(Default)]
struct WithStringer {
    pub label: StringerRef,
}

#[goish::main]
fn main() {
    // Default (= nil sentinel)
    let null: StringerRef = Default::default();
    check(null == nil, b"stringer_ref: default != nil\n");

    // From<concrete>
    let g: StringerRef = Greeting(1).into();
    check(g != nil, b"stringer_ref: concrete == nil (wrong)\n");

    // Deref to dyn Stringer — call String() through the wrapper.
    check(g.String() == string::from_static("hello"),
          b"stringer_ref: hello dispatch wrong\n");

    let w: StringerRef = Greeting(2).into();
    check(w.String() == string::from_static("world"),
          b"stringer_ref: world dispatch wrong\n");

    // Clone bumps the inner Arc's refcount.
    let g2 = g.clone();
    check(g2.String() == string::from_static("hello"),
          b"stringer_ref: clone dispatch wrong\n");

    // #[derive(Default)] on a struct with the Ref field.
    let s: WithStringer = Default::default();
    check(s.label == nil, b"stringer_ref: derived Default field != nil\n");

    const OK: &[u8] = b"stringer_ref_smoke: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
