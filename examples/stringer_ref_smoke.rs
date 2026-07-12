// stringer_ref_smoke — verifies the runtime's `#[goish::interface]`-
// decorated `fmt::Stringer` works as an interface value stored in the
// canonical `Arc<dyn Trait + Send + Sync>` shape:
//
//   1. `nil.into()` yields the nil sentinel; `== nil` reports true.
//   2. A concrete impl wrapped in `Arc<dyn Stringer>` reports `!= nil`.
//   3. Method dispatch (`String()`) works through the Arc.
//   4. Cloning the Arc bumps the refcount; dispatch still works.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;

use goish::fmt::Stringer;
use goish::{int, nil, string, syscall};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

struct Greeting(int);
impl Stringer for Greeting {
    fn String(&self) -> string {
        if self.0 == 1 {
            string::from_static("hello")
        } else {
            string::from_static("world")
        }
    }
}

#[goish::main]
fn main() {
    // 1. nil.into() → the nil sentinel; `== nil` both directions.
    let null: Arc<dyn Stringer + Send + Sync> = nil.into();
    check(null == nil, b"stringer: nil.into() != nil\n");
    check(nil == null, b"stringer: nil != nil.into()\n");

    // 2. A concrete impl in the Arc shape reports not-nil.
    let g: Arc<dyn Stringer + Send + Sync> = Arc::new(Greeting(1));
    check(g != nil, b"stringer: concrete == nil (wrong)\n");

    // 3. Method dispatch through the Arc.
    check(
        g.String() == string::from_static("hello"),
        b"stringer: hello dispatch wrong\n",
    );
    let w: Arc<dyn Stringer + Send + Sync> = Arc::new(Greeting(2));
    check(
        w.String() == string::from_static("world"),
        b"stringer: world dispatch wrong\n",
    );

    // 4. Clone bumps the inner Arc's refcount; dispatch still works.
    let g2 = g.clone();
    check(
        g2.String() == string::from_static("hello"),
        b"stringer: cloned dispatch wrong\n",
    );

    const OK: &[u8] = b"stringer_ref_smoke: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
