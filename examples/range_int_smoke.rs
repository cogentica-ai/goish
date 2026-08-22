// Go 1.22 integer-range differential smoke.
//
// Reference program:
//
//   package main
//   import "fmt"
//   func main() {
//       for _, n := range []int{-3, 0, 1, 5} {
//           values := []int{}
//           for i := range n { values = append(values, i) }
//           fmt.Printf("%d:%v\n", n, values)
//       }
//   }
//
// Go 1.25.5 output: -3:[], 0:[], 1:[0], 5:[0 1 2 3 4].

#![no_std]
#![no_main]

use core::sync::atomic::{AtomicI64, Ordering};

use goish::{int, range, syscall};

static BOUND_CALLS: AtomicI64 = AtomicI64::new(0);

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

fn bound() -> int {
    BOUND_CALLS.fetch_add(1, Ordering::SeqCst);
    return 5;
}

#[goish::main]
fn main() {
    let mut count: int = 0;
    for _ in range!(-3 as int) {
        count += 1;
    }
    check(count == 0, b"range int: negative bound yielded values\n");

    for _ in range!(0 as int) {
        count += 1;
    }
    check(count == 0, b"range int: zero bound yielded values\n");

    let mut one_values: int = 0;
    for i in range!(1 as int) {
        one_values = one_values * 10 + i + 1;
    }
    check(one_values == 1, b"range int: one bound mismatch\n");

    let mut encoded: int = 0;
    for i in range!(bound()) {
        encoded = encoded * 10 + i + 1;
    }
    check(encoded == 12345, b"range int: positive sequence mismatch\n");
    check(
        BOUND_CALLS.load(Ordering::SeqCst) == 1,
        b"range int: bound expression evaluated more than once\n",
    );
}
