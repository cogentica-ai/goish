// panic_probe_goexit — a probe for issue #6, not a test.
//
// `runtime::Goexit` lands on the SAME recovery gobuf as the panic
// handler — only the `goexiting` flag tells them apart. Making an
// unrecovered panic fatal must not make Goexit fatal with it: Goexit
// is an ordinary way for a goroutine to end (it is what
// `testing.T::FailNow` uses), and it must neither exit the process nor
// count as a panic.
//
// Expected: exit 0, "probe: after goexit" printed, panics=0.
//
// Excluded from e2e; driven by panic_fatal_ref_smoke.

#![no_std]
#![no_main]

extern crate goish;

use core::sync::atomic::{AtomicI64, Ordering};

use goish::runtime::sched;
use goish::{go, runtime, syscall, KB};

static REACHED: AtomicI64 = AtomicI64::new(0);

fn print_dec(mut n: i64) {
    let mut buf = [0u8; 24];
    let mut i = buf.len();
    if n == 0 {
        i -= 1;
        buf[i] = b'0';
    }
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    syscall::Write(syscall::STDOUT, buf[i..].as_ptr(), buf.len() - i);
}

#[goish::main]
fn main() {
    go!(stack(32 * KB), || {
        REACHED.store(1, Ordering::Release);
        runtime::Goexit();
    });
    for _ in 0..2_000_000 {
        sched::Gosched();
        if REACHED.load(Ordering::Acquire) == 1 {
            break;
        }
    }
    for _ in 0..200_000 {
        sched::Gosched();
    }
    let m = b"probe: after goexit panics=";
    syscall::Write(syscall::STDOUT, m.as_ptr(), m.len());
    print_dec(sched::G_PANIC_COUNT.load(Ordering::Acquire) as i64);
    syscall::Write(syscall::STDOUT, b"\n".as_ptr(), 1);
    syscall::Exit(0);
}
