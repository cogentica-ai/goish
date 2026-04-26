// Live test: log::Println / Printf write a date+time-prefixed line to
// stderr. Exit code only checked; the prefix is whatever the wall
// clock says at run time, so we just verify nothing panics.

#![no_std]
#![no_main]

use goish::{log, syscall};

#[goish::main]
fn main() {
    log::Println!("hello", "from log");
    log::Printf!("count = %d\n", 42 as goish::int);

    const OK: &[u8] = b"log: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
