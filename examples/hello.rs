// Milestone 1 smoke test: print "Hello, World!" via raw write(2).
// No fmt yet — this proves syscall + _start + rt0 + macro all work
// end-to-end with no glibc.

#![no_std]
#![no_main]

use goish::{len, syscall};

#[goish::main]
fn main() {
    let msg = b"Hello, World!\n";
    syscall::Write(syscall::STDOUT, msg.as_ptr(), len(msg) as usize);
}
