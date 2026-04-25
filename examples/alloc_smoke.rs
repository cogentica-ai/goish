// Milestone 2 smoke test for runtime::alloc.
//
// Verifies two paths into the same mmap-backed bump heap:
//
//   1. Direct: `runtime::alloc(size, align)` — Go-style raw allocation.
//      Used by future GoString/GoSlice internals if they ever need it.
//   2. Via #[global_allocator]: Rust's `Vec` (from `alloc` crate) draws
//      from the same heap because GoishAllocator is registered. This
//      proves Vec/String/Box can be used safely with no libc.
//
// On any check failing: writes a marker to stderr and exits non-zero.

#![no_std]
#![no_main]

extern crate alloc;
use alloc::vec::Vec;

use goish::{runtime, syscall};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

#[goish::main]
fn main() {
    unsafe {
        // (1) Two distinct allocations, each 4 KiB, 8-byte aligned.
        let a = runtime::alloc(4096, 8);
        let b = runtime::alloc(4096, 8);
        if a.is_null() || b.is_null() {
            die(b"alloc: null pointer\n");
        }
        if (a as usize) % 8 != 0 || (b as usize) % 8 != 0 {
            die(b"alloc: misaligned\n");
        }

        // Fill region A with 0xAA, region B with 0xBB.
        for i in 0..4096 {
            *a.add(i) = 0xAA;
            *b.add(i) = 0xBB;
        }
        // Verify they didn't trample each other.
        for i in 0..4096 {
            if *a.add(i) != 0xAA || *b.add(i) != 0xBB {
                die(b"alloc: cross-trample\n");
            }
        }

        // (2) realloc grows region A from 4 KiB to 16 KiB; old bytes preserved.
        let a2 = runtime::realloc(a, 4096, 16384, 8);
        if a2.is_null() || (a2 as usize) % 8 != 0 {
            die(b"realloc: null/misaligned\n");
        }
        for i in 0..4096 {
            if *a2.add(i) != 0xAA {
                die(b"realloc: payload lost\n");
            }
        }

        // (3) Vec via #[global_allocator] — push 1024 elements, force
        // multiple regrowths, verify content. Every push that triggers
        // grow goes through GoishAllocator → runtime::alloc.
        let mut v: Vec<u32> = Vec::new();
        for i in 0..1024u32 {
            v.push(i);
        }
        if v.len() != 1024 {
            die(b"vec: wrong length\n");
        }
        for i in 0..1024 {
            if v[i] != i as u32 {
                die(b"vec: corrupted payload\n");
            }
        }

        const OK: &[u8] = b"alloc: ok (raw + Vec via global_allocator)\n";
        syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
    }
}
