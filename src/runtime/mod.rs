// runtime — startup, panic handling, and (later) the heap allocator.
//
// Mirrors Go's startup pipeline:
//
//   _rt0_amd64        →  _start                (asm stub in user binary,
//                                                emitted by #[goish::main])
//   runtime.rt0_go    →  __goish_rt0           (this file)
//   runtime.main      →  body of __goish_rt0   (sets things up, calls user main)
//   main.main         →  user's #[goish::main] fn main()
//   runtime.exit      →  syscall::Exit
//
// The _start stub lives in the user's binary (so the linker actually
// emits the symbol); __goish_rt0 lives here in the rlib and is the first
// Rust code to run.

use crate::syscall;

pub mod args;
mod heap;
pub mod mheap;
mod mem;
pub mod spin;
pub use heap::{alloc, free, realloc};

/// First Rust code to run after the kernel hands control to `_start`.
/// `_start` (emitted by `#[goish::main]`) reads argc/argv off the stack,
/// loads them into rdi/rsi per SysV, then `call`s here.
///
/// `extern "C"` so the asm stub can call us with the C ABI.
#[no_mangle]
pub extern "C" fn __goish_rt0(argc: i32, argv: *const *const u8) -> ! {
    // Stash argc/argv so os::Args() can decode them lazily on first use.
    args::__set(argc, argv);

    // Hand off to the user's main. The proc-macro #[goish::main]
    // generates a #[no_mangle] extern "C" fn __goish_main wrapping the
    // user's body, so the linker resolves this `extern` block to it.
    extern "C" {
        fn __goish_main();
    }
    unsafe { __goish_main() }

    // Normal termination — Go's runtime.exit(0) equivalent.
    syscall::Exit(0)
}

// ─── panic handler ─────────────────────────────────────────────────────
//
// no_std crates must define exactly one #[panic_handler]. Since goish is
// built `panic = "abort"`, this only fires on explicit `panic!()` /
// unrecoverable conditions; we print a short marker and exit(2).

#[panic_handler]
fn on_panic(_info: &core::panic::PanicInfo) -> ! {
    const MSG: &[u8] = b"goish: panic\n";
    syscall::Write(syscall::STDERR, MSG.as_ptr(), MSG.len());
    syscall::Exit(2)
}

// Required because core's DWARF unwind tables reference this symbol,
// even though we build with `panic = "abort"`. It's never actually
// invoked at runtime — provide an empty no-mangle stub so the linker
// is satisfied.
#[no_mangle]
pub extern "C" fn rust_eh_personality() {}
