// Verifies the `goish_rt_text` link-section mechanism:
//   1. The linker auto-generates `__start_goish_rt_text` and
//      `__stop_goish_rt_text` symbols.
//   2. Functions tagged with `#[link_section = "goish_rt_text"]` +
//      `#[inline(never)]` land inside the section's address range.
//   3. Untagged functions (e.g., main itself) land *outside* it.
//
// This is a build-time correctness gate for the M17b-δ async-preempt
// PC-range filter (rt_section.rs).

#![no_std]
#![no_main]

use goish::runtime::rt_section;
use goish::syscall;

#[inline(never)]
#[link_section = "goish_rt_text"]
fn tagged_function() -> u32 {
    // Force a non-trivial body so the function isn't optimized to nothing.
    let mut x = 0u32;
    for i in 0..7 {
        x = x.wrapping_add(i);
    }
    x
}

#[inline(never)]
fn untagged_function() -> u32 {
    let mut x = 0u32;
    for i in 0..11 {
        x = x.wrapping_add(i);
    }
    x
}

fn write_hex(label: &[u8], v: u64) {
    syscall::Write(syscall::STDERR, label.as_ptr(), label.len());
    let mut buf = [0u8; 18];
    buf[0] = b'0';
    buf[1] = b'x';
    let x = v;
    for i in 0..16 {
        let nib = ((x >> ((15 - i) * 4)) & 0xf) as u8;
        buf[2 + i] = if nib < 10 { b'0' + nib } else { b'a' + (nib - 10) };
    }
    let _ = x;
    syscall::Write(syscall::STDERR, buf.as_ptr(), buf.len());
    syscall::Write(syscall::STDERR, b"\n".as_ptr(), 1);
}

#[goish::main]
fn main() {
    let (start, end, len) = rt_section::section_bounds();
    write_hex(b"start = ", start);
    write_hex(b"end   = ", end);
    write_hex(b"len   = ", len);

    let tagged_pc = tagged_function as *const () as usize as u64;
    let untagged_pc = untagged_function as *const () as usize as u64;
    write_hex(b"tagged_function    = ", tagged_pc);
    write_hex(b"untagged_function  = ", untagged_pc);

    // Force the calls so they aren't optimized away.
    let t = tagged_function();
    let u = untagged_function();
    let _ = t.wrapping_add(u);

    let tagged_in = rt_section::is_in_runtime(tagged_pc);
    let untagged_in = rt_section::is_in_runtime(untagged_pc);

    if tagged_in {
        syscall::Write(syscall::STDERR, b"tagged    : in goish_rt_text\n".as_ptr(), 30);
    } else {
        syscall::Write(syscall::STDERR, b"tagged    : NOT IN section (BUG)\n".as_ptr(), 33);
    }
    if !untagged_in {
        syscall::Write(syscall::STDERR, b"untagged  : outside section\n".as_ptr(), 28);
    } else {
        syscall::Write(syscall::STDERR, b"untagged  : INSIDE section (false positive)\n".as_ptr(), 45);
    }

    if tagged_in && !untagged_in && len > 0 && len < 0x1000_0000 {
        const OK: &[u8] = b"rt_section_smoke: ok\n";
        syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
        syscall::Exit(0);
    } else {
        const FAIL: &[u8] = b"rt_section_smoke: FAIL\n";
        syscall::Write(syscall::STDERR, FAIL.as_ptr(), FAIL.len());
        syscall::Exit(1);
    }
}
