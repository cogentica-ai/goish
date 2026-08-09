// os/exec smoke — LookPath + Command + Run with stdout capture.

#![no_std]
#![no_main]

extern crate alloc;

use goish::{nil, string, syscall};
use goish::os::exec;
use goish::bytes;

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond { die(msg); }
}

#[goish::main]
fn main() {
    // ── LookPath ─────────────────────────────────────────────────────
    let (echo_path, err) = exec::LookPath("echo");
    check(err == nil,        b"exec: LookPath(echo) error\n");
    check(echo_path.Len() > 0, b"exec: LookPath(echo) returned empty path\n");

    // ── Command: echo hello world, capture stdout ─────────────────────
    let mut cmd = exec::Command("echo", goish::slice!([]string{ "hello", "world" }));

    let out_buf = bytes::Buffer::new();
    cmd.SetStdout(out_buf);

    let err = cmd.Run();
    check(err == nil, b"exec: echo Run() error\n");

    // ── LookPath missing binary ───────────────────────────────────────
    let (_, err2) = exec::LookPath("__goish_no_such_binary_xyz__");
    check(err2 != nil, b"exec: LookPath should fail for missing binary\n");

    // ── Command: true (exit 0) ────────────────────────────────────────
    let mut cmd2 = exec::Command("true", goish::make!([]string, 0));
    let err3 = cmd2.Run();
    check(err3 == nil, b"exec: true Run() should succeed\n");

    // ── Command: false (exit 1) → error ──────────────────────────────
    let mut cmd3 = exec::Command("false", goish::make!([]string, 0));
    let err4 = cmd3.Run();
    check(err4 != nil, b"exec: false Run() should return error\n");

    const OK: &[u8] = b"os/exec: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
