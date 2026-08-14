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

    // ── Cmd.Dir is honored by the child ──────────────────────────────
    // `pwd` prints the child's cwd; with Dir set it must be /tmp, and
    // the PARENT's cwd must be untouched (the chdir lives between fork
    // and exec, so a chdir in the parent would race every goroutine).
    {
        let mut cmd4 = exec::Command("pwd", goish::make!([]string, 0));
        cmd4.Dir = string::from_static("/tmp");
        let (out, err5) = cmd4.StdoutPipe();
        check(err5 == nil, b"exec: StdoutPipe error\n");
        let mut out = out;
        let err6 = cmd4.Start();
        check(err6 == nil, b"exec: pwd Start error\n");
        let mut buf = goish::make!([]goish::byte, 256);
        let (n, _) = goish::io::Reader::Read(&mut out, &mut buf);
        let _ = cmd4.Wait();
        let got = goish::string::from_bytes(&buf.slice(0, n));
        let g: &str = got.as_ref();
        check(g.trim_end() == "/tmp", b"exec: Cmd.Dir was not honored\n");
    }

    // ── Cmd.Kill terminates a running child ──────────────────────────
    {
        let mut cmd5 = exec::Command("sleep", goish::slice!([]string{ "30" }));
        let err7 = cmd5.Start();
        check(err7 == nil, b"exec: sleep Start error\n");
        let err8 = cmd5.Kill();
        check(err8 == nil, b"exec: Kill returned an error\n");
        // Wait must return promptly (killed), not in 30 seconds.
        let start = goish::time::Now();
        let _ = cmd5.Wait();
        let elapsed = goish::time::Since(start);
        check(
            elapsed < goish::time::Duration(5 * 1_000_000_000),
            b"exec: Wait after Kill took too long\n",
        );
        // Killing a reaped pid is refused rather than signalling a
        // pid the kernel may have handed to someone else.
        check(cmd5.Kill() != nil, b"exec: Kill after Wait should fail\n");
    }

    const OK: &[u8] = b"os/exec: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
