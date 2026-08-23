// os/exec StdoutPipe / StderrPipe contract test — the streaming-read capability
// the go-git file transport depends on. Run `echo`, read its stdout via
// StdoutPipe() while the child runs, then Wait(); assert the bytes match.

#![no_std]
#![no_main]

extern crate alloc;
use alloc::vec::Vec;

use goish::io;
use goish::os::exec;
use goish::{byte, nil, slice, string, syscall};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

// Read everything from a reader into a Vec<u8> until EOF.
fn read_all(r: &mut dyn io::Reader) -> Vec<u8> {
    let mut acc: Vec<u8> = Vec::new();
    loop {
        let mut buf: slice<byte> = goish::make!([]byte, 4096);
        let (n, err) = r.Read(&mut buf);
        if n > 0 {
            let nn = n as usize;
            let mut i: usize = 0;
            while i < nn {
                acc.push(buf[i as i64]);
                i += 1;
            }
        }
        if err != nil {
            break;
        }
        if n == 0 {
            break;
        }
    }
    acc
}

#[goish::main]
fn main() {
    // ── StdoutPipe: echo hi-from-stdout ───────────────────────────────
    let mut cmd = exec::Command("echo", goish::slice!([]string{ "hi-from-stdout" }));
    let (mut out, err) = cmd.StdoutPipe();
    check(err == nil, b"exec: StdoutPipe() error\n");

    let err = cmd.Start();
    check(err == nil, b"exec: Start() after StdoutPipe error\n");

    let got = read_all(&mut out);
    let err = cmd.Wait();
    check(err == nil, b"exec: Wait() after StdoutPipe error\n");

    // echo appends a trailing newline.
    check(
        &got[..] == b"hi-from-stdout\n",
        b"exec: StdoutPipe content mismatch\n",
    );

    // ── StderrPipe: sh -c 'echo err 1>&2' ─────────────────────────────
    let mut cmd2 = exec::Command(
        "sh",
        goish::slice!([]string{ "-c", "echo err-from-stderr 1>&2" }),
    );
    let (mut errpipe, e1) = cmd2.StderrPipe();
    check(e1 == nil, b"exec: StderrPipe() error\n");
    let e2 = cmd2.Start();
    check(e2 == nil, b"exec: Start() after StderrPipe error\n");
    let got_err = read_all(&mut errpipe);
    let e3 = cmd2.Wait();
    check(e3 == nil, b"exec: Wait() after StderrPipe error\n");
    check(
        &got_err[..] == b"err-from-stderr\n",
        b"exec: StderrPipe content mismatch\n",
    );

    const OK: &[u8] = b"os/exec StdoutPipe/StderrPipe: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
