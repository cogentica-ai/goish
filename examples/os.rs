// Milestone 7 smoke test: os package.
//
// Tests Stdout/Stderr (via io::Writer impl), Args (kernel-supplied
// argv), Exit (via syscall path). Writes through os::Stdout instead
// of raw syscall::Write to prove the io::Writer chain works.

#![no_std]
#![no_main]

use goish::{bytes, len, os, range, string, syscall};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

#[goish::main]
fn main() {
    // (1) os::Args() — argv as slice<string>. Always at least 1 entry
    //     (program name = argv[0]).
    let args = os::Args();
    check(len(&args) >= 1, b"os: Args must have at least argv[0]\n");

    // (2) Args[0] should look like a path (we can't assert exact value
    //     since cargo runs the binary at a temp path; just check it's
    //     non-empty).
    check(args[0].Len() > 0, b"os: argv[0] empty\n");

    // (3) os::Stdout returns a usable io::Writer.
    let out = os::Stdout();
    let payload = bytes(string("os: write via Stdout — "));
    let (n, err) = out.Write(payload);
    check(n > 0, b"os: Stdout.Write n=0\n");
    check(err == goish::nil, b"os: Stdout.Write err\n");

    // (4) Stderr likewise.
    let errf = os::Stderr();
    let stderr_msg = bytes(string("os: stderr ok\n"));
    let (n, err) = errf.Write(stderr_msg);
    check(n > 0, b"os: Stderr.Write n=0\n");
    check(err == goish::nil, b"os: Stderr.Write err\n");

    // (5) File.Fd() / Name() round-trip.
    let stdout = os::Stdout();
    check(stdout.Fd() == 1, b"os: Stdout fd != 1\n");
    check(stdout.Name() == "/dev/stdout", b"os: Stdout name wrong\n");

    // (6) Range over Args — exercise both range! and Args iteration.
    let mut total_bytes: goish::int = 0;
    for (_, a) in range!(args) {
        total_bytes += a.Len();
    }
    check(total_bytes > 0, b"os: argv total len = 0\n");

    // (7) os::Exit equivalence — call os::Exit(0) instead of
    //     syscall::Exit(0). The success marker prints first.
    const OK: &[u8] = b"os: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
    os::Exit(0);
}
