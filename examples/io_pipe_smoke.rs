// io_pipe_smoke — exercise io.Pipe.
//
// Validates the line-by-line port of /share/go/src/io/pipe.go:
//   • One writer goroutine + one reader goroutine talking via the
//     unbuffered chan-pair underneath.
//   • Reader.Close() makes Writer.Write return ErrClosedPipe.
//   • Writer.Close() makes Reader.Read return EOF.
//   • Writer.CloseWithError(err) propagates `err` to the Reader side.
//   • ErrClosedPipe is a stable sentinel (Arc::ptr_eq via errors::Is).
//
// Goish-runtime convention: `schedule()` never returns to user code
// (it drains the queue and `Exit(0)`s), so each test's verification
// happens INSIDE its goroutines via `check()` / `die()`. Process
// exit-code 0 = all checks passed; non-zero = a check failed and
// printed a message to stderr.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;

use goish::convert;
use goish::errors;
use goish::io;
use goish::{go, make, string, syscall, KB};

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
    const START: &[u8] = b"io_pipe: starting\n";
    syscall::Write(syscall::STDOUT, START.as_ptr(), START.len());

    // ─── Test 1: ErrClosedPipe is stable + message matches Go ─────
    {
        let a: errors::error = io::ErrClosedPipe.into();
        let b: errors::error = io::ErrClosedPipe.into();
        check(!a.IsNil(), b"io_pipe: T1 ErrClosedPipe nil\n");
        check(
            a.Error() == "io: read/write on closed pipe",
            b"io_pipe: T1 ErrClosedPipe message wrong\n",
        );
        check(
            errors::Is(a, b),
            b"io_pipe: T1 ErrClosedPipe not stable\n",
        );
    }

    // ─── Test 2: Write -> Read; Writer.Close() -> Reader EOF ──────
    let (mut r1, mut w1) = io::Pipe();

    go!(stack(64 * KB), move || {
        let payload = convert::bytes("Hello");
        let (n, err) = w1.Write(payload);
        check(err.IsNil(), b"io_pipe: T2 Write returned non-nil err\n");
        check(n == 5, b"io_pipe: T2 Write returned wrong n\n");
        let _ = w1.Close();
    });

    go!(stack(64 * KB), move || {
        // First Read: get the 5 payload bytes.
        let mut buf = make!([]goish::byte, 16);
        let (n, err) = r1.Read(&mut buf);
        check(err.IsNil(), b"io_pipe: T2 1st Read returned non-nil err\n");
        check(n == 5, b"io_pipe: T2 1st Read returned wrong n\n");
        check(
            buf[0] == b'H'
                && buf[1] == b'e'
                && buf[2] == b'l'
                && buf[3] == b'l'
                && buf[4] == b'o',
            b"io_pipe: T2 payload corrupted\n",
        );
        // Second Read: should return (0, EOF) because Writer.Close().
        let (n2, err2) = r1.Read(&mut buf);
        check(n2 == 0, b"io_pipe: T2 2nd Read n != 0\n");
        check(
            errors::Is(err2, io::EOF),
            b"io_pipe: T2 2nd Read err != EOF\n",
        );
    });

    // ─── Test 3: Reader.Close() -> Writer sees ErrClosedPipe ──────
    let (mut r2, mut w2) = io::Pipe();

    go!(stack(64 * KB), move || {
        let _ = r2.Close();
    });

    go!(stack(64 * KB), move || {
        // Even if our Write races and runs before close, the Write
        // blocks on the unbuffered chan, the close fires, and Write
        // unblocks with the error.
        let payload = convert::bytes("never read");
        let (_, err) = w2.Write(payload);
        check(!err.IsNil(), b"io_pipe: T3 Write returned nil err\n");
        check(
            errors::Is(err, io::ErrClosedPipe),
            b"io_pipe: T3 Write err != ErrClosedPipe\n",
        );
    });

    // ─── Test 4: Writer.CloseWithError(err) propagates to Reader ──
    let custom_err = errors::New(string("custom pipe error"));
    let custom_err_for_writer = custom_err.clone();
    let (mut r3, w3) = io::Pipe();

    go!(stack(64 * KB), move || {
        let _ = w3.CloseWithError(custom_err_for_writer);
    });

    go!(stack(64 * KB), move || {
        let mut buf = make!([]goish::byte, 8);
        let (n, err) = r3.Read(&mut buf);
        check(n == 0, b"io_pipe: T4 Read n != 0\n");
        check(
            errors::Is(err, custom_err),
            b"io_pipe: T4 Read err != custom_err\n",
        );
    });

    // ─── Final OK message in a goroutine that runs after the rest ──
    // Spawn it last; with FIFO scheduling on the main M's runq it
    // gets dispatched after all the checker Gs have run-and-yielded
    // through their chan ops. Each test is self-verifying — if we
    // reach here, exit 0 means all checks passed.
    go!(stack(64 * KB), || {
        const OK: &[u8] = b"ok io_pipe (4 tests)\n";
        syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
    });
}
