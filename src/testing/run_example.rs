// go: package testing
//
// go: file testing/run_example.go decls: runExample
//
// Go splits this one function out of example.go only so js/wasm —
// which has no os.Pipe — can substitute its own. goish keeps the split
// because GOISH017 wants one Go file per Rust file.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::gostring::string;
use crate::testing::example::InternalExample;

// go: sdk 1.25.5 testing/run_example.go:21-66 runExample
/// Go: run one example with stdout captured, then hand what it printed
/// to processRunResult.
///
/// Go swaps the `os.Stdout` VALUE for a pipe. goish has no such value —
/// everything writes to fd 1 directly — so the capture is done one
/// level down, where Go's os.Pipe ends up anyway: dup fd 1 aside, point
/// fd 1 at a pipe with dup3, run the example, then restore. The reader
/// runs on its own goroutine because a pipe holds only 64 KiB and an
/// example printing more than that would otherwise block forever
/// writing to a pipe nobody is draining.
#[allow(non_snake_case)]
pub fn runExample(eg: &InternalExample) -> bool {
    if crate::testing::testing::__chatty_on() {
        // Go: fmt.Printf("%s=== RUN   %s\n", chatty.prefix(), eg.Name).
        // The `{}` was a Rust placeholder.
        crate::fmt::Print!(crate::fmt::Sprintf!("=== RUN   %s\n", eg.Name.clone()));
    }

    let mut fds: [i32; 2] = [0, 0];
    if crate::syscall::Pipe2(&mut fds, 0) < 0 {
        let m = b"testing: cannot create pipe\n";
        crate::syscall::Write(crate::syscall::STDERR, m.as_ptr(), m.len());
        crate::syscall::Exit(1);
    }
    let (r, w) = (fds[0], fds[1]);

    // Keep the real stdout so it can be put back.
    let saved = crate::syscall::Dup3(1, 1024, 0);
    let saved = if saved < 0 { -1 } else { saved };
    crate::syscall::Dup3(w, 1, 0);
    crate::syscall::Close(w);

    // Go: `go func() { io.Copy(&buf, r); outC <- buf.String() }()`.
    let out: Arc<crate::sync::Mutex<Vec<crate::types::byte>>> =
        Arc::new(crate::sync::Mutex::new(Vec::new()));
    let done: crate::gochan::chan<bool> = crate::gochan::chan::new_buffered(1);
    let out2 = out.clone();
    let done2 = done.clone();
    crate::go!(stack(64 * 1024), move || {
        let mut buf = [0u8; 4096];
        loop {
            let n = crate::syscall::Read(r, buf.as_mut_ptr(), buf.len());
            if n <= 0 {
                break;
            }
            out2.Lock().extend_from_slice(&buf[..n as usize]);
        }
        crate::syscall::Close(r);
        done2.Send(true);
    });

    let start = crate::time::Now();
    (eg.F)();
    let finished = true;
    let timeSpent = crate::time::Since(start);

    // Restore stdout FIRST — closing the write end is what gives the
    // reader its EOF, and until fd 1 points back at the real stdout
    // nothing printed after this would be visible.
    if saved >= 0 {
        crate::syscall::Dup3(saved, 1, 0);
        crate::syscall::Close(saved);
    }
    let _ = done.Recv();

    let captured = string::from_bytes(&out.Lock());
    return eg.processRunResult(captured, timeSpent, finished);
}
