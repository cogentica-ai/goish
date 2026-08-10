// lookpath_conc_smoke — isolate the concurrency bug: does exec::LookPath
// (NO fork, NO exec) return a stable path while background goroutines
// merely exist (parked)? If this flakes, the corruption is in the
// string/heap path, unrelated to fork+exec.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::os::exec;
use goish::{go, make, string, syscall};

static SPINS: AtomicUsize = AtomicUsize::new(0);

#[goish::main]
fn main() {
    let park = make!(chan i32, 0);
    for _ in 0..8 {
        let ch = park.clone();
        go!(stack(64 * goish::KB), move || {
            let _ = ch.Recv();
            SPINS.fetch_add(1, Ordering::Relaxed);
        });
    }

    go!(stack(64 * goish::KB), move || {
        // Settle to steady state (where a real app's tool calls happen)
        // before probing — distinguishes a startup race from a
        // persistent per-call bug.
        goish::time::Sleep(goish::time::Millisecond * 100);

        // Probe the environment directly: is PATH readable?
        let path_env = goish::os::Getenv(string("PATH"));
        syscall::Write(syscall::STDERR, b"PATH=[".as_ptr(), 6);
        let pe = path_env.as_bytes();
        let n = if pe.len() > 40 { 40 } else { pe.len() };
        syscall::Write(syscall::STDERR, pe.as_ptr(), n);
        syscall::Write(syscall::STDERR, b"]\n".as_ptr(), 2);

        let mut bad = 0;
        for i in 0..200 {
            let (p, err) = exec::LookPath(string("bash"));
            let pb = p.as_bytes();
            let ok = err == goish::nil && !pb.is_empty() && pb[0] == b'/';
            if !ok {
                bad += 1;
                let _ = i;
            }
        }
        if bad > 0 {
            goish::fmt::Println!("lookpath_conc_smoke: FAIL — {}/200 bad", bad);
            syscall::Exit(1);
        }
        const OK: &[u8] = b"lookpath_conc_smoke: ok\n";
        syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
        syscall::Exit(0);
    });

    goish::runtime::sched::schedule();
}
