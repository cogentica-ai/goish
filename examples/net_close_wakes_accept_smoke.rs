// net_close_wakes_accept_smoke — Listener.Close wakes a parked Accept.
//
// Go's contract: a goroutine blocked in Accept is woken by Close and
// gets net.ErrClosed ("use of closed network connection"). goish's
// Close used to tear the fd down WITHOUT waking the parker — kernel
// close(2) drops the fd from epoll's interest set and delivers
// nothing to existing waiters — so every ported teardown hung at
// wg.Wait() with all assertions green, until someone hand-inserted
// __wake_accept(). This test is the discriminator for the fix in
// Close itself:
//
//   * the accepter goroutine REALLY parks (Close only happens after
//     Accept has been entered and given time to reach the netpoller),
//   * the WaitGroup completes — impossible on the old code,
//   * the woken Accept's error is ErrClosed, not a timeout: a wake
//     that fires the deadline path without consulting `closed` would
//     hand back the wrong error and break Go's errors.Is contract.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

use goish::errors;
use goish::fmt;
use goish::net;
use goish::sync::WaitGroup;
use goish::time;
use goish::{go, string};

static FAILED: AtomicUsize = AtomicUsize::new(0);
/// 0 = accepter never returned, 1 = ErrClosed, 2 = some other error,
/// 3 = accept unexpectedly succeeded.
static OUTCOME: AtomicI64 = AtomicI64::new(0);

fn check(name: &'static str, ok: bool, detail: goish::string) {
    if ok {
        fmt::Printf!("PASS: %s\n", name);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("FAIL: %s — %s\n", name, detail);
    }
}

#[goish::main]
fn main() {
    goish::go!(stack(512 * 1024), move || {
        run();
    });
    loop {
        goish::runtime::sched::Gosched();
    }
}

fn run() -> ! {
    let (ln, lerr) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    if !lerr.IsNil() {
        check("listen", false, fmt::Sprintf!("%v", lerr));
        finish();
    }
    let ln = alloc::sync::Arc::new(ln);

    static WG: WaitGroup = WaitGroup::new();
    WG.Add(1);
    let ln2 = ln.clone();
    go!(stack(256 * 1024), move || {
        // Nothing ever dials, so this Accept parks on the netpoller
        // until Close evicts it.
        let (_, err) = ln2.Accept();
        OUTCOME.store(
            if err.IsNil() {
                3
            } else if errors::Is(err, net::ErrClosed) {
                1
            } else {
                2
            },
            Ordering::Release,
        );
        WG.Done();
    });

    // Let the accepter actually reach the parked state — a Close that
    // wins the race before the park would pass for the wrong reason
    // (the accepter would just see EBADF on entry).
    time::Sleep(time::Duration(200 * 1_000_000));

    let cerr = ln.Close();
    check("Close returns nil", cerr.IsNil(), fmt::Sprintf!("%v", cerr));

    // The whole point: this Wait hangs forever on the old code.
    WG.Wait();

    check(
        "parked Accept woke and returned ErrClosed",
        OUTCOME.load(Ordering::Acquire) == 1,
        fmt::Sprintf!(
            "outcome=%d (2=wrong error, 3=accept succeeded)",
            OUTCOME.load(Ordering::Acquire)
        ),
    );
    check(
        "second Close is a nil no-op",
        ln.Close().IsNil(),
        string(""),
    );

    finish();
}

fn finish() -> ! {
    let f = FAILED.load(Ordering::Relaxed);
    if f == 0 {
        fmt::Printf!("NET_CLOSE_WAKES_ACCEPT_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("NET_CLOSE_WAKES_ACCEPT_FAIL\n");
    goish::os::Exit(1);
}
