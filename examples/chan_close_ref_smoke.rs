//! Pinned against Go 1.25.5: what a CLOSED channel does.
//!
//! There are eleven `chan_*` examples and a `select_smoke`, all of
//! them tier-3 stress or throughput harnesses, and no reference smoke
//! for the semantics underneath them. Close is where those semantics
//! are least guessable and most relied on — every worker pool, every
//! fan-in, every "done" signal is built on these ten answers.
//!
//! goish matches Go on all ten. No defects; the commit is the smoke.
//!
//! The ones a reimplementation gets wrong:
//!
//!   * A closed BUFFERED channel DRAINS first. Two sends then a close
//!     still yield 1 and 2 with ok=true, and only then zero/false.
//!     Close means "no more sends", not "discard what is queued" — a
//!     producer that closes after filling the buffer loses nothing.
//!   * `len` after close is 0 but `cap` is UNCHANGED. The capacity is
//!     a property of the channel, not of what is in it.
//!   * `select` on a closed channel ALWAYS fires the receive, never
//!     the default. A closed channel is permanently ready, which is
//!     what makes `case <-done:` work as a broadcast.
//!   * `select` with a default on an EMPTY OPEN channel takes the
//!     default. Those two lines sit next to each other here because
//!     confusing them is how a done-channel poll turns into a
//!     busy-loop or a deadlock.
//!   * `range` stops AT the close, having delivered the buffer.
//!
//! Reference generated with:
//!   CGO_ENABLED=0 scripts/goref.sh sync <chanclose_ref_test.go>
#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use goish::{fmt, make, range, select, string};

/// Go's output, verbatim.
const GO: [&str; 10] = [
    "recv-1                       [1 true]",
    "recv-2                       [2 true]",
    "recv-drained                 [0 false]",
    "recv-again                   [0 false]",
    "len-cap-after-close          [0 3]",
    "range-closed                 [15 2]",
    "select-closed                [recv ok=false]",
    "select-empty-default         [default]",
    "len-cap                      [1 4]",
    "unbuffered-cap               [0 0]",
];

static mut FAILED: i64 = 0;
static mut LINE: usize = 0;

fn line(tag: &'static str, parts: alloc::vec::Vec<string>) {
    let mut out = string("");
    for (i, x) in parts.iter().enumerate() {
        if i > 0 {
            out = out + string(" ");
        }
        out = out + x.clone();
    }
    chk(fmt::Sprintf!("%-28s [%s]", string::from_static(tag), out));
}

/// Compare one rendered line against the Go reference, in order.
fn chk(got: string) {
    let i = unsafe { LINE };
    unsafe { LINE += 1 };
    let want = string::from_static(GO[i]);
    if got == want {
        return;
    }
    fmt::Printf!("DIFF go   : %s\n", want);
    fmt::Printf!("     goish: %s\n", got);
    unsafe { FAILED += 1 };
}
fn n(v: i64) -> string {
    fmt::Sprintf!("%d", v)
}
fn b(v: bool) -> string {
    fmt::Sprintf!("%v", v)
}

#[goish::main]
fn main() {
    goish::go!(stack(1024 * 1024), move || {
        run();
    });
    loop {
        goish::runtime::sched::Gosched();
    }
}

fn run() {
    let c = make!(chan i64, 3);
    c.Send(1);
    c.Send(2);
    c.Close();
    let (v, ok) = c.Recv();
    line("recv-1", alloc::vec![n(v), b(ok)]);
    let (v, ok) = c.Recv();
    line("recv-2", alloc::vec![n(v), b(ok)]);
    let (v, ok) = c.Recv();
    line("recv-drained", alloc::vec![n(v), b(ok)]);
    let (v, ok) = c.Recv();
    line("recv-again", alloc::vec![n(v), b(ok)]);
    line(
        "len-cap-after-close",
        alloc::vec![n(c.Len() as i64), n(c.Cap() as i64)],
    );

    let d = make!(chan i64, 2);
    d.Send(7);
    d.Send(8);
    d.Close();
    let mut sum = 0i64;
    let mut cnt = 0i64;
    for x in range!(d) {
        sum += x;
        cnt += 1;
    }
    line("range-closed", alloc::vec![n(sum), n(cnt)]);

    let e = make!(chan i64, 0);
    e.Close();
    let mut hit = string("");
    select! {
        let (_v, ok) = e.Recv() => { hit = string("recv ok=") + b(ok); },
        default => { hit = string("default"); },
    }
    line("select-closed", alloc::vec![hit]);

    let f = make!(chan i64, 1);
    let mut hit2 = string("");
    select! {
        let (_v, _ok) = f.Recv() => { hit2 = string("recv"); },
        default => { hit2 = string("default"); },
    }
    line("select-empty-default", alloc::vec![hit2]);

    let g = make!(chan i64, 4);
    g.Send(1);
    line("len-cap", alloc::vec![n(g.Len() as i64), n(g.Cap() as i64)]);

    let h = make!(chan i64, 0);
    line(
        "unbuffered-cap",
        alloc::vec![n(h.Len() as i64), n(h.Cap() as i64)],
    );

    let failed = unsafe { FAILED };
    let nn = GO.len() as i64;
    if failed == 0 {
        fmt::Printf!("channel close: %d/%d match Go\n", nn, nn);
        goish::os::Exit(0);
    }
    fmt::Printf!("FAIL: %d/%d diverge\n", failed, nn);
    goish::os::Exit(1);
}
