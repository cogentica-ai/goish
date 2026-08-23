// map_clear_smoke — `clear(m)` on a map (Go spec: "deletes all
// entries, resulting in an empty map"). The map must stay usable and
// keep its buckets, so a fill/clear cycle does not re-grow.
#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use goish::gomap::map;
use goish::gostring::string;
use goish::syscall;
use goish::types::int;

/// `alloc::format!` drags in fmt machinery that does not link in this
/// no_std profile; build the keys by hand.
fn key(i: i64) -> string {
    let mut b = alloc::vec::Vec::with_capacity(8);
    b.push(b'k');
    let mut d = [0u8; 20];
    let mut n = i.unsigned_abs();
    let mut j = 0;
    loop {
        d[j] = b'0' + (n % 10) as u8;
        n /= 10;
        j += 1;
        if n == 0 {
            break;
        }
    }
    while j > 0 {
        j -= 1;
        b.push(d[j]);
    }
    string::from_bytes(b.as_slice())
}

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
    let mut m: map<string, int> = map::new();
    check(m.Len() == 0, b"clear: fresh map len\n");
    m.Clear(); // clearing an empty map is a no-op
    check(m.Len() == 0, b"clear: empty clear\n");

    // Enough entries to force overflow buckets and at least one grow.
    for i in 0..500i64 {
        m.Set(key(i), i);
    }
    check(m.Len() == 500, b"clear: filled len\n");
    let (v, ok) = m.Get(key(499));
    check(ok && v == 499, b"clear: lookup before\n");

    m.Clear();
    check(m.Len() == 0, b"clear: len after\n");
    let (_, ok) = m.Get(key(499));
    check(!ok, b"clear: lookup after\n");
    check(m.Keys().len() == 0, b"clear: keys after\n");

    // Reusable: refill and read back, including keys that were present
    // before (their slots were vacated, not tombstoned in a way that
    // blocks reinsertion).
    for i in 0..500i64 {
        m.Set(key(i), i * 2);
    }
    check(m.Len() == 500, b"clear: refilled len\n");
    for i in [0i64, 1, 250, 498, 499] {
        let (v, ok) = m.Get(key(i));
        check(ok && v == i * 2, b"clear: refilled lookup\n");
    }
    m.Clear();
    check(
        m.Len() == 0 && m.Keys().len() == 0,
        b"clear: second clear\n",
    );

    let msg = b"MAP_CLEAR_OK fill/clear/refill over 500 keys\n";
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
    syscall::Exit(0);
}
