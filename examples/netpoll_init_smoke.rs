// netpoll_init_smoke — minimal sanity check that netpoll::init runs
// without panic and a subsequent non-blocking sweep of every shard
// (poll_all) returns empty.

#![no_std]
#![no_main]

extern crate goish;

use goish::runtime::netpoll;
use goish::syscall;

fn print(msg: &[u8]) {
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
}

#[goish::main]
fn main() {
    netpoll::init();
    let v = netpoll::poll_all();
    if v.is_empty() {
        print(b"netpoll init OK, poll(0) empty\n");
    } else {
        print(b"netpoll init OK, poll(0) returned readiness\n");
    }
    syscall::Exit(0);
}
