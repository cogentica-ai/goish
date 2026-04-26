// M13 convergence: time package end-to-end.
//
//   $ stopwatch 250
//   requested: 250 ms
//   elapsed: 250.something_ms

#![no_std]
#![no_main]

use goish::{len, nil, os, strconv, time, Fprintln, Println};

#[goish::main]
fn main() {
    let all = os::Args();
    if len(&all) != 2 {
        let mut e = os::Stderr();
        Fprintln!(e, "usage: stopwatch MILLIS");
        os::Exit(1);
    }
    let (ms, err) = strconv::Atoi(all[1].clone());
    if err != nil {
        let mut e = os::Stderr();
        Fprintln!(e, "parse:", err);
        os::Exit(1);
    }
    let start = time::Now();
    time::Sleep(time::Millisecond * ms);
    let elapsed = time::Since(start);
    Println!("requested:", ms, "ms");
    Println!("elapsed:", elapsed);
}
