// Milestone 11a convergence: the wip_strconv design as a real, running
// example.
//
// Behaviour:
//   $ sumargs 10 20 30
//   sum = 60
//
//   $ sumargs 1 abc
//   arg 1: strconv.Atoi: parsing "abc": invalid syntax
//   (exit 1)

#![no_std]
#![no_main]

use goish::{int, len, nil, os, range, strconv, Fprintf, Fprintln, Println};

#[goish::main]
fn main() {
    let all = os::Args();
    // os.Args[1:]
    let args = all.slice(1, len(&all));

    if len(&args) == 0 {
        let mut e = os::Stderr();
        Fprintln!(e, "usage: sumargs N...");
        os::Exit(1);
    }

    let mut errf = os::Stderr();
    let mut sum: int = 0;
    for (i, arg) in range!(args) {
        let (n, err) = strconv::Atoi(arg.clone());
        if err != nil {
            Fprintf!(errf, "arg %d: %v\n", i, err);
            os::Exit(1);
        }
        sum += n;
    }
    Println!("sum =", strconv::Itoa(sum));
}
