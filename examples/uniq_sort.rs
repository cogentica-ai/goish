// Milestone 12 convergence: the wip_slices_lib design as a real,
// running example.
//
// Behaviour:
//   $ uniq_sort 3 1 4 1 5 9 2 6 5 3 5
//   1
//   2
//   3
//   4
//   5
//   6
//   9
//
//   $ uniq_sort 1 abc
//   arg 1: strconv.Atoi: parsing "abc": invalid syntax
//   (exit 1)

#![no_std]
#![no_main]

use goish::{
    append, int, len, make, nil, os, range, slices, strconv, Fprintf, Fprintln, Println,
};

#[goish::main]
fn main() {
    let all = os::Args();
    let args = all.slice(1, len(&all));

    if len(&args) == 0 {
        let mut e = os::Stderr();
        Fprintln!(e, "usage: uniq_sort N...");
        os::Exit(1);
    }

    let mut errf = os::Stderr();
    let mut nums = make!([]int, 0, len(&args));
    for (i, arg) in range!(args) {
        let (n, err) = strconv::Atoi(arg.clone());
        if err != nil {
            Fprintf!(errf, "arg %d: %v\n", i, err);
            os::Exit(1);
        }
        nums = append!(nums, n);
    }

    slices::Sort!(nums);
    let nums = slices::Compact(nums);

    for (_, n) in range!(nums) {
        Println!(*n);
    }
}
