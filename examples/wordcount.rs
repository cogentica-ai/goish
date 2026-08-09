// map<K,V> convergence: word-count CLI.
//
//   $ printf 'the quick brown fox\nThe lazy dog the\n' | wordcount
//        1 brown
//        1 dog
//        1 fox
//        1 lazy
//        1 quick
//        3 the

#![no_std]
#![no_main]

use goish::fmt;
use goish::{bufio, int, make, os, range, slices, string, strings};

#[goish::main]
fn main() {
    let mut counts = make!(map[string]int);

    let mut sc = bufio::NewScanner(os::Stdin());
    sc.Split(bufio::ScanWords);
    while sc.Scan() {
        let word = strings::ToLower(sc.Text());
        counts[word] += 1;
    }

    let mut keys = counts.Keys();
    slices::Sort!(keys);

    for (_, k) in range!(keys) {
        let n = counts[k.clone()];
        fmt::Printf!("%6d %s\n", n, k.clone());
    }
}
