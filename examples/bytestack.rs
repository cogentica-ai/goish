// M13 convergence: bytes package ⇄ bufio Scanner pipeline.
//
//   $ printf 'apple,banana, cherry\n  date,fig\n' | bytestack ,
//     - APPLE
//     - BANANA
//     - CHERRY
//     - DATE
//     - FIG

#![no_std]
#![no_main]

use goish::fmt;
use goish::{bufio, len, nil, os, range};

#[goish::main]
fn main() {
    let all = os::Args();
    if len(&all) != 2 {
        let mut e = os::Stderr();
        fmt::Fprintln!(e, "usage: bytestack SEP");
        os::Exit(1);
    }
    // os.Args[1] is the separator as a string; convert to slice<byte>.
    let sep = goish::bytes(all[1].clone());

    let mut sc = bufio::NewScanner(os::Stdin());
    while sc.Scan() {
        let line = sc.Bytes();
        for (_, field) in range!(goish::bytes::Split(line, sep.clone())) {
            let field = goish::bytes::TrimSpace(field.clone());
            if len(&field) == 0 {
                continue;
            }
            let field = goish::bytes::ToUpper(field);
            fmt::Printf!("  - %s\n", goish::string(field));
        }
    }
    let err = sc.Err();
    if err != nil {
        let mut e = os::Stderr();
        fmt::Fprintln!(e, "scan:", err);
        os::Exit(1);
    }
}
