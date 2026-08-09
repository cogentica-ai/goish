// M12.5 convergence: bufio Scanner reads stdin line-by-line, ASCII-uppercases,
// writes to stdout.
//
//   $ printf 'hello\nworld\n' | uppercase
//   HELLO
//   WORLD

#![no_std]
#![no_main]

use goish::fmt;
use goish::{bufio, nil, os, strings};

#[goish::main]
fn main() {
    let mut sc = bufio::NewScanner(os::Stdin());
    while sc.Scan() {
        fmt::Println!(strings::ToUpper(sc.Text()));
    }
    let err = sc.Err();
    if err != nil {
        let mut e = os::Stderr();
        fmt::Fprintln!(e, "scan:", err);
        os::Exit(1);
    }
}
