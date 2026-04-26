// M12.5 convergence: bufio Scanner reads stdin line-by-line, ASCII-uppercases,
// writes to stdout.
//
//   $ printf 'hello\nworld\n' | uppercase
//   HELLO
//   WORLD

#![no_std]
#![no_main]

use goish::{bufio, nil, os, strings, Fprintln, Println};

#[goish::main]
fn main() {
    let mut sc = bufio::NewScanner(os::Stdin());
    while sc.Scan() {
        Println!(strings::ToUpper(sc.Text()));
    }
    let err = sc.Err();
    if err != nil {
        let mut e = os::Stderr();
        Fprintln!(e, "scan:", err);
        os::Exit(1);
    }
}
