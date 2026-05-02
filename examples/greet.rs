// Final convergence: the wip_greet design as a real, running example.
//
// Compare against examples/wip_greet.md — every line of the proposed
// goish syntax in that doc now compiles and runs. The only piece still
// stubbed is `strings::ToUpper` (M10), replaced inline below.
//
// Behaviour:
//   $ greet alice "" bob
//   Hello, ALICE!
//   arg 1: name cannot be empty
//   Hello, BOB!

#![no_std]
#![no_main]

use goish::{error, errors, len, nil, os, range, string, Fprintf, Fprintln, Println, Sprintf};

// Stand-in for `strings::ToUpper` (M10). Just uppercases ASCII letters,
// leaves the rest alone — fine for this demo's input.
fn ascii_upper(s: string) -> string {
    use goish::int;
    let bs = goish::bytes(s);
    let mut out = goish::make!([]goish::byte, len(&bs));
    let mut i: int = 0;
    let n = len(&bs);
    while i < n {
        let b = bs[i];
        out[i] = if b >= b'a' && b <= b'z' {
            b - 32
        } else {
            b
        };
        i += 1;
    }
    goish::string(out)
}

fn greet(name: string) -> (string, error) {
    if name == "" {
        return (string(""), errors::New("name cannot be empty"));
    }
    (Sprintf!("Hello, %s!", ascii_upper(name)), nil.into())
}

#[goish::main]
fn main() {
    let all = os::Args();
    // os.Args[1:] — Go's slice expression mapped to .slice() per
    // ROADMAP.md (copy semantics, not a view).
    let args = all.slice(1, len(&all));

    if len(&args) == 0 {
        let mut e = os::Stderr();
        Fprintln!(e, "usage: greet NAME...");
        os::Exit(1);
    }

    let mut errf = os::Stderr();
    for (i, name) in range!(args) {
        let (msg, err) = greet(name.clone());
        if err != nil {
            Fprintf!(errf, "arg %d: %v\n", i, err);
            continue;
        }
        Println!(msg);
    }
}
