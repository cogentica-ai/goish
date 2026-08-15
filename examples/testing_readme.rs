// testing_readme — the `testing` snippet shown in README.md, kept as a
// declared example so the README cannot drift from code that compiles.
//
// Everything below the attributes is byte-identical to the fenced block
// under README.md's "Testing" heading. If you edit one, edit both.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

use goish::{fmt, strings, syscall, testing};
use goish::types::int;

fn TestAddition(t: &mut testing::T) {
    let got: int = 2 + 3;
    if got != 5 {
        t.Error(fmt::Sprintf!("2+3 = %d, want 5", got));
    }
}

fn TestSubtests(t: &mut testing::T) {
    t.Run("upper", |t| {
        let got = strings::ToUpper("go");
        if got != "GO" {
            t.Error(fmt::Sprintf!("ToUpper(go) = %s, want GO", got));
        }
    });

    t.Run("cleanup", |t| {
        // Cleanups run LIFO when the test function returns, as in Go.
        t.Cleanup(|| { fmt::Println!("second"); });
        t.Cleanup(|| { fmt::Println!("first"); });
    });
}

#[goish::main]
fn main() {
    let tests: &[(&str, testing::TestFn)] = &[
        ("TestAddition", TestAddition),
        ("TestSubtests", TestSubtests),
    ];
    syscall::Exit(testing::Main(tests) as i32);
}
