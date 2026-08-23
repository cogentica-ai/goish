// fmt_sprint_smoke — exercise fmt.Sprint + fmt.Sprintln macros.
// (print.go:267, 283)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::string;
use goish::syscall;
use goish::types::int;

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Sprint with a single string.
    {
        let s = fmt::Sprint!(string("hello"));
        if s == string("hello") {
            fmt::Println!("[ 1] Sprint single             PASS");
        } else {
            fmt::Println!("[ 1] Sprint single             FAIL: ", s);
            failed += 1;
        }
    }

    // 2. Sprint concatenates without spaces (slim deviation, matches Print).
    {
        let s = fmt::Sprint!(string("foo"), string("bar"));
        if s == string("foobar") {
            fmt::Println!("[ 2] Sprint concat             PASS");
        } else {
            fmt::Println!("[ 2] Sprint concat             FAIL: ", s);
            failed += 1;
        }
    }

    // 3. Sprint with int.
    {
        let n: int = 42;
        let s = fmt::Sprint!(n);
        if s == string("42") {
            fmt::Println!("[ 3] Sprint int                PASS");
        } else {
            fmt::Println!("[ 3] Sprint int                FAIL: ", s);
            failed += 1;
        }
    }

    // 4. Sprintln with single string.
    {
        let s = fmt::Sprintln!(string("hi"));
        if s == string("hi\n") {
            fmt::Println!("[ 4] Sprintln single           PASS");
        } else {
            fmt::Println!("[ 4] Sprintln single           FAIL: ", s);
            failed += 1;
        }
    }

    // 5. Sprintln separates with spaces.
    {
        let s = fmt::Sprintln!(string("a"), string("b"), string("c"));
        if s == string("a b c\n") {
            fmt::Println!("[ 5] Sprintln spaces           PASS");
        } else {
            fmt::Println!("[ 5] Sprintln spaces           FAIL: ", s);
            failed += 1;
        }
    }

    // 6. Sprintln with int + string mix.
    {
        let n: int = 7;
        let s = fmt::Sprintln!(n, string("widgets"));
        if s == string("7 widgets\n") {
            fmt::Println!("[ 6] Sprintln mix              PASS");
        } else {
            fmt::Println!("[ 6] Sprintln mix              FAIL: ", s);
            failed += 1;
        }
    }

    // 7. Sprint with empty args produces empty string.
    {
        let s = fmt::Sprint!();
        if s == string("") {
            fmt::Println!("[ 7] Sprint empty              PASS");
        } else {
            fmt::Println!("[ 7] Sprint empty              FAIL: ", s);
            failed += 1;
        }
    }

    // 8. Sprintln with no args produces just newline.
    {
        let s = fmt::Sprintln!();
        if s == string("\n") {
            fmt::Println!("[ 8] Sprintln empty            PASS");
        } else {
            fmt::Println!("[ 8] Sprintln empty            FAIL: ", s);
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 8/8");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 8");
        syscall::Exit(1);
    }
}
