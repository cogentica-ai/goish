// runtime_goos_goarch_smoke — exercise runtime.GOOS / GOARCH / Compiler
// (extern.go:397/:401/:412) + runtime.Version() (extern.go:439).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::runtime;
use goish::string;
use goish::{syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. GOOS == "linux" — goish v1 is Linux-only.
    {
        if runtime::GOOS == "linux" {
            Println!("[ 1] GOOS == \"linux\"          PASS");
        } else {
            Println!("[ 1] GOOS == \"linux\"          FAIL got=", runtime::GOOS);
            failed += 1;
        }
    }

    // 2. GOARCH == "amd64" — goish v1 is x86_64-only.
    {
        if runtime::GOARCH == "amd64" {
            Println!("[ 2] GOARCH == \"amd64\"        PASS");
        } else {
            Println!("[ 2] GOARCH == \"amd64\"        FAIL got=", runtime::GOARCH);
            failed += 1;
        }
    }

    // 3. Compiler == "goish".
    {
        if runtime::Compiler == "goish" {
            Println!("[ 3] Compiler == \"goish\"      PASS");
        } else {
            Println!("[ 3] Compiler == \"goish\"      FAIL");
            failed += 1;
        }
    }

    // 4. Version() returns a non-empty string starting with "goish".
    {
        let v = runtime::Version();
        if v.Len() > 0 && goish::strings::HasPrefix(v.clone(), string("goish")) {
            Println!("[ 4] Version() shape           PASS");
        } else {
            Println!("[ 4] Version() shape           FAIL");
            failed += 1;
        }
    }

    // 5. Constants flow into goish::string via string() conversion.
    {
        let goos_str: string = string(runtime::GOOS);
        if goos_str == string("linux") {
            Println!("[ 5] GOOS via string()         PASS");
        } else {
            Println!("[ 5] GOOS via string()         FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 5/5");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 5");
        syscall::Exit(1);
    }
}
