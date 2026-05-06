// runtime_stubs_smoke — exercise runtime no-op stubs.
// (proc.go:4172, 4196; extern.go:285, 330; mgc.go:455)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::goslice::slice;
use goish::runtime;
use goish::string;
use goish::{syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. LockOSThread/UnlockOSThread — no-ops, just check they're callable.
    {
        runtime::LockOSThread();
        runtime::UnlockOSThread();
        Println!("[ 1] Lock/UnlockOSThread        PASS");
    }

    // 2. NumCgoCall — slim has no cgo.
    {
        if runtime::NumCgoCall() == 0 {
            Println!("[ 2] NumCgoCall                PASS");
        } else {
            Println!("[ 2] NumCgoCall                FAIL");
            failed += 1;
        }
    }

    // 3. GC — no-op, just check callable.
    {
        runtime::GC();
        Println!("[ 3] GC                        PASS");
    }

    // 4. GOROOT — empty string in slim.
    {
        if runtime::GOROOT() == string("") {
            Println!("[ 4] GOROOT                    PASS");
        } else {
            Println!("[ 4] GOROOT                    FAIL");
            failed += 1;
        }
    }

    // 5. GoroutineProfile — (0, false) signals "no profile available".
    {
        let buf: slice<()> = slice::__from_vec(alloc::vec::Vec::new());
        let (n, ok) = runtime::GoroutineProfile(buf);
        if n == 0 && !ok {
            Println!("[ 5] GoroutineProfile          PASS");
        } else {
            Println!("[ 5] GoroutineProfile          FAIL");
            failed += 1;
        }
    }

    // 6. Existing constants still readable (regression).
    {
        if runtime::GOOS == "linux"
            && runtime::GOARCH == "amd64"
            && runtime::Compiler == "goish"
        {
            Println!("[ 6] GOOS/GOARCH/Compiler      PASS");
        } else {
            Println!("[ 6] GOOS/GOARCH/Compiler      FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 6/6");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 6");
        syscall::Exit(1);
    }
}
