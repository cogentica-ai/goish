// runtime_stubs_smoke — exercise the compact runtime compatibility surface.
// (proc.go:4172, 4196; extern.go:285, 330; mgc.go:455)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::goslice::slice;
use goish::runtime;
use goish::string;
use goish::syscall;

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Focused pinning semantics live in lock_os_thread_smoke; retain the
    // public API call check here.
    {
        runtime::LockOSThread();
        runtime::UnlockOSThread();
        fmt::Println!("[ 1] Lock/UnlockOSThread        PASS");
    }

    // 2. NumCgoCall — slim has no cgo.
    {
        if runtime::NumCgoCall() == 0 {
            fmt::Println!("[ 2] NumCgoCall                PASS");
        } else {
            fmt::Println!("[ 2] NumCgoCall                FAIL");
            failed += 1;
        }
    }

    // 3. GC — no-op, just check callable.
    {
        runtime::GC();
        fmt::Println!("[ 3] GC                        PASS");
    }

    // 4. GOROOT — empty string in slim.
    {
        if runtime::GOROOT() == string("") {
            fmt::Println!("[ 4] GOROOT                    PASS");
        } else {
            fmt::Println!("[ 4] GOROOT                    FAIL");
            failed += 1;
        }
    }

    // 5. GoroutineProfile — (0, false) signals "no profile available".
    {
        let buf: slice<()> = slice::__from_vec(alloc::vec::Vec::new());
        let (n, ok) = runtime::GoroutineProfile(buf);
        if n == 0 && !ok {
            fmt::Println!("[ 5] GoroutineProfile          PASS");
        } else {
            fmt::Println!("[ 5] GoroutineProfile          FAIL");
            failed += 1;
        }
    }

    // 6. Existing constants still readable (regression).
    {
        if runtime::GOOS == "linux" && runtime::GOARCH == "amd64" && runtime::Compiler == "goish" {
            fmt::Println!("[ 6] GOOS/GOARCH/Compiler      PASS");
        } else {
            fmt::Println!("[ 6] GOOS/GOARCH/Compiler      FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 6/6");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 6");
        syscall::Exit(1);
    }
}
