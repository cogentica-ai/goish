// os_stat_smoke — verify os::Open + os::Stat + File.Stat.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::io::Reader;
use goish::os;
use goish::{string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Stat /etc/passwd — should exist on Linux, regular file > 0.
    {
        let (fi, err) = os::Stat(string("/etc/passwd"));
        if !err.IsNil() {
            fmt::Println!("[ 1] stat /etc/passwd          FAIL err");
            failed += 1;
        } else if !fi.IsDir() && fi.Size() > 0 && fi.Name() == "passwd" {
            fmt::Println!("[ 1] stat /etc/passwd          PASS size={}", fi.Size());
        } else {
            fmt::Println!(
                "[ 1] stat /etc/passwd          FAIL name={} size={} dir={}",
                fi.Name(), fi.Size(), fi.IsDir()
            );
            failed += 1;
        }
    }

    // 2. Stat /tmp — should be a directory.
    {
        let (fi, err) = os::Stat(string("/tmp"));
        if err.IsNil() && fi.IsDir() {
            fmt::Println!("[ 2] stat /tmp dir             PASS");
        } else {
            fmt::Println!("[ 2] stat /tmp dir             FAIL");
            failed += 1;
        }
    }

    // 3. Open + Read first 16 bytes of /etc/passwd, then Close.
    {
        let (mut f, err) = os::Open(string("/etc/passwd"));
        if !err.IsNil() {
            fmt::Println!("[ 3] open /etc/passwd          FAIL");
            failed += 1;
        } else {
            // err is nil ⇒ Open returned a non-nil File. Narrow.
            let f = f.MustMut();
            let mut buf = goish::goslice::slice::<u8>::__from_vec(alloc::vec![0u8; 16]);
            let (n, _re) = f.Read(&mut buf);
            if n > 0 {
                fmt::Println!("[ 3] read /etc/passwd          PASS n={}", n);
            } else {
                fmt::Println!("[ 3] read /etc/passwd          FAIL n=0");
                failed += 1;
            }
            let _ = f.Close();
        }
    }

    // 4. Stat a non-existent file → error.
    {
        let (_fi, err) = os::Stat(string("/this/does/not/exist/abc123"));
        if !err.IsNil() {
            fmt::Println!("[ 4] stat missing → error      PASS");
        } else {
            fmt::Println!("[ 4] stat missing → error      FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 4/4");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL {} of 4", failed);
        syscall::Exit(1);
    }
}
