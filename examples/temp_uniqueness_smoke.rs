// temp_uniqueness_smoke — validates os::CreateTemp + MkdirTemp generate unique
// suffixes that survive across runs (the Go nextRandom behavior).
//
// 1. CreateTemp 5 times; all 5 paths must be distinct.
// 2. Leave them behind, then CreateTemp again — must still succeed without
//    EEXIST (counter-based suffixes from a clean process would collide here).
// 3. MkdirTemp once, same retry behavior.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::fmt;
use goish::gostring::string;
use goish::os;
use goish::{nil, syscall};

#[goish::main]
fn main() {
    fmt::Println!("=== temp_uniqueness_smoke ===");

    // 1. CreateTemp 5 times in /tmp with the same pattern.
    let mut names: Vec<string> = Vec::new();
    let mut i = 0i64;
    while i < 5 {
        let (f_nilable, err) = os::CreateTemp("/tmp", "goish-uniq-*.dat");
        if err != nil {
            fmt::Println!(fmt::Sprintf!("[FAIL] CreateTemp #%d: %v", i, err));
            syscall::Exit(1);
        }
        if f_nilable == nil {
            fmt::Println!(fmt::Sprintf!("[FAIL] CreateTemp #%d: nil result", i));
            syscall::Exit(1);
        }
        let f = f_nilable.Must();
        let n = f.Name();
        let sn_str: &str = n.as_ref();
        fmt::Println!(fmt::Sprintf!("[OK] CreateTemp #%d → %s", i, sn_str));
        names.push(n);
        i += 1;
    }

    // 2. Verify uniqueness.
    let mut a = 0usize;
    while a < names.len() {
        let mut b = a + 1;
        while b < names.len() {
            if names[a] == names[b] {
                let s_str: &str = names[a].as_ref();
                fmt::Println!(fmt::Sprintf!("[FAIL] duplicate names: %s", s_str));
                syscall::Exit(1);
            }
            b += 1;
        }
        a += 1;
    }
    fmt::Println!("[OK] all 5 names are distinct");

    // 3. Leave them behind, request one more — must succeed without retry storm.
    let (f_nilable, err) = os::CreateTemp("/tmp", "goish-uniq-*.dat");
    if err != nil {
        fmt::Println!(fmt::Sprintf!(
            "[FAIL] 6th CreateTemp (with leftovers): %v",
            err
        ));
        syscall::Exit(1);
    }
    let sixth_name = f_nilable.Must().Name();
    let sn_str: &str = sixth_name.as_ref();
    fmt::Println!(fmt::Sprintf!(
        "[OK] 6th CreateTemp (with leftovers) → %s",
        sn_str
    ));
    names.push(sixth_name);

    // 4. MkdirTemp once.
    let (dname, err) = os::MkdirTemp("/tmp", "goish-uniq-dir-*");
    if err != nil {
        fmt::Println!(fmt::Sprintf!("[FAIL] MkdirTemp: %v", err));
        syscall::Exit(1);
    }
    let dn_str: &str = dname.as_ref();
    fmt::Println!(fmt::Sprintf!("[OK] MkdirTemp → %s", dn_str));

    // Cleanup so the smoke is rerunnable.
    let mut k = 0usize;
    while k < names.len() {
        let _ = os::Remove(names[k].clone());
        k += 1;
    }
    let _ = os::RemoveAll(dname);

    fmt::Println!("=== temp_uniqueness_smoke: PASS ===");
    syscall::Exit(0);
}
