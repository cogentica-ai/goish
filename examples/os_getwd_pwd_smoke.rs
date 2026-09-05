// os_getwd_pwd_smoke — Getwd must honour $PWD when $PWD really names
// the current directory.
//
// Reference: Go 1.25.5 os, measured by tools/gen_getwd_ref.go.
//
// Go documents it: "On Unix platforms, if the environment variable PWD
// provides an absolute name, and it is a name of the current
// directory, it is returned." Go's own source calls it "a clumsy but
// widespread kludge". goish went straight to getcwd(2) and never
// looked at $PWD.
//
// The only way to see the difference is from inside a directory
// reached through a symlink, where the logical path ($PWD, what the
// user typed) and the physical one (getcwd, what the kernel resolves
// to) disagree. That is not an exotic arrangement — deploy layouts
// with a `current` symlink, symlinked home directories and container
// mounts all produce it, and the shell exports $PWD as the logical
// path.
//
// Four of the five cases must NOT take the $PWD branch, and they are
// here because a fix that just returned $PWD whenever it was set would
// pass the first case and be badly wrong. The gate is dev+ino equality
// through SameFile, not a string comparison: pwd-elsewhere is absolute
// and exists and still loses.
//
// Absolute paths are machine-specific, so each line reports which of
// the two directories the answer equals rather than the path itself.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::gostring::string;
use goish::os;
use goish::path::filepath;
use goish::types::int;

const GO: [&str; 5] = [
    "pwd-symlink    eq-link=true eq-real=false err=<nil>",
    "pwd-elsewhere  eq-link=false eq-real=true err=<nil>",
    "pwd-relative   eq-link=false eq-real=true err=<nil>",
    "pwd-physical   eq-link=false eq-real=true err=<nil>",
    "pwd-unset      eq-link=false eq-real=true err=<nil>",
];

fn chk(ln: &mut usize, got: &string) {
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line: %q\n", got);
        *ln += 1;
        return;
    }
    if got == GO[*ln] {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        fmt::Printf!("[!!] line %d\n  got  %q\n  want %q\n", *ln as int + 1, got, GO[*ln]);
    }
    *ln += 1;
}

#[goish::main]
fn main() {
    let (base, err) = os::MkdirTemp(string::from(""), string::from("goishwd"));
    if !err.IsNil() {
        fmt::Printf!("[!!] mkdirtemp: %v\n", err);
        return;
    }
    // The temp root itself may be a symlink, so resolve it before
    // deriving "real" — otherwise the physical path never matches and
    // every line fails for a reason that has nothing to do with Getwd.
    let (base, _) = filepath::EvalSymlinks(base);
    let real = filepath::Join(goish::goslice::slice::__from_vec(
        alloc::vec![base.clone(), string::from("real")]));
    let link = filepath::Join(goish::goslice::slice::__from_vec(
        alloc::vec![base.clone(), string::from("link")]));

    let err = os::Mkdir(real.clone(), os::FileMode(0o755));
    if !err.IsNil() {
        fmt::Printf!("[!!] mkdir: %v\n", err);
        return;
    }
    let err = os::Symlink(real.clone(), link.clone());
    if !err.IsNil() {
        fmt::Printf!("[!!] symlink: %v\n", err);
        return;
    }
    let err = os::Chdir(link.clone());
    if !err.IsNil() {
        fmt::Printf!("[!!] chdir: %v\n", err);
        return;
    }

    let mut ln: usize = 0;
    let mut report = |ln: &mut usize, name: &str| {
        let (d, err) = os::Getwd();
        chk(ln, &fmt::Sprintf!("%-14s eq-link=%v eq-real=%v err=%v",
            string::from(name), d == link, d == real, err));
    };

    let _ = os::Setenv(string::from("PWD"), link.clone());
    report(&mut ln, "pwd-symlink");

    let _ = os::Setenv(string::from("PWD"), string::from("/"));
    report(&mut ln, "pwd-elsewhere");

    let _ = os::Setenv(string::from("PWD"), string::from("relative/not/absolute"));
    report(&mut ln, "pwd-relative");

    let _ = os::Setenv(string::from("PWD"), real.clone());
    report(&mut ln, "pwd-physical");

    let _ = os::Unsetenv(string::from("PWD"));
    report(&mut ln, "pwd-unset");

    // Leave the cwd somewhere that still exists before removing base,
    // or a later relative path in the same process resolves nowhere.
    let _ = os::Chdir(string::from("/"));
    let _ = os::RemoveAll(base);

    if ln != GO.len() {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln as int, GO.len() as int);
    }
}
