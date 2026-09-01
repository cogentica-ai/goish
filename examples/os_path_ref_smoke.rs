// os_path_ref_smoke — MkdirAll and RemoveAll against a running Go.
// (os/path.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_os_path_ref.go` run in `package os_test`
// by `scripts/goref.sh`, with the scratch directory replaced by <root>.
//
// Go's `removeAll` opens with two guards. goish had NEITHER:
//
//   * The empty path is a silent nil, for compatibility with an older
//     RemoveAll (Go issue 28830).
//   * A path whose last component is "." is EINVAL, because rmdir(2)
//     will not accept one.
//
// The second is a safety property, not a formality. Without it,
// `RemoveAll(".")` stats the current directory, finds a directory,
// reads its entries and deletes every one of them — and only then
// fails on the final rmdir. It emptied this repository's working tree
// while this file was being written; the commits were pushed, so
// nothing was lost, but that is luck rather than design. The check
// below uses `<root>/dotdir/.`, never ".", so a regression can only
// take the scratch directory with it.
//
// The error TEXT was the other half. Go returns *PathError everywhere
// here — `mkdir <path>: not a directory`, `remove <path>: directory not
// empty` — while goish returned bare strings: "mkdir failed", "remove
// failed", "mkdir: path exists and is not a directory". They named
// neither the path nor the reason, and being plain errors rather than
// *PathError they could not be inspected with `errors::As` either.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::io::fs::FileMode;
use goish::os;
use goish::types::int;
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

// go: none — goish idiom: the smokes print one PASS/FAIL line per
//     numbered check; this is that line, hoisted.
fn report(failed: &mut int, ok: bool, n: &str, what: &str) {
    if ok {
        fmt::Println!("[", n, "]", what, "PASS");
    } else {
        fmt::Println!("[", n, "]", what, "FAIL");
        *failed += 1;
    }
}

// go: none — goish idiom: replace the scratch root with "<root>" so the
//     vectors do not depend on where the smoke happens to run.
fn strip(msg: &string, root: &string) -> string {
    let mb = msg.as_bytes();
    let rb = root.as_bytes();
    let mut out: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    let mut i = 0usize;
    while i < mb.len() {
        if i + rb.len() <= mb.len() && &mb[i..i + rb.len()] == rb {
            out.extend_from_slice(b"<root>");
            i += rb.len();
            continue;
        }
        out.push(mb[i]);
        i += 1;
    }
    return string::__from_vec(out);
}

// (tag, want) — Go 1.25.5 verbatim. "" means a nil error, a
// leading '=' means a boolean, anything else is the exact error
// text with the scratch root replaced by <root>.
const CASES: [(&str, &str); 20] = [
    ("mk_fresh", ""),
    ("mk_again", ""),
    ("mk_nested", ""),
    ("mk_nested_again", ""),
    ("mk_trailing", ""),
    ("mk_dot", ""),
    ("mk_dotdot", ""),
    ("mk_empty", "mkdir : no such file or directory"),
    ("mk_over_file", "mkdir <root>/afile: not a directory"),
    ("mk_under_file", "mkdir <root>/afile: not a directory"),
    ("rm_missing", ""),
    ("rm_empty", ""),
    ("rm_file", ""),
    ("rm_tree", ""),
    ("tree_gone", "=true"),
    ("rm_dotpath", "RemoveAll <root>/dotdir/.: invalid argument"),
    ("dotdir_survived", "=true"),
    ("rm_again", ""),
    ("remove_nonempty", "remove <root>/k: directory not empty"),
    (
        "remove_missing",
        "remove <root>/zzz: no such file or directory",
    ),
];

// go: none — goish idiom: record one step as (tag, rendering), with a
//     nil error rendered as the empty string, exactly as the Go
//     reference prints it.
fn push(got: &mut alloc::vec::Vec<(string, string)>, root: &string, tag: &str, err: goish::error) {
    let v = if err.IsNil() {
        string::new()
    } else {
        strip(&err.Error(), root)
    };
    got.push((s(tag), v));
}

#[goish::main]
fn main() {
    let mut failed = 0;

    let (root, derr) = os::MkdirTemp("", "goish_path*");
    if !derr.IsNil() {
        fmt::Println!("cannot make a scratch dir:", derr.Error());
        syscall::Exit(1);
    }
    let j = |p: &str| root.clone() + s("/") + s(p);

    // Run the same sequence the Go reference ran, collecting one
    // (tag, rendering) pair per step.
    let mut got: alloc::vec::Vec<(string, string)> = alloc::vec::Vec::new();

    push(
        &mut got,
        &root,
        "mk_fresh",
        os::MkdirAll(j("a"), FileMode(0o755)),
    );
    push(
        &mut got,
        &root,
        "mk_again",
        os::MkdirAll(j("a"), FileMode(0o755)),
    );
    push(
        &mut got,
        &root,
        "mk_nested",
        os::MkdirAll(j("b/c/d"), FileMode(0o755)),
    );
    push(
        &mut got,
        &root,
        "mk_nested_again",
        os::MkdirAll(j("b/c/d"), FileMode(0o755)),
    );
    push(
        &mut got,
        &root,
        "mk_trailing",
        os::MkdirAll(j("e/f/"), FileMode(0o755)),
    );
    push(
        &mut got,
        &root,
        "mk_dot",
        os::MkdirAll(j("g/."), FileMode(0o755)),
    );
    push(
        &mut got,
        &root,
        "mk_dotdot",
        os::MkdirAll(j("h/i/.."), FileMode(0o755)),
    );
    push(
        &mut got,
        &root,
        "mk_empty",
        os::MkdirAll("", FileMode(0o755)),
    );

    let _ = os::WriteFile(j("afile"), goish::bytes("x"), FileMode(0o644));
    push(
        &mut got,
        &root,
        "mk_over_file",
        os::MkdirAll(j("afile"), FileMode(0o755)),
    );
    push(
        &mut got,
        &root,
        "mk_under_file",
        os::MkdirAll(j("afile/sub"), FileMode(0o755)),
    );

    push(&mut got, &root, "rm_missing", os::RemoveAll(j("nope")));
    push(&mut got, &root, "rm_empty", os::RemoveAll(""));
    push(&mut got, &root, "rm_file", os::RemoveAll(j("afile")));
    push(&mut got, &root, "rm_tree", os::RemoveAll(j("b")));
    let (_, se) = os::Stat(j("b"));
    got.push((
        s("tree_gone"),
        s(if os::IsNotExist(se) {
            "=true"
        } else {
            "=false"
        }),
    ));

    // The dot guard, on a path INSIDE the scratch dir — never on ".".
    let _ = os::MkdirAll(j("dotdir"), FileMode(0o755));
    push(&mut got, &root, "rm_dotpath", os::RemoveAll(j("dotdir/.")));
    let (_, de) = os::Stat(j("dotdir"));
    got.push((
        s("dotdir_survived"),
        s(if de.IsNil() { "=true" } else { "=false" }),
    ));

    push(&mut got, &root, "rm_again", os::RemoveAll(j("b")));
    let _ = os::MkdirAll(j("k/l"), FileMode(0o755));
    push(&mut got, &root, "remove_nonempty", os::Remove(j("k")));
    push(&mut got, &root, "remove_missing", os::Remove(j("zzz")));

    // 1. Every step, compared against Go's rendering.
    {
        let mut ok = true;
        let mut i = 0usize;
        while i < CASES.len() {
            let (tag, want) = CASES[i];
            let mut found = false;
            let mut k = 0usize;
            while k < got.len() {
                if got[k].0 == s(tag) {
                    found = true;
                    if got[k].1 != s(want) {
                        fmt::Println!(
                            "   ",
                            s(tag),
                            "want",
                            fmt::Sprintf!("%q", s(want)),
                            "got",
                            fmt::Sprintf!("%q", got[k].1.clone())
                        );
                        ok = false;
                    }
                }
                k += 1;
            }
            if !found {
                fmt::Println!("   ", s(tag), "missing");
                ok = false;
            }
            i += 1;
        }
        report(&mut failed, ok, " 1", "MkdirAll/RemoveAll, step for step");
    }

    // 2. The dot guard on its own, because it is the one with teeth: a
    //    path ending in "." must be REFUSED, and the directory must
    //    still be there afterwards.
    {
        let mut ok = true;
        let _ = os::MkdirAll(j("guard/inner"), FileMode(0o755));
        let e = os::RemoveAll(j("guard/."));
        if e.IsNil() {
            ok = false;
        }
        let (_, s1) = os::Stat(j("guard/inner"));
        if !s1.IsNil() {
            ok = false;
        }
        // "." itself is refused too — checked by the error only; the
        // smoke never asks RemoveAll to act on its own directory.
        report(
            &mut failed,
            ok,
            " 2",
            "a trailing dot is refused, not walked",
        );
    }

    let _ = os::RemoveAll(root);

    if failed == 0 {
        fmt::Println!("ok 2/2");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 2");
        syscall::Exit(1);
    }
}
