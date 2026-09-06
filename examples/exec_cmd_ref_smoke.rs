// exec_cmd_ref_smoke — Cmd.Env with duplicate keys, and Cmd.Dir.
//
// Reference: Go 1.25.5 os/exec, tools/gen_execenv_ref.go.
//
// Go documents it: "If Env contains duplicate environment keys, only
// the last value in the slice for each duplicate key is used." That
// rule is what makes the common shape work —
//
//     cmd.Env = append(os.Environ(), "FOO=override")
//
// — and if the FIRST value won instead, every override written that
// way would be silently ignored while the code looked right.
//
// THE OBVIOUS TEST DOES NOT WORK, which is the reason this file
// explains itself. Asking a shell for "$FOO" answers "last" whether or
// not the duplicates were ever collapsed, because a shell imports
// environ in order and later entries overwrite earlier ones. The first
// version of this measurement did exactly that and proved nothing.
//
// So the child runs `env` and the rows count the RAW entries: a
// leading "1" is the number of FOO lines actually delivered. One entry
// carrying the last value is the answer; two entries would mean the
// duplicates were passed through and the child's own import order was
// deciding.
//
// goish matches Go on all five rows, including the empty last value,
// which must win over a non-empty earlier one.
//
// The two dir rows are here because the file's header claimed
// `Dir string // not yet honored (v2: cwd inherited)` while the child
// has honoured it for some time — there is a Chdir in the fork path.
// A comment that understates what works costs a reader a workaround
// they did not need, so the behaviour is pinned and the claim
// corrected: empty inherits the parent's cwd, set changes the child's.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::os::exec;
use goish::types::int;
use goish::{fmt, slice};

const GO: [&str; 7] = [
    "single          FOO=\"1\\nFOO=first,\"",
    "dup-two         FOO=\"1\\nFOO=second,\"",
    "dup-three       FOO=\"1\\nFOO=c,\"",
    "override-shape  FOO=\"1\\nFOO=override,\"",
    "empty-last      FOO=\"1\\nFOO=,\"",
    "dir-inherit     matches=true",
    "dir-set         matches=true",
];

fn lbl(d: &&str) -> &'static str {
    if **d == *"" {
        return "inherit";
    }
    return "set";
}

static mut BAD: usize = 0;

fn chk(ln: &mut usize, got: &string) {
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line: %q\n", got);
        unsafe { BAD += 1 };
        *ln += 1;
        return;
    }
    if got == GO[*ln] {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        unsafe { BAD += 1 };
        fmt::Printf!("[!!] line %d\n  got  %q\n  want %q\n", *ln as int + 1, got, GO[*ln]);
    }
    *ln += 1;
}

#[goish::main]
fn main() {
    let dir = string::from("/tmp/claude-1000");
    let _ = goish::os::MkdirAll(dir.clone(), goish::os::FileMode(0o755));
    let outp = dir + string::from("/goish-execenv.out");

    let cases: [(&str, &[&str]); 5] = [
        ("single", &["FOO=first"]),
        ("dup-two", &["FOO=first", "FOO=second"]),
        ("dup-three", &["FOO=a", "FOO=b", "FOO=c"]),
        ("override-shape", &["PATH=/bin:/usr/bin", "FOO=orig", "BAR=x", "FOO=override"]),
        ("empty-last", &["FOO=set", "FOO="]),
    ];
    let mut ln: usize = 0;
    for (name, env) in cases.iter() {
        let _ = goish::os::Remove(outp.clone());
        // `env` prints the RAW environ, so duplicates are visible.
        let script = string::from("/usr/bin/env | grep -c '^FOO=' > ")
            + outp.clone()
            + string::from("; /usr/bin/env | grep '^FOO=' | tr '\\n' ',' >> ")
            + outp.clone();
        let mut cmd = exec::Command(
            "/bin/sh",
            slice::__from_vec(alloc::vec![string::from("-c"), script]),
        );
        let mut ev = goish::goslice::slice::<string>::new();
        for e in env.iter() {
            ev = goish::append!(ev, string::from(*e));
        }
        cmd.Env = ev;
        let err = cmd.Run();
        if !err.IsNil() {
            chk(&mut ln, &fmt::Sprintf!("%-15s err=%v", string::from(*name), err));
            continue;
        }
        let (b, rerr) = goish::os::ReadFile(outp.clone());
        if !rerr.IsNil() {
            chk(&mut ln, &fmt::Sprintf!("%-15s readfile err=%v", string::from(*name), rerr));
            continue;
        }
        chk(&mut ln, &fmt::Sprintf!("%-15s FOO=%q",
            string::from(*name), string::from_bytes(b.as_ref())));
    }
    // ── Cmd.Dir ──
    let ddir = string::from("/tmp/claude-1000/goish-execdir");
    let _ = goish::os::MkdirAll(ddir.clone(), goish::os::FileMode(0o755));
    let (parent, _) = goish::os::Getwd();
    for d in ["", "/tmp/claude-1000/goish-execdir"].iter() {
        let _ = goish::os::Remove(outp.clone());
        let mut cmd = exec::Command(
            "/bin/sh",
            slice::__from_vec(alloc::vec![
                string::from("-c"),
                string::from("pwd > ") + outp.clone(),
            ]),
        );
        if *d != "" {
            cmd.Dir = string::from(*d);
        }
        let err = cmd.Run();
        if !err.IsNil() {
            chk(&mut ln, &fmt::Sprintf!("dir-%-11s err=%v", string::from(lbl(d)), err));
            continue;
        }
        let (b, _) = goish::os::ReadFile(outp.clone());
        let got = goish::strings::TrimSpace(string::from_bytes(b.as_ref()));
        let want = if *d == "" { parent.clone() } else { string::from(*d) };
        chk(&mut ln, &fmt::Sprintf!("dir-%-11s matches=%v",
            string::from(lbl(d)), got == want));
    }

    let _ = goish::os::Remove(outp);
    if ln != GO.len() {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln as int, GO.len() as int);
        unsafe { BAD += 1 };
    }
    let bad = unsafe { BAD };
    if bad != 0 {
        // e2e_runner.sh: "rc=0 wins regardless of stdout content",
        // so printing the mismatch is not enough to fail CI.
        fmt::Printf!("[!!] %d row(s) diverge from Go\n", bad as i64);
        goish::os::Exit(1);
    }
    goish::os::Exit(0);
}
