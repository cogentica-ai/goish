// flag_ref_smoke — the flag package against a running Go.
// (flag/flag.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_flag_ref.go` run in `package flag_test`
// by `scripts/goref.sh`.
//
// goish's FlagSet was hand-written rather than ported — the file said
// so, and carried a blanket GOISH018 waiver listing forty-odd Go
// declarations it did not have. Diffing its parser against Go's over 39
// argv vectors found six divergences, and the first two are the kind a
// user hits on their first afternoon:
//
//   * A bool flag CONSUMED the next argument. Go's never does: `-b true`
//     sets b and leaves "true" as a positional, and `-b arg` sets b and
//     leaves "arg". goish parsed the next token as the bool's value, so
//     `-b arg` failed with a parse error on "arg".
//   * A non-bool flag REFUSED a next argument starting with '-'. Go
//     takes it whatever it looks like, which is what makes `-n -7`
//     parse as minus seven; goish answered "flag needs an argument".
//   * `-h` and `-help` are Go's built-in help request, returning
//     ErrHelp ("flag: help requested") after printing the defaults.
//     goish said "flag provided but not defined: -h".
//   * `---s` is "bad flag syntax: ---s" in Go. goish stripped two
//     dashes and reported an undefined flag named "-s".
//   * A failed Set left the DEFAULT in the flag. Go assigns the parsed
//     value unconditionally — `*i = intValue(v)` runs whether or not
//     ParseInt failed — so a bad value leaves the zero and an
//     out-of-range one leaves the clamped bound. A program that ignores
//     the error then runs with a value the user never asked for.
//   * `Parse` set `parsed` only on success and never populated `Args()`
//     on the error path. Go sets `parsed` first and shifts `args` as it
//     goes, so a caller that gets an error can still see the remainder.
//
// Also ported here: the error texts (`invalid value %q for flag -%s`,
// `invalid boolean value %q for -%s`, `flag needs an argument`, `no such
// flag -x`), `numError`'s unwrapping to "parse error" / "value out of
// range", `SetOutput`, `NFlag`, `Visit`, `UnquoteUsage`, `isZeroValue`
// and Go's `PrintDefaults` layout — which is checked byte for byte.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;

use goish::bytes;
use goish::flag;
use goish::goslice::slice;
use goish::gostring::string;
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

// (argv, want_err, want_s, want_n, want_b, want_f, want_d, want_args)
// — Go 1.25.5 verbatim. want_err "" means a nil error.
const CASES: [(&[&str], &str, &str, int, bool, f64, &str, &[&str]); 39] = [
    (&[], "", "def", 42, false, 2.5, "1s", &[]),
    (&["-s", "x"], "", "x", 42, false, 2.5, "1s", &[]),
    (&["--s", "x"], "", "x", 42, false, 2.5, "1s", &[]),
    (&["-s=x"], "", "x", 42, false, 2.5, "1s", &[]),
    (&["--s=x"], "", "x", 42, false, 2.5, "1s", &[]),
    (&["-n", "7"], "", "def", 7, false, 2.5, "1s", &[]),
    (&["-n=7"], "", "def", 7, false, 2.5, "1s", &[]),
    (&["-n", "-7"], "", "def", -7, false, 2.5, "1s", &[]),
    (&["-b"], "", "def", 42, true, 2.5, "1s", &[]),
    (&["--b"], "", "def", 42, true, 2.5, "1s", &[]),
    (&["-b=true"], "", "def", 42, true, 2.5, "1s", &[]),
    (&["-b=false"], "", "def", 42, false, 2.5, "1s", &[]),
    (&["-b", "true"], "", "def", 42, true, 2.5, "1s", &["true"]),
    (&["-b", "arg"], "", "def", 42, true, 2.5, "1s", &["arg"]),
    (&["-b", "-n", "3"], "", "def", 3, true, 2.5, "1s", &[]),
    (&["-f", "1.5"], "", "def", 42, false, 1.5, "1s", &[]),
    (&["-d", "1s"], "", "def", 42, false, 2.5, "1s", &[]),
    (&["-d", "1h30m"], "", "def", 42, false, 2.5, "1h30m0s", &[]),
    (
        &["-d", "nope"],
        "invalid value \"nope\" for flag -d: parse error",
        "def",
        42,
        false,
        2.5,
        "0s",
        &[],
    ),
    (
        &["-n", "notanumber"],
        "invalid value \"notanumber\" for flag -n: parse error",
        "def",
        0,
        false,
        2.5,
        "1s",
        &[],
    ),
    (
        &["-n", "99999999999999999999"],
        "invalid value \"99999999999999999999\" for flag -n: value out of range",
        "def",
        9223372036854775807,
        false,
        2.5,
        "1s",
        &[],
    ),
    (
        &["-zzz"],
        "flag provided but not defined: -zzz",
        "def",
        42,
        false,
        2.5,
        "1s",
        &[],
    ),
    (
        &["-zzz", "1"],
        "flag provided but not defined: -zzz",
        "def",
        42,
        false,
        2.5,
        "1s",
        &["1"],
    ),
    (
        &["pos1", "pos2"],
        "",
        "def",
        42,
        false,
        2.5,
        "1s",
        &["pos1", "pos2"],
    ),
    (
        &["pos1", "-s", "x"],
        "",
        "def",
        42,
        false,
        2.5,
        "1s",
        &["pos1", "-s", "x"],
    ),
    (
        &["-s", "x", "pos1", "-n", "3"],
        "",
        "x",
        42,
        false,
        2.5,
        "1s",
        &["pos1", "-n", "3"],
    ),
    (
        &["--", "-s", "x"],
        "",
        "def",
        42,
        false,
        2.5,
        "1s",
        &["-s", "x"],
    ),
    (
        &["-s", "x", "--", "-n", "3"],
        "",
        "x",
        42,
        false,
        2.5,
        "1s",
        &["-n", "3"],
    ),
    (&["-"], "", "def", 42, false, 2.5, "1s", &["-"]),
    (
        &["-s"],
        "flag needs an argument: -s",
        "def",
        42,
        false,
        2.5,
        "1s",
        &[],
    ),
    (
        &["-n"],
        "flag needs an argument: -n",
        "def",
        42,
        false,
        2.5,
        "1s",
        &[],
    ),
    (
        &["---s", "x"],
        "bad flag syntax: ---s",
        "def",
        42,
        false,
        2.5,
        "1s",
        &["---s", "x"],
    ),
    (
        &["-h"],
        "flag: help requested",
        "def",
        42,
        false,
        2.5,
        "1s",
        &[],
    ),
    (
        &["-help"],
        "flag: help requested",
        "def",
        42,
        false,
        2.5,
        "1s",
        &[],
    ),
    (&["-s", ""], "", "", 42, false, 2.5, "1s", &[]),
    (&["-s=", "y"], "", "", 42, false, 2.5, "1s", &["y"]),
    (&["-b=1"], "", "def", 42, true, 2.5, "1s", &[]),
    (&["-b=0"], "", "def", 42, false, 2.5, "1s", &[]),
    (
        &["-b=yes"],
        "invalid boolean value \"yes\" for -b: parse error",
        "def",
        42,
        false,
        2.5,
        "1s",
        &[],
    ),
];

// PrintDefaults output, byte for byte.
const WANT_DEFAULTS: &str = "  -b\ta bool\n  -empty string\n    \tno default shown\n  -n int\n    \tan int (default 42)\n  -s string\n    \ta string (default \"def\")\n";

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Every argv: the error text, all five flag values, and the
    //    residual arguments.
    {
        let mut ok = true;
        let mut bad = 0;
        let mut i = 0usize;
        while i < CASES.len() {
            let (argv, want_err, want_s, want_n, want_b, want_f, want_d, want_args) = CASES[i];
            let mut fs = flag::NewFlagSet();
            // The `-h` rows print the defaults, as Go's do; the Go
            // reference sent them to a buffer and so does this.
            fs.SetOutput(Arc::new(goish::sync::Mutex::new(bytes::Buffer::new())));
            let sv = fs.String("s", "def", "a string");
            let nv = fs.Int("n", 42, "an int");
            let bv = fs.Bool("b", false, "a bool");
            let fv = fs.Float64("f", 2.5, "a float");
            let dv = fs.Duration("d", goish::time::Second, "a duration");
            let mut v: alloc::vec::Vec<string> = alloc::vec::Vec::new();
            let mut k = 0usize;
            while k < argv.len() {
                v.push(s(argv[k]));
                k += 1;
            }
            let err = fs.Parse(&slice::__from_vec(v));

            let mut row = true;
            let got_err = if err.IsNil() {
                string::new()
            } else {
                err.Error()
            };
            if got_err != s(want_err) {
                row = false;
            }
            if sv.Get() != s(want_s) || nv.Get() != want_n || bv.Get() != want_b {
                row = false;
            }
            if fv.Get() != want_f || dv.Get().String() != s(want_d) {
                row = false;
            }
            let args = fs.Args();
            if args.Len() as usize != want_args.len() {
                row = false;
            } else {
                let mut j = 0usize;
                while j < want_args.len() {
                    if args[j as int] != s(want_args[j]) {
                        row = false;
                    }
                    j += 1;
                }
            }
            // Go sets `parsed` before it parses anything, so it is true
            // even when Parse returns an error.
            if !fs.Parsed() {
                row = false;
            }
            if !row {
                if bad < 6 {
                    fmt::Println!(
                        "   argv[",
                        i as int,
                        "] want_err",
                        fmt::Sprintf!("%q", s(want_err)),
                        "got",
                        fmt::Sprintf!("%q", got_err),
                        "s",
                        sv.Get(),
                        "n",
                        nv.Get(),
                        "b",
                        bv.Get(),
                        "args",
                        args.Len()
                    );
                }
                bad += 1;
                ok = false;
            }
            i += 1;
        }
        if bad > 0 {
            fmt::Println!("   ", bad, "rows differ");
        }
        report(&mut failed, ok, " 1", "39 argv vectors, value for value");
    }

    // 2. PrintDefaults, byte for byte. Go puts the TYPE after the name,
    //    the usage on its own indented line unless the whole prefix
    //    fits in four columns, and the default in parentheses unless it
    //    is the type's zero.
    {
        let mut fs = flag::NewFlagSet();
        let buf = Arc::new(goish::sync::Mutex::new(bytes::Buffer::new()));
        fs.SetOutput(buf.clone());
        fs.String("s", "def", "a string");
        fs.Int("n", 42, "an int");
        fs.Bool("b", false, "a bool");
        fs.String("empty", "", "no default shown");
        fs.PrintDefaults();
        let got = buf.Lock().String();
        let ok = got == s(WANT_DEFAULTS);
        if !ok {
            fmt::Println!("   want", fmt::Sprintf!("%q", s(WANT_DEFAULTS)));
            fmt::Println!("   got ", fmt::Sprintf!("%q", got));
        }
        report(&mut failed, ok, " 2", "PrintDefaults layout");
    }

    // 3. Lookup, Set, NFlag, Visit and VisitAll. Go: NFlag counts the
    //    flags that were SET, Visit walks those in name order, and a
    //    successful `Set` marks the flag as set — so "c" shows up in
    //    Visit even though it never appeared on the command line.
    {
        let mut ok = true;
        let mut fs = flag::NewFlagSet();
        fs.String("a", "1", "u");
        fs.Int("c", 2, "u");
        let mut v: alloc::vec::Vec<string> = alloc::vec::Vec::new();
        v.push(s("-a"));
        v.push(s("z"));
        if !fs.Parse(&slice::__from_vec(v)).IsNil() {
            ok = false;
        }
        if fs.NFlag() != 1 {
            ok = false;
        }
        match fs.Lookup("a") {
            Some(fl) => {
                if fl.Value.String() != s("z") {
                    ok = false;
                }
            }
            None => ok = false,
        }
        if fs.Lookup("nope").is_some() {
            ok = false;
        }
        if !fs.Set(s("c"), s("9")).IsNil() {
            ok = false;
        }
        match fs.Lookup("c") {
            Some(fl) => {
                if fl.Value.String() != s("9") {
                    ok = false;
                }
            }
            None => ok = false,
        }
        // Go: "no such flag -nope".
        let e = fs.Set(s("nope"), s("1"));
        if e.IsNil() || e.Error() != s("no such flag -nope") {
            ok = false;
        }
        let mut vis: alloc::vec::Vec<string> = alloc::vec::Vec::new();
        fs.Visit(|f| vis.push(f.Name.clone()));
        if vis.len() != 2 || vis[0] != s("a") || vis[1] != s("c") {
            ok = false;
        }
        let mut all: alloc::vec::Vec<string> = alloc::vec::Vec::new();
        fs.VisitAll(|f| all.push(f.Name.clone()));
        if all.len() != 2 || all[0] != s("a") || all[1] != s("c") {
            ok = false;
        }
        report(&mut failed, ok, " 3", "Lookup, Set, NFlag, Visit");
    }

    if failed == 0 {
        fmt::Println!("ok 3/3");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 3");
        syscall::Exit(1);
    }
}
