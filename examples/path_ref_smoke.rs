// path_ref_smoke — the slash-separated `path` package against a running Go.
// (path/path.go, path/match.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_path_ref.go` run in
// `package path_test` by `scripts/goref.sh`. goish matched Go on all
// 163 lines — no defects found, which for this package is the result
// worth having, because everything above it inherits the answer.
//
// `path` is not a convenience wrapper on path/filepath. It is what
// http.ServeMux's cleanPath, http.FileServer and io/fs are built on, so
// a Clean that disagrees with Go's is a ROUTING decision that disagrees
// with Go's. That is not hypothetical here: the commit before this one
// fixed a ServeMux that cleaned the wrong string. The cleaning itself
// was never wrong, and this is the measurement that says so.
//
// What is pinned:
//
//   * Clean is PURELY LEXICAL — it never touches a filesystem, so it
//     resolves "a/../b" to "b" even where "a" is a symlink pointing
//     elsewhere. Documented property, not a bug; a port that
//     "improves" on it diverges from every caller's expectation.
//   * ".." above the root is DROPPED when rooted ("/../a" -> "/a") and
//     KEPT when relative ("../a" stays). One half stops
//     "/../../etc/passwd" escaping; the other keeps relative traversal
//     expressible. Getting either half wrong is a bug in a different
//     direction.
//   * Clean("") is ".", never "" — an empty answer would let a
//     concatenating caller build a path with a leading slash it never
//     intended.
//   * Join cleans its result, so a ".." in a later element eats an
//     earlier one: Join("/var/www", "../../etc/passwd") is
//     "/etc/passwd". That is the exact shape of a traversal through a
//     joined user-supplied segment, and it is Go's answer — the
//     defence belongs in the caller, not in Join.
//   * "..%2f" is NOT traversal here: Join leaves it as one literal
//     element. path never percent-decodes, which is the same division
//     of labour the ServeMux fix rests on.
//   * Match is a glob, not a regexp: "*" does not cross a slash, "**"
//     is no different from "*", and a malformed pattern is an ERROR
//     rather than a quiet non-match — including "[-]", which Go
//     refuses outright.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::path;
use goish::syscall;
use goish::types::int;
const GO: [&str; 163] = [
    "clean \"\"               -> \".\"",
    "clean \".\"              -> \".\"",
    "clean \"..\"             -> \"..\"",
    "clean \"/\"              -> \"/\"",
    "clean \"//\"             -> \"/\"",
    "clean \"///\"            -> \"/\"",
    "clean \"a\"              -> \"a\"",
    "clean \"/a\"             -> \"/a\"",
    "clean \"a/\"             -> \"a\"",
    "clean \"/a/\"            -> \"/a\"",
    "clean \"a/b\"            -> \"a/b\"",
    "clean \"a//b\"           -> \"a/b\"",
    "clean \"a/./b\"          -> \"a/b\"",
    "clean \"a/../b\"         -> \"b\"",
    "clean \"../a\"           -> \"../a\"",
    "clean \"/../a\"          -> \"/a\"",
    "clean \"/../../a\"       -> \"/a\"",
    "clean \"a/b/..\"         -> \"a\"",
    "clean \"a/b/../..\"      -> \".\"",
    "clean \"a/b/../../..\"   -> \"..\"",
    "clean \"./a\"            -> \"a\"",
    "clean \"././a\"          -> \"a\"",
    "clean \"/a/b/./../c/\"   -> \"/a/c\"",
    "clean \"a/b/c/../../d\"  -> \"a/d\"",
    "clean \"...\"            -> \"...\"",
    "clean \"a...\"           -> \"a...\"",
    "clean \"..a\"            -> \"..a\"",
    "clean \"a..b\"           -> \"a..b\"",
    "clean \"/.\"             -> \"/\"",
    "clean \"/..\"            -> \"/\"",
    "clean \"/./\"            -> \"/\"",
    "clean \"/../\"           -> \"/\"",
    "clean \"abc/../../def\"  -> \"../def\"",
    "clean \"/a/../..\"       -> \"/\"",
    "clean \"x/y/../../../z\" -> \"../z\"",
    "clean \"//a//b//\"       -> \"/a/b\"",
    "clean \"a/b/c/\"         -> \"a/b/c\"",
    "clean \".../a\"          -> \".../a\"",
    "clean \"/a/.\"           -> \"/a\"",
    "split \"\"               -> dir=\"\"           file=\"\"",
    "split \".\"              -> dir=\"\"           file=\".\"",
    "split \"..\"             -> dir=\"\"           file=\"..\"",
    "split \"/\"              -> dir=\"/\"          file=\"\"",
    "split \"//\"             -> dir=\"//\"         file=\"\"",
    "split \"///\"            -> dir=\"///\"        file=\"\"",
    "split \"a\"              -> dir=\"\"           file=\"a\"",
    "split \"/a\"             -> dir=\"/\"          file=\"a\"",
    "split \"a/\"             -> dir=\"a/\"         file=\"\"",
    "split \"/a/\"            -> dir=\"/a/\"        file=\"\"",
    "split \"a/b\"            -> dir=\"a/\"         file=\"b\"",
    "split \"a//b\"           -> dir=\"a//\"        file=\"b\"",
    "split \"a/./b\"          -> dir=\"a/./\"       file=\"b\"",
    "split \"a/../b\"         -> dir=\"a/../\"      file=\"b\"",
    "split \"../a\"           -> dir=\"../\"        file=\"a\"",
    "split \"/../a\"          -> dir=\"/../\"       file=\"a\"",
    "split \"/../../a\"       -> dir=\"/../../\"    file=\"a\"",
    "split \"a/b/..\"         -> dir=\"a/b/\"       file=\"..\"",
    "split \"a/b/../..\"      -> dir=\"a/b/../\"    file=\"..\"",
    "split \"a/b/../../..\"   -> dir=\"a/b/../../\" file=\"..\"",
    "split \"./a\"            -> dir=\"./\"         file=\"a\"",
    "split \"././a\"          -> dir=\"././\"       file=\"a\"",
    "split \"/a/b/./../c/\"   -> dir=\"/a/b/./../c/\" file=\"\"",
    "split \"a/b/c/../../d\"  -> dir=\"a/b/c/../../\" file=\"d\"",
    "split \"...\"            -> dir=\"\"           file=\"...\"",
    "split \"a...\"           -> dir=\"\"           file=\"a...\"",
    "split \"..a\"            -> dir=\"\"           file=\"..a\"",
    "split \"a..b\"           -> dir=\"\"           file=\"a..b\"",
    "split \"/.\"             -> dir=\"/\"          file=\".\"",
    "split \"/..\"            -> dir=\"/\"          file=\"..\"",
    "split \"/./\"            -> dir=\"/./\"        file=\"\"",
    "split \"/../\"           -> dir=\"/../\"       file=\"\"",
    "split \"abc/../../def\"  -> dir=\"abc/../../\" file=\"def\"",
    "split \"/a/../..\"       -> dir=\"/a/../\"     file=\"..\"",
    "split \"x/y/../../../z\" -> dir=\"x/y/../../../\" file=\"z\"",
    "split \"//a//b//\"       -> dir=\"//a//b//\"   file=\"\"",
    "split \"a/b/c/\"         -> dir=\"a/b/c/\"     file=\"\"",
    "split \".../a\"          -> dir=\".../\"       file=\"a\"",
    "split \"/a/.\"           -> dir=\"/a/\"        file=\".\"",
    "parts \"\"               -> dir=\".\"          base=\".\"      ext=\"\" abs=false",
    "parts \".\"              -> dir=\".\"          base=\".\"      ext=\".\" abs=false",
    "parts \"..\"             -> dir=\".\"          base=\"..\"     ext=\".\" abs=false",
    "parts \"/\"              -> dir=\"/\"          base=\"/\"      ext=\"\" abs=true",
    "parts \"//\"             -> dir=\"/\"          base=\"/\"      ext=\"\" abs=true",
    "parts \"///\"            -> dir=\"/\"          base=\"/\"      ext=\"\" abs=true",
    "parts \"a\"              -> dir=\".\"          base=\"a\"      ext=\"\" abs=false",
    "parts \"/a\"             -> dir=\"/\"          base=\"a\"      ext=\"\" abs=true",
    "parts \"a/\"             -> dir=\"a\"          base=\"a\"      ext=\"\" abs=false",
    "parts \"/a/\"            -> dir=\"/a\"         base=\"a\"      ext=\"\" abs=true",
    "parts \"a/b\"            -> dir=\"a\"          base=\"b\"      ext=\"\" abs=false",
    "parts \"a//b\"           -> dir=\"a\"          base=\"b\"      ext=\"\" abs=false",
    "parts \"a/./b\"          -> dir=\"a\"          base=\"b\"      ext=\"\" abs=false",
    "parts \"a/../b\"         -> dir=\".\"          base=\"b\"      ext=\"\" abs=false",
    "parts \"../a\"           -> dir=\"..\"         base=\"a\"      ext=\"\" abs=false",
    "parts \"/../a\"          -> dir=\"/\"          base=\"a\"      ext=\"\" abs=true",
    "parts \"/../../a\"       -> dir=\"/\"          base=\"a\"      ext=\"\" abs=true",
    "parts \"a/b/..\"         -> dir=\"a/b\"        base=\"..\"     ext=\".\" abs=false",
    "parts \"a/b/../..\"      -> dir=\"a\"          base=\"..\"     ext=\".\" abs=false",
    "parts \"a/b/../../..\"   -> dir=\".\"          base=\"..\"     ext=\".\" abs=false",
    "parts \"./a\"            -> dir=\".\"          base=\"a\"      ext=\"\" abs=false",
    "parts \"././a\"          -> dir=\".\"          base=\"a\"      ext=\"\" abs=false",
    "parts \"/a/b/./../c/\"   -> dir=\"/a/c\"       base=\"c\"      ext=\"\" abs=true",
    "parts \"a/b/c/../../d\"  -> dir=\"a\"          base=\"d\"      ext=\"\" abs=false",
    "parts \"...\"            -> dir=\".\"          base=\"...\"    ext=\".\" abs=false",
    "parts \"a...\"           -> dir=\".\"          base=\"a...\"   ext=\".\" abs=false",
    "parts \"..a\"            -> dir=\".\"          base=\"..a\"    ext=\".a\" abs=false",
    "parts \"a..b\"           -> dir=\".\"          base=\"a..b\"   ext=\".b\" abs=false",
    "parts \"/.\"             -> dir=\"/\"          base=\".\"      ext=\".\" abs=true",
    "parts \"/..\"            -> dir=\"/\"          base=\"..\"     ext=\".\" abs=true",
    "parts \"/./\"            -> dir=\"/\"          base=\".\"      ext=\"\" abs=true",
    "parts \"/../\"           -> dir=\"/\"          base=\"..\"     ext=\"\" abs=true",
    "parts \"abc/../../def\"  -> dir=\"..\"         base=\"def\"    ext=\"\" abs=false",
    "parts \"/a/../..\"       -> dir=\"/\"          base=\"..\"     ext=\".\" abs=true",
    "parts \"x/y/../../../z\" -> dir=\"..\"         base=\"z\"      ext=\"\" abs=false",
    "parts \"//a//b//\"       -> dir=\"/a/b\"       base=\"b\"      ext=\"\" abs=true",
    "parts \"a/b/c/\"         -> dir=\"a/b/c\"      base=\"c\"      ext=\"\" abs=false",
    "parts \".../a\"          -> dir=\"...\"        base=\"a\"      ext=\"\" abs=false",
    "parts \"/a/.\"           -> dir=\"/a\"         base=\".\"      ext=\".\" abs=true",
    "join  [] -> \"\"",
    "join  [\"\"                                ] -> \"\"",
    "join  [\"a\"                               ] -> \"a\"",
    "join  [\"a\"                                \"b\"                               ] -> \"a/b\"",
    "join  [\"a\"                                \"\"                                ] -> \"a\"",
    "join  [\"\"                                 \"b\"                               ] -> \"b\"",
    "join  [\"\"                                 \"\"                                ] -> \"\"",
    "join  [\"a\"                                \"..\"                               \"b\"                               ] -> \"b\"",
    "join  [\"a\"                                \"../..\"                           ] -> \"..\"",
    "join  [\"/\"                                \"a\"                               ] -> \"/a\"",
    "join  [\"/a\"                               \"/b\"                              ] -> \"/a/b\"",
    "join  [\"a/\"                               \"/b\"                              ] -> \"a/b\"",
    "join  [\"a\"                                \"b\"                                \"c\"                               ] -> \"a/b/c\"",
    "join  [\"a\"                                \"../../b\"                         ] -> \"../b\"",
    "join  [\"/var/www\"                         \"../../etc/passwd\"                ] -> \"/etc/passwd\"",
    "join  [\"/var/www\"                         \"..%2f..%2fetc\"                   ] -> \"/var/www/..%2f..%2fetc\"",
    "join  [\"base\"                             \"sub/../../escape\"                ] -> \"escape\"",
    "join  [\"a\"                                \".\"                                \"b\"                               ] -> \"a/b\"",
    "join  [\"//\"                               \"a\"                               ] -> \"/a\"",
    "join  [\"a\"                                \"b/\"                              ] -> \"a/b\"",
    "join  [\".\"                                \"a\"                               ] -> \"a\"",
    "join  [\"..\"                               \"a\"                               ] -> \"../a\"",
    "match \"*\"      \"a\"      -> true  err=<nil>",
    "match \"*\"      \"a/b\"    -> false err=<nil>",
    "match \"*/*\"    \"a/b\"    -> true  err=<nil>",
    "match \"a/*\"    \"a/b\"    -> true  err=<nil>",
    "match \"a/*\"    \"a/b/c\"  -> false err=<nil>",
    "match \"**\"     \"a/b\"    -> false err=<nil>",
    "match \"?\"      \"a\"      -> true  err=<nil>",
    "match \"?\"      \"ab\"     -> false err=<nil>",
    "match \"[abc]\"  \"b\"      -> true  err=<nil>",
    "match \"[a-c]\"  \"b\"      -> true  err=<nil>",
    "match \"[^a]\"   \"b\"      -> true  err=<nil>",
    "match \"[!a]\"   \"b\"      -> false err=<nil>",
    "match \"a[\"     \"a[\"     -> false err=syntax error in pattern",
    "match \"[\"      \"[\"      -> false err=syntax error in pattern",
    "match \"[]\"     \"[]\"     -> false err=syntax error in pattern",
    "match \"\\\\*\"    \"*\"      -> true  err=<nil>",
    "match \"*.go\"   \"x.go\"   -> true  err=<nil>",
    "match \"*.go\"   \"a/x.go\" -> false err=<nil>",
    "match \"/*\"     \"/a\"     -> true  err=<nil>",
    "match \"\"       \"\"       -> true  err=<nil>",
    "match \"\"       \"a\"      -> false err=<nil>",
    "match \"a\"      \"\"       -> false err=<nil>",
    "match \"*\"      \"\"       -> true  err=<nil>",
    "match \"[-]\"    \"-\"      -> false err=syntax error in pattern",
];

fn chk(failed: &mut int, ln: &mut int, got: string) {
    if *ln >= GO.len() as int {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln + 1, got);
        *failed += 1;
        *ln += 1;
        return;
    }
    let want = s(GO[*ln as usize]);
    *ln += 1;
    if got == want {
        return;
    }
    fmt::Printf!("[!!] line %d FAIL\n  got  %q\n  want %q\n", *ln, got, want);
    *failed += 1;
}

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}
#[goish::main]
fn main() {
    let mut failed: int = 0;
    let mut ln: int = 0;
    let inputs = [
        "",
        ".",
        "..",
        "/",
        "//",
        "///",
        "a",
        "/a",
        "a/",
        "/a/",
        "a/b",
        "a//b",
        "a/./b",
        "a/../b",
        "../a",
        "/../a",
        "/../../a",
        "a/b/..",
        "a/b/../..",
        "a/b/../../..",
        "./a",
        "././a",
        "/a/b/./../c/",
        "a/b/c/../../d",
        "...",
        "a...",
        "..a",
        "a..b",
        "/.",
        "/..",
        "/./",
        "/../",
        "abc/../../def",
        "/a/../..",
        "x/y/../../../z",
        "//a//b//",
        "a/b/c/",
        ".../a",
        "/a/.",
    ];
    for in_ in inputs {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("clean %-16q -> %q", s(in_), path::Clean(s(in_))),
        );
    }
    for in_ in inputs {
        let (d, f) = path::Split(s(in_));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("split %-16q -> dir=%-12q file=%q", s(in_), d, f),
        );
    }
    for in_ in inputs {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "parts %-16q -> dir=%-12q base=%-8q ext=%q abs=%v",
                s(in_),
                path::Dir(s(in_)),
                path::Base(s(in_)),
                path::Ext(s(in_)),
                path::IsAbs(s(in_))
            ),
        );
    }
    let joins: [&[&str]; 22] = [
        &[],
        &[""],
        &["a"],
        &["a", "b"],
        &["a", ""],
        &["", "b"],
        &["", ""],
        &["a", "..", "b"],
        &["a", "../.."],
        &["/", "a"],
        &["/a", "/b"],
        &["a/", "/b"],
        &["a", "b", "c"],
        &["a", "../../b"],
        &["/var/www", "../../etc/passwd"],
        &["/var/www", "..%2f..%2fetc"],
        &["base", "sub/../../escape"],
        &["a", ".", "b"],
        &["//", "a"],
        &["a", "b/"],
        &[".", "a"],
        &["..", "a"],
    ];
    for j in joins {
        let mut v: alloc::vec::Vec<string> = alloc::vec::Vec::new();
        for e in j {
            v.push(s(e));
        }
        let sl = slice::<string>::__from_vec(v);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("join  %-34q -> %q", sl.clone(), path::Join(sl)),
        );
    }
    let globs = [
        ("*", "a"),
        ("*", "a/b"),
        ("*/*", "a/b"),
        ("a/*", "a/b"),
        ("a/*", "a/b/c"),
        ("**", "a/b"),
        ("?", "a"),
        ("?", "ab"),
        ("[abc]", "b"),
        ("[a-c]", "b"),
        ("[^a]", "b"),
        ("[!a]", "b"),
        ("a[", "a["),
        ("[", "["),
        ("[]", "[]"),
        ("\\*", "*"),
        ("*.go", "x.go"),
        ("*.go", "a/x.go"),
        ("/*", "/a"),
        ("", ""),
        ("", "a"),
        ("a", ""),
        ("*", ""),
        ("[-]", "-"),
    ];
    for (pat, name) in globs {
        let (ok, err) = path::Match(s(pat), s(name));
        let e = if err == goish::nil {
            s("<nil>")
        } else {
            err.Error()
        };
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("match %-8q %-8q -> %-5v err=%s", s(pat), s(name), ok, e),
        );
    }
    if ln != GO.len() as int {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln, GO.len() as int);
        failed += 1;
    }
    if failed == 0 {
        fmt::Printf!("ok %d/%d\n", ln, ln);
        return;
    }
    fmt::Printf!("FAILED %d of %d\n", failed, ln);
    syscall::Exit(1);
}
