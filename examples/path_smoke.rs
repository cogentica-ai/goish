// Smoke test: M25 — path + path/filepath pure-lexical operations.

#![no_std]
#![no_main]

use goish::path::{self, filepath};
use goish::{string, syscall};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

#[goish::main]
fn main() {
    test_clean();
    test_split_ext_base_dir();
    test_isabs();
    test_join();
    test_match();
    test_islocal_localize();
    test_volume_toslash();
    test_splitlist();
    test_rel();

    const OK: &[u8] = b"path_smoke: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}

fn test_clean() {
    // Cases lifted from /share/go/src/path/path_test.go (cleantests).
    let cases: &[(&str, &str)] = &[
        ("", "."),
        ("abc", "abc"),
        ("abc/def", "abc/def"),
        ("a/b/c", "a/b/c"),
        (".", "."),
        ("..", ".."),
        ("../..", "../.."),
        ("../../abc", "../../abc"),
        ("/abc", "/abc"),
        ("/", "/"),
        ("abc/", "abc"),
        ("abc/def/", "abc/def"),
        ("a/b/c/", "a/b/c"),
        ("./", "."),
        ("../", ".."),
        ("../../", "../.."),
        ("/abc/", "/abc"),
        ("abc//def//ghi", "abc/def/ghi"),
        ("//abc", "/abc"),
        ("///abc", "/abc"),
        ("//abc//", "/abc"),
        ("abc//", "abc"),
        ("abc/./def", "abc/def"),
        ("/./abc/def", "/abc/def"),
        ("abc/.", "abc"),
        ("abc/def/ghi/../jkl", "abc/def/jkl"),
        ("abc/def/../ghi/../jkl", "abc/jkl"),
        ("abc/def/..", "abc"),
        ("abc/def/../..", "."),
        ("/abc/def/../..", "/"),
        ("abc/def/../../..", ".."),
        ("/abc/def/../../..", "/"),
        ("abc/def/../../../ghi/jkl/../../../mno", "../../mno"),
    ];
    for (input, want) in cases {
        let got = path::Clean(*input);
        check(got == *want, b"path::Clean: mismatch\n");
        // filepath::Clean delegates to path::Clean on Unix.
        let got2 = filepath::Clean(*input);
        check(got2 == *want, b"filepath::Clean: mismatch\n");
    }
}

fn test_split_ext_base_dir() {
    let split_cases: &[(&str, &str, &str)] = &[
        ("a/b", "a/", "b"),
        ("a/b/", "a/b/", ""),
        ("a/", "a/", ""),
        ("a", "", "a"),
        ("/", "/", ""),
        ("", "", ""),
    ];
    for (p, want_dir, want_file) in split_cases {
        let (d, f) = path::Split(*p);
        check(d == *want_dir, b"path::Split: dir mismatch\n");
        check(f == *want_file, b"path::Split: file mismatch\n");
    }

    let ext_cases: &[(&str, &str)] = &[
        ("path.go", ".go"),
        ("path.pb.go", ".go"),
        ("a.dir/b", ""),
        ("a.dir/b.go", ".go"),
        ("a.dir/", ""),
    ];
    for (p, want) in ext_cases {
        let got = path::Ext(*p);
        check(got == *want, b"path::Ext: mismatch\n");
    }

    let base_cases: &[(&str, &str)] = &[
        ("", "."),
        (".", "."),
        ("/.", "."),
        ("/", "/"),
        ("////", "/"),
        ("x/", "x"),
        ("abc", "abc"),
        ("abc/def", "def"),
        ("a/b/.x", ".x"),
        ("a/b/c.x", "c.x"),
    ];
    for (p, want) in base_cases {
        let got = path::Base(*p);
        check(got == *want, b"path::Base: mismatch\n");
    }

    let dir_cases: &[(&str, &str)] = &[
        ("", "."),
        (".", "."),
        ("/.", "/"),
        ("/", "/"),
        ("/foo", "/"),
        ("x/", "x"),
        ("abc", "."),
        ("abc/def", "abc"),
        ("a/b/.x", "a/b"),
        ("a/b/c.x", "a/b"),
    ];
    for (p, want) in dir_cases {
        let got = path::Dir(*p);
        check(got == *want, b"path::Dir: mismatch\n");
    }
}

fn test_isabs() {
    check(path::IsAbs("/usr/local"), b"IsAbs(/usr/local) want true\n");
    check(path::IsAbs("/"), b"IsAbs(/) want true\n");
    check(!path::IsAbs("usr/local"), b"IsAbs(usr/local) want false\n");
    check(!path::IsAbs(""), b"IsAbs() want false\n");
    check(
        filepath::IsAbs("/etc"),
        b"filepath::IsAbs(/etc) want true\n",
    );
    check(
        !filepath::IsAbs("etc"),
        b"filepath::IsAbs(etc) want false\n",
    );
}

fn test_join() {
    let joined = path::Join(goish::slice!([]string{"a", "b", "c"}));
    check(joined == "a/b/c", b"Join abc\n");

    let joined = path::Join(goish::slice!([]string{"a", "", "b"}));
    check(joined == "a/b", b"Join with empty\n");

    let joined = path::Join(goish::slice!([]string{"/a", "b"}));
    check(joined == "/a/b", b"Join rooted\n");

    let joined = path::Join(goish::slice!([]string{"", ""}));
    check(joined == "", b"Join empties\n");

    let joined = path::Join(goish::slice!([]string{"a/b", "../c"}));
    check(joined == "a/c", b"Join with dotdot\n");

    let joined = filepath::Join(goish::slice!([]string{"/usr", "local", "bin"}));
    check(joined == "/usr/local/bin", b"filepath::Join\n");
}

fn test_match() {
    let tests: &[(&str, &str, bool)] = &[
        ("abc", "abc", true),
        ("*", "abc", true),
        ("*c", "abc", true),
        ("a*", "a", true),
        ("a*", "abc", true),
        ("a*", "ab/c", false),
        ("a*/b", "abc/b", true),
        ("a*/b", "a/c/b", false),
        ("a*b*c*d*e*/f", "axbxcxdxexxx/f", true),
        ("?", "a", true),
        ("?/?", "a/b", true),
        ("[a-z]", "a", true),
        ("[^a-z]", "a", false),
        ("[", "a", false),
        ("a", "", false),
        ("", "", true),
    ];
    for (pat, name, want) in tests {
        let (ok, _err) = path::Match(*pat, *name);
        check(ok == *want, b"path::Match: mismatch\n");
        let (ok2, _err) = filepath::Match(*pat, *name);
        check(ok2 == *want, b"filepath::Match: mismatch\n");
    }

    // Bad pattern produces an error (we just check that err != nil).
    let (_, err) = path::Match("[", "abc");
    check(err != goish::nil, b"path::Match: bad pattern want err\n");
}

fn test_islocal_localize() {
    check(filepath::IsLocal("foo"), b"IsLocal(foo)\n");
    check(filepath::IsLocal("a/b"), b"IsLocal(a/b)\n");
    check(!filepath::IsLocal(""), b"IsLocal()\n");
    check(!filepath::IsLocal("/foo"), b"IsLocal(/foo)\n");
    check(!filepath::IsLocal(".."), b"IsLocal(..)\n");
    check(!filepath::IsLocal("../a"), b"IsLocal(../a)\n");
    check(filepath::IsLocal("a/.."), b"IsLocal(a/..) clean=.\n");

    let (s, e) = filepath::Localize("a/b");
    check(e == goish::nil && s == "a/b", b"Localize valid\n");
    let (_, e) = filepath::Localize("/abs");
    check(e != goish::nil, b"Localize abs want err\n");
    let (_, e) = filepath::Localize("a/..");
    check(e != goish::nil, b"Localize dotdot want err\n");
}

fn test_volume_toslash() {
    check(
        filepath::VolumeName("/usr/local") == "",
        b"VolumeName empty on unix\n",
    );
    check(filepath::ToSlash("a/b/c") == "a/b/c", b"ToSlash identity\n");
    check(
        filepath::FromSlash("a/b/c") == "a/b/c",
        b"FromSlash identity\n",
    );
}

fn test_splitlist() {
    let parts = filepath::SplitList("");
    check(goish::len(&parts) == 0, b"SplitList(empty) -> []\n");

    let parts = filepath::SplitList("a:b:c");
    check(goish::len(&parts) == 3, b"SplitList abc len\n");
    check(parts[0] == "a", b"SplitList[0]\n");
    check(parts[1] == "b", b"SplitList[1]\n");
    check(parts[2] == "c", b"SplitList[2]\n");

    let parts = filepath::SplitList(":");
    check(goish::len(&parts) == 2, b"SplitList(:) -> 2\n");
    check(parts[0] == "" && parts[1] == "", b"SplitList(:) empties\n");
}

fn test_rel() {
    let cases: &[(&str, &str, &str)] = &[
        ("a/b", "a/b", "."),
        ("a/b/.", "a/b", "."),
        ("a/b", "a/b/", "."),
        ("a/b", "a/c", "../c"),
        ("a/b", "c/d", "../../c/d"),
        (".", "a/b", "a/b"),
        ("a/b", "a/b/c/d", "c/d"),
        ("/a/b", "/a/b/c", "c"),
        ("/a", "/a/b/c", "b/c"),
    ];
    for (base, targ, want) in cases {
        let (got, err) = filepath::Rel(*base, *targ);
        check(err == goish::nil, b"Rel: unexpected err\n");
        check(got == *want, b"Rel: mismatch\n");
    }
    // Rel error: targ rooted, base relative.
    let (_, err) = filepath::Rel("a", "/a/b");
    check(err != goish::nil, b"Rel: rooted/rel mismatch want err\n");
}
