// Smoke test: M15 strings/bytes completeness pass — Cut*, Fields*,
// IndexAny/Func, Map, TrimFunc, ContainsAny/Func, NewReader,
// SplitAfter, Compare, Clone.

#![no_std]
#![no_main]

use goish::{byte, slice, string, strings, syscall, unicode};

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
    // ─── strings.Cut / CutPrefix / CutSuffix ─────────────────────────
    let (a, b, ok) = strings::Cut("foo=bar=baz", "=");
    check(ok && a == "foo" && b == "bar=baz", b"strings: Cut\n");

    let (a, b, ok) = strings::Cut("nope", "=");
    check(!ok && a == "nope" && b == "", b"strings: Cut miss\n");

    let (a, ok) = strings::CutPrefix("hello-world", "hello-");
    check(ok && a == "world", b"strings: CutPrefix\n");

    let (a, ok) = strings::CutPrefix("hello", "no");
    check(!ok && a == "hello", b"strings: CutPrefix miss\n");

    let (a, ok) = strings::CutSuffix("file.txt", ".txt");
    check(ok && a == "file", b"strings: CutSuffix\n");

    // ─── strings.Compare / Clone ─────────────────────────────────────
    check(strings::Compare("a", "b") == -1, b"strings: Compare lt\n");
    check(strings::Compare("b", "a") == 1, b"strings: Compare gt\n");
    check(strings::Compare("a", "a") == 0, b"strings: Compare eq\n");

    let s = string("alice");
    let c = strings::Clone(s.clone());
    check(c == "alice", b"strings: Clone\n");

    // ─── strings.Fields / FieldsFunc ─────────────────────────────────
    let fs = strings::Fields("  hello   world  foo ");
    check(fs.Len() == 3, b"strings: Fields count\n");
    check(fs[0] == "hello" && fs[1] == "world" && fs[2] == "foo",
          b"strings: Fields values\n");

    let fs = strings::FieldsFunc("a,b;c,,d", |r: goish::rune| r == ',' as goish::rune || r == ';' as goish::rune);
    check(fs.Len() == 4, b"strings: FieldsFunc count\n");
    check(fs[3] == "d", b"strings: FieldsFunc[3]\n");

    // ─── strings.IndexAny / LastIndexAny / LastIndexByte ─────────────
    check(strings::IndexAny("hello", "xyzo") == 4, b"strings: IndexAny\n");
    check(strings::IndexAny("abc", "xyz") == -1, b"strings: IndexAny miss\n");
    check(strings::LastIndexAny("hello", "lo") == 4, b"strings: LastIndexAny\n");
    check(strings::LastIndexByte("foobar", b'o') == 2, b"strings: LastIndexByte\n");

    // ─── strings.IndexFunc / LastIndexFunc / ContainsFunc ────────────
    let i = strings::IndexFunc("abc123", unicode::IsDigit);
    check(i == 3, b"strings: IndexFunc\n");
    let i = strings::LastIndexFunc("abc123x", unicode::IsDigit);
    check(i == 5, b"strings: LastIndexFunc\n");
    check(strings::ContainsFunc("hello", unicode::IsLetter), b"strings: ContainsFunc\n");
    check(!strings::ContainsFunc("12345", unicode::IsLetter), b"strings: !ContainsFunc\n");

    check(strings::ContainsAny("hello", "xyzh"), b"strings: ContainsAny\n");
    check(!strings::ContainsAny("abc", "xyz"), b"strings: !ContainsAny\n");

    // ─── strings.TrimFunc / TrimLeftFunc / TrimRightFunc ─────────────
    let r = strings::TrimFunc("  hello  ", unicode::IsSpace);
    check(r == "hello", b"strings: TrimFunc\n");
    let r = strings::TrimLeftFunc("---abc---", |c: goish::rune| c == '-' as goish::rune);
    check(r == "abc---", b"strings: TrimLeftFunc\n");
    let r = strings::TrimRightFunc("abc---", |c: goish::rune| c == '-' as goish::rune);
    check(r == "abc", b"strings: TrimRightFunc\n");

    // ─── strings.Map ─────────────────────────────────────────────────
    let r = strings::Map(unicode::ToUpper, "Hello");
    check(r == "HELLO", b"strings: Map ToUpper\n");
    // Drop digits via negative return.
    let r = strings::Map(|c: goish::rune| if unicode::IsDigit(c) { -1 } else { c }, "a1b2c3");
    check(r == "abc", b"strings: Map drop\n");

    // ─── strings.SplitAfter / SplitAfterN ────────────────────────────
    let parts = strings::SplitAfter("a,b,c", ",");
    check(parts.Len() == 3, b"strings: SplitAfter count\n");
    check(parts[0] == "a,", b"strings: SplitAfter[0]\n");
    check(parts[1] == "b,", b"strings: SplitAfter[1]\n");
    check(parts[2] == "c", b"strings: SplitAfter[2]\n");

    let parts = strings::SplitAfterN("a,b,c,d", ",", 2);
    check(parts.Len() == 2, b"strings: SplitAfterN count\n");
    check(parts[0] == "a,", b"strings: SplitAfterN[0]\n");
    check(parts[1] == "b,c,d", b"strings: SplitAfterN[1]\n");

    // ─── strings.NewReader → io::Reader ──────────────────────────────
    let mut r = strings::NewReader("hello");
    check(r.Len() == 5, b"strings: Reader.Len\n");
    let mut buf: slice<goish::byte> = goish::make!([]byte, 3);
    let (n, err) = r.Read(&mut buf);
    check(err == goish::nil && n == 3, b"strings: Reader.Read 3\n");
    check(buf[0] == b'h' && buf[2] == b'l', b"strings: Reader.Read content\n");

    let (n, _) = r.Read(&mut buf);
    check(n == 2, b"strings: Reader.Read remaining\n");

    // ─── bytes parallel sanity ──────────────────────────────────────
    use goish::bytes;
    let s = goish::slice!([]byte{ b'a', b',', b'b', b',', b'c' });
    let (a, b, ok) = bytes::Cut(s.clone(), b",".as_slice());
    check(ok && a.Len() == 1 && a[0] == b'a', b"bytes: Cut a\n");
    check(b.Len() == 3, b"bytes: Cut b\n");

    let fs = bytes::Fields(b"  one  two ".as_slice());
    check(fs.Len() == 2, b"bytes: Fields count\n");
    check(fs[0].Len() == 3, b"bytes: Fields[0] len\n");

    let r = bytes::TrimFunc(b"--abc--".as_slice(), |c: goish::rune| c == '-' as goish::rune);
    check(r.Len() == 3 && r[0] == b'a', b"bytes: TrimFunc\n");

    let r = bytes::Map(unicode::ToUpper, b"hi".as_slice());
    check(r.Len() == 2 && r[0] == b'H' && r[1] == b'I', b"bytes: Map\n");

    const OK: &[u8] = b"strings_completeness: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
