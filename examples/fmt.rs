// Milestone 8 smoke test: fmt package.
//
// Tests Sprintf with the launch verb set, Println formatting, Errorf
// + %w wrap+chain integration, custom Stringer types.

#![no_std]
#![no_main]

use goish::fmt::Stringer;
use goish::{errors, int, nil, os, rune, string, syscall, Errorf, Fprintf, Fprintln, Println, Printf, Sprintf};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

// ─── Custom Stringer ─────────────────────────────────────────────────

struct Coord {
    x: int,
    y: int,
}

impl Stringer for Coord {
    fn String(&self) -> string {
        Sprintf!("(%d, %d)", self.x, self.y)
    }
}

#[goish::main]
fn main() {
    // (1) %s with string arg.
    let s = Sprintf!("hello %s!", string("world"));
    check(s == "hello world!", b"fmt: %s wrong\n");

    // (2) %d with int arg.
    let s = Sprintf!("n=%d", 42 as int);
    check(s == "n=42", b"fmt: %d wrong\n");

    // (3) %d with negative int.
    let s = Sprintf!("n=%d", -7 as int);
    check(s == "n=-7", b"fmt: %d negative wrong\n");

    // (4) %x / %X — hex.
    let s = Sprintf!("%x %X", 255 as int, 255 as int);
    check(s == "ff FF", b"fmt: %x/%X wrong\n");

    // (5) %b — binary.
    let s = Sprintf!("%b", 10 as int);
    check(s == "1010", b"fmt: %b wrong\n");

    // (6) %o — octal.
    let s = Sprintf!("%o", 8 as int);
    check(s == "10", b"fmt: %o wrong\n");

    // (7) %t — bool.
    let s = Sprintf!("%t %t", true, false);
    check(s == "true false", b"fmt: %t wrong\n");

    // (8) %v — default.
    let s = Sprintf!("%v %v", 7 as int, string("x"));
    check(s == "7 x", b"fmt: %v wrong\n");

    // (9) %% — literal percent.
    let s = Sprintf!("100%% done");
    check(s == "100% done", b"fmt: %% wrong\n");

    // (10) %q — quoted string.
    let s = Sprintf!("%q", string("hi\nthere"));
    check(s == "\"hi\\nthere\"", b"fmt: %q wrong\n");

    // (11) %c — rune as character.
    let s = Sprintf!("%c", 'A' as rune);
    check(s == "A", b"fmt: %c wrong\n");

    // (12) Multiple args, mixed verbs.
    let s = Sprintf!("[%d] %s = %v", 1 as int, string("k"), true);
    check(s == "[1] k = true", b"fmt: multi-verb wrong\n");

    // (13) Custom Stringer.
    let c = Coord { x: 3, y: 7 };
    let s = c.String();
    check(s == "(3, 7)", b"fmt: Stringer.String wrong\n");

    // (14) error formatting via %v / %s.
    let e = errors::New("file not found");
    let s = Sprintf!("got error: %v", e);
    check(s == "got error: file not found", b"fmt: %v on error wrong\n");

    // (15) Errorf with %w — wraps and is reachable via errors::Is/Unwrap.
    let inner = errors::New("disk full");
    let outer = Errorf!("write failed: %w", inner.clone());
    check(outer.Error() == "write failed: disk full", b"fmt: %w text wrong\n");
    check(errors::Is(outer.clone(), inner.clone()), b"fmt: Is must walk %w chain\n");
    check(errors::Unwrap(outer) == inner, b"fmt: Unwrap on Errorf wrong\n");

    // (16) Errorf without %w — plain error.
    let e = Errorf!("bad: %s", string("input"));
    check(e.Error() == "bad: input", b"fmt: Errorf plain wrong\n");
    check(errors::Unwrap(e) == nil, b"fmt: Errorf no-%w must Unwrap to nil\n");

    // (17) Println — to stdout, real I/O.
    Println!("fmt: stdout println", 42 as int, true);

    // (18) Printf — to stdout.
    Printf!("count=%d, ok=%t\n", 5 as int, true);

    // (19) Fprintf — to a writer.
    let mut e = os::Stderr();
    Fprintf!(e, "fmt: fprintf %d to stderr\n", 99 as int);

    // (20) Fprintln — to a writer.
    let mut o = os::Stdout();
    Fprintln!(o, "fmt: fprintln", 1 as int, 2 as int);

    const OK: &[u8] = b"fmt: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
