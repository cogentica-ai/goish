// Milestone 10 smoke test: strings package.
//
// Tag normalizer, mirroring the Go original in examples/wip_strings.md:
// split a comma-separated input, trim each field, lowercase, drop a
// leading '#', skip empties, rejoin.
//
// Expected output:
//   hello, world, goish, rust

#![no_std]
#![no_main]

use goish::strings;
use goish::{range, string, syscall, Println};

fn normalize(input: string) -> string {
    let parts = strings::Split(input, ",");

    let mut out = strings::Builder::new();
    for (_, p) in range!(parts) {
        let p = strings::TrimSpace(p.clone());
        if p == "" {
            continue;
        }
        let p = strings::ToLower(p);
        let p = strings::TrimPrefix(p, "#");

        if out.Len() > 0 {
            out.WriteString(", ");
        }
        out.WriteString(p);
    }
    out.String()
}

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
    // (1) The headline normalize example.
    let got = normalize(string("Hello,  WORLD , #goish, , Rust"));
    check(got == "hello, world, goish, rust", b"strings: normalize wrong\n");
    Println!(got);

    // (2) Spot-checks for each public function used in the design table.
    check(
        strings::Contains(string("foobar"), "oba"),
        b"strings: Contains wrong\n",
    );
    check(
        !strings::Contains(string("foobar"), "xyz"),
        b"strings: Contains negative wrong\n",
    );
    check(
        strings::HasPrefix(string("greetings"), "greet"),
        b"strings: HasPrefix wrong\n",
    );
    check(
        strings::HasSuffix(string("greetings"), "ings"),
        b"strings: HasSuffix wrong\n",
    );
    check(strings::Index(string("abcdef"), "cd") == 2, b"strings: Index wrong\n");
    check(
        strings::IndexByte(string("hello"), b'l') == 2,
        b"strings: IndexByte wrong\n",
    );
    check(
        strings::LastIndex(string("ababab"), "ab") == 4,
        b"strings: LastIndex wrong\n",
    );
    check(strings::Count(string("cheese"), "e") == 3, b"strings: Count wrong\n");

    // Trim family.
    check(
        strings::TrimSpace(string("  hi  ")) == "hi",
        b"strings: TrimSpace wrong\n",
    );
    check(
        strings::Trim(string("..hi..."), ".") == "hi",
        b"strings: Trim wrong\n",
    );
    check(
        strings::TrimLeft(string("xxhello"), "x") == "hello",
        b"strings: TrimLeft wrong\n",
    );
    check(
        strings::TrimRight(string("hello!!"), "!") == "hello",
        b"strings: TrimRight wrong\n",
    );
    check(
        strings::TrimPrefix(string("Mr. Smith"), "Mr. ") == "Smith",
        b"strings: TrimPrefix wrong\n",
    );
    check(
        strings::TrimSuffix(string("file.rs"), ".rs") == "file",
        b"strings: TrimSuffix wrong\n",
    );

    // Case (ASCII-only).
    check(
        strings::ToUpper(string("hello")) == "HELLO",
        b"strings: ToUpper wrong\n",
    );
    check(
        strings::ToLower(string("HELLO")) == "hello",
        b"strings: ToLower wrong\n",
    );

    // Replace.
    check(
        strings::Replace(string("aaa"), "a", "b", 2) == "bba",
        b"strings: Replace n=2 wrong\n",
    );
    check(
        strings::ReplaceAll(string("a-b-c"), "-", " ") == "a b c",
        b"strings: ReplaceAll wrong\n",
    );

    // Repeat.
    check(
        strings::Repeat(string("ab"), 3) == "ababab",
        b"strings: Repeat wrong\n",
    );

    // EqualFold (ASCII).
    check(
        strings::EqualFold(string("Hello"), "hELLO"),
        b"strings: EqualFold wrong\n",
    );

    // Join.
    let parts = strings::Split(string("a,b,c"), ",");
    check(strings::Join(parts, "-") == "a-b-c", b"strings: Join wrong\n");

    const OK: &[u8] = b"strings: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
