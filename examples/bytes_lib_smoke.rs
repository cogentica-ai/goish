// Milestone 13 smoke test: bytes package.
//
// Mirrors strings smoke test over slice<byte>. Plus Buffer round-trip
// and Reader integration with bufio Scanner.

#![no_std]
#![no_main]

use goish::{bufio, byte, make, nil, slice, string, syscall};

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
    use goish::bytes;
    use goish::slices;

    // ─── Equal / Compare / Clone ──────────────────────────────────────

    check(bytes::Equal(b"hi", b"hi"), b"bytes: Equal yes wrong\n");
    check(!bytes::Equal(b"hi", b"hey"), b"bytes: Equal no wrong\n");
    check(bytes::Compare(b"abc", b"abd") == -1, b"bytes: Compare lt wrong\n");
    check(bytes::Compare(b"abc", b"abc") == 0, b"bytes: Compare eq wrong\n");
    check(bytes::Compare(b"abd", b"abc") == 1, b"bytes: Compare gt wrong\n");

    let cloned = bytes::Clone(b"original");
    check(bytes::Equal(&cloned, b"original"), b"bytes: Clone wrong\n");

    // ─── Search ───────────────────────────────────────────────────────

    check(bytes::Contains(b"foobar", b"oba"), b"bytes: Contains hit wrong\n");
    check(!bytes::Contains(b"foobar", b"xyz"), b"bytes: Contains miss wrong\n");
    check(bytes::HasPrefix(b"greetings", b"greet"), b"bytes: HasPrefix wrong\n");
    check(bytes::HasSuffix(b"greetings", b"ings"), b"bytes: HasSuffix wrong\n");
    check(bytes::Index(b"abcdef", b"cd") == 2, b"bytes: Index wrong\n");
    check(bytes::IndexByte(b"hello", b'l') == 2, b"bytes: IndexByte wrong\n");
    check(bytes::LastIndex(b"ababab", b"ab") == 4, b"bytes: LastIndex wrong\n");
    check(bytes::LastIndexByte(b"hello", b'l') == 3, b"bytes: LastIndexByte wrong\n");
    check(bytes::Count(b"cheese", b"e") == 3, b"bytes: Count wrong\n");

    // ─── Trim family ──────────────────────────────────────────────────

    check(
        bytes::Equal(bytes::TrimSpace(b"  hi  "), b"hi"),
        b"bytes: TrimSpace wrong\n",
    );
    check(
        bytes::Equal(bytes::Trim(b"..hi...", b"."), b"hi"),
        b"bytes: Trim wrong\n",
    );
    check(
        bytes::Equal(bytes::TrimLeft(b"xxhello", b"x"), b"hello"),
        b"bytes: TrimLeft wrong\n",
    );
    check(
        bytes::Equal(bytes::TrimRight(b"hello!!", b"!"), b"hello"),
        b"bytes: TrimRight wrong\n",
    );
    check(
        bytes::Equal(bytes::TrimPrefix(b"Mr. Smith", b"Mr. "), b"Smith"),
        b"bytes: TrimPrefix wrong\n",
    );
    check(
        bytes::Equal(bytes::TrimSuffix(b"file.rs", b".rs"), b"file"),
        b"bytes: TrimSuffix wrong\n",
    );

    // ─── Case (ASCII-only) / EqualFold ────────────────────────────────

    check(
        bytes::Equal(bytes::ToUpper(b"hello"), b"HELLO"),
        b"bytes: ToUpper wrong\n",
    );
    check(
        bytes::Equal(bytes::ToLower(b"HELLO"), b"hello"),
        b"bytes: ToLower wrong\n",
    );
    check(bytes::EqualFold(b"Hello", b"hELLO"), b"bytes: EqualFold wrong\n");

    // ─── Replace / ReplaceAll / Repeat ────────────────────────────────

    check(
        bytes::Equal(bytes::Replace(b"aaa", b"a", b"b", 2), b"bba"),
        b"bytes: Replace n=2 wrong\n",
    );
    check(
        bytes::Equal(bytes::ReplaceAll(b"a-b-c", b"-", b" "), b"a b c"),
        b"bytes: ReplaceAll wrong\n",
    );
    check(
        bytes::Equal(bytes::Repeat(b"ab", 3), b"ababab"),
        b"bytes: Repeat wrong\n",
    );

    // ─── Split / Join ─────────────────────────────────────────────────

    let parts = bytes::Split(b"a,b,c", b",");
    check(parts.Len() == 3, b"bytes: Split count wrong\n");
    check(bytes::Equal(parts[0].clone(), b"a"), b"bytes: Split[0] wrong\n");
    check(bytes::Equal(parts[1].clone(), b"b"), b"bytes: Split[1] wrong\n");
    check(bytes::Equal(parts[2].clone(), b"c"), b"bytes: Split[2] wrong\n");

    let joined = bytes::Join(parts, b"-");
    check(bytes::Equal(joined, b"a-b-c"), b"bytes: Join wrong\n");

    // SplitN with n=2 keeps the unsplit remainder.
    let parts = bytes::SplitN(b"a,b,c,d", b",", 2);
    check(parts.Len() == 2, b"bytes: SplitN count wrong\n");
    check(bytes::Equal(parts[0].clone(), b"a"), b"bytes: SplitN[0] wrong\n");
    check(bytes::Equal(parts[1].clone(), b"b,c,d"), b"bytes: SplitN[1] wrong\n");

    // ─── Buffer write→read round-trip ─────────────────────────────────

    let mut buf = bytes::Buffer::new();
    let (n, err) = buf.Write(make_slice(b"hello"));
    check(n == 5 && err == nil, b"bytes: Buffer Write wrong\n");
    let (n, err) = buf.WriteString(", world");
    check(n == 7 && err == nil, b"bytes: Buffer WriteString wrong\n");
    let _ = buf.WriteByte(b'!');
    check(buf.Len() == 13, b"bytes: Buffer Len wrong\n");
    check(buf.String() == "hello, world!", b"bytes: Buffer String wrong\n");

    // Read part of the buffer.
    let mut dst: slice<byte> = make!([]byte, 5);
    let (n, err) = buf.Read(&mut dst);
    check(n == 5 && err == nil, b"bytes: Buffer Read wrong\n");
    check(bytes::Equal(&dst, b"hello"), b"bytes: Buffer Read content wrong\n");
    check(buf.Len() == 8, b"bytes: Buffer Len after Read wrong\n");

    // Reset.
    buf.Reset();
    check(buf.Len() == 0, b"bytes: Buffer Reset wrong\n");

    // ─── NewBufferString ──────────────────────────────────────────────

    let buf = bytes::NewBufferString("seed");
    check(buf.Len() == 4, b"bytes: NewBufferString len wrong\n");
    check(buf.String() == "seed", b"bytes: NewBufferString contents wrong\n");

    // ─── Reader integration with bufio Scanner ────────────────────────

    let r = bytes::NewReader(make_slice(b"alpha\nbeta\ngamma\n"));
    let mut sc = bufio::NewScanner(r);
    let mut out = make!([]string, 0, 3);
    while sc.Scan() {
        out = goish::append!(out, sc.Text());
    }
    check(sc.Err() == nil, b"bytes: Reader+Scanner Err wrong\n");
    let want: slice<string> = goish::slice!([]string{ "alpha", "beta", "gamma" });
    check(slices::Equal(&out, &want), b"bytes: Reader+Scanner content wrong\n");

    // ─── &'static str / &'static [u8] / b"..." flow via Into ──────────

    // Mix arg shapes — confirm the From impls let everything in.
    check(bytes::Equal(b"x", b"x"), b"bytes: byte-array literal flow wrong\n");
    let owned = bytes::Clone(b"abc");
    check(bytes::Equal(owned, b"abc"), b"bytes: owned-vs-literal Equal wrong\n");

    const OK: &[u8] = b"bytes: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}

// Helper: turn a byte literal into an owned slice<byte> for code that
// needs a value (not a literal) — used by the Buffer test where we
// don't want to Into-from-literal at every call site.
fn make_slice(b: &'static [u8]) -> slice<byte> {
    b.into()
}
