// bytes_ref_smoke — the bytes package against a running Go.
// (bytes/bytes.go, bytes/buffer.go, bytes/reader.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_bytes_ref.go` run in
// `package bytes_test` by `scripts/goref.sh`.
//
// bytes mirrors strings, but on a type that CAN hold invalid UTF-8 —
// which is the whole reason the two packages exist separately, and the
// half a port is least likely to have exercised, because a Rust &str
// cannot even express the inputs. Every rune-oriented function here has
// defined behaviour on a malformed encoding, and it is never "skip it":
// a bad byte decodes as RuneError with width 1, so it participates in
// Map, in the Trim cutsets, in Runes, in the Index family and in
// EqualFold as a real element. Getting that wrong turns a byte slice
// that came off a socket into a different slice, silently. So the
// inputs here are built from raw bytes: "a\xffb", and 日 <bad> 語.
//
// Buffer is the other half: a Reader and a Writer at once, with a read
// cursor that Truncate and Reset move and that Next and UnreadByte
// step.
//
// goish came through this almost intact — IndexAny and friends are
// already rune-based here, unlike their strings counterparts. One
// defect: Buffer.Read on an EMPTY buffer answered io.EOF even when the
// caller passed a zero-length p. Go returns (0, nil) for that case, and
// io.Reader's contract singles it out: "Implementations of Read are
// discouraged from returning a zero byte count with a nil error, except
// when len(p) == 0." An empty p is a caller asking for nothing, not the
// end of a stream, and answering EOF tells a copier the source is
// finished when it has only been handed an empty buffer. Go's
// accompanying Reset-to-recover-space on the empty path was missing
// too, and is restored with it.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::goslice::slice;
use goish::gostring::string;
use goish::types::{byte, int, rune};
use goish::{bytes, fmt, io, syscall, unicode};

fn b(v: &[u8]) -> slice<byte> {
    return slice::__from_vec(v.to_vec());
}
fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

// go: none — goish idiom: the reference lines, in the order Go printed
//     them. Comparing whole rendered lines keeps this smoke and the
//     generator in lockstep: a case added to one is a mismatch in the
//     other, never a silent pass.
const GO: [&str; 84] = [
    "runes bad=\"a\\xffb\" -> ['a' '�' 'b']",
    "runes badseq=\"日\\xff語\" -> ['日' '�' '語']",
    "tovalid bad=\"a\\xffb\" -> \"a?b\" \"ab\"",
    "tovalid badseq=\"日\\xff語\" -> \"日!語\"",
    "map upper bad=\"a\\xffb\" -> \"A�B\"",
    "map drop bad=\"a\\xffb\" -> \"ab\"",
    "case bad lower=\"a�b\" upper=\"A�B\" title=\"A�b\"",
    "valid bad=true badseq=true good=true",
    "index \"a\\xffb\"     \"\\xff\"   -> idx=1   last=1   count=1",
    "index \"a\\xffb\"     \"b\"      -> idx=2   last=2   count=1",
    "index \"日\\xff語\"     \"日\"      -> idx=0   last=0   count=1",
    "index \"日\\xff語\"     \"\\xff\"   -> idx=3   last=3   count=1",
    "index \"日本語\"        \"本\"      -> idx=3   last=3   count=1",
    "index \"\"           \"\"       -> idx=0   last=0   count=1",
    "index \"abc\"        \"\"       -> idx=0   last=3   count=4",
    "indexany \"日本語\"        \"本語\"       -> any=3   lastany=6",
    "indexany \"a\\xffb\"     \"ab\"       -> any=0   lastany=2",
    "indexany \"a\\xffb\"     \"�\"        -> any=1   lastany=1",
    "indexany \"日\\xff語\"     \"語\"        -> any=4   lastany=4",
    "indexany \"abc\"        \"\"         -> any=-1  lastany=-1",
    "indexrune bad=\"a\\xffb\" r='b'       -> 2  badseq -> -1",
    "indexrune bad=\"a\\xffb\" r='�'       -> 1  badseq -> 3",
    "indexrune bad=\"a\\xffb\" r='日'       -> -1  badseq -> 0",
    "indexrune bad=\"a\\xffb\" r='�'       -> -1  badseq -> -1",
    "split \"a,b,c\"        \",\"  -> [\"a\" \"b\" \"c\"]  after=[\"a,\" \"b,\" \"c\"]",
    "split \"a\\xffb\"       \"\"   -> [\"a\" \"\\xff\" \"b\"]  after=[\"a\" \"\\xff\" \"b\"]",
    "split \"日\\xff語\"       \"\"   -> [\"日\" \"\\xff\" \"語\"]  after=[\"日\" \"\\xff\" \"語\"]",
    "split \"\"             \",\"  -> [\"\"]  after=[\"\"]",
    "split \"\"             \"\"   -> []  after=[]",
    "split \"日本\"           \"\"   -> [\"日\" \"本\"]  after=[\"日\" \"本\"]",
    "splitn n=-1  -> [\"a\" \"b\" \"c\" \"d\"]  after=[\"a,\" \"b,\" \"c,\" \"d\"]",
    "splitn n=0   -> []  after=[]",
    "splitn n=1   -> [\"a,b,c,d\"]  after=[\"a,b,c,d\"]",
    "splitn n=2   -> [\"a\" \"b,c,d\"]  after=[\"a,\" \"b,c,d\"]",
    "splitn n=10  -> [\"a\" \"b\" \"c\" \"d\"]  after=[\"a,\" \"b,\" \"c,\" \"d\"]",
    "trim \"a\\xffb\"     \"ab\"       -> t=\"\\xff\"       l=\"\\xffb\"      r=\"a\\xff\"     ",
    "trim \"a\\xffb\"     \"�\"        -> t=\"a\\xffb\"     l=\"a\\xffb\"     r=\"a\\xffb\"    ",
    "trim \"日\\xff語\"     \"日語\"       -> t=\"\\xff\"       l=\"\\xff語\"      r=\"日\\xff\"     ",
    "trim \"xxhixx\"     \"x\"        -> t=\"hi\"         l=\"hixx\"       r=\"xxhi\"      ",
    "trim \"  hi  \"     \"\"         -> t=\"  hi  \"     l=\"  hi  \"     r=\"  hi  \"    ",
    "trimspace bad=\"a\\xffb\" badseq=\"日\\xff語\" sp=\"hi\"",
    "fields \"a\\xffb\"       -> [\"a\\xffb\"]",
    "fields \"日\\xff語\"       -> [\"日\\xff語\"]",
    "fields \"  a b  \"      -> [\"a\" \"b\"]",
    "fields \"\"             -> []",
    "fields \"\"             -> []",
    "eq \"\"           \"\"           -> equal=true  fold=true  cmp=0",
    "eq \"\"           \"\"           -> equal=true  fold=true  cmp=0",
    "eq \"\"           \"\"           -> equal=true  fold=true  cmp=0",
    "eq \"a\"          \"A\"          -> equal=false fold=true  cmp=1",
    "eq \"a\\xffb\"     \"a\\xffb\"     -> equal=true  fold=true  cmp=0",
    "eq \"a\\xffb\"     \"a\\xfeb\"     -> equal=false fold=true  cmp=1",
    "eq \"K\"          \"K\"          -> equal=false fold=true  cmp=-1",
    "eq \"ß\"          \"ss\"         -> equal=false fold=false cmp=1",
    "buf zero len=0 cap=0 str=\"\"",
    "buf write len=11 str=\"hello world\"",
    "buf read n=5 err=<nil> p=\"hello\" rest=\" world\" len=6",
    "buf next3=\" wo\" rest=\"rld\"",
    "buf readbyte='r' err=<nil> rest=\"ld\"",
    "buf unread err=<nil> rest=\"rld\"",
    "buf drain n=3 err=<nil> empty=\"\"",
    "buf read-empty n=0 err=EOF",
    "buf read-nil n=0 err=<nil>",
    "buf readbyte-empty err=EOF",
    "trunc4 \"abcd\" len=4",
    "trunc0 \"\" len=0",
    "reset \"\" len=0",
    "readstring 0 -> \"line1\\n\" err=<nil>",
    "readstring 1 -> \"line2\\n\" err=<nil>",
    "readstring 2 -> \"line3\" err=EOF",
    "readfrom n=11 err=<nil> s=\"from-reader\"",
    "writeto m=11 err=<nil> out=\"from-reader\" src=\"\"",
    "buf mixed \"日!\\xff\" bytes=\"日!\\xff\"",
    "reader len=10 size=10",
    "reader read n=4 err=<nil> p=\"0123\" len=6",
    "reader seek off=2 err=<nil> len=8",
    "reader readat n=4 err=<nil> p=\"6789\"",
    "reader readat-short n=2 err=EOF p=\"89\"",
    "reader readat-past err=EOF",
    "reader readbyte='2' err=<nil>",
    "reader unread err=<nil>",
    "reader readrune='2' size=1 err=<nil>",
    "reader seek-neg err=bytes.Reader.Seek: negative position",
    "reader reset len=2 size=2",
];

// go: none — goish idiom: one comparison, printing the divergence when
//     it is one, so a FAIL says what it got and not just that it did.
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

#[goish::main]
fn main() {
    let mut failed: int = 0;
    let mut ln: int = 0;

    let bad: &[u8] = &[b'a', 0xff, b'b'];
    let badseq: &[u8] = &[0xe6, 0x97, 0xa5, 0xff, 0xe8, 0xaa, 0x9e];
    // 1
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!("runes bad=%q -> %q", b(bad), bytes::Runes(b(bad))),
    );
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!("runes badseq=%q -> %q", b(badseq), bytes::Runes(b(badseq))),
    );
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!(
            "tovalid bad=%q -> %q %q",
            b(bad),
            bytes::ToValidUTF8(b(bad), b(b"?")),
            bytes::ToValidUTF8(b(bad), b(b""))
        ),
    );
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!(
            "tovalid badseq=%q -> %q",
            b(badseq),
            bytes::ToValidUTF8(b(badseq), b(b"!"))
        ),
    );
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!(
            "map upper bad=%q -> %q",
            b(bad),
            bytes::Map(unicode::ToUpper, b(bad))
        ),
    );
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!(
            "map drop bad=%q -> %q",
            b(bad),
            bytes::Map(
                |r: rune| -> rune {
                    if r == 0xFFFD {
                        return -1;
                    }
                    return r;
                },
                b(bad)
            )
        ),
    );
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!(
            "case bad lower=%q upper=%q title=%q",
            bytes::ToLower(b(bad)),
            bytes::ToUpper(b(bad)),
            bytes::Title(b(bad))
        ),
    );
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!(
            "valid bad=%v badseq=%v good=%v",
            bytes::ContainsRune(b(bad), 0xFFFD),
            bytes::ContainsRune(b(badseq), 0xFFFD),
            bytes::ContainsRune(b("日本".as_bytes()), '本' as rune)
        ),
    );
    // 2
    let idx: [(&[u8], &[u8]); 7] = [
        (bad, &[0xff]),
        (bad, b"b"),
        (badseq, "日".as_bytes()),
        (badseq, &[0xff]),
        ("日本語".as_bytes(), "本".as_bytes()),
        (b"", b""),
        (b"abc", b""),
    ];
    for (x, sub) in idx.iter() {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "index %-12q %-8q -> idx=%-3d last=%-3d count=%d",
                b(x),
                b(sub),
                bytes::Index(b(x), b(sub)),
                bytes::LastIndex(b(x), b(sub)),
                bytes::Count(b(x), b(sub))
            ),
        );
    }
    let anys: [(&[u8], &[u8]); 5] = [
        ("日本語".as_bytes(), "本語".as_bytes()),
        (bad, b"ab"),
        (bad, "\u{fffd}".as_bytes()),
        (badseq, "語".as_bytes()),
        (b"abc", b""),
    ];
    for (x, ch) in anys.iter() {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "indexany %-12q %-10q -> any=%-3d lastany=%d",
                b(x),
                b(ch),
                bytes::IndexAny(b(x), b(ch)),
                bytes::LastIndexAny(b(x), b(ch))
            ),
        );
    }
    for r in [b'b' as rune, 0xFFFD, '日' as rune, 0x110000] {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "indexrune bad=%q r=%-9q -> %d  badseq -> %d",
                b(bad),
                r,
                bytes::IndexRune(b(bad), r),
                bytes::IndexRune(b(badseq), r)
            ),
        );
    }
    // 3
    let sp: [(&[u8], &[u8]); 6] = [
        (b"a,b,c", b","),
        (bad, b""),
        (badseq, b""),
        (b"", b","),
        (b"", b""),
        ("日本".as_bytes(), b""),
    ];
    for (x, sep) in sp.iter() {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "split %-14q %-4q -> %q  after=%q",
                b(x),
                b(sep),
                bytes::Split(b(x), b(sep)),
                bytes::SplitAfter(b(x), b(sep))
            ),
        );
    }
    for n in [-1 as int, 0, 1, 2, 10] {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "splitn n=%-3d -> %q  after=%q",
                n,
                bytes::SplitN(b(b"a,b,c,d"), b(b","), n),
                bytes::SplitAfterN(b(b"a,b,c,d"), b(b","), n)
            ),
        );
    }
    // 4
    let trims: [(&[u8], &[u8]); 5] = [
        (bad, b"ab"),
        (bad, "\u{fffd}".as_bytes()),
        (badseq, "日語".as_bytes()),
        (b"xxhixx", b"x"),
        (b"  hi  ", b""),
    ];
    for (x, cut) in trims.iter() {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "trim %-12q %-10q -> t=%-12q l=%-12q r=%-12q",
                b(x),
                b(cut),
                bytes::Trim(b(x), b(cut)),
                bytes::TrimLeft(b(x), b(cut)),
                bytes::TrimRight(b(x), b(cut))
            ),
        );
    }
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!(
            "trimspace bad=%q badseq=%q sp=%q",
            bytes::TrimSpace(b(bad)),
            bytes::TrimSpace(b(badseq)),
            bytes::TrimSpace(b(b" \t hi \n "))
        ),
    );
    let flds: [&[u8]; 5] = [bad, badseq, b"  a b  ", b"", b""];
    for x in flds.iter() {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("fields %-14q -> %q", b(x), bytes::Fields(b(x))),
        );
    }
    // 5
    let eqs: [(&[u8], &[u8]); 8] = [
        (b"", b""),
        (b"", b""),
        (b"", b""),
        (b"a", b"A"),
        (bad, bad),
        (bad, &[b'a', 0xfe, b'b']),
        (b"K", "\u{212a}".as_bytes()),
        ("ß".as_bytes(), b"ss"),
    ];
    for (x, y) in eqs.iter() {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "eq %-12q %-12q -> equal=%-5v fold=%-5v cmp=%d",
                b(x),
                b(y),
                bytes::Equal(b(x), b(y)),
                bytes::EqualFold(b(x), b(y)),
                bytes::Compare(b(x), b(y))
            ),
        );
    }
    // 6
    {
        let mut buf = bytes::Buffer::new();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "buf zero len=%d cap=%d str=%q",
                buf.Len(),
                buf.Cap(),
                buf.String()
            ),
        );
        buf.WriteString(s("hello world"));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("buf write len=%d str=%q", buf.Len(), buf.String()),
        );
        let mut p: slice<byte> = slice::__from_vec(alloc::vec![0u8; 5]);
        let (n, err) = buf.Read(&mut p);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "buf read n=%d err=%v p=%q rest=%q len=%d",
                n,
                err,
                {
                    let pv: &[u8] = &p;
                    b(&pv[..n as usize])
                },
                buf.String(),
                buf.Len()
            ),
        );
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("buf next3=%q rest=%q", buf.Next(3), buf.String()),
        );
        let (c, err) = buf.ReadByte();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "buf readbyte=%q err=%v rest=%q",
                c as rune,
                err,
                buf.String()
            ),
        );
        let err = buf.UnreadByte();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("buf unread err=%v rest=%q", err, buf.String()),
        );
        let mut rest: slice<byte> = slice::__from_vec(alloc::vec![0u8; 64]);
        let (n, err) = buf.Read(&mut rest);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("buf drain n=%d err=%v empty=%q", n, err, buf.String()),
        );
        let (n, err) = buf.Read(&mut rest);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("buf read-empty n=%d err=%v", n, err),
        );
        let mut nilp: slice<byte> = slice::__from_vec(alloc::vec![]);
        let (n, err) = buf.Read(&mut nilp);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("buf read-nil n=%d err=%v", n, err),
        );
        let (_, err) = buf.ReadByte();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("buf readbyte-empty err=%v", err),
        );
    }
    {
        let mut buf = bytes::Buffer::new();
        buf.WriteString(s("abcdefghij"));
        buf.Truncate(4);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("trunc4 %q len=%d", buf.String(), buf.Len()),
        );
        buf.Truncate(0);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("trunc0 %q len=%d", buf.String(), buf.Len()),
        );
        buf.WriteString(s("xyz"));
        buf.Reset();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("reset %q len=%d", buf.String(), buf.Len()),
        );
    }
    {
        let mut buf = bytes::Buffer::new();
        buf.WriteString(s("line1\nline2\nline3"));
        for i in 0..4i64 {
            let (line, err) = buf.ReadString(b'\n');
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("readstring %d -> %q err=%v", i, line, err),
            );
            if err != goish::errors::nil {
                break;
            }
        }
    }
    {
        let mut buf = bytes::Buffer::new();
        let mut src = bytes::NewReader(b(b"from-reader"));
        let (n, err) = buf.ReadFrom(&mut src);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("readfrom n=%d err=%v s=%q", n, err, buf.String()),
        );
        let mut out = bytes::Buffer::new();
        let (m, err) = buf.WriteTo(&mut out);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "writeto m=%d err=%v out=%q src=%q",
                m,
                err,
                out.String(),
                buf.String()
            ),
        );
    }
    {
        let mut buf = bytes::Buffer::new();
        buf.WriteRune('日' as rune);
        buf.WriteByte(b'!');
        buf.Write(b(&[0xff]));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("buf mixed %q bytes=%q", buf.String(), buf.Bytes()),
        );
    }
    // 7
    {
        let mut r = bytes::NewReader(b(b"0123456789"));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("reader len=%d size=%d", r.Len(), r.Size()),
        );
        let mut p: slice<byte> = slice::__from_vec(alloc::vec![0u8; 4]);
        let (n, err) = r.Read(&mut p);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "reader read n=%d err=%v p=%q len=%d",
                n,
                err,
                {
                    let pv: &[u8] = &p;
                    b(&pv[..n as usize])
                },
                r.Len()
            ),
        );
        let (off, err) = r.Seek(2, io::SeekStart);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("reader seek off=%d err=%v len=%d", off, err, r.Len()),
        );
        let (n, err) = r.ReadAt(&mut p, 6);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("reader readat n=%d err=%v p=%q", n, err, {
                let pv: &[u8] = &p;
                b(&pv[..n as usize])
            }),
        );
        let (n, err) = r.ReadAt(&mut p, 8);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("reader readat-short n=%d err=%v p=%q", n, err, {
                let pv: &[u8] = &p;
                b(&pv[..n as usize])
            }),
        );
        let (_, err) = r.ReadAt(&mut p, 20);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("reader readat-past err=%v", err),
        );
        let (c, err) = r.ReadByte();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("reader readbyte=%q err=%v", c as rune, err),
        );
        let err = r.UnreadByte();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("reader unread err=%v", err),
        );
        let (rr, size, err) = r.ReadRune();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("reader readrune=%q size=%d err=%v", rr, size, err),
        );
        let (_, err) = r.Seek(-1, io::SeekStart);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("reader seek-neg err=%v", err),
        );
        r.Reset(b(b"xy"));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("reader reset len=%d size=%d", r.Len(), r.Size()),
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
