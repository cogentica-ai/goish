// quotedprintable_ref_smoke — mime/quotedprintable against a running Go.
// (mime/quotedprintable/reader.go, mime/quotedprintable/writer.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_qp_ref.go` run in
// `package quotedprintable_test` by `scripts/goref.sh`. goish matched
// Go on all 78 lines — no defects found.
//
// This decoder is the one place in the mail path that turns arbitrary
// text back into arbitrary BYTES, and its input comes from whoever sent
// the message. What it accepts decides what every layer above it ever
// sees, so the interesting cases are the malformed ones.
//
// Go's reader is deliberately LENIENT in specific, enumerated ways — it
// has to be, because real mailers emit malformed quoted-printable
// constantly — and each leniency is a decision that cannot be derived
// from the RFC:
//
//   * "=" not followed by two hex digits is passed THROUGH as a literal
//     "=" rather than refused, so a message is not lost over one bad
//     byte. But not always: "=ZZ", "=4Z", "= 41" and a trailing "=4"
//     all survive, while "==" is a hard "unexpected EOF" and "abc=\r"
//     is "invalid hex byte 0x0d". Four recoveries and two refusals,
//     with no rule connecting them that a reader could guess.
//   * Trailing whitespace before a newline is STRIPPED, because
//     transports add it. "a   \n" and "a\n" therefore decode
//     identically — and "=20" does NOT, which is the whole reason the
//     encoding exists. A port that preserved the raw spaces would
//     produce different bytes for a message that hashed the same on
//     the way in.
//   * A bare CR, a lone LF and a CRLF all end a line the same way, and
//     a soft break ("=" then newline) joins lines producing no bytes.
//
// The writer half is pinned byte for byte, including the 76-character
// wrap — the cases at 75, 76 and 77 characters, and the one where an
// encoded byte straddles the boundary, are where an off-by-one lives.
//
// One result worth reading twice: the all-bytes round trip is
// same=FALSE. Encoding every byte 0x00..0xFF and decoding it back does
// NOT return the input, because the raw CR and LF in the middle are
// written literally and then normalised on the way in. That is Go's
// behaviour and it is correct for a LINE-oriented encoding — but a
// caller who assumed quoted-printable was binary-safe would be wrong,
// and Binary mode (also pinned) is the answer to that.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use alloc::vec::Vec;
use goish::errors::error;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::io;
use goish::mime::quotedprintable as qp;
use goish::strings;
use goish::syscall;
use goish::types::{byte, int};
const GO: [&str; 78] = [
    "dec empty                        in=\"\"                       -> out=\"\"                       err=<nil>",
    "dec plain                        in=\"hello world\"            -> out=\"hello world\"            err=<nil>",
    "dec hex-upper                    in=\"=41=42=43\"              -> out=\"ABC\"                    err=<nil>",
    "dec hex-lower                    in=\"=61=62=63\"              -> out=\"abc\"                    err=<nil>",
    "dec hex-mixed-case               in=\"=aB=Cd\"                 -> out=\"\\xab\\xcd\"               err=<nil>",
    "dec equals-eof                   in=\"abc=\"                   -> out=\"abc\"                    err=<nil>",
    "dec equals-one-hex-eof           in=\"abc=4\"                  -> out=\"abc=4\"                  err=<nil>",
    "dec equals-bad-hex               in=\"=ZZ\"                    -> out=\"=ZZ\"                    err=<nil>",
    "dec equals-half-bad              in=\"=4Z\"                    -> out=\"=4Z\"                    err=<nil>",
    "dec equals-space                 in=\"= 41\"                   -> out=\"= 41\"                   err=<nil>",
    "dec equals-equals                in=\"==\"                     -> out=\"\"                       err=unexpected EOF",
    "dec soft-break-lf                in=\"abc=\\ndef\"              -> out=\"abcdef\"                 err=<nil>",
    "dec soft-break-crlf              in=\"abc=\\r\\ndef\"            -> out=\"abcdef\"                 err=<nil>",
    "dec soft-break-eof               in=\"abc=\\n\"                 -> out=\"abc\"                    err=<nil>",
    "dec soft-break-cr                in=\"abc=\\rdef\"              -> out=\"abc\"                    err=quotedprintable: invalid hex byte 0x0d",
    "dec hard-break-lf                in=\"abc\\ndef\"               -> out=\"abc\\ndef\"               err=<nil>",
    "dec hard-break-crlf              in=\"abc\\r\\ndef\"             -> out=\"abc\\r\\ndef\"             err=<nil>",
    "dec hard-break-cr                in=\"abc\\rdef\"               -> out=\"abc\\rdef\"               err=<nil>",
    "dec trailing-space               in=\"abc   \\ndef\"            -> out=\"abc\\ndef\"               err=<nil>",
    "dec trailing-tab                 in=\"abc\\t\\t\\ndef\"           -> out=\"abc\\ndef\"               err=<nil>",
    "dec trailing-space-eof           in=\"abc   \"                 -> out=\"abc\"                    err=<nil>",
    "dec trailing-space-crlf          in=\"abc \\r\\ndef\"            -> out=\"abc\\r\\ndef\"             err=<nil>",
    "dec encoded-space-kept           in=\"abc=20\\ndef\"            -> out=\"abc \\ndef\"              err=<nil>",
    "dec nul                          in=\"=00\"                    -> out=\"\\x00\"                   err=<nil>",
    "dec high-byte                    in=\"=FF=FE\"                 -> out=\"\\xff\\xfe\"               err=<nil>",
    "dec raw-high-byte                in=\"café\"                   -> out=\"café\"                   err=<nil>",
    "dec crlf-only                    in=\"\\r\\n\"                   -> out=\"\\r\\n\"                   err=<nil>",
    "dec lf-only                      in=\"\\n\"                     -> out=\"\\n\"                     err=<nil>",
    "dec cr-only                      in=\"\\r\"                     -> out=\"\"                       err=<nil>",
    "dec many-blank-lines             in=\"a\\n\\n\\nb\"               -> out=\"a\\n\\n\\nb\"               err=<nil>",
    "dec long-line                    in=\"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\" -> out=\"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\" err=<nil>",
    "dec equals-newline-only          in=\"=\\n\"                    -> out=\"\"                       err=<nil>",
    "dec equals-at-line-end-then-eof  in=\"a=\\r\\n\"                 -> out=\"a\"                      err=<nil>",
    "dec underscore                   in=\"a_b\"                    -> out=\"a_b\"                    err=<nil>",
    "dec lowercase-hex-sep            in=\"=3d\"                    -> out=\"=\"                      err=<nil>",
    "dec1 \"abc=\\ndef\"    -> out=\"abcdef\"         err=<nil>",
    "dec1 \"a=41b\"        -> out=\"aAb\"            err=<nil>",
    "dec1 \"abc   \\ndef\"  -> out=\"abc\\ndef\"       err=<nil>",
    "dec1 \"=4\"           -> out=\"=4\"             err=<nil>",
    "enc empty              -> n=0    out=\"\"                                       werr=<nil> cerr=<nil>",
    "rt  empty              -> same=true  err=<nil>",
    "enc plain              -> n=11   out=\"hello world\"                            werr=<nil> cerr=<nil>",
    "rt  plain              -> same=true  err=<nil>",
    "enc equals             -> n=3    out=\"a=3Db\"                                  werr=<nil> cerr=<nil>",
    "rt  equals             -> same=true  err=<nil>",
    "enc high-bytes         -> n=5    out=\"caf=C3=A9\"                              werr=<nil> cerr=<nil>",
    "rt  high-bytes         -> same=true  err=<nil>",
    "enc nul                -> n=1    out=\"=00\"                                    werr=<nil> cerr=<nil>",
    "rt  nul                -> same=true  err=<nil>",
    "enc tab                -> n=3    out=\"a\\tb\"                                   werr=<nil> cerr=<nil>",
    "rt  tab                -> same=true  err=<nil>",
    "enc trailing-space     -> n=4    out=\"abc=20\"                                 werr=<nil> cerr=<nil>",
    "rt  trailing-space     -> same=true  err=<nil>",
    "enc trailing-tab       -> n=4    out=\"abc=09\"                                 werr=<nil> cerr=<nil>",
    "rt  trailing-tab       -> same=true  err=<nil>",
    "enc space-then-newline -> n=8    out=\"abc=20\\r\\nxyz\"                          werr=<nil> cerr=<nil>",
    "rt  space-then-newline -> same=false err=<nil>",
    "enc newline            -> n=3    out=\"a\\r\\nb\"                                 werr=<nil> cerr=<nil>",
    "rt  newline            -> same=false err=<nil>",
    "enc crlf               -> n=4    out=\"a\\r\\nb\"                                 werr=<nil> cerr=<nil>",
    "rt  crlf               -> same=true  err=<nil>",
    "enc cr                 -> n=3    out=\"a\\r\\nb\"                                 werr=<nil> cerr=<nil>",
    "rt  cr                 -> same=false err=<nil>",
    "enc exactly-75         -> n=75   out=\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\" werr=<nil> cerr=<nil>",
    "rt  exactly-75         -> same=true  err=<nil>",
    "enc exactly-76         -> n=76   out=\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=\\r\\na\" werr=<nil> cerr=<nil>",
    "rt  exactly-76         -> same=true  err=<nil>",
    "enc exactly-77         -> n=77   out=\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=\\r\\naa\" werr=<nil> cerr=<nil>",
    "rt  exactly-77         -> same=true  err=<nil>",
    "enc long               -> n=200  out=\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=\\r\\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=\\r\\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\" werr=<nil> cerr=<nil>",
    "rt  long               -> same=true  err=<nil>",
    "enc long-encoded       -> n=40   out=\"=FF=FF=FF=FF=FF=FF=FF=FF=FF=FF=FF=FF=FF=FF=FF=FF=FF=FF=FF=FF=FF=FF=FF=FF=FF=\\r\\n=FF=FF=FF=FF=FF=FF=FF=FF=FF=FF=FF=FF=FF=FF=FF\" werr=<nil> cerr=<nil>",
    "rt  long-encoded       -> same=true  err=<nil>",
    "enc boundary-encoded   -> n=75   out=\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=\\r\\n=FF\" werr=<nil> cerr=<nil>",
    "rt  boundary-encoded   -> same=true  err=<nil>",
    "enc all-bytes          -> n=256  out=\"=00=01=02=03=04=05=06=07=08=09\\r\\n=0B=0C\\r\\n=0E=0F=10=11=12=13=14=15=16=17=18=19=1A=1B=1C=1D=1E=1F !\\\"#$%&'()*+,-./01234=\\r\\n56789:;<=3D>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\\\]^_`abcdefghijklmnopqrstuvwxyz{|}=\\r\\n~=7F=80=81=82=83=84=85=86=87=88=89=8A=8B=8C=8D=8E=8F=90=91=92=93=94=95=96=\\r\\n=97=98=99=9A=9B=9C=9D=9E=9F=A0=A1=A2=A3=A4=A5=A6=A7=A8=A9=AA=AB=AC=AD=AE=AF=\\r\\n=B0=B1=B2=B3=B4=B5=B6=B7=B8=B9=BA=BB=BC=BD=BE=BF=C0=C1=C2=C3=C4=C5=C6=C7=C8=\\r\\n=C9=CA=CB=CC=CD=CE=CF=D0=D1=D2=D3=D4=D5=D6=D7=D8=D9=DA=DB=DC=DD=DE=DF=E0=E1=\\r\\n=E2=E3=E4=E5=E6=E7=E8=E9=EA=EB=EC=ED=EE=EF=F0=F1=F2=F3=F4=F5=F6=F7=F8=F9=FA=\\r\\n=FB=FC=FD=FE=FF\" werr=<nil> cerr=<nil>",
    "rt  all-bytes          -> same=false err=<nil>",
    "enc binary-200 -> len=206 out=\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
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
fn sb(b: &[u8]) -> string {
    return string::from_bytes(b);
}
fn errText(err: error) -> string {
    if err == goish::nil {
        return s("<nil>");
    }
    return err.Error();
}
// A Reader that hands back exactly one byte per call, so the decoder
// cannot depend on how the input happens to be chunked.
struct IterReader {
    s: Vec<u8>,
    i: usize,
}
impl io::Reader for IterReader {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        if self.i >= self.s.len() {
            return (0, io::EOF.into());
        }
        p[0] = self.s[self.i];
        self.i += 1;
        return (1, goish::nil.into());
    }
}
fn allBytes() -> Vec<u8> {
    let mut b: Vec<u8> = Vec::new();
    for i in 0..256usize {
        b.push(i as u8);
    }
    return b;
}
#[goish::main]
fn main() {
    let mut failed: int = 0;
    let mut ln: int = 0;
    let long200 = strings::Repeat(s("x"), 200);
    let a75 = strings::Repeat(s("a"), 75);
    let a76 = strings::Repeat(s("a"), 76);
    let a77 = strings::Repeat(s("a"), 77);
    let a200 = strings::Repeat(s("a"), 200);
    let ff40 = strings::Repeat(sb(b"\xff"), 40);
    let bound = strings::Repeat(s("a"), 74) + sb(b"\xff");
    let decs: [(&str, string); 35] = [
        ("empty", string::new()),
        ("plain", s("hello world")),
        ("hex-upper", s("=41=42=43")),
        ("hex-lower", s("=61=62=63")),
        ("hex-mixed-case", s("=aB=Cd")),
        ("equals-eof", s("abc=")),
        ("equals-one-hex-eof", s("abc=4")),
        ("equals-bad-hex", s("=ZZ")),
        ("equals-half-bad", s("=4Z")),
        ("equals-space", s("= 41")),
        ("equals-equals", s("==")),
        ("soft-break-lf", s("abc=\ndef")),
        ("soft-break-crlf", s("abc=\r\ndef")),
        ("soft-break-eof", s("abc=\n")),
        ("soft-break-cr", s("abc=\rdef")),
        ("hard-break-lf", s("abc\ndef")),
        ("hard-break-crlf", s("abc\r\ndef")),
        ("hard-break-cr", s("abc\rdef")),
        ("trailing-space", s("abc   \ndef")),
        ("trailing-tab", s("abc\t\t\ndef")),
        ("trailing-space-eof", s("abc   ")),
        ("trailing-space-crlf", s("abc \r\ndef")),
        ("encoded-space-kept", s("abc=20\ndef")),
        ("nul", s("=00")),
        ("high-byte", s("=FF=FE")),
        ("raw-high-byte", sb(b"caf\xc3\xa9")),
        ("crlf-only", s("\r\n")),
        ("lf-only", s("\n")),
        ("cr-only", s("\r")),
        ("many-blank-lines", s("a\n\n\nb")),
        ("long-line", long200.clone()),
        ("equals-newline-only", s("=\n")),
        ("equals-at-line-end-then-eof", s("a=\r\n")),
        ("underscore", s("a_b")),
        ("lowercase-hex-sep", s("=3d")),
    ];
    for (name, in_) in decs.iter() {
        let mut r = qp::NewReader(strings::NewReader(in_.clone()));
        let (out, err) = io::ReadAll(&mut r);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "dec %-28s in=%-24q -> out=%-24q err=%s",
                s(name),
                in_.clone(),
                string::from_bytes(&out.to_vec()),
                errText(err)
            ),
        );
    }
    for c in ["abc=\ndef", "a=41b", "abc   \ndef", "=4"] {
        let mut r = qp::NewReader(IterReader {
            s: c.as_bytes().to_vec(),
            i: 0,
        });
        let (out, err) = io::ReadAll(&mut r);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "dec1 %-14q -> out=%-16q err=%s",
                s(c),
                string::from_bytes(&out.to_vec()),
                errText(err)
            ),
        );
    }
    let encs: [(&str, string); 19] = [
        ("empty", string::new()),
        ("plain", s("hello world")),
        ("equals", s("a=b")),
        ("high-bytes", sb(b"caf\xc3\xa9")),
        ("nul", sb(b"\x00")),
        ("tab", s("a\tb")),
        ("trailing-space", s("abc ")),
        ("trailing-tab", s("abc\t")),
        ("space-then-newline", s("abc \nxyz")),
        ("newline", s("a\nb")),
        ("crlf", s("a\r\nb")),
        ("cr", s("a\rb")),
        ("exactly-75", a75),
        ("exactly-76", a76),
        ("exactly-77", a77),
        ("long", a200.clone()),
        ("long-encoded", ff40),
        ("boundary-encoded", bound),
        ("all-bytes", sb(&allBytes())),
    ];
    for (name, in_) in encs.iter() {
        let mut out = strings::Builder::new();
        let mut w = qp::NewWriter(&mut out);
        let (n, werr) = w.Write(slice::<byte>::__from_vec(in_.as_bytes().to_vec()));
        let cerr = w.Close();
        let got = out.String();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "enc %-18s -> n=%-4d out=%-40q werr=%s cerr=%s",
                s(name),
                n,
                got.clone(),
                errText(werr),
                errText(cerr)
            ),
        );
        let mut r = qp::NewReader(strings::NewReader(got));
        let (back, rerr) = io::ReadAll(&mut r);
        let same = string::from_bytes(&back.to_vec()) == in_.clone();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "rt  %-18s -> same=%-5v err=%s",
                s(name),
                same,
                errText(rerr)
            ),
        );
    }
    {
        let mut out = strings::Builder::new();
        let mut w = qp::NewWriter(&mut out);
        w.Binary = true;
        let _ = w.Write(slice::<byte>::__from_vec(a200.as_bytes().to_vec()));
        let _ = w.Close();
        let got = out.String();
        let head = string::from_bytes(&got.as_bytes()[..40]);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("enc binary-200 -> len=%d out=%q", got.Len(), head),
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
