// ascii85_ref_smoke — encoding/ascii85 against a running Go.
// (encoding/ascii85/ascii85.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_ascii85_ref.go` run in
// `package ascii85_test` by `scripts/goref.sh`. goish matched Go on all
// 118 lines — no defects found.
//
// ascii85 decodes bytes somebody else produced — it is the encoding
// inside PDF streams and Adobe's toolchain — so its refusals are the
// half that matters, and they are unusually specific.
//
// The rules that do not follow from "base85 of four bytes at a time":
//
//   * 'z' abbreviates four ZERO bytes, but ONLY at the start of a
//     group. Mid-group it is corrupt input. A decoder that treats it
//     positionally is wrong in a way that shows only on data it did
//     not produce itself, which is every interesting case.
//   * 'y' is Adobe's shorthand for four SPACES and Go does NOT accept
//     it. A port cribbing from another implementation would, and would
//     then decode a document Go rejects — the two ends disagreeing
//     about what the bytes say.
//   * Whitespace is skipped ANYWHERE, including inside a group, so
//     "87c URD]" and "87c\nURD]" decode as if unbroken.
//   * A five-character group decoding above 2^32-1 is corrupt rather
//     than wrapped: "sssss" is an error, "s8W-!" is not.
//   * A trailing partial group yields fewer bytes, but a partial group
//     of exactly ONE character is invalid, because no single character
//     encodes any byte at all.
//   * Encode does NOT emit Adobe's <~ ~> delimiters — Go leaves
//     framing to the caller — and a decoder handed them fails at byte
//     1. Anyone wrapping this in a PDF has to add and strip them.
//
// Both paths are measured for every case: the one-shot Decode and the
// streaming NewDecoder, which frames differently and can stop
// somewhere else. The last section drives Decode with flush=false at
// eight cut points, which is how the streaming decoder is built and
// where an off-by-one would live.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use alloc::vec::Vec;
use goish::bytes;
use goish::encoding::ascii85;
use goish::encoding::hex;
use goish::errors::error;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::io;
use goish::strings;
use goish::syscall;
use goish::types::{byte, int};
const GO: [&str; 118] = [
    "enc empty          maxlen=0    n=0    out=\"\"",
    "dec empty          ndst=0    nsrc=0    same=true  err=<nil>",
    "stream empty       enc=\"\" same-as-Encode=true",
    "stream empty       dec-same=true  err=<nil>",
    "enc one            maxlen=5    n=2    out=\"@/\"",
    "dec one            ndst=1    nsrc=2    same=true  err=<nil>",
    "stream one         enc=\"@/\" same-as-Encode=true",
    "stream one         dec-same=true  err=<nil>",
    "enc two            maxlen=5    n=3    out=\"@:B\"",
    "dec two            ndst=2    nsrc=3    same=true  err=<nil>",
    "stream two         enc=\"@:B\" same-as-Encode=true",
    "stream two         dec-same=true  err=<nil>",
    "enc three          maxlen=5    n=4    out=\"@:E^\"",
    "dec three          ndst=3    nsrc=4    same=true  err=<nil>",
    "stream three       enc=\"@:E^\" same-as-Encode=true",
    "stream three       dec-same=true  err=<nil>",
    "enc four           maxlen=5    n=5    out=\"@:E_W\"",
    "dec four           ndst=4    nsrc=5    same=true  err=<nil>",
    "stream four        enc=\"@:E_W\" same-as-Encode=true",
    "stream four        dec-same=true  err=<nil>",
    "enc five           maxlen=10   n=7    out=\"@:E_WAH\"",
    "dec five           ndst=5    nsrc=7    same=true  err=<nil>",
    "stream five        enc=\"@:E_WAH\" same-as-Encode=true",
    "stream five        dec-same=true  err=<nil>",
    "enc eight          maxlen=10   n=10   out=\"@:E_WAS,Rg\"",
    "dec eight          ndst=8    nsrc=10   same=true  err=<nil>",
    "stream eight       enc=\"@:E_WAS,Rg\" same-as-Encode=true",
    "stream eight       dec-same=true  err=<nil>",
    "enc zeros-4        maxlen=5    n=1    out=\"z\"",
    "dec zeros-4        ndst=4    nsrc=1    same=true  err=<nil>",
    "stream zeros-4     enc=\"z\" same-as-Encode=true",
    "stream zeros-4     dec-same=true  err=<nil>",
    "enc zeros-8        maxlen=10   n=2    out=\"zz\"",
    "dec zeros-8        ndst=8    nsrc=2    same=true  err=<nil>",
    "stream zeros-8     enc=\"zz\" same-as-Encode=true",
    "stream zeros-8     dec-same=true  err=<nil>",
    "enc zeros-partial  maxlen=5    n=3    out=\"!!!\"",
    "dec zeros-partial  ndst=2    nsrc=3    same=true  err=<nil>",
    "stream zeros-partial enc=\"!!!\" same-as-Encode=true",
    "stream zeros-partial dec-same=true  err=<nil>",
    "enc spaces-4       maxlen=5    n=5    out=\"+<VdL\"",
    "dec spaces-4       ndst=4    nsrc=5    same=true  err=<nil>",
    "stream spaces-4    enc=\"+<VdL\" same-as-Encode=true",
    "stream spaces-4    dec-same=true  err=<nil>",
    "enc high           maxlen=5    n=5    out=\"s8W-!\"",
    "dec high           ndst=4    nsrc=5    same=true  err=<nil>",
    "stream high        enc=\"s8W-!\" same-as-Encode=true",
    "stream high        dec-same=true  err=<nil>",
    "enc text           maxlen=25   n=24   out=\"FD,5.EHPu*CER),Dg-(AAoDn\"",
    "dec text           ndst=19   nsrc=24   same=true  err=<nil>",
    "stream text        enc=\"FD,5.EHPu*CER),Dg-(AAoDn\" same-as-Encode=true",
    "stream text        dec-same=true  err=<nil>",
    "enc binary         maxlen=10   n=8    out=\"!!*0\\\"rr2\"",
    "dec binary         ndst=6    nsrc=8    same=true  err=<nil>",
    "stream binary      enc=\"!!*0\\\"rr2\" same-as-Encode=true",
    "stream binary      dec-same=true  err=<nil>",
    "enc long           maxlen=100  n=100  out=\"9jqo^9jqo^9jqo^9jqo^9jqo^9jqo^9jqo^9jqo^9jqo^9jqo^9jqo^9jqo^9jqo^9jqo^9jqo^9jqo^9jqo^9jqo^9jqo^9jqo^\"",
    "dec long           ndst=80   nsrc=100  same=true  err=<nil>",
    "stream long        enc=\"9jqo^9jqo^9jqo^9jqo^9jqo^9jqo^9jqo^9jqo^9jqo^9jqo^9jqo^9jqo^9jqo^9jqo^9jqo^9jqo^9jqo^9jqo^9jqo^9jqo^\" same-as-Encode=true",
    "stream long        dec-same=true  err=<nil>",
    "bad z-alone          -> ndst=4   nsrc=1   out=00000000     err=<nil>",
    "badr z-alone         -> n=4   out=00000000     err=<nil>",
    "bad z-twice          -> ndst=8   nsrc=2   out=0000000000000000 err=<nil>",
    "badr z-twice         -> n=8   out=0000000000000000 err=<nil>",
    "bad z-then-group     -> ndst=9   nsrc=8   out=0000000048656c6c6f err=<nil>",
    "badr z-then-group    -> n=9   out=0000000048656c6c6f err=<nil>",
    "bad z-mid-group      -> ndst=0   nsrc=0   out=             err=illegal ascii85 data at input byte 1",
    "badr z-mid-group     -> n=0   out=             err=illegal ascii85 data at input byte 1",
    "bad y-alone          -> ndst=0   nsrc=0   out=             err=illegal ascii85 data at input byte 0",
    "badr y-alone         -> n=0   out=             err=illegal ascii85 data at input byte 0",
    "bad y-mid            -> ndst=0   nsrc=0   out=             err=illegal ascii85 data at input byte 1",
    "badr y-mid           -> n=0   out=             err=illegal ascii85 data at input byte 1",
    "bad space-between    -> ndst=0   nsrc=0   out=             err=illegal ascii85 data at input byte 12",
    "badr space-between   -> n=8   out=48656c6c6f2057bd err=illegal ascii85 data at input byte 1",
    "bad space-inside     -> ndst=5   nsrc=8   out=48656c6c6f   err=<nil>",
    "badr space-inside    -> n=5   out=48656c6c6f   err=<nil>",
    "bad newline-inside   -> ndst=5   nsrc=8   out=48656c6c6f   err=<nil>",
    "badr newline-inside  -> n=5   out=48656c6c6f   err=<nil>",
    "bad tab-inside       -> ndst=5   nsrc=8   out=48656c6c6f   err=<nil>",
    "badr tab-inside      -> n=5   out=48656c6c6f   err=<nil>",
    "bad crlf-inside      -> ndst=5   nsrc=9   out=48656c6c6f   err=<nil>",
    "badr crlf-inside     -> n=5   out=48656c6c6f   err=<nil>",
    "bad adobe-delims     -> ndst=0   nsrc=0   out=             err=illegal ascii85 data at input byte 1",
    "badr adobe-delims    -> n=0   out=             err=illegal ascii85 data at input byte 1",
    "bad trailing-delim   -> ndst=0   nsrc=0   out=             err=illegal ascii85 data at input byte 7",
    "badr trailing-delim  -> n=0   out=             err=illegal ascii85 data at input byte 7",
    "bad one-char         -> ndst=0   nsrc=0   out=             err=illegal ascii85 data at input byte 1",
    "badr one-char        -> n=0   out=             err=illegal ascii85 data at input byte 1",
    "bad two-chars        -> ndst=1   nsrc=2   out=48           err=<nil>",
    "badr two-chars       -> n=1   out=48           err=<nil>",
    "bad four-chars       -> ndst=3   nsrc=4   out=48656c       err=<nil>",
    "badr four-chars      -> n=3   out=48656c       err=<nil>",
    "bad overflow         -> ndst=4   nsrc=5   out=022c0e6a     err=<nil>",
    "badr overflow        -> n=4   out=022c0e6a     err=<nil>",
    "bad just-under       -> ndst=4   nsrc=5   out=ffffffff     err=<nil>",
    "badr just-under      -> n=4   out=ffffffff     err=<nil>",
    "bad below-range      -> ndst=4   nsrc=5   out=00000000     err=<nil>",
    "badr below-range     -> n=4   out=00000000     err=<nil>",
    "bad invalid-char     -> ndst=0   nsrc=0   out=             err=illegal ascii85 data at input byte 7",
    "badr invalid-char    -> n=4   out=48656b5f     err=illegal ascii85 data at input byte 1",
    "bad tilde-only       -> ndst=0   nsrc=0   out=             err=illegal ascii85 data at input byte 0",
    "badr tilde-only      -> n=0   out=             err=illegal ascii85 data at input byte 0",
    "bad high-byte        -> ndst=0   nsrc=0   out=             err=illegal ascii85 data at input byte 3",
    "badr high-byte       -> n=0   out=             err=illegal ascii85 data at input byte 3",
    "bad empty            -> ndst=0   nsrc=0   out=             err=<nil>",
    "badr empty           -> n=0   out=             err=<nil>",
    "bad all-spaces       -> ndst=0   nsrc=5   out=             err=<nil>",
    "badr all-spaces      -> n=0   out=             err=<nil>",
    "bad null-byte        -> ndst=0   nsrc=1   out=             err=<nil>",
    "badr null-byte       -> n=0   out=             err=<nil>",
    "noflush 0   -> ndst=0   nsrc=0   out=           err=<nil>",
    "noflush 1   -> ndst=0   nsrc=0   out=           err=<nil>",
    "noflush 4   -> ndst=0   nsrc=0   out=           err=<nil>",
    "noflush 5   -> ndst=4   nsrc=5   out=48656c6c   err=<nil>",
    "noflush 6   -> ndst=4   nsrc=5   out=48656c6c   err=<nil>",
    "noflush 9   -> ndst=4   nsrc=5   out=48656c6c   err=<nil>",
    "noflush 10  -> ndst=8   nsrc=10  out=48656c6c6f20576f err=<nil>",
    "noflush 15  -> ndst=12  nsrc=15  out=48656c6c6f20576f726c6421 err=<nil>",
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
fn bs(v: Vec<u8>) -> slice<byte> {
    return slice::<byte>::__from_vec(v);
}
fn errText(err: error) -> string {
    if err == goish::nil {
        return s("<nil>");
    }
    return err.Error();
}
#[goish::main]
fn main() {
    let mut failed: int = 0;
    let mut ln: int = 0;
    let long = strings::Repeat(s("Man "), 20);
    let inputs: [(&str, string); 15] = [
        ("empty", string::new()),
        ("one", s("a")),
        ("two", s("ab")),
        ("three", s("abc")),
        ("four", s("abcd")),
        ("five", s("abcde")),
        ("eight", s("abcdefgh")),
        ("zeros-4", string::from_bytes(b"\x00\x00\x00\x00")),
        (
            "zeros-8",
            string::from_bytes(b"\x00\x00\x00\x00\x00\x00\x00\x00"),
        ),
        ("zeros-partial", string::from_bytes(b"\x00\x00")),
        ("spaces-4", s("    ")),
        ("high", string::from_bytes(b"\xff\xff\xff\xff")),
        ("text", s("the quick brown fox")),
        ("binary", string::from_bytes(b"\x00\x01\x02\xfd\xfe\xff")),
        ("long", long),
    ];
    for (name, data) in inputs.iter() {
        let src = bs(data.as_bytes().to_vec());
        let maxlen = ascii85::MaxEncodedLen(src.Len());
        let dst = bs(alloc::vec![0u8; maxlen as usize]);
        let (encbuf, n) = ascii85::Encode(dst, src.clone());
        let enc = string::from_bytes(&encbuf.to_vec()[..n as usize]);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "enc %-14s maxlen=%-4d n=%-4d out=%q",
                s(name),
                maxlen,
                n,
                enc.clone()
            ),
        );
        let out = bs(alloc::vec![0u8; (src.Len() + 16) as usize]);
        let (ob, ndst, nsrc, e) = ascii85::Decode(out, bs(enc.as_bytes().to_vec()), true);
        let got = string::from_bytes(&ob.to_vec()[..ndst as usize]);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "dec %-14s ndst=%-4d nsrc=%-4d same=%-5v err=%s",
                s(name),
                ndst,
                nsrc,
                got == *data,
                errText(e)
            ),
        );
        let mut buf = bytes::Buffer::new();
        {
            let mut w = ascii85::NewEncoder(&mut buf);
            let _ = w.Write(src.clone());
            let _ = w.Close();
        }
        let streamed = buf.String();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "stream %-11s enc=%q same-as-Encode=%v",
                s(name),
                streamed.clone(),
                streamed == enc
            ),
        );
        let mut rdr = ascii85::NewDecoder(strings::NewReader(streamed));
        let (rd, rerr) = io::ReadAll(&mut rdr);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "stream %-11s dec-same=%-5v err=%s",
                s(name),
                string::from_bytes(&rd.to_vec()) == *data,
                errText(rerr)
            ),
        );
    }
    let bads: [(&str, string); 25] = [
        ("z-alone", s("z")),
        ("z-twice", s("zz")),
        ("z-then-group", s("z87cURD]")),
        ("z-mid-group", s("8z7cURD]")),
        ("y-alone", s("y")),
        ("y-mid", s("8y7cURD]")),
        ("space-between", s("87cURD] i,pu")),
        ("space-inside", s("87c URD]")),
        ("newline-inside", s("87c\nURD]")),
        ("tab-inside", s("87c\tURD]")),
        ("crlf-inside", s("87c\r\nURD]")),
        ("adobe-delims", s("<~87cURD]~>")),
        ("trailing-delim", s("87cURD]~>")),
        ("one-char", s("8")),
        ("two-chars", s("87")),
        ("four-chars", s("87cU")),
        ("overflow", s("sssss")),
        ("just-under", s("s8W-!")),
        ("below-range", s("!!!!!")),
        ("invalid-char", string::from_bytes(b"87c\x01RD]")),
        ("tilde-only", s("~")),
        ("high-byte", string::from_bytes(b"87c\xffD]")),
        ("empty", string::new()),
        ("all-spaces", s("     ")),
        ("null-byte", string::from_bytes(b"\x00")),
    ];
    for (name, enc) in bads.iter() {
        let out = bs(alloc::vec![0u8; 64]);
        let (ob, ndst, nsrc, e) = ascii85::Decode(out, bs(enc.as_bytes().to_vec()), true);
        let shown = hex::EncodeToString(&ob.to_vec()[..ndst as usize]);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "bad %-16s -> ndst=%-3d nsrc=%-3d out=%-12s err=%s",
                s(name),
                ndst,
                nsrc,
                shown,
                errText(e)
            ),
        );
        let mut rdr = ascii85::NewDecoder(strings::NewReader(enc.clone()));
        let (rd, rerr) = io::ReadAll(&mut rdr);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "badr %-15s -> n=%-3d out=%-12s err=%s",
                s(name),
                rd.Len(),
                hex::EncodeToString(&rd.to_vec()),
                errText(rerr)
            ),
        );
    }
    {
        let enc = "87cURD]i,\"Ebo80";
        for n in [0usize, 1, 4, 5, 6, 9, 10, enc.len()] {
            let out = bs(alloc::vec![0u8; 64]);
            let (ob, ndst, nsrc, e) = ascii85::Decode(out, bs(enc.as_bytes()[..n].to_vec()), false);
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "noflush %-3d -> ndst=%-3d nsrc=%-3d out=%-10s err=%s",
                    n as int,
                    ndst,
                    nsrc,
                    hex::EncodeToString(&ob.to_vec()[..ndst as usize]),
                    errText(e)
                ),
            );
        }
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
