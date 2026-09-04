// pem_ref_smoke — encoding/pem against a running Go.
// (encoding/pem/pem.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_pem_ref.go` run in
// `package pem_test` by `scripts/goref.sh`. goish matched Go on all 50
// lines — no defects found.
//
// encoding/pem decodes the wrapper around every certificate, key and
// CSR that arrives as text, so its refusals are the half that matters:
// PEM is a forgiving format read by unforgiving code, and the question
// worth asking is what Decode does with input that is ALMOST valid,
// because whatever it hands back is what gets parsed as a key.
//
// The properties pinned, and why each one is a decision rather than a
// detail:
//
//   * Decode returns the REST of the input alongside the block. A
//     caller that ignores `rest` silently accepts trailing data —
//     "trailing-junk" and "two-blocks" show precisely what it holds, so
//     a caller can tell "one block, clean" from "one block, and more".
//   * Leading data before the BEGIN line is SKIPPED, not refused. That
//     is how a PEM file with a human-readable preamble works, and it is
//     equally how anything at all can be prepended to a file that is
//     still accepted. Pinned so a port cannot drift stricter or looser
//     without the smoke saying so.
//   * A mismatched END line, a missing END, an unparseable body and a
//     header line without a colon each yield nil rather than a
//     half-built block — and the `rest` returned with that nil says
//     where the decoder gave up.
//   * Base64 with embedded spaces, CRLF line endings and blank lines
//     inside the body are each accepted or refused in Go's exact
//     pattern, none of which is guessable from the format description.
//   * On the encode side the line width is 64 base64 characters, and
//     the header ORDER is Proc-Type first and the rest sorted — a
//     stable order, so a re-encoded block is byte-identical rather than
//     merely equivalent.
//   * A header key containing a colon makes Encode fail and
//     EncodeToMemory return nothing at all, whereas a header VALUE
//     containing a newline is written out and silently breaks the
//     round trip. Two adjacent inputs, two different answers.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use alloc::vec::Vec;
use goish::encoding::hex;
use goish::encoding::pem;
use goish::fmt;
use goish::gomap::map;
use goish::goslice::slice;
use goish::gostring::string;
use goish::sort;
use goish::strings;
use goish::syscall;
use goish::types::{byte, int};
const GO: [&str; 50] = [
    "dec empty                  -> nil rest=\"\"",
    "dec good                   -> type=\"CERTIFICATE\"      hdrs=[] bytes=68656c6c6f2070656d20776f726c642068656c6c6f2070656d20776f726c64 rest=\"\"",
    "dec no-trailing-newline    -> type=\"CERTIFICATE\"      hdrs=[] bytes=68656c6c6f2070656d20776f726c642068656c6c6f2070656d20776f726c64 rest=\"\"",
    "dec crlf                   -> type=\"CERTIFICATE\"      hdrs=[] bytes=68656c6c6f2070656d20776f726c642068656c6c6f2070656d20776f726c64 rest=\"\"",
    "dec leading-text           -> type=\"CERTIFICATE\"      hdrs=[] bytes=68656c6c6f2070656d20776f726c642068656c6c6f2070656d20776f726c64 rest=\"\"",
    "dec leading-partial-begin  -> type=\"CERTIFICATE\"      hdrs=[] bytes=68656c6c6f2070656d20776f726c642068656c6c6f2070656d20776f726c64 rest=\"\"",
    "dec trailing-junk          -> type=\"CERTIFICATE\"      hdrs=[] bytes=68656c6c6f2070656d20776f726c642068656c6c6f2070656d20776f726c64 rest=\"trailing junk\\n\"",
    "dec two-blocks             -> type=\"CERTIFICATE\"      hdrs=[] bytes=68656c6c6f2070656d20776f726c642068656c6c6f2070656d20776f726c64 rest=\"-----BEGIN PRIVATE KEY-----\\naGVsbG8gcGVtIHdvcmxkIGhlbGxvIHBlbSB3b3JsZA==\\n-----END PRIVATE KEY-----\\n\"",
    "dec begin-only             -> nil rest=\"-----BEGIN CERTIFICATE-----\\n\"",
    "dec no-end                 -> nil rest=\"-----BEGIN CERTIFICATE-----\\naGVsbG8gcGVtIHdvcmxkIGhlbGxvIHBlbSB3b3JsZA==\\n\"",
    "dec mismatched-end         -> nil rest=\"-----BEGIN CERTIFICATE-----\\naGVsbG8gcGVtIHdvcmxkIGhlbGxvIHBlbSB3b3JsZA==\\n-----END PRIVATE KEY-----\\n\"",
    "dec empty-type             -> type=\"\"                 hdrs=[] bytes=68656c6c6f2070656d20776f726c642068656c6c6f2070656d20776f726c64 rest=\"\"",
    "dec empty-body             -> type=\"CERTIFICATE\"      hdrs=[] bytes= rest=\"\"",
    "dec bad-base64             -> nil rest=\"-----BEGIN CERTIFICATE-----\\n!!!not base64!!!\\n-----END CERTIFICATE-----\\n\"",
    "dec base64-wrong-pad       -> nil rest=\"-----BEGIN CERTIFICATE-----\\naGVsbG8\\n-----END CERTIFICATE-----\\n\"",
    "dec base64-spaces          -> type=\"CERTIFICATE\"      hdrs=[] bytes=68656c6c6f2070656d rest=\"\"",
    "dec wrapped-body           -> type=\"CERTIFICATE\"      hdrs=[] bytes=68656c6c6f2070656d20776f726c642068656c6c6f2070656d20776f726c64 rest=\"\"",
    "dec headers                -> type=\"RSA PRIVATE KEY\"  hdrs=[DEK-Info=\"AES-128-CBC,0123456789ABCDEF\" Proc-Type=\"4,ENCRYPTED\"] bytes=68656c6c6f2070656d20776f726c642068656c6c6f2070656d20776f726c64 rest=\"\"",
    "dec header-no-blank-line   -> type=\"CERTIFICATE\"      hdrs=[X-Thing=\"yes\"] bytes=68656c6c6f2070656d20776f726c642068656c6c6f2070656d20776f726c64 rest=\"\"",
    "dec header-no-colon        -> nil rest=\"-----BEGIN CERTIFICATE-----\\nnotaheader\\n\\naGVsbG8gcGVtIHdvcmxkIGhlbGxvIHBlbSB3b3JsZA==\\n-----END CERTIFICATE-----\\n\"",
    "dec header-empty-value     -> type=\"CERTIFICATE\"      hdrs=[X-Empty=\"\"] bytes=68656c6c6f2070656d20776f726c642068656c6c6f2070656d20776f726c64 rest=\"\"",
    "dec header-spaces          -> type=\"CERTIFICATE\"      hdrs=[X-Sp=\"padded\"] bytes=68656c6c6f2070656d20776f726c642068656c6c6f2070656d20776f726c64 rest=\"\"",
    "dec type-with-spaces       -> type=\"EC PRIVATE KEY\"   hdrs=[] bytes=68656c6c6f2070656d20776f726c642068656c6c6f2070656d20776f726c64 rest=\"\"",
    "dec type-lowercase         -> type=\"certificate\"      hdrs=[] bytes=68656c6c6f2070656d20776f726c642068656c6c6f2070656d20776f726c64 rest=\"\"",
    "dec begin-no-dashes        -> nil rest=\"BEGIN CERTIFICATE\\naGVsbG8gcGVtIHdvcmxkIGhlbGxvIHBlbSB3b3JsZA==\\nEND CERTIFICATE\\n\"",
    "dec extra-dashes           -> nil rest=\"------BEGIN CERTIFICATE------\\naGVsbG8gcGVtIHdvcmxkIGhlbGxvIHBlbSB3b3JsZA==\\n------END CERTIFICATE------\\n\"",
    "dec end-inline             -> nil rest=\"-----BEGIN CERTIFICATE-----\\naGVsbG8gcGVtIHdvcmxkIGhlbGxvIHBlbSB3b3JsZA==-----END CERTIFICATE-----\\n\"",
    "dec blank-lines-inside     -> type=\"CERTIFICATE\"      hdrs=[] bytes=68656c6c6f2070656d20776f726c642068656c6c6f2070656d20776f726c64 rest=\"\"",
    "dec only-end               -> nil rest=\"-----END CERTIFICATE-----\\n\"",
    "dec nested-begin           -> type=\"B\"                hdrs=[] bytes=68656c6c6f2070656d20776f726c642068656c6c6f2070656d20776f726c64 rest=\"\"",
    "enc plain          -> \"-----BEGIN CERTIFICATE-----\\naGVsbG8gcGVtIHdvcmxk\\n-----END CERTIFICATE-----\\n\"",
    "rt  plain          -> type=\"CERTIFICATE\"      same=true nhdr=0 rest=\"\"",
    "enc empty-bytes    -> \"-----BEGIN CERTIFICATE-----\\n-----END CERTIFICATE-----\\n\"",
    "rt  empty-bytes    -> type=\"CERTIFICATE\"      same=true nhdr=0 rest=\"\"",
    "enc empty-type     -> \"-----BEGIN -----\\neA==\\n-----END -----\\n\"",
    "rt  empty-type     -> type=\"\"                 same=true nhdr=0 rest=\"\"",
    "enc long           -> \"-----BEGIN CERTIFICATE-----\\nMDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3\\nODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1\\nNjc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5\\n-----END CERTIFICATE-----\\n\"",
    "rt  long           -> type=\"CERTIFICATE\"      same=true nhdr=0 rest=\"\"",
    "enc exactly-48     -> \"-----BEGIN CERTIFICATE-----\\nYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh\\n-----END CERTIFICATE-----\\n\"",
    "rt  exactly-48     -> type=\"CERTIFICATE\"      same=true nhdr=0 rest=\"\"",
    "enc exactly-49     -> \"-----BEGIN CERTIFICATE-----\\nYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh\\nYQ==\\n-----END CERTIFICATE-----\\n\"",
    "rt  exactly-49     -> type=\"CERTIFICATE\"      same=true nhdr=0 rest=\"\"",
    "enc binary         -> \"-----BEGIN KEY-----\\nAAEC/f7/\\n-----END KEY-----\\n\"",
    "rt  binary         -> type=\"KEY\"              same=true nhdr=0 rest=\"\"",
    "enc headers        -> \"-----BEGIN RSA PRIVATE KEY-----\\nProc-Type: 4,ENCRYPTED\\nA-First: 1\\nDEK-Info: AES-128-CBC,00\\n\\nc2VjcmV0\\n-----END RSA PRIVATE KEY-----\\n\"",
    "rt  headers        -> type=\"RSA PRIVATE KEY\"  same=true nhdr=3 rest=\"\"",
    "hdr \"map[X:a:b]\" -> \"-----BEGIN T-----\\nX: a:b\\n\\neA==\\n-----END T-----\\n\"",
    "hdr \"map[X:a\\nb]\" -> \"-----BEGIN T-----\\nX: a\\nb\\n\\neA==\\n-----END T-----\\n\"",
    "hdr \"map[X:bad:v]\" -> \"\"",
    "hdr \"map[X:]\"    -> \"-----BEGIN T-----\\nX: \\n\\neA==\\n-----END T-----\\n\"",
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
fn bs(x: &string) -> slice<byte> {
    return slice::<byte>::__from_vec(x.as_bytes().to_vec());
}
fn mk(typ: &str, hdrs: &str, b64: &str) -> string {
    let mut out = string::from("-----BEGIN ") + s(typ) + "-----\n";
    out = out + s(hdrs);
    out = out + s(b64) + "\n";
    out = out + "-----END " + s(typ) + "-----\n";
    return out;
}
#[goish::main]
fn main() {
    let mut failed: int = 0;
    let mut ln: int = 0;
    let body = "aGVsbG8gcGVtIHdvcmxkIGhlbGxvIHBlbSB3b3JsZA==";
    let good = mk("CERTIFICATE", "", body);
    let cases: [(&str, string); 30] = [
        ("empty", string::new()),
        ("good", good.clone()),
        (
            "no-trailing-newline",
            strings::TrimSuffix(good.clone(), s("\n")),
        ),
        (
            "crlf",
            strings::ReplaceAll(good.clone(), s("\n"), s("\r\n")),
        ),
        (
            "leading-text",
            string::from("hello\nworld\n") + good.clone(),
        ),
        (
            "leading-partial-begin",
            string::from("-----BEGIN\n") + good.clone(),
        ),
        ("trailing-junk", good.clone() + "trailing junk\n"),
        ("two-blocks", good.clone() + mk("PRIVATE KEY", "", body)),
        ("begin-only", s("-----BEGIN CERTIFICATE-----\n")),
        (
            "no-end",
            string::from("-----BEGIN CERTIFICATE-----\n") + s(body) + "\n",
        ),
        (
            "mismatched-end",
            string::from("-----BEGIN CERTIFICATE-----\n")
                + s(body)
                + "\n-----END PRIVATE KEY-----\n",
        ),
        ("empty-type", mk("", "", body)),
        ("empty-body", mk("CERTIFICATE", "", "")),
        ("bad-base64", mk("CERTIFICATE", "", "!!!not base64!!!")),
        ("base64-wrong-pad", mk("CERTIFICATE", "", "aGVsbG8")),
        ("base64-spaces", mk("CERTIFICATE", "", "aGVs bG8g cGVt")),
        (
            "wrapped-body",
            mk(
                "CERTIFICATE",
                "",
                "aGVsbG8gcGVt\nIHdvcmxkIGhl\nbGxvIHBlbSB3\nb3JsZA==",
            ),
        ),
        (
            "headers",
            mk(
                "RSA PRIVATE KEY",
                "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0123456789ABCDEF\n\n",
                body,
            ),
        ),
        (
            "header-no-blank-line",
            mk("CERTIFICATE", "X-Thing: yes\n", body),
        ),
        ("header-no-colon", mk("CERTIFICATE", "notaheader\n\n", body)),
        (
            "header-empty-value",
            mk("CERTIFICATE", "X-Empty:\n\n", body),
        ),
        (
            "header-spaces",
            mk("CERTIFICATE", "X-Sp :  padded  \n\n", body),
        ),
        ("type-with-spaces", mk("EC PRIVATE KEY", "", body)),
        ("type-lowercase", mk("certificate", "", body)),
        (
            "begin-no-dashes",
            string::from("BEGIN CERTIFICATE\n") + s(body) + "\nEND CERTIFICATE\n",
        ),
        (
            "extra-dashes",
            string::from("------BEGIN CERTIFICATE------\n")
                + s(body)
                + "\n------END CERTIFICATE------\n",
        ),
        (
            "end-inline",
            string::from("-----BEGIN CERTIFICATE-----\n") + s(body) + "-----END CERTIFICATE-----\n",
        ),
        (
            "blank-lines-inside",
            string::from("-----BEGIN CERTIFICATE-----\n\n")
                + s(body)
                + "\n\n-----END CERTIFICATE-----\n",
        ),
        ("only-end", s("-----END CERTIFICATE-----\n")),
        (
            "nested-begin",
            string::from("-----BEGIN A-----\n-----BEGIN B-----\n")
                + s(body)
                + "\n-----END B-----\n",
        ),
    ];
    for (name, data) in cases.iter() {
        let (b, rest) = pem::Decode(bs(data));
        let b = match b {
            None => {
                chk(
                    &mut failed,
                    &mut ln,
                    fmt::Sprintf!(
                        "dec %-22s -> nil rest=%q",
                        s(name),
                        string::from_bytes(&rest.to_vec())
                    ),
                );
                continue;
            }
            Some(b) => b,
        };
        let mut keys: Vec<string> = Vec::new();
        for (k, _) in b.Headers.__iter() {
            keys.push(k.clone());
        }
        let mut ks = slice::<string>::__from_vec(keys);
        sort::Strings(&mut ks);
        let mut hs: Vec<string> = Vec::new();
        for i in 0..ks.Len() {
            let k = ks[i].clone();
            hs.push(fmt::Sprintf!(
                "%s=%q",
                k.clone(),
                b.Headers.Get(k.clone()).0
            ));
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "dec %-22s -> type=%-18q hdrs=[%s] bytes=%s rest=%q",
                s(name),
                b.Type.clone(),
                strings::Join(slice::<string>::__from_vec(hs), s(" ")),
                hex::EncodeToString(&b.Bytes.to_vec()),
                string::from_bytes(&rest.to_vec())
            ),
        );
    }
    let mut encs: Vec<(&str, pem::Block)> = Vec::new();
    let mkb = |t: &str, by: slice<byte>| -> pem::Block {
        let mut b = pem::Block {
            Type: string::new(),
            Headers: map::<string, string>::new(),
            Bytes: slice::<byte>::__from_vec(Vec::new()),
        };
        b.Type = s(t);
        b.Bytes = by;
        return b;
    };
    encs.push(("plain", mkb("CERTIFICATE", bs(&s("hello pem world")))));
    encs.push((
        "empty-bytes",
        mkb("CERTIFICATE", slice::<byte>::__from_vec(Vec::new())),
    ));
    encs.push(("empty-type", mkb("", bs(&s("x")))));
    encs.push((
        "long",
        mkb("CERTIFICATE", bs(&strings::Repeat(s("0123456789"), 12))),
    ));
    encs.push((
        "exactly-48",
        mkb("CERTIFICATE", bs(&strings::Repeat(s("a"), 48))),
    ));
    encs.push((
        "exactly-49",
        mkb("CERTIFICATE", bs(&strings::Repeat(s("a"), 49))),
    ));
    encs.push((
        "binary",
        mkb(
            "KEY",
            slice::<byte>::__from_vec(alloc::vec![0u8, 1, 2, 0xfd, 0xfe, 0xff]),
        ),
    ));
    {
        let mut b = mkb("RSA PRIVATE KEY", bs(&s("secret")));
        let mut h: map<string, string> = map::<string, string>::new();
        h.Set(s("Proc-Type"), s("4,ENCRYPTED"));
        h.Set(s("DEK-Info"), s("AES-128-CBC,00"));
        h.Set(s("A-First"), s("1"));
        b.Headers = h;
        encs.push(("headers", b));
    }
    for (name, blk) in encs.iter() {
        let out = pem::EncodeToMemory(blk);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "enc %-14s -> %q",
                s(name),
                string::from_bytes(&out.to_vec())
            ),
        );
        let (b, rest) = pem::Decode(out);
        let b = match b {
            None => {
                chk(
                    &mut failed,
                    &mut ln,
                    fmt::Sprintf!(
                        "rt  %-14s -> nil rest=%q",
                        s(name),
                        string::from_bytes(&rest.to_vec())
                    ),
                );
                continue;
            }
            Some(b) => b,
        };
        let same = string::from_bytes(&b.Bytes.to_vec()) == string::from_bytes(&blk.Bytes.to_vec());
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "rt  %-14s -> type=%-18q same=%v nhdr=%d rest=%q",
                s(name),
                b.Type.clone(),
                same,
                b.Headers.Len(),
                string::from_bytes(&rest.to_vec())
            ),
        );
    }
    let hdrs: [(&str, &str, &str); 4] = [
        ("X", "a:b", "map[X:a:b]"),
        ("X", "a\nb", "map[X:a\nb]"),
        ("X:bad", "v", "map[X:bad:v]"),
        ("X", "", "map[X:]"),
    ];
    for (k, v, shown) in hdrs.iter() {
        let mut b = pem::Block {
            Type: string::new(),
            Headers: map::<string, string>::new(),
            Bytes: slice::<byte>::__from_vec(Vec::new()),
        };
        b.Type = s("T");
        let mut h: map<string, string> = map::<string, string>::new();
        h.Set(s(k), s(v));
        b.Headers = h;
        b.Bytes = bs(&s("x"));
        let out = pem::EncodeToMemory(&b);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "hdr %-12q -> %q",
                s(shown),
                string::from_bytes(&out.to_vec())
            ),
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
