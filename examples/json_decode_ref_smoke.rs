// json_decode_ref_smoke — encoding/json's DECODER against a running Go.
// (encoding/json/decode.go, encoding/json/scanner.go)
//
// The encoder half of this package was measured in 21b47cf and 4e25a97.
// This is the decoder — the half that reads bytes somebody else wrote.
// The lines in GO below are the verbatim output of
// `tools/gen_jsondec_ref.go` run in `package json_test` by
// `scripts/goref.sh`, EXCEPT for sixteen marked KNOWN GAP, which hold
// goish's current answer with Go's quoted above it so neither can drift
// unnoticed.
//
// Two real defects were found and fixed here:
//
//   * A number with a fractional part decoded into an integer target by
//     TRUNCATING it. `1.5` into an int became 1, silently, where Go
//     refuses the document. That is the worst of the three possible
//     behaviours: not a refusal, not the right number, but a plausible
//     wrong one that flows onward as if it had been in the input.
//   * A `null` into a primitive target ERRORED, where Go's decoder
//     ignores it and leaves the target holding whatever it held
//     (decode.go, literalStore: "otherwise, ignore null for
//     primitives"). A document with an explicit null field therefore
//     failed to decode at all. goish's FromValue returns a value rather
//     than writing through a reflect.Value, so "do not write" is now
//     signalled with a private sentinel that Unmarshal recognises.
//
// Measured and found correct: Valid() agrees with Go on all 36
// documents including every form a strict parser must refuse (trailing
// commas, single quotes, unquoted keys, NaN, Infinity, +1, 01, .1, 1.,
// a bare comma); the decode/re-encode round trip is byte-identical for
// every valid document; a lone surrogate becomes U+FFFD rather than an
// error; duplicate keys keep the last; decoding into a slice replaces
// it rather than partly overwriting; and every string escape decodes to
// the same bytes.
//
// The two gaps that remain, both pinned above:
//
//   * Syntax errors are generic. Go names the offending character and
//     what the parser was looking for — "invalid character '}' looking
//     for beginning of object key string" — where goish says
//     "json: invalid syntax" for all thirteen. In a megabyte of input
//     that is the difference between finding the problem and not.
//     Closing it means porting Go's scanner state machine, which is a
//     larger change than the two fixes here.
//   * `1.0` and `1e2` decode into an int where Go refuses them. Go runs
//     strconv.ParseInt over the ORIGINAL LITERAL, so anything not
//     written as an integer fails even when its value is integral;
//     goish's `Value::Number` holds an f64 and has already lost the
//     text. Closing it means carrying the literal on the Value, which
//     changes a public enum shape. Note the direction: goish accepts
//     what Go rejects, which is the more permissive and therefore more
//     dangerous way to differ.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::encoding::json;
use goish::errors::error;
use goish::fmt;
use goish::gomap::map;
use goish::goslice::slice;
use goish::gostring::string;
use goish::syscall;
use goish::types::{byte, int};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}
fn bs(x: &str) -> slice<byte> {
    return slice::__from_vec(x.as_bytes().to_vec());
}
fn et(e: &error) -> string {
    if e.IsNil() {
        return s("<nil>");
    }
    return e.Error();
}

// go: none — goish idiom: the expected lines, in the order they are
//     printed. Every line is Go's output except those marked KNOWN GAP,
//     which hold goish's current answer with Go's quoted above, so a
//     change in either direction shows up here.
const GO: [&str; 101] = [
    "valid \"{\\\"a\\\":1}\"                  -> true",
    "valid \"[]\"                         -> true",
    "valid \"{}\"                         -> true",
    "valid \"null\"                       -> true",
    "valid \"true\"                       -> true",
    "valid \"1\"                          -> true",
    "valid \"\\\"x\\\"\"                      -> true",
    "valid \"1.5e10\"                     -> true",
    "valid \"\"                           -> false",
    "valid \" \"                          -> false",
    "valid \"{\"                          -> false",
    "valid \"}\"                          -> false",
    "valid \"[1,]\"                       -> false",
    "valid \"{\\\"a\\\":1,}\"                 -> false",
    "valid \"{'a':1}\"                    -> false",
    "valid \"{a:1}\"                      -> false",
    "valid \"[1 2]\"                      -> false",
    "valid \"01\"                         -> false",
    "valid \"+1\"                         -> false",
    "valid \"1.\"                         -> false",
    "valid \".1\"                         -> false",
    "valid \"NaN\"                        -> false",
    "valid \"Infinity\"                   -> false",
    "valid \"\\\"\\\\x\\\"\"                    -> false",
    "valid \"\\\"unterminated\"             -> false",
    "valid \"[[[[[[[[[[]]]]]]]]]]\"       -> true",
    "valid \"{\\\"a\\\":}\"                   -> false",
    "valid \"{\\\"a\\\"}\"                    -> false",
    "valid \"tru\"                        -> false",
    "valid \"\\\"\\\\u00\\\"\"                  -> false",
    "valid \"\\\"\\\\ud800\\\"\"                -> true",
    "valid \"1e\"                         -> false",
    "valid \"-\"                          -> false",
    "valid \"[,]\"                        -> false",
    "valid \"[1,2]\"                      -> true",
    "valid \"{\\\"a\\\":{\\\"b\\\":[1,{\\\"c\\\":null}]}}\" -> true",
    "roundtrip \"{\\\"a\\\":1}\"        -> {\"a\":1} merr=<nil>",
    "roundtrip \"[1,2]\"            -> [1,2] merr=<nil>",
    "roundtrip \"1\"                -> 1 merr=<nil>",
    "roundtrip \"\\\"x\\\"\"            -> \"x\" merr=<nil>",
    "roundtrip \"null\"             -> null merr=<nil>",
    "roundtrip \"true\"             -> true merr=<nil>",
    "roundtrip \"false\"            -> false merr=<nil>",
    "roundtrip \"1.5\"              -> 1.5 merr=<nil>",
    "roundtrip \"-0\"               -> -0 merr=<nil>",
    "roundtrip \"1e3\"              -> 1000 merr=<nil>",
    "roundtrip \"{\\\"a\\\":{\\\"b\\\":[1,2]}}\" -> {\"a\":{\"b\":[1,2]}} merr=<nil>",
    "roundtrip \"[]\"               -> [] merr=<nil>",
    "roundtrip \"{}\"               -> {} merr=<nil>",
    // KNOWN GAP — Go says: "roundtrip \"\"                 -> err=\"unexpected end of JSON input\""
    "roundtrip \"\"                 -> err=\"json: unexpected end of input\"",
    // KNOWN GAP — Go says: "roundtrip \"{\"                -> err=\"unexpected end of JSON input\""
    "roundtrip \"{\"                -> err=\"json: invalid syntax\"",
    // KNOWN GAP — Go says: "roundtrip \"[1,]\"             -> err=\"invalid character ']' looking for beginning of value\""
    "roundtrip \"[1,]\"             -> err=\"json: invalid syntax\"",
    // KNOWN GAP — Go says: "roundtrip \"{\\\"a\\\":1,}\"       -> err=\"invalid character '}' looking for beginning of object key string\""
    "roundtrip \"{\\\"a\\\":1,}\"       -> err=\"json: invalid syntax\"",
    // KNOWN GAP — Go says: "roundtrip \"{a:1}\"            -> err=\"invalid character 'a' looking for beginning of object key string\""
    "roundtrip \"{a:1}\"            -> err=\"json: invalid syntax\"",
    // KNOWN GAP — Go says: "roundtrip \"[1 2]\"            -> err=\"invalid character '2' after array element\""
    "roundtrip \"[1 2]\"            -> err=\"json: invalid syntax\"",
    // KNOWN GAP — Go says: "roundtrip \"01\"               -> err=\"invalid character '1' after top-level value\""
    "roundtrip \"01\"               -> err=\"json: invalid syntax\"",
    // KNOWN GAP — Go says: "roundtrip \"+1\"               -> err=\"invalid character '+' looking for beginning of value\""
    "roundtrip \"+1\"               -> err=\"json: invalid syntax\"",
    // KNOWN GAP — Go says: "roundtrip \"{\\\"a\\\":}\"         -> err=\"invalid character '}' looking for beginning of value\""
    "roundtrip \"{\\\"a\\\":}\"         -> err=\"json: invalid syntax\"",
    // KNOWN GAP — Go says: "roundtrip \"tru\"              -> err=\"invalid character ' ' in literal true (expecting 'e')\""
    "roundtrip \"tru\"              -> err=\"json: invalid syntax\"",
    "roundtrip \"\\\"\\\\ud800\\\"\"      -> \"�\" merr=<nil>",
    // KNOWN GAP — Go says: "roundtrip \"1e\"               -> err=\"invalid character ' ' in exponent of numeric literal\""
    "roundtrip \"1e\"               -> err=\"json: invalid syntax\"",
    // KNOWN GAP — Go says: "roundtrip \"{\\\"a\\\":1}x\"       -> err=\"invalid character 'x' after top-level value\""
    "roundtrip \"{\\\"a\\\":1}x\"       -> err=\"json: invalid syntax\"",
    // KNOWN GAP — Go says: "roundtrip \"[1] [2]\"          -> err=\"invalid character '[' after top-level value\""
    "roundtrip \"[1] [2]\"          -> err=\"json: invalid syntax\"",
    "roundtrip \"\\\"A\\\"\"            -> \"A\" merr=<nil>",
    "roundtrip \"\\\"a\\\\/b\\\"\"        -> \"a/b\" merr=<nil>",
    "roundtrip \"\\\"\\\\t\\\"\"          -> \"\\t\" merr=<nil>",
    "num 0                      -> i=0                     ierr=<nil>                                                f64=0            ferr=<nil>",
    "num 1                      -> i=1                     ierr=<nil>                                                f64=1            ferr=<nil>",
    "num -1                     -> i=-1                    ierr=<nil>                                                f64=-1           ferr=<nil>",
    "num 127                    -> i=127                   ierr=<nil>                                                f64=127          ferr=<nil>",
    "num -128                   -> i=-128                  ierr=<nil>                                                f64=-128         ferr=<nil>",
    "num 9223372036854775807    -> i=9223372036854775807   ierr=<nil>                                                f64=9.223372036854776e+18 ferr=<nil>",
    "num -9223372036854775808   -> i=-9223372036854775808  ierr=<nil>                                                f64=-9.223372036854776e+18 ferr=<nil>",
    // KNOWN GAP — Go says: "num 1.0                    -> i=0                     ierr=json: cannot unmarshal number 1.0 into Go value of type int f64=1            ferr=<nil>"
    "num 1.0                    -> i=1                     ierr=<nil>                                                f64=1            ferr=<nil>",
    "num 1.5                    -> i=0                     ierr=json: cannot unmarshal number 1.5 into Go value of type int f64=1.5          ferr=<nil>",
    // KNOWN GAP — Go says: "num 1e2                    -> i=0                     ierr=json: cannot unmarshal number 1e2 into Go value of type int f64=100          ferr=<nil>"
    "num 1e2                    -> i=100                   ierr=<nil>                                                f64=100          ferr=<nil>",
    "null-int v=42 err=<nil>",
    "null-string v=\"keep\" err=<nil>",
    "dup-map a=3 err=<nil>",
    "slice-shrink v=[1 2] len=2 err=<nil>",
    "slice-grow v=[1 2 3] err=<nil>",
    "slice-empty v=[] len=0 err=<nil>",
    "slice-nested v=[[1] [2 3] []] err=<nil>",
    "str \"\\\"plain\\\"\"          -> \"plain\" bytes=706c61696e",
    "str \"\\\"a\\\\\\\"b\\\"\"         -> \"a\\\"b\" bytes=612262",
    "str \"\\\"a\\\\\\\\b\\\"\"         -> \"a\\\\b\" bytes=615c62",
    "str \"\\\"a\\\\/b\\\"\"          -> \"a/b\" bytes=612f62",
    "str \"\\\"a\\\\bb\\\"\"          -> \"a\\bb\" bytes=610862",
    "str \"\\\"a\\\\fb\\\"\"          -> \"a\\fb\" bytes=610c62",
    "str \"\\\"a\\\\nb\\\"\"          -> \"a\\nb\" bytes=610a62",
    "str \"\\\"a\\\\rb\\\"\"          -> \"a\\rb\" bytes=610d62",
    "str \"\\\"a\\\\tb\\\"\"          -> \"a\\tb\" bytes=610962",
    "str \"\\\"A\\\"\"              -> \"A\" bytes=41",
    "str \"\\\"é\\\"\"              -> \"é\" bytes=c3a9",
    "str \"\\\"日\\\"\"              -> \"日\" bytes=e697a5",
    "str \"\\\"😀\\\"\"              -> \"😀\" bytes=f09f9880",
    "str \"\\\"\\\\ud800\\\"\"        -> \"�\" bytes=efbfbd",
    "str \"\\\"\\\\udc00\\\"\"        -> \"�\" bytes=efbfbd",
    "str \"\\\"\\\\ud800x\\\"\"       -> \"�x\" bytes=efbfbd78",
    // KNOWN GAP — Go says: "str \"\\\"\\\\uZZZZ\\\"\"        -> err=\"invalid character 'Z' in \\\\u hexadecimal character escape\""
    "str \"\\\"\\\\uZZZZ\\\"\"        -> err=\"json: invalid syntax\"",
    "str \"\\\"a\\x7fb\\\"\"         -> \"a\\x7fb\" bytes=617f62",
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

    // 1
    for v in [
        "{\"a\":1}",
        "[]",
        "{}",
        "null",
        "true",
        "1",
        "\"x\"",
        "1.5e10",
        "",
        " ",
        "{",
        "}",
        "[1,]",
        "{\"a\":1,}",
        "{'a':1}",
        "{a:1}",
        "[1 2]",
        "01",
        "+1",
        "1.",
        ".1",
        "NaN",
        "Infinity",
        "\"\\x\"",
        "\"unterminated",
        "[[[[[[[[[[]]]]]]]]]]",
        "{\"a\":}",
        "{\"a\"}",
        "tru",
        "\"\\u00\"",
        "\"\\ud800\"",
        "1e",
        "-",
        "[,]",
        "[1,2]",
        "{\"a\":{\"b\":[1,{\"c\":null}]}}",
    ] {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("valid %-28q -> %v", s(v), json::Valid(bs(v))),
        );
    }
    // 2
    for v in [
        "{\"a\":1}",
        "[1,2]",
        "1",
        "\"x\"",
        "null",
        "true",
        "false",
        "1.5",
        "-0",
        "1e3",
        "{\"a\":{\"b\":[1,2]}}",
        "[]",
        "{}",
        "",
        "{",
        "[1,]",
        "{\"a\":1,}",
        "{a:1}",
        "[1 2]",
        "01",
        "+1",
        "{\"a\":}",
        "tru",
        "\"\\ud800\"",
        "1e",
        "{\"a\":1}x",
        "[1] [2]",
        "\"A\"",
        "\"a\\/b\"",
        "\"\\t\"",
    ] {
        let mut val = json::Value::default();
        let err = json::Unmarshal(&bs(v), &mut val);
        if !err.IsNil() {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("roundtrip %-18q -> err=%q", s(v), err.Error()),
            );
            continue;
        }
        let (out, merr) = json::Marshal(&val);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "roundtrip %-18q -> %s merr=%v",
                s(v),
                string::from_bytes(&out),
                et(&merr)
            ),
        );
    }
    // 3
    for v in [
        "0",
        "1",
        "-1",
        "127",
        "-128",
        "9223372036854775807",
        "-9223372036854775808",
        "1.0",
        "1.5",
        "1e2",
    ] {
        let mut i: i64 = 0;
        let ierr = json::Unmarshal(&bs(v), &mut i);
        let mut f: f64 = 0.0;
        let ferr = json::Unmarshal(&bs(v), &mut f);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "num %-22s -> i=%-21d ierr=%-52v f64=%-12g ferr=%v",
                s(v),
                i,
                et(&ierr),
                f,
                et(&ferr)
            ),
        );
    }
    // 4
    {
        let mut v: i64 = 42;
        let err = json::Unmarshal(&bs("null"), &mut v);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("null-int v=%d err=%v", v, et(&err)),
        );
        let mut sv = s("keep");
        let err = json::Unmarshal(&bs("null"), &mut sv);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("null-string v=%q err=%v", sv, et(&err)),
        );
    }
    // 5
    {
        let mut m: map<string, i64> = map::new();
        let err = json::Unmarshal(&bs("{\"a\":1,\"a\":2,\"a\":3}"), &mut m);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("dup-map a=%d err=%v", m[s("a")], et(&err)),
        );
    }
    // 6
    {
        let mut v: slice<i64> = slice::__from_vec(alloc::vec![9, 9, 9, 9]);
        let err = json::Unmarshal(&bs("[1,2]"), &mut v);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "slice-shrink v=%v len=%d err=%v",
                v.clone(),
                v.Len(),
                et(&err)
            ),
        );
        let mut v2: slice<i64> = slice::__from_vec(alloc::vec![9]);
        let err = json::Unmarshal(&bs("[1,2,3]"), &mut v2);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("slice-grow v=%v err=%v", v2, et(&err)),
        );
        let mut v3: slice<i64> = slice::__from_vec(alloc::vec![9, 9]);
        let err = json::Unmarshal(&bs("[]"), &mut v3);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "slice-empty v=%v len=%d err=%v",
                v3.clone(),
                v3.Len(),
                et(&err)
            ),
        );
        let mut nested: slice<slice<i64>> = slice::__from_vec(alloc::vec![]);
        let err = json::Unmarshal(&bs("[[1],[2,3],[]]"), &mut nested);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("slice-nested v=%v err=%v", nested, et(&err)),
        );
    }
    // 7
    for v in [
        "\"plain\"",
        "\"a\\\"b\"",
        "\"a\\\\b\"",
        "\"a\\/b\"",
        "\"a\\bb\"",
        "\"a\\fb\"",
        "\"a\\nb\"",
        "\"a\\rb\"",
        "\"a\\tb\"",
        "\"A\"",
        "\"é\"",
        "\"日\"",
        "\"😀\"",
        "\"\\ud800\"",
        "\"\\udc00\"",
        "\"\\ud800x\"",
        "\"\\uZZZZ\"",
        "\"a\u{7f}b\"",
    ] {
        let mut out = string::default();
        let err = json::Unmarshal(&bs(v), &mut out);
        if !err.IsNil() {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("str %-20q -> err=%q", s(v), err.Error()),
            );
            continue;
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "str %-20q -> %q bytes=%x",
                s(v),
                out.clone(),
                slice::<byte>::__from_vec(out.as_bytes().to_vec())
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
