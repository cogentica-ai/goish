// hex_decodestring_ref_smoke — hex.DecodeString over bytes Go accepts
// as a `string` and a Rust `&str` cannot hold.
//
// Go's `hex.DecodeString(s string)` takes arbitrary bytes and its whole
// contract is to reject the ones that are not hex digits, naming the
// offender: `encoding/hex: invalid byte: U+00FF 'ÿ'`.
//
// goish's took a `&str`. goish's `string: AsRef<str>` TRUNCATES at the
// first invalid UTF-8 byte, so `DecodeString(s.as_ref())` silently
// decoded a PREFIX and returned NO error. Measured before the fix:
//
//     DecodeString("41\xff42")   goish  1 byte, err = nil
//                                Go     1 byte, err = invalid byte U+00FF
//
// The one caller in the tree is crypto/x509's PEM decryptor, reading
// the DEK-Info IV out of an attacker-supplied PEM header. Its
// `iv.Len() != blockSize` check catches most truncations — but not one
// where the valid prefix is exactly a full IV and the garbage follows,
// which Go rejects outright.
//
// 24 inputs from Go 1.25.5 (`scripts/goref.sh encoding/hex`), input,
// output and error text all dumped as hex so no row depends on a
// quoting decision on this side.
#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;

use goish::encoding::hex;
use goish::fmt;
use goish::gostring::string;
use goish::types::int;

static mut PASS: int = 0;
static mut FAIL: int = 0;

fn unhex(h: &str) -> alloc::vec::Vec<u8> {
    let b = h.as_bytes();
    let mut out = alloc::vec::Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i + 1 < b.len() {
        fn nib(c: u8) -> u8 {
            if c >= b'0' && c <= b'9' {
                return c - b'0';
            }
            return c - b'a' + 10;
        }
        out.push(nib(b[i]) * 16 + nib(b[i + 1]));
        i += 2;
    }
    return out;
}

fn drow(idx: int, inp: &'static str, want_out: &'static str, want_err: &'static str) {
    let s = string::from_bytes(&unhex(inp));
    let (b, err) = hex::DecodeString(s);
    let goterr = if err == goish::errors::nil {
        string::from_static("")
    } else {
        err.Error()
    };
    let got = hex::EncodeToString(&b) + string::from_static("|") + goterr;
    let want = string::from_bytes(want_out.as_bytes())
        + string::from_static("|")
        + string::from_bytes(want_err.as_bytes());
    unsafe {
        if got == want {
            PASS += 1;
        } else {
            FAIL += 1;
            fmt::Printf!(
                "FAIL %v in=%s\n     got  %s\n     want %s\n",
                idx,
                inp,
                got.clone(),
                want.clone()
            );
        }
    }
}

#[goish::main]
fn main() {
    drow(0, "", "", "");
    drow(1, "3431", "41", "");
    drow(2, "34313432", "4142", "");
    drow(3, "34", "", "encoding/hex: odd length hex string");
    drow(4, "343134", "41", "encoding/hex: odd length hex string");
    drow(5, "7a7a", "", "encoding/hex: invalid byte: U+007A 'z'");
    drow(6, "347a", "", "encoding/hex: invalid byte: U+007A 'z'");
    drow(7, "7a34", "", "encoding/hex: invalid byte: U+007A 'z'");
    drow(8, "3431ff3432", "41", "encoding/hex: invalid byte: U+00FF 'ÿ'");
    drow(9, "ff3431", "", "encoding/hex: invalid byte: U+00FF 'ÿ'");
    drow(10, "3431ff", "41", "encoding/hex: invalid byte: U+00FF 'ÿ'");
    drow(11, "ff", "", "encoding/hex: invalid byte: U+00FF 'ÿ'");
    drow(12, "3431c3", "41", "encoding/hex: invalid byte: U+00C3 'Ã'");
    drow(13, "eda0803431", "", "encoding/hex: invalid byte: U+00ED 'í'");
    drow(14, "616263646566", "abcdef", "");
    drow(15, "414243444546", "abcdef", "");
    drow(16, "30313233343536373839", "0123456789", "");
    drow(17, "3447", "", "encoding/hex: invalid byte: U+0047 'G'");
    drow(18, "4734", "", "encoding/hex: invalid byte: U+0047 'G'");
    drow(19, "2f30", "", "encoding/hex: invalid byte: U+002F '/'");
    drow(20, "3a30", "", "encoding/hex: invalid byte: U+003A ':'");
    drow(21, "4061", "", "encoding/hex: invalid byte: U+0040 '@'");
    drow(22, "6061", "", "encoding/hex: invalid byte: U+0060 '`'");
    drow(23, "6730", "", "encoding/hex: invalid byte: U+0067 'g'");
    unsafe {
        let (pass, fail) = (PASS, FAIL);
        if pass + fail != 24 {
            fmt::Printf!("FAIL ran %v rows, expected 24\n", pass + fail);
            FAIL += 1;
        }
        let fail = FAIL;
        fmt::Printf!("hex_decodestring_ref_smoke: %v checks, %v failed\n", pass + fail, fail);
        if fail > 0 {
            goish::syscall::Exit(1);
        }
    }
}
