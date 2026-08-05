// json_int_diff — differential sweep for json/v2 integer decoding.
//
// goish decoded a JSON number into an integer by parsing it as a float
// and truncating, so `1.5` silently became 1 and `1e30` became garbage.
// Go parses the RAW LITERAL as an integer: a number that is merely
// integer-VALUED (`1.0`, `1e2`) is "invalid syntax", and one past the
// target width is "value out of range". Found while porting
// typescript-go's internal/packagejson, whose Expected[int] records
// only whether the decode succeeded — so the truncation would have
// shown up as a field silently reported valid.
//
// Reference: `GOEXPERIMENT=jsonv2 go run tools/gen_jsonint_ref.go >
// examples/jsonint_ref.txt`, byte-compared here.
//
// The message TEXT is deliberately NOT compared. Go names its own types
// ("int32"), and goish cannot distinguish its `int` alias from `i64`,
// so the port names the Rust primitive. What is compared is the
// behaviour: which inputs are accepted, which rejected, with which of
// Go's two reasons, and the resulting value — across all seven widths,
// at every width boundary, so an off-by-one in a range check cannot
// hide.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::string::String as RustString;
use alloc::vec::Vec;

use goish::encoding::json::v2 as json2;
use goish::strings;
use goish::syscall;

const REF: &str = include_str!("jsonint_ref.txt");

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn push_usize(out: &mut RustString, v: usize) {
    let mut d = [0u8; 24];
    let mut i = 0;
    let mut n = v;
    loop {
        d[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
        if n == 0 {
            break;
        }
    }
    while i > 0 {
        i -= 1;
        out.push(d[i] as char);
    }
}

fn push_i128(out: &mut RustString, v: i128) {
    if v < 0 {
        out.push('-');
        push_usize(out, (-v) as usize);
    } else {
        push_usize(out, v as usize);
    }
}

/// The generator's `reason`.
fn reason(e: &goish::error) -> &'static str {
    if *e == goish::nil {
        return "-";
    }
    let text = e.Error();
    if strings::Contains(text.clone(), "value out of range") {
        "range"
    } else if strings::Contains(text, "invalid syntax") {
        "syntax"
    } else {
        "type"
    }
}

fn corpus() -> Vec<&'static str> {
    alloc::vec![
        "0", "1", "-1", "42", "-42",
        "1.0", "-1.0", "1e2", "1E2", "1e+2", "0.0", "-0.0",
        "1.5", "-2.5", "0.1",
        "127", "128", "-128", "-129",
        "255", "256",
        "32767", "32768", "-32768", "-32769",
        "65535", "65536",
        "2147483647", "2147483648", "-2147483648", "-2147483649",
        "4294967295", "4294967296",
        "9223372036854775807", "9223372036854775808",
        "-9223372036854775808", "-9223372036854775809",
        "1e30",
        "-1",
        "-0",
        "null", "true", "false", "\"7\"", "[]", "{}",
    ]
}

macro_rules! one {
    ($out:expr, $label:literal, $ty:ty, $doc:expr) => {{
        let mut v: $ty = 0;
        let e = json2::Unmarshal($doc.as_bytes(), &mut v, &[]);
        $out.push(' ');
        $out.push_str($label);
        $out.push('=');
        push_i128($out, v as i128);
        $out.push('/');
        $out.push_str(reason(&e));
    }};
}

#[goish::main]
fn main() {
    let mut got = RustString::new();
    for (i, doc) in corpus().iter().enumerate() {
        got.push_str("N ");
        push_usize(&mut got, i);
        got.push(' ');
        got.push_str(doc);
        one!(&mut got, "i8", i8, doc);
        one!(&mut got, "i16", i16, doc);
        one!(&mut got, "i32", i32, doc);
        one!(&mut got, "i64", i64, doc);
        one!(&mut got, "u8", u8, doc);
        one!(&mut got, "u16", u16, doc);
        one!(&mut got, "u32", u32, doc);
        got.push('\n');
    }

    if got != REF {
        let mut line = 1usize;
        let mut gi = got.lines();
        let mut ri = REF.lines();
        loop {
            match (gi.next(), ri.next()) {
                (None, None) => break,
                (Some(g), Some(r)) if g == r => line += 1,
                (g, r) => {
                    let mut m = RustString::from("JSON_INT MISMATCH at line ");
                    push_usize(&mut m, line);
                    m.push_str("\n want: ");
                    m.push_str(r.unwrap_or("<eof>"));
                    m.push_str("\n got:  ");
                    m.push_str(g.unwrap_or("<eof>"));
                    m.push('\n');
                    die(m.as_bytes());
                }
            }
            if line > 10000 {
                die(b"json_int: runaway diff\n");
            }
        }
    }

    let mut msg = RustString::from("JSON_INT_OK ");
    push_usize(&mut msg, REF.lines().count());
    msg.push_str(" rows byte-exact vs real Go json/v2 (7 widths each)\n");
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
}
