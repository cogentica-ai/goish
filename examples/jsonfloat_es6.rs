// jsonfloat_es6 — differential sweep for JSON float formatting.
//
// Go formats JSON numbers with the ES6 number-to-string conversion
// (encoding/json floatEncoder; json/v2's
// internal/jsonwire.AppendFloat, exported as jsontext.AppendFloat):
// fixed notation unless |x| < 1e-6 or |x| >= 1e21, and the exponent
// never carries a leading zero (e-09 -> e-9). goish previously used
// strconv.FormatFloat(_, 'g', -1, 64), which differs on all three
// counts (1e+20 vs 100000000000000000000, 1e-06 vs 0.000001,
// 1e-07 vs 1e-7).
//
// examples/jsonfloat_ref.txt is `jsontext.AppendFloat` over a fixed
// vector list plus 2000 deterministic random f64 bit patterns
// (math/rand seed 42); this binary replays it byte-for-byte.
#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use alloc::string::String as RustString;
use alloc::vec::Vec;

use goish::encoding::json::jsontext;
use goish::syscall;

const REF: &str = include_str!("jsonfloat_ref.txt");

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

#[goish::main]
fn main() {
    let mut got = RustString::with_capacity(REF.len());
    let mut line_no = 0;
    for line in REF.lines() {
        line_no += 1;
        let (bits_hex, _want) = match line.split_once(' ') {
            Some(p) => p,
            None => die(b"jsonfloat: malformed ref line\n"),
        };
        let bits = match u64::from_str_radix(bits_hex, 16) {
            Ok(b) => b,
            Err(_) => die(b"jsonfloat: bad hex in ref\n"),
        };
        let f = f64::from_bits(bits);
        let mut out: Vec<u8> = Vec::new();
        jsontext::AppendFloat(&mut out, f, 64);
        got.push_str(bits_hex);
        got.push(' ');
        for &c in out.iter() {
            got.push(c as char);
        }
        got.push('\n');
    }
    if line_no == 0 {
        die(b"jsonfloat: empty ref\n");
    }
    if got != REF {
        let mut n = 1;
        let mut r = REF.lines();
        let mut g = got.lines();
        loop {
            match (r.next(), g.next()) {
                (Some(a), Some(b)) if a == b => n += 1,
                (a, b) => {
                    let mut msg = RustString::from("JSONFLOAT MISMATCH at line ");
                    msg.push_str(itoa(n).as_str());
                    msg.push_str("\n want: ");
                    msg.push_str(a.unwrap_or("<eof>"));
                    msg.push_str("\n got:  ");
                    msg.push_str(b.unwrap_or("<eof>"));
                    msg.push('\n');
                    die(msg.as_bytes());
                }
            }
        }
    }
    let msg = b"JSONFLOAT_OK 2028 vectors byte-exact vs jsontext.AppendFloat\n";
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
    syscall::Exit(0);
}

fn itoa(mut v: u64) -> RustString {
    let mut d = [0u8; 20];
    let mut i = 0;
    loop {
        d[i] = b'0' + (v % 10) as u8;
        v /= 10;
        i += 1;
        if v == 0 {
            break;
        }
    }
    let mut s = RustString::new();
    while i > 0 {
        i -= 1;
        s.push(d[i] as char);
    }
    s
}
