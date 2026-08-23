// big_exp_diff — differential sweep for (*big.Int).Exp.
//
// goish walked `y.abs.len()*32` exponent bits instead of y.BitLen(),
// so it kept squaring the base past the exponent's highest set bit.
// With a modulus that is merely wasteful (values stay reduced); with
// m == 0 it is fatal — Exp(2, 64, 0) squares up to 2^(2^31) and never
// returns. Go's nat.expNN walks bitLen.
//
// examples/bigexp_ref.txt is math/big's Exp over 30 hand-picked
// triples (limb boundaries 31/32/33/63/64/65/127/128, negative bases
// with odd and even exponents, zero base/exponent, ±1, and modular
// cases) plus 200 deterministic random triples (math/rand seed 7,
// base in [-1000,1000), exponent in [0,160), modulus in [0,3)).
#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use alloc::string::String as RustString;

use goish::math::big;
use goish::syscall;

const REF: &str = include_str!("bigexp_ref.txt");

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

#[goish::main]
fn main() {
    let mut got = RustString::with_capacity(REF.len());
    let mut n = 0;
    for line in REF.lines() {
        n += 1;
        let mut it = line.split(' ');
        let b: i64 = it
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| die(b"bad ref\n"));
        let e: i64 = it
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| die(b"bad ref\n"));
        let m: i64 = it
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| die(b"bad ref\n"));

        let mut bi = big::Int::new();
        bi.SetInt64(b);
        let mut ei = big::Int::new();
        ei.SetInt64(e);
        let mut mi = big::Int::new();
        mi.SetInt64(m);
        let mut z = big::Int::new();
        z.Exp(&bi, &ei, &mi);

        got.push_str(line.rsplit_once(' ').map(|p| p.0).unwrap_or(line));
        got.push(' ');
        for &c in z.Text(10).as_bytes() {
            got.push(c as char);
        }
        got.push('\n');
    }
    if n == 0 {
        die(b"big_exp_diff: empty ref\n");
    }
    if got != REF {
        let mut i = 1;
        let mut r = REF.lines();
        let mut g = got.lines();
        loop {
            match (r.next(), g.next()) {
                (Some(a), Some(b)) if a == b => i += 1,
                (a, b) => {
                    let mut msg = RustString::from("BIGEXP MISMATCH at line ");
                    let mut d = alloc::vec::Vec::new();
                    let mut v = i;
                    if v == 0 {
                        d.push(b'0');
                    }
                    while v > 0 {
                        d.push(b'0' + (v % 10) as u8);
                        v /= 10;
                    }
                    d.reverse();
                    for &c in &d {
                        msg.push(c as char);
                    }
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
    let msg = b"BIGEXP_OK 230 triples byte-exact vs Go math/big\n";
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
    syscall::Exit(0);
}
