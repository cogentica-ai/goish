// math_pow_diff — differential sweep for math.Pow / Frexp / Ldexp.
//
// goish delegated Pow to libm (musl/fdlibm), which differs from Go's
// own algorithm by up to 1 ULP: Pow(7, -2) is 0.020408163265306124
// under libm and 0.02040816326530612 in Go. Go's math/pow.go is now
// ported verbatim (with the Frexp/Ldexp/normalize/isOddInt helpers it
// needs), so results agree bit-for-bit.
//
// KNOWN GAP: a fractional exponent runs Exp(yf*Log(x)), and Go
// implements Exp and Log in hand-written amd64 assembly (exp_amd64.s,
// log_amd64.s — haveArchLog/useFMA). goish calls libm for both, so
// those results agree only to within 2 ULP. Closing it means porting
// that assembly; until then this binary asserts the bound and prints
// the observed worst case. Integer exponents — the path
// typescript-go's jsnum.Exponentiate cares about — are bit-exact.
//
// examples/mathpow_ref.txt is Go's math.Pow over 22 bases x 26
// exponents (signed zeros, ±1, ±Inf, NaN, MaxFloat64, the smallest
// subnormal, the 1<<63 exponent cutoff, half-integer exponents) plus
// 1500 deterministic random pairs (math/rand seed 11), then Frexp over
// 12 values and Ldexp over those x 10 exponents including the
// underflow/overflow edges. Values are compared as raw bit patterns,
// so a 1-ULP difference fails.
#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use alloc::string::String as RustString;

use goish::math;
use goish::syscall;

const REF: &str = include_str!("mathpow_ref.txt");

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn hex(out: &mut RustString, v: u64) {
    if v == 0 {
        out.push('0');
        return;
    }
    let mut d = [0u8; 16];
    let mut i = 0;
    let mut v = v;
    while v > 0 {
        let n = (v & 0xF) as u8;
        d[i] = if n < 10 { b'0' + n } else { b'a' + (n - 10) };
        v >>= 4;
        i += 1;
    }
    while i > 0 {
        i -= 1;
        out.push(d[i] as char);
    }
}

fn dec(out: &mut RustString, v: i64) {
    if v < 0 {
        out.push('-');
    }
    let mut n = v.unsigned_abs();
    let mut d = [0u8; 20];
    let mut i = 0;
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

/// Largest tolerated deviation on the fractional-exponent path. The
/// measured worst case over this corpus is 2 ULP; the binary prints
/// the observed worst so a regression is visible even below the cap.
const MAX_ULP: u64 = 2;

/// Distance in representable steps between two f64 bit patterns
/// (both NaN, or both the same sign; otherwise "far apart").
fn ulp_apart(a: u64, b: u64) -> u64 {
    let fa = f64::from_bits(a);
    let fb = f64::from_bits(b);
    if fa.is_nan() || fb.is_nan() {
        return if fa.is_nan() && fb.is_nan() {
            0
        } else {
            u64::MAX
        };
    }
    let key = |bits: u64| -> i64 {
        if bits & (1 << 63) != 0 {
            (!bits).wrapping_add(1) as i64
        } else {
            bits as i64
        }
    };
    (key(a) - key(b)).unsigned_abs()
}

#[goish::main]
fn main() {
    let mut got = RustString::with_capacity(REF.len());
    for line in REF.lines() {
        let mut it = line.split(' ');
        let kind = it.next().unwrap_or("");
        match kind {
            "pow" | "powulp" => {
                let x =
                    f64::from_bits(u64::from_str_radix(it.next().unwrap_or(""), 16).unwrap_or(0));
                let y =
                    f64::from_bits(u64::from_str_radix(it.next().unwrap_or(""), 16).unwrap_or(0));
                let want = u64::from_str_radix(it.next().unwrap_or(""), 16).unwrap_or(0);
                let bits = math::Pow(x, y).to_bits();
                got.push_str(kind);
                got.push(' ');
                hex(&mut got, x.to_bits());
                got.push(' ');
                hex(&mut got, y.to_bits());
                got.push(' ');
                // A fractional exponent runs Exp(yf*Log(x)); Go uses
                // hand-written amd64 assembly for Exp and Log, goish
                // uses libm, so those agree only to within 2 ULP.
                // Everything else must match bit-for-bit.
                if kind == "powulp" && ulp_apart(bits, want) <= MAX_ULP {
                    hex(&mut got, want);
                } else {
                    hex(&mut got, bits);
                }
            }
            "frexp" => {
                let f =
                    f64::from_bits(u64::from_str_radix(it.next().unwrap_or(""), 16).unwrap_or(0));
                let (frac, exp) = math::Frexp(f);
                got.push_str("frexp ");
                hex(&mut got, f.to_bits());
                got.push(' ');
                hex(&mut got, frac.to_bits());
                got.push(' ');
                dec(&mut got, exp as i64);
            }
            "ldexp" => {
                let f =
                    f64::from_bits(u64::from_str_radix(it.next().unwrap_or(""), 16).unwrap_or(0));
                let e: i64 = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
                got.push_str("ldexp ");
                hex(&mut got, f.to_bits());
                got.push(' ');
                dec(&mut got, e);
                got.push(' ');
                hex(&mut got, math::Ldexp(f, e as goish::types::int).to_bits());
            }
            _ => die(b"math_pow_diff: bad ref line\n"),
        }
        got.push('\n');
    }
    if got != REF {
        let mut i = 1;
        let mut r = REF.lines();
        let mut g = got.lines();
        loop {
            match (r.next(), g.next()) {
                (Some(a), Some(b)) if a == b => i += 1,
                (a, b) => {
                    let mut msg = RustString::from("MATHPOW MISMATCH at line ");
                    dec(&mut msg, i);
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
    {
        let mut worst = 0u64;
        for line in REF.lines() {
            let mut it = line.split(' ');
            if it.next() != Some("powulp") {
                continue;
            }
            let x = f64::from_bits(u64::from_str_radix(it.next().unwrap_or(""), 16).unwrap_or(0));
            let y = f64::from_bits(u64::from_str_radix(it.next().unwrap_or(""), 16).unwrap_or(0));
            let want = u64::from_str_radix(it.next().unwrap_or(""), 16).unwrap_or(0);
            let d = ulp_apart(math::Pow(x, y).to_bits(), want);
            if d > worst && d != u64::MAX {
                worst = d;
            }
        }
        let mut m = RustString::from("worst fractional-exponent ULP: ");
        dec(&mut m, worst as i64);
        m.push('\n');
        syscall::Write(syscall::STDOUT, m.as_ptr(), m.len());
    }
    let msg = b"MATHPOW_OK 2204 vectors vs Go math.Pow/Frexp/Ldexp (1455 bit-exact, 617 fractional-exponent within 2 ULP)\n";
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
    syscall::Exit(0);
}
