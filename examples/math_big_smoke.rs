// math/big smoke — sign, compare, mod, exp on big.Int, plus
// genuine multi-precision Mul / Div / DivMod / Exp.

#![no_std]
#![no_main]

use goish::{int, syscall};
use goish::math::big;
use goish::fmt::Stringer;

static mut PASS: i32 = 0;
static mut TOTAL: i32 = 0;

fn write(fd: i32, msg: &[u8]) {
    syscall::Write(fd, msg.as_ptr(), msg.len());
}

fn check(cond: bool, name: &[u8]) {
    unsafe {
        TOTAL += 1;
        if cond {
            PASS += 1;
            write(syscall::STDOUT, b"PASS ");
        } else {
            write(syscall::STDERR, b"FAIL ");
        }
    }
    write(syscall::STDOUT, name);
    write(syscall::STDOUT, b"\n");
}

// Print "ok P/T" and exit with the right status.
fn report() -> ! {
    let (p, t) = unsafe { (PASS, TOTAL) };
    write(syscall::STDOUT, b"ok ");
    write_i32(p);
    write(syscall::STDOUT, b"/");
    write_i32(t);
    write(syscall::STDOUT, b"\n");
    syscall::Exit(if p == t { 0 } else { 1 });
}

fn write_i32(mut n: i32) {
    let mut buf = [0u8; 12];
    let mut i = buf.len();
    if n == 0 {
        write(syscall::STDOUT, b"0");
        return;
    }
    let neg = n < 0;
    let mut un: u32 = if neg { (n as i64).unsigned_abs() as u32 } else { n as u32 };
    let _ = &mut n;
    while un > 0 {
        i -= 1;
        buf[i] = b'0' + (un % 10) as u8;
        un /= 10;
    }
    if neg {
        i -= 1;
        buf[i] = b'-';
    }
    write(syscall::STDOUT, &buf[i..]);
}

// Decimal-string equality of a big::Int against an expected literal.
fn dec_eq(z: &big::Int, want: &[u8]) -> bool {
    let s = z.String();
    s.as_bytes() == want
}

// 10^n as a big::Int (n >= 0).
fn pow10(n: u32) -> big::Int {
    let ten = big::NewInt(10);
    let mut acc = big::NewInt(1);
    for _ in 0..n {
        let mut t = big::Int::new();
        t.Mul(&acc, &ten);
        acc = t;
    }
    acc
}

#[goish::main]
fn main() {
    // ── Sign ───────────────────────────────────────────────────────
    let zero = big::NewInt(0);
    let pos  = big::NewInt(42);
    let neg  = big::NewInt(-7);
    check(zero.Sign() == 0,  b"sign zero");
    check(pos.Sign()  == 1,  b"sign pos");
    check(neg.Sign()  == -1, b"sign neg");

    // ── Int64 round-trip ───────────────────────────────────────────
    check(pos.Int64() == 42, b"int64 pos");
    check(neg.Int64() == -7, b"int64 neg");

    // ── Cmp ────────────────────────────────────────────────────────
    check(pos.Cmp(&zero) == 1,  b"cmp pos zero");
    check(zero.Cmp(&pos) == -1, b"cmp zero pos");
    check(pos.Cmp(&pos)  == 0,  b"cmp pos pos");
    check(neg.Cmp(&pos)  == -1, b"cmp neg pos");

    // ── Mod (small) ────────────────────────────────────────────────
    let mut z = big::Int::new();
    z.Mod(&big::NewInt(100), &big::NewInt(7));
    check(z.Int64() == 2, b"mod 100/7");
    z.Mod(&big::NewInt(13), &big::NewInt(5));
    check(z.Int64() == 3, b"mod 13/5");
    // Euclidean: -17 mod 5 == 3.
    z.Mod(&big::NewInt(-17), &big::NewInt(5));
    check(z.Int64() == 3, b"mod -17/5 euclid");

    // ── Exp (small) ────────────────────────────────────────────────
    z.Exp(&big::NewInt(2), &big::NewInt(10), &big::NewInt(1000));
    check(z.Int64() == 24, b"exp 2^10 mod 1000");
    z.Exp(&big::NewInt(3), &big::NewInt(4), &big::NewInt(100));
    check(z.Int64() == 81, b"exp 3^4 mod 100");

    // ── SetInt64 ───────────────────────────────────────────────────
    let mut a = big::Int::new();
    a.SetInt64(999);
    check(a.Int64() == 999, b"setint64 999");
    a.SetInt64(-1);
    check(a.Sign() == -1, b"setint64 -1 sign");

    // ── Multi-precision Mul: two numbers far larger than u64 ───────
    // p = 10^30, q = 10^25  =>  p*q = 10^55  (well past 2^64).
    let p = pow10(30);
    let q = pow10(25);
    let mut prod = big::Int::new();
    prod.Mul(&p, &q);
    check(
        dec_eq(&prod, b"10000000000000000000000000000000000000000000000000000000"),
        b"mul 10^30 * 10^25 == 10^55",
    );

    // Signed: (-10^30) * (10^25) is negative; * itself again positive.
    let mut neg_prod = big::Int::new();
    neg_prod.Mul(&big::NewInt(-1), &p);          // -10^30
    let mut signed = big::Int::new();
    signed.Mul(&neg_prod, &q);                   // -10^55
    check(signed.Sign() == -1, b"mul signed negative");
    let mut back = big::Int::new();
    back.Mul(&neg_prod, &neg_prod);              // (+) 10^60
    check(back.Sign() == 1 && dec_eq(&back,
        b"1000000000000000000000000000000000000000000000000000000000000"),
        b"mul neg*neg == 10^60");

    // Mul where neither operand fits in u64, irregular digits.
    // x = 123456789012345678901234567890
    // y =        98765432109876543210
    // x*y verified against Python: 12193263113702179522496570642237463801111263526900
    let mut x = big::Int::new();
    x.Mul(&pow10(20), &big::NewInt(1234567890)); // 1234567890 * 10^20
    {
        let mut t = big::Int::new();
        t.Mul(&pow10(10), &big::NewInt(1234567890));
        let mut u = big::Int::new();
        u.Add(&x, &t);
        x = u;
        let mut v = big::Int::new();
        v.Add(&x, &big::NewInt(1234567890));
        x = v;
    }
    // x is now 123456789012345678901234567890
    check(dec_eq(&x, b"123456789012345678901234567890"), b"mul build x");
    let mut y = big::Int::new();
    y.Mul(&pow10(10), &big::NewInt(9876543210i64));
    {
        let mut v = big::Int::new();
        v.Add(&y, &big::NewInt(9876543210i64));
        y = v;
    }
    // y is now 98765432109876543210
    check(dec_eq(&y, b"98765432109876543210"), b"mul build y");
    let mut xy = big::Int::new();
    xy.Mul(&x, &y);
    check(
        dec_eq(&xy, b"12193263113702179522496570642237463801111263526900"),
        b"mul irregular x*y",
    );

    // ── Multi-precision Div / DivMod: large / large divisor ────────
    // dividend = 10^55 + 7, divisor = 10^25 + 3.
    let mut dividend = big::Int::new();
    dividend.Add(&prod, &big::NewInt(7));        // 10^55 + 7
    let mut divisor = big::Int::new();
    divisor.Add(&q, &big::NewInt(3));            // 10^25 + 3
    let mut quo = big::Int::new();
    let mut rem = big::Int::new();
    quo.DivMod(&dividend, &divisor, &mut rem);
    // Check the division identity: quo*divisor + rem == dividend, and 0 <= rem < divisor.
    let mut chk = big::Int::new();
    chk.Mul(&quo, &divisor);
    let mut chk2 = big::Int::new();
    chk2.Add(&chk, &rem);
    check(chk2.Cmp(&dividend) == 0, b"divmod identity q*d+r==n");
    check(rem.Sign() >= 0 && rem.Cmp(&divisor) == -1, b"divmod 0<=r<d");

    // Div alone must agree with DivMod's quotient.
    let mut quo2 = big::Int::new();
    quo2.Div(&dividend, &divisor);
    check(quo2.Cmp(&quo) == 0, b"div agrees with divmod");

    // Negative dividend, Euclidean: identity must still hold with 0 <= r < d.
    let mut neg_dividend = big::Int::new();
    neg_dividend.Mul(&big::NewInt(-1), &dividend);
    let mut nquo = big::Int::new();
    let mut nrem = big::Int::new();
    nquo.DivMod(&neg_dividend, &divisor, &mut nrem);
    let mut nchk = big::Int::new();
    nchk.Mul(&nquo, &divisor);
    let mut nchk2 = big::Int::new();
    nchk2.Add(&nchk, &nrem);
    check(nchk2.Cmp(&neg_dividend) == 0, b"divmod neg identity");
    check(nrem.Sign() >= 0 && nrem.Cmp(&divisor) == -1, b"divmod neg 0<=r<d");

    // Exact division: (10^55) / (10^25) == 10^30, remainder 0.
    let mut exq = big::Int::new();
    let mut exr = big::Int::new();
    exq.DivMod(&prod, &q, &mut exr);
    check(dec_eq(&exq, b"1000000000000000000000000000000") && exr.Sign() == 0,
        b"div exact 10^55/10^25");

    // ── Multi-precision Exp: operands & modulus larger than u32 ────
    // Base, exponent, modulus all a few hundred bits.
    // base = 10^40 + 9, exp = 10^15 + 1, mod = 10^50 + 7.
    let mut ebase = big::Int::new();
    ebase.Add(&pow10(40), &big::NewInt(9));
    let mut eexp = big::Int::new();
    eexp.Add(&pow10(15), &big::NewInt(1));
    let mut emod = big::Int::new();
    emod.Add(&pow10(50), &big::NewInt(7));
    let mut eres = big::Int::new();
    eres.Exp(&ebase, &eexp, &emod);
    // Result must be reduced: 0 <= eres < emod, and non-trivial.
    check(eres.Sign() >= 0 && eres.Cmp(&emod) == -1, b"exp big in range");
    // Exact value cross-checked against Python's pow(base, exp, mod).
    check(dec_eq(&eres, b"73926293254195207749682038714681681753283032610409"),
        b"exp big exact value");

    // Cross-check exp via the definition for a small exponent but
    // multi-precision base & modulus: base^3 mod m == ((base*base mod m)*base) mod m.
    let mut three = big::NewInt(3);
    let mut ec = big::Int::new();
    ec.Exp(&ebase, &three, &emod);
    let mut sq = big::Int::new();
    sq.Mul(&ebase, &ebase);
    let mut sqm = big::Int::new();
    sqm.Mod(&sq, &emod);
    let mut cube = big::Int::new();
    cube.Mul(&sqm, &ebase);
    let mut cubem = big::Int::new();
    cubem.Mod(&cube, &emod);
    check(ec.Cmp(&cubem) == 0, b"exp base^3 == manual");
    let _ = &mut three;

    // RSA-sized sanity: a known modular identity x^1 mod m == x mod m.
    let mut one = big::NewInt(1);
    let mut e1 = big::Int::new();
    e1.Exp(&ebase, &one, &emod);
    let mut xm = big::Int::new();
    xm.Mod(&ebase, &emod);
    check(e1.Cmp(&xm) == 0, b"exp x^1 == x mod m");
    let _ = &mut one;

    // x^0 mod m == 1.
    let mut e0 = big::Int::new();
    e0.Exp(&ebase, &big::NewInt(0), &emod);
    check(e0.Int64() == 1, b"exp x^0 == 1");

    let _ = &int::from(0);
    report();
}
