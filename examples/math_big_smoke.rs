// math/big smoke — sign, compare, mod, exp on big.Int, plus
// genuine multi-precision Mul / Div / DivMod / Exp.

#![no_std]
#![no_main]

use goish::{int, slice, string, syscall};
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

// 2^n as a big::Int via Lsh (n >= 0).
fn pow2(n: u64) -> big::Int {
    let mut acc = big::Int::new();
    acc.Lsh(&big::NewInt(1), n);
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

    // ── Sub ────────────────────────────────────────────────────────
    let mut s = big::Int::new();
    s.Sub(&big::NewInt(10), &big::NewInt(3));
    check(s.Int64() == 7, b"sub 10-3");
    s.Sub(&big::NewInt(3), &big::NewInt(10));
    check(s.Int64() == -7, b"sub 3-10");
    s.Sub(&big::NewInt(-5), &big::NewInt(8));      // -5 - 8 = -13
    check(s.Int64() == -13, b"sub -5-8");
    s.Sub(&big::NewInt(-5), &big::NewInt(-8));     // -5 - (-8) = 3
    check(s.Int64() == 3, b"sub -5-(-8)");
    s.Sub(&big::NewInt(7), &big::NewInt(7));       // 7 - 7 = 0
    check(s.Int64() == 0 && s.Sign() == 0, b"sub 7-7 zero");
    // Multi-precision: (10^55 + 7) - 10^55 == 7.
    let mut bigsub = big::Int::new();
    bigsub.Sub(&dividend, &prod);
    check(bigsub.Int64() == 7, b"sub big 10^55+7 - 10^55");

    // ── Neg ────────────────────────────────────────────────────────
    let mut ng = big::Int::new();
    ng.Neg(&big::NewInt(42));
    check(ng.Int64() == -42, b"neg 42");
    ng.Neg(&big::NewInt(-42));
    check(ng.Int64() == 42, b"neg -42");
    ng.Neg(&big::NewInt(0));
    check(ng.Sign() == 0, b"neg 0 stays non-neg");

    // ── BitLen / TrailingZeroBits ──────────────────────────────────
    check(big::NewInt(0).BitLen() == 0,  b"bitlen 0");
    check(big::NewInt(1).BitLen() == 1,  b"bitlen 1");
    check(big::NewInt(255).BitLen() == 8, b"bitlen 255");
    check(big::NewInt(256).BitLen() == 9, b"bitlen 256");
    // 2^40 has bit length 41.
    check(pow2(40).BitLen() == 41, b"bitlen 2^40");
    check(big::NewInt(0).TrailingZeroBits() == 0, b"tzb 0");
    check(big::NewInt(1).TrailingZeroBits() == 0, b"tzb 1");
    check(big::NewInt(8).TrailingZeroBits() == 3, b"tzb 8");
    // 2^40 has 40 trailing zero bits.
    check(pow2(40).TrailingZeroBits() == 40, b"tzb 2^40");

    // ── Bit ────────────────────────────────────────────────────────
    let bx = big::NewInt(0b1010);                  // = 10
    check(bx.Bit(0) == 0, b"bit 10[0]");
    check(bx.Bit(1) == 1, b"bit 10[1]");
    check(bx.Bit(2) == 0, b"bit 10[2]");
    check(bx.Bit(3) == 1, b"bit 10[3]");
    check(bx.Bit(99) == 0, b"bit 10[99] above range");
    // Negative: -1 is all-ones in two's complement -> every bit is 1.
    let bneg = big::NewInt(-1);
    check(bneg.Bit(0) == 1 && bneg.Bit(5) == 1 && bneg.Bit(70) == 1, b"bit -1 all ones");
    // -2 == ...11111110 -> bit0=0, bit1..=1.
    let bneg2 = big::NewInt(-2);
    check(bneg2.Bit(0) == 0 && bneg2.Bit(1) == 1 && bneg2.Bit(8) == 1, b"bit -2");

    // ── SetBit ─────────────────────────────────────────────────────
    let mut sb = big::Int::new();
    sb.SetBit(&big::NewInt(0), 4, 1);              // 0 | (1<<4) = 16
    check(sb.Int64() == 16, b"setbit 0 bit4=1");
    sb.SetBit(&big::NewInt(0b1111), 1, 0);         // 15 &^ (1<<1) = 13
    check(sb.Int64() == 13, b"setbit 15 bit1=0");
    sb.SetBit(&big::NewInt(5), 1, 1);              // 5 | 2 = 7
    check(sb.Int64() == 7, b"setbit 5 bit1=1");
    // Negative: -1 with bit0 cleared == -2 (two's complement).
    sb.SetBit(&big::NewInt(-1), 0, 0);
    check(sb.Int64() == -2, b"setbit -1 bit0=0 -> -2");

    // ── Bitwise on positive operands ───────────────────────────────
    // 0b1100 (12) & 0b1010 (10) = 0b1000 (8)
    let mut bw = big::Int::new();
    bw.And(&big::NewInt(12), &big::NewInt(10));
    check(bw.Int64() == 8, b"and 12&10");
    bw.Or(&big::NewInt(12), &big::NewInt(10));     // = 14
    check(bw.Int64() == 14, b"or 12|10");
    bw.Xor(&big::NewInt(12), &big::NewInt(10));    // = 6
    check(bw.Int64() == 6, b"xor 12^10");
    bw.AndNot(&big::NewInt(12), &big::NewInt(10)); // 12 &^ 10 = 4
    check(bw.Int64() == 4, b"andnot 12&^10");
    bw.Not(&big::NewInt(0));                       // ^0 = -1
    check(bw.Int64() == -1, b"not 0 == -1");
    bw.Not(&big::NewInt(5));                       // ^5 = -6
    check(bw.Int64() == -6, b"not 5 == -6");

    // ── Bitwise on negative operands (two's complement) ────────────
    // Cross-checked against Python's arbitrary-precision integers.
    // -5 & 3 == 3
    bw.And(&big::NewInt(-5), &big::NewInt(3));
    check(bw.Int64() == 3, b"and -5&3 == 3");
    // -5 & -3 == -7
    bw.And(&big::NewInt(-5), &big::NewInt(-3));
    check(bw.Int64() == -7, b"and -5&-3 == -7");
    // -5 | 3 == -5
    bw.Or(&big::NewInt(-5), &big::NewInt(3));
    check(bw.Int64() == -5, b"or -5|3 == -5");
    // -5 | -3 == -1
    bw.Or(&big::NewInt(-5), &big::NewInt(-3));
    check(bw.Int64() == -1, b"or -5|-3 == -1");
    // -5 ^ 3 == -8
    bw.Xor(&big::NewInt(-5), &big::NewInt(3));
    check(bw.Int64() == -8, b"xor -5^3 == -8");
    // -5 ^ -3 == 6
    bw.Xor(&big::NewInt(-5), &big::NewInt(-3));
    check(bw.Int64() == 6, b"xor -5^-3 == 6");
    // -5 &^ 3 == -8   (-5 & ^3)
    bw.AndNot(&big::NewInt(-5), &big::NewInt(3));
    check(bw.Int64() == -8, b"andnot -5&^3 == -8");
    // 12 &^ -3 == 0   (12 & ^(-3) == 12 & 2)
    bw.AndNot(&big::NewInt(12), &big::NewInt(-3));
    check(bw.Int64() == 0, b"andnot 12&^-3 == 0");
    // -12 &^ -3 == 0   (cross-checked: -12 & ~(-3) == -12 & 2 == 0)
    bw.AndNot(&big::NewInt(-12), &big::NewInt(-3));
    check(bw.Int64() == 0 && bw.Sign() == 0, b"andnot -12&^-3 == 0");
    // -5 &^ -3 == 2
    bw.AndNot(&big::NewInt(-5), &big::NewInt(-3));
    check(bw.Int64() == 2, b"andnot -5&^-3 == 2");
    // ^-1 == 0
    bw.Not(&big::NewInt(-1));
    check(bw.Int64() == 0 && bw.Sign() == 0, b"not -1 == 0");
    // ^-6 == 5
    bw.Not(&big::NewInt(-6));
    check(bw.Int64() == 5, b"not -6 == 5");

    // ── Lsh / Rsh ──────────────────────────────────────────────────
    let mut sh = big::Int::new();
    sh.Lsh(&big::NewInt(1), 10);                   // 1 << 10 = 1024
    check(sh.Int64() == 1024, b"lsh 1<<10");
    sh.Lsh(&big::NewInt(3), 40);                   // 3 << 40
    check(dec_eq(&sh, b"3298534883328"), b"lsh 3<<40");
    sh.Lsh(&big::NewInt(-1), 4);                   // -1 << 4 = -16
    check(sh.Int64() == -16, b"lsh -1<<4 == -16");
    sh.Rsh(&big::NewInt(1024), 10);                // 1024 >> 10 = 1
    check(sh.Int64() == 1, b"rsh 1024>>10");
    sh.Rsh(&big::NewInt(255), 4);                  // 255 >> 4 = 15
    check(sh.Int64() == 15, b"rsh 255>>4");
    // Negative arithmetic shift: -8 >> 1 == -4 ; -5 >> 1 == -3.
    sh.Rsh(&big::NewInt(-8), 1);
    check(sh.Int64() == -4, b"rsh -8>>1 == -4");
    sh.Rsh(&big::NewInt(-5), 1);
    check(sh.Int64() == -3, b"rsh -5>>1 == -3");
    // -1 >> 100 == -1 (sign-extends forever).
    sh.Rsh(&big::NewInt(-1), 100);
    check(sh.Int64() == -1, b"rsh -1>>100 == -1");
    // Lsh then Rsh round-trips a multi-limb value.
    let mut rt = big::Int::new();
    rt.Lsh(&big::NewInt(123456789), 50);
    rt.Rsh(&rt.clone(), 50);
    check(rt.Int64() == 123456789, b"lsh/rsh roundtrip 50 bits");

    // ── SetString / Text round-trips ───────────────────────────────
    // A large multi-limb value: 123456789012345678901234567890.
    let big_dec = b"123456789012345678901234567890";
    {
        let mut t = big::Int::new();
        let (_, ok) = t.SetString(string::from_bytes(big_dec), 10);
        check(ok && dec_eq(&t, big_dec), b"setstring base10 large");
        // Text(10) must agree with String().
        check(t.Text(10).as_bytes() == t.String().as_bytes(), b"text10 == string");
        // Round-trip through bases 2, 8, 10, 16.
        check(t.Text(2).as_bytes()
            == b"1100011101110100100001111111101101100001101110011111000001110111001001110001111110000101011010010",
            b"text base2 large");
        check(t.Text(8).as_bytes() == b"143564417755415637016711617605322", b"text base8 large");
        check(t.Text(16).as_bytes() == b"18ee90ff6c373e0ee4e3f0ad2", b"text base16 large");
        // Re-parse each representation and confirm equality.
        for &(repr, base) in &[
            (b"1100011101110100100001111111101101100001101110011111000001110111001001110001111110000101011010010" as &[u8], 2i64),
            (b"143564417755415637016711617605322" as &[u8], 8),
            (b"18ee90ff6c373e0ee4e3f0ad2" as &[u8], 16),
        ] {
            let mut u = big::Int::new();
            let (_, uok) = u.SetString(string::from_bytes(repr), base);
            check(uok && u.Cmp(&t) == 0, b"setstring/text roundtrip");
        }
    }

    // Negative multi-limb value through every base.
    {
        let neg_dec = b"-987654321098765432109876543210987654321";
        let mut t = big::Int::new();
        let (_, ok) = t.SetString(string::from_bytes(neg_dec), 10);
        check(ok && t.Sign() == -1, b"setstring negative parsed");
        check(t.Text(10).as_bytes() == neg_dec, b"text negative base10");
        check(t.Text(16).as_bytes() == b"-2e7074d9c994179b09b1bc62f21c70cb1",
            b"text negative base16");
        // Round-trip via base 16.
        let mut u = big::Int::new();
        u.SetString(string::from_bytes(b"-2e7074d9c994179b09b1bc62f21c70cb1"), 16);
        check(u.Cmp(&t) == 0, b"setstring negative base16 roundtrip");
        // Round-trip via base 2.
        let bin = t.Text(2);
        let mut w = big::Int::new();
        w.SetString(bin.clone(), 2);
        check(w.Cmp(&t) == 0, b"setstring negative base2 roundtrip");
    }

    // Bases above 16 — 36 and 62 (cross-checked against Python).
    {
        let mut t = big::Int::new();
        t.SetString(string::from_bytes(big_dec), 10);
        check(t.Text(36).as_bytes() == b"byw97um9s91dlz68tsi", b"text base36");
        check(t.Text(62).as_bytes() == b"2AyLS9BKAMjjsWHR0", b"text base62");
        let mut u = big::Int::new();
        u.SetString(string::from_bytes(b"2AyLS9BKAMjjsWHR0"), 62);
        check(u.Cmp(&t) == 0, b"setstring base62 roundtrip");
    }

    // ── SetString base-0 auto-detect ───────────────────────────────
    {
        let mut hx = big::Int::new();
        let (_, ok) = hx.SetString(string::from_bytes(b"0xFF"), 0);
        check(ok && hx.Int64() == 255, b"setstring base0 0xFF");

        let mut bn = big::Int::new();
        let (_, ok) = bn.SetString(string::from_bytes(b"0b101"), 0);
        check(ok && bn.Int64() == 5, b"setstring base0 0b101");

        let mut oc = big::Int::new();
        let (_, ok) = oc.SetString(string::from_bytes(b"0o17"), 0);
        check(ok && oc.Int64() == 15, b"setstring base0 0o17");

        // Bare-zero octal prefix: "017" == 15.
        let mut oc2 = big::Int::new();
        let (_, ok) = oc2.SetString(string::from_bytes(b"017"), 0);
        check(ok && oc2.Int64() == 15, b"setstring base0 017 octal");

        // No prefix → decimal.
        let mut dc = big::Int::new();
        let (_, ok) = dc.SetString(string::from_bytes(b"42"), 0);
        check(ok && dc.Int64() == 42, b"setstring base0 decimal");

        // Negative with prefix.
        let mut nh = big::Int::new();
        let (_, ok) = nh.SetString(string::from_bytes(b"-0x10"), 0);
        check(ok && nh.Int64() == -16, b"setstring base0 -0x10");

        // Underscore separators (base 0 only).
        let mut us = big::Int::new();
        let (_, ok) = us.SetString(string::from_bytes(b"0x_de_ad_be_ef"), 0);
        check(ok && us.Int64() == 0xdeadbeef, b"setstring base0 underscores");
    }

    // ── SetString parse failures return false ──────────────────────
    {
        // Bad digit for the base.
        let mut f = big::Int::new();
        let saved = big::NewInt(777);
        f.Set(&saved);
        let (_, ok) = f.SetString(string::from_bytes(b"12x9"), 10);
        check(!ok, b"setstring bad digit -> false");
        // Self left unchanged on failure.
        check(f.Int64() == 777, b"setstring failure leaves self");

        // '9' is not a valid binary digit.
        let mut f2 = big::Int::new();
        let (_, ok) = f2.SetString(string::from_bytes(b"1019"), 2);
        check(!ok, b"setstring bad binary digit -> false");

        // Empty string.
        let mut f3 = big::Int::new();
        let (_, ok) = f3.SetString(string::from_bytes(b""), 10);
        check(!ok, b"setstring empty -> false");

        // Trailing junk.
        let mut f4 = big::Int::new();
        let (_, ok) = f4.SetString(string::from_bytes(b"123 "), 10);
        check(!ok, b"setstring trailing junk -> false");

        // Misplaced underscore.
        let mut f5 = big::Int::new();
        let (_, ok) = f5.SetString(string::from_bytes(b"1__2"), 0);
        check(!ok, b"setstring double underscore -> false");
    }

    // ── Bytes / SetBytes round-trip ────────────────────────────────
    {
        // Large value: 123456789012345678901234567890.
        let mut t = big::Int::new();
        t.SetString(string::from_bytes(big_dec), 10);
        let raw = t.Bytes();
        // Python: v.to_bytes(13,'big').hex() == 018ee90ff6c373e0ee4e3f0ad2
        // (Bytes() strips the leading zero byte -> 13 bytes here).
        check(raw.len() == 13, b"bytes large length 13");
        let expect: [u8; 13] = [
            0x01, 0x8e, 0xe9, 0x0f, 0xf6, 0xc3, 0x73, 0xe0, 0xee, 0x4e, 0x3f, 0x0a, 0xd2,
        ];
        let mut bytes_ok = true;
        for i in 0..13 {
            if raw[int::from(i as i64)] != expect[i] {
                bytes_ok = false;
            }
        }
        check(bytes_ok, b"bytes large content");

        // SetBytes back must reproduce the original magnitude.
        let mut u = big::Int::new();
        u.SetBytes(raw.clone());
        check(u.Cmp(&t) == 0, b"setbytes roundtrip large");

        // Sign is dropped — SetBytes is unsigned.
        let mut neg = big::Int::new();
        neg.SetString(string::from_bytes(big_dec), 10);
        neg.Neg(&neg.clone());
        let nb = neg.Bytes();
        check(nb.len() == 13, b"bytes of negative drops sign");
        let mut back = big::Int::new();
        back.SetBytes(nb);
        check(back.Cmp(&t) == 0 && back.Sign() == 1, b"setbytes magnitude only");

        // Zero round-trips to an empty slice.
        let z0 = big::NewInt(0);
        check(z0.Bytes().len() == 0, b"bytes zero -> empty");
        let mut fromempty = big::NewInt(12345);
        fromempty.SetBytes(z0.Bytes());
        check(fromempty.Sign() == 0, b"setbytes empty -> zero");

        // A small known value: 0x010203 == 66051.
        let mut sb = big::Int::new();
        let three: [u8; 3] = [0x01, 0x02, 0x03];
        sb.SetBytes(slice::__from_vec(three.to_vec()));
        check(sb.Int64() == 0x010203, b"setbytes 010203");
        // And its Bytes() comes back identical.
        let rt = sb.Bytes();
        check(rt.len() == 3 && rt[int::from(0)] == 1
            && rt[int::from(1)] == 2 && rt[int::from(2)] == 3,
            b"bytes 010203 roundtrip");

        // Leading zero bytes in the input are ignored.
        let mut lz = big::Int::new();
        let padded: [u8; 5] = [0x00, 0x00, 0x01, 0x02, 0x03];
        lz.SetBytes(slice::__from_vec(padded.to_vec()));
        check(lz.Int64() == 0x010203, b"setbytes leading zeros ignored");
    }

    let _ = &int::from(0);
    report();
}
