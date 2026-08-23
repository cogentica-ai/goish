// math/big smoke — sign, compare, mod, exp on big.Int, plus
// genuine multi-precision Mul / Div / DivMod / Exp.

#![no_std]
#![no_main]

extern crate alloc;

use goish::fmt::Stringer;
use goish::math::big;
use goish::math::rand;
use goish::{int, slice, string, syscall};

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
    let mut un: u32 = if neg {
        (n as i64).unsigned_abs() as u32
    } else {
        n as u32
    };
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

// ── In-test fmt::State scaffold ───────────────────────────────────────
//
// To exercise the `Int` / `Float` `fmt::Formatter` impls we need a
// concrete `fmt::State`. `TestState` is a byte-buffer Writer whose
// width / precision / flags are configurable; `Format` writes its
// output through `Write`, and the captured bytes can be compared
// against the expected string.
//
// A `fmt::ScanState` scaffold for the upcoming Int/Rat/Float `Scan`
// task would be analogous but cursor-shaped: hold the input bytes + a
// read position, impl `ReadRune` / `UnreadRune` / `SkipSpace` /
// `Token` / `Width`. It is just as feasible to build in-test.
struct TestState {
    buf: alloc::vec::Vec<u8>,
    width: int,
    has_width: bool,
    prec: int,
    has_prec: bool,
    flags: alloc::vec::Vec<u8>, // flag chars that report `true`
}

impl TestState {
    fn new() -> Self {
        TestState {
            buf: alloc::vec::Vec::new(),
            width: 0,
            has_width: false,
            prec: 0,
            has_prec: false,
            flags: alloc::vec::Vec::new(),
        }
    }
    fn with_width(mut self, w: int) -> Self {
        self.width = w;
        self.has_width = true;
        self
    }
    fn with_prec(mut self, p: int) -> Self {
        self.prec = p;
        self.has_prec = true;
        self
    }
    fn with_flag(mut self, c: u8) -> Self {
        self.flags.push(c);
        self
    }
}

impl goish::io::Writer for TestState {
    fn Write(&mut self, p: slice<goish::byte>) -> (int, goish::error) {
        let n = p.len() as int;
        self.buf.extend_from_slice(&*p);
        (n, goish::nil.into())
    }
}

impl goish::fmt::State for TestState {
    fn Width(&self) -> (int, bool) {
        (self.width, self.has_width)
    }
    fn Precision(&self) -> (int, bool) {
        (self.prec, self.has_prec)
    }
    fn Flag(&self, c: int) -> bool {
        self.flags.iter().any(|&f| f as int == c)
    }
}

// ── In-test fmt::ScanState scaffold ───────────────────────────────────
//
// `ScanCursor` wraps an ASCII byte buffer plus a read position so the
// `Int` / `Rat` / `Float` `fmt::Scanner` impls have a concrete
// `ScanState` to read through. `ReadRune` / `UnreadRune` step the
// cursor a byte at a time (ASCII-only is enough for numeric literals);
// `Token` skips leading space then collects the run of bytes accepted
// by the predicate `f`.
struct ScanCursor {
    buf: alloc::vec::Vec<u8>,
    pos: usize,
    last: usize, // pos before the most recent ReadRune (for UnreadRune)
}

impl ScanCursor {
    fn new(s: &[u8]) -> Self {
        ScanCursor {
            buf: s.to_vec(),
            pos: 0,
            last: 0,
        }
    }
}

impl goish::fmt::ScanState for ScanCursor {
    fn ReadRune(&mut self) -> (goish::rune, int, goish::error) {
        if self.pos >= self.buf.len() {
            return (0, 0, goish::io::EOF.into());
        }
        self.last = self.pos;
        let b = self.buf[self.pos];
        self.pos += 1;
        (b as goish::rune, 1, goish::nil.into())
    }
    fn UnreadRune(&mut self) -> goish::error {
        self.pos = self.last;
        goish::nil.into()
    }
    fn SkipSpace(&mut self) {
        while self.pos < self.buf.len()
            && (self.buf[self.pos] == b' '
                || self.buf[self.pos] == b'\t'
                || self.buf[self.pos] == b'\n'
                || self.buf[self.pos] == b'\r')
        {
            self.pos += 1;
        }
    }
    fn Token(
        &mut self,
        skip_space: bool,
        f: alloc::sync::Arc<dyn Fn(goish::rune) -> bool + Send + Sync>,
    ) -> (slice<goish::byte>, goish::error) {
        if skip_space {
            self.SkipSpace();
        }
        let mut out: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        while self.pos < self.buf.len() {
            let b = self.buf[self.pos];
            if !f(b as goish::rune) {
                break;
            }
            out.push(b);
            self.pos += 1;
        }
        (slice::<goish::byte>::__from_vec(out), goish::nil.into())
    }
    fn Width(&self) -> (int, bool) {
        (0, false)
    }
}

#[goish::main]
fn main() {
    // ── Sign ───────────────────────────────────────────────────────
    let zero = big::NewInt(0);
    let pos = big::NewInt(42);
    let neg = big::NewInt(-7);
    check(zero.Sign() == 0, b"sign zero");
    check(pos.Sign() == 1, b"sign pos");
    check(neg.Sign() == -1, b"sign neg");

    // ── Int64 round-trip ───────────────────────────────────────────
    check(pos.Int64() == 42, b"int64 pos");
    check(neg.Int64() == -7, b"int64 neg");

    // ── Cmp ────────────────────────────────────────────────────────
    check(pos.Cmp(&zero) == 1, b"cmp pos zero");
    check(zero.Cmp(&pos) == -1, b"cmp zero pos");
    check(pos.Cmp(&pos) == 0, b"cmp pos pos");
    check(neg.Cmp(&pos) == -1, b"cmp neg pos");

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
        dec_eq(
            &prod,
            b"10000000000000000000000000000000000000000000000000000000",
        ),
        b"mul 10^30 * 10^25 == 10^55",
    );

    // Signed: (-10^30) * (10^25) is negative; * itself again positive.
    let mut neg_prod = big::Int::new();
    neg_prod.Mul(&big::NewInt(-1), &p); // -10^30
    let mut signed = big::Int::new();
    signed.Mul(&neg_prod, &q); // -10^55
    check(signed.Sign() == -1, b"mul signed negative");
    let mut back = big::Int::new();
    back.Mul(&neg_prod, &neg_prod); // (+) 10^60
    check(
        back.Sign() == 1
            && dec_eq(
                &back,
                b"1000000000000000000000000000000000000000000000000000000000000",
            ),
        b"mul neg*neg == 10^60",
    );

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
    check(
        dec_eq(&x, b"123456789012345678901234567890"),
        b"mul build x",
    );
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
    dividend.Add(&prod, &big::NewInt(7)); // 10^55 + 7
    let mut divisor = big::Int::new();
    divisor.Add(&q, &big::NewInt(3)); // 10^25 + 3
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
    check(
        nrem.Sign() >= 0 && nrem.Cmp(&divisor) == -1,
        b"divmod neg 0<=r<d",
    );

    // Exact division: (10^55) / (10^25) == 10^30, remainder 0.
    let mut exq = big::Int::new();
    let mut exr = big::Int::new();
    exq.DivMod(&prod, &q, &mut exr);
    check(
        dec_eq(&exq, b"1000000000000000000000000000000") && exr.Sign() == 0,
        b"div exact 10^55/10^25",
    );

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
    check(
        eres.Sign() >= 0 && eres.Cmp(&emod) == -1,
        b"exp big in range",
    );
    // Exact value cross-checked against Python's pow(base, exp, mod).
    check(
        dec_eq(&eres, b"73926293254195207749682038714681681753283032610409"),
        b"exp big exact value",
    );

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
    s.Sub(&big::NewInt(-5), &big::NewInt(8)); // -5 - 8 = -13
    check(s.Int64() == -13, b"sub -5-8");
    s.Sub(&big::NewInt(-5), &big::NewInt(-8)); // -5 - (-8) = 3
    check(s.Int64() == 3, b"sub -5-(-8)");
    s.Sub(&big::NewInt(7), &big::NewInt(7)); // 7 - 7 = 0
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
    check(big::NewInt(0).BitLen() == 0, b"bitlen 0");
    check(big::NewInt(1).BitLen() == 1, b"bitlen 1");
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
    let bx = big::NewInt(0b1010); // = 10
    check(bx.Bit(0) == 0, b"bit 10[0]");
    check(bx.Bit(1) == 1, b"bit 10[1]");
    check(bx.Bit(2) == 0, b"bit 10[2]");
    check(bx.Bit(3) == 1, b"bit 10[3]");
    check(bx.Bit(99) == 0, b"bit 10[99] above range");
    // Negative: -1 is all-ones in two's complement -> every bit is 1.
    let bneg = big::NewInt(-1);
    check(
        bneg.Bit(0) == 1 && bneg.Bit(5) == 1 && bneg.Bit(70) == 1,
        b"bit -1 all ones",
    );
    // -2 == ...11111110 -> bit0=0, bit1..=1.
    let bneg2 = big::NewInt(-2);
    check(
        bneg2.Bit(0) == 0 && bneg2.Bit(1) == 1 && bneg2.Bit(8) == 1,
        b"bit -2",
    );

    // ── SetBit ─────────────────────────────────────────────────────
    let mut sb = big::Int::new();
    sb.SetBit(&big::NewInt(0), 4, 1); // 0 | (1<<4) = 16
    check(sb.Int64() == 16, b"setbit 0 bit4=1");
    sb.SetBit(&big::NewInt(0b1111), 1, 0); // 15 &^ (1<<1) = 13
    check(sb.Int64() == 13, b"setbit 15 bit1=0");
    sb.SetBit(&big::NewInt(5), 1, 1); // 5 | 2 = 7
    check(sb.Int64() == 7, b"setbit 5 bit1=1");
    // Negative: -1 with bit0 cleared == -2 (two's complement).
    sb.SetBit(&big::NewInt(-1), 0, 0);
    check(sb.Int64() == -2, b"setbit -1 bit0=0 -> -2");

    // ── Bitwise on positive operands ───────────────────────────────
    // 0b1100 (12) & 0b1010 (10) = 0b1000 (8)
    let mut bw = big::Int::new();
    bw.And(&big::NewInt(12), &big::NewInt(10));
    check(bw.Int64() == 8, b"and 12&10");
    bw.Or(&big::NewInt(12), &big::NewInt(10)); // = 14
    check(bw.Int64() == 14, b"or 12|10");
    bw.Xor(&big::NewInt(12), &big::NewInt(10)); // = 6
    check(bw.Int64() == 6, b"xor 12^10");
    bw.AndNot(&big::NewInt(12), &big::NewInt(10)); // 12 &^ 10 = 4
    check(bw.Int64() == 4, b"andnot 12&^10");
    bw.Not(&big::NewInt(0)); // ^0 = -1
    check(bw.Int64() == -1, b"not 0 == -1");
    bw.Not(&big::NewInt(5)); // ^5 = -6
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
    sh.Lsh(&big::NewInt(1), 10); // 1 << 10 = 1024
    check(sh.Int64() == 1024, b"lsh 1<<10");
    sh.Lsh(&big::NewInt(3), 40); // 3 << 40
    check(dec_eq(&sh, b"3298534883328"), b"lsh 3<<40");
    sh.Lsh(&big::NewInt(-1), 4); // -1 << 4 = -16
    check(sh.Int64() == -16, b"lsh -1<<4 == -16");
    sh.Rsh(&big::NewInt(1024), 10); // 1024 >> 10 = 1
    check(sh.Int64() == 1, b"rsh 1024>>10");
    sh.Rsh(&big::NewInt(255), 4); // 255 >> 4 = 15
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
        check(
            t.Text(10).as_bytes() == t.String().as_bytes(),
            b"text10 == string",
        );
        // Round-trip through bases 2, 8, 10, 16.
        check(t.Text(2).as_bytes()
            == b"1100011101110100100001111111101101100001101110011111000001110111001001110001111110000101011010010",
            b"text base2 large");
        check(
            t.Text(8).as_bytes() == b"143564417755415637016711617605322",
            b"text base8 large",
        );
        check(
            t.Text(16).as_bytes() == b"18ee90ff6c373e0ee4e3f0ad2",
            b"text base16 large",
        );
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
        check(
            t.Text(16).as_bytes() == b"-2e7074d9c994179b09b1bc62f21c70cb1",
            b"text negative base16",
        );
        // Round-trip via base 16.
        let mut u = big::Int::new();
        u.SetString(
            string::from_bytes(b"-2e7074d9c994179b09b1bc62f21c70cb1"),
            16,
        );
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
        check(
            t.Text(36).as_bytes() == b"byw97um9s91dlz68tsi",
            b"text base36",
        );
        check(
            t.Text(62).as_bytes() == b"2AyLS9BKAMjjsWHR0",
            b"text base62",
        );
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
        check(
            ok && us.Int64() == 0xdeadbeef,
            b"setstring base0 underscores",
        );
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
        check(
            back.Cmp(&t) == 0 && back.Sign() == 1,
            b"setbytes magnitude only",
        );

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
        check(
            rt.len() == 3
                && rt[int::from(0)] == 1
                && rt[int::from(1)] == 2
                && rt[int::from(2)] == 3,
            b"bytes 010203 roundtrip",
        );

        // Leading zero bytes in the input are ignored.
        let mut lz = big::Int::new();
        let padded: [u8; 5] = [0x00, 0x00, 0x01, 0x02, 0x03];
        lz.SetBytes(slice::__from_vec(padded.to_vec()));
        check(lz.Int64() == 0x010203, b"setbytes leading zeros ignored");
    }

    // ── Quo / Rem / QuoRem (truncated / T-division) ────────────────
    // Truncated division: quotient rounds toward zero, remainder sign
    // follows the dividend. Negative cases differ from Euclidean Div/Mod.
    {
        // -7 Quo 2 == -3   (Euclidean Div gives -4)
        let mut tq = big::Int::new();
        tq.Quo(&big::NewInt(-7), &big::NewInt(2));
        check(tq.Int64() == -3, b"quo -7/2 == -3");
        // -7 Rem 2 == -1   (Euclidean Mod gives 1)
        let mut tr = big::Int::new();
        tr.Rem(&big::NewInt(-7), &big::NewInt(2));
        check(tr.Int64() == -1, b"rem -7/2 == -1");
        // -7 Quo -2 == 3
        tq.Quo(&big::NewInt(-7), &big::NewInt(-2));
        check(tq.Int64() == 3, b"quo -7/-2 == 3");
        // 7 Quo -2 == -3
        tq.Quo(&big::NewInt(7), &big::NewInt(-2));
        check(tq.Int64() == -3, b"quo 7/-2 == -3");
        // 7 Rem -2 == 1  (remainder sign follows dividend)
        tr.Rem(&big::NewInt(7), &big::NewInt(-2));
        check(tr.Int64() == 1, b"rem 7/-2 == 1");
        // -7 Rem -2 == -1
        tr.Rem(&big::NewInt(-7), &big::NewInt(-2));
        check(tr.Int64() == -1, b"rem -7/-2 == -1");
        // Positive: 17 Quo 5 == 3, 17 Rem 5 == 2.
        tq.Quo(&big::NewInt(17), &big::NewInt(5));
        check(tq.Int64() == 3, b"quo 17/5 == 3");
        tr.Rem(&big::NewInt(17), &big::NewInt(5));
        check(tr.Int64() == 2, b"rem 17/5 == 2");
        // Exact division: remainder zero must not be flagged negative.
        let mut eq = big::Int::new();
        let mut er = big::Int::new();
        eq.QuoRem(&big::NewInt(-12), &big::NewInt(3), &mut er);
        check(eq.Int64() == -4 && er.Sign() == 0, b"quorem -12/3 exact");

        // QuoRem identity for the signed small cases: y*q + r == x.
        for &(xv, yv) in &[(-7i64, 2i64), (-7, -2), (7, -2), (13, 4), (-13, 4)] {
            let mut q = big::Int::new();
            let mut r = big::Int::new();
            q.QuoRem(&big::NewInt(xv), &big::NewInt(yv), &mut r);
            let mut yq = big::Int::new();
            yq.Mul(&big::NewInt(yv), &q);
            let mut recon = big::Int::new();
            recon.Add(&yq, &r);
            check(recon.Int64() == xv, b"quorem identity y*q+r==x");
        }

        // Multi-limb Quo: (10^55 + 7) Quo (10^25 + 3) — operands far
        // exceed 64 bits. Verify via the truncated identity y*q + r == x
        // with |r| < |y| and r sign following x.
        let mut mq = big::Int::new();
        mq.Quo(&dividend, &divisor);
        let mut mr = big::Int::new();
        mr.Rem(&dividend, &divisor);
        {
            let mut yq = big::Int::new();
            yq.Mul(&divisor, &mq);
            let mut recon = big::Int::new();
            recon.Add(&yq, &mr);
            let mut absr = big::Int::new();
            absr.Abs(&mr);
            check(
                recon.Cmp(&dividend) == 0 && absr.Cmp(&divisor) == -1,
                b"quo multi-limb identity",
            );
        }

        // Multi-limb QuoRem with a negative dividend: -(10^55+7) / (10^25+3).
        // Truncated: quotient is the negation of the positive case,
        // remainder sign follows the (negative) dividend.
        let mut nmq = big::Int::new();
        let mut nmr = big::Int::new();
        nmq.QuoRem(&neg_dividend, &divisor, &mut nmr);
        {
            let mut yq = big::Int::new();
            yq.Mul(&divisor, &nmq);
            let mut recon = big::Int::new();
            recon.Add(&yq, &nmr);
            check(
                recon.Cmp(&neg_dividend) == 0,
                b"quorem multi-limb neg identity",
            );
            // Truncated quotient must equal -(positive quotient).
            let mut negq = big::Int::new();
            negq.Neg(&mq);
            check(nmq.Cmp(&negq) == 0, b"quorem multi-limb neg quotient");
            // Remainder is non-positive (sign follows negative dividend).
            check(nmr.Sign() <= 0, b"quorem multi-limb neg rem sign");
        }

        // Exact multi-limb: (10^55) Quo (10^25) == 10^30, remainder 0.
        let mut xeq = big::Int::new();
        let mut xer = big::Int::new();
        xeq.QuoRem(&prod, &q, &mut xer);
        check(
            dec_eq(&xeq, b"1000000000000000000000000000000") && xer.Sign() == 0,
            b"quorem exact 10^55/10^25",
        );
    }

    // ── GCD ────────────────────────────────────────────────────────
    {
        // Coprime small pair: gcd(35, 64) == 1.
        let mut g = big::Int::new();
        g.GCD(goish::nil, goish::nil, &big::NewInt(35), &big::NewInt(64));
        check(g.Int64() == 1, b"gcd 35,64 == 1");

        // Non-coprime small pair: gcd(12, 18) == 6.
        g.GCD(goish::nil, goish::nil, &big::NewInt(12), &big::NewInt(18));
        check(g.Int64() == 6, b"gcd 12,18 == 6");

        // gcd(0,0) == 0.
        g.GCD(goish::nil, goish::nil, &big::NewInt(0), &big::NewInt(0));
        check(g.Sign() == 0, b"gcd 0,0 == 0");

        // gcd(a,0) == |a|, gcd(0,b) == |b|.
        g.GCD(goish::nil, goish::nil, &big::NewInt(-42), &big::NewInt(0));
        check(g.Int64() == 42, b"gcd -42,0 == 42");
        g.GCD(goish::nil, goish::nil, &big::NewInt(0), &big::NewInt(-99));
        check(g.Int64() == 99, b"gcd 0,-99 == 99");

        // Negative operands — gcd is always >= 0.
        g.GCD(goish::nil, goish::nil, &big::NewInt(-12), &big::NewInt(-18));
        check(g.Int64() == 6 && g.Sign() >= 0, b"gcd -12,-18 == 6");

        // Multi-limb: gcd(10^30, 10^25) == 10^25.
        let p30 = pow10(30);
        let p25 = pow10(25);
        g.GCD(goish::nil, goish::nil, &p30, &p25);
        check(
            g.Cmp(&p25) == 0 && dec_eq(&g, b"10000000000000000000000000"),
            b"gcd 10^30,10^25 == 10^25",
        );

        // Multi-limb coprime: (10^25 + 1) and (10^25 + 3) — both odd,
        // differ by 2, so gcd is 1.
        let mut bp = big::Int::new();
        bp.Add(&p25, &big::NewInt(1));
        let mut bq = big::Int::new();
        bq.Add(&p25, &big::NewInt(3));
        g.GCD(goish::nil, goish::nil, &bp, &bq);
        check(g.Int64() == 1, b"gcd big coprime == 1");

        // Bézout identity: a*x + b*y == gcd, for several pairs.
        for &(av, bv) in &[(35i64, 64i64), (12, 18), (-12, 18), (240, 46), (-17, -5)] {
            let a = big::NewInt(av);
            let b = big::NewInt(bv);
            let mut gz = big::Int::new();
            let mut xc = big::Int::new();
            let mut yc = big::Int::new();
            gz.GCD(&mut xc, &mut yc, &a, &b);
            // recon = a*x + b*y
            let mut ax = big::Int::new();
            ax.Mul(&a, &xc);
            let mut by = big::Int::new();
            by.Mul(&b, &yc);
            let mut recon = big::Int::new();
            recon.Add(&ax, &by);
            check(recon.Cmp(&gz) == 0, b"gcd bezout a*x+b*y==g");
        }

        // Bézout on multi-limb operands.
        {
            let a = pow10(30);
            let mut b = big::Int::new();
            b.Add(&pow10(20), &big::NewInt(7));
            let mut gz = big::Int::new();
            let mut xc = big::Int::new();
            let mut yc = big::Int::new();
            gz.GCD(&mut xc, &mut yc, &a, &b);
            let mut ax = big::Int::new();
            ax.Mul(&a, &xc);
            let mut by = big::Int::new();
            by.Mul(&b, &yc);
            let mut recon = big::Int::new();
            recon.Add(&ax, &by);
            check(recon.Cmp(&gz) == 0, b"gcd bezout multi-limb");
        }
    }

    // ── ModInverse ─────────────────────────────────────────────────
    {
        // 3 * 4 == 12 == 1 (mod 11) -> inverse of 3 mod 11 is 4.
        let mut inv = big::Int::new();
        inv.ModInverse(&big::NewInt(3), &big::NewInt(11));
        check(inv.Int64() == 4, b"modinverse 3 mod 11 == 4");

        // Verify z*g mod n == 1 for several coprime pairs.
        for &(gv, nv) in &[(3i64, 11i64), (7, 26), (17, 3120), (2, 9), (10, 17)] {
            let g = big::NewInt(gv);
            let n = big::NewInt(nv);
            let mut z = big::Int::new();
            z.ModInverse(&g, &n);
            let mut prod = big::Int::new();
            prod.Mul(&z, &g);
            let mut r = big::Int::new();
            r.Mod(&prod, &n);
            check(r.Int64() == 1, b"modinverse z*g mod n == 1");
        }

        // Negative g is reduced first: inverse of -3 mod 11 == 7 (since -3≡8, 8*7=56≡1).
        let mut invn = big::Int::new();
        invn.ModInverse(&big::NewInt(-3), &big::NewInt(11));
        {
            let mut prod = big::Int::new();
            prod.Mul(&invn, &big::NewInt(-3));
            let mut r = big::Int::new();
            r.Mod(&prod, &big::NewInt(11));
            check(r.Int64() == 1, b"modinverse negative g");
        }

        // Multi-limb modulus: inverse of 65537 mod (10^25 + 1).
        {
            let mut n = big::Int::new();
            n.Add(&pow10(25), &big::NewInt(1));
            let gv = big::NewInt(65537);
            let mut z = big::Int::new();
            z.ModInverse(&gv, &n);
            let mut prod = big::Int::new();
            prod.Mul(&z, &gv);
            let mut r = big::Int::new();
            r.Mod(&prod, &n);
            check(r.Int64() == 1, b"modinverse multi-limb mod");
            // Result is normalised into [0, n).
            check(
                z.Sign() >= 0 && z.Cmp(&n) == -1,
                b"modinverse result in range",
            );
        }

        // Non-coprime: gcd(6,9)==3 != 1 — no inverse. self stays unchanged.
        let mut nc = big::NewInt(12345);
        nc.ModInverse(&big::NewInt(6), &big::NewInt(9));
        check(nc.Int64() == 12345, b"modinverse non-coprime leaves self");
    }

    // ── Exp with negative exponent ─────────────────────────────────
    {
        // 3^(-1) mod 11 == modinverse(3,11) == 4.
        let mut e = big::Int::new();
        e.Exp(&big::NewInt(3), &big::NewInt(-1), &big::NewInt(11));
        check(e.Int64() == 4, b"exp 3^-1 mod 11 == 4");

        // 3^(-2) mod 11 == (3^-1)^2 == 4^2 == 16 == 5.
        e.Exp(&big::NewInt(3), &big::NewInt(-2), &big::NewInt(11));
        check(e.Int64() == 5, b"exp 3^-2 mod 11 == 5");

        // x.Exp(base,-e,m) == ModInverse(base,m)^e mod m, cross-checked.
        for &(bv, ev, mv) in &[(3i64, 3i64, 11i64), (7, 4, 26), (2, 5, 9), (10, 3, 17)] {
            let base = big::NewInt(bv);
            let modulus = big::NewInt(mv);
            let mut lhs = big::Int::new();
            lhs.Exp(&base, &big::NewInt(-ev), &modulus);
            // rhs = ModInverse(base,m) ^ e mod m
            let mut inv = big::Int::new();
            inv.ModInverse(&base, &modulus);
            let mut rhs = big::Int::new();
            rhs.Exp(&inv, &big::NewInt(ev), &modulus);
            check(lhs.Cmp(&rhs) == 0, b"exp neg == modinverse^e");
        }

        // y < 0 && m == 0 -> 1 (Go's documented case, unchanged).
        let mut z0 = big::Int::new();
        z0.Exp(&big::NewInt(5), &big::NewInt(-3), &big::NewInt(0));
        check(z0.Int64() == 1, b"exp neg exp, m==0 -> 1");

        // Multi-limb negative exponent: base coprime to a big modulus.
        {
            let mut m = big::Int::new();
            m.Add(&pow10(25), &big::NewInt(1));
            let base = big::NewInt(65537);
            let mut lhs = big::Int::new();
            lhs.Exp(&base, &big::NewInt(-2), &m);
            // rhs = inv^2 mod m
            let mut inv = big::Int::new();
            inv.ModInverse(&base, &m);
            let mut rhs = big::Int::new();
            rhs.Exp(&inv, &big::NewInt(2), &m);
            check(lhs.Cmp(&rhs) == 0 && lhs.Sign() >= 0, b"exp neg multi-limb");
        }
    }

    // ── Sqrt ───────────────────────────────────────────────────────
    {
        // Perfect squares.
        let mut sq = big::Int::new();
        sq.Sqrt(&big::NewInt(0));
        check(sq.Sign() == 0, b"sqrt 0 == 0");
        sq.Sqrt(&big::NewInt(1));
        check(sq.Int64() == 1, b"sqrt 1 == 1");
        sq.Sqrt(&big::NewInt(144));
        check(sq.Int64() == 12, b"sqrt 144 == 12");
        sq.Sqrt(&big::NewInt(1000000));
        check(sq.Int64() == 1000, b"sqrt 10^6 == 1000");

        // Non-perfect squares — floor behaviour.
        sq.Sqrt(&big::NewInt(15));
        check(sq.Int64() == 3, b"sqrt 15 == 3 floor");
        sq.Sqrt(&big::NewInt(99));
        check(sq.Int64() == 9, b"sqrt 99 == 9 floor");
        sq.Sqrt(&big::NewInt(2));
        check(sq.Int64() == 1, b"sqrt 2 == 1 floor");
        sq.Sqrt(&big::NewInt(8));
        check(sq.Int64() == 2, b"sqrt 8 == 2 floor");

        // Multi-limb perfect square: sqrt of (10^20)^2 == 10^20.
        let p20 = pow10(20);
        let mut sqr = big::Int::new();
        sqr.Mul(&p20, &p20); // 10^40
        let mut root = big::Int::new();
        root.Sqrt(&sqr);
        check(root.Cmp(&p20) == 0, b"sqrt (10^20)^2 == 10^20");

        // Multi-limb non-perfect square: sqrt(10^40 - 1) == 10^20 - 1.
        let mut one = big::NewInt(1);
        let mut sqr_m1 = big::Int::new();
        sqr_m1.Sub(&sqr, &big::NewInt(1)); // 10^40 - 1
        let mut root2 = big::Int::new();
        root2.Sqrt(&sqr_m1);
        let mut p20_m1 = big::Int::new();
        p20_m1.Sub(&p20, &big::NewInt(1)); // 10^20 - 1
        check(
            root2.Cmp(&p20_m1) == 0,
            b"sqrt (10^40 - 1) floor == 10^20 - 1",
        );
        // Verify the floor property: root² <= x < (root+1)².
        {
            let mut rr = big::Int::new();
            rr.Mul(&root2, &root2);
            let mut rp1 = big::Int::new();
            rp1.Add(&root2, &one);
            let mut rp1sq = big::Int::new();
            rp1sq.Mul(&rp1, &rp1);
            check(
                rr.Cmp(&sqr_m1) <= 0 && sqr_m1.Cmp(&rp1sq) == -1,
                b"sqrt multi-limb floor property",
            );
        }
        let _ = &mut one;
    }

    // ── ProbablyPrime ──────────────────────────────────────────────
    {
        // Known small primes.
        check(big::NewInt(2).ProbablyPrime(0), b"prime 2");
        check(big::NewInt(3).ProbablyPrime(0), b"prime 3");
        check(big::NewInt(97).ProbablyPrime(0), b"prime 97");
        check(big::NewInt(7919).ProbablyPrime(0), b"prime 7919");
        // 2^31 - 1 == 2147483647 is a Mersenne prime.
        check(big::NewInt(2147483647).ProbablyPrime(0), b"prime 2^31-1");

        // Known composites.
        check(!big::NewInt(1).ProbablyPrime(0), b"composite 1");
        check(!big::NewInt(0).ProbablyPrime(0), b"composite 0");
        check(!big::NewInt(4).ProbablyPrime(0), b"composite 4");
        check(!big::NewInt(100).ProbablyPrime(0), b"composite 100");
        check(!big::NewInt(7917).ProbablyPrime(0), b"composite 7917");
        // 561 is the smallest Carmichael number — fools the Fermat test.
        check(
            !big::NewInt(561).ProbablyPrime(0),
            b"composite 561 carmichael",
        );
        // Negative receiver is never prime.
        check(!big::NewInt(-7).ProbablyPrime(0), b"composite negative");

        // Multi-limb prime: 10^20 + 39 is prime (cross-checked).
        let mut bigprime = big::Int::new();
        bigprime.Add(&pow10(20), &big::NewInt(39));
        check(bigprime.ProbablyPrime(0), b"prime multi-limb 10^20+39");

        // Multi-limb composite: 10^20 (obviously even / divisible).
        check(!pow10(20).ProbablyPrime(0), b"composite multi-limb 10^20");
        // Multi-limb composite with no small factors: (10^10+19)^2,
        // a product of two equal large primes.
        {
            let mut f = big::Int::new();
            f.Add(&pow10(10), &big::NewInt(19)); // 10^10 + 19, prime
            let mut comp = big::Int::new();
            comp.Mul(&f, &f);
            check(!comp.ProbablyPrime(0), b"composite multi-limb prime^2");
        }
    }

    // ── ModSqrt ────────────────────────────────────────────────────
    {
        // Helper-free verification: z*z mod p == x mod p.
        // p ≡ 3 (mod 4): p = 23.
        {
            let p = big::NewInt(23);
            // x = 2 is a residue mod 23 (5^2 = 25 == 2).
            let mut z = big::Int::new();
            z.ModSqrt(&big::NewInt(2), &p);
            let mut zz = big::Int::new();
            zz.Mul(&z, &z);
            let mut r = big::Int::new();
            r.Mod(&zz, &p);
            check(r.Int64() == 2, b"modsqrt p=23 (3mod4) z^2==2");

            // x = 0 -> z = 0.
            let mut z0 = big::Int::new();
            z0.ModSqrt(&big::NewInt(0), &p);
            check(z0.Sign() == 0, b"modsqrt x=0 -> 0");

            // x reduced first: x = 25 == 2 mod 23, same root squared.
            let mut z25 = big::Int::new();
            z25.ModSqrt(&big::NewInt(25), &p);
            let mut z25sq = big::Int::new();
            z25sq.Mul(&z25, &z25);
            let mut r25 = big::Int::new();
            r25.Mod(&z25sq, &p);
            check(r25.Int64() == 2, b"modsqrt x reduced mod p");

            // Sweep every residue: for a in [1,22], (a*a) has a root.
            let mut all_ok = true;
            for a in 1i64..23 {
                let mut xv = big::Int::new();
                xv.Mod(&big::NewInt(a * a), &p); // quadratic residue
                let mut zr = big::Int::new();
                zr.ModSqrt(&xv, &p);
                let mut zrsq = big::Int::new();
                zrsq.Mul(&zr, &zr);
                let mut rr = big::Int::new();
                rr.Mod(&zrsq, &p);
                if rr.Cmp(&xv) != 0 {
                    all_ok = false;
                }
            }
            check(all_ok, b"modsqrt p=23 sweep all residues");
        }

        // p ≡ 1 (mod 4): p = 17 — exercises Tonelli-Shanks.
        {
            let p = big::NewInt(17);
            // x = 2 is a residue mod 17 (6^2 = 36 == 2).
            let mut z = big::Int::new();
            z.ModSqrt(&big::NewInt(2), &p);
            let mut zz = big::Int::new();
            zz.Mul(&z, &z);
            let mut r = big::Int::new();
            r.Mod(&zz, &p);
            check(r.Int64() == 2, b"modsqrt p=17 (1mod4) z^2==2");

            // Sweep every residue mod 17.
            let mut all_ok = true;
            for a in 1i64..17 {
                let mut xv = big::Int::new();
                xv.Mod(&big::NewInt(a * a), &p);
                let mut zr = big::Int::new();
                zr.ModSqrt(&xv, &p);
                let mut zrsq = big::Int::new();
                zrsq.Mul(&zr, &zr);
                let mut rr = big::Int::new();
                rr.Mod(&zrsq, &p);
                if rr.Cmp(&xv) != 0 {
                    all_ok = false;
                }
            }
            check(all_ok, b"modsqrt p=17 sweep all residues");
        }

        // p ≡ 1 (mod 4): p = 13 — another Tonelli-Shanks check.
        {
            let p = big::NewInt(13);
            // x = 3 is a residue mod 13 (4^2 = 16 == 3).
            let mut z = big::Int::new();
            z.ModSqrt(&big::NewInt(3), &p);
            let mut zz = big::Int::new();
            zz.Mul(&z, &z);
            let mut r = big::Int::new();
            r.Mod(&zz, &p);
            check(r.Int64() == 3, b"modsqrt p=13 (1mod4) z^2==3");
        }

        // Non-residue: 5 is not a quadratic residue mod 23.
        // self must be left unchanged (precondition violated).
        {
            let p = big::NewInt(23);
            let mut nr = big::NewInt(99999);
            nr.ModSqrt(&big::NewInt(5), &p);
            check(nr.Int64() == 99999, b"modsqrt non-residue leaves self");
        }

        // Multi-limb modulus: a large prime p ≡ 3 (mod 4).
        // p = 10^20 + 39 (prime). 39 mod 4 == 3, so p ≡ 3 mod 4.
        {
            let mut p = big::Int::new();
            p.Add(&pow10(20), &big::NewInt(39));
            // x = 4 has a known root (2), exercising the multi-limb
            // p ≡ 3 mod 4 path: z² mod p must equal x.
            let mut z = big::Int::new();
            z.ModSqrt(&big::NewInt(4), &p);
            let mut zz = big::Int::new();
            zz.Mul(&z, &z);
            let mut r = big::Int::new();
            r.Mod(&zz, &p);
            check(r.Int64() == 4, b"modsqrt multi-limb p z^2==x");
        }
    }

    // ── SetUint64 / Uint64 round-trip ──────────────────────────────
    {
        let mut z = big::Int::new();
        z.SetUint64(42);
        check(z.Uint64() == 42, b"setuint64 small");
        check(z.Sign() == 1, b"setuint64 positive");
        // A value above i64::MAX must survive the round-trip.
        let big_u: u64 = 0xFFFF_FFFF_FFFF_FFFF;
        z.SetUint64(big_u);
        check(z.Uint64() == big_u, b"setuint64 above i64max");
        check(z.Sign() == 1, b"setuint64 above i64max positive");
        // 2^63 exactly.
        let mid: u64 = 0x8000_0000_0000_0000;
        z.SetUint64(mid);
        check(z.Uint64() == mid, b"setuint64 2^63");
        // Uint64 bit-truncates the magnitude, ignoring sign (Go).
        let mut nz = big::Int::new();
        nz.SetInt64(-5);
        check(nz.Uint64() == 5, b"uint64 ignores sign");
        // Uint64 of zero is 0.
        check(big::NewInt(0).Uint64() == 0, b"uint64 zero");
    }

    // ── IsInt64 / IsUint64 boundary cases ──────────────────────────
    {
        let mut z = big::Int::new();
        check(big::NewInt(0).IsInt64(), b"isint64 zero");
        check(big::NewInt(i64::MAX).IsInt64(), b"isint64 i64max");
        check(big::NewInt(i64::MIN).IsInt64(), b"isint64 i64min");
        // i64::MAX + 1 does not fit a signed i64.
        z.SetUint64((i64::MAX as u64) + 1);
        check(!z.IsInt64(), b"isint64 i64max+1 false");
        check(z.IsUint64(), b"isuint64 i64max+1 true");
        // u64::MAX fits unsigned but not signed.
        z.SetUint64(u64::MAX);
        check(!z.IsInt64(), b"isint64 u64max false");
        check(z.IsUint64(), b"isuint64 u64max true");
        // A negative value never fits a u64.
        check(!big::NewInt(-1).IsUint64(), b"isuint64 neg false");
        check(big::NewInt(-1).IsInt64(), b"isint64 neg one");
        // i64::MIN magnitude (2^63) is the largest negative that fits.
        let mut neg63 = big::Int::new();
        neg63.SetUint64((i64::MAX as u64) + 1);
        neg63.Neg(&neg63.clone());
        check(neg63.IsInt64(), b"isint64 -2^63");
        // -(2^63 + 1) does not fit.
        let mut neg63p1 = big::Int::new();
        neg63p1.SetUint64((i64::MAX as u64) + 2);
        neg63p1.Neg(&neg63p1.clone());
        check(!neg63p1.IsInt64(), b"isint64 -(2^63+1) false");
        // A multi-word value fits neither.
        let huge = pow2(100);
        check(!huge.IsInt64(), b"isint64 2^100 false");
        check(!huge.IsUint64(), b"isuint64 2^100 false");
    }

    // ── CmpAbs ─────────────────────────────────────────────────────
    {
        let a = big::NewInt(-100);
        let b = big::NewInt(50);
        check(a.CmpAbs(&b) == 1, b"cmpabs |-100|>|50|");
        check(b.CmpAbs(&a) == -1, b"cmpabs |50|<|-100|");
        // Opposite signs, equal magnitude → 0.
        let p = big::NewInt(77);
        let n = big::NewInt(-77);
        check(p.CmpAbs(&n) == 0, b"cmpabs opposite signs equal");
        check(n.CmpAbs(&p) == 0, b"cmpabs opposite signs equal 2");
        check(big::NewInt(0).CmpAbs(&big::NewInt(0)) == 0, b"cmpabs zero");
        // Multi-word magnitudes.
        check(pow2(200).CmpAbs(&pow2(100)) == 1, b"cmpabs 2^200>2^100");
    }

    // ── Binomial ───────────────────────────────────────────────────
    {
        let mut z = big::Int::new();
        z.Binomial(10, 3);
        check(z.Int64() == 120, b"binomial C(10,3)==120");
        z.Binomial(52, 5);
        check(z.Int64() == 2598960, b"binomial C(52,5)==2598960");
        z.Binomial(5, 0);
        check(z.Int64() == 1, b"binomial C(5,0)==1");
        z.Binomial(5, 5);
        check(z.Int64() == 1, b"binomial C(5,5)==1");
        z.Binomial(5, 6);
        check(z.Int64() == 0, b"binomial C(5,6)==0 (k>n)");
        z.Binomial(7, 4);
        check(z.Int64() == 35, b"binomial C(7,4)==35");
        // Large: C(67,33) = 14226520737620288370.
        z.Binomial(67, 33);
        check(dec_eq(&z, b"14226520737620288370"), b"binomial C(67,33)");
    }

    // ── MulRange ───────────────────────────────────────────────────
    {
        let mut z = big::Int::new();
        z.MulRange(1, 10);
        check(z.Int64() == 3628800, b"mulrange 1..10 == 10!");
        // Empty range → 1.
        z.MulRange(5, 2);
        check(z.Int64() == 1, b"mulrange empty == 1");
        // Range including 0 → 0.
        z.MulRange(-3, 4);
        check(z.Int64() == 0, b"mulrange incl 0 == 0");
        // Single element.
        z.MulRange(7, 7);
        check(z.Int64() == 7, b"mulrange 7..7 == 7");
        // Negative range, even count of factors → positive.
        // (-4)*(-3) = 12, count 2 (even).
        z.MulRange(-4, -3);
        check(z.Int64() == 12, b"mulrange -4..-3 == 12");
        // Negative range, odd count of factors → negative.
        // (-3)*(-2)*(-1) = -6, count 3 (odd).
        z.MulRange(-3, -1);
        check(z.Int64() == -6, b"mulrange -3..-1 == -6");
        // Larger product: 1..20 = 20! = 2432902008176640000.
        z.MulRange(1, 20);
        check(dec_eq(&z, b"2432902008176640000"), b"mulrange 1..20 == 20!");
    }

    // ── Float64 ────────────────────────────────────────────────────
    {
        // Exact small values.
        let (f, acc) = big::NewInt(0).Float64();
        check(
            f == 0.0 && acc == big::Accuracy::Exact,
            b"float64 zero exact",
        );
        let (f, acc) = big::NewInt(42).Float64();
        check(
            f == 42.0 && acc == big::Accuracy::Exact,
            b"float64 42 exact",
        );
        let (f, acc) = big::NewInt(-7).Float64();
        check(
            f == -7.0 && acc == big::Accuracy::Exact,
            b"float64 -7 exact",
        );
        // 2^53 is exactly representable.
        let (f, acc) = pow2(53).Float64();
        check(
            f == 9007199254740992.0 && acc == big::Accuracy::Exact,
            b"float64 2^53 exact",
        );
        // 2^60 has only one significant bit → exact despite > 53 bits.
        let (f, acc) = pow2(60).Float64();
        check(
            f == 1152921504606846976.0 && acc == big::Accuracy::Exact,
            b"float64 2^60 exact",
        );
        // 2^54 + 1 cannot be represented exactly: 54 significant bits.
        // It rounds down to 2^54 (even mantissa) → Below.
        let mut inexact = pow2(54);
        inexact.Add(&inexact.clone(), &big::NewInt(1));
        let (f, acc) = inexact.Float64();
        check(
            f == 18014398509481984.0 && acc == big::Accuracy::Below,
            b"float64 2^54+1 below",
        );
        // 2^54 + 3 rounds up to 2^54 + 4 → Above.
        let mut up = pow2(54);
        up.Add(&up.clone(), &big::NewInt(3));
        let (f, acc) = up.Float64();
        check(
            f == 18014398509481988.0 && acc == big::Accuracy::Above,
            b"float64 2^54+3 above",
        );
        // Negative inexact flips Below<->Above: -(2^54+1) → Above.
        let mut negin = pow2(54);
        negin.Add(&negin.clone(), &big::NewInt(1));
        negin.Neg(&negin.clone());
        let (f, acc) = negin.Float64();
        check(
            f == -18014398509481984.0 && acc == big::Accuracy::Above,
            b"float64 -(2^54+1) above",
        );
        // Accuracy::String() values.
        check(
            big::Accuracy::Below.String().as_bytes() == b"Below",
            b"accuracy string below",
        );
        check(
            big::Accuracy::Exact.String().as_bytes() == b"Exact",
            b"accuracy string exact",
        );
        check(
            big::Accuracy::Above.String().as_bytes() == b"Above",
            b"accuracy string above",
        );
    }

    // ── FillBytes ──────────────────────────────────────────────────
    {
        // 0x1234 zero-padded into an 8-byte buffer.
        let z = big::NewInt(0x1234);
        let buf: slice<goish::byte> = slice::__from_vec(alloc::vec![0u8; 8]);
        let out = z.FillBytes(buf);
        check(out.len() == 8, b"fillbytes len 8");
        let mut want = [0u8; 8];
        want[6] = 0x12;
        want[7] = 0x34;
        let mut ok = true;
        for i in 0usize..8 {
            if out[i] != want[i] {
                ok = false;
            }
        }
        check(ok, b"fillbytes left-pad big-endian");
        // Zero fills with all-zero bytes.
        let zb: slice<goish::byte> = slice::__from_vec(alloc::vec![0xFFu8; 4]);
        let zout = big::NewInt(0).FillBytes(zb);
        let mut allzero = true;
        for i in 0usize..4 {
            if zout[i] != 0 {
                allzero = false;
            }
        }
        check(allzero, b"fillbytes zero is all-zero");
        // Exact-fit buffer: 0xABCD into 2 bytes.
        let eb: slice<goish::byte> = slice::__from_vec(alloc::vec![0u8; 2]);
        let eout = big::NewInt(0xABCD).FillBytes(eb);
        check(
            eout[0usize] == 0xAB && eout[1usize] == 0xCD,
            b"fillbytes exact fit",
        );
    }

    // ── Bits / SetBits round-trip ──────────────────────────────────
    {
        // Single-word value.
        let z = big::NewInt(0x1234_5678);
        let bits = z.Bits();
        check(bits.len() == 1, b"bits single word len");
        check(bits[0usize] == 0x1234_5678, b"bits single word value");
        let mut back = big::Int::new();
        back.SetBits(bits);
        check(back.Cmp(&z) == 0, b"setbits single word round-trip");
        // Multi-word value: 2^100 + 2^10.
        let mut mw = pow2(100);
        mw.Add(&mw.clone(), &pow2(10));
        let mwbits = mw.Bits();
        check(mwbits.len() == 2, b"bits multi-word len");
        let mut mwback = big::Int::new();
        mwback.SetBits(mwbits);
        check(mwback.Cmp(&mw) == 0, b"setbits multi-word round-trip");
        // SetBits makes the receiver non-negative.
        let words: slice<big::Word> = slice::__from_vec(alloc::vec![7u64, 0u64]);
        let mut sb = big::Int::new();
        sb.SetInt64(-999); // pre-existing negative state
        sb.SetBits(words);
        check(sb.Sign() == 1, b"setbits forces non-negative");
        check(sb.Int64() == 7, b"setbits drops trailing zero word");
        // Zero round-trip.
        let zbits = big::NewInt(0).Bits();
        check(zbits.len() == 0, b"bits zero is empty");
        // Word value that exercises both u32 halves.
        let mut wmix = big::Int::new();
        let mixed: slice<big::Word> = slice::__from_vec(alloc::vec![0xDEAD_BEEF_CAFE_F00Du64]);
        wmix.SetBits(mixed);
        check(
            wmix.Uint64() == 0xDEAD_BEEF_CAFE_F00D,
            b"setbits both halves",
        );
        let wb = wmix.Bits();
        check(wb[0usize] == 0xDEAD_BEEF_CAFE_F00D, b"bits both halves");
    }

    // ── MarshalText / UnmarshalText round-trip ─────────────────────
    {
        // Build a multi-limb value so the magnitude spans >1 limb.
        let big_pos = pow10(40); // 10^40
        let mut big_neg = big::Int::new();
        big_neg.Neg(&big_pos);
        let cases: [&big::Int; 4] = [
            &big::NewInt(0),
            &big::NewInt(123456789),
            &big::NewInt(-987654321),
            &big_pos,
        ];
        let names: [&[u8]; 4] = [b"zero", b"pos", b"neg", b"multi-limb"];
        for k in 0usize..4 {
            let (txt, err) = cases[k].MarshalText();
            check(err == goish::nil, b"marshaltext nil error");
            let mut back = big::Int::new();
            let derr = back.UnmarshalText(txt);
            check(derr == goish::nil, b"unmarshaltext nil error");
            check(back.Cmp(cases[k]) == 0, names[k]);
        }
        // Negative multi-limb explicitly.
        let (ntxt, _) = big_neg.MarshalText();
        let mut nback = big::Int::new();
        nback.UnmarshalText(ntxt);
        check(nback.Cmp(&big_neg) == 0, b"unmarshaltext neg multi-limb");
        // Text content sanity: decimal, no quotes.
        let (dt, _) = big::NewInt(-42).MarshalText();
        check(&*dt == &b"-42"[..], b"marshaltext content -42");
        // UnmarshalText on invalid input -> non-nil error.
        let bad: slice<goish::byte> = slice::__from_vec(b"12x34".to_vec());
        let mut be = big::Int::new();
        let baderr = be.UnmarshalText(bad);
        check(baderr != goish::nil, b"unmarshaltext invalid -> error");
        let empty: slice<goish::byte> = slice::__from_vec(alloc::vec![]);
        let mut ee = big::Int::new();
        check(
            ee.UnmarshalText(empty) != goish::nil,
            b"unmarshaltext empty -> error",
        );
    }

    // ── MarshalJSON / UnmarshalJSON round-trip + null ──────────────
    {
        let big_pos = pow10(35);
        let cases: [&big::Int; 3] = [&big::NewInt(0), &big::NewInt(-7777), &big_pos];
        let names: [&[u8]; 3] = [b"json zero", b"json neg", b"json multi-limb"];
        for k in 0usize..3 {
            let (j, err) = cases[k].MarshalJSON();
            check(err == goish::nil, b"marshaljson nil error");
            let mut back = big::Int::new();
            let derr = back.UnmarshalJSON(j);
            check(derr == goish::nil, b"unmarshaljson nil error");
            check(back.Cmp(cases[k]) == 0, names[k]);
        }
        // MarshalJSON content: decimal, no quotes.
        let (jc, _) = big::NewInt(12345).MarshalJSON();
        check(&*jc == &b"12345"[..], b"marshaljson content 12345");
        // JSON null leaves the receiver unchanged.
        let mut keep = big::NewInt(555);
        let nullbuf: slice<goish::byte> = slice::__from_vec(b"null".to_vec());
        let nerr = keep.UnmarshalJSON(nullbuf);
        check(nerr == goish::nil, b"unmarshaljson null nil error");
        check(keep.Int64() == 555, b"unmarshaljson null leaves receiver");
    }

    // ── GobEncode / GobDecode round-trip ───────────────────────────
    {
        let mut big_neg = big::Int::new();
        big_neg.Neg(&pow10(50));
        let cases: [&big::Int; 4] = [
            &big::NewInt(0),
            &big::NewInt(424242),
            &big::NewInt(-1),
            &big_neg,
        ];
        let names: [&[u8]; 4] = [
            b"gob zero",
            b"gob pos",
            b"gob neg small",
            b"gob neg multi-limb",
        ];
        for k in 0usize..4 {
            let (enc, eerr) = cases[k].GobEncode();
            check(eerr == goish::nil, b"gobencode nil error");
            let mut back = big::Int::new();
            // Pre-poison the receiver to ensure decode fully overwrites.
            back.SetInt64(-99999);
            let derr = back.GobDecode(enc);
            check(derr == goish::nil, b"gobdecode nil error");
            check(back.Cmp(cases[k]) == 0, names[k]);
        }
        // Multi-limb positive too.
        let mp = pow10(45);
        let (menc, _) = mp.GobEncode();
        let mut mback = big::Int::new();
        mback.GobDecode(menc);
        check(mback.Cmp(&mp) == 0, b"gob pos multi-limb");
        // Empty buffer resets receiver to zero.
        let mut zr = big::NewInt(123);
        let eb: slice<goish::byte> = slice::__from_vec(alloc::vec![]);
        let zerr = zr.GobDecode(eb);
        check(zerr == goish::nil, b"gobdecode empty nil error");
        check(zr.Sign() == 0, b"gobdecode empty resets to zero");
        // Version-mismatch buffer -> non-nil error.
        let badver: slice<goish::byte> = slice::__from_vec(alloc::vec![0xFFu8, 0x01u8]);
        let mut bv = big::Int::new();
        check(
            bv.GobDecode(badver) != goish::nil,
            b"gobdecode bad version -> error",
        );
        // Sign-bit check: encoding of a negative value has bit 0 set.
        let (nenc, _) = big::NewInt(-5).GobEncode();
        check(nenc[0usize] & 1 == 1, b"gobencode negative sign bit");
        let (penc, _) = big::NewInt(5).GobEncode();
        check(penc[0usize] & 1 == 0, b"gobencode positive sign bit clear");
    }

    // ── Append into a non-empty buffer ─────────────────────────────
    {
        let prefix: slice<goish::byte> = slice::__from_vec(b"x=".to_vec());
        let out = big::NewInt(255).Append(prefix, 16);
        check(&*out == &b"x=ff"[..], b"append base16 into non-empty buf");
        let prefix2: slice<goish::byte> = slice::__from_vec(b"n:".to_vec());
        let out2 = big::NewInt(-42).Append(prefix2, 10);
        check(&*out2 == &b"n:-42"[..], b"append base10 negative");
        let prefix3: slice<goish::byte> = slice::__from_vec(b">".to_vec());
        let out3 = big::NewInt(13).Append(prefix3, 2);
        check(&*out3 == &b">1101"[..], b"append base2 into non-empty buf");
    }

    // ── Rat arithmetic + GCD normalization ─────────────────────────
    {
        // Add: 1/2 + 1/3 == 5/6.
        let mut r = big::Rat::new();
        r.Add(&big::NewRat(1, 2), &big::NewRat(1, 3));
        check(r.Num().Cmp(&big::NewInt(5)) == 0, b"rat add num 5");
        check(r.Denom().Cmp(&big::NewInt(6)) == 0, b"rat add den 6");

        // Sub: 5/6 - 1/3 == 1/2.
        let mut s = big::Rat::new();
        s.Sub(&big::NewRat(5, 6), &big::NewRat(1, 3));
        check(s.Num().Cmp(&big::NewInt(1)) == 0, b"rat sub num 1");
        check(s.Denom().Cmp(&big::NewInt(2)) == 0, b"rat sub den 2");

        // Mul: 2/3 * 3/4 == 1/2 (reduced).
        let mut m = big::Rat::new();
        m.Mul(&big::NewRat(2, 3), &big::NewRat(3, 4));
        check(m.Num().Cmp(&big::NewInt(1)) == 0, b"rat mul num 1");
        check(m.Denom().Cmp(&big::NewInt(2)) == 0, b"rat mul den 2");

        // Quo: (1/2) / (3/4) == 2/3.
        let mut q = big::Rat::new();
        q.Quo(&big::NewRat(1, 2), &big::NewRat(3, 4));
        check(q.Num().Cmp(&big::NewInt(2)) == 0, b"rat quo num 2");
        check(q.Denom().Cmp(&big::NewInt(3)) == 0, b"rat quo den 3");

        // norm reduction: 2/4 -> 1/2.
        let red = big::NewRat(2, 4);
        check(red.Num().Cmp(&big::NewInt(1)) == 0, b"rat 2/4 reduces num");
        check(
            red.Denom().Cmp(&big::NewInt(2)) == 0,
            b"rat 2/4 reduces den",
        );

        // norm reduction: 6/8 -> 3/4.
        let mut sf = big::Rat::new();
        sf.SetFrac(&big::NewInt(6), &big::NewInt(8));
        check(sf.Num().Cmp(&big::NewInt(3)) == 0, b"rat 6/8 -> 3/4 num");
        check(sf.Denom().Cmp(&big::NewInt(4)) == 0, b"rat 6/8 -> 3/4 den");

        // Negative denominator: sign moves onto the numerator.
        let mut nd = big::Rat::new();
        nd.SetFrac(&big::NewInt(1), &big::NewInt(-2));
        check(nd.Num().Cmp(&big::NewInt(-1)) == 0, b"rat neg-den num -1");
        check(nd.Denom().Cmp(&big::NewInt(2)) == 0, b"rat neg-den den +2");

        // Zero numerator normalizes to 0/1.
        let mut zr = big::Rat::new();
        zr.SetFrac(&big::NewInt(0), &big::NewInt(7));
        check(zr.Num().Sign() == 0, b"rat 0/7 num zero");
        check(zr.Denom().Cmp(&big::NewInt(1)) == 0, b"rat 0/7 den 1");

        // Neg: -(1/3) == -1/3.
        let mut ng = big::Rat::new();
        ng.Neg(&big::NewRat(1, 3));
        check(ng.Num().Cmp(&big::NewInt(-1)) == 0, b"rat neg num -1");
        check(ng.Denom().Cmp(&big::NewInt(3)) == 0, b"rat neg den 3");

        // Abs: |-2/5| == 2/5.
        let mut ab = big::Rat::new();
        ab.Abs(&big::NewRat(-2, 5));
        check(ab.Num().Cmp(&big::NewInt(2)) == 0, b"rat abs num 2");
        check(ab.Sign() == 1, b"rat abs sign +1");

        // Inv: 1/(3/4) == 4/3.
        let mut iv = big::Rat::new();
        iv.Inv(&big::NewRat(3, 4));
        check(iv.Num().Cmp(&big::NewInt(4)) == 0, b"rat inv num 4");
        check(iv.Denom().Cmp(&big::NewInt(3)) == 0, b"rat inv den 3");
        // Inv of a negative keeps the denominator positive.
        let mut ivn = big::Rat::new();
        ivn.Inv(&big::NewRat(-2, 5));
        check(ivn.Num().Cmp(&big::NewInt(-5)) == 0, b"rat inv neg num -5");
        check(ivn.Denom().Cmp(&big::NewInt(2)) == 0, b"rat inv neg den 2");

        // Cmp: 1/3 < 1/2 < 2/3, with equality.
        check(
            big::NewRat(1, 3).Cmp(&big::NewRat(1, 2)) == -1,
            b"rat cmp lt",
        );
        check(
            big::NewRat(1, 2).Cmp(&big::NewRat(2, 4)) == 0,
            b"rat cmp eq",
        );
        check(
            big::NewRat(2, 3).Cmp(&big::NewRat(1, 2)) == 1,
            b"rat cmp gt",
        );

        // Sign.
        check(big::NewRat(-1, 4).Sign() == -1, b"rat sign neg");
        check(big::NewRat(0, 4).Sign() == 0, b"rat sign zero");
        check(big::NewRat(3, 4).Sign() == 1, b"rat sign pos");

        // IsInt: 4/2 reduces to 2/1 (int); 1/2 is not.
        check(big::NewRat(4, 2).IsInt(), b"rat 4/2 is int");
        check(!big::NewRat(1, 2).IsInt(), b"rat 1/2 not int");

        // SetInt64 / SetUint64 / SetFrac64.
        let mut si = big::Rat::new();
        si.SetInt64(-7);
        check(si.Num().Cmp(&big::NewInt(-7)) == 0, b"rat setint64 num");
        check(si.IsInt(), b"rat setint64 is int");
        let mut su = big::Rat::new();
        su.SetUint64(42);
        check(su.Num().Cmp(&big::NewInt(42)) == 0, b"rat setuint64 num");
        check(su.IsInt(), b"rat setuint64 is int");
        let mut s64 = big::Rat::new();
        s64.SetFrac64(10, -4);
        check(
            s64.Num().Cmp(&big::NewInt(-5)) == 0,
            b"rat setfrac64 num -5",
        );
        check(
            s64.Denom().Cmp(&big::NewInt(2)) == 0,
            b"rat setfrac64 den 2",
        );

        // Aliasing: r.Add(r, r) == 2*r.
        let mut al = big::NewRat(1, 4);
        let snap = al.clone();
        al.Add(&snap, &snap);
        check(al.Num().Cmp(&big::NewInt(1)) == 0, b"rat alias add num 1");
        check(al.Denom().Cmp(&big::NewInt(2)) == 0, b"rat alias add den 2");
    }

    // ── Rat I/O: String / RatString / FloatString ─────────────────
    {
        check(
            big::NewRat(1, 2).String().as_bytes() == b"1/2",
            b"rat string 1/2",
        );
        // 4/2 reduces to 2/1 — String always shows the "a/b" form.
        check(
            big::NewRat(4, 2).String().as_bytes() == b"2/1",
            b"rat string 4/2",
        );
        // RatString drops the denominator when it is 1.
        check(
            big::NewRat(1, 2).RatString().as_bytes() == b"1/2",
            b"rat ratstring 1/2",
        );
        check(
            big::NewRat(4, 2).RatString().as_bytes() == b"2",
            b"rat ratstring 4/2",
        );

        // FloatString: prec digits after the point, rounded.
        check(
            big::NewRat(1, 3).FloatString(4).as_bytes() == b"0.3333",
            b"rat floatstring 1/3 p4",
        );
        check(
            big::NewRat(1, 2).FloatString(2).as_bytes() == b"0.50",
            b"rat floatstring 1/2 p2",
        );
        check(
            big::NewRat(-1, 3).FloatString(4).as_bytes() == b"-0.3333",
            b"rat floatstring neg",
        );
        // 2/3 = 0.666... — last digit rounds up.
        check(
            big::NewRat(2, 3).FloatString(2).as_bytes() == b"0.67",
            b"rat floatstring 2/3 round",
        );
    }

    // ── Rat SetString ──────────────────────────────────────────────
    {
        let mut r = big::Rat::new();
        let (_, ok) = r.SetString("22/7");
        check(ok, b"rat setstring 22/7 ok");
        check(
            r.Num().Cmp(&big::NewInt(22)) == 0,
            b"rat setstring 22/7 num",
        );
        check(
            r.Denom().Cmp(&big::NewInt(7)) == 0,
            b"rat setstring 22/7 den",
        );

        let mut ri = big::Rat::new();
        let (_, ok) = ri.SetString("5");
        check(ok, b"rat setstring 5 ok");
        check(ri.Num().Cmp(&big::NewInt(5)) == 0, b"rat setstring 5 num");
        check(ri.Denom().Cmp(&big::NewInt(1)) == 0, b"rat setstring 5 den");

        let mut rf = big::Rat::new();
        let (_, ok) = rf.SetString("1.5");
        check(ok, b"rat setstring 1.5 ok");
        check(rf.Num().Cmp(&big::NewInt(3)) == 0, b"rat setstring 1.5 num");
        check(
            rf.Denom().Cmp(&big::NewInt(2)) == 0,
            b"rat setstring 1.5 den",
        );

        let mut re = big::Rat::new();
        let (_, ok) = re.SetString("-0.25e1");
        check(ok, b"rat setstring -0.25e1 ok");
        // -0.25e1 == -2.5 == -5/2.
        check(
            re.Num().Cmp(&big::NewInt(-5)) == 0,
            b"rat setstring -0.25e1 num",
        );
        check(
            re.Denom().Cmp(&big::NewInt(2)) == 0,
            b"rat setstring -0.25e1 den",
        );

        let mut rbad = big::Rat::new();
        let (_, ok) = rbad.SetString("not-a-rat");
        check(!ok, b"rat setstring invalid -> false");
    }

    // ── Rat Float64 / Float32 (exact flag) ─────────────────────────
    {
        let (f, exact) = big::NewRat(1, 2).Float64();
        check(f == 0.5 && exact, b"rat float64 1/2 exact");
        let (f3, exact3) = big::NewRat(1, 3).Float64();
        check(
            f3 > 0.333 && f3 < 0.334 && !exact3,
            b"rat float64 1/3 inexact",
        );

        let (g, gexact) = big::NewRat(1, 2).Float32();
        check(g == 0.5f32 && gexact, b"rat float32 1/2 exact");
        let (g3, g3exact) = big::NewRat(1, 3).Float32();
        check(
            g3 > 0.333f32 && g3 < 0.334f32 && !g3exact,
            b"rat float32 1/3 inexact",
        );

        // Negative sign is carried onto the float.
        let (nf, _) = big::NewRat(-1, 2).Float64();
        check(nf == -0.5, b"rat float64 neg sign");
    }

    // ── Rat FloatPrec ──────────────────────────────────────────────
    {
        let (n, exact) = big::NewRat(1, 2).FloatPrec();
        check(n == 1 && exact, b"rat floatprec 1/2");
        let (n4, exact4) = big::NewRat(1, 4).FloatPrec();
        check(n4 == 2 && exact4, b"rat floatprec 1/4");
        let (_, exact3) = big::NewRat(1, 3).FloatPrec();
        check(!exact3, b"rat floatprec 1/3 not exact");
        // 1/6 = 0.1666... — one non-repeating digit, not exact.
        let (n6, exact6) = big::NewRat(1, 6).FloatPrec();
        check(n6 == 1 && !exact6, b"rat floatprec 1/6");
    }

    // ── Rat SetFloat64 ─────────────────────────────────────────────
    {
        let mut rh = big::Rat::new();
        let (_, ok) = rh.SetFloat64(0.5);
        check(ok, b"rat setfloat64 0.5 ok");
        check(
            rh.Num().Cmp(&big::NewInt(1)) == 0,
            b"rat setfloat64 0.5 num",
        );
        check(
            rh.Denom().Cmp(&big::NewInt(2)) == 0,
            b"rat setfloat64 0.5 den",
        );

        // An integer-valued float -> a/1.
        let mut r3 = big::Rat::new();
        let (_, ok) = r3.SetFloat64(3.0);
        check(ok, b"rat setfloat64 3.0 ok");
        check(
            r3.IsInt() && r3.Num().Cmp(&big::NewInt(3)) == 0,
            b"rat setfloat64 3.0 int",
        );
    }

    // ── Rat MarshalText / UnmarshalText round-trip ─────────────────
    {
        let src = big::NewRat(22, 7);
        let (text, err) = src.MarshalText();
        check(err == goish::nil, b"rat marshaltext no err");
        check(&*text == &b"22/7"[..], b"rat marshaltext bytes");

        let mut back = big::Rat::new();
        let uerr = back.UnmarshalText(text);
        check(uerr == goish::nil, b"rat unmarshaltext no err");
        check(back.Cmp(&src) == 0, b"rat marshaltext round-trip");

        // An integer Rat marshals without the "/1".
        let (itext, _) = big::NewRat(6, 2).MarshalText();
        check(&*itext == &b"3"[..], b"rat marshaltext integer form");
    }

    // ── Rat GobEncode / GobDecode round-trip ───────────────────────
    {
        let src = big::NewRat(-355, 113);
        let (gob, err) = src.GobEncode();
        check(err == goish::nil, b"rat gobencode no err");

        let mut back = big::Rat::new();
        let derr = back.GobDecode(gob);
        check(derr == goish::nil, b"rat gobdecode no err");
        check(back.Cmp(&src) == 0, b"rat gob round-trip");

        // An empty buffer resets to the zero value 0/1.
        let mut zr = big::NewRat(7, 9);
        let eb: slice<goish::byte> = slice::__from_vec(alloc::vec![]);
        let zerr = zr.GobDecode(eb);
        check(zerr == goish::nil, b"rat gobdecode empty no err");
        check(
            zr.Sign() == 0 && zr.Denom().Cmp(&big::NewInt(1)) == 0,
            b"rat gobdecode empty resets",
        );
    }

    // ── Float core: type, RoundingMode, setters, predicates ────────
    {
        // NewFloat / SetFloat64 — read back the basic state.
        let pf = big::NewFloat(3.5);
        check(pf.Sign() == 1, b"float newfloat sign pos");
        check(!pf.Signbit(), b"float newfloat signbit");
        check(!pf.IsInf(), b"float newfloat not inf");
        check(pf.Prec() == 53, b"float newfloat prec 53");
        check(
            pf.Mode() == big::RoundingMode::ToNearestEven,
            b"float newfloat mode",
        );
        check(
            pf.Acc() == big::Accuracy::Exact,
            b"float newfloat acc exact",
        );
        check(pf.IsInt() == false, b"float 3.5 not int");

        let nf = big::NewFloat(-2.0);
        check(nf.Sign() == -1, b"float newfloat sign neg");
        check(nf.Signbit(), b"float newfloat neg signbit");
        check(nf.IsInt(), b"float -2.0 is int");

        let mut zf = big::Float::new();
        zf.SetFloat64(0.0);
        check(zf.Sign() == 0, b"float zero sign");
        check(zf.IsInt(), b"float zero is int");

        // Zero value default.
        let dv = big::Float::default();
        check(dv.Sign() == 0 && dv.Prec() == 0, b"float default zero");
        check(
            dv.Mode() == big::RoundingMode::ToNearestEven,
            b"float default mode",
        );
    }

    // ── Float: SetInt64 / SetUint64 / SetInt ───────────────────────
    {
        let mut a = big::Float::new();
        a.SetInt64(-12345);
        check(a.Sign() == -1, b"float setint64 sign");
        check(a.Prec() == 64, b"float setint64 prec 64");
        check(a.IsInt(), b"float setint64 is int");

        let mut u = big::Float::new();
        u.SetUint64(9000000000000000000);
        check(u.Sign() == 1 && u.Prec() == 64, b"float setuint64");

        let big_int = pow2(100); // needs 101 bits
        let mut fi = big::Float::new();
        fi.SetInt(&big_int);
        check(fi.Sign() == 1, b"float setint sign");
        check(fi.Prec() == 101, b"float setint prec = bitlen");
        check(fi.IsInt(), b"float setint is int");

        let mut fs = big::Float::new();
        fs.SetInt(&big::NewInt(7));
        check(fs.Prec() == 64, b"float setint small prec 64");
    }

    // ── Float: SetInf / IsInf / Signbit ────────────────────────────
    {
        let mut pi = big::Float::new();
        pi.SetInf(false);
        check(pi.IsInf(), b"float +inf is inf");
        check(!pi.Signbit(), b"float +inf signbit");
        check(pi.Sign() == 1, b"float +inf sign");
        check(!pi.IsInt(), b"float +inf not int");

        let mut ni = big::Float::new();
        ni.SetInf(true);
        check(ni.IsInf(), b"float -inf is inf");
        check(ni.Signbit(), b"float -inf signbit");
        check(ni.Sign() == -1, b"float -inf sign");
    }

    // ── Float: Cmp ─────────────────────────────────────────────────
    {
        let one = big::NewFloat(1.0);
        let two = big::NewFloat(2.0);
        let one2 = big::NewFloat(1.0);
        check(one.Cmp(&two) == -1, b"float cmp less");
        check(two.Cmp(&one) == 1, b"float cmp greater");
        check(one.Cmp(&one2) == 0, b"float cmp equal");

        // ±0 compare equal.
        let mut pz = big::Float::new();
        pz.SetFloat64(0.0);
        let mut nz = big::Float::new();
        nz.SetFloat64(-0.0);
        check(pz.Cmp(&nz) == 0, b"float cmp +0 == -0");

        // ±Inf.
        let mut pinf = big::Float::new();
        pinf.SetInf(false);
        let mut ninf = big::Float::new();
        ninf.SetInf(true);
        check(ninf.Cmp(&pinf) == -1, b"float cmp -inf < +inf");
        check(pinf.Cmp(&one) == 1, b"float cmp +inf > 1");
        check(ninf.Cmp(&one) == -1, b"float cmp -inf < 1");
        let mut pinf2 = big::Float::new();
        pinf2.SetInf(false);
        check(pinf.Cmp(&pinf2) == 0, b"float cmp +inf == +inf");
    }

    // ── Float: MantExp / SetMantExp round-trip ─────────────────────
    {
        // 12.0 = 0.75 × 2^4.
        let x = big::NewFloat(12.0);
        let exp_only = x.MantExp(goish::nil);
        check(exp_only == 4, b"float mantexp exponent (nil out)");

        let mut mant = big::Float::new();
        let exp = x.MantExp(&mut mant);
        check(exp == 4, b"float mantexp exponent");
        // mant ∈ [0.5, 1): 0.5 <= mant < 1.0  ⇔  MantExp(mant) == 0.
        check(
            mant.MantExp(goish::nil) == 0,
            b"float mantexp mant normalized",
        );
        let half = big::NewFloat(0.5);
        let one = big::NewFloat(1.0);
        check(
            mant.Cmp(&half) >= 0 && mant.Cmp(&one) < 0,
            b"float mantexp mant in [0.5,1)",
        );

        // SetMantExp reconstructs x from (mant, exp).
        let mut rebuilt = big::Float::new();
        rebuilt.SetMantExp(&mant, exp);
        check(rebuilt.Cmp(&x) == 0, b"float setmantexp round-trip");

        // ±0 / ±Inf special cases: exponent 0.
        let z = big::NewFloat(0.0);
        check(z.MantExp(goish::nil) == 0, b"float mantexp zero = 0");
        let mut inf = big::Float::new();
        inf.SetInf(false);
        check(inf.MantExp(goish::nil) == 0, b"float mantexp inf = 0");
    }

    // ── Float: SetPrec rounds (exercises round helper) / MinPrec ────
    {
        // 0.75 = 0.11b → needs 2 mantissa bits. 13.0 = 1101b → needs 4.
        let thirteen = big::NewFloat(13.0);
        check(thirteen.MinPrec() == 4, b"float minprec 13.0 = 4");

        // A value needing 10 bits: 1023.0 = 1111111111b.
        let mut wide = big::Float::new();
        wide.SetInt64(1023);
        check(wide.MinPrec() == 10, b"float minprec 1023 = 10");

        // Round 1023 down to 4 bits of precision — must change + report.
        let mut narrowed = big::Float::new();
        narrowed.Copy(&wide);
        narrowed.SetPrec(4);
        check(narrowed.Prec() == 4, b"float setprec 4");
        check(
            narrowed.Acc() != big::Accuracy::Exact,
            b"float setprec inexact acc",
        );
        check(narrowed.Cmp(&wide) != 0, b"float setprec changed value");
        check(narrowed.MinPrec() <= 4, b"float setprec minprec fits");

        // SetPrec to a precision >= MinPrec is exact.
        let mut keep = big::Float::new();
        keep.Copy(&wide);
        keep.SetPrec(16);
        check(
            keep.Acc() == big::Accuracy::Exact,
            b"float setprec wide exact",
        );
        check(keep.Cmp(&wide) == 0, b"float setprec wide unchanged");

        // SetPrec(0) collapses a finite value to ±0.
        let mut collapsed = big::Float::new();
        collapsed.Copy(&wide);
        collapsed.SetPrec(0);
        check(
            collapsed.Sign() == 0 && collapsed.Prec() == 0,
            b"float setprec 0 = zero",
        );
    }

    // ── Float: arithmetic (Add/Sub/Mul/Quo/Neg/Abs/Sqrt) ──────────
    {
        // Add: 2.5 + 0.5 == 3.0
        let mut s = big::Float::new();
        s.Add(&big::NewFloat(2.5), &big::NewFloat(0.5));
        check(s.Cmp(&big::NewFloat(3.0)) == 0, b"float add 2.5+0.5=3.0");
        check(s.Acc() == big::Accuracy::Exact, b"float add exact acc");

        // Add mixed sign: 2.0 + (-0.5) == 1.5
        let mut s2 = big::Float::new();
        s2.Add(&big::NewFloat(2.0), &big::NewFloat(-0.5));
        check(
            s2.Cmp(&big::NewFloat(1.5)) == 0,
            b"float add 2.0+(-0.5)=1.5",
        );

        // Sub: 1.0 - 0.25 == 0.75
        let mut d = big::Float::new();
        d.Sub(&big::NewFloat(1.0), &big::NewFloat(0.25));
        check(d.Cmp(&big::NewFloat(0.75)) == 0, b"float sub 1.0-0.25=0.75");

        // Sub crossing zero: 0.25 - 1.0 == -0.75
        let mut d2 = big::Float::new();
        d2.Sub(&big::NewFloat(0.25), &big::NewFloat(1.0));
        check(
            d2.Cmp(&big::NewFloat(-0.75)) == 0,
            b"float sub 0.25-1.0=-0.75",
        );

        // Sub to exact zero.
        let mut dz = big::Float::new();
        dz.Sub(&big::NewFloat(3.0), &big::NewFloat(3.0));
        check(dz.Sign() == 0, b"float sub 3.0-3.0=0");

        // Mul: 1.5 * 4.0 == 6.0
        let mut m = big::Float::new();
        m.Mul(&big::NewFloat(1.5), &big::NewFloat(4.0));
        check(m.Cmp(&big::NewFloat(6.0)) == 0, b"float mul 1.5*4.0=6.0");

        // Mul sign: (-2.0) * 3.0 == -6.0
        let mut m2 = big::Float::new();
        m2.Mul(&big::NewFloat(-2.0), &big::NewFloat(3.0));
        check(
            m2.Cmp(&big::NewFloat(-6.0)) == 0,
            b"float mul (-2.0)*3.0=-6.0",
        );

        // Quo: 7.0 / 2.0 == 3.5
        let mut q = big::Float::new();
        q.Quo(&big::NewFloat(7.0), &big::NewFloat(2.0));
        check(q.Cmp(&big::NewFloat(3.5)) == 0, b"float quo 7.0/2.0=3.5");

        // Quo sign: (-9.0) / 3.0 == -3.0
        let mut q2 = big::Float::new();
        q2.Quo(&big::NewFloat(-9.0), &big::NewFloat(3.0));
        check(
            q2.Cmp(&big::NewFloat(-3.0)) == 0,
            b"float quo (-9.0)/3.0=-3.0",
        );

        // Neg / Abs.
        let mut n = big::Float::new();
        n.Neg(&big::NewFloat(2.5));
        check(n.Cmp(&big::NewFloat(-2.5)) == 0, b"float neg 2.5=-2.5");
        let mut a = big::Float::new();
        a.Abs(&big::NewFloat(-2.5));
        check(a.Cmp(&big::NewFloat(2.5)) == 0, b"float abs -2.5=2.5");
        let mut a2 = big::Float::new();
        a2.Abs(&big::NewFloat(2.5));
        check(a2.Cmp(&big::NewFloat(2.5)) == 0, b"float abs 2.5=2.5");

        // Sqrt of a perfect square: √4 == 2.
        let mut r = big::Float::new();
        r.Sqrt(&big::NewFloat(4.0));
        check(r.Cmp(&big::NewFloat(2.0)) == 0, b"float sqrt 4=2");

        // Sqrt(9) == 3, Sqrt(0.25) == 0.5.
        let mut r9 = big::Float::new();
        r9.Sqrt(&big::NewFloat(9.0));
        check(r9.Cmp(&big::NewFloat(3.0)) == 0, b"float sqrt 9=3");
        let mut rq = big::Float::new();
        rq.Sqrt(&big::NewFloat(0.25));
        check(rq.Cmp(&big::NewFloat(0.5)) == 0, b"float sqrt 0.25=0.5");

        // Sqrt(2): z·z must be ≈ 2 within rounding.
        let mut root2 = big::Float::new();
        root2.SetPrec(64);
        root2.Sqrt(&big::NewFloat(2.0));
        // root2 close to 1.4142135... — bracket it.
        let lo = big::NewFloat(1.41421356);
        let hi = big::NewFloat(1.41421357);
        check(
            root2.Cmp(&lo) > 0 && root2.Cmp(&hi) < 0,
            b"float sqrt 2 in range",
        );
        let mut sq = big::Float::new();
        sq.SetPrec(64);
        sq.Mul(&root2, &root2);
        // sq ≈ 2.0; within a couple ulps.
        let two_lo = big::NewFloat(1.9999999);
        let two_hi = big::NewFloat(2.0000001);
        check(
            sq.Cmp(&two_lo) > 0 && sq.Cmp(&two_hi) < 0,
            b"float sqrt 2 squared ~= 2",
        );

        // Sqrt special cases.
        let mut rzero = big::Float::new();
        rzero.Sqrt(&big::NewFloat(0.0));
        check(rzero.Sign() == 0, b"float sqrt 0 = 0");
        let mut sinf = big::Float::new();
        sinf.SetInf(false);
        let mut rinf = big::Float::new();
        rinf.Sqrt(&sinf);
        check(rinf.IsInf() && !rinf.Signbit(), b"float sqrt +Inf = +Inf");

        // ── special cases: ±Inf, ±0 ───────────────────────────────
        let mut pinf = big::Float::new();
        pinf.SetInf(false);
        let mut ninf = big::Float::new();
        ninf.SetInf(true);

        // x + (+Inf) == +Inf
        let mut ai = big::Float::new();
        ai.Add(&big::NewFloat(5.0), &pinf);
        check(ai.IsInf() && !ai.Signbit(), b"float add x++Inf=+Inf");

        // (+Inf) + (+Inf) == +Inf
        let mut aii = big::Float::new();
        aii.Add(&pinf, &pinf);
        check(aii.IsInf() && !aii.Signbit(), b"float add +Inf++Inf=+Inf");

        // 1.0 / 0.0 == +Inf
        let mut div0 = big::Float::new();
        div0.Quo(&big::NewFloat(1.0), &big::NewFloat(0.0));
        check(div0.IsInf() && !div0.Signbit(), b"float quo 1.0/0.0=+Inf");

        // (-1.0) / 0.0 == -Inf
        let mut div0n = big::Float::new();
        div0n.Quo(&big::NewFloat(-1.0), &big::NewFloat(0.0));
        check(div0n.IsInf() && div0n.Signbit(), b"float quo -1.0/0.0=-Inf");

        // x / +Inf == ±0
        let mut divinf = big::Float::new();
        divinf.Quo(&big::NewFloat(7.0), &pinf);
        check(divinf.Sign() == 0, b"float quo x/+Inf=0");

        // ±0 + ±0 special cases.
        let mut zz = big::Float::new();
        zz.Add(&big::NewFloat(0.0), &big::NewFloat(0.0));
        check(zz.Sign() == 0 && !zz.Signbit(), b"float add +0++0=+0");

        // Inf - finite == Inf
        let mut subinf = big::Float::new();
        subinf.Sub(&ninf, &big::NewFloat(100.0));
        check(
            subinf.IsInf() && subinf.Signbit(),
            b"float sub -Inf-100=-Inf",
        );

        // ── rounding: low-precision result reports Below/Above ─────
        // 1/3 is not representable; a 4-bit result must round inexact.
        let mut third = big::Float::new();
        third.SetPrec(4);
        third.Quo(&big::NewFloat(1.0), &big::NewFloat(3.0));
        check(
            third.Acc() != big::Accuracy::Exact,
            b"float quo 1/3 inexact acc",
        );
        // ToZero rounds the magnitude down => result Below the exact 1/3.
        let mut third_dn = big::Float::new();
        third_dn.SetPrec(4);
        third_dn.SetMode(big::RoundingMode::ToZero);
        third_dn.Quo(&big::NewFloat(1.0), &big::NewFloat(3.0));
        check(
            third_dn.Acc() == big::Accuracy::Below,
            b"float quo 1/3 ToZero=Below",
        );
        // AwayFromZero rounds the magnitude up => result Above.
        let mut third_up = big::Float::new();
        third_up.SetPrec(4);
        third_up.SetMode(big::RoundingMode::AwayFromZero);
        third_up.Quo(&big::NewFloat(1.0), &big::NewFloat(3.0));
        check(
            third_up.Acc() == big::Accuracy::Above,
            b"float quo 1/3 AwayFromZero=Above",
        );

        // ── aliasing: receiver also an operand ─────────────────────
        let mut alias_add = big::NewFloat(2.5);
        let alias_add_snap = alias_add.clone();
        alias_add.Add(&alias_add_snap, &alias_add_snap);
        check(
            alias_add.Cmp(&big::NewFloat(5.0)) == 0,
            b"float add aliased z=z+z",
        );

        // True self-alias: z.Add(z, z) — exercises the snapshot path.
        let mut z_aa = big::NewFloat(3.0);
        let z_aa_ptr = z_aa.clone();
        z_aa.Add(&z_aa_ptr, &z_aa_ptr);
        check(z_aa.Cmp(&big::NewFloat(6.0)) == 0, b"float add z.Add(z,z)");

        let mut alias_mul = big::NewFloat(3.0);
        let alias_mul_snap = alias_mul.clone();
        alias_mul.Mul(&alias_mul_snap, &alias_mul_snap);
        check(
            alias_mul.Cmp(&big::NewFloat(9.0)) == 0,
            b"float mul aliased z=z*z",
        );

        // Aliased Sub down to zero.
        let mut alias_sub = big::NewFloat(4.0);
        let alias_sub_snap = alias_sub.clone();
        alias_sub.Sub(&alias_sub_snap, &alias_sub_snap);
        check(alias_sub.Sign() == 0, b"float sub aliased z=z-z=0");

        // Precision inheritance: z.prec==0 adopts max(x,y).
        let mut p1 = big::Float::new();
        p1.SetPrec(80);
        p1.SetFloat64(1.0);
        let mut p2 = big::Float::new();
        p2.SetPrec(40);
        p2.SetFloat64(2.0);
        let mut psum = big::Float::new();
        psum.Add(&p1, &p2);
        check(psum.Prec() == 80, b"float add prec=max(x,y)");

        // ── numeric conversions: Float64 / Float32 ─────────────────
        // SetFloat64(x).Float64() round-trips exactly for representable x.
        for &v in &[0.5f64, 3.0, -2.25, 0.1] {
            let mut f = big::Float::new();
            f.SetFloat64(v);
            let (got, acc) = f.Float64();
            check(got == v, b"float Float64 round-trip");
            check(
                acc == big::Accuracy::Exact,
                b"float Float64 round-trip Exact",
            );
        }

        // Float32 round-trip for an exactly representable value.
        let mut f32rt = big::Float::new();
        f32rt.SetFloat64(-2.25);
        let (g32, a32) = f32rt.Float32();
        check(g32 == -2.25f32, b"float Float32 round-trip");
        check(
            a32 == big::Accuracy::Exact,
            b"float Float32 round-trip Exact",
        );

        // A value needing more precision than 53 bits rounds inexactly.
        // 1/3 at high precision → nearest f64 is rounded.
        let mut hp = big::Float::new();
        hp.SetPrec(200);
        hp.Quo(&big::NewFloat(1.0), &big::NewFloat(3.0));
        let (g13, a13) = hp.Float64();
        // nearest f64 to 1/3 is ToNearestEven-rounded → Below the true 1/3
        // (matches Go: Float64 of a 200-bit 1/3 reports Below).
        check(a13 == big::Accuracy::Below, b"float Float64 1/3 Below");
        let (g13_32, a13_32) = hp.Float32();
        check(a13_32 != big::Accuracy::Exact, b"float Float32 1/3 inexact");
        let _ = (g13, g13_32);

        // A value that needs more than 24 bits but is exact in f64.
        // 1/3 truncated to a 30-bit Float is exact as f64 but inexact f32.
        let mut bits30 = big::Float::new();
        bits30.SetPrec(30);
        bits30.Quo(&big::NewFloat(1.0), &big::NewFloat(3.0));
        let (_, a30_64) = bits30.Float64();
        check(
            a30_64 == big::Accuracy::Exact,
            b"float Float64 30-bit Exact",
        );
        let (_, a30_32) = bits30.Float32();
        check(
            a30_32 != big::Accuracy::Exact,
            b"float Float32 30-bit inexact",
        );

        // ── numeric conversions: Int64 / Uint64 ────────────────────
        let mut three = big::Float::new();
        three.SetFloat64(3.0);
        let (i3, ai3) = three.Int64();
        check(
            i3 == 3 && ai3 == big::Accuracy::Exact,
            b"float Int64 3.0=3 Exact",
        );
        let (u3, au3) = three.Uint64();
        check(
            u3 == 3 && au3 == big::Accuracy::Exact,
            b"float Uint64 3.0=3 Exact",
        );

        let mut frac = big::Float::new();
        frac.SetFloat64(3.9);
        let (i39, ai39) = frac.Int64();
        check(
            i39 == 3 && ai39 == big::Accuracy::Below,
            b"float Int64 3.9=3 Below",
        );
        // Go quirk: Uint64's exactness check is MinPrec()<=64, so a
        // 53-bit 3.9 truncates to 3 yet reports Exact (matches Go).
        let (u39, au39) = frac.Uint64();
        check(
            u39 == 3 && au39 == big::Accuracy::Exact,
            b"float Uint64 3.9=3 (Go quirk)",
        );

        // Negative truncation: -3.9 → -3, Above (truncation toward zero).
        let mut nfrac = big::Float::new();
        nfrac.SetFloat64(-3.9);
        let (in39, ain39) = nfrac.Int64();
        check(
            in39 == -3 && ain39 == big::Accuracy::Above,
            b"float Int64 -3.9=-3 Above",
        );
        // Uint64 of a negative value saturates to (0, Above).
        let (un, aun) = nfrac.Uint64();
        check(
            un == 0 && aun == big::Accuracy::Above,
            b"float Uint64 neg=0 Above",
        );

        // Out-of-range saturation: 2^100 → MaxInt64/MaxUint64, Below.
        let mut huge = big::Float::new();
        huge.SetInt(&pow2(100));
        let (ihuge, aihuge) = huge.Int64();
        check(
            ihuge == i64::MAX && aihuge == big::Accuracy::Below,
            b"float Int64 2^100=MaxInt64 Below",
        );
        let (uhuge, auhuge) = huge.Uint64();
        check(
            uhuge == u64::MAX && auhuge == big::Accuracy::Below,
            b"float Uint64 2^100=MaxUint64 Below",
        );

        // ── numeric conversions: Int ───────────────────────────────
        let mut seven_half = big::Float::new();
        seven_half.SetFloat64(7.5);
        let (iz, aiz) = seven_half.Int(big::Int::new());
        check(
            iz.Int64() == 7 && aiz == big::Accuracy::Below,
            b"float Int 7.5=7 Below",
        );
        // Exact integer: Int of 12.0 → 12 Exact.
        let mut twelve = big::Float::new();
        twelve.SetFloat64(12.0);
        let (iz12, aiz12) = twelve.Int(goish::nil);
        check(
            iz12.Int64() == 12 && aiz12 == big::Accuracy::Exact,
            b"float Int 12.0=12 Exact",
        );

        // ── numeric conversions: Rat ───────────────────────────────
        let mut half = big::Float::new();
        half.SetFloat64(0.5);
        let (rz, arz) = half.Rat(big::Rat::new());
        check(
            rz.Num().Int64() == 1 && rz.Denom().Int64() == 2 && arz == big::Accuracy::Exact,
            b"float Rat 0.5=1/2 Exact",
        );
        // Rat of 3.0 → 3/1.
        let mut rthree = big::Float::new();
        rthree.SetFloat64(3.0);
        let (rz3, _) = rthree.Rat(goish::nil);
        check(
            rz3.Num().Int64() == 3 && rz3.Denom().Int64() == 1,
            b"float Rat 3.0=3/1",
        );

        // ── numeric conversions: SetRat ────────────────────────────
        // SetRat of 1/4 → exact, Float64()==0.25.
        let mut quarter_rat = big::Rat::new();
        quarter_rat.SetFrac(&big::NewInt(1), &big::NewInt(4));
        let mut sr = big::Float::new();
        sr.SetRat(&quarter_rat);
        let (srv, _) = sr.Float64();
        check(srv == 0.25, b"float SetRat 1/4=0.25");
        // SetRat of 1/3 at low precision rounds inexactly.
        let mut third_rat = big::Rat::new();
        third_rat.SetFrac(&big::NewInt(1), &big::NewInt(3));
        let mut sr3 = big::Float::new();
        sr3.SetPrec(8);
        sr3.SetRat(&third_rat);
        check(
            sr3.Acc() != big::Accuracy::Exact,
            b"float SetRat 1/3 inexact",
        );
        // SetRat of an integer Rat → exact integer Float.
        let mut int_rat = big::Rat::new();
        int_rat.SetFrac(&big::NewInt(10), &big::NewInt(2));
        let mut sri = big::Float::new();
        sri.SetRat(&int_rat);
        check(sri.Cmp(&big::NewFloat(5.0)) == 0, b"float SetRat 10/2=5");
    }

    // ── Float string I/O ──────────────────────────────────────────────
    {
        // Text / String for simple decimal values.
        let three = big::NewFloat(3.0);
        check(three.String().as_bytes() == b"3", b"float String 3.0=\"3\"");
        check(three.Text(b'g', 10).as_bytes() == b"3", b"float Text g 3.0");

        let half = big::NewFloat(0.5);
        check(
            half.String().as_bytes() == b"0.5",
            b"float String 0.5=\"0.5\"",
        );

        let mneg = big::NewFloat(-2.25);
        check(mneg.String().as_bytes() == b"-2.25", b"float String -2.25");

        let zero = big::NewFloat(0.0);
        check(zero.String().as_bytes() == b"0", b"float String 0=\"0\"");

        let mut pinf = big::Float::new();
        pinf.SetInf(false);
        check(pinf.String().as_bytes() == b"+Inf", b"float String +Inf");
        let mut ninf = big::Float::new();
        ninf.SetInf(true);
        check(ninf.String().as_bytes() == b"-Inf", b"float String -Inf");

        // Text('f', 2) of 1/3 → "0.33".
        let mut third = big::Float::new();
        third.SetPrec(64);
        third.Quo(&big::NewFloat(1.0), &big::NewFloat(3.0));
        check(
            third.Text(b'f', 2).as_bytes() == b"0.33",
            b"float Text f2 1/3=\"0.33\"",
        );

        // Text('f', 4) of -2.25.
        check(
            mneg.Text(b'f', 4).as_bytes() == b"-2.2500",
            b"float Text f4 -2.25",
        );

        // Text('e', ...) — scientific notation.
        let mut big100 = big::Float::new();
        big100.SetFloat64(125.0);
        check(
            big100.Text(b'e', 2).as_bytes() == b"1.25e+02",
            b"float Text e2 125",
        );
        check(
            big100.Text(b'E', 2).as_bytes() == b"1.25E+02",
            b"float Text E2 125",
        );

        // Text('g') for a large number switches to exponent form.
        let mut million = big::Float::new();
        million.SetFloat64(1.0e7);
        check(
            million.Text(b'g', -1).as_bytes() == b"1e+07",
            b"float Text g 1e7",
        );

        // 'b' / 'p' / 'x' binary/hex forms — at least non-empty & sane.
        let two = big::NewFloat(2.0);
        check(
            two.Text(b'x', -1).as_bytes() == b"0x1p+01",
            b"float Text x 2.0",
        );
        let onex = big::NewFloat(1.0);
        check(
            onex.Text(b'p', -1).as_bytes().len() > 0,
            b"float Text p 1.0 non-empty",
        );
        check(
            onex.Text(b'b', -1).as_bytes().len() > 0,
            b"float Text b 1.0 non-empty",
        );

        // Append onto an existing buffer.
        let pre: slice<goish::byte> = slice::__from_vec(b"=".to_vec());
        let app = three.Append(pre, b'g', 10);
        check(&*app == b"=3", b"float Append onto buffer");

        // Round-trip: Parse(Text(x)) recovers x for several values.
        for &v in &[3.0f64, 0.5, -2.25, 123.5, 0.0] {
            let x = big::NewFloat(v);
            let txt = x.Text(b'g', -1);
            let mut y = big::Float::new();
            y.SetPrec(53);
            let (_, _, err) = y.Parse(txt.clone(), 10);
            check(
                err == goish::nil && y.Cmp(&x) == 0,
                b"float Parse(Text(x))==x",
            );
        }

        // High-precision round-trip.
        let mut hp = big::Float::new();
        hp.SetPrec(200);
        hp.Quo(&big::NewFloat(22.0), &big::NewFloat(7.0));
        let hptxt = hp.Text(b'g', -1);
        let mut hp2 = big::Float::new();
        hp2.SetPrec(200);
        let (_, _, hperr) = hp2.Parse(hptxt, 10);
        check(
            hperr == goish::nil && hp2.Cmp(&hp) == 0,
            b"float Parse(Text) hi-prec round-trip",
        );

        // SetString then Float64() ≈ 3.14159.
        let mut pi = big::Float::new();
        pi.SetPrec(64);
        let (_, ok) = pi.SetString("3.14159");
        let (piv, _) = pi.Float64();
        check(
            ok && piv > 3.14158 && piv < 3.14160,
            b"float SetString 3.14159",
        );

        // ParseFloat with explicit precision/mode.
        let (pf, pfb, pferr) = big::ParseFloat("2.5", 10, 64, big::RoundingMode::ToNearestEven);
        check(
            pferr == goish::nil && pfb == 10 && pf.Cmp(&big::NewFloat(2.5)) == 0,
            b"float ParseFloat 2.5",
        );

        // Base-0 hex-float literal.
        let mut hf = big::Float::new();
        hf.SetPrec(64);
        let (_, hfb, hferr) = hf.Parse("0x1.8p1", 0);
        check(
            hferr == goish::nil && hfb == 16 && hf.Cmp(&big::NewFloat(3.0)) == 0,
            b"float Parse 0x1.8p1=3",
        );

        // Invalid parse → non-nil error / ok==false.
        let mut bad = big::Float::new();
        let (_, _, berr) = bad.Parse("not-a-number", 10);
        check(berr != goish::nil, b"float Parse invalid -> error");
        let mut bad2 = big::Float::new();
        let (_, bok) = bad2.SetString("12.3.4");
        check(!bok, b"float SetString invalid -> ok==false");

        // MarshalText / UnmarshalText round-trip.
        for &v in &[7.5f64, -0.125, 0.0] {
            let x = big::NewFloat(v);
            let (txt, merr) = x.MarshalText();
            let mut y = big::Float::new();
            y.SetPrec(53);
            let uerr = y.UnmarshalText(txt);
            check(
                merr == goish::nil && uerr == goish::nil && y.Cmp(&x) == 0,
                b"float MarshalText/UnmarshalText round-trip",
            );
        }

        // GobEncode → GobDecode round-trip (incl. negative, zero, Inf).
        {
            let mut neg_g = big::Float::new();
            neg_g.SetPrec(64);
            neg_g.SetFloat64(-12.75);
            let (gb, gerr) = neg_g.GobEncode();
            let mut gd = big::Float::new();
            let derr = gd.GobDecode(gb);
            check(
                gerr == goish::nil && derr == goish::nil && gd.Cmp(&neg_g) == 0,
                b"float Gob round-trip negative",
            );

            let zero_g = big::NewFloat(0.0);
            let (zgb, _) = zero_g.GobEncode();
            let mut zgd = big::Float::new();
            let zderr = zgd.GobDecode(zgb);
            check(
                zderr == goish::nil && zgd.Cmp(&zero_g) == 0,
                b"float Gob round-trip zero",
            );

            let mut inf_g = big::Float::new();
            inf_g.SetInf(true);
            let (igb, _) = inf_g.GobEncode();
            let mut igd = big::Float::new();
            let iderr = igd.GobDecode(igb);
            check(
                iderr == goish::nil && igd.IsInf() && igd.Signbit(),
                b"float Gob round-trip -Inf",
            );

            // Hi-precision Gob round-trip.
            let mut hpg = big::Float::new();
            hpg.SetPrec(160);
            hpg.Quo(&big::NewFloat(1.0), &big::NewFloat(7.0));
            let (hgb, _) = hpg.GobEncode();
            let mut hgd = big::Float::new();
            let hderr = hgd.GobDecode(hgb);
            check(
                hderr == goish::nil && hgd.Cmp(&hpg) == 0,
                b"float Gob round-trip hi-prec",
            );
        }

        // ── Cross-check vs real Go 1.25 (*big.Float).GobEncode ─────────
        // Reference blobs captured from Go 1.25's math/big. For values
        // built by SetFloat64 the mantissa is minimal, so goish's
        // whole-64-bit-word framing must reproduce a 64-bit Go build's
        // bytes exactly.
        {
            let (e1, _) = {
                let mut f = big::Float::new();
                f.SetPrec(80);
                f.SetFloat64(1.5);
                f.GobEncode()
            };
            check(
                &*e1 == &[
                    0x01u8, 0x0a, 0, 0, 0, 0x50, 0, 0, 0, 0x01, 0xc0, 0, 0, 0, 0, 0, 0, 0,
                ][..],
                b"float Gob bytes == Go (p80 1.5)",
            );

            let (e2, _) = {
                let mut f = big::Float::new();
                f.SetPrec(100);
                f.SetFloat64(-3.25);
                f.GobEncode()
            };
            check(
                &*e2 == &[
                    0x01u8, 0x0b, 0, 0, 0, 0x64, 0, 0, 0, 0x02, 0xd0, 0, 0, 0, 0, 0, 0, 0,
                ][..],
                b"float Gob bytes == Go (p100 -3.25)",
            );

            let (e3, _) = {
                let mut f = big::Float::new();
                f.SetPrec(64);
                f.SetFloat64(0.5);
                f.GobEncode()
            };
            check(
                &*e3 == &[
                    0x01u8, 0x0a, 0, 0, 0, 0x40, 0, 0, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0,
                ][..],
                b"float Gob bytes == Go (p64 0.5)",
            );

            // Decode a Go-produced blob → correct value + precision.
            let goblob = slice::<goish::byte>::__from_vec(alloc::vec![
                0x01u8, 0x0a, 0, 0, 0, 0x50, 0, 0, 0, 0x01, 0xc0, 0, 0, 0, 0, 0, 0, 0
            ]);
            let mut dec = big::Float::new();
            let derr2 = dec.GobDecode(goblob);
            let mut want15 = big::Float::new();
            want15.SetPrec(80);
            want15.SetFloat64(1.5);
            check(
                derr2 == goish::nil && dec.Cmp(&want15) == 0 && dec.Prec() == 80,
                b"float Gob decode Go blob (p80 1.5)",
            );

            // Decode a Go arithmetic-built blob whose mantissa carries
            // an extra trailing zero word (2.0 @ prec 256, 16-byte mant).
            let goblob2 = slice::<goish::byte>::__from_vec(alloc::vec![
                0x01u8, 0x0a, 0, 0, 0x01, 0, 0, 0, 0, 0x02, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0
            ]);
            let mut dec2 = big::Float::new();
            let derr3 = dec2.GobDecode(goblob2);
            check(
                derr3 == goish::nil && dec2.Cmp(&big::NewFloat(2.0)) == 0,
                b"float Gob decode Go blob (longer mantissa)",
            );
        }
    }

    // ── Int.Rand — uniform pseudo-random in [0, n) ─────────────────
    {
        use goish::fmt::Formatter;

        // Deterministic source so the smoke test is reproducible.
        let mut rnd = rand::New(rand::NewSource(1));

        // n <= 0 → result is 0.
        let zero_n = big::NewInt(0);
        let mut zr = big::Int::new();
        zr.Rand(&mut rnd, &zero_n);
        check(zr.Sign() == 0, b"rand n==0 -> 0");

        let neg_n = big::NewInt(-5);
        let mut nr = big::Int::new();
        nr.Rand(&mut rnd, &neg_n);
        check(nr.Sign() == 0, b"rand n<0 -> 0");

        // Small bound: many draws, every sample in [0, n).
        let small = big::NewInt(7);
        let mut small_ok = true;
        let mut seen_nonzero = false;
        for _ in 0..200 {
            let mut r = big::Int::new();
            r.Rand(&mut rnd, &small);
            if !(r.Sign() >= 0 && r.Cmp(&small) < 0) {
                small_ok = false;
            }
            if r.Sign() > 0 {
                seen_nonzero = true;
            }
        }
        check(small_ok, b"rand small in [0,7)");
        check(seen_nonzero, b"rand small produces nonzero");

        // n == 1 → only value possible is 0.
        let one = big::NewInt(1);
        let mut all_zero = true;
        for _ in 0..50 {
            let mut r = big::Int::new();
            r.Rand(&mut rnd, &one);
            if r.Sign() != 0 {
                all_zero = false;
            }
        }
        check(all_zero, b"rand n==1 -> always 0");

        // Multi-limb bound: 10^40 spans several u32 limbs.
        let huge = pow10(40);
        let mut huge_ok = true;
        for _ in 0..200 {
            let mut r = big::Int::new();
            r.Rand(&mut rnd, &huge);
            if !(r.Sign() >= 0 && r.Cmp(&huge) < 0) {
                huge_ok = false;
            }
        }
        check(huge_ok, b"rand multi-limb in [0,10^40)");

        // Power-of-two bound exercises the top-word masking (msw fully
        // significant when bitlen is a multiple of 32).
        let p32 = pow2(64);
        let mut p32_ok = true;
        for _ in 0..200 {
            let mut r = big::Int::new();
            r.Rand(&mut rnd, &p32);
            if !(r.Sign() >= 0 && r.Cmp(&p32) < 0) {
                p32_ok = false;
            }
        }
        check(p32_ok, b"rand in [0,2^64)");

        // ── Int.Format via fmt::Formatter ──────────────────────────
        let v = big::NewInt(255);

        // %x — base 16, matches Text(16).
        let mut st = TestState::new();
        v.Format(&mut st, 'x' as goish::rune);
        check(
            st.buf == v.Text(16).as_bytes(),
            b"Int.Format %x == Text(16)",
        );

        // %d — base 10.
        let mut st = TestState::new();
        v.Format(&mut st, 'd' as goish::rune);
        check(st.buf == b"255", b"Int.Format %d");

        // %b — base 2.
        let mut st = TestState::new();
        v.Format(&mut st, 'b' as goish::rune);
        check(st.buf == v.Text(2).as_bytes(), b"Int.Format %b == Text(2)");

        // %X — uppercase hex.
        let mut st = TestState::new();
        v.Format(&mut st, 'X' as goish::rune);
        check(st.buf == b"FF", b"Int.Format %X uppercase");

        // %#x — '#' flag adds 0x prefix.
        let mut st = TestState::new().with_flag(b'#');
        v.Format(&mut st, 'x' as goish::rune);
        check(st.buf == b"0xff", b"Int.Format %#x prefix");

        // %O — octal with 0o prefix.
        let mut st = TestState::new();
        big::NewInt(8).Format(&mut st, 'O' as goish::rune);
        check(st.buf == b"0o10", b"Int.Format %O prefix");

        // Negative sign.
        let mut st = TestState::new();
        big::NewInt(-12).Format(&mut st, 'd' as goish::rune);
        check(st.buf == b"-12", b"Int.Format %d negative");

        // '+' flag forces a sign on positives.
        let mut st = TestState::new().with_flag(b'+');
        big::NewInt(12).Format(&mut st, 'd' as goish::rune);
        check(st.buf == b"+12", b"Int.Format %+d sign");

        // Precision zero-pads the digits ("%.5d" of 42 → 00042).
        let mut st = TestState::new().with_prec(5);
        big::NewInt(42).Format(&mut st, 'd' as goish::rune);
        check(st.buf == b"00042", b"Int.Format %.5d precision");

        // Width pads on the left with spaces ("%6d" of 42 → "    42").
        let mut st = TestState::new().with_width(6);
        big::NewInt(42).Format(&mut st, 'd' as goish::rune);
        check(st.buf == b"    42", b"Int.Format %6d width");

        // '0' flag zero-pads to the width.
        let mut st = TestState::new().with_width(6).with_flag(b'0');
        big::NewInt(42).Format(&mut st, 'd' as goish::rune);
        check(st.buf == b"000042", b"Int.Format %06d zero-pad");

        // '-' flag left-justifies.
        let mut st = TestState::new().with_width(6).with_flag(b'-');
        big::NewInt(42).Format(&mut st, 'd' as goish::rune);
        check(st.buf == b"42    ", b"Int.Format %-6d left");

        // Unsupported verb → %!<verb>(big.Int=<dec>).
        let mut st = TestState::new();
        big::NewInt(9).Format(&mut st, 'q' as goish::rune);
        check(st.buf == b"%!q(big.Int=9)", b"Int.Format bad verb");

        // ── Float.Format via fmt::Formatter ────────────────────────
        let fv = big::NewFloat(2.25);

        // %f — fixed point, default precision 6.
        let mut st = TestState::new();
        fv.Format(&mut st, 'f' as goish::rune);
        check(
            st.buf == fv.Text(b'f', 6).as_bytes(),
            b"Float.Format %f default prec",
        );

        // %.2f — precision from State.
        let mut st = TestState::new().with_prec(2);
        fv.Format(&mut st, 'f' as goish::rune);
        check(st.buf == b"2.25", b"Float.Format %.2f");

        // %e — scientific.
        let mut st = TestState::new().with_prec(2);
        big::NewFloat(125.0).Format(&mut st, 'e' as goish::rune);
        check(st.buf == b"1.25e+02", b"Float.Format %e");

        // %g — like Text('g', -1) by default (no precision).
        let mut st = TestState::new();
        big::NewFloat(1.0e7).Format(&mut st, 'g' as goish::rune);
        check(st.buf == b"1e+07", b"Float.Format %g default");

        // Negative float carries its sign.
        let mut st = TestState::new().with_prec(2);
        big::NewFloat(-2.25).Format(&mut st, 'f' as goish::rune);
        check(st.buf == b"-2.25", b"Float.Format %f negative");

        // '+' flag forces a sign on positive floats.
        let mut st = TestState::new().with_prec(2).with_flag(b'+');
        fv.Format(&mut st, 'f' as goish::rune);
        check(st.buf == b"+2.25", b"Float.Format %+f sign");

        // Width pads on the left.
        let mut st = TestState::new().with_prec(2).with_width(8);
        fv.Format(&mut st, 'f' as goish::rune);
        check(st.buf == b"    2.25", b"Float.Format %8.2f width");

        // '0' flag zero-pads a float to width.
        let mut st = TestState::new().with_prec(2).with_width(8).with_flag(b'0');
        fv.Format(&mut st, 'f' as goish::rune);
        check(st.buf == b"00002.25", b"Float.Format %08.2f zero-pad");

        // '-' flag left-justifies.
        let mut st = TestState::new().with_prec(2).with_width(8).with_flag(b'-');
        fv.Format(&mut st, 'f' as goish::rune);
        check(st.buf == b"2.25    ", b"Float.Format %-8.2f left");

        // %v handled like %g.
        let mut st = TestState::new();
        big::NewFloat(3.5).Format(&mut st, 'v' as goish::rune);
        check(
            st.buf == big::NewFloat(3.5).String().as_bytes() || st.buf == b"3.5",
            b"Float.Format %v like g",
        );

        // Unsupported verb → %!<verb>(big.Float=...).
        let mut st = TestState::new();
        fv.Format(&mut st, 'd' as goish::rune);
        check(&st.buf[..11] == b"%!d(big.Flo", b"Float.Format bad verb");
    }

    // ── fmt::Scanner — Int / Rat / Float ───────────────────────────
    {
        use goish::fmt::Scanner;

        // Int.Scan — decimal under the 'd' verb.
        let mut z = big::Int::new();
        let mut cur = ScanCursor::new(b"1234");
        let err = z.Scan(&mut cur, 'd' as goish::rune);
        check(err == goish::nil && z.Int64() == 1234, b"Int.Scan 1234");

        // Int.Scan — negative.
        let mut z = big::Int::new();
        let mut cur = ScanCursor::new(b"-42");
        let err = z.Scan(&mut cur, 'd' as goish::rune);
        check(err == goish::nil && z.Int64() == -42, b"Int.Scan -42");

        // Int.Scan — multi-limb decimal (10^25, well beyond i64).
        let want = pow10(25);
        let mut z = big::Int::new();
        let mut cur = ScanCursor::new(want.String().as_bytes());
        let err = z.Scan(&mut cur, 'd' as goish::rune);
        check(
            err == goish::nil && z.Cmp(&want) == 0,
            b"Int.Scan multi-limb",
        );

        // Int.Scan — hex literal under the 'x' verb (0xff == 255).
        let mut z = big::Int::new();
        let mut cur = ScanCursor::new(b"ff");
        let err = z.Scan(&mut cur, 'x' as goish::rune);
        check(err == goish::nil && z.Int64() == 255, b"Int.Scan hex ff");

        // Int.Scan — leading whitespace is skipped.
        let mut z = big::Int::new();
        let mut cur = ScanCursor::new(b"   77");
        let err = z.Scan(&mut cur, 'd' as goish::rune);
        check(err == goish::nil && z.Int64() == 77, b"Int.Scan skip space");

        // Int.Scan — unsupported verb → non-nil error.
        let mut z = big::Int::new();
        let mut cur = ScanCursor::new(b"5");
        let err = z.Scan(&mut cur, 'q' as goish::rune);
        check(err != goish::nil, b"Int.Scan bad verb");

        // Rat.Scan — fraction "22/7" under the 'v' verb.
        let mut r = big::Rat::default();
        let mut cur = ScanCursor::new(b"22/7");
        let err = r.Scan(&mut cur, 'v' as goish::rune);
        check(
            err == goish::nil && r.Num().Int64() == 22 && r.Denom().Int64() == 7,
            b"Rat.Scan 22/7",
        );

        // Rat.Scan — a plain integer "3" → 3/1.
        let mut r = big::Rat::default();
        let mut cur = ScanCursor::new(b"3");
        let err = r.Scan(&mut cur, 'g' as goish::rune);
        check(
            err == goish::nil && r.Num().Int64() == 3 && r.Denom().Int64() == 1,
            b"Rat.Scan 3",
        );

        // Rat.Scan — unsupported verb → non-nil error.
        let mut r = big::Rat::default();
        let mut cur = ScanCursor::new(b"1/2");
        let err = r.Scan(&mut cur, 'd' as goish::rune);
        check(err != goish::nil, b"Rat.Scan bad verb");

        // Float.Scan — decimal "3.14159" under the 'g' verb.
        let mut fl = big::Float::new();
        let mut cur = ScanCursor::new(b"3.14159");
        let err = fl.Scan(&mut cur, 'g' as goish::rune);
        let (fv, _) = fl.Float64();
        check(
            err == goish::nil && (fv - 3.14159).abs() < 1e-9,
            b"Float.Scan 3.14159",
        );

        // Float.Scan — scientific "-2.5e3" under the 'e' verb.
        let mut fl = big::Float::new();
        let mut cur = ScanCursor::new(b"-2.5e3");
        let err = fl.Scan(&mut cur, 'e' as goish::rune);
        let (fv, _) = fl.Float64();
        check(
            err == goish::nil && (fv - (-2500.0)).abs() < 1e-6,
            b"Float.Scan -2.5e3",
        );

        // Float.Scan — unsupported verb → non-nil error.
        let mut fl = big::Float::new();
        let mut cur = ScanCursor::new(b"1.0");
        let err = fl.Scan(&mut cur, 'd' as goish::rune);
        check(err != goish::nil, b"Float.Scan bad verb");
    }

    // ── Salvaged from src/math/big/mod.rs's deleted #[cfg(test)] ───
    //
    // `cargo test` cannot link in this crate (the test harness pulls
    // in std, whose `panic_impl` lang item collides with goish's), so
    // that module was unreachable. Everything it covered that this
    // example did not already reach is below.
    {
        // Euclidean Div/DivMod at explicit small values. The
        // multi-precision cases above check the q*d+r==n identity,
        // which several conventions satisfy; these pin Go's.
        let mut q = big::Int::new();
        q.Div(&big::NewInt(17), &big::NewInt(5));
        check(q.Int64() == 3, b"div 17/5");

        let mut q2 = big::Int::new();
        let mut m2 = big::Int::new();
        q2.DivMod(&big::NewInt(17), &big::NewInt(5), &mut m2);
        check(q2.Int64() == 3 && m2.Int64() == 2, b"divmod 17/5");

        // -17 = (-4)*5 + 3, with 0 <= 3 < 5.
        let mut q3 = big::Int::new();
        let mut m3 = big::Int::new();
        q3.DivMod(&big::NewInt(-17), &big::NewInt(5), &mut m3);
        check(q3.Int64() == -4 && m3.Int64() == 3, b"divmod -17/5 euclid");

        // The remainder stays non-negative when the divisor is
        // negative too: -17 = 4*(-5) + 3.
        let mut q4 = big::Int::new();
        let mut m4 = big::Int::new();
        q4.DivMod(&big::NewInt(-17), &big::NewInt(-5), &mut m4);
        check(q4.Int64() == 4 && m4.Int64() == 3, b"divmod -17/-5 euclid");

        // Abs, including the self-aliasing z.Abs(z) path.
        let mut ab = big::Int::new();
        ab.Abs(&big::NewInt(-42));
        check(ab.Int64() == 42, b"abs -42");
        ab.Abs(&big::NewInt(42));
        check(ab.Int64() == 42, b"abs 42");
        let mut al = big::NewInt(-9);
        let al_src = al.clone();
        al.Abs(&al_src);
        check(al.Int64() == 9, b"abs self-aliased");

        // BorrowMut yields a non-nil nilable_refmut; dropping it
        // releases the borrow and leaves the Int untouched.
        let mut bm = big::NewInt(99);
        let nrm = bm.BorrowMut();
        let was_nil = nrm.IsNil();
        drop(nrm);
        check(!was_nil && bm.Int64() == 99, b"borrowmut not nil");

        // Rat.SetInt gives denominator 1.
        let mut ri = big::Rat::new();
        ri.SetInt(&big::NewInt(42));
        check(
            ri.Num().Int64() == 42 && ri.Denom().Int64() == 1,
            b"rat setint 42",
        );

        // SetFrac normalizes too, so (2/3)*(3/4) reads back as 1/2 and
        // not 6/12 -- Go's Rat has no unreduced state at all: every
        // constructor and operator ends in norm().
        //
        //   scripts/goref.sh math/big:
        //     SetFrac mul: num=1 denom=2
        let mut ua = big::Rat::new();
        ua.SetFrac(&big::NewInt(2), &big::NewInt(3));
        let mut ub = big::Rat::new();
        ub.SetFrac(&big::NewInt(3), &big::NewInt(4));
        let mut uc = big::Rat::new();
        uc.Mul(&ua, &ub);
        check(
            uc.Num().Int64() == 1 && uc.Denom().Int64() == 2,
            b"rat setfrac mul reduces",
        );

        // val.Mul(val, mv) -- the self-aliasing shape fmt's Sscanf
        // driver uses when accumulating a scanned decimal.
        let mut val = big::Rat::new();
        val.SetFrac(&big::NewInt(7), &big::NewInt(2));
        let mut mv = big::Rat::new();
        mv.SetInt(&big::NewInt(3)); // 3/1
        let val_src = val.clone();
        val.Mul(&val_src, &mv);
        check(
            val.Num().Int64() == 21 && val.Denom().Int64() == 2,
            b"rat mul self-aliased",
        );

        // parse_decimal_into_rat -- reached indirectly through
        // fmt.Sscanf("%f") (see examples/fmt_sscanf_smoke.rs); these
        // pin it directly. Values are Go's Rat.SetString, which is what
        // it mirrors:
        //
        //   scripts/goref.sh math/big:
        //     SetString("3.14") num=157 denom=50
        //     SetString("100")  num=100 denom=1
        //     SetString("-0.5") num=-1  denom=2
        let mut p1 = big::Rat::new();
        let ok1 = big::parse_decimal_into_rat("3.14", &mut p1);
        check(
            ok1 && p1.Num().Int64() == 157 && p1.Denom().Int64() == 50,
            b"parse rat 3.14",
        );

        let mut p2 = big::Rat::new();
        let ok2 = big::parse_decimal_into_rat("100", &mut p2);
        check(
            ok2 && p2.Num().Int64() == 100 && p2.Denom().Int64() == 1,
            b"parse rat 100",
        );

        let mut p3 = big::Rat::new();
        let ok3 = big::parse_decimal_into_rat("-0.5", &mut p3);
        check(
            ok3 && p3.Num().Int64() == -1 && p3.Denom().Int64() == 2,
            b"parse rat -0.5",
        );

        let mut p4 = big::Rat::new();
        check(
            !big::parse_decimal_into_rat("not-a-number", &mut p4),
            b"parse rat rejects junk",
        );
    }

    let _ = &int::from(0);
    let _ = string::from("");
    report();
}
