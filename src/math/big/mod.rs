// math/big — minimal port of Go's `math/big` package.
//
//   Go                                   goish
//   ──────────────────────────────────   ──────────────────────────────────
//   var z big.Int                        let mut z = big::Int::default();
//   z := big.NewInt(42)                  let z = big::NewInt(42);
//   z.SetInt64(x)                        z.SetInt64(x);
//   z.Cmp(other)                         z.Cmp(&other)
//   z.Int64()                            z.Int64()
//   z.Exp(x, y, m)                       z.Exp(&x, &y, &m)   (panics if y is negative)
//   z.Mod(x, y)                          z.Mod(&x, &y)       (Euclidean)
//
// Scope: this v1 is genuine multi-precision arithmetic. The internal
// layout is `Vec<u32>` little-endian limbs + a sign bit — same shape as
// Go's `nat []Word`, just with a narrower 32-bit limb so intermediate
// products stay in u64 without needing `__udivmodti4`/`__umodti3`.
//
//   * `Mul` is schoolbook (operand-scanning) multiplication, O(n*m).
//   * `Div` / `Mod` / `DivMod` use multi-precision long division
//     (Knuth TAOCP vol. 2, Algorithm D — normalised classic long
//     division). The divisor may be any size. Semantics are Euclidean
//     (non-negative remainder), matching Go's `(*Int).Div`/`Mod`/
//     `DivMod`.
//   * `Exp` is square-and-multiply on top of the multi-precision `Mul`
//     and `Mod`, so RSA-sized operands and moduli work.
//
// The one remaining limitation: `Exp` with a negative exponent panics
// (it requires a modular inverse / extended-GCD, which is deferred).
// Everything else is unrestricted.

#![allow(non_snake_case)]

extern crate alloc;
use alloc::vec::Vec;
use core::cmp::Ordering;

use crate::types::int;

/// `big.Word` — a raw arithmetic word. Go's `Word` is `uintptr`; on this
/// 64-bit target it is `u64`. Surfaced by `(*Int).Bits` / `SetBits`.
pub type Word = u64;

/// `big.Accuracy` — describes the rounding error produced by a result
/// that could not be represented exactly. Go models it as an `int8`
/// with `Below = -1, Exact = 0, Above = +1`; the goish-shape is an
/// enum carrying the same three states. Reused by `Float` (later task).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Accuracy {
    /// The result is smaller than the true (exact) value.
    Below,
    /// The result is exact.
    Exact,
    /// The result is larger than the true (exact) value.
    Above,
}

impl crate::fmt::Stringer for Accuracy {
    fn String(&self) -> crate::gostring::string {
        match self {
            Accuracy::Below => crate::gostring::string::from("Below"),
            Accuracy::Exact => crate::gostring::string::from("Exact"),
            Accuracy::Above => crate::gostring::string::from("Above"),
        }
    }
}

/// `big.Int` — signed multi-precision integer. Zero value represents 0.
#[derive(Clone, Default)]
pub struct Int {
    neg: bool,
    abs: Vec<u32>, // little-endian limbs, no trailing zeros
}

/// `big.Rat` — arbitrary-precision rational. Stored as numerator and
/// denominator pair; the denominator is always > 0 and the fraction
/// is kept in lowest terms after `SetFrac`. Zero value represents 0/1.
///
/// Surfaced by gopkg.in/inf.v0's `Dec.scaleQuoExact` path, which uses
/// `new(big.Rat).SetFrac(num, den).Denom()` to factor 2's and 5's out
/// of the denominator. The implementation is intentionally minimal:
/// only the two methods inf.v0 needs are exposed; full Rat arithmetic
/// is deferred until a port surfaces a real need.
#[derive(Clone, Default)]
pub struct Rat {
    num: Int,
    den: Int, // 1 when zero (Go's normalization convention)
}

impl Rat {
    /// `var z big.Rat` — fresh zero-valued Rat (0/1).
    pub fn new() -> Self {
        Rat { num: Int::default(), den: NewInt(1) }
    }

    /// `(*Rat).SetFrac(a, b)` — set z = a/b, reduced to lowest terms.
    /// Panics on b=0. Returns &mut Self per Go's chained-call idiom.
    pub fn SetFrac(&mut self, a: &Int, b: &Int) -> &mut Self {
        if b.Sign() == 0 {
            panic!("division by zero");
        }
        self.num = a.clone();
        self.den = b.clone();
        self.norm()
    }

    /// `(*Rat).norm()` — mirror of Go's `rat.go:norm`. Moves a negative
    /// denominator's sign onto the numerator, reduces num/den by their
    /// GCD, and normalizes a zero numerator to `0/1`. Panics on den=0.
    fn norm(&mut self) -> &mut Self {
        if self.den.Sign() == 0 {
            panic!("division by zero");
        }
        // Denominator is always > 0 in Go's Rat — carry sign onto num.
        if self.den.neg {
            self.num.neg = !self.num.neg;
            self.den.neg = false;
        }
        if self.num.Sign() == 0 {
            // z == 0; normalize to 0/1.
            self.num.neg = false;
            self.den = NewInt(1);
            return self;
        }
        // z is a fraction; divide num and den by gcd(|num|, |den|).
        let mut g = Int::default();
        g.GCD(crate::nilval::nil, crate::nilval::nil, &self.num, &self.den);
        if g.Cmp(&NewInt(1)) != 0 {
            let mut new_num = Int::default();
            new_num.Div(&self.num, &g);
            let mut new_den = Int::default();
            new_den.Div(&self.den, &g);
            self.num = new_num;
            self.den = new_den;
        }
        self
    }

    /// `(*Rat).Num()` — returns a borrow of the numerator. Go returns
    /// `*Int`; the &Int form is the Goish-shape equivalent.
    pub fn Num(&self) -> &Int {
        &self.num
    }

    /// `(*Rat).Denom()` — returns a borrow of the denominator.
    pub fn Denom(&self) -> &Int {
        &self.den
    }

    /// `(*Rat).SetInt(x)` — set z = x/1 and return self.
    /// Mirrors Go's `rat.go:SetInt`: copies the integer into the
    /// numerator and forces the denominator to 1. Accepts any
    /// `AsRef<Int>` (covers `&Int`, owned `Int`, `nilable<Int>`,
    /// `nilable_refmut<Int>` — matches Go's `*big.Int` passes).
    pub fn SetInt<X: AsRef<Int>>(&mut self, x: X) -> &mut Self {
        let x = x.as_ref();
        self.num = x.clone();
        self.den = NewInt(1);
        // Normalise sign — Rat keeps the sign on the numerator only.
        self.den.neg = false;
        self
    }

    /// `(*Rat).Set(x)` — copy x into z and return z.
    pub fn Set(&mut self, x: &Rat) -> &mut Self {
        if !core::ptr::eq(self as *const _, x as *const _) {
            self.num = x.num.clone();
            self.den = x.den.clone();
        }
        self
    }

    /// `(*Rat).Mul(x, y)` — z = x*y, return z. Mirrors Go's
    /// `rat.go:Mul`. Aliasing-safe: callers commonly write
    /// `val.Mul(val, mv)` so we read x and y before mutating self.
    /// Takes `&Rat` for both args (the canonical Go shape after
    /// pointer-strip lowering). AsRef-widening exposed deeper
    /// transpiler borrow-conflict bugs at the `val.Mul(val, mv)`
    /// pattern — keeping the strict signature so the transpiler's
    /// own auto-borrow/clone fix is the right place to address them.
    pub fn Mul(&mut self, x: &Rat, y: &Rat) -> &mut Self {
        // Snapshot inputs first to handle self-aliasing.
        let xnum = x.num.clone();
        let xden = x.den.clone();
        let ynum = y.num.clone();
        let yden = y.den.clone();
        // num = xnum * ynum
        let mut new_num = Int::default();
        new_num.Mul(&xnum, &ynum);
        // den = xden * yden
        let mut new_den = Int::default();
        new_den.Mul(&xden, &yden);
        self.num = new_num;
        self.den = new_den;
        self.norm()
    }

    /// `(*Rat).Add(x, y)` — z = x + y, reduced. Aliasing-safe.
    pub fn Add(&mut self, x: &Rat, y: &Rat) -> &mut Self {
        let xnum = x.num.clone();
        let xden = x.den.clone();
        let ynum = y.num.clone();
        let yden = y.den.clone();
        // num = xnum*yden + ynum*xden
        let mut a1 = Int::default();
        a1.Mul(&xnum, &yden);
        let mut a2 = Int::default();
        a2.Mul(&ynum, &xden);
        let mut new_num = Int::default();
        new_num.Add(&a1, &a2);
        // den = xden*yden
        let mut new_den = Int::default();
        new_den.Mul(&xden, &yden);
        self.num = new_num;
        self.den = new_den;
        self.norm()
    }

    /// `(*Rat).Sub(x, y)` — z = x - y, reduced. Aliasing-safe.
    pub fn Sub(&mut self, x: &Rat, y: &Rat) -> &mut Self {
        let xnum = x.num.clone();
        let xden = x.den.clone();
        let ynum = y.num.clone();
        let yden = y.den.clone();
        // num = xnum*yden - ynum*xden
        let mut a1 = Int::default();
        a1.Mul(&xnum, &yden);
        let mut a2 = Int::default();
        a2.Mul(&ynum, &xden);
        let mut new_num = Int::default();
        new_num.Sub(&a1, &a2);
        // den = xden*yden
        let mut new_den = Int::default();
        new_den.Mul(&xden, &yden);
        self.num = new_num;
        self.den = new_den;
        self.norm()
    }

    /// `(*Rat).Quo(x, y)` — z = x / y, reduced. Panics if y == 0.
    /// Aliasing-safe.
    pub fn Quo(&mut self, x: &Rat, y: &Rat) -> &mut Self {
        if y.num.Sign() == 0 {
            panic!("big::Rat::Quo: division by zero");
        }
        let xnum = x.num.clone();
        let xden = x.den.clone();
        let ynum = y.num.clone();
        let yden = y.den.clone();
        // num = xnum*yden, den = xden*ynum
        let mut new_num = Int::default();
        new_num.Mul(&xnum, &yden);
        let mut new_den = Int::default();
        new_den.Mul(&xden, &ynum);
        self.num = new_num;
        self.den = new_den;
        self.norm()
    }

    /// `(*Rat).Neg(x)` — z = -x. Aliasing-safe.
    pub fn Neg(&mut self, x: &Rat) -> &mut Self {
        let mut new_num = Int::default();
        new_num.Neg(&x.num);
        self.num = new_num;
        self.den = x.den.clone();
        self.norm()
    }

    /// `(*Rat).Abs(x)` — z = |x|. Aliasing-safe.
    pub fn Abs(&mut self, x: &Rat) -> &mut Self {
        let mut new_num = Int::default();
        new_num.Abs(&x.num);
        self.num = new_num;
        self.den = x.den.clone();
        self.norm()
    }

    /// `(*Rat).Inv(x)` — z = 1/x. Panics if x == 0. Aliasing-safe.
    pub fn Inv(&mut self, x: &Rat) -> &mut Self {
        if x.num.Sign() == 0 {
            panic!("big::Rat::Inv: division by zero");
        }
        // Swap numerator and denominator.
        let new_num = x.den.clone();
        let new_den = x.num.clone();
        self.num = new_num;
        self.den = new_den;
        self.norm()
    }

    /// `(*Rat).Cmp(y)` — -1 / 0 / 1. Cross-multiplies; both denominators
    /// are positive so the comparison direction is preserved.
    pub fn Cmp(&self, y: &Rat) -> int {
        let mut a = Int::default();
        a.Mul(&self.num, &y.den);
        let mut b = Int::default();
        b.Mul(&y.num, &self.den);
        a.Cmp(&b)
    }

    /// `(*Rat).Sign()` — sign of the numerator: -1 / 0 / 1.
    pub fn Sign(&self) -> int {
        self.num.Sign()
    }

    /// `(*Rat).IsInt()` — true iff the denominator is 1.
    pub fn IsInt(&self) -> bool {
        self.den.Cmp(&NewInt(1)) == 0
    }

    /// `(*Rat).SetInt64(x)` — z = x/1, return z.
    pub fn SetInt64(&mut self, x: i64) -> &mut Self {
        self.num = NewInt(x);
        self.den = NewInt(1);
        self
    }

    /// `(*Rat).SetUint64(x)` — z = x/1, return z.
    pub fn SetUint64(&mut self, x: u64) -> &mut Self {
        let mut num = Int::default();
        num.SetUint64(x);
        self.num = num;
        self.den = NewInt(1);
        self
    }

    /// `(*Rat).SetFrac64(a, b)` — z = a/b, reduced. Panics on b=0.
    pub fn SetFrac64(&mut self, a: i64, b: i64) -> &mut Self {
        if b == 0 {
            panic!("division by zero");
        }
        self.num = NewInt(a);
        self.den = NewInt(b);
        self.norm()
    }

    /// `(*Rat).String()` — `"a/b"` form, always (even when b == 1).
    pub fn String(&self) -> crate::string {
        crate::string::from_bytes(&rat_marshal(&self.num, &self.den))
    }

    /// `(*Rat).RatString()` — `"a/b"` if b != 1, else just `"a"`.
    pub fn RatString(&self) -> crate::string {
        if self.IsInt() {
            return self.num.Text(10);
        }
        self.String()
    }

    /// `(*Rat).FloatString(prec)` — decimal string with exactly `prec`
    /// digits after the radix point. The last digit is rounded to
    /// nearest; halves are rounded away from zero (matching Go).
    pub fn FloatString(&self, prec: int) -> crate::string {
        let mut buf: Vec<u8> = Vec::new();
        if self.IsInt() {
            buf.extend_from_slice(&itoa(self.num.neg, &self.num.abs, 10));
            if prec > 0 {
                buf.push(b'.');
                for _ in 0..prec {
                    buf.push(b'0');
                }
            }
            return crate::string::from_bytes(&buf);
        }
        // self.den != 1
        let (mut q, mut r) = divmod_limbs(&self.num.abs, &self.den.abs);

        // p = 10**prec (1 when prec <= 0).
        let p = if prec > 0 {
            pow10_limbs(prec as u64)
        } else {
            alloc::vec![1u32]
        };

        // r = (r * p) / den, with r2 = (r * p) % den.
        r = mul_limbs(&r, &p);
        let (r_q, r2) = divmod_limbs(&r, &self.den.abs);
        let mut r = r_q;

        // Round up if 2*r2 >= den.
        let r2_double = add_limbs(&r2, &r2);
        if abs_cmp(&self.den.abs, &r2_double) != Ordering::Greater {
            r = add_limbs(&r, &[1]);
            if abs_cmp(&r, &p) != Ordering::Less {
                q = add_limbs(&q, &[1]);
                r = sub_limbs(&r, &p);
            }
        }

        if self.num.neg {
            buf.push(b'-');
        }
        // itoa ignores the sign when q == 0.
        buf.extend_from_slice(&itoa(false, &q, 10));

        if prec > 0 {
            buf.push(b'.');
            let rs = itoa(false, &r, 10);
            for _ in 0..(prec - rs.len() as int) {
                buf.push(b'0');
            }
            buf.extend_from_slice(&rs);
        }
        crate::string::from_bytes(&buf)
    }

    /// `(*Rat).SetString(s)` — parse `"a/b"`, a plain integer, or a
    /// decimal/scientific float. Returns `(self, ok)`. On failure the
    /// value of self is undefined (matching Go) and `ok == false`.
    pub fn SetString<S: Into<crate::string>>(&mut self, s: S) -> (&mut Rat, bool) {
        let s: crate::string = s.into();
        let bytes = s.as_bytes();
        if bytes.is_empty() {
            return (self, false);
        }
        // Fraction "a/b" form.
        if let Some(sep) = bytes.iter().position(|&c| c == b'/') {
            let num_part = &bytes[..sep];
            let den_part = &bytes[sep + 1..];
            // Numerator may be signed; parse base-0 (auto-detects 0x/0o/0b).
            let num = match scan_int(num_part, 0) {
                Some((neg, abs)) => {
                    let mut n = Int::default();
                    n.neg = neg && !abs.is_empty();
                    n.abs = abs;
                    n
                }
                None => return (self, false),
            };
            // Denominator may not be signed.
            if den_part.is_empty()
                || den_part[0] == b'+'
                || den_part[0] == b'-'
            {
                return (self, false);
            }
            let den = match scan_int(den_part, 0) {
                Some((_, abs)) if !abs.is_empty() => {
                    let mut d = Int::default();
                    d.abs = abs;
                    d
                }
                _ => return (self, false),
            };
            self.num = num;
            self.den = den;
            self.norm();
            return (self, true);
        }
        // Decimal / scientific float (or a plain integer).
        if parse_decimal_into_rat(core::str::from_utf8(bytes).unwrap_or(""), self) {
            (self, true)
        } else {
            (self, false)
        }
    }

    /// `(*Rat).Float32()` — nearest f32 to x, plus an exact flag.
    /// The sign of the result always matches the sign of x.
    pub fn Float32(&self) -> (crate::types::float32, bool) {
        let (f, exact) = quot_to_float32(&self.num.abs, &self.den.abs);
        if self.num.neg {
            (-f, exact)
        } else {
            (f, exact)
        }
    }

    /// `(*Rat).Float64()` — nearest f64 to x, plus an exact flag.
    /// The sign of the result always matches the sign of x.
    pub fn Float64(&self) -> (crate::types::float64, bool) {
        let (f, exact) = quot_to_float64(&self.num.abs, &self.den.abs);
        if self.num.neg {
            (-f, exact)
        } else {
            (f, exact)
        }
    }

    /// `(*Rat).FloatPrec()` — `(n, exact)`. `n` is the number of
    /// non-repeating fractional decimal digits; `exact` is true iff a
    /// finite decimal representation exists (i.e. the reduced
    /// denominator's only prime factors are 2 and 5).
    pub fn FloatPrec(&self) -> (int, bool) {
        // d >= 1 (denominator is always positive; zero-value acts as 1).
        let d: Vec<u32> = if self.den.abs.is_empty() {
            alloc::vec![1u32]
        } else {
            self.den.abs.clone()
        };
        // p2 = number of trailing zero bits of d. Reduce d by 2^p2.
        let p2 = trailing_zero_bits(&d);
        let mut q = rsh_limbs(&d, p2);
        // p5 = number of factors of 5 in q.
        let mut p5: u64 = 0;
        let five = alloc::vec![5u32];
        loop {
            let (quot, rem) = divmod_limbs(&q, &five);
            if !rem.is_empty() {
                break;
            }
            p5 += 1;
            q = quot;
        }
        let n = if p2 > p5 { p2 } else { p5 };
        let exact = abs_cmp(&q, &[1]) == Ordering::Equal;
        (n as int, exact)
    }

    /// `(*Rat).SetFloat64(f)` — exact conversion from an f64. The bool
    /// is `false` for Inf/NaN (self is then left unchanged), matching
    /// Go's `nil` return for non-finite inputs.
    pub fn SetFloat64(&mut self, f: crate::types::float64) -> (&mut Rat, bool) {
        const EXP_MASK: u64 = (1 << 11) - 1;
        let bits = f.to_bits();
        let mut mantissa = bits & ((1u64 << 52) - 1);
        let mut exp: i64 = ((bits >> 52) & EXP_MASK) as i64;
        if exp == EXP_MASK as i64 {
            // non-finite (Inf / NaN)
            return (self, false);
        } else if exp == 0 {
            // denormal
            exp -= 1022;
        } else {
            // normal
            mantissa |= 1 << 52;
            exp -= 1023;
        }
        let mut shift: i64 = 52 - exp;
        // Partially pre-normalise.
        while mantissa & 1 == 0 && shift > 0 {
            mantissa >>= 1;
            shift -= 1;
        }
        let mut num = Int::default();
        num.abs = u64_to_limbs(mantissa);
        num.neg = f < 0.0;
        let mut den = NewInt(1);
        if shift > 0 {
            den.abs = lsh_limbs(&den.abs, shift as u64);
        } else if shift < 0 {
            num.abs = lsh_limbs(&num.abs, (-shift) as u64);
        }
        self.num = num;
        self.den = den;
        self.norm();
        (self, true)
    }

    /// `(*Rat).AppendText(b)` — append the text encoding of x to `b`.
    /// `"a"` form when x is an integer, `"a/b"` otherwise. Error is
    /// always nil.
    pub fn AppendText(
        &self,
        b: crate::slice<crate::types::byte>,
    ) -> (crate::slice<crate::types::byte>, crate::error) {
        if self.IsInt() {
            return self.num.AppendText(b);
        }
        let mut out = b.__into_vec();
        out.extend_from_slice(&rat_marshal(&self.num, &self.den));
        (
            crate::slice::<crate::types::byte>::__from_vec(out),
            crate::errors::nil,
        )
    }

    /// `(*Rat).MarshalText()` — the text encoding of x. Error is always
    /// nil, matching Go.
    pub fn MarshalText(&self) -> (crate::slice<crate::types::byte>, crate::error) {
        self.AppendText(crate::slice::<crate::types::byte>::new())
    }

    /// `(*Rat).UnmarshalText(text)` — parse `text` into x. Returns a
    /// non-nil error if `text` is not a valid rational.
    pub fn UnmarshalText(
        &mut self,
        text: crate::slice<crate::types::byte>,
    ) -> crate::error {
        let s = crate::string::from_bytes(&text);
        let (_, ok) = self.SetString(s.clone());
        if ok {
            crate::errors::nil
        } else {
            crate::errors::New(crate::fmt::Sprintf!(
                "math/big: cannot unmarshal %q into a *big.Rat",
                s
            ))
        }
    }

    /// `(*Rat).GobEncode()` — gob wire format. A version/sign byte
    /// (`ratGobVersion << 1`, bit 0 set when negative), a big-endian
    /// 4-byte numerator length, the big-endian numerator magnitude,
    /// then the big-endian denominator magnitude. Error is always nil.
    pub fn GobEncode(&self) -> (crate::slice<crate::types::byte>, crate::error) {
        let nbytes = limbs_to_be_bytes(&self.num.abs);
        let dbytes = limbs_to_be_bytes(&self.den.abs);
        if u32::try_from(nbytes.len()).is_err() {
            return (
                crate::slice::<crate::types::byte>::new(),
                crate::errors::New("Rat.GobEncode: numerator too large"),
            );
        }
        let mut out: Vec<u8> = Vec::with_capacity(1 + 4 + nbytes.len() + dbytes.len());
        let mut b: u8 = RAT_GOB_VERSION << 1; // make space for sign bit
        if self.num.neg {
            b |= 1;
        }
        out.push(b);
        let n = nbytes.len() as u32;
        out.extend_from_slice(&n.to_be_bytes());
        out.extend_from_slice(&nbytes);
        out.extend_from_slice(&dbytes);
        (
            crate::slice::<crate::types::byte>::__from_vec(out),
            crate::errors::nil,
        )
    }

    /// `(*Rat).GobDecode(buf)` — inverse of `GobEncode`. An empty `buf`
    /// resets self to the zero value (0/1). A version mismatch, a
    /// too-short buffer, or an invalid length returns a non-nil error.
    pub fn GobDecode(&mut self, buf: crate::slice<crate::types::byte>) -> crate::error {
        if buf.len() == 0 {
            // Other side sent a nil or default value.
            self.num = Int::default();
            self.den = NewInt(1);
            return crate::errors::nil;
        }
        if buf.len() < 5 {
            return crate::errors::New("Rat.GobDecode: buffer too small");
        }
        let b = buf[0usize];
        if b >> 1 != RAT_GOB_VERSION {
            return crate::errors::New(crate::fmt::Sprintf!(
                "Rat.GobDecode: encoding version %d not supported",
                int::from((b >> 1) as i64)
            ));
        }
        const J: usize = 1 + 4;
        let lenb = &(*buf)[J - 4..J];
        let ln = u32::from_be_bytes([lenb[0], lenb[1], lenb[2], lenb[3]]) as usize;
        let i = J + ln;
        if buf.len() < i {
            return crate::errors::New("Rat.GobDecode: buffer too small");
        }
        self.num.neg = b & 1 != 0;
        self.num.abs = be_bytes_to_limbs(&(*buf)[J..i]);
        self.num.neg = self.num.neg && !self.num.abs.is_empty();
        self.den.neg = false;
        self.den.abs = be_bytes_to_limbs(&(*buf)[i..]);
        if self.den.abs.is_empty() {
            // Zero-value denominator acts as 1.
            self.den.abs = alloc::vec![1u32];
        }
        crate::errors::nil
    }
}

impl AsRef<Rat> for Rat {
    fn as_ref(&self) -> &Rat { self }
}

impl AsRef<Rat> for crate::nilable<Rat> {
    #[track_caller]
    fn as_ref(&self) -> &Rat {
        self.Must()
    }
}

impl<'a> AsRef<Rat> for crate::gonilable_ref::nilable_refmut<'a, Rat> {
    #[track_caller]
    fn as_ref(&self) -> &Rat {
        self.Must()
    }
}

/// Parse a decimal numeric string (Go's `%f` shape: optional sign, digits,
/// optional `.frac`, optional `e[+-]digits`) into a Rat. Returns true on
/// success. Used by `fmt::Sscanf` for the `%f` verb against a `&mut Rat`
/// (the only Sscanf-into-Rat path the ports currently exercise).
pub fn parse_decimal_into_rat(s: &str, out: &mut Rat) -> bool {
    let bytes = s.trim().as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let mut i = 0;
    let neg = match bytes[0] {
        b'+' => { i += 1; false }
        b'-' => { i += 1; true }
        _ => false,
    };
    let mut digits: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    let mut frac_len: i64 = 0;
    let mut saw_digit = false;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_digit() {
            digits.push(c - b'0');
            saw_digit = true;
            i += 1;
        } else {
            break;
        }
    }
    if i < bytes.len() && bytes[i] == b'.' {
        i += 1;
        while i < bytes.len() {
            let c = bytes[i];
            if c.is_ascii_digit() {
                digits.push(c - b'0');
                frac_len += 1;
                saw_digit = true;
                i += 1;
            } else {
                break;
            }
        }
    }
    let mut exp: i64 = 0;
    if i < bytes.len() && (bytes[i] == b'e' || bytes[i] == b'E') {
        i += 1;
        let eneg = if i < bytes.len() && bytes[i] == b'-' {
            i += 1;
            true
        } else if i < bytes.len() && bytes[i] == b'+' {
            i += 1;
            false
        } else {
            false
        };
        let mut eval: i64 = 0;
        let mut saw_e_digit = false;
        while i < bytes.len() {
            let c = bytes[i];
            if c.is_ascii_digit() {
                eval = eval.saturating_mul(10).saturating_add((c - b'0') as i64);
                saw_e_digit = true;
                i += 1;
            } else {
                break;
            }
        }
        if !saw_e_digit {
            return false;
        }
        exp = if eneg { -eval } else { eval };
    }
    if i != bytes.len() || !saw_digit {
        return false;
    }
    // Build numerator from digits (base 10).
    let mut num = Int::default();
    let ten = NewInt(10);
    for d in &digits {
        let mut tmp = Int::default();
        tmp.Mul(&num, &ten);
        let mut digit_int = Int::default();
        digit_int.SetInt64(*d as i64);
        num = Int::default();
        num.Add(&tmp, &digit_int);
    }
    if neg {
        num.neg = !num.abs.is_empty();
    }
    // The fraction places shift the denominator. Combined exponent:
    // value = digits * 10^(exp - frac_len)
    let net_exp = exp - frac_len;
    let mut numer = num;
    let mut denom = NewInt(1);
    if net_exp >= 0 {
        let mut mult = NewInt(1);
        for _ in 0..net_exp {
            let mut tmp = Int::default();
            tmp.Mul(&mult, &ten);
            mult = tmp;
        }
        let mut new_num = Int::default();
        new_num.Mul(&numer, &mult);
        numer = new_num;
    } else {
        let n = (-net_exp) as i64;
        for _ in 0..n {
            let mut tmp = Int::default();
            tmp.Mul(&denom, &ten);
            denom = tmp;
        }
    }
    out.SetFrac(&numer, &denom);
    true
}

/// `big.NewRat(a, b)` — convenience for `new(Rat).SetFrac(NewInt(a), NewInt(b))`.
pub fn NewRat(a: i64, b: i64) -> Rat {
    let mut r = Rat::new();
    r.SetFrac(&NewInt(a), &NewInt(b));
    r
}

impl Int {
    /// `var z big.Int` — fresh zero-valued Int.
    pub fn new() -> Self {
        Int { neg: false, abs: Vec::new() }
    }

    /// `(*Int).Sign()` — -1, 0, or +1.
    pub fn Sign(&self) -> int {
        if self.abs.is_empty() { 0 } else if self.neg { -1 } else { 1 }
    }

    /// `(*Int).SetInt64(x)` — assign and return self (Go: `z *Int`).
    pub fn SetInt64(&mut self, x: i64) -> &mut Self {
        let (neg, mag) = if x < 0 {
            (true, (x as i128).unsigned_abs() as u64)
        } else {
            (false, x as u64)
        };
        self.neg = neg;
        self.abs = u64_to_limbs(mag);
        self
    }

    /// `(*Int).Set(x)` — copy x into self and return self.
    pub fn Set(&mut self, x: &Int) -> &mut Self {
        self.neg = x.neg;
        self.abs = x.abs.clone();
        self
    }

    /// `(*Int).Int64()` — low 64 bits as a signed value (Go bit-truncates).
    pub fn Int64(&self) -> i64 {
        let mag = limbs_to_u64(&self.abs);
        if self.neg { -(mag as i64) } else { mag as i64 }
    }

    /// `(*Int).Cmp(y)` — -1 / 0 / 1.
    pub fn Cmp(&self, y: &Int) -> int {
        match (self.Sign(), y.Sign()) {
            (a, b) if a < b => -1,
            (a, b) if a > b => 1,
            _ => match abs_cmp(&self.abs, &y.abs) {
                Ordering::Less => if self.neg { 1 } else { -1 },
                Ordering::Equal => 0,
                Ordering::Greater => if self.neg { -1 } else { 1 },
            },
        }
    }

    /// `(*Int).Mod(x, y)` — Euclidean remainder (always 0 ≤ r < |y|).
    /// Returns self after assigning the result. Panics if y == 0.
    /// The divisor may be any size (multi-precision long division).
    pub fn Mod(&mut self, x: &Int, y: &Int) -> &mut Self {
        if y.abs.is_empty() {
            panic!("big::Int::Mod: division by zero");
        }
        // T-division: r magnitude is |x| mod |y|, r sign follows x.
        let r_abs = divmod_limbs(&x.abs, &y.abs).1;
        let r_neg_t = !r_abs.is_empty() && x.neg;
        // Euclidean correction: if r_t < 0, add |y| (Go: z.Sub/Add by y0).
        let (mag, neg) = if r_neg_t {
            (sub_limbs(&y.abs, &r_abs), false)
        } else {
            (r_abs, false)
        };
        self.neg = neg && !mag.is_empty();
        self.abs = mag;
        self
    }

    /// `(*Int).Exp(x, y, m)` — modular exponentiation: z = x**y mod |m|
    /// (the sign of m is ignored, matching Go). Fully multi-precision:
    /// operands and modulus may be any size (RSA-sized inputs work).
    ///
    /// Semantics match Go's `(*Int).Exp`:
    ///   * If m == 0 (nil-equivalent), z = x**y unless y <= 0 then z = 1.
    ///   * Otherwise z = x**y mod |m|, normalised to 0 <= z < |m|.
    ///   * For y < 0 with m != 0, z = (x⁻¹ mod |m|)**(-y) mod |m|.
    ///     Panics with Go's message if x is not coprime to m.
    ///   * For y < 0 with m == 0, z = 1 (matches Go).
    pub fn Exp(&mut self, x: &Int, y: &Int, m: &Int) -> &mut Self {
        let m_zero = m.abs.is_empty();
        if y.neg {
            if m_zero {
                // Go: y < 0 && m == 0  ->  z = 1.
                return self.SetInt64(1);
            }
            // Negative exponent: x**y == (x⁻¹)**(-y) mod |m|.
            // Snapshot up front — self may alias x, y or m.
            let mut m_abs = Int::new();
            m_abs.Abs(m);
            // gcd(x mod |m|, |m|) must be 1 for the inverse to exist.
            let mut x_red = Int::new();
            x_red.Mod(x, &m_abs);
            let mut g = Int::new();
            g.GCD(crate::nilval::nil, crate::nilval::nil, &x_red, &m_abs);
            let mut one = Int::new();
            one.SetInt64(1);
            if g.Cmp(&one) != 0 {
                panic!("negative exponent and modulus not relatively prime");
            }
            let mut inv = Int::new();
            inv.ModInverse(&x_red, &m_abs);
            // pos_y = -y (the magnitude of the exponent).
            let mut pos_y = Int::new();
            pos_y.Neg(y);
            return self.Exp(&inv, &pos_y, &m_abs);
        }
        // m_abs is |m| (sign ignored, per Go).
        let m_abs = &m.abs;

        // Compute the magnitude x**y (mod |m| when m != 0) by
        // square-and-multiply over the limb vectors.
        // Reduce the base mod |m| up front when a modulus is present.
        let mut base = if m_zero {
            x.abs.clone()
        } else {
            divmod_limbs(&x.abs, m_abs).1
        };
        // acc starts at 1, reduced mod |m| (so |m| == 1 yields 0).
        let mut acc: Vec<u32> = if m_zero {
            alloc::vec![1u32]
        } else {
            divmod_limbs(&alloc::vec![1u32], m_abs).1
        };
        // Walk the exponent bits LSB→MSB, stopping at y's highest set
        // bit. Using the full limb width instead would keep squaring
        // `base` past the last significant bit: harmless-but-wasteful
        // with a modulus (the value stays reduced), fatal without one —
        // `Exp(2, 64, 0)` would square 2^(2^k) up to k=31 and never
        // finish. Go's nat.expNN walks `y.bitLen()` for the same reason.
        let yw = &y.abs;
        let mut bit: usize = 0;
        let total_bits = bit_len(yw) as usize;
        while bit < total_bits {
            let limb = yw[bit / 32];
            if (limb >> (bit % 32)) & 1 == 1 {
                acc = mul_limbs(&acc, &base);
                if !m_zero {
                    acc = divmod_limbs(&acc, m_abs).1;
                }
            }
            bit += 1;
            if bit < total_bits {
                base = mul_limbs(&base, &base);
                if !m_zero {
                    base = divmod_limbs(&base, m_abs).1;
                }
            }
        }
        // Sign: x**y is negative only when x < 0 and y is odd. With a
        // modulus, Go normalises the result to 0 <= z < |m|.
        let y_odd = !yw.is_empty() && (yw[0] & 1 == 1);
        let mut neg = !acc.is_empty() && x.neg && y_odd;
        if neg && !m_zero {
            // make modulus result positive: z = |m| - z
            acc = sub_limbs(m_abs, &acc);
            neg = false;
        }
        self.neg = neg && !acc.is_empty();
        self.abs = acc;
        self
    }

    /// `(*Int).GCD(x, y, a, b)` — z = gcd(|a|, |b|), always >= 0.
    /// If `x` / `y` are non-nil they receive Bézout coefficients such
    /// that `a*x + b*y == z`. Pass bare `nil` for an out-parameter to
    /// skip it (Go's `GCD(nil, nil, a, b)`).
    ///
    /// `a` and `b` may be positive, zero or negative. Edge cases match
    /// Go: `gcd(0,0)==0`, and when one operand is zero gcd is the
    /// magnitude of the other. The coefficients satisfy the Bézout
    /// identity for the *signed* a, b; a plain extended Euclidean is
    /// used, so coefficient values may differ from Go's Lehmer path
    /// while still satisfying `a*x + b*y == z`.
    pub fn GCD<X: MaybeMutInt, Y: MaybeMutInt, A: AsRef<Int>, B: AsRef<Int>>(
        &mut self,
        mut x: X,
        mut y: Y,
        a: A,
        b: B,
    ) -> &mut Self {
        // Snapshot a, b up front — z / x / y may alias either operand.
        let a0 = a.as_ref().clone();
        let b0 = b.as_ref().clone();

        // Run extended Euclidean on the magnitudes |a|, |b|.
        // Maintain: r0 = ca*|a| + cb*|b|, r1 = da*|a| + db*|b|.
        let mut r0 = Int { neg: false, abs: a0.abs.clone() };
        let mut r1 = Int { neg: false, abs: b0.abs.clone() };
        let mut ca = Int::new(); ca.SetInt64(1); // 1
        let mut cb = Int::new();                 // 0
        let mut da = Int::new();                 // 0
        let mut db = Int::new(); db.SetInt64(1); // 1

        while r1.Sign() != 0 {
            // q = r0 div r1, rem = r0 mod r1 (both magnitudes positive).
            let mut q = Int::new();
            let mut rem = Int::new();
            q.DivMod(&r0, &r1, &mut rem);
            // (r0, r1) = (r1, rem)
            r0 = r1;
            r1 = rem;
            // (ca, da) = (da, ca - q*da)
            let mut qda = Int::new();
            qda.Mul(&q, &da);
            let mut nca = Int::new();
            nca.Sub(&ca, &qda);
            ca = da;
            da = nca;
            // (cb, db) = (db, cb - q*db)
            let mut qdb = Int::new();
            qdb.Mul(&q, &db);
            let mut ncb = Int::new();
            ncb.Sub(&cb, &qdb);
            cb = db;
            db = ncb;
        }
        // r0 == gcd(|a|,|b|) and r0 = ca*|a| + cb*|b|.

        // Bézout coefficients for the *signed* operands: |a| = sign(a)*a,
        // so ca*|a| = (ca*sign(a))*a. Fold the sign into the coefficient.
        if let Some(xr) = x.maybe_mut_int() {
            if a0.neg {
                xr.Neg(&ca);
            } else {
                xr.Set(&ca);
            }
        }
        if let Some(yr) = y.maybe_mut_int() {
            if b0.neg {
                yr.Neg(&cb);
            } else {
                yr.Set(&cb);
            }
        }

        self.neg = false;
        self.abs = r0.abs;
        self
    }

    /// `(*Int).ModInverse(g, n)` — z = the multiplicative inverse of g
    /// in ℤ/nℤ, i.e. `z*g ≡ 1 (mod n)`, normalised to `0 <= z < |n|`.
    ///
    /// If `g` and `n` are not relatively prime, g has no inverse: Go
    /// returns nil there. goish methods return `&mut Self`, so in the
    /// no-inverse case `self` is left **unchanged** and a `false`
    /// status would be needed to detect it — callers must ensure
    /// `gcd(g,n)==1` (use `GCD` to check). It never stores a garbage
    /// value. Panics if `n == 0` (division by zero), matching Go.
    pub fn ModInverse<G: AsRef<Int>, N: AsRef<Int>>(&mut self, g: G, n: N) -> &mut Self {
        // GCD operates on magnitudes; work with |n| and g reduced mod |n|.
        let n0 = n.as_ref().clone();
        if n0.abs.is_empty() {
            panic!("big::Int::ModInverse: division by zero");
        }
        let mut n_abs = Int::new();
        n_abs.Abs(&n0);
        // g may be negative — reduce into [0, |n|).
        let mut g_red = Int::new();
        g_red.Mod(g.as_ref(), &n_abs);

        // d = gcd(g_red, |n|) with Bézout x: g_red*x + |n|*y = d.
        let mut d = Int::new();
        let mut xc = Int::new();
        d.GCD(&mut xc, crate::nilval::nil, &g_red, &n_abs);

        // Inverse exists iff gcd == 1.
        let mut one = Int::new();
        one.SetInt64(1);
        if d.Cmp(&one) != 0 {
            // Not coprime: leave self unchanged (Go returns nil here).
            return self;
        }
        // x is the inverse but may be negative; normalise to [0, |n|).
        if xc.neg {
            self.Add(&xc, &n_abs);
        } else {
            self.Set(&xc);
        }
        self
    }

    /// `(*Int).Mul(x, y)` — z = x*y, return z. Accepts any type that
    /// can be borrowed as `&Int` (covers `&Int`, `Int`, `nilable<Int>`,
    /// `nilable_refmut<Int>`, `&Lazy<nilable<Int>>`).
    pub fn Mul<X: AsRef<Int>, Y: AsRef<Int>>(&mut self, x: X, y: Y) -> &mut Self {
        let x = x.as_ref();
        let y = y.as_ref();
        let mag = mul_limbs(&x.abs, &y.abs);
        let neg = !mag.is_empty() && (x.neg != y.neg);
        self.abs = mag;
        self.neg = neg;
        self
    }

    /// `(*Int).Abs(x)` — z = |x|, return z.
    pub fn Abs<X: AsRef<Int>>(&mut self, x: X) -> &mut Self {
        let x = x.as_ref();
        // Handle aliasing: `b.Abs(b)` where b is self.
        if core::ptr::eq(self as *const _, x as *const _) {
            self.neg = false;
        } else {
            self.abs = x.abs.clone();
            self.neg = false;
        }
        self
    }

    /// `(*Int).Div(x, y)` — Euclidean quotient. z = x div y, return z.
    /// Panics if y == 0. The divisor may be any size (multi-precision
    /// long division).
    pub fn Div<X: AsRef<Int>, Y: AsRef<Int>>(&mut self, x: X, y: Y) -> &mut Self {
        let x = x.as_ref();
        let y = y.as_ref();
        if y.abs.is_empty() {
            panic!("big::Int::Div: division by zero");
        }
        let (q_abs, r_abs) = divmod_limbs(&x.abs, &y.abs);
        // T-division: q sign = x.neg != y.neg; r sign follows x.
        let q_neg_t = !q_abs.is_empty() && (x.neg != y.neg);
        let r_neg_t = !r_abs.is_empty() && x.neg;
        let mut q = Int { neg: q_neg_t, abs: q_abs };
        // Euclidean correction: if r_t < 0, adjust q by ±1.
        if r_neg_t {
            if y.neg {
                q.AddInt64(1);
            } else {
                q.AddInt64(-1);
            }
        }
        self.neg = q.neg;
        self.abs = q.abs;
        self
    }

    /// `(*Int).DivMod(x, y, m)` — Euclidean division. z = x div y,
    /// m = x mod y (with 0 ≤ m < |y|). Returns (z, m).
    /// `m` is borrowed mutably and updated in place.
    pub fn DivMod<X, Y, M>(&mut self, x: X, y: Y, mut m: M) -> (&mut Int, M)
    where
        X: AsRef<Int>,
        Y: AsRef<Int>,
        M: AsMutInt,
    {
        let x = x.as_ref();
        let y = y.as_ref();
        if y.abs.is_empty() {
            panic!("big::Int::DivMod: division by zero");
        }
        let (q_abs, r_abs) = divmod_limbs(&x.abs, &y.abs);
        // T-division then Euclidean correction.
        let q_neg_t = !q_abs.is_empty() && (x.neg != y.neg);
        let r_neg_t = !r_abs.is_empty() && x.neg;
        let mut q = Int { neg: q_neg_t, abs: q_abs };
        let mut rem_abs = r_abs;
        let mut rem_neg = r_neg_t;
        if rem_neg {
            // r_eucl = |y| - r ; q -= sign(y)
            rem_abs = sub_limbs(&y.abs, &rem_abs);
            rem_neg = false;
            if y.neg {
                q.AddInt64(1);
            } else {
                q.AddInt64(-1);
            }
        }
        self.neg = q.neg;
        self.abs = q.abs;
        {
            let m_ref = m.as_mut_int();
            m_ref.neg = rem_neg;
            m_ref.abs = rem_abs;
        }
        (self, m)
    }

    /// `(*Int).Quo(x, y)` — truncated quotient. z = x/y rounded toward
    /// zero, return z. Panics if y == 0.
    pub fn Quo<X: AsRef<Int>, Y: AsRef<Int>>(&mut self, x: X, y: Y) -> &mut Self {
        let x = x.as_ref();
        let y = y.as_ref();
        if y.abs.is_empty() {
            panic!("big::Int::Quo: division by zero");
        }
        let q_abs = divmod_limbs(&x.abs, &y.abs).0;
        // T-division: q sign = x.neg != y.neg; 0 has no sign.
        self.neg = !q_abs.is_empty() && (x.neg != y.neg);
        self.abs = q_abs;
        self
    }

    /// `(*Int).Rem(x, y)` — truncated remainder. z = x%y, the sign of
    /// the result follows x, return z. Panics if y == 0.
    pub fn Rem<X: AsRef<Int>, Y: AsRef<Int>>(&mut self, x: X, y: Y) -> &mut Self {
        let x = x.as_ref();
        let y = y.as_ref();
        if y.abs.is_empty() {
            panic!("big::Int::Rem: division by zero");
        }
        let r_abs = divmod_limbs(&x.abs, &y.abs).1;
        // T-division: r sign follows x; 0 has no sign.
        self.neg = !r_abs.is_empty() && x.neg;
        self.abs = r_abs;
        self
    }

    /// `(*Int).QuoRem(x, y, r)` — T-division. z = x/y truncated,
    /// r = x - y*z. Returns (z, r). Panics if y == 0.
    pub fn QuoRem<X, Y, R>(&mut self, x: X, y: Y, mut r: R) -> (&mut Int, R)
    where
        X: AsRef<Int>,
        Y: AsRef<Int>,
        R: AsMutInt,
    {
        let x = x.as_ref();
        let y = y.as_ref();
        if y.abs.is_empty() {
            panic!("big::Int::QuoRem: division by zero");
        }
        let (q_abs, r_abs) = divmod_limbs(&x.abs, &y.abs);
        // T-division: q sign = x.neg != y.neg; r sign follows x.
        // No Euclidean correction. 0 has no sign.
        self.neg = !q_abs.is_empty() && (x.neg != y.neg);
        self.abs = q_abs;
        {
            let r_ref = r.as_mut_int();
            r_ref.neg = !r_abs.is_empty() && x.neg;
            r_ref.abs = r_abs;
        }
        (self, r)
    }

    /// `(*Int).BorrowMut()` — Goish convenience: wrap `&mut self`
    /// as a `nilable_refmut<Int>` so it can be passed where the
    /// signature expects `nilable![&mut Int]`.
    pub fn BorrowMut(&mut self) -> crate::gonilable_ref::nilable_refmut<'_, Int> {
        crate::gonilable_ref::nilable_refmut::new(self)
    }

    /// `(*Int).Add(x, y)` — z = x + y, return z. Accepts any
    /// `AsRef<Int>` so callers can pass owned/borrowed/nilable forms.
    pub fn Add<X: AsRef<Int>, Y: AsRef<Int>>(&mut self, x: X, y: Y) -> &mut Self {
        let x = x.as_ref();
        let y = y.as_ref();
        let res = add_signed(x, y);
        self.neg = res.neg;
        self.abs = res.abs;
        self
    }

    /// Internal helper: in-place add a small signed integer to self.
    /// Used by `Div` / `DivMod` for the Euclidean correction step.
    fn AddInt64(&mut self, delta: i64) {
        if delta == 0 {
            return;
        }
        // Convert to two Int operands and use existing logic.
        let mut other = Int::default();
        other.SetInt64(delta);
        // self = self + other
        let res = add_signed(self, &other);
        self.neg = res.neg;
        self.abs = res.abs;
    }

    /// `(*Int).Sub(x, y)` — z = x - y, return z. Subtraction is addition
    /// with `y`'s sign flipped, reusing the sign-aware `add_signed` core.
    pub fn Sub<X: AsRef<Int>, Y: AsRef<Int>>(&mut self, x: X, y: Y) -> &mut Self {
        let x = x.as_ref();
        let y = y.as_ref();
        // -y: flip the sign of y's magnitude (zero stays non-negative).
        let neg_y = Int { neg: !y.neg && !y.abs.is_empty(), abs: y.abs.clone() };
        let res = add_signed(x, &neg_y);
        self.neg = res.neg;
        self.abs = res.abs;
        self
    }

    /// `(*Int).Neg(x)` — z = -x, return z. Zero stays non-negative.
    pub fn Neg<X: AsRef<Int>>(&mut self, x: X) -> &mut Self {
        let x = x.as_ref();
        let abs = x.abs.clone();
        self.neg = !abs.is_empty() && !x.neg;
        self.abs = abs;
        self
    }

    /// `(*Int).BitLen()` — bit length of |x|. The bit length of 0 is 0.
    pub fn BitLen(&self) -> int {
        bit_len(&self.abs)
    }

    /// `(*Int).TrailingZeroBits()` — count of consecutive least-significant
    /// zero bits of |x|. Zero has 0 trailing-zero bits.
    pub fn TrailingZeroBits(&self) -> crate::types::uint {
        trailing_zero_bits(&self.abs)
    }

    /// `(*Int).Bit(i)` — value of the i-th bit of x, i.e. `(x>>i)&1`.
    /// Panics on a negative index. For negative x, Go reports the bit
    /// of the two's-complement representation: bit i of -x is
    /// `bit i of (|x|-1)` inverted.
    pub fn Bit(&self, i: int) -> crate::types::uint {
        if i == 0 {
            // Bit 0 is identical for x and -x in two's complement.
            return if self.abs.is_empty() {
                0
            } else {
                (self.abs[0] & 1) as crate::types::uint
            };
        }
        if i < 0 {
            panic!("negative bit index");
        }
        let bi = i as u64;
        if self.neg {
            let t = sub_limbs(&self.abs, &[1]);
            limb_bit(&t, bi) ^ 1
        } else {
            limb_bit(&self.abs, bi)
        }
    }

    /// `(*Int).SetBit(x, i, b)` — z = x with x's i-th bit set to b (0 or 1).
    /// If b == 1: `z = x | (1 << i)`; if b == 0: `z = x &^ (1 << i)`.
    /// Panics on a negative index or b not in {0, 1}. Negative x is
    /// handled in two's-complement, matching Go.
    pub fn SetBit<X: AsRef<Int>>(&mut self, x: X, i: int, b: crate::types::uint) -> &mut Self {
        let x = x.as_ref();
        if i < 0 {
            panic!("negative bit index");
        }
        if b != 0 && b != 1 {
            panic!("set bit is not 0 or 1");
        }
        let bi = i as u64;
        if x.neg {
            // -x == ^(x-1); flipping bit b on -x flips bit (b^1) on (x-1).
            let t = sub_limbs(&x.abs, &[1]);
            let t = limb_set_bit(&t, bi, b ^ 1);
            let abs = add_limbs(&t, &[1]);
            self.neg = !abs.is_empty();
            self.abs = abs;
        } else {
            self.abs = limb_set_bit(&x.abs, bi, b);
            self.neg = false;
        }
        self
    }

    /// `(*Int).Lsh(x, n)` — z = x << n. The sign is preserved.
    pub fn Lsh<X: AsRef<Int>>(&mut self, x: X, n: crate::types::uint) -> &mut Self {
        let x = x.as_ref();
        self.abs = lsh_limbs(&x.abs, n);
        self.neg = x.neg && !self.abs.is_empty();
        self
    }

    /// `(*Int).Rsh(x, n)` — z = x >> n (arithmetic right shift). For
    /// negative x, Go uses two's-complement semantics:
    /// `(-x) >> n == -(((|x|-1) >> n) + 1)`.
    pub fn Rsh<X: AsRef<Int>>(&mut self, x: X, n: crate::types::uint) -> &mut Self {
        let x = x.as_ref();
        if x.neg {
            // (-x) >> n == ^((x-1) >> n) == -(((x-1) >> n) + 1)
            let t = sub_limbs(&x.abs, &[1]);
            let t = rsh_limbs(&t, n);
            self.abs = add_limbs(&t, &[1]);
            self.neg = true; // result cannot be zero when x is negative
        } else {
            self.abs = rsh_limbs(&x.abs, n);
            self.neg = false;
        }
        self
    }

    /// `(*Int).And(x, y)` — z = x & y, in two's-complement semantics for
    /// negative operands (matches Go's `(*Int).And`).
    pub fn And<X: AsRef<Int>, Y: AsRef<Int>>(&mut self, x: X, y: Y) -> &mut Self {
        let x = x.as_ref();
        let y = y.as_ref();
        if x.neg == y.neg {
            if x.neg {
                // (-x) & (-y) == -(((x-1) | (y-1)) + 1)
                let x1 = sub_limbs(&x.abs, &[1]);
                let y1 = sub_limbs(&y.abs, &[1]);
                let abs = add_limbs(&or_limbs(&x1, &y1), &[1]);
                self.neg = true;
                self.abs = abs;
            } else {
                self.abs = and_limbs(&x.abs, &y.abs);
                self.neg = false;
            }
        } else {
            // x.neg != y.neg; & is symmetric — make x the positive one.
            let (xp, yn) = if x.neg { (y, x) } else { (x, y) };
            // xp & (-yn) == xp &^ (yn-1)
            let y1 = sub_limbs(&yn.abs, &[1]);
            self.abs = and_not_limbs(&xp.abs, &y1);
            self.neg = false;
        }
        self
    }

    /// `(*Int).AndNot(x, y)` — z = x &^ y (bit clear), two's-complement
    /// faithful for negative operands (matches Go's `(*Int).AndNot`).
    pub fn AndNot<X: AsRef<Int>, Y: AsRef<Int>>(&mut self, x: X, y: Y) -> &mut Self {
        let x = x.as_ref();
        let y = y.as_ref();
        if x.neg == y.neg {
            if x.neg {
                // (-x) &^ (-y) == (y-1) &^ (x-1)
                let x1 = sub_limbs(&x.abs, &[1]);
                let y1 = sub_limbs(&y.abs, &[1]);
                self.abs = and_not_limbs(&y1, &x1);
                self.neg = false;
            } else {
                self.abs = and_not_limbs(&x.abs, &y.abs);
                self.neg = false;
            }
        } else if x.neg {
            // (-x) &^ y == -(((x-1) | y) + 1)
            let x1 = sub_limbs(&x.abs, &[1]);
            let abs = add_limbs(&or_limbs(&x1, &y.abs), &[1]);
            self.neg = true;
            self.abs = abs;
        } else {
            // x &^ (-y) == x & (y-1)
            let y1 = sub_limbs(&y.abs, &[1]);
            self.abs = and_limbs(&x.abs, &y1);
            self.neg = false;
        }
        self
    }

    /// `(*Int).Or(x, y)` — z = x | y, two's-complement faithful for
    /// negative operands (matches Go's `(*Int).Or`).
    pub fn Or<X: AsRef<Int>, Y: AsRef<Int>>(&mut self, x: X, y: Y) -> &mut Self {
        let x = x.as_ref();
        let y = y.as_ref();
        if x.neg == y.neg {
            if x.neg {
                // (-x) | (-y) == -(((x-1) & (y-1)) + 1)
                let x1 = sub_limbs(&x.abs, &[1]);
                let y1 = sub_limbs(&y.abs, &[1]);
                let abs = add_limbs(&and_limbs(&x1, &y1), &[1]);
                self.neg = true;
                self.abs = abs;
            } else {
                self.abs = or_limbs(&x.abs, &y.abs);
                self.neg = false;
            }
        } else {
            // | is symmetric — make x the positive one.
            let (xp, yn) = if x.neg { (y, x) } else { (x, y) };
            // xp | (-yn) == -(((yn-1) &^ xp) + 1)
            let y1 = sub_limbs(&yn.abs, &[1]);
            let abs = add_limbs(&and_not_limbs(&y1, &xp.abs), &[1]);
            self.neg = true;
            self.abs = abs;
        }
        self
    }

    /// `(*Int).Xor(x, y)` — z = x ^ y, two's-complement faithful for
    /// negative operands (matches Go's `(*Int).Xor`).
    pub fn Xor<X: AsRef<Int>, Y: AsRef<Int>>(&mut self, x: X, y: Y) -> &mut Self {
        let x = x.as_ref();
        let y = y.as_ref();
        if x.neg == y.neg {
            if x.neg {
                // (-x) ^ (-y) == (x-1) ^ (y-1)
                let x1 = sub_limbs(&x.abs, &[1]);
                let y1 = sub_limbs(&y.abs, &[1]);
                self.abs = xor_limbs(&x1, &y1);
                self.neg = false;
            } else {
                self.abs = xor_limbs(&x.abs, &y.abs);
                self.neg = false;
            }
        } else {
            // ^ is symmetric — make x the positive one.
            let (xp, yn) = if x.neg { (y, x) } else { (x, y) };
            // xp ^ (-yn) == -((xp ^ (yn-1)) + 1)
            let y1 = sub_limbs(&yn.abs, &[1]);
            let abs = add_limbs(&xor_limbs(&xp.abs, &y1), &[1]);
            self.neg = !abs.is_empty();
            self.abs = abs;
        }
        self
    }

    /// `(*Int).Not(x)` — z = ^x (two's-complement bitwise NOT).
    /// `^x == -x - 1`; `^(-x) == x - 1`.
    pub fn Not<X: AsRef<Int>>(&mut self, x: X) -> &mut Self {
        let x = x.as_ref();
        if x.neg {
            // ^(-x) == x - 1
            self.abs = sub_limbs(&x.abs, &[1]);
            self.neg = false;
        } else {
            // ^x == -(x + 1)
            self.abs = add_limbs(&x.abs, &[1]);
            self.neg = true; // x+1 > 0, result is negative
        }
        self
    }

    /// `(*Int).SetString(s, base)` — parse `s` as an integer in `base`
    /// into `self`, returning `(self, ok)`. `ok` is false on a parse
    /// failure, in which case `self` is left unchanged.
    ///
    /// `base` must be 0 or a value between 2 and 62 (Go's `MaxBase`).
    /// For base 0 the actual base is taken from the literal prefix:
    /// `0b`/`0B` → 2, `0o`/`0O` → 8, `0x`/`0X` → 16, a leading `0`
    /// (immediately followed by digits) → 8, otherwise 10. An optional
    /// leading `+`/`-` sign is accepted. When base is 0, `_` digit
    /// separators are permitted between successive digits (and between
    /// a base prefix and a digit), matching Go's `int.go`/`natconv.go`.
    ///
    /// For bases ≤ 36 letter digits are case-insensitive; for bases
    /// > 36 the upper-case letters carry digit values 36..=61.
    pub fn SetString<S: Into<crate::string>>(&mut self, s: S, base: int) -> (&mut Int, bool) {
        let s = s.into();
        match scan_int(s.as_bytes(), base) {
            Some((neg, abs)) => {
                self.neg = neg && !abs.is_empty();
                self.abs = abs;
                (self, true)
            }
            None => (self, false),
        }
    }

    /// `(*Int).Text(base)` — string representation of `self` in `base`.
    /// `base` must be between 2 and 62 inclusive; lower-case letters
    /// `a`..`z` cover digit values 10..35 and upper-case `A`..`Z` cover
    /// 36..61. No `0x`-style prefix is added. Negative values are
    /// prefixed with `-`.
    pub fn Text(&self, base: int) -> crate::string {
        if base < 2 || base > MAX_BASE {
            panic!("big::Int::Text: invalid base");
        }
        let buf = itoa(self.neg, &self.abs, base);
        crate::string::from_bytes(&buf)
    }

    /// `(*Int).Bytes()` — big-endian byte representation of the absolute
    /// value of `self`. No sign and no leading zero bytes; zero yields
    /// an empty slice. Matches Go's `(*Int).Bytes()`.
    pub fn Bytes(&self) -> crate::slice<crate::types::byte> {
        crate::slice::<crate::types::byte>::__from_vec(limbs_to_be_bytes(&self.abs))
    }

    /// `(*Int).SetBytes(buf)` — interpret `buf` as a big-endian unsigned
    /// integer and assign it to `self` (sign set non-negative). Returns
    /// `self`. Matches Go's `(*Int).SetBytes`.
    pub fn SetBytes(&mut self, buf: crate::slice<crate::types::byte>) -> &mut Self {
        self.abs = be_bytes_to_limbs(&buf);
        self.neg = false;
        self
    }

    /// `(*Int).SetUint64(x)` — assign an unsigned 64-bit value (always
    /// non-negative) and return self. Matches Go's `(*Int).SetUint64`.
    pub fn SetUint64(&mut self, x: u64) -> &mut Self {
        self.abs = u64_to_limbs(x);
        self.neg = false;
        self
    }

    /// `(*Int).Uint64()` — low 64 bits as an unsigned value. Go
    /// bit-truncates and ignores the sign; if the value doesn't fit a
    /// `u64` the result is the low 64 bits of the magnitude.
    pub fn Uint64(&self) -> u64 {
        limbs_to_u64(&self.abs)
    }

    /// `(*Int).IsInt64()` — reports whether the value fits a signed i64.
    pub fn IsInt64(&self) -> bool {
        // Magnitude must occupy at most 64 bits (two u32 limbs).
        if self.abs.len() > 2 {
            return false;
        }
        let w = limbs_to_u64(&self.abs);
        if self.neg {
            // Negative values fit iff |x| <= 2^63.
            w <= (i64::MAX as u64) + 1
        } else {
            w <= i64::MAX as u64
        }
    }

    /// `(*Int).IsUint64()` — reports whether the value is non-negative
    /// and fits an unsigned u64.
    pub fn IsUint64(&self) -> bool {
        !self.neg && self.abs.len() <= 2
    }

    /// `(*Int).CmpAbs(y)` — compare magnitudes only, ignoring sign:
    /// -1 if |x| < |y|, 0 if equal, +1 if |x| > |y|.
    pub fn CmpAbs<Y: AsRef<Int>>(&self, y: Y) -> int {
        match abs_cmp(&self.abs, &y.as_ref().abs) {
            Ordering::Less => -1,
            Ordering::Equal => 0,
            Ordering::Greater => 1,
        }
    }

    /// `(*Int).MulRange(a, b)` — z = product of all integers in [a, b]
    /// inclusively. If a > b the result is 1; if the range includes 0
    /// the result is 0. Returns self.
    pub fn MulRange(&mut self, a: i64, b: i64) -> &mut Self {
        if a > b {
            return self.SetInt64(1); // empty range
        }
        if a <= 0 && b >= 0 {
            return self.SetInt64(0); // range includes 0
        }
        // a <= b && (b < 0 || a > 0)
        let mut neg = false;
        let (lo, hi) = if a < 0 {
            // Negate the range; an even count of factors flips no sign.
            neg = (b - a) & 1 == 0;
            ((-b) as i128 as u64, (-a) as i128 as u64)
        } else {
            (a as u64, b as u64)
        };
        // Accumulate the product of lo..=hi.
        self.abs = u64_to_limbs(1);
        for n in lo..=hi {
            self.abs = mul_limbs(&self.abs, &u64_to_limbs(n));
        }
        self.neg = neg && !self.abs.is_empty();
        self
    }

    /// `(*Int).Binomial(n, k)` — z = the binomial coefficient C(n, k).
    /// Returns self. Mirrors Go's multiplicative-formula loop.
    pub fn Binomial(&mut self, n: i64, k: i64) -> &mut Self {
        if k < 0 || k > n {
            return self.SetInt64(0);
        }
        // C(n, k) == C(n, n-k): reduce k to cut the multiplication count.
        let k = if k > n - k { n - k } else { k };
        // z = 1; i = 0; while i < k { z *= n-i; i++; z /= i }
        let mut nn = Int::new();
        nn.SetInt64(n);
        let mut z = Int::new();
        z.SetInt64(1);
        let mut i = Int::new();
        let mut one = Int::new();
        one.SetInt64(1);
        let mut ival: i64 = 0;
        while ival < k {
            let mut t = Int::new();
            t.SetInt64(n - ival);
            let zc = z.clone();
            z.Mul(&zc, &t);
            ival += 1;
            i.SetInt64(ival);
            let zc = z.clone();
            z.Quo(&zc, &i);
        }
        *self = z;
        self
    }

    /// `(*Int).Float64()` — the f64 nearest the value, plus whether the
    /// result is `Below`, `Exact`, or `Above` the true value.
    pub fn Float64(&self) -> (crate::types::float64, Accuracy) {
        let n = bit_len(&self.abs);
        if n == 0 {
            return (0.0, Accuracy::Exact);
        }
        // Fast path: the value fits a 53-bit f64 mantissa exactly when it
        // has <= 53 significant bits, or fits in 64 bits with enough
        // trailing zeros that the significant span is <= 53.
        let tz = trailing_zero_bits(&self.abs) as int;
        if n <= 53 || (n < 64 && n - tz <= 53) {
            let mag = limbs_to_u64(&self.abs);
            // u64 -> f64 is exact here (significant span <= 53 bits).
            let mut f = f64_from_u64(mag);
            if self.neg {
                f = -f;
            }
            return (f, Accuracy::Exact);
        }
        // Slow path: round the magnitude to the nearest f64 and report
        // the direction of the rounding error.
        let (mag_f, acc) = round_limbs_to_f64(&self.abs);
        if self.neg {
            // Negating flips Below<->Above.
            let acc = match acc {
                Accuracy::Below => Accuracy::Above,
                Accuracy::Above => Accuracy::Below,
                Accuracy::Exact => Accuracy::Exact,
            };
            (-mag_f, acc)
        } else {
            (mag_f, acc)
        }
    }

    /// `(*Int).FillBytes(buf)` — write the absolute value into `buf` as a
    /// zero-extended big-endian byte slice and return `buf`. Panics if
    /// the value does not fit, matching Go.
    pub fn FillBytes(
        &self,
        buf: crate::slice<crate::types::byte>,
    ) -> crate::slice<crate::types::byte> {
        let be = limbs_to_be_bytes(&self.abs);
        let n = buf.len() as usize;
        if be.len() > n {
            panic!("math/big: buffer too small to fit value");
        }
        // Left-pad with zeros, then copy the big-endian magnitude.
        let mut out: Vec<u8> = alloc::vec![0u8; n];
        let start = n - be.len();
        out[start..].copy_from_slice(&be);
        crate::slice::<crate::types::byte>::__from_vec(out)
    }

    /// `(*Int).Bits()` — the absolute value as a little-endian `[]Word`
    /// slice. The internal u32 limbs are repacked into 64-bit words.
    pub fn Bits(&self) -> crate::slice<Word> {
        crate::slice::<Word>::__from_vec(limbs_to_words(&self.abs))
    }

    /// `(*Int).SetBits(abs)` — set the value from a little-endian `[]Word`
    /// slice (the receiver becomes non-negative) and return self. The
    /// 64-bit words are unpacked into u32 limbs and normalized.
    pub fn SetBits(&mut self, abs: crate::slice<Word>) -> &mut Self {
        self.abs = words_to_limbs(&abs);
        self.neg = false;
        self
    }

    /// `(*Int).Sqrt(x)` — z = ⌊√x⌋, the largest integer with z² ≤ x.
    /// Panics if x is negative, matching Go. Uses Newton's method on
    /// `Int`: the iterate `t = (t + x/t) / 2` converges down to ⌊√x⌋.
    pub fn Sqrt(&mut self, x: &Int) -> &mut Self {
        if x.neg {
            panic!("big::Int::Sqrt: square root of negative number");
        }
        // Snapshot x — self may alias x at the call site.
        let x = x.clone();
        // ⌊√0⌋ = 0, ⌊√1⌋ = 1: handle directly (also dodges div-by-zero).
        if x.abs.is_empty() {
            return self.SetInt64(0);
        }
        let mut one = Int::new();
        one.SetInt64(1);
        if x.Cmp(&one) == 0 {
            return self.SetInt64(1);
        }

        // Initial guess: 1 << ((BitLen+1)/2) — an upper bound on ⌊√x⌋.
        let shift = ((x.BitLen() + 1) / 2) as crate::types::uint;
        let mut t = Int::new();
        t.Lsh(&one, shift);

        // Newton iteration: t_{k+1} = (t_k + x/t_k) / 2. The sequence
        // decreases monotonically (after the first step) toward ⌊√x⌋;
        // stop once it no longer decreases.
        let mut two = Int::new();
        two.SetInt64(2);
        loop {
            let mut q = Int::new();
            q.Div(&x, &t);
            let mut sum = Int::new();
            sum.Add(&t, &q);
            let mut next = Int::new();
            next.Div(&sum, &two);
            if next.Cmp(&t) >= 0 {
                // Converged: t is ⌊√x⌋.
                break;
            }
            t = next;
        }
        self.neg = false;
        self.abs = t.abs;
        self
    }

    /// `(*Int).ProbablyPrime(n)` — reports whether `self` is probably
    /// prime. Panics if `n < 0` (Go: `"negative n for ProbablyPrime"`).
    /// Negative receivers and values `< 2` are not prime.
    ///
    /// Algorithm: small-case + small-prime trial division, then the
    /// Miller-Rabin test with the 12 deterministic bases
    /// 2,3,5,7,11,13,17,19,23,29,31,37 — provably exact for every
    /// integer below 3.3×10²⁴ — plus `n` extra rounds with those same
    /// bases for larger inputs.
    ///
    /// Deviation from Go: Go additionally runs a Baillie-PSW strong
    /// Lucas test after Miller-Rabin. This implementation is
    /// Miller-Rabin only; for non-adversarial inputs the probability of
    /// a false positive is at most ¼ per extra round.
    pub fn ProbablyPrime(&self, n: int) -> bool {
        if n < 0 {
            panic!("negative n for ProbablyPrime");
        }
        // Negative or zero — never prime.
        if self.neg || self.abs.is_empty() {
            return false;
        }
        // Small primes that fit in i64 — settles 2, 3, even-ness early.
        const SMALL_PRIMES: [u32; 12] =
            [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];

        let mut one = Int::new();
        one.SetInt64(1);
        if self.Cmp(&one) <= 0 {
            return false; // x < 2
        }
        // Trial division by the small primes.
        for &p in SMALL_PRIMES.iter() {
            let mut pi = Int::new();
            pi.SetInt64(p as i64);
            match self.Cmp(&pi) {
                0 => return true,         // x is itself a small prime
                -1 => return false,       // 2 < x < p, already trial-divided
                _ => {}
            }
            let mut r = Int::new();
            r.Mod(self, &pi);
            if r.abs.is_empty() {
                return false; // divisible by p
            }
        }

        // Miller-Rabin. Decompose n-1 = d·2^s with d odd.
        let mut nm1 = Int::new();
        nm1.Sub(self, &one);
        let s = nm1.TrailingZeroBits();
        let mut d = Int::new();
        d.Rsh(&nm1, s);

        // Witness rounds: the 12 deterministic bases give exactness
        // below 3.3×10²⁴; `n` extra rounds reuse the same bases.
        let rounds = SMALL_PRIMES.len() + (n as usize);
        for i in 0..rounds {
            let base = SMALL_PRIMES[i % SMALL_PRIMES.len()];
            let mut a = Int::new();
            a.SetInt64(base as i64);
            // A base >= n contributes nothing — but n > 37 here, so
            // every small-prime base is a valid 2 <= a <= n-2.
            let mut y = Int::new();
            y.Exp(&a, &d, self); // y = a^d mod self
            if y.Cmp(&one) == 0 || y.Cmp(&nm1) == 0 {
                continue; // probable prime for this base
            }
            let mut composite = true;
            // Square up to s-1 times, looking for y == n-1.
            let mut j: crate::types::uint = 1;
            while j < s {
                let mut sq = Int::new();
                sq.Mul(&y, &y);
                let mut next = Int::new();
                next.Mod(&sq, self);
                y = next;
                if y.Cmp(&nm1) == 0 {
                    composite = false;
                    break;
                }
                if y.Cmp(&one) == 0 {
                    return false; // non-trivial root of 1 -> composite
                }
                j += 1;
            }
            if composite {
                return false;
            }
        }
        true
    }

    /// `(*Int).ModSqrt(x, p)` — z² ≡ x (mod p), with `p` an odd prime.
    /// Returns `self`.
    ///
    /// The result is normalised into `[0, p)`. The fast path is used
    /// when `p ≡ 3 (mod 4)`; otherwise the general Tonelli-Shanks
    /// algorithm runs (covering `p ≡ 1 (mod 4)`).
    ///
    /// Precondition: `x` must be a quadratic residue mod `p`. When it
    /// is not (no square root exists), `self` is left **unchanged** —
    /// matching the design of `ModInverse`'s no-inverse case. Go
    /// returns nil there; goish methods return `&mut Self` and cannot
    /// cleanly surface a nil sentinel, so callers must verify the
    /// residue precondition themselves. A garbage value is never
    /// stored.
    pub fn ModSqrt(&mut self, x: &Int, p: &Int) -> &mut Self {
        // Snapshot — self may alias x or p at the call site.
        let p = p.clone();
        let mut x = x.clone();

        let mut zero = Int::new();
        zero.SetInt64(0);
        let mut one = Int::new();
        one.SetInt64(1);
        let mut two = Int::new();
        two.SetInt64(2);

        // Reduce x into [0, p).
        {
            let mut xr = Int::new();
            xr.Mod(&x, &p);
            x = xr;
        }
        // sqrt(0) mod p == 0.
        if x.abs.is_empty() {
            return self.SetInt64(0);
        }

        // Euler's criterion: x is a quadratic residue iff
        // x^((p-1)/2) ≡ 1 (mod p).
        let mut pm1 = Int::new();
        pm1.Sub(&p, &one);
        let mut e = Int::new();
        e.Div(&pm1, &two); // (p-1)/2
        let mut legendre = Int::new();
        legendre.Exp(&x, &e, &p);
        if legendre.Cmp(&one) != 0 {
            // Not a quadratic residue — no square root. Leave self
            // unchanged (Go returns nil here).
            return self;
        }

        // Fast path: p ≡ 3 (mod 4) -> z = x^((p+1)/4) mod p.
        if !p.abs.is_empty() && (p.abs[0] & 3) == 3 {
            let mut pp1 = Int::new();
            pp1.Add(&p, &one);
            let mut exp = Int::new();
            exp.Div(&pp1, &big_four()); // (p+1)/4
            let mut r = Int::new();
            r.Exp(&x, &exp, &p);
            self.neg = false;
            self.abs = r.abs;
            return self;
        }

        // General case: Tonelli-Shanks. Break p-1 = s·2^ee with s odd.
        let ee = pm1.TrailingZeroBits();
        let mut s = Int::new();
        s.Rsh(&pm1, ee);

        // Find a quadratic non-residue n: smallest n with
        // n^((p-1)/2) ≡ -1 (mod p).
        let mut n = Int::new();
        n.SetInt64(2);
        loop {
            let mut t = Int::new();
            t.Exp(&n, &e, &p);
            // t == p-1 means Legendre(n,p) == -1.
            if t.Cmp(&pm1) == 0 {
                break;
            }
            let mut next = Int::new();
            next.Add(&n, &one);
            n = next;
        }

        // y = x^((s+1)/2), b = x^s, g = n^s, r = ee.
        let mut sp1 = Int::new();
        sp1.Add(&s, &one);
        let mut half = Int::new();
        half.Rsh(&sp1, 1);
        let mut y = Int::new();
        y.Exp(&x, &half, &p);
        let mut b = Int::new();
        b.Exp(&x, &s, &p);
        let mut g = Int::new();
        g.Exp(&n, &s, &p);
        let mut r = ee;

        loop {
            // Find the least m with ord_p(b) = 2^m.
            let mut m: crate::types::uint = 0;
            let mut t = Int::new();
            t.Set(&b);
            while t.Cmp(&one) != 0 {
                let mut sq = Int::new();
                sq.Mul(&t, &t);
                let mut red = Int::new();
                red.Mod(&sq, &p);
                t = red;
                m += 1;
            }
            if m == 0 {
                // b == 1: y is the square root.
                self.neg = false;
                self.abs = y.abs;
                return self;
            }
            // t = g^(2^(r-m-1)) mod p.
            let mut texp = Int::new();
            texp.SetInt64(0);
            texp.SetBit(&zero, (r - m - 1) as int, 1);
            let mut tt = Int::new();
            tt.Exp(&g, &texp, &p);
            // g = t² mod p ; y = y·t mod p ; b = b·g mod p ; r = m.
            {
                let mut gg = Int::new();
                gg.Mul(&tt, &tt);
                let mut gr = Int::new();
                gr.Mod(&gg, &p);
                g = gr;
            }
            {
                let mut yy = Int::new();
                yy.Mul(&y, &tt);
                let mut yr = Int::new();
                yr.Mod(&yy, &p);
                y = yr;
            }
            {
                let mut bb = Int::new();
                bb.Mul(&b, &g);
                let mut br = Int::new();
                br.Mod(&bb, &p);
                b = br;
            }
            r = m;
        }
    }

    /// `(*Int).Append(buf, base)` — append the base-`base` text of
    /// `self` (as produced by `Text`) to `buf` and return the extended
    /// slice. `base` must be 2..=62.
    pub fn Append(
        &self,
        buf: crate::slice<crate::types::byte>,
        base: int,
    ) -> crate::slice<crate::types::byte> {
        if base < 2 || base > MAX_BASE {
            panic!("big::Int::Append: invalid base");
        }
        let mut out = buf.__into_vec();
        out.extend_from_slice(&itoa(self.neg, &self.abs, base));
        crate::slice::<crate::types::byte>::__from_vec(out)
    }

    /// `(*Int).AppendText(b)` — append the decimal text of `self` to
    /// `b`. The error is always nil for `Int`, matching Go.
    pub fn AppendText(
        &self,
        b: crate::slice<crate::types::byte>,
    ) -> (crate::slice<crate::types::byte>, crate::error) {
        (self.Append(b, 10), crate::errors::nil)
    }

    /// `(*Int).MarshalText()` — the decimal text bytes of `self`. The
    /// error is always nil for `Int`, matching Go.
    pub fn MarshalText(&self) -> (crate::slice<crate::types::byte>, crate::error) {
        self.AppendText(crate::slice::<crate::types::byte>::new())
    }

    /// `(*Int).UnmarshalText(text)` — parse decimal `text` into `self`.
    /// Returns a non-nil error if `text` is not a valid integer.
    pub fn UnmarshalText(
        &mut self,
        text: crate::slice<crate::types::byte>,
    ) -> crate::error {
        match scan_int(&text, 0) {
            Some((neg, abs)) => {
                self.neg = neg && !abs.is_empty();
                self.abs = abs;
                crate::errors::nil
            }
            None => crate::errors::New(crate::fmt::Sprintf!(
                "math/big: cannot unmarshal %q into a *big.Int",
                crate::string::from_bytes(&text)
            )),
        }
    }

    /// `(*Int).MarshalJSON()` — the decimal text bytes of `self` (no
    /// quotes). Same as `MarshalText` for `Int`. Error is always nil.
    pub fn MarshalJSON(&self) -> (crate::slice<crate::types::byte>, crate::error) {
        self.MarshalText()
    }

    /// `(*Int).Rand(rnd, n)` — set `self` to a uniform pseudo-random
    /// value in `[0, n)` and return `self`. If `n <= 0`, `self` is set
    /// to 0. The result is always non-negative.
    ///
    /// Mirrors Go's `(*Int).Rand` (int.go) on top of `nat.random`
    /// (nat.go): generate random limbs, mask the top limb to `n`'s
    /// exact bit count, and reject any candidate `>= n` so the
    /// distribution stays uniform. As this uses `math/rand`, it must
    /// not be used for security-sensitive work.
    pub fn Rand(
        &mut self,
        rnd: &mut crate::math::rand::Rand,
        n: &Int,
    ) -> &mut Self {
        // n <= 0 → result is 0. (n.neg or empty magnitude.)
        if n.neg || n.abs.is_empty() {
            self.neg = false;
            self.abs = Vec::new();
            return self;
        }
        self.neg = false;
        self.abs = nat_random(rnd, &n.abs, bit_len(&n.abs));
        self
    }

    /// `(*Int).UnmarshalJSON(text)` — parse JSON `text` into `self`. A
    /// JSON `null` leaves the receiver unchanged (matching Go);
    /// otherwise behaves like `UnmarshalText`.
    pub fn UnmarshalJSON(
        &mut self,
        text: crate::slice<crate::types::byte>,
    ) -> crate::error {
        if &*text == b"null" {
            return crate::errors::nil;
        }
        self.UnmarshalText(text)
    }

    /// `(*Int).GobEncode()` — gob wire format: a single version/sign
    /// byte (`intGobVersion << 1`, with bit 0 set when negative)
    /// followed by the big-endian magnitude bytes. Error is always nil.
    pub fn GobEncode(&self) -> (crate::slice<crate::types::byte>, crate::error) {
        let mut out: Vec<u8> = Vec::new();
        let mut b: u8 = INT_GOB_VERSION << 1; // make space for sign bit
        if self.neg {
            b |= 1;
        }
        out.push(b);
        out.extend_from_slice(&limbs_to_be_bytes(&self.abs));
        (
            crate::slice::<crate::types::byte>::__from_vec(out),
            crate::errors::nil,
        )
    }

    /// `(*Int).GobDecode(buf)` — inverse of `GobEncode`. An empty `buf`
    /// resets `self` to zero (the other side sent a nil/default value);
    /// a version-byte mismatch returns a non-nil error.
    pub fn GobDecode(&mut self, buf: crate::slice<crate::types::byte>) -> crate::error {
        if buf.len() == 0 {
            // Other side sent a nil or default value.
            self.neg = false;
            self.abs = Vec::new();
            return crate::errors::nil;
        }
        let b = buf[0usize];
        if b >> 1 != INT_GOB_VERSION {
            return crate::errors::New(crate::fmt::Sprintf!(
                "Int.GobDecode: encoding version %d not supported",
                int::from((b >> 1) as i64)
            ));
        }
        self.neg = b & 1 != 0;
        self.abs = be_bytes_to_limbs(&(*buf)[1..]);
        crate::errors::nil
    }
}

/// Gob codec version — leading version byte (top bits also carry the
/// sign). Mirrors `intmarsh.go:intGobVersion`.
const INT_GOB_VERSION: u8 = 1;

/// The constant 4 as an `Int` — used by `ModSqrt`'s p ≡ 3 mod 4 path.
fn big_four() -> Int {
    let mut f = Int::new();
    f.SetInt64(4);
    f
}

/// `big.NewInt(x)` — Go's package-level constructor.
pub fn NewInt(x: i64) -> Int {
    let mut z = Int::new();
    z.SetInt64(x);
    z
}

// ─── Stringer / Format — `%v` / `%d` / `%s` on `big::Int` ──────────────
//
// Go's `*big.Int` implements `fmt.Stringer` and produces the decimal
// representation. Goish mirrors that: implement `fmt::Stringer` so
// the blanket `impl<T: Stringer> Format for T` picks it up
// automatically for all printf verbs. (`%d` and `%v` both wind up
// calling `String()` once the value reaches the formatter via Stringer.)
impl crate::fmt::Stringer for Int {
    fn String(&self) -> crate::gostring::string {
        // Go's `(*Int).String()` is exactly `x.Text(10)`.
        self.Text(10)
    }
}

// Go's `*big.Rat` also implements `fmt.Stringer`, yielding the `"a/b"`
// form. Mirror it so all printf verbs pick the Rat up automatically.
impl crate::fmt::Stringer for Rat {
    fn String(&self) -> crate::gostring::string {
        self.String()
    }
}

// ─── fmt.Formatter — verb-aware `%x` / `%d` / `%.8d` etc. ─────────────
//
// Go's `*big.Int` and `*big.Float` implement `fmt.Formatter` so a
// `%#x` / `%+d` / `%8.4f` printf verb renders with the full flag /
// width / precision suite. Goish mirrors the two `Format` methods on
// top of `crate::fmt::State` (the `io::Writer` carrying the parsed
// modifiers). The sign / width / zero-pad logic is identical between
// the two, so it lives in the shared `fmt_pad` helper below.
mod fmt_pad {
    use crate::fmt::State;
    use crate::types::int;

    /// Write `text` `count` times through `s` (Go's `writeMultiple`).
    fn write_multiple(s: &mut dyn State, text: &[u8], count: int) {
        if text.is_empty() {
            return;
        }
        let mut c = count;
        while c > 0 {
            let buf = crate::slice::<crate::types::byte>::__from_vec(text.to_vec());
            let _ = s.Write(buf);
            c -= 1;
        }
    }

    /// Whether the state has the given flag character set.
    pub fn flag(s: &dyn State, c: u8) -> bool {
        s.Flag(c as int)
    }

    /// Render `[left pad][sign][prefix][zero pad][digits][right pad]`
    /// through `s`, honoring `Precision` (digit zero-padding) and
    /// `Width` (field padding). Mirrors the tail of Go's
    /// `(*Int).Format` (intconv.go) — the shared layout used by both
    /// the `Int` and `Float` formatters.
    ///
    /// `precision_for_zeros` controls whether `Precision()` adds
    /// leading zeros to the digits: `Int` honors it, `Float` derives
    /// its precision into `Append` directly and passes `false` here.
    pub fn emit(
        s: &mut dyn State,
        sign: &[u8],
        prefix: &[u8],
        digits: &[u8],
        precision_for_zeros: bool,
    ) {
        // number padding from precision: least digits to output.
        let mut zeros: int = 0;
        let (precision, precision_set) = s.Precision();
        if precision_for_zeros && precision_set {
            let dl = digits.len() as int;
            if dl < precision {
                zeros = precision - dl;
            } else if digits == b"0" && precision == 0 {
                // zero value with zero precision — print nothing.
                return;
            }
        }

        // field pad from width.
        let mut left: int = 0;
        let mut right: int = 0;
        let length = sign.len() as int + prefix.len() as int + zeros
            + digits.len() as int;
        let (width, width_set) = s.Width();
        if width_set && length < width {
            let d = width - length;
            if flag(s, b'-') {
                // pad on the right; supersedes '0'.
                right = d;
            } else if flag(s, b'0') && !(precision_for_zeros && precision_set) {
                // pad with zeros unless precision also specified.
                zeros = d;
            } else {
                left = d;
            }
        }

        write_multiple(s, b" ", left);
        write_multiple(s, sign, 1);
        write_multiple(s, prefix, 1);
        write_multiple(s, b"0", zeros);
        let dbuf = crate::slice::<crate::types::byte>::__from_vec(digits.to_vec());
        let _ = s.Write(dbuf);
        write_multiple(s, b" ", right);
    }

    /// Float field padding — Go's `(*Float).Format` tail. The `Append`
    /// output already carries the rendered digits + exponent; this only
    /// applies sign + field padding (no precision zero-pad). `is_inf`
    /// suppresses '0'-padding (Go pads Inf with spaces).
    pub fn emit_float(s: &mut dyn State, sign: &[u8], body: &[u8], is_inf: bool) {
        let mut padding: int = 0;
        let (width, width_set) = s.Width();
        let length = sign.len() as int + body.len() as int;
        if width_set && width > length {
            padding = width - length;
        }
        if flag(s, b'0') && !is_inf {
            write_multiple(s, sign, 1);
            write_multiple(s, b"0", padding);
            let b = crate::slice::<crate::types::byte>::__from_vec(body.to_vec());
            let _ = s.Write(b);
        } else if flag(s, b'-') {
            write_multiple(s, sign, 1);
            let b = crate::slice::<crate::types::byte>::__from_vec(body.to_vec());
            let _ = s.Write(b);
            write_multiple(s, b" ", padding);
        } else {
            write_multiple(s, b" ", padding);
            write_multiple(s, sign, 1);
            let b = crate::slice::<crate::types::byte>::__from_vec(body.to_vec());
            let _ = s.Write(b);
        }
    }

    /// Write the Go `%!<verb>(big.<kind>=<value>)` form for an
    /// unsupported verb.
    pub fn write_bad_verb(s: &mut dyn State, verb: crate::types::rune, kind: &[u8], value: &[u8]) {
        let mut out: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        out.extend_from_slice(b"%!");
        let mut rbuf = [0u8; 4];
        let rn = crate::unicode::utf8::EncodeRune(&mut rbuf, verb);
        out.extend_from_slice(&rbuf[..rn as usize]);
        out.push(b'(');
        out.extend_from_slice(kind);
        out.push(b'=');
        out.extend_from_slice(value);
        out.push(b')');
        let buf = crate::slice::<crate::types::byte>::__from_vec(out);
        let _ = s.Write(buf);
    }
}

// `(*Int).Format` — Go's intconv.go:Format. Accepts the verbs
// `b o O d s v x X`; honors the `#` `+` ` ` `-` `0` flags plus width
// and precision. An unrecognized verb writes `%!<verb>(big.Int=<dec>)`.
impl crate::fmt::Formatter for Int {
    fn Format(&self, f: &mut dyn crate::fmt::State, c: crate::types::rune) {
        // determine base from the verb.
        let base: int = match c {
            x if x == 'b' as crate::types::rune => 2,
            x if x == 'o' as crate::types::rune
                || x == 'O' as crate::types::rune => 8,
            x if x == 'd' as crate::types::rune
                || x == 's' as crate::types::rune
                || x == 'v' as crate::types::rune => 10,
            x if x == 'x' as crate::types::rune
                || x == 'X' as crate::types::rune => 16,
            _ => {
                // unknown verb.
                let dec = self.Text(10);
                fmt_pad::write_bad_verb(f, c, b"big.Int", dec.as_bytes());
                return;
            }
        };

        // sign character.
        let sign: &[u8] = if self.neg {
            b"-"
        } else if fmt_pad::flag(f, b'+') {
            b"+"
        } else if fmt_pad::flag(f, b' ') {
            b" "
        } else {
            b""
        };

        // base-indicating prefix for the `#` flag (and `O`).
        let mut prefix: &[u8] = b"";
        if fmt_pad::flag(f, b'#') {
            prefix = match c {
                x if x == 'b' as crate::types::rune => b"0b",
                x if x == 'o' as crate::types::rune => b"0",
                x if x == 'x' as crate::types::rune => b"0x",
                x if x == 'X' as crate::types::rune => b"0X",
                _ => b"",
            };
        }
        if c == 'O' as crate::types::rune {
            prefix = b"0o";
        }

        // render the magnitude digits (Text without the sign).
        let digit_str = {
            let mut t = Int::new();
            t.abs = self.abs.clone();
            t.neg = false;
            t.Text(base)
        };
        let mut digits: Vec<u8> = digit_str.as_bytes().to_vec();
        if c == 'X' as crate::types::rune {
            for d in digits.iter_mut() {
                if (b'a'..=b'z').contains(d) {
                    *d = b'A' + (*d - b'a');
                }
            }
        }

        fmt_pad::emit(f, sign, prefix, &digits, true);
    }
}

// `(*Float).Format` — Go's ftoa.go:Format. Accepts the verbs
// `b e E f F g G x p v`; maps each to `Text`'s format byte, derives
// the precision argument from `f.Precision()`, then applies sign +
// width padding. An unrecognized verb writes `%!<verb>(big.Float=...)`.
impl crate::fmt::Formatter for Float {
    fn Format(&self, f: &mut dyn crate::fmt::State, c: crate::types::rune) {
        let (prec_set_i, has_prec) = f.Precision();
        let mut prec: int = if has_prec { prec_set_i } else { 6 };

        // map the verb to a Text format byte.
        let format: u8 = match c {
            x if x == 'e' as crate::types::rune => b'e',
            x if x == 'E' as crate::types::rune => b'E',
            x if x == 'f' as crate::types::rune => b'f',
            x if x == 'b' as crate::types::rune => b'b',
            x if x == 'p' as crate::types::rune => b'p',
            x if x == 'x' as crate::types::rune => b'x',
            // 'F' is handled like 'f'.
            x if x == 'F' as crate::types::rune => b'f',
            // 'v' is handled like 'g'.
            x if x == 'v' as crate::types::rune
                || x == 'g' as crate::types::rune => {
                if !has_prec {
                    prec = -1;
                }
                b'g'
            }
            x if x == 'G' as crate::types::rune => {
                if !has_prec {
                    prec = -1;
                }
                b'G'
            }
            _ => {
                let g = self.String();
                fmt_pad::write_bad_verb(f, c, b"big.Float", g.as_bytes());
                return;
            }
        };

        // render the body (Append already produces sign + digits).
        let mut buf: Vec<u8> = self.append_internal(Vec::new(), format, prec);
        if buf.is_empty() {
            buf = b"?".to_vec();
        }

        // peel the leading sign character off the body.
        let (sign, body): (&[u8], &[u8]) = match buf[0] {
            b'-' => (b"-", &buf[1..]),
            b'+' => {
                // +Inf — ' ' flag downgrades '+' to a space.
                if fmt_pad::flag(f, b' ') {
                    (b" ", &buf[1..])
                } else {
                    (b"+", &buf[1..])
                }
            }
            _ => {
                if fmt_pad::flag(f, b'+') {
                    (b"+", &buf[..])
                } else if fmt_pad::flag(f, b' ') {
                    (b" ", &buf[..])
                } else {
                    (b"", &buf[..])
                }
            }
        };

        fmt_pad::emit_float(f, sign, body, self.IsInf());
    }
}

// ─── fmt::Scanner — Int / Rat / Float ─────────────────────────────────
//
// Go reference: math/big/intconv.go, ratconv.go, floatconv.go. Each of
// `*big.Int`, `*big.Rat`, `*big.Float` implements `fmt.Scanner` so a
// printf-style `Sscanf("%d", &z)` parses the value through the
// scanner's `Scan` method.
//
// Go drives the scan via a `byteReader` that wraps `fmt.ScanState` as
// an `io.ByteScanner`, reading one rune at a time. Goish's `ScanState`
// already exposes `Token`, which is the simplest faithful path: a
// predicate selects the run of characters that may belong to a numeric
// literal, and the collected bytes are handed to the existing string
// parsers (`scan_int` / `SetString` / `Parse`).
mod scan_tok {
    use crate::types::rune;
    use alloc::sync::Arc;

    /// Predicate for `Int.Scan`: sign, the base-prefix letters, the
    /// digit characters of every base goish accepts, and the `_`
    /// separator. Mirrors the character set Go's `nat.scan` consumes.
    pub fn int_tok(ch: rune) -> bool {
        matches!(ch as u32 as u8 as char,
            '+' | '-' | '_' | '.'
            | '0'..='9' | 'a'..='z' | 'A'..='Z')
            && ch >= 0 && ch < 128
    }

    /// Predicate for `Rat.Scan` — Go's `ratTok`: `"+-/0123456789.eE"`.
    pub fn rat_tok(ch: rune) -> bool {
        matches!(ch as u32 as u8 as char,
            '+' | '-' | '/' | '.' | 'e' | 'E' | '0'..='9')
            && ch >= 0 && ch < 128
    }

    /// Predicate for `Float.Scan`: a float literal's character set —
    /// sign, base-prefix letters, digits, radix point, and the `e`/`p`
    /// exponent indicators (plus `_` for base-0 separators).
    pub fn float_tok(ch: rune) -> bool {
        matches!(ch as u32 as u8 as char,
            '+' | '-' | '_' | '.'
            | '0'..='9' | 'a'..='z' | 'A'..='Z')
            && ch >= 0 && ch < 128
    }

    /// Pull a numeric token out of `state` using `pred`, skipping any
    /// leading whitespace. Returns the collected bytes, or an error
    /// when the state reports a read failure.
    pub fn token(
        state: &mut dyn crate::fmt::ScanState,
        pred: fn(rune) -> bool,
    ) -> (crate::slice<crate::types::byte>, crate::error) {
        let f: Arc<dyn Fn(rune) -> bool + Send + Sync> = Arc::new(pred);
        state.Token(true, f)
    }
}

// `(*Int).Scan` — Go's intconv.go:Scan. Accepts the verbs `b o d x X`
// (base 2/8/10/16) plus `s`/`v` (base auto-detected from the literal
// prefix). Reads a numeric token from `state` and parses it with
// `scan_int`. An unsupported verb returns `errors.New("Int.Scan:
// invalid verb")`.
impl crate::fmt::Scanner for Int {
    fn Scan(
        &mut self,
        state: &mut dyn crate::fmt::ScanState,
        verb: crate::types::rune,
    ) -> crate::error {
        let base: int = match verb {
            x if x == 'b' as crate::types::rune => 2,
            x if x == 'o' as crate::types::rune => 8,
            x if x == 'd' as crate::types::rune => 10,
            x if x == 'x' as crate::types::rune
                || x == 'X' as crate::types::rune => 16,
            x if x == 's' as crate::types::rune
                || x == 'v' as crate::types::rune => 0,
            _ => return crate::errors::New("Int.Scan: invalid verb"),
        };
        let (tok, err) = scan_tok::token(state, scan_tok::int_tok);
        if err != crate::errors::nil {
            return err;
        }
        match scan_int(&tok, base) {
            Some((neg, abs)) => {
                self.neg = neg && !abs.is_empty();
                self.abs = abs;
                crate::errors::nil
            }
            None => crate::errors::New("Int.Scan: invalid syntax"),
        }
    }
}

// `(*Rat).Scan` — Go's ratconv.go:Scan. Accepts the verbs `e E f F g
// G v` (all equivalent). Reads a numeric token and parses it with
// `Rat::SetString`. An unsupported verb returns `errors.New("Rat.Scan:
// invalid verb")`.
impl crate::fmt::Scanner for Rat {
    fn Scan(
        &mut self,
        state: &mut dyn crate::fmt::ScanState,
        verb: crate::types::rune,
    ) -> crate::error {
        let (tok, err) = scan_tok::token(state, scan_tok::rat_tok);
        if err != crate::errors::nil {
            return err;
        }
        let ok_verb = matches!(verb,
            x if x == 'e' as crate::types::rune
                || x == 'E' as crate::types::rune
                || x == 'f' as crate::types::rune
                || x == 'F' as crate::types::rune
                || x == 'g' as crate::types::rune
                || x == 'G' as crate::types::rune
                || x == 'v' as crate::types::rune);
        if !ok_verb {
            return crate::errors::New("Rat.Scan: invalid verb");
        }
        let s = crate::string::from_bytes(&tok);
        let (_, ok) = self.SetString(s);
        if ok {
            crate::errors::nil
        } else {
            crate::errors::New("Rat.Scan: invalid syntax")
        }
    }
}

// `(*Float).Scan` — Go's floatconv.go:Scan. Accepts the floating-point
// verbs `b e E f F g G`. Reads a numeric token and parses it with
// `Float::Parse` (base 0). Scan does not handle ±Inf. An unsupported
// verb returns `errors.New("Float.Scan: invalid verb")`.
impl crate::fmt::Scanner for Float {
    fn Scan(
        &mut self,
        state: &mut dyn crate::fmt::ScanState,
        verb: crate::types::rune,
    ) -> crate::error {
        let ok_verb = matches!(verb,
            x if x == 'b' as crate::types::rune
                || x == 'e' as crate::types::rune
                || x == 'E' as crate::types::rune
                || x == 'f' as crate::types::rune
                || x == 'F' as crate::types::rune
                || x == 'g' as crate::types::rune
                || x == 'G' as crate::types::rune);
        if !ok_verb {
            return crate::errors::New("Float.Scan: invalid verb");
        }
        let (tok, err) = scan_tok::token(state, scan_tok::float_tok);
        if err != crate::errors::nil {
            return err;
        }
        let s = crate::string::from_bytes(&tok);
        let (_, _, perr) = self.Parse(s, 0);
        perr
    }
}

/// Rat gob codec version — mirrors `ratmarsh.go:ratGobVersion`.
const RAT_GOB_VERSION: u8 = 1;

/// `(*Rat).marshal` — append the `"a/b"` text of a num/den pair to a
/// fresh buffer (always `"a/b"`, even when den == 1). A zero-value
/// denominator (empty limbs) prints as `1`.
fn rat_marshal(num: &Int, den: &Int) -> Vec<u8> {
    let mut buf = itoa(num.neg, &num.abs, 10);
    buf.push(b'/');
    if !den.abs.is_empty() {
        buf.extend_from_slice(&itoa(false, &den.abs, 10));
    } else {
        buf.push(b'1');
    }
    buf
}

/// `10**n` as little-endian u32 limbs (n >= 0).
fn pow10_limbs(n: u64) -> Vec<u32> {
    let mut acc = alloc::vec![1u32];
    let ten = alloc::vec![10u32];
    for _ in 0..n {
        acc = mul_limbs(&acc, &ten);
    }
    acc
}

/// `quotToFloat64` — nearest f64 to the non-negative quotient a/b,
/// round-half-to-even. Preconditions: b non-zero (a zero-value `b`,
/// i.e. empty limbs, is treated as 1); a and b have no common factors.
/// Mirrors `rat.go:quotToFloat64`.
fn quot_to_float64(a: &[u32], b: &[u32]) -> (f64, bool) {
    // float64 layout constants.
    const MSIZE: i64 = 52;
    const MSIZE1: i64 = MSIZE + 1; // incl. implicit 1
    const MSIZE2: i64 = MSIZE1 + 1;
    const ESIZE: i64 = 64 - MSIZE1;
    const EBIAS: i64 = (1 << (ESIZE - 1)) - 1;
    const EMIN: i64 = 1 - EBIAS;

    let one = alloc::vec![1u32];
    let b: &[u32] = if b.is_empty() { &one } else { b };

    let alen = bit_len(a);
    if alen == 0 {
        return (0.0, true);
    }
    let blen = bit_len(b);
    if blen == 0 {
        panic!("division by zero");
    }

    // 1. Left-shift a or b so the quotient lands in the desired range.
    let mut exp: i64 = (alen - blen) as i64;
    let mut a2 = a.to_vec();
    let mut b2 = b.to_vec();
    let shift = MSIZE2 - exp;
    if shift > 0 {
        a2 = lsh_limbs(&a2, shift as u64);
    } else if shift < 0 {
        b2 = lsh_limbs(&b2, (-shift) as u64);
    }

    // 2. Quotient and remainder.
    let (q, r) = divmod_limbs(&a2, &b2);
    let mut mantissa: u64 = limbs_to_u64(&q);
    let mut have_rem = !r.is_empty();

    // 3. If the quotient didn't fit in Msize2 bits, redo by b2<<1.
    if mantissa >> MSIZE2 == 1 {
        if mantissa & 1 == 1 {
            have_rem = true;
        }
        mantissa >>= 1;
        exp += 1;
    }
    if mantissa >> MSIZE1 != 1 {
        panic!("expected exactly Msize2 bits of result");
    }

    // 4. Rounding.
    if EMIN - MSIZE <= exp && exp <= EMIN {
        // Denormal case; lose 'sh' bits of precision.
        let sh = (EMIN - (exp - 1)) as u64;
        let lostbits = mantissa & ((1u64 << sh) - 1);
        have_rem = have_rem || lostbits != 0;
        mantissa >>= sh;
        exp = 2 - EBIAS;
    }
    // Round q using round-half-to-even.
    let mut exact = !have_rem;
    if mantissa & 1 != 0 {
        exact = false;
        if have_rem || mantissa & 2 != 0 {
            mantissa += 1;
            if mantissa >= 1 << MSIZE2 {
                mantissa >>= 1;
                exp += 1;
            }
        }
    }
    mantissa >>= 1; // discard rounding bit; mantissa scaled by 1<<Msize1.

    let f = ldexp_f64(mantissa, exp - MSIZE1);
    if f.is_infinite() {
        exact = false;
    }
    (f, exact)
}

/// `quotToFloat32` — nearest f32 to the non-negative quotient a/b,
/// round-half-to-even. Mirrors `rat.go:quotToFloat32`.
fn quot_to_float32(a: &[u32], b: &[u32]) -> (f32, bool) {
    const MSIZE: i64 = 23;
    const MSIZE1: i64 = MSIZE + 1; // incl. implicit 1
    const MSIZE2: i64 = MSIZE1 + 1;
    const ESIZE: i64 = 32 - MSIZE1;
    const EBIAS: i64 = (1 << (ESIZE - 1)) - 1;
    const EMIN: i64 = 1 - EBIAS;

    let one = alloc::vec![1u32];
    let b: &[u32] = if b.is_empty() { &one } else { b };

    let alen = bit_len(a);
    if alen == 0 {
        return (0.0, true);
    }
    let blen = bit_len(b);
    if blen == 0 {
        panic!("division by zero");
    }

    let mut exp: i64 = (alen - blen) as i64;
    let mut a2 = a.to_vec();
    let mut b2 = b.to_vec();
    let shift = MSIZE2 - exp;
    if shift > 0 {
        a2 = lsh_limbs(&a2, shift as u64);
    } else if shift < 0 {
        b2 = lsh_limbs(&b2, (-shift) as u64);
    }

    let (q, r) = divmod_limbs(&a2, &b2);
    let mut mantissa: u32 = limbs_to_u64(&q) as u32;
    let mut have_rem = !r.is_empty();

    if mantissa >> MSIZE2 == 1 {
        if mantissa & 1 == 1 {
            have_rem = true;
        }
        mantissa >>= 1;
        exp += 1;
    }
    if mantissa >> MSIZE1 != 1 {
        panic!("expected exactly Msize2 bits of result");
    }

    if EMIN - MSIZE <= exp && exp <= EMIN {
        let sh = (EMIN - (exp - 1)) as u32;
        let lostbits = mantissa & ((1u32 << sh) - 1);
        have_rem = have_rem || lostbits != 0;
        mantissa >>= sh;
        exp = 2 - EBIAS;
    }
    let mut exact = !have_rem;
    if mantissa & 1 != 0 {
        exact = false;
        if have_rem || mantissa & 2 != 0 {
            mantissa += 1;
            if mantissa >= 1 << MSIZE2 {
                mantissa >>= 1;
                exp += 1;
            }
        }
    }
    mantissa >>= 1;

    let f64v = ldexp_f64(u64::from(mantissa), exp - MSIZE1);
    let f = f64v as f32;
    if f.is_infinite() {
        exact = false;
    }
    (f, exact)
}

/// `math.Ldexp(frac, exp)` for a non-negative integer `mantissa` — the
/// value `mantissa * 2^exp`. Avoids `core`'s missing libm by scaling
/// through f64 multiplications/divisions by powers of two.
fn ldexp_f64(mantissa: u64, exp: i64) -> f64 {
    let mut f = f64_from_u64_full(mantissa);
    if f == 0.0 {
        return 0.0;
    }
    // Apply the binary exponent in chunks small enough to stay finite.
    let mut e = exp;
    while e > 0 {
        let step = e.min(60);
        f *= f64::from_bits(((1023 + step) as u64) << 52);
        e -= step;
    }
    while e < 0 {
        let step = (-e).min(60);
        f /= f64::from_bits(((1023 + step) as u64) << 52);
        e += step;
    }
    f
}

/// Convert any `u64` to the nearest `f64` (round-half-to-even). Unlike
/// `f64_from_u64`, this does not assume the value fits in 53 bits.
fn f64_from_u64_full(x: u64) -> f64 {
    if x == 0 {
        return 0.0;
    }
    let msb = 63 - x.leading_zeros();
    if msb < 53 {
        return f64_from_u64(x);
    }
    // Round the low (msb-52) bits into the kept 53-bit mantissa.
    let drop = msb - 52;
    let keep = x >> drop;
    let rem = x & ((1u64 << drop) - 1);
    let half = 1u64 << (drop - 1);
    let mut mant = keep;
    let mut exp = msb;
    if rem > half || (rem == half && (keep & 1) == 1) {
        mant += 1;
        if mant >> 53 == 1 {
            mant >>= 1;
            exp += 1;
        }
    }
    // mant has 53 significant bits; assemble via the 53-bit-safe path.
    ldexp_f64(mant, i64::from(exp) - 52)
}

// ─── nil-poly: Go callers do `if z == nil` on `*big.Int` ──────────────
//
// In goish the canonical zero-value of `Int` IS the zero, so the
// "nil pointer" case is equivalent to a fresh `Int::default()`. Match
// any zero-valued Int.
impl PartialEq<crate::nilval::Nil> for Int {
    fn eq(&self, _: &crate::nilval::Nil) -> bool {
        self.abs.is_empty() && !self.neg
    }
}
impl PartialEq<Int> for crate::nilval::Nil {
    fn eq(&self, other: &Int) -> bool {
        other.abs.is_empty() && !other.neg
    }
}
impl From<crate::nilval::Nil> for Int {
    fn from(_: crate::nilval::Nil) -> Self {
        Int::new()
    }
}

// ─── helpers ───────────────────────────────────────────────────────────

fn u64_to_limbs(x: u64) -> Vec<u32> {
    if x == 0 {
        Vec::new()
    } else if x <= u32::MAX as u64 {
        alloc::vec![x as u32]
    } else {
        alloc::vec![x as u32, (x >> 32) as u32]
    }
}

fn limbs_to_u64(limbs: &[u32]) -> u64 {
    match limbs.len() {
        0 => 0,
        1 => limbs[0] as u64,
        _ => limbs[0] as u64 | ((limbs[1] as u64) << 32),
    }
}

fn abs_cmp(a: &[u32], b: &[u32]) -> Ordering {
    match a.len().cmp(&b.len()) {
        Ordering::Equal => {
            for (x, y) in a.iter().rev().zip(b.iter().rev()) {
                match x.cmp(y) {
                    Ordering::Equal => continue,
                    o => return o,
                }
            }
            Ordering::Equal
        }
        o => o,
    }
}

/// Long division by a single u32 divisor returning (quotient_limbs, remainder).
/// `quotient_limbs` is trimmed of leading zeros.
fn divmod_by_u32(num: &[u32], d: u32) -> (Vec<u32>, u32) {
    debug_assert!(d != 0);
    let dv = d as u64;
    let mut q = alloc::vec![0u32; num.len()];
    let mut r: u64 = 0;
    for (i, &limb) in num.iter().enumerate().rev() {
        let cur = (r << 32) | (limb as u64);
        q[i] = (cur / dv) as u32;
        r = cur % dv;
    }
    // Trim leading zero limbs.
    while q.last().copied() == Some(0) {
        q.pop();
    }
    (q, r as u32)
}

/// Shift a trimmed limb vector left by `s` bits (0 <= s < 32).
/// Used by the divisor-normalisation step of Knuth Algorithm D.
fn shl_small(a: &[u32], s: u32) -> Vec<u32> {
    if a.is_empty() {
        return Vec::new();
    }
    if s == 0 {
        return a.to_vec();
    }
    let mut out = alloc::vec![0u32; a.len() + 1];
    let mut carry: u32 = 0;
    for (i, &limb) in a.iter().enumerate() {
        let v = ((limb as u64) << s) | (carry as u64);
        out[i] = v as u32;
        carry = (v >> 32) as u32;
    }
    out[a.len()] = carry;
    while out.last().copied() == Some(0) {
        out.pop();
    }
    out
}

/// Shift a limb vector right by `s` bits (0 <= s < 32). The vector is
/// not required to be trimmed on entry; the result is trimmed.
fn shr_small(a: &[u32], s: u32) -> Vec<u32> {
    if a.is_empty() {
        return Vec::new();
    }
    if s == 0 {
        let mut out = a.to_vec();
        while out.last().copied() == Some(0) {
            out.pop();
        }
        return out;
    }
    let mut out = alloc::vec![0u32; a.len()];
    let mut carry: u32 = 0;
    for i in (0..a.len()).rev() {
        let v = a[i];
        out[i] = (v >> s) | carry;
        carry = v << (32 - s);
    }
    while out.last().copied() == Some(0) {
        out.pop();
    }
    out
}

/// Unsigned multi-precision long division: returns (quotient, remainder)
/// for `num / den`, both trimmed (no trailing zero limbs).
///
/// Implements Knuth TAOCP vol. 2, §4.3.1 Algorithm D — normalised
/// classic long division with a base-2^32 limb. The single-limb
/// divisor case is delegated to `divmod_by_u32`. `den` must be
/// non-empty (the public methods check division-by-zero first).
fn divmod_limbs(num: &[u32], den: &[u32]) -> (Vec<u32>, Vec<u32>) {
    debug_assert!(!den.is_empty());
    // num < den  ->  quotient 0, remainder num.
    if abs_cmp(num, den) == Ordering::Less {
        let mut r = num.to_vec();
        while r.last().copied() == Some(0) {
            r.pop();
        }
        return (Vec::new(), r);
    }
    // Single-limb divisor: fast path.
    if den.len() == 1 {
        let (q, r) = divmod_by_u32(num, den[0]);
        return (q, if r == 0 { Vec::new() } else { alloc::vec![r] });
    }

    // ── Knuth Algorithm D ──────────────────────────────────────────
    let n = den.len(); // n >= 2
    let m = num.len() - n; // num.len() > n here (cmp ruled out <)

    // D1. Normalise so the divisor's top limb has its high bit set.
    let shift = den[n - 1].leading_zeros();
    let dn = shl_small(den, shift); // normalised divisor, n limbs (top stays high)
    debug_assert_eq!(dn.len(), n);
    // Normalised dividend; force exactly num.len()+1 limbs so the
    // extra top limb un[m+n] always exists.
    let mut un = shl_small(num, shift);
    un.resize(num.len() + 1, 0);

    let dn_hi = dn[n - 1] as u64;
    let dn_lo = dn[n - 2] as u64;
    let base: u64 = 1u64 << 32;

    let mut q = alloc::vec![0u32; m + 1];

    // D2-D7. Main loop, from the most-significant quotient limb down.
    for j in (0..=m).rev() {
        // D3. Estimate q̂.
        let num_hi = ((un[j + n] as u64) << 32) | (un[j + n - 1] as u64);
        let mut qhat = num_hi / dn_hi;
        let mut rhat = num_hi % dn_hi;
        // Refine: q̂ is at most 2 too large.
        while qhat >= base
            || qhat * dn_lo > (rhat << 32) | (un[j + n - 2] as u64)
        {
            qhat -= 1;
            rhat += dn_hi;
            if rhat >= base {
                break;
            }
        }

        // D4. Multiply and subtract: un[j..j+n+1] -= q̂ * dn.
        let mut borrow: i64 = 0;
        let mut carry: u64 = 0;
        for i in 0..n {
            let p = qhat * (dn[i] as u64) + carry;
            carry = p >> 32;
            let sub = (un[j + i] as i64) - borrow - ((p as u32) as i64);
            un[j + i] = sub as u32;
            borrow = if sub < 0 { 1 } else { 0 };
        }
        let sub = (un[j + n] as i64) - borrow - (carry as i64);
        un[j + n] = sub as u32;
        borrow = if sub < 0 { 1 } else { 0 };

        // D5/D6. If we subtracted too much, q̂ was 1 too big: add back.
        if borrow != 0 {
            qhat -= 1;
            let mut add_carry: u64 = 0;
            for i in 0..n {
                let s = (un[j + i] as u64) + (dn[i] as u64) + add_carry;
                un[j + i] = s as u32;
                add_carry = s >> 32;
            }
            un[j + n] = un[j + n].wrapping_add(add_carry as u32);
        }
        q[j] = qhat as u32;
    }

    // Trim quotient.
    while q.last().copied() == Some(0) {
        q.pop();
    }
    // Remainder = un[0..n] de-normalised (shift right by `shift`).
    let rem = shr_small(&un[0..n], shift);
    (q, rem)
}

/// Unsigned multi-precision multiplication: schoolbook O(n*m).
/// Returns trimmed limbs (no trailing zeros).
fn mul_limbs(a: &[u32], b: &[u32]) -> Vec<u32> {
    if a.is_empty() || b.is_empty() {
        return Vec::new();
    }
    let mut out = alloc::vec![0u32; a.len() + b.len()];
    for (i, &ai) in a.iter().enumerate() {
        let mut carry: u64 = 0;
        for (j, &bj) in b.iter().enumerate() {
            let prod = (ai as u64) * (bj as u64) + (out[i + j] as u64) + carry;
            out[i + j] = prod as u32;
            carry = prod >> 32;
        }
        out[i + b.len()] = out[i + b.len()].wrapping_add(carry as u32);
    }
    while out.last().copied() == Some(0) {
        out.pop();
    }
    out
}

/// Unsigned multi-precision addition.
fn add_limbs(a: &[u32], b: &[u32]) -> Vec<u32> {
    let n = a.len().max(b.len());
    let mut out = alloc::vec![0u32; n + 1];
    let mut carry: u64 = 0;
    for i in 0..n {
        let av = a.get(i).copied().unwrap_or(0) as u64;
        let bv = b.get(i).copied().unwrap_or(0) as u64;
        let s = av + bv + carry;
        out[i] = s as u32;
        carry = s >> 32;
    }
    out[n] = carry as u32;
    while out.last().copied() == Some(0) {
        out.pop();
    }
    out
}

/// Unsigned multi-precision subtraction assuming a >= b. Returns a - b.
fn sub_limbs(a: &[u32], b: &[u32]) -> Vec<u32> {
    debug_assert!(abs_cmp(a, b) != Ordering::Less);
    let mut out = alloc::vec![0u32; a.len()];
    let mut borrow: i64 = 0;
    for i in 0..a.len() {
        let av = a[i] as i64;
        let bv = b.get(i).copied().unwrap_or(0) as i64;
        let mut d = av - bv - borrow;
        if d < 0 {
            d += 1i64 << 32;
            borrow = 1;
        } else {
            borrow = 0;
        }
        out[i] = d as u32;
    }
    while out.last().copied() == Some(0) {
        out.pop();
    }
    out
}

// ─── string / byte conversion helpers ─────────────────────────────────
//
// Mirrors Go's `natconv.go` (`itoa` / `scan`) and `intconv.go`
// (`(*Int).SetString` / `Text`). The limb is a 32-bit `u32`; Go's
// `nat` uses a 64-bit `Word`, but the algorithms are limb-width
// agnostic — the only externally visible constant is `MAX_BASE`.

/// `big.MaxBase` — largest base accepted for string conversions:
/// `10 + ('z'-'a'+1) + ('Z'-'A'+1)` == 62.
pub const MAX_BASE: int = 62;
/// Bases up to this value treat `A`-`Z` as a case-insensitive alias
/// of `a`-`z` (digit values 10..35). Above it, `A`-`Z` carry 36..61.
const MAX_BASE_SMALL: int = 36;

/// Go's `digits` table: digit value → ASCII character.
const DIGIT_CHARS: &[u8; 62] =
    b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// Map an ASCII character to its digit value, or `None` if it is not a
/// digit. For `base <= 36`, `A`-`Z` alias `a`-`z`; above that they
/// continue the sequence at 36. Mirrors `natconv.go:scan`'s switch.
fn digit_value(ch: u8, base: int) -> Option<u32> {
    let d = if ch.is_ascii_digit() {
        (ch - b'0') as u32
    } else if (b'a'..=b'z').contains(&ch) {
        (ch - b'a') as u32 + 10
    } else if (b'A'..=b'Z').contains(&ch) {
        if base <= MAX_BASE_SMALL {
            (ch - b'A') as u32 + 10
        } else {
            (ch - b'A') as u32 + MAX_BASE_SMALL as u32
        }
    } else {
        return None;
    };
    if (d as int) < base { Some(d) } else { None }
}

/// In-place multiply-and-add: `limbs = limbs*mul + add` (base 2^32).
/// `mul` and `add` are single u32 words. The limb vector is trimmed.
fn mul_add_word(limbs: &mut Vec<u32>, mul: u32, add: u32) {
    let mut carry: u64 = add as u64;
    for limb in limbs.iter_mut() {
        let v = (*limb as u64) * (mul as u64) + carry;
        *limb = v as u32;
        carry = v >> 32;
    }
    if carry != 0 {
        limbs.push(carry as u32);
    }
    while limbs.last().copied() == Some(0) {
        limbs.pop();
    }
}

/// Scan a signed integer from `bytes` in the given `base`. Returns
/// `(neg, abs_limbs)` on success, `None` on any syntax error.
///
/// `base` is 0 (prefix-detected) or 2..=62. For base 0, `_` digit
/// separators are honoured per Go's `natconv.go:scan` grammar.
fn scan_int(bytes: &[u8], base: int) -> Option<(bool, Vec<u32>)> {
    if !(base == 0 || (2..=MAX_BASE).contains(&base)) {
        return None;
    }
    let mut i = 0usize;
    // Optional sign.
    let neg = match bytes.first().copied() {
        Some(b'-') => { i += 1; true }
        Some(b'+') => { i += 1; false }
        _ => false,
    };

    // Determine the actual base and consume any literal prefix.
    let mut b = base;
    // `prefix` records which prefix was consumed: 0 (none), b'b', b'o',
    // b'x', or b'0' (the bare-zero octal prefix). `prev` tracks the
    // previous significant char for `_`-separator validation: it is
    // '_' , '0' (a digit), or '.' (start / anything else).
    let mut prefix: u8 = 0;
    let mut prev: u8 = b'.';
    if base == 0 {
        b = 10;
        if bytes.get(i).copied() == Some(b'0') {
            // A leading '0' counts as the previous "digit" — Go keeps
            // `prev == '0'` across the prefix so a `_` may follow it.
            prev = b'0';
            i += 1;
            match bytes.get(i).copied() {
                Some(b'b') | Some(b'B') => { b = 2; prefix = b'b'; i += 1; }
                Some(b'o') | Some(b'O') => { b = 8; prefix = b'o'; i += 1; }
                Some(b'x') | Some(b'X') => { b = 16; prefix = b'x'; i += 1; }
                _ => { b = 8; prefix = b'0'; }
            }
        }
    }

    let mut limbs: Vec<u32> = Vec::new();
    let mut count: usize = 0; // number of digits parsed
    let mut inval_sep = false;

    while i < bytes.len() {
        let ch = bytes[i];
        if ch == b'_' && base == 0 {
            // A separator may only follow a digit.
            if prev != b'0' {
                inval_sep = true;
            }
            prev = b'_';
            i += 1;
            continue;
        }
        match digit_value(ch, b) {
            Some(d) => {
                mul_add_word(&mut limbs, b as u32, d);
                count += 1;
                prev = b'0';
                i += 1;
            }
            None => {
                // Not a digit — the number ends here.
                break;
            }
        }
    }

    // The whole string must be consumed; trailing junk is a failure.
    if i != bytes.len() {
        return None;
    }
    // A '_' may not be the last char, and an invalid placement fails.
    if inval_sep || prev == b'_' {
        return None;
    }
    if count == 0 {
        // A bare "0" (octal prefix with no following digits) is the
        // valid value zero; every other empty case is a failure.
        if prefix == b'0' {
            return Some((false, Vec::new()));
        }
        return None;
    }
    Some((neg, limbs))
}

/// Format the magnitude `abs` in `base` (2..=62), prepending `-` when
/// `neg` and the value is non-zero. Mirrors `natconv.go:itoa`.
fn itoa(neg: bool, abs: &[u32], base: int) -> Vec<u8> {
    debug_assert!((2..=MAX_BASE).contains(&base));
    if abs.is_empty() {
        return alloc::vec![b'0'];
    }
    // Repeatedly divide the magnitude by `base`, collecting digits
    // least-significant first, then reverse.
    let mut limbs = abs.to_vec();
    while limbs.last().copied() == Some(0) {
        limbs.pop();
    }
    let mut digits: Vec<u8> = Vec::new();
    let bw = base as u32;
    while !limbs.is_empty() {
        let (q, r) = divmod_by_u32(&limbs, bw);
        digits.push(DIGIT_CHARS[r as usize]);
        limbs = q;
    }
    if neg {
        digits.push(b'-');
    }
    digits.reverse();
    digits
}

/// Big-endian byte representation of a magnitude (no leading zero
/// bytes; an empty magnitude yields an empty buffer). Mirrors Go's
/// `nat.bytes`.
fn limbs_to_be_bytes(abs: &[u32]) -> Vec<u8> {
    // Trim trailing zero limbs defensively.
    let mut top = abs.len();
    while top > 0 && abs[top - 1] == 0 {
        top -= 1;
    }
    if top == 0 {
        return Vec::new();
    }
    // Emit limbs most-significant first, big-endian within each limb.
    let mut out: Vec<u8> = Vec::with_capacity(top * 4);
    for i in (0..top).rev() {
        let limb = abs[i];
        out.push((limb >> 24) as u8);
        out.push((limb >> 16) as u8);
        out.push((limb >> 8) as u8);
        out.push(limb as u8);
    }
    // Strip leading zero bytes (the most-significant limb may have them).
    let mut start = 0usize;
    while start < out.len() - 1 && out[start] == 0 {
        start += 1;
    }
    if out[start] == 0 {
        // Whole thing was zero (cannot happen given top>0, but be safe).
        return Vec::new();
    }
    out.drain(0..start);
    out
}

/// Interpret `buf` as a big-endian unsigned integer, returning its
/// little-endian u32 limbs (trimmed). Mirrors Go's `nat.setBytes`.
fn be_bytes_to_limbs(buf: &[u8]) -> Vec<u32> {
    // Skip leading zero bytes for a clean magnitude.
    let mut start = 0usize;
    while start < buf.len() && buf[start] == 0 {
        start += 1;
    }
    let sig = &buf[start..];
    if sig.is_empty() {
        return Vec::new();
    }
    let nlimbs = (sig.len() + 3) / 4;
    let mut limbs = alloc::vec![0u32; nlimbs];
    // Walk from the least-significant byte (end of buf) backwards,
    // packing 4 bytes per limb.
    let mut bit = 0u32;
    let mut li = 0usize;
    for &byte in sig.iter().rev() {
        limbs[li] |= (byte as u32) << bit;
        bit += 8;
        if bit == 32 {
            bit = 0;
            li += 1;
        }
    }
    while limbs.last().copied() == Some(0) {
        limbs.pop();
    }
    limbs
}

// ─── bitwise / shift limb helpers ──────────────────────────────────────
//
// The limb is a 32-bit `u32` (Go's `_W` is 64; here it is 32). Bitwise
// ops below operate on trimmed magnitude vectors only — the sign-aware
// two's-complement bookkeeping is done by the `Int` methods, which
// translate negative operands into `|x|-1` magnitudes before calling.

/// Trim trailing zero limbs in place (the canonical normal form).
fn trim(mut v: Vec<u32>) -> Vec<u32> {
    while v.last().copied() == Some(0) {
        v.pop();
    }
    v
}

/// Bit length of a magnitude (number of bits in |x|). `bitLen` of 0 is 0.
fn bit_len(a: &[u32]) -> int {
    let mut i = a.len();
    while i > 0 && a[i - 1] == 0 {
        i -= 1;
    }
    if i == 0 {
        return 0;
    }
    ((i - 1) * 32) as int + (32 - a[i - 1].leading_zeros()) as int
}

/// `nat.random` — uniform pseudo-random magnitude in `[0, limit)`.
/// `n` is the bit length of `limit`. Generates random 32-bit limbs,
/// masks the top limb to `n`'s exact bit count, and rejects any
/// candidate `>= limit` (rejection sampling). Mirrors `nat.go:random`
/// (the `_W == 32` branch — goish uses 32-bit limbs). `limit` must be
/// non-empty (caller guarantees `n > 0`).
fn nat_random(rnd: &mut crate::math::rand::Rand, limit: &[u32], n: int) -> Vec<u32> {
    let len = limit.len();
    let bit_len_of_msw = {
        let r = (n as u32) % 32;
        if r == 0 { 32 } else { r }
    };
    // mask for the most-significant word.
    let mask: u32 = if bit_len_of_msw == 32 {
        u32::MAX
    } else {
        (1u32 << bit_len_of_msw) - 1
    };
    let mut z: Vec<u32> = alloc::vec![0u32; len];
    loop {
        for limb in z.iter_mut() {
            *limb = rnd.Uint32();
        }
        z[len - 1] &= mask;
        if abs_cmp(&z, limit) == Ordering::Less {
            break;
        }
    }
    // norm: drop trailing zero limbs.
    while z.last() == Some(&0) {
        z.pop();
    }
    z
}

/// Repack little-endian u32 limbs into little-endian 64-bit `Word`s.
/// Pairs of limbs `(lo, hi)` become one word `hi<<32 | lo`; a trailing
/// odd limb becomes a final word with a zero high half. Trailing zero
/// words are dropped so the result stays normalized.
fn limbs_to_words(abs: &[u32]) -> Vec<Word> {
    let mut out: Vec<Word> = Vec::with_capacity(abs.len().div_ceil(2));
    let mut i = 0usize;
    while i < abs.len() {
        let lo = u64::from(abs[i]);
        let hi = if i + 1 < abs.len() {
            u64::from(abs[i + 1])
        } else {
            0
        };
        out.push((hi << 32) | lo);
        i += 2;
    }
    while out.last() == Some(&0) {
        out.pop();
    }
    out
}

/// Unpack little-endian 64-bit `Word`s into little-endian u32 limbs.
/// Each word splits into `(lo, hi)`; trailing zero limbs are dropped.
fn words_to_limbs(words: &[Word]) -> Vec<u32> {
    let mut out: Vec<u32> = Vec::with_capacity(words.len() * 2);
    for &w in words {
        let lo = u32::try_from(w & 0xFFFF_FFFF).unwrap_or(0);
        let hi = u32::try_from((w >> 32) & 0xFFFF_FFFF).unwrap_or(0);
        out.push(lo);
        out.push(hi);
    }
    while out.last() == Some(&0) {
        out.pop();
    }
    out
}

/// Convert a `u64` known to have at most 53 significant bits into the
/// exact `f64` with that value. No `as` cast: assemble the IEEE-754
/// bit pattern directly (or return 0 for an all-zero input).
fn f64_from_u64(x: u64) -> f64 {
    if x == 0 {
        return 0.0;
    }
    // bitpos of the most significant set bit (0-based).
    let msb = 63 - x.leading_zeros();
    // Mantissa: 52 fraction bits below the implicit leading 1.
    let frac = if msb >= 52 {
        (x >> (msb - 52)) & ((1u64 << 52) - 1)
    } else {
        (x << (52 - msb)) & ((1u64 << 52) - 1)
    };
    // Biased exponent = msb + 1023.
    let exp = u64::from(msb) + 1023;
    f64::from_bits((exp << 52) | frac)
}

/// Round a non-zero magnitude (little-endian u32 limbs) to the nearest
/// `f64`, ties-to-even, and report whether the rounded value is `Below`
/// or `Above` the true magnitude (or `Exact`). The magnitude is assumed
/// to exceed the 53-bit fast path, so the result is always > 0 and the
/// exponent is well within the normal f64 range for any practical Int.
fn round_limbs_to_f64(abs: &[u32]) -> (f64, Accuracy) {
    let n = bit_len(abs); // > 53 here
    // Take the top 54 bits: 53 to keep plus 1 guard bit.
    let drop = n - 54; // number of low bits discarded (>= 0)
    let top54 = extract_high_bits(abs, drop, 54);
    let guard = top54 & 1;
    let mut keep = top54 >> 1; // 53 bits
    // Sticky: any set bit strictly below the guard bit.
    let sticky = !low_bits_all_zero(abs, drop);
    let mut acc = Accuracy::Exact;
    if guard == 1 {
        if sticky || (keep & 1) == 1 {
            // Round up (ties-to-even rounds the odd mantissa up).
            keep += 1;
            acc = Accuracy::Above;
        } else {
            // Exact tie to an even mantissa: truncates downward.
            acc = Accuracy::Below;
        }
    } else if guard == 0 && sticky {
        acc = Accuracy::Below;
    }
    // keep now holds 53 or 54 bits (54 if the round-up carried out).
    let mut exp_of_keep = drop + 1; // weight of keep's bit 0
    let mut keep_bits = 64 - keep.leading_zeros();
    if keep_bits > 53 {
        // Carry-out grew the mantissa; shift back to 53 significant bits.
        keep >>= 1;
        exp_of_keep += 1;
        keep_bits = 64 - keep.leading_zeros();
    }
    // Assemble IEEE-754: value = keep * 2^exp_of_keep.
    let msb = keep_bits - 1; // 0-based index of keep's top bit
    let frac = if msb >= 52 {
        (keep >> (u64::from(msb) - 52)) & ((1u64 << 52) - 1)
    } else {
        (keep << (52 - u64::from(msb))) & ((1u64 << 52) - 1)
    };
    // Unbiased exponent of the value = exp_of_keep + msb.
    let unbiased = exp_of_keep + int::from(msb);
    let biased = unbiased + 1023;
    let bits = (u64::try_from(biased).unwrap_or(0) << 52) | frac;
    (f64::from_bits(bits), acc)
}

/// Extract `width` bits from a little-endian u32 magnitude, starting at
/// bit index `start` (LSB = 0), as a `u64` (width must be <= 64).
fn extract_high_bits(abs: &[u32], start: int, width: int) -> u64 {
    let mut out: u64 = 0;
    let mut produced: int = 0;
    while produced < width {
        let bit = start + produced;
        if bit < 0 {
            produced += 1;
            continue;
        }
        let limb = (bit / 32) as usize;
        let off = (bit % 32) as u32;
        let b = if limb < abs.len() {
            u64::from((abs[limb] >> off) & 1)
        } else {
            0
        };
        out |= b << produced;
        produced += 1;
    }
    out
}

/// Reports whether every bit strictly below bit index `below` of a
/// little-endian u32 magnitude is zero.
fn low_bits_all_zero(abs: &[u32], below: int) -> bool {
    if below <= 0 {
        return true;
    }
    let full = (below / 32) as usize;
    for &limb in abs.iter().take(full.min(abs.len())) {
        if limb != 0 {
            return false;
        }
    }
    let rem = (below % 32) as u32;
    if rem > 0 && full < abs.len() {
        let mask = (1u32 << rem) - 1;
        if abs[full] & mask != 0 {
            return false;
        }
    }
    true
}

/// Count of consecutive least-significant zero bits of a magnitude.
fn trailing_zero_bits(a: &[u32]) -> crate::types::uint {
    if a.is_empty() {
        return 0;
    }
    let mut i = 0usize;
    while i < a.len() && a[i] == 0 {
        i += 1;
    }
    if i == a.len() {
        return 0; // all-zero magnitude (not normalized) — treat as 0
    }
    (i as u64) * 32 + a[i].trailing_zeros() as u64
}

/// Value of bit `i` (lsb == bit 0) of a magnitude.
fn limb_bit(a: &[u32], i: u64) -> crate::types::uint {
    let j = (i / 32) as usize;
    if j >= a.len() {
        return 0;
    }
    ((a[j] >> (i % 32)) & 1) as crate::types::uint
}

/// Magnitude `a` with bit `i` set to `b` (0 or 1). Result is trimmed.
fn limb_set_bit(a: &[u32], i: u64, b: crate::types::uint) -> Vec<u32> {
    let j = (i / 32) as usize;
    let m: u32 = 1u32 << (i % 32);
    let mut z = a.to_vec();
    if b == 0 {
        if j < z.len() {
            z[j] &= !m;
        }
    } else {
        if j >= z.len() {
            z.resize(j + 1, 0);
        }
        z[j] |= m;
    }
    trim(z)
}

/// Magnitude left shift: `x << s` bits. Result is trimmed.
fn lsh_limbs(x: &[u32], s: u64) -> Vec<u32> {
    if x.is_empty() {
        return Vec::new();
    }
    let limb_shift = (s / 32) as usize;
    let bit_shift = (s % 32) as u32;
    let shifted = if bit_shift == 0 {
        x.to_vec()
    } else {
        shl_small(x, bit_shift)
    };
    if limb_shift == 0 {
        return trim(shifted);
    }
    let mut out = alloc::vec![0u32; limb_shift];
    out.extend_from_slice(&shifted);
    trim(out)
}

/// Magnitude right shift: `x >> s` bits. Result is trimmed.
fn rsh_limbs(x: &[u32], s: u64) -> Vec<u32> {
    if x.is_empty() {
        return Vec::new();
    }
    let limb_shift = (s / 32) as usize;
    let bit_shift = (s % 32) as u32;
    if limb_shift >= x.len() {
        return Vec::new();
    }
    let dropped = &x[limb_shift..];
    let out = if bit_shift == 0 {
        dropped.to_vec()
    } else {
        shr_small(dropped, bit_shift)
    };
    trim(out)
}

/// Bitwise AND of two magnitudes. Result is trimmed.
fn and_limbs(x: &[u32], y: &[u32]) -> Vec<u32> {
    let m = x.len().min(y.len());
    let mut z = alloc::vec![0u32; m];
    for i in 0..m {
        z[i] = x[i] & y[i];
    }
    trim(z)
}

/// Bitwise AND-NOT of two magnitudes: `x &^ y`. Result is trimmed.
fn and_not_limbs(x: &[u32], y: &[u32]) -> Vec<u32> {
    let m = x.len();
    let n = y.len().min(m);
    let mut z = alloc::vec![0u32; m];
    for i in 0..n {
        z[i] = x[i] & !y[i];
    }
    z[n..m].copy_from_slice(&x[n..m]);
    trim(z)
}

/// Bitwise OR of two magnitudes. Result is trimmed.
fn or_limbs(x: &[u32], y: &[u32]) -> Vec<u32> {
    let (short, long) = if x.len() < y.len() { (x, y) } else { (y, x) };
    let n = short.len();
    let mut z = long.to_vec();
    for i in 0..n {
        z[i] = x[i] | y[i];
    }
    trim(z)
}

/// Bitwise XOR of two magnitudes. Result is trimmed.
fn xor_limbs(x: &[u32], y: &[u32]) -> Vec<u32> {
    let (short, long) = if x.len() < y.len() { (x, y) } else { (y, x) };
    let n = short.len();
    let mut z = long.to_vec();
    for i in 0..n {
        z[i] = x[i] ^ y[i];
    }
    trim(z)
}

/// Signed addition: a + b respecting signs.
fn add_signed(a: &Int, b: &Int) -> Int {
    if a.neg == b.neg {
        Int { neg: a.neg && !(a.abs.is_empty() && b.abs.is_empty()), abs: add_limbs(&a.abs, &b.abs) }
    } else {
        // Different signs: subtract smaller magnitude from larger.
        match abs_cmp(&a.abs, &b.abs) {
            Ordering::Equal => Int { neg: false, abs: Vec::new() },
            Ordering::Greater => Int { neg: a.neg, abs: sub_limbs(&a.abs, &b.abs) },
            Ordering::Less => Int { neg: b.neg, abs: sub_limbs(&b.abs, &a.abs) },
        }
    }
}

// ═══ big.Float — arbitrary-precision binary floating point ═══════════
//
// Go reference: math/big/float.go. This is Float-task 1 of 3: the type,
// its core (non-arithmetic) surface, and the internal `round` /
// normalization helpers that the later arithmetic task builds on.
// Add/Sub/Mul/Quo/Sqrt and Text/Parse/conversions are deliberately NOT
// implemented here.

/// Internal representation tag for a `Float` value (Go's unexported
/// `form` enum). The order — `Zero < Finite < Inf` — is meaningful in
/// Go; we keep an explicit discriminant for clarity.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[allow(non_camel_case_types)]
enum form {
    /// `±0` — mantissa and exponent are ignored.
    Zero,
    /// `0 < |x| < +Inf` — mantissa and exponent are significant.
    Finite,
    /// `±Inf` — mantissa and exponent are ignored.
    Inf,
}

/// `big.RoundingMode` — how a [`Float`] result is rounded to its target
/// precision. The zero value (and `Default`) is `ToNearestEven`,
/// matching Go.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RoundingMode {
    /// IEEE 754-2008 roundTiesToEven.
    ToNearestEven,
    /// IEEE 754-2008 roundTiesToAway.
    ToNearestAway,
    /// IEEE 754-2008 roundTowardZero.
    ToZero,
    /// No IEEE 754-2008 equivalent — always rounds the magnitude up.
    AwayFromZero,
    /// IEEE 754-2008 roundTowardNegative.
    ToNegativeInf,
    /// IEEE 754-2008 roundTowardPositive.
    ToPositiveInf,
}

impl Default for RoundingMode {
    fn default() -> Self {
        RoundingMode::ToNearestEven
    }
}

impl crate::fmt::Stringer for RoundingMode {
    fn String(&self) -> crate::gostring::string {
        crate::gostring::string::from(match self {
            RoundingMode::ToNearestEven => "ToNearestEven",
            RoundingMode::ToNearestAway => "ToNearestAway",
            RoundingMode::ToZero => "ToZero",
            RoundingMode::AwayFromZero => "AwayFromZero",
            RoundingMode::ToNegativeInf => "ToNegativeInf",
            RoundingMode::ToPositiveInf => "ToPositiveInf",
        })
    }
}

/// Limb width of a `Float` mantissa in bits. Go's `nat` uses 64-bit
/// words (`_W`); the goish `big` module uses 32-bit limbs throughout
/// (`Int`, `Rat`), so `Float` follows suit for easy Int↔Float bridging.
const FW: u32 = 32;

/// `big.Float` — a multi-precision binary floating-point number.
///
/// A nonzero finite value represents
///
/// ```text
///   x = (-1)^neg · mant · 2^exp
/// ```
///
/// where `mant` (the [`Float::mant`] limbs interpreted as a fraction —
/// `mant / 2^(limbs·32)`) is **normalized** into `[0.5, 1)`: the most
/// significant bit of the most-significant limb is set. `exp` is the
/// binary exponent. A `Float` may also be `±0` or `±Inf` (see [`form`]),
/// in which case `mant` and `exp` are ignored.
///
/// Each value carries a `prec` (max mantissa bits), a [`RoundingMode`],
/// and an [`Accuracy`] describing the error of the most recent result.
///
/// The zero value is `+0.0` exactly, with precision 0 and rounding mode
/// `ToNearestEven`, and is ready to use.
#[derive(Clone)]
pub struct Float {
    /// Maximum mantissa precision in bits (Go's `prec uint32`).
    prec: u32,
    /// Rounding mode applied when a result exceeds `prec` bits.
    mode: RoundingMode,
    /// Error of the most recent operation relative to the exact result.
    acc: Accuracy,
    /// Internal representation tag (`Zero` / `Finite` / `Inf`).
    form: form,
    /// Sign bit — `true` for negative (incl. `-0` and `-Inf`).
    neg: bool,
    /// Mantissa limbs, little-endian u32, msb-normalized when `Finite`.
    mant: Vec<u32>,
    /// Binary exponent (Go's `exp int32`).
    exp: i32,
}

/// `big.MaxExp` — largest supported `Float` exponent.
pub const MaxExp: int = i32::MAX as int;
/// `big.MinExp` — smallest supported `Float` exponent.
pub const MinExp: int = i32::MIN as int;
/// `big.MaxPrec` — largest (theoretically) supported precision.
pub const MaxPrec: crate::types::uint = u32::MAX as crate::types::uint;

/// `big.ErrNaN` — the panic value raised by a [`Float`] operation that
/// would produce a NaN under IEEE 754 rules (e.g. `(+Inf) + (-Inf)`,
/// `0 · Inf`, `0 / 0`, `√(negative)`). It implements the goish `error`
/// interface via [`crate::errors::ErrorTrait`].
///
/// goish's `panic!` does not carry a typed payload in `no_std`, so the
/// arithmetic ops `panic!` with the exact Go message text; this type
/// exists so callers can still construct/inspect an `ErrNaN` value and
/// lift it into an `error`.
#[derive(Clone)]
pub struct ErrNaN {
    msg: crate::string,
}

impl ErrNaN {
    /// Build an `ErrNaN` carrying `msg`.
    pub fn new<S: Into<crate::string>>(msg: S) -> Self {
        ErrNaN { msg: msg.into() }
    }
}

impl crate::errors::ErrorTrait for ErrNaN {
    fn Error(&self) -> crate::string {
        self.msg.clone()
    }
}

impl Default for Float {
    /// The zero value: `+0.0`, precision 0, mode `ToNearestEven`.
    fn default() -> Self {
        Float {
            prec: 0,
            mode: RoundingMode::ToNearestEven,
            acc: Accuracy::Exact,
            form: form::Zero,
            neg: false,
            mant: Vec::new(),
            exp: 0,
        }
    }
}

/// `makeAcc` — `Above` if `above`, else `Below`. Used by `round` and
/// the setters to record the direction of an inexact result.
fn make_acc(above: bool) -> Accuracy {
    if above {
        Accuracy::Above
    } else {
        Accuracy::Below
    }
}

/// `fnorm` — normalize mantissa `m` in place by shifting it left so the
/// msb of its most-significant limb is 1, and return the shift amount.
/// Assumes `m` is non-empty and its top limb is nonzero. The mantissa
/// width (`len·32`) is unchanged; only the bits move.
fn fnorm(m: &mut [u32]) -> i64 {
    debug_assert!(!m.is_empty() && *m.last().unwrap() != 0);
    let s = m.last().unwrap().leading_zeros();
    if s > 0 {
        // Left-shift the whole limb slice by `s` bits, in place.
        let n = m.len();
        let mut carry: u32 = 0;
        for i in 0..n {
            let v = m[i];
            m[i] = (v << s) | carry;
            carry = v >> (FW - s);
        }
        debug_assert!(carry == 0, "fnorm carry must be zero");
    }
    i64::from(s)
}

/// `addVW` analogue — add the single limb `v` into the least-significant
/// end of `m` (in place). Returns the final carry out of the top limb.
fn float_add_vw(m: &mut [u32], v: u32) -> u32 {
    let mut carry = u64::from(v);
    for limb in m.iter_mut() {
        let t = u64::from(*limb) + carry;
        *limb = t as u32;
        carry = t >> FW;
    }
    carry as u32
}

/// `rshVU` analogue — shift `m` right by `s` bits in place
/// (`0 < s < 32`). The bits shifted out at the bottom are discarded.
fn float_rsh(m: &mut [u32], s: u32) {
    debug_assert!(s > 0 && s < FW);
    let n = m.len();
    let mut carry: u32 = 0;
    for i in (0..n).rev() {
        let v = m[i];
        m[i] = (v >> s) | carry;
        carry = v << (FW - s);
    }
}

/// `nat.sticky(i)` analogue — 1 if any of the lowest `i` bits of the
/// msb-normalized mantissa `m` is set, else 0.
fn float_sticky(m: &[u32], i: u32) -> u32 {
    let words = (i / FW) as usize;
    if words >= m.len() {
        // All limbs lie entirely within the low `i` bits.
        for limb in m {
            if *limb != 0 {
                return 1;
            }
        }
        return 0;
    }
    for limb in &m[..words] {
        if *limb != 0 {
            return 1;
        }
    }
    let rem = i % FW;
    if rem != 0 && (m[words] & ((1u32 << rem) - 1)) != 0 {
        return 1;
    }
    0
}

/// `nat.bit(i)` analogue — value of bit `i` of the mantissa limbs.
fn float_bit(m: &[u32], i: u32) -> u32 {
    let w = (i / FW) as usize;
    if w >= m.len() {
        return 0;
    }
    (m[w] >> (i % FW)) & 1
}

/// `msb32` analogue — the 32 most-significant bits of the msb-normalized
/// mantissa `m` (i.e. its top limb). 0 for an empty mantissa.
fn msb32(m: &[u32]) -> u32 {
    match m.last() {
        Some(&w) => w,
        None => 0,
    }
}

/// `msb64` analogue — the 64 most-significant bits of the msb-normalized
/// mantissa `m`: the top limb shifted into the high half, OR'd with the
/// next limb (if any) in the low half. 0 for an empty mantissa.
fn msb64(m: &[u32]) -> u64 {
    let n = m.len();
    if n == 0 {
        return 0;
    }
    let mut v = u64::from(m[n - 1]) << 32;
    if n > 1 {
        v |= u64::from(m[n - 2]);
    }
    v
}

impl Float {
    /// `var z big.Float` — fresh zero-valued `Float` (`+0.0`).
    pub fn new() -> Self {
        Float::default()
    }

    // ─── internal: round / setExpAndRound ────────────────────────────

    /// `(*Float).round(sbit)` — round `self` to `self.prec` mantissa
    /// bits under `self.mode`, set `self.acc`, and (on mantissa
    /// overflow) bump `self.exp`. `sbit` is the incoming sticky bit
    /// (0 or 1). The mantissa must be msb-normalized or empty, and
    /// `self.neg` must already be correct (the directed modes depend
    /// on the sign). Used by every rounding setter and, later, by the
    /// arithmetic ops.
    fn round(&mut self, sbit_in: u32) {
        self.acc = Accuracy::Exact;
        if self.form != form::Finite {
            // ±0 or ±Inf — nothing to round.
            return;
        }

        let m = self.mant.len() as u32; // present mantissa length in limbs
        let bits = m * FW; // present mantissa bits; > 0
        if bits <= self.prec {
            // Mantissa fits — nothing to do.
            return;
        }
        // bits > self.prec: mantissa too large => round.

        // r = position of the rounding bit (the "0.5" bit just below
        // the kept prec leading bits).
        let r = bits - self.prec - 1;
        let rbit = float_bit(&self.mant, r) & 1;
        // The sticky bit is only needed for ToNearestEven, or when the
        // rounding bit is zero — skip the scan otherwise.
        let mut sbit = sbit_in;
        if sbit == 0 && (rbit == 0 || self.mode == RoundingMode::ToNearestEven) {
            sbit = float_sticky(&self.mant, r);
        }
        sbit &= 1;

        // Cut off extra limbs: keep the `n` most-significant ones.
        let n = (self.prec + (FW - 1)) / FW;
        if m > n {
            let drop = (m - n) as usize;
            self.mant.drain(0..drop);
        }

        // Trailing-zero-bit count of the kept mantissa's lsb limb.
        let ntz = n * FW - self.prec; // 0 <= ntz < 32
        let lsb: u32 = 1u32 << ntz;

        if rbit | sbit != 0 {
            // Result is inexact. Default is truncation ("round down");
            // decide whether to increment the magnitude instead.
            let inc = match self.mode {
                RoundingMode::ToNegativeInf => self.neg,
                RoundingMode::ToZero => false,
                RoundingMode::ToNearestEven => {
                    rbit != 0 && (sbit != 0 || self.mant[0] & lsb != 0)
                }
                RoundingMode::ToNearestAway => rbit != 0,
                RoundingMode::AwayFromZero => true,
                RoundingMode::ToPositiveInf => !self.neg,
            };

            // A positive (!neg) result is Above if incremented, Below
            // if truncated; for a negative result it is the opposite.
            self.acc = make_acc(inc != self.neg);

            if inc {
                if float_add_vw(&mut self.mant, lsb) != 0 {
                    // Mantissa overflow => bump exponent, halve mantissa.
                    if self.exp >= MaxExp as i32 {
                        self.form = form::Inf;
                        return;
                    }
                    self.exp += 1;
                    float_rsh(&mut self.mant, 1);
                    // Re-set the msb dropped in by the carry.
                    let top = (n as usize) - 1;
                    self.mant[top] |= 1u32 << (FW - 1);
                }
            }
        }

        // Zero out the trailing (sub-precision) bits of the lsb limb.
        self.mant[0] &= !(lsb - 1);
    }

    /// `(*Float).setExpAndRound` — set `self` finite with binary
    /// exponent `exp`, handling under/overflow, then round. Internal
    /// helper shared by the (future) arithmetic ops and `SetMantExp`.
    fn set_exp_and_round(&mut self, exp: i64, sbit: u32) {
        if exp < MinExp as i64 {
            // Underflow to ±0.
            self.acc = make_acc(self.neg);
            self.form = form::Zero;
            return;
        }
        if exp > MaxExp as i64 {
            // Overflow to ±Inf.
            self.acc = make_acc(!self.neg);
            self.form = form::Inf;
            return;
        }
        self.form = form::Finite;
        self.exp = exp as i32;
        self.round(sbit);
    }

    /// `setBits64` — shared body of `SetInt64` / `SetUint64`. Sets
    /// `self` to `(-1)^neg · x`, defaulting precision to 64.
    fn set_bits64(&mut self, neg: bool, x: u64) -> &mut Self {
        if self.prec == 0 {
            self.prec = 64;
        }
        self.acc = Accuracy::Exact;
        self.neg = neg;
        if x == 0 {
            self.form = form::Zero;
            return self;
        }
        self.form = form::Finite;
        // Normalize: shift so the msb of x lands at bit 63.
        let s = x.leading_zeros();
        let v = x << s;
        // Mantissa is the two 32-bit limbs of the normalized 64-bit value.
        self.mant = alloc::vec![v as u32, (v >> 32) as u32];
        self.exp = 64 - s as i32; // always fits an i32
        if self.prec < 64 {
            self.round(0);
        }
        self
    }

    // ─── constructors / setters ──────────────────────────────────────

    /// `(*Float).SetUint64(x)` — set `self` to `x`. If precision is 0,
    /// it is changed to 64 (so rounding has no effect).
    pub fn SetUint64(&mut self, x: u64) -> &mut Self {
        self.set_bits64(false, x)
    }

    /// `(*Float).SetInt64(x)` — set `self` to `x`. If precision is 0,
    /// it is changed to 64 (so rounding has no effect).
    pub fn SetInt64(&mut self, x: i64) -> &mut Self {
        let u = (x as i128).unsigned_abs() as u64;
        // The sign affects rounding, so it must be set before set_bits64.
        self.set_bits64(x < 0, u)
    }

    /// `(*Float).SetFloat64(x)` — set `self` to the exact value of the
    /// f64 `x`. If precision is 0, it is changed to 53. Panics if `x`
    /// is a NaN, matching Go's `ErrNaN`.
    pub fn SetFloat64(&mut self, x: crate::types::float64) -> &mut Self {
        if self.prec == 0 {
            self.prec = 53;
        }
        if x.is_nan() {
            panic!("big::Float::SetFloat64(NaN)");
        }
        self.acc = Accuracy::Exact;
        let bits = x.to_bits();
        self.neg = bits >> 63 == 1; // handles -0 / -Inf
        if x == 0.0 {
            self.form = form::Zero;
            return self;
        }
        if x.is_infinite() {
            self.form = form::Inf;
            return self;
        }
        // Finite nonzero: decompose the IEEE-754 fields.
        let raw_exp = ((bits >> 52) & 0x7ff) as i64;
        let frac = bits & ((1u64 << 52) - 1);
        let (sig, e) = if raw_exp == 0 {
            // Subnormal: value = frac · 2^(-1074), no implicit 1 bit.
            // Shift the msb of frac up to bit 63; as a fraction /2^64
            // the binary exponent is then -1074 - s + 64.
            let s = frac.leading_zeros();
            (frac << s, -1074 - i64::from(s) + 64)
        } else {
            // Normal: value = (1<<52 | frac) · 2^(raw_exp-1075).
            // sig has its msb at bit 52; shifting up to bit 63 (<<11)
            // and reading as a fraction /2^64 gives exp = raw_exp-1022.
            let sig = (1u64 << 52) | frac;
            (sig << 11, raw_exp - 1022)
        };
        self.form = form::Finite;
        self.mant = alloc::vec![sig as u32, (sig >> 32) as u32];
        self.exp = e as i32; // always fits an i32
        if self.prec < 53 {
            self.round(0);
        }
        self
    }

    /// `(*Float).SetInt(x)` — set `self` to the value of the [`Int`]
    /// `x`. If precision is 0, it is changed to `max(x.BitLen(), 64)`.
    pub fn SetInt<X: AsRef<Int>>(&mut self, x: X) -> &mut Self {
        let xi = x.as_ref();
        let bits = bit_len(&xi.abs) as i64;
        if self.prec == 0 {
            let want = if bits > 64 { bits } else { 64 };
            self.prec = want as u32;
        }
        self.acc = Accuracy::Exact;
        self.neg = xi.neg;
        if xi.abs.is_empty() {
            self.form = form::Zero;
            return self;
        }
        // Mantissa = |x|'s limbs, then msb-normalized.
        let mut mant = xi.abs.clone();
        // Drop any (already-absent) trailing zero limbs defensively.
        while mant.len() > 1 && *mant.last().unwrap() == 0 {
            mant.pop();
        }
        fnorm(&mut mant);
        self.mant = mant;
        self.set_exp_and_round(bits, 0);
        self
    }

    /// `(*Float).SetPrec(prec)` — set the mantissa precision to `prec`
    /// and round `self` to fit. `SetPrec(0)` maps all finite values to
    /// `±0`; infinities are unchanged. `prec` is capped at `MaxPrec`.
    pub fn SetPrec(&mut self, prec: crate::types::uint) -> &mut Self {
        self.acc = Accuracy::Exact; // optimistically

        if prec == 0 {
            self.prec = 0;
            if self.form == form::Finite {
                self.acc = make_acc(self.neg);
                self.form = form::Zero;
            }
            return self;
        }

        let prec = if prec > MaxPrec { MaxPrec } else { prec };
        let old = self.prec;
        self.prec = prec as u32;
        if self.prec < old {
            self.round(0);
        }
        self
    }

    /// `(*Float).SetMode(mode)` — set the rounding mode and return an
    /// `Exact` `self`. `z.SetMode(z.Mode())` is a cheap way to reset
    /// accuracy to `Exact`.
    pub fn SetMode(&mut self, mode: RoundingMode) -> &mut Self {
        self.mode = mode;
        self.acc = Accuracy::Exact;
        self
    }

    /// `(*Float).SetInf(signbit)` — set `self` to `-Inf` if `signbit`,
    /// else `+Inf`. Precision is unchanged; the result is `Exact`.
    pub fn SetInf(&mut self, signbit: bool) -> &mut Self {
        self.acc = Accuracy::Exact;
        self.form = form::Inf;
        self.neg = signbit;
        self
    }

    /// `(*Float).Set(x)` — set `self` to the (possibly rounded) value
    /// of `x`. If `self`'s precision is 0, it adopts `x`'s precision
    /// (and rounding has no effect); otherwise the result is rounded
    /// to `self`'s precision and mode, and `self.acc` reports the error.
    pub fn Set<X: AsRef<Float>>(&mut self, x: X) -> &mut Self {
        let x = x.as_ref();
        self.acc = Accuracy::Exact;
        self.form = x.form;
        self.neg = x.neg;
        if x.form == form::Finite {
            self.exp = x.exp;
            self.mant = x.mant.clone();
        }
        if self.prec == 0 {
            self.prec = x.prec;
        } else if self.prec < x.prec {
            self.round(0);
        }
        self
    }

    /// `(*Float).Copy(x)` — set `self` to `x` with the *same*
    /// precision, rounding mode, and accuracy. No rounding occurs.
    pub fn Copy(&mut self, x: &Float) -> &mut Self {
        self.prec = x.prec;
        self.mode = x.mode;
        self.acc = x.acc;
        self.form = x.form;
        self.neg = x.neg;
        if self.form == form::Finite {
            self.mant = x.mant.clone();
            self.exp = x.exp;
        } else {
            self.mant = Vec::new();
            self.exp = 0;
        }
        self
    }

    /// `(*Float).SetMantExp(mant, exp)` — set `self` to
    /// `mant · 2^exp`. The result has `mant`'s precision and rounding
    /// mode. `±0`/`±Inf` are copied through unchanged. Inverse of
    /// [`Float::MantExp`].
    pub fn SetMantExp(&mut self, mant: &Float, exp: int) -> &mut Self {
        self.Copy(mant);
        if self.form == form::Finite {
            self.set_exp_and_round(i64::from(self.exp) + exp as i64, 0);
        }
        self
    }

    // ─── read-only / predicates ──────────────────────────────────────

    /// `(*Float).Sign()` — `-1` if `x < 0`, `0` if `x` is `±0`,
    /// `+1` if `x > 0`.
    pub fn Sign(&self) -> int {
        if self.form == form::Zero {
            return 0;
        }
        if self.neg {
            -1
        } else {
            1
        }
    }

    /// `(*Float).Signbit()` — whether `x` is negative (incl. `-0`).
    pub fn Signbit(&self) -> bool {
        self.neg
    }

    /// `(*Float).IsInf()` — whether `x` is `+Inf` or `-Inf`.
    pub fn IsInf(&self) -> bool {
        self.form == form::Inf
    }

    /// `(*Float).IsInt()` — whether `x` is an integer. `±Inf` is not an
    /// integer; `±0` is.
    pub fn IsInt(&self) -> bool {
        if self.form != form::Finite {
            return self.form == form::Zero;
        }
        if self.exp <= 0 {
            return false;
        }
        // exp > 0: integer if the value has no fractional mantissa bits.
        self.prec <= self.exp as u32 || self.MinPrec() <= self.exp as crate::types::uint
    }

    /// `(*Float).Prec()` — mantissa precision in bits. May be 0 for
    /// `|x| == 0` or `|x| == Inf`.
    pub fn Prec(&self) -> crate::types::uint {
        self.prec as crate::types::uint
    }

    /// `(*Float).MinPrec()` — minimum precision needed to represent `x`
    /// exactly (the smallest `prec` before `SetPrec` would round). 0
    /// for `|x| == 0` or `|x| == Inf`.
    pub fn MinPrec(&self) -> crate::types::uint {
        if self.form != form::Finite {
            return 0;
        }
        (self.mant.len() as u64) * u64::from(FW) - trailing_zero_bits(&self.mant)
    }

    /// `(*Float).Mode()` — the rounding mode of `x`.
    pub fn Mode(&self) -> RoundingMode {
        self.mode
    }

    /// `(*Float).Acc()` — the accuracy produced by the most recent
    /// operation on `x`.
    pub fn Acc(&self) -> Accuracy {
        self.acc
    }

    /// `ord` — classify `x`: `-2` `-Inf`, `-1` negative finite, `0`
    /// `±0`, `+1` positive finite, `+2` `+Inf`.
    fn ord(&self) -> int {
        let m = match self.form {
            form::Finite => 1,
            form::Zero => return 0,
            form::Inf => 2,
        };
        if self.neg {
            -m
        } else {
            m
        }
    }

    /// `ucmp` — compare magnitudes of two finite `Float`s: `-1`/`0`/`+1`
    /// for `|self| < / == / > |y|`.
    fn ucmp(&self, y: &Float) -> int {
        if self.exp < y.exp {
            return -1;
        }
        if self.exp > y.exp {
            return 1;
        }
        // Equal exponents — compare mantissa limbs, most-significant first.
        let mut i = self.mant.len();
        let mut j = y.mant.len();
        while i > 0 || j > 0 {
            let xm = if i > 0 {
                i -= 1;
                self.mant[i]
            } else {
                0
            };
            let ym = if j > 0 {
                j -= 1;
                y.mant[j]
            } else {
                0
            };
            if xm < ym {
                return -1;
            }
            if xm > ym {
                return 1;
            }
        }
        0
    }

    /// `(*Float).Cmp(y)` — `-1` if `x < y`, `0` if `x == y` (incl.
    /// `-0 == 0`, `-Inf == -Inf`, `+Inf == +Inf`), `+1` if `x > y`.
    pub fn Cmp(&self, y: &Float) -> int {
        let mx = self.ord();
        let my = y.ord();
        if mx < my {
            return -1;
        }
        if mx > my {
            return 1;
        }
        // mx == my — only the ±finite case needs a mantissa compare.
        match mx {
            -1 => y.ucmp(self),
            1 => self.ucmp(y),
            _ => 0,
        }
    }

    /// `(*Float).MantExp(mant)` — break `x` into mantissa and exponent,
    /// returning the exponent. If `mant` is non-nil it is set to the
    /// mantissa of `x` (same precision and mode as `x`), normalized so
    /// `0.5 <= |mant| < 1.0`; `x == mant · 2^exp`. Passing `nil` is an
    /// efficient way to read just the exponent.
    ///
    /// Special cases: `(±0).MantExp(m)` and `(±Inf).MantExp(m)` both
    /// return `0` with `m` set to `±0` / `±Inf`.
    pub fn MantExp<M: MaybeMutFloat>(&self, mut mant: M) -> int {
        let exp = if self.form == form::Finite {
            self.exp as int
        } else {
            0
        };
        if let Some(m) = mant.maybe_mut_float() {
            m.Copy(self);
            if m.form == form::Finite {
                m.exp = 0;
            }
        }
        exp
    }

    // ─── numeric conversions ─────────────────────────────────────────
    //
    // Go reference: math/big/float.go — `Float32`, `Float64`, `Int64`,
    // `Uint64`, `Int`, `Rat`, `SetRat`. Each conversion reports an
    // `Accuracy` describing the error relative to the exact value of
    // `self`. `Float32`/`Float64` round to nearest (with overflow to
    // `±Inf` and underflow to `±0`); `Int64`/`Uint64`/`Int` truncate
    // toward zero; `Rat` is always exact for a finite value.

    /// `(*Float).Uint64()` — the unsigned integer obtained by truncating
    /// `self` toward zero. For `0 <= x <= MaxUint64` the result is
    /// `Exact` if `x` is an integer and `Below` otherwise. The result is
    /// `(0, Above)` for `x < 0` and `(MaxUint64, Below)` for
    /// `x > MaxUint64`.
    pub fn Uint64(&self) -> (u64, Accuracy) {
        match self.form {
            form::Finite => {
                if self.neg {
                    return (0, Accuracy::Above);
                }
                // 0 < x < +Inf
                if self.exp <= 0 {
                    // 0 < x < 1
                    return (0, Accuracy::Below);
                }
                // 1 <= x < +Inf
                if self.exp <= 64 {
                    // u = trunc(x) fits into a u64.
                    let u = msb64(&self.mant) >> (64 - self.exp as u32);
                    if self.MinPrec() <= 64 {
                        return (u, Accuracy::Exact);
                    }
                    return (u, Accuracy::Below); // x truncated
                }
                // x too large
                (u64::MAX, Accuracy::Below)
            }
            form::Zero => (0, Accuracy::Exact),
            form::Inf => {
                if self.neg {
                    (0, Accuracy::Above)
                } else {
                    (u64::MAX, Accuracy::Below)
                }
            }
        }
    }

    /// `(*Float).Int64()` — the integer obtained by truncating `self`
    /// toward zero. For `MinInt64 <= x <= MaxInt64` the result is
    /// `Exact` if `x` is an integer, and `Above` (`x < 0`) or `Below`
    /// (`x > 0`) otherwise. The result saturates to `(MinInt64, Above)`
    /// for `x < MinInt64` and `(MaxInt64, Below)` for `x > MaxInt64`.
    pub fn Int64(&self) -> (i64, Accuracy) {
        match self.form {
            form::Finite => {
                // 0 < |x| < +Inf
                let acc = make_acc(self.neg);
                if self.exp <= 0 {
                    // 0 < |x| < 1
                    return (0, acc);
                }
                // exp > 0: 1 <= |x| < +Inf
                if self.exp <= 63 {
                    // i = trunc(x) fits into an i64 (excluding MinInt64).
                    let mag = msb64(&self.mant) >> (64 - self.exp as u32);
                    let i = if self.neg {
                        -(mag as i64)
                    } else {
                        mag as i64
                    };
                    if self.MinPrec() <= self.exp as crate::types::uint {
                        return (i, Accuracy::Exact);
                    }
                    return (i, acc); // x truncated
                }
                if self.neg {
                    // Special case x == MinInt64 (i.e. x == -(0.5 << 64)).
                    let acc = if self.exp == 64 && self.MinPrec() == 1 {
                        Accuracy::Exact
                    } else {
                        acc
                    };
                    return (i64::MIN, acc);
                }
                // x too large
                (i64::MAX, Accuracy::Below)
            }
            form::Zero => (0, Accuracy::Exact),
            form::Inf => {
                if self.neg {
                    (i64::MIN, Accuracy::Above)
                } else {
                    (i64::MAX, Accuracy::Below)
                }
            }
        }
    }

    /// `(*Float).Float32()` — the `f32` nearest to `self`. If `|x|` is
    /// too small to represent (`|x| < SmallestNonzeroFloat32`) the
    /// result is `(0, Below)` or `(-0, Above)`; if `|x|` is too large
    /// (`|x| > MaxFloat32`) it is `(+Inf, Above)` or `(-Inf, Below)`.
    pub fn Float32(&self) -> (crate::types::float32, Accuracy) {
        match self.form {
            form::Finite => {
                // 0 < |x| < +Inf
                const FBITS: i32 = 32; // float size
                const MBITS: i32 = 23; // mantissa size (excluding implicit msb)
                const EBITS: i32 = FBITS - MBITS - 1; // 8  exponent size
                const BIAS: i32 = (1 << (EBITS - 1)) - 1; // 127  exponent bias
                const EMIN: i32 = 1 - BIAS; // -126  smallest normal exponent
                const EMAX: i32 = BIAS; // 127  largest normal exponent
                const SMALLEST_NONZERO_F32: f32 = 1.401298464324817e-45;

                // Float mantissa m is 0.5 <= m < 1.0; e is the exponent
                // for the normal float32 mantissa with 1.0 <= m < 2.0.
                let mut e = self.exp - 1;

                // Precision p for the float32 mantissa.
                let mut p = MBITS + 1; // precision of a normal float
                if e < EMIN {
                    // Denormal before rounding — recompute precision.
                    p = MBITS + 1 - EMIN + e;
                    if p < 0
                        || p == 0
                            && float_sticky(&self.mant, (self.mant.len() as u32) * FW - 1) == 0
                    {
                        // underflow to ±0 (m <= 0.25, or m == 0.5 → even)
                        if self.neg {
                            return (-0.0f32, Accuracy::Above);
                        }
                        return (0.0f32, Accuracy::Below);
                    }
                    if p == 0 {
                        // m > 0.5 → round up to the smallest denormal.
                        if self.neg {
                            return (-SMALLEST_NONZERO_F32, Accuracy::Below);
                        }
                        return (SMALLEST_NONZERO_F32, Accuracy::Above);
                    }
                }
                // p > 0

                // Round a copy of self to p bits.
                let mut r = Float::default();
                r.prec = p as u32;
                r.Set(self);
                e = r.exp - 1;

                // Rounding may have overflowed r to ±Inf; or e too large.
                if r.form == form::Inf || e > EMAX {
                    if self.neg {
                        return (f32::NEG_INFINITY, Accuracy::Below);
                    }
                    return (f32::INFINITY, Accuracy::Above);
                }
                // e <= EMAX

                let mut sign: u32 = 0;
                if self.neg {
                    sign = 1 << (FBITS - 1);
                }
                let bexp: u32;
                let mant: u32;
                if e < EMIN {
                    // Denormal — recompute precision (p > 0 here).
                    p = MBITS + 1 - EMIN + e;
                    bexp = 0;
                    mant = msb32(&r.mant) >> (FBITS - p) as u32;
                } else {
                    // Normal: EMIN <= e <= EMAX.
                    bexp = ((e + BIAS) as u32) << MBITS;
                    mant = (msb32(&r.mant) >> EBITS as u32) & ((1u32 << MBITS) - 1);
                }
                (f32::from_bits(sign | bexp | mant), r.acc)
            }
            form::Zero => {
                if self.neg {
                    (-0.0f32, Accuracy::Exact)
                } else {
                    (0.0f32, Accuracy::Exact)
                }
            }
            form::Inf => {
                if self.neg {
                    (f32::NEG_INFINITY, Accuracy::Exact)
                } else {
                    (f32::INFINITY, Accuracy::Exact)
                }
            }
        }
    }

    /// `(*Float).Float64()` — the `f64` nearest to `self`. If `|x|` is
    /// too small to represent (`|x| < SmallestNonzeroFloat64`) the
    /// result is `(0, Below)` or `(-0, Above)`; if `|x|` is too large
    /// (`|x| > MaxFloat64`) it is `(+Inf, Above)` or `(-Inf, Below)`.
    pub fn Float64(&self) -> (crate::types::float64, Accuracy) {
        match self.form {
            form::Finite => {
                // 0 < |x| < +Inf
                const FBITS: i32 = 64; // float size
                const MBITS: i32 = 52; // mantissa size (excluding implicit msb)
                const EBITS: i32 = FBITS - MBITS - 1; // 11  exponent size
                const BIAS: i32 = (1 << (EBITS - 1)) - 1; // 1023  exponent bias
                const EMIN: i32 = 1 - BIAS; // -1022  smallest normal exponent
                const EMAX: i32 = BIAS; // 1023  largest normal exponent
                const SMALLEST_NONZERO_F64: f64 = 5e-324;

                // Float mantissa m is 0.5 <= m < 1.0; e is the exponent
                // for the normal float64 mantissa with 1.0 <= m < 2.0.
                let mut e = self.exp - 1;

                // Precision p for the float64 mantissa.
                let mut p = MBITS + 1; // precision of a normal float
                if e < EMIN {
                    // Denormal before rounding — recompute precision.
                    p = MBITS + 1 - EMIN + e;
                    if p < 0
                        || p == 0
                            && float_sticky(&self.mant, (self.mant.len() as u32) * FW - 1) == 0
                    {
                        // underflow to ±0 (m <= 0.25, or m == 0.5 → even)
                        if self.neg {
                            return (-0.0f64, Accuracy::Above);
                        }
                        return (0.0f64, Accuracy::Below);
                    }
                    if p == 0 {
                        // m > 0.5 → round up to the smallest denormal.
                        if self.neg {
                            return (-SMALLEST_NONZERO_F64, Accuracy::Below);
                        }
                        return (SMALLEST_NONZERO_F64, Accuracy::Above);
                    }
                }
                // p > 0

                // Round a copy of self to p bits.
                let mut r = Float::default();
                r.prec = p as u32;
                r.Set(self);
                e = r.exp - 1;

                // Rounding may have overflowed r to ±Inf; or e too large.
                if r.form == form::Inf || e > EMAX {
                    if self.neg {
                        return (f64::NEG_INFINITY, Accuracy::Below);
                    }
                    return (f64::INFINITY, Accuracy::Above);
                }
                // e <= EMAX

                let mut sign: u64 = 0;
                if self.neg {
                    sign = 1 << (FBITS - 1);
                }
                let bexp: u64;
                let mant: u64;
                if e < EMIN {
                    // Denormal — recompute precision (p > 0 here).
                    p = MBITS + 1 - EMIN + e;
                    bexp = 0;
                    mant = msb64(&r.mant) >> (FBITS - p) as u32;
                } else {
                    // Normal: EMIN <= e <= EMAX.
                    bexp = ((e + BIAS) as u64) << MBITS;
                    mant = (msb64(&r.mant) >> EBITS as u32) & ((1u64 << MBITS) - 1);
                }
                (f64::from_bits(sign | bexp | mant), r.acc)
            }
            form::Zero => {
                if self.neg {
                    (-0.0f64, Accuracy::Exact)
                } else {
                    (0.0f64, Accuracy::Exact)
                }
            }
            form::Inf => {
                if self.neg {
                    (f64::NEG_INFINITY, Accuracy::Exact)
                } else {
                    (f64::INFINITY, Accuracy::Exact)
                }
            }
        }
    }

    /// `(*Float).Int(z)` — the result of truncating `self` toward zero,
    /// as an [`Int`]. The accuracy is `Exact` if `self.IsInt()`, else
    /// `Below` for `x > 0` and `Above` for `x < 0`. If a non-nil `z` is
    /// provided the result is also stored into it; the owned `Int` in
    /// the returned tuple always carries the value. Panics if `self` is
    /// an infinity (Go returns `nil`; goish has no `*Int` so a panic is
    /// the faithful "no integer value" signal).
    pub fn Int<Z: MaybeMutInt>(&self, mut z: Z) -> (Int, Accuracy) {
        let (out, acc): (Int, Accuracy) = match self.form {
            form::Finite => {
                // 0 < |x| < +Inf
                let mut acc = make_acc(self.neg);
                if self.exp <= 0 {
                    // 0 < |x| < 1 → truncates to 0
                    (Int::default(), acc)
                } else {
                    // exp > 0: 1 <= |x| < +Inf
                    let all_bits = (self.mant.len() as crate::types::uint) * (FW as crate::types::uint);
                    let exp = self.exp as crate::types::uint;
                    if self.MinPrec() <= exp {
                        acc = Accuracy::Exact;
                    }
                    // Shift the mantissa so its binary point lands after
                    // the integer part: value = mant · 2^(exp - all_bits).
                    let abs = if exp > all_bits {
                        lsh_limbs(&self.mant, exp - all_bits)
                    } else if exp < all_bits {
                        rsh_limbs(&self.mant, all_bits - exp)
                    } else {
                        trim(self.mant.clone())
                    };
                    let abs = trim(abs);
                    let neg = self.neg && !abs.is_empty();
                    (Int { neg, abs }, acc)
                }
            }
            form::Zero => (Int::default(), Accuracy::Exact),
            form::Inf => panic!("big::Float::Int of an infinity"),
        };
        if let Some(dst) = z.maybe_mut_int() {
            dst.neg = out.neg;
            dst.abs = out.abs.clone();
        }
        (out, acc)
    }

    /// `(*Float).Rat(z)` — the rational number equal to `self`. A finite
    /// `Float` is `mant · 2^exp`, hence always exactly rational, so the
    /// accuracy is always `Exact`. If a non-nil `z` is provided the
    /// result is also stored into it; the owned [`Rat`] in the returned
    /// tuple always carries the value. Panics if `self` is an infinity
    /// (Go returns `nil`).
    pub fn Rat<Z: MaybeMutRat>(&self, mut z: Z) -> (Rat, Accuracy) {
        let (out, acc): (Rat, Accuracy) = match self.form {
            form::Finite => {
                // 0 < |x| < +Inf
                let all_bits = (self.mant.len() as i64) * i64::from(FW);
                let exp = i64::from(self.exp);
                let mut r = Rat::new();
                if exp > all_bits {
                    // value = (mant << (exp-all_bits)) / 1
                    r.num = Int {
                        neg: self.neg,
                        abs: lsh_limbs(&self.mant, (exp - all_bits) as u64),
                    };
                    r.den = NewInt(1);
                } else if exp < all_bits {
                    // value = mant / 2^(all_bits-exp), then reduce.
                    r.num = Int { neg: self.neg, abs: trim(self.mant.clone()) };
                    r.den = Int {
                        neg: false,
                        abs: lsh_limbs(&[1u32], (all_bits - exp) as u64),
                    };
                    r.norm();
                } else {
                    // exp == all_bits → integer mant / 1
                    r.num = Int { neg: self.neg, abs: trim(self.mant.clone()) };
                    r.den = NewInt(1);
                }
                (r, Accuracy::Exact)
            }
            form::Zero => (Rat::new(), Accuracy::Exact),
            form::Inf => panic!("big::Float::Rat of an infinity"),
        };
        if let Some(dst) = z.maybe_mut_rat() {
            dst.num = out.num.clone();
            dst.den = out.den.clone();
        }
        (out, acc)
    }

    /// `(*Float).SetRat(x)` — set `self` to the (possibly rounded) value
    /// of the [`Rat`] `x`. If `self`'s precision is 0 it is changed to
    /// the largest of `Num().BitLen()`, `Denom().BitLen()`, or 64
    /// (matching Go's operand-derived default). Rounding follows `self`'s
    /// precision and mode.
    pub fn SetRat<X: AsRef<Rat>>(&mut self, x: X) -> &mut Self {
        // Snapshot — SetRat reads x while mutating self.
        let x = x.as_ref().clone();
        if x.IsInt() {
            return self.SetInt(x.Num());
        }
        // a / b with both as Floats.
        let mut a = Float::default();
        a.SetInt(x.Num());
        let mut b = Float::default();
        b.SetInt(x.Denom());
        if self.prec == 0 {
            self.prec = if a.prec > b.prec { a.prec } else { b.prec };
        }
        self.Quo(&a, &b)
    }

    // ─── internal: unsigned-mantissa arithmetic helpers ──────────────
    //
    // These mirror Go's `uadd` / `usub` / `umul` / `uquo`: they ignore
    // the operand signs (the caller sets `self.neg` first, since the
    // directed rounding modes consult it) and end by calling
    // `set_exp_and_round`. Operands `x` and `y` must be `Finite` with a
    // non-empty mantissa. Aliasing is safe — operands are passed by
    // value (clones), so `self` may freely be one of them.

    /// `z = x + y`, ignoring signs. Both operands finite & nonzero.
    fn uadd(&mut self, x: &Float, y: &Float) {
        // Exponents of the mantissae with the binary point on the right
        // (i.e. interpreting the limbs as integers). i64 avoids overflow.
        let ex = i64::from(x.exp) - (x.mant.len() as i64) * i64::from(FW);
        let ey = i64::from(y.exp) - (y.mant.len() as i64) * i64::from(FW);

        let (sum, e) = if ex < ey {
            let t = lsh_limbs(&y.mant, (ey - ex) as u64);
            (add_limbs(&x.mant, &t), ex)
        } else if ex > ey {
            let t = lsh_limbs(&x.mant, (ex - ey) as u64);
            (add_limbs(&t, &y.mant), ey)
        } else {
            (add_limbs(&x.mant, &y.mant), ex)
        };

        self.mant = sum;
        // len(z.mant) > 0 — adding two nonzero magnitudes can't cancel.
        let s = fnorm(&mut self.mant);
        self.set_exp_and_round(e + (self.mant.len() as i64) * i64::from(FW) - s, 0);
    }

    /// `z = x - y` for `|x| > |y|`, ignoring signs. Both finite & nonzero.
    fn usub(&mut self, x: &Float, y: &Float) {
        let ex = i64::from(x.exp) - (x.mant.len() as i64) * i64::from(FW);
        let ey = i64::from(y.exp) - (y.mant.len() as i64) * i64::from(FW);

        let (diff, e) = if ex < ey {
            let t = lsh_limbs(&y.mant, (ey - ex) as u64);
            (sub_limbs(&x.mant, &t), ex)
        } else if ex > ey {
            let t = lsh_limbs(&x.mant, (ex - ey) as u64);
            (sub_limbs(&t, &y.mant), ey)
        } else {
            (sub_limbs(&x.mant, &y.mant), ex)
        };

        // The operands may have canceled each other out exactly.
        if diff.is_empty() {
            self.acc = Accuracy::Exact;
            self.form = form::Zero;
            self.neg = false;
            return;
        }

        self.mant = diff;
        let s = fnorm(&mut self.mant);
        self.set_exp_and_round(e + (self.mant.len() as i64) * i64::from(FW) - s, 0);
    }

    /// `z = x · y`, ignoring signs. Both finite & nonzero.
    fn umul(&mut self, x: &Float, y: &Float) {
        let e = i64::from(x.exp) + i64::from(y.exp);
        self.mant = mul_limbs(&x.mant, &y.mant);
        // x and y nonzero => product nonzero => mantissa non-empty.
        let s = fnorm(&mut self.mant);
        self.set_exp_and_round(e - s, 0);
    }

    /// `z = x / y`, ignoring signs. Both finite & nonzero.
    fn uquo(&mut self, x: &Float, y: &Float) {
        // Mantissa length in limbs for the desired result precision + 1
        // (at least one extra bit so the rounding bit survives division).
        let n = (self.prec / FW) as usize + 1;

        // Pad x's mantissa on the low end with `d` zero limbs so the
        // quotient is long enough to include the rounding bit.
        let mut xadj = x.mant.clone();
        let d_pad = n as i64 - x.mant.len() as i64 + y.mant.len() as i64;
        if d_pad > 0 {
            let mut padded = alloc::vec![0u32; d_pad as usize];
            padded.extend_from_slice(&x.mant);
            xadj = padded;
        }

        let d = xadj.len() as i64 - y.mant.len() as i64;
        let (q, r) = divmod_limbs(&xadj, &y.mant);
        self.mant = q;
        let e = i64::from(x.exp)
            - i64::from(y.exp)
            - (d - self.mant.len() as i64) * i64::from(FW);

        // A non-zero remainder means the (uncomputed) fractional part
        // would have a non-zero sticky bit.
        let sbit: u32 = if r.is_empty() { 0 } else { 1 };

        // q is nonzero: x,y nonzero and xadj padded so quotient ≥ 1 bit.
        let s = fnorm(&mut self.mant);
        self.set_exp_and_round(e - s, sbit);
    }

    // ─── public arithmetic ───────────────────────────────────────────

    /// `(*Float).Add(x, y)` — set `self` to the rounded sum `x + y`. If
    /// `self`'s precision is 0 it becomes `max(x.prec, y.prec)`. Rounding
    /// uses `self`'s precision and mode; `self.acc` reports the error.
    /// Panics (Go's `ErrNaN`) if `x` and `y` are infinities with opposite
    /// signs.
    pub fn Add<X: AsRef<Float>, Y: AsRef<Float>>(&mut self, x: X, y: Y) -> &mut Self {
        // Snapshot operands — callers may alias (`z.Add(z, x)`).
        let x = x.as_ref().clone();
        let y = y.as_ref().clone();

        if self.prec == 0 {
            self.prec = x.prec.max(y.prec);
        }

        if x.form == form::Finite && y.form == form::Finite {
            let yneg = y.neg;
            self.neg = x.neg;
            if x.neg == yneg {
                //   x  +   y  ==  (x + y)
                // (-x) + (-y) == -(x + y)
                self.uadd(&x, &y);
            } else if x.ucmp(&y) > 0 {
                //  x + (-y) == x - y
                self.usub(&x, &y);
            } else {
                // (-x) + y == y - x == -(x - y)
                self.neg = !self.neg;
                self.usub(&y, &x);
            }
            if self.form == form::Zero
                && self.mode == RoundingMode::ToNegativeInf
                && self.acc == Accuracy::Exact
            {
                self.neg = true;
            }
            return self;
        }

        if x.form == form::Inf && y.form == form::Inf && x.neg != y.neg {
            // (+Inf) + (-Inf) — undefined; leave self valid, then panic.
            self.acc = Accuracy::Exact;
            self.form = form::Zero;
            self.neg = false;
            panic!("addition of infinities with opposite signs");
        }

        if x.form == form::Zero && y.form == form::Zero {
            // ±0 + ±0  (only -0 + -0 == -0)
            self.acc = Accuracy::Exact;
            self.form = form::Zero;
            self.neg = x.neg && y.neg;
            return self;
        }

        if x.form == form::Inf || y.form == form::Zero {
            // ±Inf + y  /  x + ±0
            return self.Set(&x);
        }
        // ±0 + y  /  x + ±Inf
        self.Set(&y)
    }

    /// `(*Float).Sub(x, y)` — set `self` to the rounded difference
    /// `x - y`. Precision, rounding, and accuracy as for [`Float::Add`].
    /// Panics (Go's `ErrNaN`) if `x` and `y` are infinities with equal
    /// signs.
    pub fn Sub<X: AsRef<Float>, Y: AsRef<Float>>(&mut self, x: X, y: Y) -> &mut Self {
        let x = x.as_ref().clone();
        let y = y.as_ref().clone();

        if self.prec == 0 {
            self.prec = x.prec.max(y.prec);
        }

        if x.form == form::Finite && y.form == form::Finite {
            let yneg = y.neg;
            self.neg = x.neg;
            if x.neg != yneg {
                //   x  - (-y) ==  (x + y)
                // (-x) -   y  == -(x + y)
                self.uadd(&x, &y);
            } else if x.ucmp(&y) > 0 {
                //   x  -   y  ==  (x - y)
                self.usub(&x, &y);
            } else {
                // (-x) - (-y) == y - x == -(x - y)
                self.neg = !self.neg;
                self.usub(&y, &x);
            }
            if self.form == form::Zero
                && self.mode == RoundingMode::ToNegativeInf
                && self.acc == Accuracy::Exact
            {
                self.neg = true;
            }
            return self;
        }

        if x.form == form::Inf && y.form == form::Inf && x.neg == y.neg {
            // (+Inf) - (+Inf)  /  (-Inf) - (-Inf) — undefined.
            self.acc = Accuracy::Exact;
            self.form = form::Zero;
            self.neg = false;
            panic!("subtraction of infinities with equal signs");
        }

        if x.form == form::Zero && y.form == form::Zero {
            // ±0 - ±0  (only -0 - +0 == -0)
            self.acc = Accuracy::Exact;
            self.form = form::Zero;
            self.neg = x.neg && !y.neg;
            return self;
        }

        if x.form == form::Inf || y.form == form::Zero {
            // ±Inf - y  /  x - ±0
            return self.Set(&x);
        }
        // ±0 - y  /  x - ±Inf
        self.Neg(&y)
    }

    /// `(*Float).Mul(x, y)` — set `self` to the rounded product `x · y`.
    /// Precision, rounding, and accuracy as for [`Float::Add`]. Panics
    /// (Go's `ErrNaN`) if one operand is zero and the other an infinity.
    pub fn Mul<X: AsRef<Float>, Y: AsRef<Float>>(&mut self, x: X, y: Y) -> &mut Self {
        let x = x.as_ref().clone();
        let y = y.as_ref().clone();

        if self.prec == 0 {
            self.prec = x.prec.max(y.prec);
        }

        self.neg = x.neg != y.neg;

        if x.form == form::Finite && y.form == form::Finite {
            self.umul(&x, &y);
            return self;
        }

        self.acc = Accuracy::Exact;
        if (x.form == form::Zero && y.form == form::Inf)
            || (x.form == form::Inf && y.form == form::Zero)
        {
            // ±0 · ±Inf — undefined; leave self valid, then panic.
            self.form = form::Zero;
            self.neg = false;
            panic!("multiplication of zero with infinity");
        }

        if x.form == form::Inf || y.form == form::Inf {
            // ±Inf · y  /  x · ±Inf
            self.form = form::Inf;
            return self;
        }
        // ±0 · y  /  x · ±0
        self.form = form::Zero;
        self
    }

    /// `(*Float).Quo(x, y)` — set `self` to the rounded quotient `x / y`.
    /// Precision, rounding, and accuracy as for [`Float::Add`]. Panics
    /// (Go's `ErrNaN`) if both operands are zero or both infinities.
    pub fn Quo<X: AsRef<Float>, Y: AsRef<Float>>(&mut self, x: X, y: Y) -> &mut Self {
        let x = x.as_ref().clone();
        let y = y.as_ref().clone();

        if self.prec == 0 {
            self.prec = x.prec.max(y.prec);
        }

        self.neg = x.neg != y.neg;

        if x.form == form::Finite && y.form == form::Finite {
            self.uquo(&x, &y);
            return self;
        }

        self.acc = Accuracy::Exact;
        if (x.form == form::Zero && y.form == form::Zero)
            || (x.form == form::Inf && y.form == form::Inf)
        {
            // ±0 / ±0  /  ±Inf / ±Inf — undefined; leave self valid.
            self.form = form::Zero;
            self.neg = false;
            panic!("division of zero by zero or infinity by infinity");
        }

        if x.form == form::Zero || y.form == form::Inf {
            // ±0 / y  /  x / ±Inf
            self.form = form::Zero;
            return self;
        }
        // x / ±0  /  ±Inf / y
        self.form = form::Inf;
        self
    }

    /// `(*Float).Abs(x)` — set `self` to the (possibly rounded) value
    /// `|x|`.
    pub fn Abs<X: AsRef<Float>>(&mut self, x: X) -> &mut Self {
        self.Set(x);
        self.neg = false;
        self
    }

    /// `(*Float).Neg(x)` — set `self` to the (possibly rounded) value of
    /// `x` with its sign negated.
    pub fn Neg<X: AsRef<Float>>(&mut self, x: X) -> &mut Self {
        self.Set(x);
        self.neg = !self.neg;
        self
    }

    /// `(*Float).Sqrt(x)` — set `self` to the rounded square root of `x`.
    /// If `self`'s precision is 0 it becomes `x`'s precision. Rounding
    /// uses `self`'s precision and mode; `self.acc` is left undefined
    /// (matching Go). Panics (Go's `ErrNaN`) if `x < 0`. `√±0 = ±0`,
    /// `√(+Inf) = +Inf`.
    pub fn Sqrt<X: AsRef<Float>>(&mut self, x: X) -> &mut Self {
        let x = x.as_ref().clone();

        if self.prec == 0 {
            self.prec = x.prec;
        }

        if x.Sign() == -1 {
            // IEEE 754-2008 §7.2.
            panic!("square root of negative operand");
        }

        // Handle ±0 and +Inf.
        if x.form != form::Finite {
            self.acc = Accuracy::Exact;
            self.form = x.form;
            self.neg = x.neg; // √±0 == ±0
            self.mant = Vec::new();
            self.exp = 0;
            return self;
        }

        // MantExp would lower self.prec if self.prec > x.prec; capture
        // and restore it across the call.
        let prec = self.prec;
        let b = x.MantExp(&mut *self);
        self.prec = prec;

        // Compute √(z·2^b):
        //   √( z)·2^(½b)    if b even
        //   √(2z)·2^(⌊½b⌋)  if b > 0 odd
        //   √(½z)·2^(⌈½b⌉)  if b < 0 odd
        match b % 2 {
            0 => {}
            1 => self.exp += 1,
            -1 => self.exp -= 1,
            _ => {}
        }
        // 0.25 <= self < 2.0

        let root = self.sqrt_inverse();
        self.Set(&root);

        // Re-attach the halved exponent.
        let half = b / 2;
        let snapshot = self.clone();
        self.SetMantExp(&snapshot, half)
    }

    /// Compute `√x` (to `self.prec` precision) by solving `1/t² - x = 0`
    /// for `t` with Newton's method, then inverting. `self` holds the
    /// normalized `x` (`0.25 <= x < 2.0`) on entry; the returned `Float`
    /// is `√x`. Mirrors Go's `sqrtInverse`.
    fn sqrt_inverse(&self) -> Float {
        let x = self;
        // ng: Newton step  t2 = ½t(3 - x·t²).
        let three = NewFloat(3.0);
        let next_guess = |t: &Float| -> Float {
            let mut u = Float::new();
            u.prec = t.prec;
            let mut v = Float::new();
            v.prec = t.prec;
            u.Mul(t, t); // u = t²
            let u2 = u.clone();
            u.Mul(x, &u2); //   = x·t²
            v.Sub(&three, &u); // v = 3 - x·t²
            u.Mul(t, &v); // u = t(3 - x·t²)
            u.exp -= 1; //   = ½t(3 - x·t²)
            let mut t2 = Float::new();
            t2.prec = t.prec;
            t2.Set(&u);
            t2
        };

        // Initial guess 1/√x from an f64 approximation.
        let xf = x.to_f64_approx();
        let mut sqi = Float::new();
        sqi.prec = x.prec;
        sqi.SetFloat64(1.0 / sqrt_f64(xf));

        // Newton's method doubles the correct digits each step; grow the
        // working precision the same way until it covers prec + 32 bits.
        let prec = self.prec + 32;
        while sqi.prec < prec {
            sqi.prec *= 2;
            sqi = next_guess(&sqi);
        }
        // sqi = 1/√x

        // √x = x / √x = x · (1/√x)
        let mut z = Float::new();
        z.prec = self.prec;
        z.Mul(x, &sqi);
        z
    }

    /// Internal: a coarse `f64` approximation of a finite `Float`, used
    /// only to seed `Sqrt`'s Newton iteration. `Float64()` proper is a
    /// later task; this reads the top 64 mantissa bits and `ldexp`s.
    fn to_f64_approx(&self) -> f64 {
        if self.form != form::Finite || self.mant.is_empty() {
            return 0.0;
        }
        // Top 64 bits of the msb-normalized mantissa.
        let n = self.mant.len();
        let hi = u64::from(self.mant[n - 1]);
        let lo = if n >= 2 { u64::from(self.mant[n - 2]) } else { 0 };
        let m = (hi << 32) | lo; // msb set (normalized)
        // m represents the fraction m / 2^64, so value = m · 2^(exp-64).
        let v = ldexp_f64(m, i64::from(self.exp) - 64);
        if self.neg { -v } else { v }
    }

    // ─── string I/O — formatting ─────────────────────────────────────
    //
    // Go reference: math/big/{ftoa,decimal}.go. The core algorithm
    // converts the binary mantissa exactly into a decimal-digit string
    // (`Decimal`), rounds it to the requested precision, then renders
    // it in the chosen format. The binary/hex forms ('b', 'p', 'x') are
    // rendered directly from the limbs.

    /// `(*Float).Text(format, prec)` — format `self` as text. The
    /// `format` byte is one of `'e' 'E' 'f' 'g' 'G' 'x' 'b' 'p'`; see
    /// the Go docs for the meaning of each. `prec` is the digit count
    /// (`-1` selects the shortest representation that round-trips). An
    /// unrecognized `format` yields `"%<format>"`.
    pub fn Text(&self, format: crate::types::byte, prec: int) -> crate::string {
        let buf = self.append_internal(Vec::new(), format, prec);
        crate::string::from_bytes(&buf)
    }

    /// `(*Float).String()` — formats `self` like `Text('g', 10)`.
    pub fn String(&self) -> crate::string {
        self.Text(b'g', 10)
    }

    /// `(*Float).Append(buf, format, prec)` — append the `Text`
    /// formatting of `self` to `buf` and return the extended slice.
    pub fn Append(
        &self,
        buf: crate::slice<crate::types::byte>,
        format: crate::types::byte,
        prec: int,
    ) -> crate::slice<crate::types::byte> {
        let out = self.append_internal(buf.__into_vec(), format, prec);
        crate::slice::<crate::types::byte>::__from_vec(out)
    }

    /// Internal: the `Append` body operating on a Rust `Vec<u8>`.
    /// Mirrors `ftoa.go:(*Float).Append`.
    fn append_internal(&self, mut buf: Vec<u8>, fmt: u8, mut prec: int) -> Vec<u8> {
        // sign
        if self.neg {
            buf.push(b'-');
        }

        // Inf
        if self.form == form::Inf {
            if !self.neg {
                buf.push(b'+');
            }
            buf.extend_from_slice(b"Inf");
            return buf;
        }

        // pick off easy formats
        match fmt {
            b'b' => return self.fmt_b(buf),
            b'p' => return self.fmt_p(buf),
            b'x' => return self.fmt_x(buf, prec),
            _ => {}
        }

        // 1) convert Float to multiprecision decimal
        let mut d = Decimal::new();
        if self.form == form::Finite {
            // x != 0; exp - bitLen(mant) is the shift of the integer mantissa
            let shift = i64::from(self.exp) - i64::from(bit_len(&self.mant));
            d.init(&self.mant, shift);
        }

        // 2) round to desired precision
        let shortest = prec < 0;
        if shortest {
            round_shortest(&mut d, self);
            match fmt {
                b'e' | b'E' => prec = d.mant.len() as int - 1,
                b'f' => prec = core::cmp::max(d.mant.len() as int - d.exp as int, 0),
                b'g' | b'G' => prec = d.mant.len() as int,
                _ => {}
            }
        } else {
            match fmt {
                b'e' | b'E' => d.round(1 + prec),
                b'f' => d.round(d.exp as int + prec),
                b'g' | b'G' => {
                    if prec == 0 {
                        prec = 1;
                    }
                    d.round(prec);
                }
                _ => {}
            }
        }

        // 3) read digits out and format
        match fmt {
            b'e' | b'E' => fmt_e(buf, fmt, prec, &d),
            b'f' => fmt_f(buf, prec, &d),
            b'g' | b'G' => {
                let mut eprec = prec;
                if eprec > d.mant.len() as int && d.mant.len() as int >= d.exp as int {
                    eprec = d.mant.len() as int;
                }
                if shortest {
                    eprec = 6;
                }
                let exp = d.exp as int - 1;
                if exp < -4 || exp >= eprec {
                    if prec > d.mant.len() as int {
                        prec = d.mant.len() as int;
                    }
                    // fmt+'e'-'g' maps 'g'->'e', 'G'->'E'
                    let efmt = fmt - b'g' + b'e';
                    return fmt_e(buf, efmt, prec - 1, &d);
                }
                if prec > d.exp as int {
                    prec = d.mant.len() as int;
                }
                fmt_f(buf, core::cmp::max(prec - d.exp as int, 0), &d)
            }
            _ => {
                // unknown format
                if self.neg {
                    buf.pop(); // sign was added prematurely
                }
                buf.push(b'%');
                buf.push(fmt);
                buf
            }
        }
    }

    /// `fmtB` — `mantissa "p" exponent`, decimal mantissa using exactly
    /// `prec` bits, binary exponent. `"0"` for zero. Sign ignored.
    fn fmt_b(&self, mut buf: Vec<u8>) -> Vec<u8> {
        if self.form == form::Zero {
            buf.push(b'0');
            return buf;
        }
        // adjust mantissa to use exactly self.prec bits
        let w = self.mant.len() as u32 * FW;
        let m = if w < self.prec {
            lsh_limbs(&self.mant, u64::from(self.prec - w))
        } else if w > self.prec {
            rsh_limbs(&self.mant, u64::from(w - self.prec))
        } else {
            self.mant.clone()
        };
        buf.extend_from_slice(&itoa(false, &m, 10));
        buf.push(b'p');
        let e = i64::from(self.exp) - i64::from(self.prec);
        if e >= 0 {
            buf.push(b'+');
        }
        append_int(buf, e)
    }

    /// `fmtP` — `"0x." mantissa "p" exponent`, hex mantissa in
    /// `[0.5, 1)`, binary exponent. `"0"` for zero. Sign ignored.
    fn fmt_p(&self, mut buf: Vec<u8>) -> Vec<u8> {
        if self.form == form::Zero {
            buf.push(b'0');
            return buf;
        }
        // remove trailing 0 limbs early (no need to trim hex 0's later)
        let mut m: &[u32] = &self.mant;
        let mut i = 0usize;
        while i < m.len() && m[i] == 0 {
            i += 1;
        }
        m = &m[i..];
        buf.extend_from_slice(b"0x.");
        let mut hex = itoa(false, m, 16);
        // trim trailing '0's
        while hex.last() == Some(&b'0') {
            hex.pop();
        }
        buf.extend_from_slice(&hex);
        buf.push(b'p');
        if self.exp >= 0 {
            buf.push(b'+');
        }
        append_int(buf, i64::from(self.exp))
    }

    /// `fmtX` — `"0x1." mantissa "p" exponent`, hex mantissa in
    /// `[1, 2)`, binary exponent. `"0x0p+00"` for zero. Sign ignored.
    fn fmt_x(&self, mut buf: Vec<u8>, prec: int) -> Vec<u8> {
        if self.form == form::Zero {
            buf.extend_from_slice(b"0x0");
            if prec > 0 {
                buf.push(b'.');
                for _ in 0..prec {
                    buf.push(b'0');
                }
            }
            buf.extend_from_slice(b"p+00");
            return buf;
        }

        // round mantissa to n bits
        let n: u32 = if prec < 0 {
            1 + (self.MinPrec() as u32 - 1 + 3) / 4 * 4
        } else {
            1 + 4 * prec as u32
        };
        // n%4 == 1; build a rounded copy at precision n
        let mut x = Float::new();
        x.SetPrec(n as crate::types::uint);
        x.SetMode(self.mode);
        x.Set(self);

        let w = x.mant.len() as u32 * FW;
        let m = if w < n {
            lsh_limbs(&x.mant, u64::from(n - w))
        } else if w > n {
            rsh_limbs(&x.mant, u64::from(w - n))
        } else {
            x.mant.clone()
        };
        let mut exp64 = i64::from(x.exp) - 1;

        let hm = itoa(false, &m, 16);
        buf.extend_from_slice(b"0x1");
        if hm.len() > 1 {
            buf.push(b'.');
            buf.extend_from_slice(&hm[1..]);
        }
        buf.push(b'p');
        if exp64 >= 0 {
            buf.push(b'+');
        } else {
            exp64 = -exp64;
            buf.push(b'-');
        }
        if exp64 < 10 {
            buf.push(b'0');
        }
        append_int(buf, exp64)
    }

    // ─── string I/O — parsing ────────────────────────────────────────
    //
    // Go reference: math/big/floatconv.go. `Parse` reads a float
    // literal (decimal, or — for base 0 — `0x`/`0b`/`0o`-prefixed),
    // applies the radix-point and exponent corrections via powers of
    // 2 and 5, and rounds to the receiver's precision.

    /// `(*Float).Parse(s, base)` — parse a floating-point literal from
    /// `s` in the given mantissa `base` (`0`, `2`, `8`, `10`, `16`).
    /// Returns `(self, actual_base, err)`. The whole string must be
    /// consumed. If `self`'s precision is 0 it becomes 64.
    pub fn Parse<S: Into<crate::string>>(
        &mut self,
        s: S,
        base: int,
    ) -> (&mut Float, int, crate::error) {
        let s = s.into();
        let bytes = s.as_bytes().to_vec();
        match float_scan(&bytes, base) {
            Ok((neg, mant_limbs, b, fcount, exp, ebase, is_inf)) => {
                if is_inf {
                    self.SetInf(neg);
                    return (self, b, crate::errors::nil);
                }
                let err = self.apply_scan(neg, mant_limbs, b, fcount, exp, ebase);
                (self, b, err)
            }
            Err(msg) => {
                self.form = form::Zero;
                (self, base, crate::errors::New(msg))
            }
        }
    }

    /// Internal: given the decomposed parse result, build `self`.
    /// Mirrors the tail of `floatconv.go:(*Float).scan`.
    fn apply_scan(
        &mut self,
        neg: bool,
        mut mant: Vec<u32>,
        b: int,
        fcount: i64,
        exp: i64,
        ebase: int,
    ) -> crate::error {
        let prec = if self.prec == 0 { 64 } else { self.prec };
        self.neg = neg;

        // special-case 0
        if mant.is_empty() {
            self.prec = prec;
            self.acc = Accuracy::Exact;
            self.form = form::Zero;
            return crate::errors::nil;
        }

        // normalize mantissa and determine initial exponent contributions
        let s = fnorm(&mut mant);
        let mut exp2 = (mant.len() as i64) * i64::from(FW) - s;
        let mut exp5: i64 = 0;
        self.mant = mant;

        // radix-point contribution
        if fcount < 0 {
            let d = fcount;
            match b {
                10 => {
                    exp5 = d;
                    exp2 += d;
                }
                2 => exp2 += d,
                8 => exp2 += d * 3,
                16 => exp2 += d * 4,
                _ => unreachable!(),
            }
        }

        // actual exponent
        match ebase {
            10 => {
                exp5 += exp;
                exp2 += exp;
            }
            2 => exp2 += exp,
            _ => unreachable!(),
        }

        // apply 2**exp2
        if MinExp as i64 <= exp2 && exp2 <= MaxExp as i64 {
            self.prec = prec;
            self.form = form::Finite;
            self.exp = exp2 as i32;
        } else {
            return crate::errors::New("exponent overflow");
        }

        if exp5 == 0 {
            self.round(0);
            return crate::errors::nil;
        }

        // apply 5**exp5
        let mut p = Float::new();
        p.SetPrec((self.Prec() + 64) as crate::types::uint);
        if exp5 < 0 {
            let p5 = pow5_float((-exp5) as u64, self.prec + 64);
            let snap = self.clone();
            self.Quo(&snap, &p5);
        } else {
            let p5 = pow5_float(exp5 as u64, self.prec + 64);
            let snap = self.clone();
            self.Mul(&snap, &p5);
        }
        let _ = p;
        crate::errors::nil
    }

    /// `(*Float).SetString(s)` — set `self` to the value of `s`
    /// (base 0). Returns `(self, ok)`; on failure `ok` is false and
    /// `self`'s value is undefined.
    pub fn SetString<S: Into<crate::string>>(
        &mut self,
        s: S,
    ) -> (&mut Float, bool) {
        let (_, _, err) = self.Parse(s, 0);
        let ok = err == crate::errors::nil;
        (self, ok)
    }

    // ─── string I/O — marshalling ────────────────────────────────────
    //
    // Go reference: math/big/floatmarsh.go. Gob carries the full Float
    // state (precision, mode, accuracy, form, sign, exponent, mantissa);
    // text marshalling carries only the value, in full precision.

    /// `(*Float).AppendText(b)` — append the full-precision `'g'`-format
    /// text of `self` to `b`. The error is always nil, matching Go.
    pub fn AppendText(
        &self,
        b: crate::slice<crate::types::byte>,
    ) -> (crate::slice<crate::types::byte>, crate::error) {
        (self.Append(b, b'g', -1), crate::errors::nil)
    }

    /// `(*Float).MarshalText()` — the full-precision text encoding of
    /// `self`. The error is always nil, matching Go.
    pub fn MarshalText(&self) -> (crate::slice<crate::types::byte>, crate::error) {
        self.AppendText(crate::slice::<crate::types::byte>::new())
    }

    /// `(*Float).UnmarshalText(text)` — parse `text` (base 0) into
    /// `self`, rounded per `self`'s precision and mode (precision 0
    /// becomes 64). Returns a non-nil error if `text` is invalid.
    pub fn UnmarshalText(
        &mut self,
        text: crate::slice<crate::types::byte>,
    ) -> crate::error {
        let s = crate::string::from_bytes(&text);
        let (_, _, err) = self.Parse(s.clone(), 0);
        if err != crate::errors::nil {
            return crate::errors::New(crate::fmt::Sprintf!(
                "math/big: cannot unmarshal %q into a *big.Float (%v)",
                s,
                err
            ));
        }
        crate::errors::nil
    }

    /// `(*Float).GobEncode()` — gob wire format: a version byte, a
    /// packed `mode|acc|form|neg` byte, a big-endian 4-byte precision,
    /// and (for finite values) a big-endian 4-byte exponent followed by
    /// the big-endian mantissa bytes. Error is always nil.
    pub fn GobEncode(&self) -> (crate::slice<crate::types::byte>, crate::error) {
        let mut out: Vec<u8> = Vec::new();
        out.push(FLOAT_GOB_VERSION);
        // mode (3 bits) << 5 | (acc+1) (2 bits) << 3 | form (2 bits) << 1 | neg
        let mode_bits = rounding_mode_to_bits(self.mode) & 7;
        let acc_bits = ((accuracy_to_signed(self.acc) + 1) & 3) as u8;
        let form_bits = form_to_bits(self.form) & 3;
        let mut b = (mode_bits << 5) | (acc_bits << 3) | (form_bits << 1);
        if self.neg {
            b |= 1;
        }
        out.push(b);
        // prec, big-endian u32
        out.extend_from_slice(&self.prec.to_be_bytes());

        if self.form == form::Finite {
            out.extend_from_slice(&(self.exp as u32).to_be_bytes());
            // Go's gob mantissa is a whole number of machine words; on
            // a 64-bit Go build that is ceil(MinPrec/64) 64-bit words.
            // The whole-word framing matters for interop, not just
            // looks: Go's GobDecode repacks the bytes via nat.setBytes
            // into 64-bit words and then validate() rejects a mantissa
            // whose top word's msb is unset — which is exactly what a
            // non-multiple-of-8 byte length produces. So frame goish's
            // 32-bit limbs into an even count 2*ceil(MinPrec/64)
            // (significant limbs at the high end, low end zero-filled).
            // For SetString/SetFloat64/SetInt-built values the bytes
            // are then identical to a 64-bit Go build; arithmetic
            // results may carry extra trailing zero words in Go and so
            // differ in length, but stay cross-decodable both ways.
            let words = (usize::try_from(self.MinPrec()).unwrap_or(0) + 63) / 64;
            let n_limbs = words * 2;
            let take = core::cmp::min(self.mant.len(), n_limbs);
            let mut framed = alloc::vec![0u32; n_limbs];
            framed[n_limbs - take..]
                .copy_from_slice(&self.mant[self.mant.len() - take..]);
            out.extend_from_slice(&limbs_to_be_bytes_fixed(&framed));
        }

        (
            crate::slice::<crate::types::byte>::__from_vec(out),
            crate::errors::nil,
        )
    }

    /// `(*Float).GobDecode(buf)` — inverse of `GobEncode`. An empty
    /// `buf` resets `self` to the zero value; a version mismatch or a
    /// truncated buffer returns a non-nil error. The result is rounded
    /// per `self`'s precision and mode unless that precision is 0.
    pub fn GobDecode(&mut self, buf: crate::slice<crate::types::byte>) -> crate::error {
        if buf.len() == 0 {
            *self = Float::default();
            return crate::errors::nil;
        }
        if buf.len() < 6 {
            return crate::errors::New("Float.GobDecode: buffer too small");
        }
        if buf[0usize] != FLOAT_GOB_VERSION {
            return crate::errors::New(crate::fmt::Sprintf!(
                "Float.GobDecode: encoding version %d not supported",
                int::from(buf[0usize] as i64)
            ));
        }

        let old_prec = self.prec;
        let old_mode = self.mode;

        let b = buf[1usize];
        self.mode = rounding_mode_from_bits((b >> 5) & 7);
        self.acc = accuracy_from_signed((((b >> 3) & 3) as i32) - 1);
        self.form = form_from_bits((b >> 1) & 3);
        self.neg = b & 1 != 0;
        let raw = &*buf;
        self.prec = u32::from_be_bytes([raw[2], raw[3], raw[4], raw[5]]);

        if self.form == form::Finite {
            if buf.len() < 10 {
                return crate::errors::New(
                    "Float.GobDecode: buffer too small for finite form float",
                );
            }
            self.exp = u32::from_be_bytes([raw[6], raw[7], raw[8], raw[9]]) as i32;
            self.mant = be_bytes_to_limbs_padded(&raw[10..]);
        } else {
            self.mant = Vec::new();
            self.exp = 0;
        }

        if old_prec != 0 {
            self.mode = old_mode;
            self.SetPrec(old_prec as crate::types::uint);
        }
        crate::errors::nil
    }
}

// ─── Float string-I/O support: the `decimal` type ─────────────────────
//
// Go reference: math/big/decimal.go. `Decimal` holds an unsigned
// floating-point number in decimal: value == mant · 10^exp with
// 0.1 <= mant < 1, big-endian ASCII digits, no trailing zeros. The only
// operations are exact binary→decimal conversion and rounding.

/// Maximum shift done in one `decimal_rsh` pass without overflowing a
/// `u64` accumulator: `(1<<maxShift - 1)*10 + 9` must fit a `u64`.
/// Go uses `_W - 4` (`_W` == 64). Here the accumulator is a `u64`.
const DEC_MAX_SHIFT: u32 = 60;

/// `decimal` — an unsigned decimal floating-point number used solely
/// for `Float`→string conversion. Mirrors `decimal.go:decimal`.
struct Decimal {
    /// Mantissa ASCII digits, big-endian, most-significant at index 0.
    mant: Vec<u8>,
    /// Decimal exponent: value == 0.mant · 10^exp.
    exp: i32,
}

impl Decimal {
    /// The ready-to-use zero decimal.
    fn new() -> Self {
        Decimal {
            mant: Vec::new(),
            exp: 0,
        }
    }

    /// `(*decimal).at(i)` — the `i`'th mantissa digit, `'0'` if out of
    /// range.
    fn at(&self, i: int) -> u8 {
        if i >= 0 && (i as usize) < self.mant.len() {
            self.mant[i as usize]
        } else {
            b'0'
        }
    }

    /// `(*decimal).init(m, shift)` — set the decimal to `m << shift`
    /// (for `shift >= 0`) or `m >> -shift` (for `shift < 0`), where `m`
    /// is a magnitude in little-endian u32 limbs.
    fn init(&mut self, m: &[u32], shift: i64) {
        // special case 0
        if bit_len(m) == 0 {
            self.mant.clear();
            self.exp = 0;
            return;
        }

        let mut mag = m.to_vec();
        while mag.last() == Some(&0) {
            mag.pop();
        }
        let mut shift = shift;

        // Optimization: trim trailing zero bits before a right shift.
        if shift < 0 {
            let ntz = trailing_zero_bits(&mag) as i64;
            let s = (-shift).min(ntz);
            if s > 0 {
                mag = rsh_limbs(&mag, s as u64);
            }
            shift += s;
        }

        // Do any shift-left in binary representation.
        if shift > 0 {
            mag = lsh_limbs(&mag, shift as u64);
            shift = 0;
        }

        // Convert mantissa into decimal representation.
        let s = itoa(false, &mag, 10);
        let mut n = s.len();
        self.exp = n as i32;
        // Trim trailing zeros; the exponent tracks the decimal point.
        while n > 0 && s[n - 1] == b'0' {
            n -= 1;
        }
        self.mant.clear();
        self.mant.extend_from_slice(&s[..n]);

        // Do any remaining shift-right in decimal representation.
        if shift < 0 {
            let mut sh = -shift;
            while sh > i64::from(DEC_MAX_SHIFT) {
                decimal_rsh(self, DEC_MAX_SHIFT);
                sh -= i64::from(DEC_MAX_SHIFT);
            }
            decimal_rsh(self, sh as u32);
        }
    }

    /// `(*decimal).round(n)` — round to at most `n` mantissa digits,
    /// ToNearestEven. `n < 0` leaves the decimal unchanged.
    fn round(&mut self, n: int) {
        if n < 0 || n >= self.mant.len() as int {
            return;
        }
        if decimal_should_round_up(self, n as usize) {
            self.round_up(n);
        } else {
            self.round_down(n);
        }
    }

    /// `(*decimal).roundUp(n)` — round the mantissa up to `n` digits.
    fn round_up(&mut self, n: int) {
        if n < 0 || n >= self.mant.len() as int {
            return;
        }
        let mut n = n as usize;
        // find first digit < '9'
        while n > 0 && self.mant[n - 1] >= b'9' {
            n -= 1;
        }
        if n == 0 {
            // all '9's => round up to '1', bump exponent
            self.mant[0] = b'1';
            self.mant.truncate(1);
            self.exp += 1;
            return;
        }
        self.mant[n - 1] += 1;
        self.mant.truncate(n);
    }

    /// `(*decimal).roundDown(n)` — truncate the mantissa to `n` digits.
    fn round_down(&mut self, n: int) {
        if n < 0 || n >= self.mant.len() as int {
            return;
        }
        self.mant.truncate(n as usize);
        decimal_trim(self);
    }
}

/// `decimal.go:rsh` — `x >> s` in decimal, for `s <= DEC_MAX_SHIFT`.
fn decimal_rsh(x: &mut Decimal, s: u32) {
    // Division by 1<<s using shift-and-subtract.
    let mut r = 0usize; // read index
    let mut n: u64 = 0;
    // pick up enough leading digits to cover the first shift
    while n >> s == 0 && r < x.mant.len() {
        let ch = u64::from(x.mant[r]);
        r += 1;
        n = n * 10 + ch - u64::from(b'0');
    }
    if n == 0 {
        // x == 0 — shouldn't get here, handle anyway
        x.mant.clear();
        return;
    }
    while n >> s == 0 {
        r += 1;
        n *= 10;
    }
    x.exp += 1 - r as i32;

    let mask: u64 = (1u64 << s) - 1;
    let mut w = 0usize; // write index
    while r < x.mant.len() {
        let ch = u64::from(x.mant[r]);
        r += 1;
        let d = n >> s;
        n &= mask;
        x.mant[w] = (d + u64::from(b'0')) as u8;
        w += 1;
        n = n * 10 + ch - u64::from(b'0');
    }
    // write extra digits that still fit
    while n > 0 && w < x.mant.len() {
        let d = n >> s;
        n &= mask;
        x.mant[w] = (d + u64::from(b'0')) as u8;
        w += 1;
        n *= 10;
    }
    x.mant.truncate(w);
    // append additional digits that didn't fit
    while n > 0 {
        let d = n >> s;
        n &= mask;
        x.mant.push((d + u64::from(b'0')) as u8);
        n *= 10;
    }
    decimal_trim(x);
}

/// `decimal.go:shouldRoundUp` — whether `x` rounds up when shortened to
/// `n` digits. `n` must be a valid mantissa index.
fn decimal_should_round_up(x: &Decimal, n: usize) -> bool {
    if x.mant[n] == b'5' && n + 1 == x.mant.len() {
        // exactly halfway — round to even
        return n > 0 && (x.mant[n - 1] - b'0') & 1 != 0;
    }
    x.mant[n] >= b'5'
}

/// `decimal.go:trim` — cut off trailing zeros from the mantissa.
fn decimal_trim(x: &mut Decimal) {
    let mut i = x.mant.len();
    while i > 0 && x.mant[i - 1] == b'0' {
        i -= 1;
    }
    x.mant.truncate(i);
    if i == 0 {
        x.exp = 0;
    }
}

/// `ftoa.go:roundShortest` — shorten `d` to the fewest digits that
/// still round back to `x` under `x`'s precision (ToNearestEven).
fn round_shortest(d: &mut Decimal, x: &Float) {
    if d.mant.is_empty() {
        return;
    }

    // 1) normalized mantissa with lsb == 1/2 ulp (x.prec+1 bits)
    let mut mant = x.mant.clone();
    while mant.last() == Some(&0) {
        mant.pop();
    }
    let mut exp = i64::from(x.exp) - i64::from(bit_len(&mant));
    let s = i64::from(bit_len(&mant)) - i64::from(x.prec + 1);
    if s < 0 {
        mant = lsh_limbs(&mant, (-s) as u64);
    } else if s > 0 {
        mant = rsh_limbs(&mant, s as u64);
    }
    exp += s;
    // x == mant · 2^exp with lsb(mant) == 1/2 ulp of x.prec

    // 2) lower bound = mant - 1
    let mut lower = Decimal::new();
    lower.init(&sub_limbs(&mant, &[1u32]), exp);

    // 3) upper bound = mant + 1
    let mut upper = Decimal::new();
    upper.init(&add_limbs(&mant, &[1u32]), exp);

    // bounds are inclusive only when the original mantissa is even
    // (test bit 1 — the original mantissa was shifted by 1)
    let inclusive = (mant.first().copied().unwrap_or(0) & 2) == 0;

    // Walk along until d distinguishes itself from lower and upper.
    for i in 0..d.mant.len() {
        let m = d.mant[i];
        let l = lower.at(i as int);
        let u = upper.at(i as int);

        let okdown = l != m || (inclusive && i + 1 == lower.mant.len());
        let okup = m != u
            && (inclusive || m + 1 < u || i + 1 < upper.mant.len());

        if okdown && okup {
            d.round(i as int + 1);
            return;
        } else if okdown {
            d.round_down(i as int + 1);
            return;
        } else if okup {
            d.round_up(i as int + 1);
            return;
        }
    }
}

/// `ftoa.go:fmtE` — `d.ddddde±dd`. `efmt` is `'e'` or `'E'`.
fn fmt_e(mut buf: Vec<u8>, efmt: u8, prec: int, d: &Decimal) -> Vec<u8> {
    // first digit
    let ch = if !d.mant.is_empty() { d.mant[0] } else { b'0' };
    buf.push(ch);

    // .moredigits
    if prec > 0 {
        buf.push(b'.');
        let mut i = 1usize;
        let m = core::cmp::min(d.mant.len(), prec as usize + 1);
        if i < m {
            buf.extend_from_slice(&d.mant[i..m]);
            i = m;
        }
        while i <= prec as usize {
            buf.push(b'0');
            i += 1;
        }
    }

    // e±
    buf.push(efmt);
    let mut exp: i64 = if !d.mant.is_empty() {
        i64::from(d.exp) - 1
    } else {
        0
    };
    if exp < 0 {
        buf.push(b'-');
        exp = -exp;
    } else {
        buf.push(b'+');
    }
    // at least two exponent digits
    if exp < 10 {
        buf.push(b'0');
    }
    append_int(buf, exp)
}

/// `ftoa.go:fmtF` — `ddddddd.ddddd`.
fn fmt_f(mut buf: Vec<u8>, prec: int, d: &Decimal) -> Vec<u8> {
    // integer part, zero-padded as needed
    if d.exp > 0 {
        let mut m = core::cmp::min(d.mant.len(), d.exp as usize);
        buf.extend_from_slice(&d.mant[..m]);
        while m < d.exp as usize {
            buf.push(b'0');
            m += 1;
        }
    } else {
        buf.push(b'0');
    }

    // fraction
    if prec > 0 {
        buf.push(b'.');
        for i in 0..prec {
            buf.push(d.at(d.exp as int + i));
        }
    }
    buf
}

/// Append the decimal text of an `i64` to `buf`. Internal equivalent of
/// `strconv.AppendInt(buf, v, 10)`; a negative `v` is prefixed with `-`.
fn append_int(mut buf: Vec<u8>, v: i64) -> Vec<u8> {
    if v == 0 {
        buf.push(b'0');
        return buf;
    }
    let mut n: u64 = if v < 0 {
        buf.push(b'-');
        (v as i128).unsigned_abs() as u64
    } else {
        v as u64
    };
    let mut tmp = [0u8; 20];
    let mut i = tmp.len();
    while n > 0 {
        i -= 1;
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    buf.extend_from_slice(&tmp[i..]);
    buf
}

// ─── Float parse support ──────────────────────────────────────────────

/// Decomposed result of scanning a float literal:
/// `(neg, mant_limbs, base, fcount, exp, ebase, is_inf)`.
type FloatScan = (bool, Vec<u32>, int, i64, i64, int, bool);

/// `floatconv.go:scan` + `Parse` prefix handling — scan a float literal
/// from `bytes` in the given mantissa `base`. Returns the decomposed
/// fields, or an error message string. The whole input must be a valid
/// number (no trailing junk).
fn float_scan(bytes: &[u8], base: int) -> Result<FloatScan, crate::string> {
    // ±Inf / ±inf
    if bytes == b"Inf" || bytes == b"inf" {
        return Ok((false, Vec::new(), 10, 0, 0, 10, true));
    }
    if bytes.len() == 4
        && (bytes[0] == b'+' || bytes[0] == b'-')
        && (&bytes[1..] == b"Inf" || &bytes[1..] == b"inf")
    {
        return Ok((bytes[0] == b'-', Vec::new(), 10, 0, 0, 10, true));
    }

    if !(base == 0 || base == 2 || base == 8 || base == 10 || base == 16) {
        return Err(crate::string::from("invalid number base"));
    }

    let mut i = 0usize;

    // sign
    let neg = match bytes.first().copied() {
        Some(b'-') => {
            i += 1;
            true
        }
        Some(b'+') => {
            i += 1;
            false
        }
        _ => false,
    };

    let allow_underscore = base == 0;

    // base prefix
    let mut b = base;
    if base == 0 {
        b = 10;
        if bytes.get(i).copied() == Some(b'0') {
            match bytes.get(i + 1).copied() {
                Some(b'b') | Some(b'B') => {
                    b = 2;
                    i += 2;
                }
                Some(b'o') | Some(b'O') => {
                    b = 8;
                    i += 2;
                }
                Some(b'x') | Some(b'X') => {
                    b = 16;
                    i += 2;
                }
                _ => {}
            }
        }
    }

    // mantissa: digits, optional '.', optional digits
    let mut mant: Vec<u32> = Vec::new();
    let mut digit_count: usize = 0;
    let mut fcount: i64 = 0; // number of fractional digits (negated later)
    let mut seen_dot = false;
    let mut prev_digit = false; // for underscore validation
    let mut prev_underscore = false;
    let mut invalid_sep = false;
    let bw = b as u32;

    while i < bytes.len() {
        let ch = bytes[i];
        if ch == b'_' && allow_underscore {
            if !prev_digit {
                invalid_sep = true;
            }
            prev_digit = false;
            prev_underscore = true;
            i += 1;
            continue;
        }
        if ch == b'.' && !seen_dot {
            seen_dot = true;
            prev_digit = false;
            prev_underscore = false;
            i += 1;
            continue;
        }
        match digit_value(ch, b) {
            Some(d) => {
                mul_add_word(&mut mant, bw, d);
                digit_count += 1;
                if seen_dot {
                    fcount += 1;
                }
                prev_digit = true;
                prev_underscore = false;
                i += 1;
            }
            None => break,
        }
    }

    if digit_count == 0 {
        return Err(crate::string::from("number has no digits"));
    }
    if prev_underscore || invalid_sep {
        return Err(crate::string::from("'_' must separate successive digits"));
    }

    // exponent
    let mut exp: i64 = 0;
    let mut ebase: int = 10;
    if i < bytes.len() {
        let ech = bytes[i];
        let is_e = ech == b'e' || ech == b'E';
        let is_p = ech == b'p' || ech == b'P';
        // for hex mantissae, 'e'/'E' are digits — only 'p'/'P' begin an
        // exponent (Go: scanExponent).
        let exp_ok = if b == 16 { is_p } else { is_e || is_p };
        if exp_ok {
            if is_p {
                ebase = 2;
            }
            i += 1;
            let eneg = match bytes.get(i).copied() {
                Some(b'-') => {
                    i += 1;
                    true
                }
                Some(b'+') => {
                    i += 1;
                    false
                }
                _ => false,
            };
            let mut ecount = 0usize;
            let mut eprev_digit = false;
            let mut eprev_us = false;
            while i < bytes.len() {
                let c = bytes[i];
                if c == b'_' && allow_underscore {
                    if !eprev_digit {
                        invalid_sep = true;
                    }
                    eprev_digit = false;
                    eprev_us = true;
                    i += 1;
                    continue;
                }
                if c.is_ascii_digit() {
                    exp = exp
                        .saturating_mul(10)
                        .saturating_add(i64::from(c - b'0'));
                    ecount += 1;
                    eprev_digit = true;
                    eprev_us = false;
                    i += 1;
                } else {
                    break;
                }
            }
            if ecount == 0 {
                return Err(crate::string::from("exponent has no digits"));
            }
            if eprev_us || invalid_sep {
                return Err(crate::string::from(
                    "'_' must separate successive digits",
                ));
            }
            if eneg {
                exp = -exp;
            }
        }
    }

    // entire string must be consumed
    if i != bytes.len() {
        return Err(crate::string::from("expected end of string"));
    }

    // fcount is the number of fractional digits; pass it negated so a
    // radix-point amounts to a division by b**(-fcount).
    Ok((neg, mant, b, -fcount, exp, ebase, false))
}

/// `5**n` as a `Float` at the given precision (bits). Mirrors
/// `floatconv.go:pow5` (binary exponentiation, n >= 0).
fn pow5_float(n: u64, prec: u32) -> Float {
    let mut z = Float::new();
    z.SetPrec(prec as crate::types::uint);

    if (n as usize) < POW5_TAB.len() {
        z.SetUint64(POW5_TAB[n as usize]);
        return z;
    }
    let m = POW5_TAB.len() as u64 - 1;
    z.SetUint64(POW5_TAB[m as usize]);
    let mut n = n - m;

    let mut f = Float::new();
    f.SetPrec((prec + 64) as crate::types::uint);
    f.SetUint64(5);

    while n > 0 {
        if n & 1 != 0 {
            let snap = z.clone();
            z.Mul(&snap, &f);
        }
        let fsnap = f.clone();
        f.Mul(&fsnap, &fsnap);
        n >>= 1;
    }
    z
}

/// Powers of 5 that fit into a `u64`. Mirrors `floatconv.go:pow5tab`.
const POW5_TAB: [u64; 28] = [
    1,
    5,
    25,
    125,
    625,
    3125,
    15625,
    78125,
    390625,
    1953125,
    9765625,
    48828125,
    244140625,
    1220703125,
    6103515625,
    30517578125,
    152587890625,
    762939453125,
    3814697265625,
    19073486328125,
    95367431640625,
    476837158203125,
    2384185791015625,
    11920928955078125,
    59604644775390625,
    298023223876953125,
    1490116119384765625,
    7450580596923828125,
];

// ─── Float gob support ────────────────────────────────────────────────

/// Float gob codec version — mirrors `floatmarsh.go:floatGobVersion`.
const FLOAT_GOB_VERSION: u8 = 1;

/// Map a [`RoundingMode`] to its 3-bit gob encoding (Go's `mode&7`).
fn rounding_mode_to_bits(m: RoundingMode) -> u8 {
    match m {
        RoundingMode::ToNearestEven => 0,
        RoundingMode::ToNearestAway => 1,
        RoundingMode::ToZero => 2,
        RoundingMode::AwayFromZero => 3,
        RoundingMode::ToNegativeInf => 4,
        RoundingMode::ToPositiveInf => 5,
    }
}

/// Inverse of [`rounding_mode_to_bits`].
fn rounding_mode_from_bits(b: u8) -> RoundingMode {
    match b & 7 {
        1 => RoundingMode::ToNearestAway,
        2 => RoundingMode::ToZero,
        3 => RoundingMode::AwayFromZero,
        4 => RoundingMode::ToNegativeInf,
        5 => RoundingMode::ToPositiveInf,
        _ => RoundingMode::ToNearestEven,
    }
}

/// Map an [`Accuracy`] to Go's signed encoding (`Below=-1 .. Above=+1`).
fn accuracy_to_signed(a: Accuracy) -> i32 {
    match a {
        Accuracy::Below => -1,
        Accuracy::Exact => 0,
        Accuracy::Above => 1,
    }
}

/// Inverse of [`accuracy_to_signed`].
fn accuracy_from_signed(v: i32) -> Accuracy {
    match v {
        -1 => Accuracy::Below,
        1 => Accuracy::Above,
        _ => Accuracy::Exact,
    }
}

/// Map a [`form`] to its 2-bit gob encoding (Go's `form&3`).
fn form_to_bits(f: form) -> u8 {
    match f {
        form::Zero => 0,
        form::Finite => 1,
        form::Inf => 2,
    }
}

/// Inverse of [`form_to_bits`].
fn form_from_bits(b: u8) -> form {
    match b & 3 {
        1 => form::Finite,
        2 => form::Inf,
        _ => form::Zero,
    }
}

/// Big-endian bytes of a `Float` mantissa: each limb emitted
/// most-significant first, whole words (no trimming) so the limb
/// boundary is recoverable. Mirrors `nat.bytes` for a normalized
/// mantissa whose top word's msb is set (no leading zero bytes).
fn limbs_to_be_bytes_fixed(limbs: &[u32]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(limbs.len() * 4);
    for &limb in limbs.iter().rev() {
        out.extend_from_slice(&limb.to_be_bytes());
    }
    out
}

/// Inverse of [`limbs_to_be_bytes_fixed`]: a big-endian byte buffer
/// (length a multiple of 4) back into little-endian u32 limbs.
fn be_bytes_to_limbs_padded(buf: &[u8]) -> Vec<u32> {
    let nlimbs = (buf.len() + 3) / 4;
    let mut limbs = alloc::vec![0u32; nlimbs];
    // buf is most-significant limb first.
    for (k, chunk) in buf.chunks(4).enumerate() {
        let mut w: u32 = 0;
        for &byte in chunk {
            w = (w << 8) | u32::from(byte);
        }
        limbs[nlimbs - 1 - k] = w;
    }
    while limbs.last() == Some(&0) {
        limbs.pop();
    }
    limbs
}

/// `big.ParseFloat(s, base, prec, mode)` — construct a [`Float`] with
/// the given precision and rounding mode, then parse `s` into it.
/// Returns `(value, actual_base, err)`. Mirrors `floatconv.go:ParseFloat`.
pub fn ParseFloat<S: Into<crate::string>>(
    s: S,
    base: int,
    prec: crate::types::uint,
    mode: RoundingMode,
) -> (Float, int, crate::error) {
    let mut z = Float::new();
    z.SetPrec(prec);
    z.SetMode(mode);
    let (_, b, err) = z.Parse(s, base);
    (z, b, err)
}

/// Internal: `√x` for a non-negative `f64`, no libm. Newton's method
/// seeded from an exponent-halving bit-trick; ~5 iterations converge to
/// full f64 precision. Only used to seed [`Float::Sqrt`].
fn sqrt_f64(x: f64) -> f64 {
    if x == 0.0 || x.is_nan() {
        return x;
    }
    if x < 0.0 {
        return f64::NAN;
    }
    if x.is_infinite() {
        return x;
    }
    // Seed: halve the biased exponent (the classic "fast" estimate).
    let bits = x.to_bits();
    let seed = f64::from_bits(((bits >> 1) + (0x1ff8_0000_0000_0000u64)) & !(1u64 << 63));
    let mut g = if seed > 0.0 && seed.is_finite() { seed } else { x };
    // Newton: g ← ½(g + x/g).
    for _ in 0..8 {
        g = 0.5 * (g + x / g);
    }
    g
}

/// `big.NewFloat(x)` — allocate a new [`Float`] set to `x`, with
/// precision 53 and rounding mode `ToNearestEven`. Panics if `x` is a
/// NaN, matching Go's `ErrNaN`.
pub fn NewFloat(x: crate::types::float64) -> Float {
    if x.is_nan() {
        panic!("big::NewFloat(NaN)");
    }
    let mut z = Float::default();
    z.SetFloat64(x);
    z
}

impl crate::fmt::Stringer for Float {
    /// `(*Float).String()` — formats `x` like `x.Text('g', 10)`.
    fn String(&self) -> crate::gostring::string {
        Float::String(self)
    }
}

// ─── AsRef<Float> bridge ─────────────────────────────────────────────
//
// `Set` accepts any of: &Float, owned Float, nilable<Float>,
// nilable_refmut<'_, Float>. Mirrors the AsRef<Int> block.

impl AsRef<Float> for Float {
    fn as_ref(&self) -> &Float {
        self
    }
}

impl AsRef<Float> for crate::nilable<Float> {
    #[track_caller]
    fn as_ref(&self) -> &Float {
        self.Must()
    }
}

impl<'a> AsRef<Float> for crate::gonilable_ref::nilable_refmut<'a, Float> {
    #[track_caller]
    fn as_ref(&self) -> &Float {
        self.Must()
    }
}

/// Internal: an *optional* mutable `Float` out-parameter — the `Float`
/// analogue of [`MaybeMutInt`]. Lets a caller pass bare `nil` for an
/// out-parameter it wants to skip, modelling Go's `MantExp(mant *Float)`
/// where `mant` may be `nil`.
pub trait MaybeMutFloat {
    fn maybe_mut_float(&mut self) -> Option<&mut Float>;
}

impl MaybeMutFloat for Float {
    fn maybe_mut_float(&mut self) -> Option<&mut Float> {
        Some(self)
    }
}

impl MaybeMutFloat for &mut Float {
    fn maybe_mut_float(&mut self) -> Option<&mut Float> {
        Some(*self)
    }
}

impl MaybeMutFloat for crate::nilval::Nil {
    fn maybe_mut_float(&mut self) -> Option<&mut Float> {
        None
    }
}

impl<'a> MaybeMutFloat for crate::gonilable_ref::nilable_refmut<'a, Float> {
    #[track_caller]
    fn maybe_mut_float(&mut self) -> Option<&mut Float> {
        if self.IsNil() {
            None
        } else {
            Some(self.MustMutRef())
        }
    }
}

impl MaybeMutFloat for crate::nilable<Float> {
    #[track_caller]
    fn maybe_mut_float(&mut self) -> Option<&mut Float> {
        if self.IsNil() {
            None
        } else {
            Some(self.MustMut())
        }
    }
}

/// Optional `&mut Rat` out-parameter — the [`Rat`] analogue of
/// [`MaybeMutFloat`]. Lets a caller pass bare `nil` for an unwanted
/// destination (e.g. `Float::Rat`); a `None` result means "no
/// destination", in which case only the owned tuple value carries the
/// result.
pub trait MaybeMutRat {
    fn maybe_mut_rat(&mut self) -> Option<&mut Rat>;
}

impl MaybeMutRat for Rat {
    fn maybe_mut_rat(&mut self) -> Option<&mut Rat> {
        Some(self)
    }
}

impl MaybeMutRat for &mut Rat {
    fn maybe_mut_rat(&mut self) -> Option<&mut Rat> {
        Some(*self)
    }
}

impl MaybeMutRat for crate::nilval::Nil {
    fn maybe_mut_rat(&mut self) -> Option<&mut Rat> {
        None
    }
}

impl<'a> MaybeMutRat for crate::gonilable_ref::nilable_refmut<'a, Rat> {
    #[track_caller]
    fn maybe_mut_rat(&mut self) -> Option<&mut Rat> {
        if self.IsNil() {
            None
        } else {
            Some(self.MustMutRef())
        }
    }
}

impl MaybeMutRat for crate::nilable<Rat> {
    #[track_caller]
    fn maybe_mut_rat(&mut self) -> Option<&mut Rat> {
        if self.IsNil() {
            None
        } else {
            Some(self.MustMut())
        }
    }
}

// ─── AsRef<Int> bridge ───────────────────────────────────────────────
//
// Methods like `Mul`, `Div`, `DivMod`, `Abs` accept any of:
//   * &Int (canonical)
//   * Int (by value)
//   * nilable<Int>
//   * nilable_refmut<'_, Int>
//   * &Lazy<nilable<Int>> (static refs to Lazy<…>)
//
// via the `AsRef<Int>` trait. Each wrapper exposes the inner Int.

impl AsRef<Int> for Int {
    fn as_ref(&self) -> &Int { self }
}

impl AsRef<Int> for crate::nilable<Int> {
    #[track_caller]
    fn as_ref(&self) -> &Int {
        self.Must()
    }
}

impl<'a> AsRef<Int> for crate::gonilable_ref::nilable_refmut<'a, Int> {
    #[track_caller]
    fn as_ref(&self) -> &Int {
        // `Must(&self) -> &T` is the borrow-shaped peek on nilable_refmut
        // (panics on nil), matching Go's nil-deref semantics.
        self.Must()
    }
}

impl AsRef<Int> for crate::lazy::Lazy<crate::nilable<Int>> {
    fn as_ref(&self) -> &Int {
        // Lazy: Deref<Target=nilable<Int>>; nilable: AsRef<Int>.
        (**self).as_ref()
    }
}

impl AsRef<Int> for crate::lazy::Lazy<Int> {
    fn as_ref(&self) -> &Int {
        &**self
    }
}

/// Internal: get a `&mut Int` from things that can carry one for
/// the `m` argument of `DivMod`. Used to accept both owned `Int`
/// (by value) and `&mut Int` at call sites.
pub trait AsMutInt {
    fn as_mut_int(&mut self) -> &mut Int;
}

impl AsMutInt for Int {
    fn as_mut_int(&mut self) -> &mut Int { self }
}

impl AsMutInt for &mut Int {
    fn as_mut_int(&mut self) -> &mut Int { *self }
}

impl<'a> AsMutInt for crate::gonilable_ref::nilable_refmut<'a, Int> {
    #[track_caller]
    fn as_mut_int(&mut self) -> &mut Int {
        // `MustMutRef(&mut self)` is the borrow-shaped peek; panics on nil.
        self.MustMutRef()
    }
}

impl AsMutInt for crate::nilable<Int> {
    #[track_caller]
    fn as_mut_int(&mut self) -> &mut Int {
        self.MustMut()
    }
}

/// Internal: an *optional* mutable Int out-parameter. Unlike
/// `AsMutInt` (which panics on nil), this lets a caller pass bare
/// `nil` for an out-parameter it wants to skip — modelling Go's
/// `GCD(x, y, a, b)` where `x` or `y` may be `nil`.
pub trait MaybeMutInt {
    fn maybe_mut_int(&mut self) -> Option<&mut Int>;
}

impl MaybeMutInt for Int {
    fn maybe_mut_int(&mut self) -> Option<&mut Int> { Some(self) }
}

impl MaybeMutInt for &mut Int {
    fn maybe_mut_int(&mut self) -> Option<&mut Int> { Some(*self) }
}

impl MaybeMutInt for crate::nilval::Nil {
    fn maybe_mut_int(&mut self) -> Option<&mut Int> { None }
}

impl<'a> MaybeMutInt for crate::gonilable_ref::nilable_refmut<'a, Int> {
    #[track_caller]
    fn maybe_mut_int(&mut self) -> Option<&mut Int> {
        if self.IsNil() { None } else { Some(self.MustMutRef()) }
    }
}

impl MaybeMutInt for crate::nilable<Int> {
    #[track_caller]
    fn maybe_mut_int(&mut self) -> Option<&mut Int> {
        if self.IsNil() { None } else { Some(self.MustMut()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newint_int64_roundtrip() {
        for &x in &[0i64, 1, -1, 42, -42, 1_000_000, -(1i64 << 40)] {
            assert_eq!(NewInt(x).Int64(), x, "roundtrip {x}");
        }
    }

    #[test]
    fn cmp_basic() {
        assert_eq!(NewInt(1).Cmp(&NewInt(2)), -1);
        assert_eq!(NewInt(2).Cmp(&NewInt(2)), 0);
        assert_eq!(NewInt(3).Cmp(&NewInt(2)), 1);
        assert_eq!(NewInt(-1).Cmp(&NewInt(1)), -1);
    }

    #[test]
    fn mod_small_divisor() {
        // 100 mod 7 = 2
        let mut r = Int::default();
        r.Mod(&NewInt(100), &NewInt(7));
        assert_eq!(r.Int64(), 2);

        // Build a "large" int by hand: 2^40 + 5 == 1099511627781
        let mut big = Int::default();
        big.SetInt64(1_099_511_627_781);
        let mut r2 = Int::default();
        r2.Mod(&big, &NewInt(11));
        // 1099511627781 % 11 == ?
        assert_eq!(r2.Int64(), (1_099_511_627_781i64 % 11));
    }

    #[test]
    fn exp_modular() {
        // 2^10 mod 13 = 1024 mod 13 = 10
        let mut r = Int::default();
        r.Exp(&NewInt(2), &NewInt(10), &NewInt(13));
        assert_eq!(r.Int64(), 10);

        // ROCA fingerprint check: residue r=2 prime p=11 → 2^k mod 11
        // for k=0..11 should cover {1,2,4,8,5,10,9,7,3,6,1} (cycle).
        // The "fingerprint" set is the j values where 2^j ≡ 1 mod 11
        // — only j=0 and j=10 satisfy that.
        let mut found = alloc::vec::Vec::new();
        for j in 0i64..11 {
            let mut acc = Int::default();
            acc.Exp(&NewInt(j), &NewInt(2), &NewInt(11));
            if acc.Cmp(&NewInt(1)) == 0 { found.push(j); }
        }
        // Wait, I had it backwards: rocacheck checks `j^residue mod prime == 1`.
        // For (residue=2, prime=11) ROCA pair: j^2 ≡ 1 mod 11 means j ≡ ±1
        // mod 11, i.e. j ∈ {1, 10}.
        assert_eq!(found, alloc::vec![1, 10]);
    }

    #[test]
    fn mul_signed() {
        // 7 * 6 = 42
        let mut z = Int::default();
        z.Mul(&NewInt(7), &NewInt(6));
        assert_eq!(z.Int64(), 42);

        // -7 * 6 = -42
        let mut z2 = Int::default();
        z2.Mul(&NewInt(-7), &NewInt(6));
        assert_eq!(z2.Int64(), -42);

        // -7 * -6 = 42
        let mut z3 = Int::default();
        z3.Mul(&NewInt(-7), &NewInt(-6));
        assert_eq!(z3.Int64(), 42);

        // 0 * anything = 0 (with sign normalized)
        let mut z4 = Int::default();
        z4.Mul(&NewInt(0), &NewInt(-42));
        assert_eq!(z4.Int64(), 0);
        assert_eq!(z4.Sign(), 0);
    }

    #[test]
    fn abs_basic() {
        let mut z = Int::default();
        z.Abs(&NewInt(-42));
        assert_eq!(z.Int64(), 42);
        z.Abs(&NewInt(42));
        assert_eq!(z.Int64(), 42);

        // Aliasing: z.Abs(z) on a negative z.
        let mut a = NewInt(-9);
        let a_clone = a.clone();
        // Borrow checker: pass &a_clone, but we model the aliasing path
        // separately by self-aliasing through the pointer-eq branch.
        a.Abs(&a_clone);
        assert_eq!(a.Int64(), 9);
    }

    #[test]
    fn div_and_divmod_euclidean() {
        // Positive case: 17 / 5 = 3, 17 mod 5 = 2.
        let mut q = Int::default();
        q.Div(&NewInt(17), &NewInt(5));
        assert_eq!(q.Int64(), 3);

        let mut q2 = Int::default();
        let mut m = Int::default();
        let (_, _) = q2.DivMod(&NewInt(17), &NewInt(5), &mut m);
        assert_eq!(q2.Int64(), 3);
        assert_eq!(m.Int64(), 2);

        // Negative dividend, Euclidean: -17 / 5 = -4, -17 mod 5 = 3
        // (because -17 = (-4)*5 + 3, and 0 ≤ 3 < 5).
        let mut q3 = Int::default();
        let mut m3 = Int::default();
        let (_, _) = q3.DivMod(&NewInt(-17), &NewInt(5), &mut m3);
        assert_eq!(q3.Int64(), -4);
        assert_eq!(m3.Int64(), 3);

        // Negative divisor: -17 / -5 = 4, -17 mod -5 = 3.
        let mut q4 = Int::default();
        let mut m4 = Int::default();
        let (_, _) = q4.DivMod(&NewInt(-17), &NewInt(-5), &mut m4);
        assert_eq!(q4.Int64(), 4);
        assert_eq!(m4.Int64(), 3);
    }

    #[test]
    fn borrow_mut_and_nilable_refmut_as_ref() {
        // BorrowMut wraps &mut Int as nilable_refmut, and AsRef<Int>
        // peeks back through it (panic on nil — non-nil here).
        let mut z = NewInt(99);
        let nrm = z.BorrowMut();
        // Drop nrm to release the borrow before using z.
        assert!(!nrm.IsNil());
        drop(nrm);
        assert_eq!(z.Int64(), 99);
    }

    #[test]
    fn stringer_decimal() {
        use crate::fmt::Stringer;
        assert_eq!(NewInt(0).String().as_bytes(), b"0");
        assert_eq!(NewInt(7).String().as_bytes(), b"7");
        assert_eq!(NewInt(-42).String().as_bytes(), b"-42");
        // Cross the single-limb boundary: 2^33 = 8589934592.
        let mut z = Int::default();
        let _ = z.Mul(NewInt(1 << 16), NewInt(1 << 17));
        assert_eq!(z.String().as_bytes(), b"8589934592");
    }

    #[test]
    fn rat_setint() {
        let mut r = Rat::default();
        r.SetInt(&NewInt(42));
        assert_eq!(r.Num().Int64(), 42);
        assert_eq!(r.Denom().Int64(), 1);
    }

    #[test]
    fn rat_mul_basic() {
        // (2/3) * (3/4) = 6/12 (unreduced — we only reduce when forced).
        let mut a = Rat::default();
        a.SetFrac(&NewInt(2), &NewInt(3));
        let mut b = Rat::default();
        b.SetFrac(&NewInt(3), &NewInt(4));
        let mut c = Rat::default();
        c.Mul(&a, &b);
        assert_eq!(c.Num().Int64(), 6);
        assert_eq!(c.Denom().Int64(), 12);
    }

    #[test]
    fn rat_mul_self_aliasing() {
        // val.Mul(val, mv) — dustin pattern.
        let mut val = Rat::default();
        val.SetFrac(&NewInt(7), &NewInt(2));
        let mut mv = Rat::default();
        mv.SetInt(&NewInt(3)); // 3/1
        let val_snapshot = val.clone();
        val.Mul(&val_snapshot, &mv);
        // 7/2 * 3/1 = 21/2
        assert_eq!(val.Num().Int64(), 21);
        assert_eq!(val.Denom().Int64(), 2);
    }

    #[test]
    fn parse_decimal_into_rat_basic() {
        // "3.14" → 314/100
        let mut r = Rat::default();
        assert!(parse_decimal_into_rat("3.14", &mut r));
        assert_eq!(r.Num().Int64(), 314);
        assert_eq!(r.Denom().Int64(), 100);

        // "100" → 100/1
        let mut r2 = Rat::default();
        assert!(parse_decimal_into_rat("100", &mut r2));
        assert_eq!(r2.Num().Int64(), 100);
        assert_eq!(r2.Denom().Int64(), 1);

        // "-0.5" → -5/10
        let mut r3 = Rat::default();
        assert!(parse_decimal_into_rat("-0.5", &mut r3));
        assert_eq!(r3.Num().Int64(), -5);
        assert_eq!(r3.Denom().Int64(), 10);

        // Bad input.
        let mut r4 = Rat::default();
        assert!(!parse_decimal_into_rat("not-a-number", &mut r4));
    }

    #[test]
    fn int_add_basic() {
        let mut z = Int::default();
        z.Add(&NewInt(2), &NewInt(3));
        assert_eq!(z.Int64(), 5);
        z.Add(&NewInt(-2), &NewInt(7));
        assert_eq!(z.Int64(), 5);
    }
}

// go: none — goish-only: the reflect descriptor for `big.Int`.
//
// Go's `encoding/asn1` matches `reflect.TypeOf(new(big.Int))` — the
// *pointer* type — by identity to give it the INTEGER tag, then hands it
// to makeBigInt. goish's `Int` is a value type, so the identity to match
// is the struct itself. Its two fields (neg, abs) are unexported and are
// never walked, so the field list is empty.
// go: none — goish-only: the field list `__reflect_value` below emits.
//
// Go's `big.Int` fields (`neg`, `abs`) are unexported, so nothing can
// read them through reflect. goish reflects the two values a port needs
// to rebuild an Int. These names describe what is emitted; they are not
// Go's field names, and nothing matches on them.
//
// The list has to exist. `__reflect_type` used to declare `&[]` while
// `__reflect_value` emitted two fields, and that mismatch is not
// cosmetic: `reflect::Zero` builds a struct zero by looping
// `NumField()`, so the zero of an `Int` had no fields and could never
// equal a reflected one. `encoding/asn1`'s `makeField` omits an OPTIONAL
// field with exactly that test — `v == Zero(v.Type())` — so an absent
// OPTIONAL `*big.Int` was *encoded* where Go omits it, which reaches
// `crypto/x509`'s `pkcs1PrivateKey.Dp/Dq/Qinv`. Pinned by
// examples/x509_keys_smoke.rs against `scripts/goref.sh encoding/asn1`.
static INT_FIELDS: [crate::reflect::StructField; 2] = [
    crate::reflect::StructField {
        Name: "neg",
        Tag: crate::reflect::StructTag::__new(""),
        Type: <crate::types::int as crate::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
    crate::reflect::StructField {
        Name: "abs",
        Tag: crate::reflect::StructTag::__new(""),
        Type: <crate::slice<crate::types::byte> as crate::reflect::Reflect>::__reflect_type,
        PkgPath: "",
        Anonymous: false,
    },
];

impl crate::reflect::Reflect for Int {
    // go: none — goish-only: see above.
    fn __reflect_type() -> crate::reflect::Type {
        return crate::reflect::Type::__new(crate::reflect::Kind::Struct, "Int", &INT_FIELDS);
    }

    // go: none — goish-only: see above.
    fn __reflect_value(&self) -> crate::reflect::Value {
        // Sign and big-endian magnitude — enough to rebuild the Int with
        // SetBytes + Neg. A reflected Int that discarded its value would
        // be useless to a port that reads it back, which is what
        // encoding/asn1's makeBody does before calling makeBigInt. See
        // INT_FIELDS above for why the declared list must agree.
        return crate::reflect::Value::Struct {
            ty: <Int as crate::reflect::Reflect>::__reflect_type(),
            fields: alloc::vec![
                crate::reflect::Value::Int(self.Sign()),
                crate::reflect::Reflect::__reflect_value(&self.Bytes()),
            ],
        };
    }
}

// go: none — goish idiom: fill the `#[goish::interface]` downcast
// registries for the types this package declares. See AGENTS.md §9b.
/// Register `math/big`'s types into the `fmt` interface registries.
/// Idempotent; called from `goish::init()`.
pub fn register_big_impls() {
    use crate::fmt::{
        __goish_register_Formatter_impl, __goish_register_Scanner_impl,
        __goish_register_Stringer_impl,
    };
    __goish_register_Stringer_impl::<Int>();
    __goish_register_Stringer_impl::<Float>();
    __goish_register_Stringer_impl::<Rat>();
    __goish_register_Stringer_impl::<Accuracy>();
    __goish_register_Stringer_impl::<RoundingMode>();
    __goish_register_Formatter_impl::<Int>();
    __goish_register_Formatter_impl::<Float>();
    __goish_register_Scanner_impl::<Int>();
    __goish_register_Scanner_impl::<Float>();
    __goish_register_Scanner_impl::<Rat>();
}
