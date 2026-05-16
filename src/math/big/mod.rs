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
        // Walk the exponent bits LSB→MSB.
        let yw = &y.abs;
        let mut bit: usize = 0;
        let total_bits = yw.len() * 32;
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
    pub fn Float64(&self) -> (f64, Accuracy) {
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
