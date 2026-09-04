// big_int_ref_smoke — math/big's Int against a running Go.
// (math/big/int.go, math/big/intconv.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_bigint_ref.go` run in
// `package big` by `scripts/goref.sh`.
//
// math/big is the arithmetic under crypto/rsa, crypto/ecdsa, crypto/dsa
// and x509, so "close enough" is not a category it has. goish had 7009
// lines of it with five anchors and no reference test. Three of its
// rules are the ones a plausible port gets wrong, and all three are
// silent when wrong — the answer is still a number, just not Go's:
//
//   * Div/Mod are EUCLIDEAN: the modulus is never negative, so
//     (-7).Div(2) is -4 and (-7).Mod(2) is 1, while Quo/Rem truncate
//     toward zero and give -3 and -1. Rust's own `/` and `%` truncate,
//     so a port that reaches for them gets Quo/Rem semantics under the
//     Div/Mod names — right for positive operands, wrong for the rest.
//   * The bitwise operators treat a negative Int as an INFINITE two's
//     complement value. (-1) is all ones, so (-1) & x == x and
//     (-1).Not() == 0. A sign-magnitude implementation that combines
//     magnitudes and keeps a sign bit answers differently for every
//     negative operand.
//   * Bit(i) reads that same infinite two's complement, so (-1).Bit(0)
//     is 1 and so is Bit(1000), and Rsh on a negative floors rather
//     than truncating.
//
// goish matches Go on all of those. What it did not match was Exp with
// a negative exponent: Go documents (int.go:563) "if y < 0, and x and m
// are not relatively prime, z is unchanged and nil is returned", and
// goish PANICKED instead. Exp(x, -1, m) is how a caller asks for a
// modular inverse, and whether one exists is a property of operands
// that in crypto can come from the far end of a connection — so that
// turned "no inverse" into a crash on attacker-chosen input. Case 8
// pins it.
//
// Int.String() was also simply missing (Go: intconv.go:39), so the one
// method every %s and %v of an Int goes through did not exist.
//
// Two documented goish deviations are exercised as such: Go returns a
// nil *Int from Exp/ModInverse/ModSqrt where goish returns `&mut Self`
// and leaves the receiver unchanged, and Go's nil modulus is spelled as
// a zero Int. `sentinel` and `nil_or` below make "unchanged" legible as
// Go's "<nil>" so the two sides can be compared line for line.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::goslice::slice;
use goish::gostring::string;
use goish::math::big;
use goish::types::int;
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}
fn n(v: i64) -> big::Int {
    return big::NewInt(v);
}
fn zero() -> big::Int {
    return big::Int::new();
}
// Go returns a nil *Int from ModInverse/ModSqrt when there is no
// answer; goish leaves the receiver untouched (documented at both
// sites). Seed the receiver with a sentinel so "untouched" is legible
// as Go's "<nil>".
fn sentinel() -> big::Int {
    let mut z = big::Int::new();
    z.SetInt64(-987654321);
    return z;
}
fn nil_or(z: &big::Int) -> string {
    let mut sen = sentinel();
    if z.Cmp(&sen) == 0 {
        return s("<nil>");
    }
    let _ = &mut sen;
    return z.String();
}

// go: none — goish idiom: the reference lines, in the order Go printed
//     them. Comparing whole rendered lines keeps this smoke and the
//     generator in lockstep: a case added to one is a mismatch in the
//     other, never a silent pass.
const GO: [&str; 385] = [
    "divmod     7     2 -> div=3     mod=1    quo=3     rem=1     divmod=(3,1) quorem=(3,1)",
    "divmod     7    -2 -> div=-3    mod=1    quo=-3    rem=1     divmod=(-3,1) quorem=(-3,1)",
    "divmod     7     3 -> div=2     mod=1    quo=2     rem=1     divmod=(2,1) quorem=(2,1)",
    "divmod     7    -3 -> div=-2    mod=1    quo=-2    rem=1     divmod=(-2,1) quorem=(-2,1)",
    "divmod     7     7 -> div=1     mod=0    quo=1     rem=0     divmod=(1,0) quorem=(1,0)",
    "divmod     7    -7 -> div=-1    mod=0    quo=-1    rem=0     divmod=(-1,0) quorem=(-1,0)",
    "divmod     7     1 -> div=7     mod=0    quo=7     rem=0     divmod=(7,0) quorem=(7,0)",
    "divmod     7    -1 -> div=-7    mod=0    quo=-7    rem=0     divmod=(-7,0) quorem=(-7,0)",
    "divmod    -7     2 -> div=-4    mod=1    quo=-3    rem=-1    divmod=(-4,1) quorem=(-3,-1)",
    "divmod    -7    -2 -> div=4     mod=1    quo=3     rem=-1    divmod=(4,1) quorem=(3,-1)",
    "divmod    -7     3 -> div=-3    mod=2    quo=-2    rem=-1    divmod=(-3,2) quorem=(-2,-1)",
    "divmod    -7    -3 -> div=3     mod=2    quo=2     rem=-1    divmod=(3,2) quorem=(2,-1)",
    "divmod    -7     7 -> div=-1    mod=0    quo=-1    rem=0     divmod=(-1,0) quorem=(-1,0)",
    "divmod    -7    -7 -> div=1     mod=0    quo=1     rem=0     divmod=(1,0) quorem=(1,0)",
    "divmod    -7     1 -> div=-7    mod=0    quo=-7    rem=0     divmod=(-7,0) quorem=(-7,0)",
    "divmod    -7    -1 -> div=7     mod=0    quo=7     rem=0     divmod=(7,0) quorem=(7,0)",
    "divmod     8     2 -> div=4     mod=0    quo=4     rem=0     divmod=(4,0) quorem=(4,0)",
    "divmod     8    -2 -> div=-4    mod=0    quo=-4    rem=0     divmod=(-4,0) quorem=(-4,0)",
    "divmod     8     3 -> div=2     mod=2    quo=2     rem=2     divmod=(2,2) quorem=(2,2)",
    "divmod     8    -3 -> div=-2    mod=2    quo=-2    rem=2     divmod=(-2,2) quorem=(-2,2)",
    "divmod     8     7 -> div=1     mod=1    quo=1     rem=1     divmod=(1,1) quorem=(1,1)",
    "divmod     8    -7 -> div=-1    mod=1    quo=-1    rem=1     divmod=(-1,1) quorem=(-1,1)",
    "divmod     8     1 -> div=8     mod=0    quo=8     rem=0     divmod=(8,0) quorem=(8,0)",
    "divmod     8    -1 -> div=-8    mod=0    quo=-8    rem=0     divmod=(-8,0) quorem=(-8,0)",
    "divmod    -8     2 -> div=-4    mod=0    quo=-4    rem=0     divmod=(-4,0) quorem=(-4,0)",
    "divmod    -8    -2 -> div=4     mod=0    quo=4     rem=0     divmod=(4,0) quorem=(4,0)",
    "divmod    -8     3 -> div=-3    mod=1    quo=-2    rem=-2    divmod=(-3,1) quorem=(-2,-2)",
    "divmod    -8    -3 -> div=3     mod=1    quo=2     rem=-2    divmod=(3,1) quorem=(2,-2)",
    "divmod    -8     7 -> div=-2    mod=6    quo=-1    rem=-1    divmod=(-2,6) quorem=(-1,-1)",
    "divmod    -8    -7 -> div=2     mod=6    quo=1     rem=-1    divmod=(2,6) quorem=(1,-1)",
    "divmod    -8     1 -> div=-8    mod=0    quo=-8    rem=0     divmod=(-8,0) quorem=(-8,0)",
    "divmod    -8    -1 -> div=8     mod=0    quo=8     rem=0     divmod=(8,0) quorem=(8,0)",
    "divmod     0     2 -> div=0     mod=0    quo=0     rem=0     divmod=(0,0) quorem=(0,0)",
    "divmod     0    -2 -> div=0     mod=0    quo=0     rem=0     divmod=(0,0) quorem=(0,0)",
    "divmod     0     3 -> div=0     mod=0    quo=0     rem=0     divmod=(0,0) quorem=(0,0)",
    "divmod     0    -3 -> div=0     mod=0    quo=0     rem=0     divmod=(0,0) quorem=(0,0)",
    "divmod     0     7 -> div=0     mod=0    quo=0     rem=0     divmod=(0,0) quorem=(0,0)",
    "divmod     0    -7 -> div=0     mod=0    quo=0     rem=0     divmod=(0,0) quorem=(0,0)",
    "divmod     0     1 -> div=0     mod=0    quo=0     rem=0     divmod=(0,0) quorem=(0,0)",
    "divmod     0    -1 -> div=0     mod=0    quo=0     rem=0     divmod=(0,0) quorem=(0,0)",
    "divmod     1     2 -> div=0     mod=1    quo=0     rem=1     divmod=(0,1) quorem=(0,1)",
    "divmod     1    -2 -> div=0     mod=1    quo=0     rem=1     divmod=(0,1) quorem=(0,1)",
    "divmod     1     3 -> div=0     mod=1    quo=0     rem=1     divmod=(0,1) quorem=(0,1)",
    "divmod     1    -3 -> div=0     mod=1    quo=0     rem=1     divmod=(0,1) quorem=(0,1)",
    "divmod     1     7 -> div=0     mod=1    quo=0     rem=1     divmod=(0,1) quorem=(0,1)",
    "divmod     1    -7 -> div=0     mod=1    quo=0     rem=1     divmod=(0,1) quorem=(0,1)",
    "divmod     1     1 -> div=1     mod=0    quo=1     rem=0     divmod=(1,0) quorem=(1,0)",
    "divmod     1    -1 -> div=-1    mod=0    quo=-1    rem=0     divmod=(-1,0) quorem=(-1,0)",
    "divmod    -1     2 -> div=-1    mod=1    quo=0     rem=-1    divmod=(-1,1) quorem=(0,-1)",
    "divmod    -1    -2 -> div=1     mod=1    quo=0     rem=-1    divmod=(1,1) quorem=(0,-1)",
    "divmod    -1     3 -> div=-1    mod=2    quo=0     rem=-1    divmod=(-1,2) quorem=(0,-1)",
    "divmod    -1    -3 -> div=1     mod=2    quo=0     rem=-1    divmod=(1,2) quorem=(0,-1)",
    "divmod    -1     7 -> div=-1    mod=6    quo=0     rem=-1    divmod=(-1,6) quorem=(0,-1)",
    "divmod    -1    -7 -> div=1     mod=6    quo=0     rem=-1    divmod=(1,6) quorem=(0,-1)",
    "divmod    -1     1 -> div=-1    mod=0    quo=-1    rem=0     divmod=(-1,0) quorem=(-1,0)",
    "divmod    -1    -1 -> div=1     mod=0    quo=1     rem=0     divmod=(1,0) quorem=(1,0)",
    "divmod   100     2 -> div=50    mod=0    quo=50    rem=0     divmod=(50,0) quorem=(50,0)",
    "divmod   100    -2 -> div=-50   mod=0    quo=-50   rem=0     divmod=(-50,0) quorem=(-50,0)",
    "divmod   100     3 -> div=33    mod=1    quo=33    rem=1     divmod=(33,1) quorem=(33,1)",
    "divmod   100    -3 -> div=-33   mod=1    quo=-33   rem=1     divmod=(-33,1) quorem=(-33,1)",
    "divmod   100     7 -> div=14    mod=2    quo=14    rem=2     divmod=(14,2) quorem=(14,2)",
    "divmod   100    -7 -> div=-14   mod=2    quo=-14   rem=2     divmod=(-14,2) quorem=(-14,2)",
    "divmod   100     1 -> div=100   mod=0    quo=100   rem=0     divmod=(100,0) quorem=(100,0)",
    "divmod   100    -1 -> div=-100  mod=0    quo=-100  rem=0     divmod=(-100,0) quorem=(-100,0)",
    "divmod  -100     2 -> div=-50   mod=0    quo=-50   rem=0     divmod=(-50,0) quorem=(-50,0)",
    "divmod  -100    -2 -> div=50    mod=0    quo=50    rem=0     divmod=(50,0) quorem=(50,0)",
    "divmod  -100     3 -> div=-34   mod=2    quo=-33   rem=-1    divmod=(-34,2) quorem=(-33,-1)",
    "divmod  -100    -3 -> div=34    mod=2    quo=33    rem=-1    divmod=(34,2) quorem=(33,-1)",
    "divmod  -100     7 -> div=-15   mod=5    quo=-14   rem=-2    divmod=(-15,5) quorem=(-14,-2)",
    "divmod  -100    -7 -> div=15    mod=5    quo=14    rem=-2    divmod=(15,5) quorem=(14,-2)",
    "divmod  -100     1 -> div=-100  mod=0    quo=-100  rem=0     divmod=(-100,0) quorem=(-100,0)",
    "divmod  -100    -1 -> div=100   mod=0    quo=100   rem=0     divmod=(100,0) quorem=(100,0)",
    "bitwise     0     0 -> and=0      or=0      xor=0      andnot=0     ",
    "bitwise     0     1 -> and=0      or=1      xor=1      andnot=0     ",
    "bitwise     0    -1 -> and=0      or=-1     xor=-1     andnot=0     ",
    "bitwise     0     3 -> and=0      or=3      xor=3      andnot=0     ",
    "bitwise     0    -3 -> and=0      or=-3     xor=-3     andnot=0     ",
    "bitwise     0   255 -> and=0      or=255    xor=255    andnot=0     ",
    "bitwise     0  -255 -> and=0      or=-255   xor=-255   andnot=0     ",
    "bitwise     1     0 -> and=0      or=1      xor=1      andnot=1     ",
    "bitwise     1     1 -> and=1      or=1      xor=0      andnot=0     ",
    "bitwise     1    -1 -> and=1      or=-1     xor=-2     andnot=0     ",
    "bitwise     1     3 -> and=1      or=3      xor=2      andnot=0     ",
    "bitwise     1    -3 -> and=1      or=-3     xor=-4     andnot=0     ",
    "bitwise     1   255 -> and=1      or=255    xor=254    andnot=0     ",
    "bitwise     1  -255 -> and=1      or=-255   xor=-256   andnot=0     ",
    "bitwise    -1     0 -> and=0      or=-1     xor=-1     andnot=-1    ",
    "bitwise    -1     1 -> and=1      or=-1     xor=-2     andnot=-2    ",
    "bitwise    -1    -1 -> and=-1     or=-1     xor=0      andnot=0     ",
    "bitwise    -1     3 -> and=3      or=-1     xor=-4     andnot=-4    ",
    "bitwise    -1    -3 -> and=-3     or=-1     xor=2      andnot=2     ",
    "bitwise    -1   255 -> and=255    or=-1     xor=-256   andnot=-256  ",
    "bitwise    -1  -255 -> and=-255   or=-1     xor=254    andnot=254   ",
    "bitwise     5     0 -> and=0      or=5      xor=5      andnot=5     ",
    "bitwise     5     1 -> and=1      or=5      xor=4      andnot=4     ",
    "bitwise     5    -1 -> and=5      or=-1     xor=-6     andnot=0     ",
    "bitwise     5     3 -> and=1      or=7      xor=6      andnot=4     ",
    "bitwise     5    -3 -> and=5      or=-3     xor=-8     andnot=0     ",
    "bitwise     5   255 -> and=5      or=255    xor=250    andnot=0     ",
    "bitwise     5  -255 -> and=1      or=-251   xor=-252   andnot=4     ",
    "bitwise    -5     0 -> and=0      or=-5     xor=-5     andnot=-5    ",
    "bitwise    -5     1 -> and=1      or=-5     xor=-6     andnot=-6    ",
    "bitwise    -5    -1 -> and=-5     or=-1     xor=4      andnot=0     ",
    "bitwise    -5     3 -> and=3      or=-5     xor=-8     andnot=-8    ",
    "bitwise    -5    -3 -> and=-7     or=-1     xor=6      andnot=2     ",
    "bitwise    -5   255 -> and=251    or=-1     xor=-252   andnot=-256  ",
    "bitwise    -5  -255 -> and=-255   or=-5     xor=250    andnot=250   ",
    "bitwise     6     0 -> and=0      or=6      xor=6      andnot=6     ",
    "bitwise     6     1 -> and=0      or=7      xor=7      andnot=6     ",
    "bitwise     6    -1 -> and=6      or=-1     xor=-7     andnot=0     ",
    "bitwise     6     3 -> and=2      or=7      xor=5      andnot=4     ",
    "bitwise     6    -3 -> and=4      or=-1     xor=-5     andnot=2     ",
    "bitwise     6   255 -> and=6      or=255    xor=249    andnot=0     ",
    "bitwise     6  -255 -> and=0      or=-249   xor=-249   andnot=6     ",
    "bitwise    -6     0 -> and=0      or=-6     xor=-6     andnot=-6    ",
    "bitwise    -6     1 -> and=0      or=-5     xor=-5     andnot=-6    ",
    "bitwise    -6    -1 -> and=-6     or=-1     xor=5      andnot=0     ",
    "bitwise    -6     3 -> and=2      or=-5     xor=-7     andnot=-8    ",
    "bitwise    -6    -3 -> and=-8     or=-1     xor=7      andnot=2     ",
    "bitwise    -6   255 -> and=250    or=-1     xor=-251   andnot=-256  ",
    "bitwise    -6  -255 -> and=-256   or=-5     xor=251    andnot=250   ",
    "bitwise   255     0 -> and=0      or=255    xor=255    andnot=255   ",
    "bitwise   255     1 -> and=1      or=255    xor=254    andnot=254   ",
    "bitwise   255    -1 -> and=255    or=-1     xor=-256   andnot=0     ",
    "bitwise   255     3 -> and=3      or=255    xor=252    andnot=252   ",
    "bitwise   255    -3 -> and=253    or=-1     xor=-254   andnot=2     ",
    "bitwise   255   255 -> and=255    or=255    xor=0      andnot=0     ",
    "bitwise   255  -255 -> and=1      or=-1     xor=-2     andnot=254   ",
    "bitwise  -255     0 -> and=0      or=-255   xor=-255   andnot=-255  ",
    "bitwise  -255     1 -> and=1      or=-255   xor=-256   andnot=-256  ",
    "bitwise  -255    -1 -> and=-255   or=-1     xor=254    andnot=0     ",
    "bitwise  -255     3 -> and=1      or=-253   xor=-254   andnot=-256  ",
    "bitwise  -255    -3 -> and=-255   or=-3     xor=252    andnot=0     ",
    "bitwise  -255   255 -> and=1      or=-1     xor=-2     andnot=-256  ",
    "bitwise  -255  -255 -> and=-255   or=-255   xor=0      andnot=0     ",
    "bitwise  -256     0 -> and=0      or=-256   xor=-256   andnot=-256  ",
    "bitwise  -256     1 -> and=0      or=-255   xor=-255   andnot=-256  ",
    "bitwise  -256    -1 -> and=-256   or=-1     xor=255    andnot=0     ",
    "bitwise  -256     3 -> and=0      or=-253   xor=-253   andnot=-256  ",
    "bitwise  -256    -3 -> and=-256   or=-3     xor=253    andnot=0     ",
    "bitwise  -256   255 -> and=0      or=-1     xor=-1     andnot=-256  ",
    "bitwise  -256  -255 -> and=-256   or=-255   xor=1      andnot=0     ",
    "bitwise  1024     0 -> and=0      or=1024   xor=1024   andnot=1024  ",
    "bitwise  1024     1 -> and=0      or=1025   xor=1025   andnot=1024  ",
    "bitwise  1024    -1 -> and=1024   or=-1     xor=-1025  andnot=0     ",
    "bitwise  1024     3 -> and=0      or=1027   xor=1027   andnot=1024  ",
    "bitwise  1024    -3 -> and=1024   or=-3     xor=-1027  andnot=0     ",
    "bitwise  1024   255 -> and=0      or=1279   xor=1279   andnot=1024  ",
    "bitwise  1024  -255 -> and=1024   or=-255   xor=-1279  andnot=0     ",
    "bitwise -1024     0 -> and=0      or=-1024  xor=-1024  andnot=-1024 ",
    "bitwise -1024     1 -> and=0      or=-1023  xor=-1023  andnot=-1024 ",
    "bitwise -1024    -1 -> and=-1024  or=-1     xor=1023   andnot=0     ",
    "bitwise -1024     3 -> and=0      or=-1021  xor=-1021  andnot=-1024 ",
    "bitwise -1024    -3 -> and=-1024  or=-3     xor=1021   andnot=0     ",
    "bitwise -1024   255 -> and=0      or=-769   xor=-769   andnot=-1024 ",
    "bitwise -1024  -255 -> and=-1024  or=-255   xor=769    andnot=0     ",
    "not     0 -> -1",
    "not     1 -> -2",
    "not    -1 -> 0",
    "not     5 -> -6",
    "not    -5 -> 4",
    "not   255 -> -256",
    "not  -255 -> 254",
    "not  -256 -> 255",
    "bits     0 -> len=0   tz=0    b0=0 b1=0 b2=0 b7=0 b8=0 b100=0",
    "bits     1 -> len=1   tz=0    b0=1 b1=0 b2=0 b7=0 b8=0 b100=0",
    "bits    -1 -> len=1   tz=0    b0=1 b1=1 b2=1 b7=1 b8=1 b100=1",
    "bits     5 -> len=3   tz=0    b0=1 b1=0 b2=1 b7=0 b8=0 b100=0",
    "bits    -5 -> len=3   tz=0    b0=1 b1=1 b2=0 b7=1 b8=1 b100=1",
    "bits     8 -> len=4   tz=3    b0=0 b1=0 b2=0 b7=0 b8=0 b100=0",
    "bits    -8 -> len=4   tz=3    b0=0 b1=0 b2=0 b7=1 b8=1 b100=1",
    "bits   255 -> len=8   tz=0    b0=1 b1=1 b2=1 b7=1 b8=0 b100=0",
    "bits  -255 -> len=8   tz=0    b0=1 b1=0 b2=0 b7=0 b8=1 b100=1",
    "bits  -256 -> len=9   tz=8    b0=0 b1=0 b2=0 b7=0 b8=1 b100=1",
    "setbit     0 i=0 v=0 -> 0",
    "setbit     0 i=0 v=1 -> 1",
    "setbit     0 i=1 v=0 -> 0",
    "setbit     0 i=1 v=1 -> 2",
    "setbit     0 i=7 v=0 -> 0",
    "setbit     0 i=7 v=1 -> 128",
    "setbit     1 i=0 v=0 -> 0",
    "setbit     1 i=0 v=1 -> 1",
    "setbit     1 i=1 v=0 -> 1",
    "setbit     1 i=1 v=1 -> 3",
    "setbit     1 i=7 v=0 -> 1",
    "setbit     1 i=7 v=1 -> 129",
    "setbit    -1 i=0 v=0 -> -2",
    "setbit    -1 i=0 v=1 -> -1",
    "setbit    -1 i=1 v=0 -> -3",
    "setbit    -1 i=1 v=1 -> -1",
    "setbit    -1 i=7 v=0 -> -129",
    "setbit    -1 i=7 v=1 -> -1",
    "setbit     5 i=0 v=0 -> 4",
    "setbit     5 i=0 v=1 -> 5",
    "setbit     5 i=1 v=0 -> 5",
    "setbit     5 i=1 v=1 -> 7",
    "setbit     5 i=7 v=0 -> 5",
    "setbit     5 i=7 v=1 -> 133",
    "setbit    -5 i=0 v=0 -> -6",
    "setbit    -5 i=0 v=1 -> -5",
    "setbit    -5 i=1 v=0 -> -7",
    "setbit    -5 i=1 v=1 -> -5",
    "setbit    -5 i=7 v=0 -> -133",
    "setbit    -5 i=7 v=1 -> -5",
    "setbit  -256 i=0 v=0 -> -256",
    "setbit  -256 i=0 v=1 -> -255",
    "setbit  -256 i=1 v=0 -> -256",
    "setbit  -256 i=1 v=1 -> -254",
    "setbit  -256 i=7 v=0 -> -256",
    "setbit  -256 i=7 v=1 -> -128",
    "shift     1 n=0   -> lsh=1                        rsh=1",
    "shift     1 n=1   -> lsh=2                        rsh=0",
    "shift     1 n=3   -> lsh=8                        rsh=0",
    "shift     1 n=8   -> lsh=256                      rsh=0",
    "shift     1 n=64  -> lsh=18446744073709551616     rsh=0",
    "shift    -1 n=0   -> lsh=-1                       rsh=-1",
    "shift    -1 n=1   -> lsh=-2                       rsh=-1",
    "shift    -1 n=3   -> lsh=-8                       rsh=-1",
    "shift    -1 n=8   -> lsh=-256                     rsh=-1",
    "shift    -1 n=64  -> lsh=-18446744073709551616    rsh=-1",
    "shift     5 n=0   -> lsh=5                        rsh=5",
    "shift     5 n=1   -> lsh=10                       rsh=2",
    "shift     5 n=3   -> lsh=40                       rsh=0",
    "shift     5 n=8   -> lsh=1280                     rsh=0",
    "shift     5 n=64  -> lsh=92233720368547758080     rsh=0",
    "shift    -5 n=0   -> lsh=-5                       rsh=-5",
    "shift    -5 n=1   -> lsh=-10                      rsh=-3",
    "shift    -5 n=3   -> lsh=-40                      rsh=-1",
    "shift    -5 n=8   -> lsh=-1280                    rsh=-1",
    "shift    -5 n=64  -> lsh=-92233720368547758080    rsh=-1",
    "shift     8 n=0   -> lsh=8                        rsh=8",
    "shift     8 n=1   -> lsh=16                       rsh=4",
    "shift     8 n=3   -> lsh=64                       rsh=1",
    "shift     8 n=8   -> lsh=2048                     rsh=0",
    "shift     8 n=64  -> lsh=147573952589676412928    rsh=0",
    "shift    -8 n=0   -> lsh=-8                       rsh=-8",
    "shift    -8 n=1   -> lsh=-16                      rsh=-4",
    "shift    -8 n=3   -> lsh=-64                      rsh=-1",
    "shift    -8 n=8   -> lsh=-2048                    rsh=-1",
    "shift    -8 n=64  -> lsh=-147573952589676412928   rsh=-1",
    "shift   255 n=0   -> lsh=255                      rsh=255",
    "shift   255 n=1   -> lsh=510                      rsh=127",
    "shift   255 n=3   -> lsh=2040                     rsh=31",
    "shift   255 n=8   -> lsh=65280                    rsh=0",
    "shift   255 n=64  -> lsh=4703919738795935662080   rsh=0",
    "shift  -255 n=0   -> lsh=-255                     rsh=-255",
    "shift  -255 n=1   -> lsh=-510                     rsh=-128",
    "shift  -255 n=3   -> lsh=-2040                    rsh=-32",
    "shift  -255 n=8   -> lsh=-65280                   rsh=-1",
    "shift  -255 n=64  -> lsh=-4703919738795935662080  rsh=-1",
    "shift  -256 n=0   -> lsh=-256                     rsh=-256",
    "shift  -256 n=1   -> lsh=-512                     rsh=-128",
    "shift  -256 n=3   -> lsh=-2048                    rsh=-32",
    "shift  -256 n=8   -> lsh=-65536                   rsh=-1",
    "shift  -256 n=64  -> lsh=-4722366482869645213696  rsh=-1",
    "text           0 -> b2=0                              b8=0            b10=0           b16=0         b36=0 str=0",
    "text           1 -> b2=1                              b8=1            b10=1           b16=1         b36=1 str=1",
    "text          -1 -> b2=-1                             b8=-1           b10=-1          b16=-1        b36=-1 str=-1",
    "text         255 -> b2=11111111                       b8=377          b10=255         b16=ff        b36=73 str=255",
    "text        -255 -> b2=-11111111                      b8=-377         b10=-255        b16=-ff       b36=-73 str=-255",
    "text   123456789 -> b2=111010110111100110100010101    b8=726746425    b10=123456789   b16=75bcd15   b36=21i3v9 str=123456789",
    "text  -123456789 -> b2=-111010110111100110100010101   b8=-726746425   b10=-123456789  b16=-75bcd15  b36=-21i3v9 str=-123456789",
    "setstring \"0\"      base=10  -> 0,true",
    "setstring \"-0\"     base=10  -> 0,true",
    "setstring \"+42\"    base=10  -> 42,true",
    "setstring \"42\"     base=10  -> 42,true",
    "setstring \"  42\"   base=10  -> nil,false",
    "setstring \"42 \"    base=10  -> nil,false",
    "setstring \"\"       base=10  -> nil,false",
    "setstring \"-\"      base=10  -> nil,false",
    "setstring \"0x1f\"   base=0   -> 31,true",
    "setstring \"0X1F\"   base=0   -> 31,true",
    "setstring \"0b101\"  base=0   -> 5,true",
    "setstring \"0o17\"   base=0   -> 15,true",
    "setstring \"017\"    base=0   -> 15,true",
    "setstring \"0_1_7\"  base=0   -> 15,true",
    "setstring \"1_000\"  base=0   -> 1000,true",
    "setstring \"1_000\"  base=10  -> nil,false",
    "setstring \"_100\"   base=0   -> nil,false",
    "setstring \"100_\"   base=0   -> nil,false",
    "setstring \"0x\"     base=0   -> nil,false",
    "setstring \"ff\"     base=16  -> 255,true",
    "setstring \"FF\"     base=16  -> 255,true",
    "setstring \"zz\"     base=36  -> 1295,true",
    "setstring \"zz\"     base=35  -> nil,false",
    "setstring \"-0x10\"  base=0   -> -16,true",
    "setstring \"1e3\"    base=10  -> nil,false",
    "setstring \"0x1f\"   base=16  -> nil,false",
    "setstring \"0\"      base=0   -> 0,true",
    "setstring \"00\"     base=0   -> 0,true",
    "setstring \"08\"     base=0   -> nil,false",
    "bytes            0 ->  fill8=0000000000000000 back=0",
    "bytes            1 -> 01 fill8=0000000000000001 back=1",
    "bytes           -1 -> 01 fill8=0000000000000001 back=1",
    "bytes          255 -> ff fill8=00000000000000ff back=255",
    "bytes          256 -> 0100 fill8=0000000000000100 back=256",
    "bytes        65535 -> ffff fill8=000000000000ffff back=65535",
    "bytes       -65535 -> ffff fill8=000000000000ffff back=65535",
    "bytes 1099511627776 -> 010000000000 fill8=0000010000000000 back=1099511627776",
    "exp   2^10   mod 0      -> 1024",
    "exp   2^10   mod 1000   -> 24",
    "exp   2^0    mod 7      -> 1",
    "exp   0^0    mod 0      -> 1",
    "exp   3^100  mod 7      -> 4",
    "exp  -3^3    mod 0      -> -27",
    "exp  -3^3    mod 7      -> 1",
    "exp  -3^2    mod 7      -> 2",
    "exp   2^-1   mod 7      -> 4",
    "exp   2^-1   mod 0      -> 1",
    "exp   5^-1   mod 7      -> 3",
    "exp   7^-1   mod 7      -> <nil>",
    "exp   2^10   mod -1000  -> 24",
    "gcd    12    18 -> g=6 x=-1 y=1",
    "gcd    17     5 -> g=1 x=-2 y=7",
    "gcd     0     5 -> skipped (GCD requires a,b > 0)",
    "gcd     5     0 -> skipped (GCD requires a,b > 0)",
    "gcd     0     0 -> skipped (GCD requires a,b > 0)",
    "gcd   -12    18 -> skipped (GCD requires a,b > 0)",
    "gcd    12   -18 -> skipped (GCD requires a,b > 0)",
    "gcd   270   192 -> g=6 x=5 y=-7",
    "modinv     3 mod 7    -> 5",
    "modinv     2 mod 7    -> 4",
    "modinv     6 mod 9    -> <nil>",
    "modinv     1 mod 7    -> 1",
    "modinv    -3 mod 7    -> 2",
    "modinv     3 mod 1    -> 0",
    "modsqrt     4 mod 7    -> 2",
    "modsqrt     2 mod 7    -> 4",
    "modsqrt     2 mod 17   -> 6",
    "modsqrt     0 mod 7    -> 0",
    "modsqrt     9 mod 13   -> 3",
    "unary                     0 -> abs=0                     neg=0                      sign=0  sqrt=0",
    "unary                     1 -> abs=1                     neg=-1                     sign=1  sqrt=1",
    "unary                    -1 -> abs=1                     neg=1                      sign=-1 sqrt=n/a",
    "unary                     2 -> abs=2                     neg=-2                     sign=1  sqrt=1",
    "unary                    -2 -> abs=2                     neg=2                      sign=-1 sqrt=n/a",
    "unary                     7 -> abs=7                     neg=-7                     sign=1  sqrt=2",
    "unary                    -7 -> abs=7                     neg=7                      sign=-1 sqrt=n/a",
    "unary                     8 -> abs=8                     neg=-8                     sign=1  sqrt=2",
    "unary                    -8 -> abs=8                     neg=8                      sign=-1 sqrt=n/a",
    "unary                   255 -> abs=255                   neg=-255                   sign=1  sqrt=15",
    "unary                  -255 -> abs=255                   neg=255                    sign=-1 sqrt=n/a",
    "unary                   256 -> abs=256                   neg=-256                   sign=1  sqrt=16",
    "unary                  -256 -> abs=256                   neg=256                    sign=-1 sqrt=n/a",
    "unary               1048576 -> abs=1048576               neg=-1048576               sign=1  sqrt=1024",
    "unary              -1048576 -> abs=1048576               neg=1048576                sign=-1 sqrt=n/a",
    "unary   4611686018427387903 -> abs=4611686018427387903   neg=-4611686018427387903   sign=1  sqrt=2147483647",
    "unary  -4611686018427387903 -> abs=4611686018427387903   neg=4611686018427387903    sign=-1 sqrt=n/a",
    "cmp  -5  -5 -> cmp=0  cmpabs=0",
    "cmp  -5   0 -> cmp=-1 cmpabs=1",
    "cmp  -5   5 -> cmp=-1 cmpabs=0",
    "cmp   0  -5 -> cmp=1  cmpabs=-1",
    "cmp   0   0 -> cmp=0  cmpabs=0",
    "cmp   0   5 -> cmp=-1 cmpabs=-1",
    "cmp   5  -5 -> cmp=1  cmpabs=0",
    "cmp   5   0 -> cmp=1  cmpabs=1",
    "cmp   5   5 -> cmp=0  cmpabs=0",
    "range 0                     -> isi64=true  isu64=true  i64=0                     u64=0",
    "range 1                     -> isi64=true  isu64=true  i64=1                     u64=1",
    "range -1                    -> isi64=true  isu64=false i64=-1                    u64=1",
    "range 9223372036854775807   -> isi64=true  isu64=true  i64=9223372036854775807   u64=9223372036854775807",
    "range 9223372036854775808   -> isi64=false isu64=true  i64=-9223372036854775808  u64=9223372036854775808",
    "range -9223372036854775808  -> isi64=true  isu64=false i64=-9223372036854775808  u64=9223372036854775808",
    "range -9223372036854775809  -> isi64=false isu64=false i64=9223372036854775807   u64=9223372036854775809",
    "range 18446744073709551615  -> isi64=false isu64=true  i64=-1                    u64=18446744073709551615",
    "range 18446744073709551616  -> isi64=false isu64=false i64=0                     u64=0",
    "prime 0                                        -> n0=false n20=false",
    "prime 1                                        -> n0=false n20=false",
    "prime 2                                        -> n0=true  n20=true",
    "prime 3                                        -> n0=true  n20=true",
    "prime 4                                        -> n0=false n20=false",
    "prime 561                                      -> n0=false n20=false",
    "prime 1105                                     -> n0=false n20=false",
    "prime 7919                                     -> n0=true  n20=true",
    "prime 104729                                   -> n0=true  n20=true",
    "prime 170141183460469231731687303715884105727  -> n0=true  n20=true",
    "big add=1111111110111111111011111111100",
    "big sub=-864197532086419753208641975320",
    "big mul=121932631137021795226185032733622923332237463801111263526900",
    "big quo=8 rem=9000000000900000000090",
    "big div=-9 mod=123456780012345678001234567800",
    "big exp=115792089237316195423570985008687907853269984665640564039457584007913129639936",
    "big hex=10000000000000000000000000000000000000000000000000000000000000000",
    "big bytes=0100000000000000000000000000000000000000000000000000",
    "big bitlen=257",
];

// go: none — goish idiom: one comparison, printing the divergence when
//     it is one, so a FAIL says what it got and not just that it did.
fn chk(failed: &mut int, ln: &mut int, got: string) {
    if *ln >= GO.len() as int {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln + 1, got);
        *failed += 1;
        *ln += 1;
        return;
    }
    let want = s(GO[*ln as usize]);
    *ln += 1;
    if got == want {
        return;
    }
    fmt::Printf!("[!!] line %d FAIL\n  got  %q\n  want %q\n", *ln, got, want);
    *failed += 1;
}

#[goish::main]
fn main() {
    let mut failed: int = 0;
    let mut ln: int = 0;

    let vals: [i64; 17] = [
        0,
        1,
        -1,
        2,
        -2,
        7,
        -7,
        8,
        -8,
        255,
        -255,
        256,
        -256,
        1 << 20,
        -(1 << 20),
        (1i64 << 62) - 1,
        -((1i64 << 62) - 1),
    ];
    // 1
    for a in [7i64, -7, 8, -8, 0, 1, -1, 100, -100] {
        for b in [2i64, -2, 3, -3, 7, -7, 1, -1] {
            let (x, y) = (n(a), n(b));
            let mut d = zero();
            d.Div(&x, &y);
            let mut m = zero();
            m.Mod(&x, &y);
            let mut q = zero();
            q.Quo(&x, &y);
            let mut r = zero();
            r.Rem(&x, &y);
            let mut dm = zero();
            let mut dmr = zero();
            dm.DivMod(&x, &y, &mut dmr);
            let mut qr = zero();
            let mut qrr = zero();
            qr.QuoRem(&x, &y, &mut qrr);
            chk(&mut failed, &mut ln, fmt::Sprintf!("divmod %5d %5d -> div=%-5s mod=%-4s quo=%-5s rem=%-5s divmod=(%s,%s) quorem=(%s,%s)",
                a, b, d.String(), m.String(), q.String(), r.String(),
                dm.String(), dmr.String(), qr.String(), qrr.String()));
        }
    }
    // 2
    for a in [0i64, 1, -1, 5, -5, 6, -6, 255, -255, -256, 1024, -1024] {
        for b in [0i64, 1, -1, 3, -3, 255, -255] {
            let (x, y) = (n(a), n(b));
            let mut r1 = zero();
            r1.And(&x, &y);
            let mut r2 = zero();
            r2.Or(&x, &y);
            let mut r3 = zero();
            r3.Xor(&x, &y);
            let mut r4 = zero();
            r4.AndNot(&x, &y);
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "bitwise %5d %5d -> and=%-6s or=%-6s xor=%-6s andnot=%-6s",
                    a,
                    b,
                    r1.String(),
                    r2.String(),
                    r3.String(),
                    r4.String()
                ),
            );
        }
    }
    for a in [0i64, 1, -1, 5, -5, 255, -255, -256] {
        let x = n(a);
        let mut r = zero();
        r.Not(&x);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("not %5d -> %s", a, r.String()),
        );
    }
    // 3
    for a in [0i64, 1, -1, 5, -5, 8, -8, 255, -255, -256] {
        let x = n(a);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "bits %5d -> len=%-3d tz=%-4d b0=%d b1=%d b2=%d b7=%d b8=%d b100=%d",
                a,
                x.BitLen(),
                x.TrailingZeroBits() as i64,
                x.Bit(0) as i64,
                x.Bit(1) as i64,
                x.Bit(2) as i64,
                x.Bit(7) as i64,
                x.Bit(8) as i64,
                x.Bit(100) as i64
            ),
        );
    }
    for a in [0i64, 1, -1, 5, -5, -256] {
        for i in [0 as int, 1, 7] {
            for v in [0u64, 1] {
                let mut r = zero();
                r.SetBit(&n(a), i, v as goish::types::uint);
                chk(
                    &mut failed,
                    &mut ln,
                    fmt::Sprintf!("setbit %5d i=%d v=%d -> %s", a, i, v as i64, r.String()),
                );
            }
        }
    }
    // 4
    for a in [1i64, -1, 5, -5, 8, -8, 255, -255, -256] {
        for sh in [0u64, 1, 3, 8, 64] {
            let mut l = zero();
            l.Lsh(&n(a), sh as goish::types::uint);
            let mut rr = zero();
            rr.Rsh(&n(a), sh as goish::types::uint);
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "shift %5d n=%-3d -> lsh=%-24s rsh=%s",
                    a,
                    sh as i64,
                    l.String(),
                    rr.String()
                ),
            );
        }
    }
    // 5
    for a in [0i64, 1, -1, 255, -255, 123456789, -123456789] {
        let x = n(a);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "text %11d -> b2=%-30s b8=%-12s b10=%-11s b16=%-9s b36=%s str=%s",
                a,
                x.Text(2),
                x.Text(8),
                x.Text(10),
                x.Text(16),
                x.Text(36),
                x.String()
            ),
        );
    }
    // 6
    let cases: [(&str, int); 29] = [
        ("0", 10),
        ("-0", 10),
        ("+42", 10),
        ("42", 10),
        ("  42", 10),
        ("42 ", 10),
        ("", 10),
        ("-", 10),
        ("0x1f", 0),
        ("0X1F", 0),
        ("0b101", 0),
        ("0o17", 0),
        ("017", 0),
        ("0_1_7", 0),
        ("1_000", 0),
        ("1_000", 10),
        ("_100", 0),
        ("100_", 0),
        ("0x", 0),
        ("ff", 16),
        ("FF", 16),
        ("zz", 36),
        ("zz", 35),
        ("-0x10", 0),
        ("1e3", 10),
        ("0x1f", 16),
        ("0", 0),
        ("00", 0),
        ("08", 0),
    ];
    for (st, base) in cases.iter() {
        let mut x = zero();
        let ok = {
            let (_, ok) = x.SetString(*st, *base);
            ok
        };
        if !ok {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("setstring %-8q base=%-3d -> nil,false", s(st), *base),
            );
            continue;
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "setstring %-8q base=%-3d -> %s,true",
                s(st),
                *base,
                x.String()
            ),
        );
    }
    // 7
    for a in [0i64, 1, -1, 255, 256, 65535, -65535, 1i64 << 40] {
        let x = n(a);
        let b = x.Bytes();
        let buf: slice<goish::types::byte> = slice::__from_vec(alloc::vec![0u8; 8]);
        let filled = x.FillBytes(buf);
        let mut back = zero();
        back.SetBytes(b.clone());
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "bytes %12d -> %x fill8=%x back=%s",
                a,
                b,
                filled,
                back.String()
            ),
        );
    }
    // 8
    let exps: [(i64, i64, i64); 13] = [
        (2, 10, 0),
        (2, 10, 1000),
        (2, 0, 7),
        (0, 0, 0),
        (3, 100, 7),
        (-3, 3, 0),
        (-3, 3, 7),
        (-3, 2, 7),
        (2, -1, 7),
        (2, -1, 0),
        (5, -1, 7),
        (7, -1, 7),
        (2, 10, -1000),
    ];
    for (b, e, m) in exps.iter() {
        let mm = if *m != 0 { n(*m) } else { zero() };
        let mut r = sentinel();
        r.Exp(&n(*b), &n(*e), &mm);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("exp %3d^%-4d mod %-6d -> %v", *b, *e, *m, nil_or(&r)),
        );
    }
    // 9
    for (a, b) in [
        (12i64, 18i64),
        (17, 5),
        (0, 5),
        (5, 0),
        (0, 0),
        (-12, 18),
        (12, -18),
        (270, 192),
    ]
    .iter()
    {
        if *a > 0 && *b > 0 {
            let mut g = zero();
            let mut xx = zero();
            let mut yy = zero();
            g.GCD(&mut xx, &mut yy, &n(*a), &n(*b));
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "gcd %5d %5d -> g=%s x=%s y=%s",
                    *a,
                    *b,
                    g.String(),
                    xx.String(),
                    yy.String()
                ),
            );
        } else {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("gcd %5d %5d -> skipped (GCD requires a,b > 0)", *a, *b),
            );
        }
    }
    for (a, b) in [(3i64, 7i64), (2, 7), (6, 9), (1, 7), (-3, 7), (3, 1)].iter() {
        let mut r = sentinel();
        r.ModInverse(&n(*a), &n(*b));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("modinv %5d mod %-4d -> %v", *a, *b, nil_or(&r)),
        );
    }
    for (a, b) in [(4i64, 7i64), (2, 7), (2, 17), (0, 7), (9, 13)].iter() {
        let mut r = sentinel();
        r.ModSqrt(&n(*a), &n(*b));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("modsqrt %5d mod %-4d -> %v", *a, *b, nil_or(&r)),
        );
    }
    // 10
    for a in vals.iter() {
        let x = n(*a);
        let mut ab = zero();
        ab.Abs(&x);
        let mut ng = zero();
        ng.Neg(&x);
        let sq = if *a >= 0 {
            let mut q = zero();
            q.Sqrt(&x);
            q.String()
        } else {
            s("n/a")
        };
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "unary %21d -> abs=%-21s neg=%-22s sign=%-2d sqrt=%s",
                *a,
                ab.String(),
                ng.String(),
                x.Sign(),
                sq
            ),
        );
    }
    for a in [-5i64, 0, 5] {
        for b in [-5i64, 0, 5] {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "cmp %3d %3d -> cmp=%-2d cmpabs=%d",
                    a,
                    b,
                    n(a).Cmp(&n(b)),
                    n(a).CmpAbs(&n(b))
                ),
            );
        }
    }
    // 11
    for st in [
        "0",
        "1",
        "-1",
        "9223372036854775807",
        "9223372036854775808",
        "-9223372036854775808",
        "-9223372036854775809",
        "18446744073709551615",
        "18446744073709551616",
    ] {
        let mut x = zero();
        let _ = x.SetString(st, 10);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "range %-21s -> isi64=%-5v isu64=%-5v i64=%-21d u64=%d",
                s(st),
                x.IsInt64(),
                x.IsUint64(),
                x.Int64(),
                x.Uint64()
            ),
        );
    }
    // 12
    for st in [
        "0",
        "1",
        "2",
        "3",
        "4",
        "561",
        "1105",
        "7919",
        "104729",
        "170141183460469231731687303715884105727",
    ] {
        let mut x = zero();
        let _ = x.SetString(st, 10);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "prime %-40s -> n0=%-5v n20=%v",
                s(st),
                x.ProbablyPrime(0),
                x.ProbablyPrime(20)
            ),
        );
    }
    // 13
    let mut a = zero();
    let _ = a.SetString("123456789012345678901234567890", 10);
    let mut b = zero();
    let _ = b.SetString("987654321098765432109876543210", 10);
    let mut t = zero();
    t.Add(&a, &b);
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!("big add=%s", t.String()),
    );
    let mut t = zero();
    t.Sub(&a, &b);
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!("big sub=%s", t.String()),
    );
    let mut t = zero();
    t.Mul(&a, &b);
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!("big mul=%s", t.String()),
    );
    let mut q = zero();
    q.Quo(&b, &a);
    let mut r = zero();
    r.Rem(&b, &a);
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!("big quo=%s rem=%s", q.String(), r.String()),
    );
    let mut nb = zero();
    nb.Neg(&b);
    let mut d = zero();
    d.Div(&nb, &a);
    let mut m = zero();
    m.Mod(&nb, &a);
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!("big div=%s mod=%s", d.String(), m.String()),
    );
    let mut e = zero();
    e.Exp(&n(2), &n(256), &zero());
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!("big exp=%s", e.String()),
    );
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!("big hex=%s", e.Text(16)),
    );
    let mut e2 = zero();
    e2.Exp(&n(2), &n(200), &zero());
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!("big bytes=%x", e2.Bytes()),
    );
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!("big bitlen=%d", e.BitLen()),
    );
    if ln != GO.len() as int {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln, GO.len() as int);
        failed += 1;
    }
    if failed == 0 {
        fmt::Printf!("ok %d/%d\n", ln, ln);
        return;
    }
    fmt::Printf!("FAILED %d of %d\n", failed, ln);
    syscall::Exit(1);
}
