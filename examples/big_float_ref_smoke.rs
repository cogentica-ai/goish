// big_float_ref_smoke — math/big's Float against a running Go.
// (math/big/float.go, math/big/floatconv.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_bigfloat_ref.go` run in
// `package big` by `scripts/goref.sh`.
//
// big.Float is not a wider float64. It is a mantissa of arbitrary,
// CALLER-CHOSEN precision, and every operation reports how it had to
// round through an Accuracy. Four rules carry that, and a port that
// treats Float as "f64 with extra digits" gets all four wrong while
// still printing plausible numbers:
//
//   * The precision of a result comes from the RECEIVER, not the
//     operands. z.Add(x, y) with z.Prec() == 0 adopts the larger of the
//     two operand precisions; with z.Prec() set, it rounds to that.
//   * Accuracy is Below / Exact / Above relative to the true value and
//     is set by every operation. Exact is the interesting one: it says
//     the result needed no rounding at all.
//   * The rounding mode belongs to the receiver too, and ToZero /
//     AwayFromZero / ToNegativeInf / ToPositiveInf differ from
//     ToNearestEven in the last bit — which is the entire point of
//     having them.
//   * SetPrec on an existing value ROUNDS it and reports the accuracy
//     of that rounding, so lowering precision is lossy and says so.
//
// goish matched Go on all of that, and on Text across eight format
// verbs (including 'x', 'p' and 'b', where a port that routes through
// strconv on a float64 loses digits). What it did not match was
// Float.Parse, in three ways that only show on the error and edge
// paths — the ones a happy-path test never reaches:
//
//   * an empty string returned a home-made "number has no digits"
//     instead of the io.EOF SENTINEL Go passes through from scanSign.
//     A caller reading a stream of numbers tells "done" from
//     "malformed" with errors.Is(err, io.EOF), and could not here.
//   * trailing junk said only "expected end of string", dropping the
//     character that ended the number: Go says
//     `expected end of string, found '.'`.
//   * "Inf" returned the requested base instead of 0. Go handles ±Inf
//     in Parse before ever calling scan, so the returned base is the
//     named return's zero value — which is how a caller using
//     Parse(s, 0) learns that no digits, and therefore no base, were
//     seen.
//
// Two Go behaviours are deliberately NOT pinned here, because a
// panicking case cannot be compared line-for-line in this harness:
// Quo(0, 0) and Sqrt(-1). Both were checked by hand against goish and
// panic with Go's exact messages — "division of zero by zero or
// infinity by infinity" and "square root of negative operand".

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt::Stringer;
use goish::gostring::string;
use goish::math::big;
use goish::math::big::{Float, RoundingMode};
use goish::nilval::nil;
use goish::types::{int, uint};
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}
fn f(v: f64) -> Float {
    return big::NewFloat(v);
}
fn nf() -> Float {
    return Float::new();
}

// go: none — goish idiom: the reference lines, in the order Go printed
//     them. Comparing whole rendered lines keeps this smoke and the
//     generator in lockstep: a case added to one is a mismatch in the
//     other, never a silent pass.
const GO: [&str; 252] = [
    "zero prec=0 mode=ToNearestEven acc=Exact sign=0 signbit=false inf=false s=\"0\"",
    "inf +=\"+Inf\" -=\"-Inf\" +sign=1 -sign=-1 +isinf=true -signbit=true",
    "setf64 0                      prec=0    -> 0                            acc=Exact back=0                      backacc=Exact",
    "setf64 0                      prec=1    -> 0                            acc=Exact back=0                      backacc=Exact",
    "setf64 0                      prec=2    -> 0                            acc=Exact back=0                      backacc=Exact",
    "setf64 0                      prec=8    -> 0                            acc=Exact back=0                      backacc=Exact",
    "setf64 0                      prec=24   -> 0                            acc=Exact back=0                      backacc=Exact",
    "setf64 0                      prec=53   -> 0                            acc=Exact back=0                      backacc=Exact",
    "setf64 0                      prec=100  -> 0                            acc=Exact back=0                      backacc=Exact",
    "setf64 1                      prec=0    -> 1                            acc=Exact back=1                      backacc=Exact",
    "setf64 1                      prec=1    -> 1                            acc=Exact back=1                      backacc=Exact",
    "setf64 1                      prec=2    -> 1                            acc=Exact back=1                      backacc=Exact",
    "setf64 1                      prec=8    -> 1                            acc=Exact back=1                      backacc=Exact",
    "setf64 1                      prec=24   -> 1                            acc=Exact back=1                      backacc=Exact",
    "setf64 1                      prec=53   -> 1                            acc=Exact back=1                      backacc=Exact",
    "setf64 1                      prec=100  -> 1                            acc=Exact back=1                      backacc=Exact",
    "setf64 -1                     prec=0    -> -1                           acc=Exact back=-1                     backacc=Exact",
    "setf64 -1                     prec=1    -> -1                           acc=Exact back=-1                     backacc=Exact",
    "setf64 -1                     prec=2    -> -1                           acc=Exact back=-1                     backacc=Exact",
    "setf64 -1                     prec=8    -> -1                           acc=Exact back=-1                     backacc=Exact",
    "setf64 -1                     prec=24   -> -1                           acc=Exact back=-1                     backacc=Exact",
    "setf64 -1                     prec=53   -> -1                           acc=Exact back=-1                     backacc=Exact",
    "setf64 -1                     prec=100  -> -1                           acc=Exact back=-1                     backacc=Exact",
    "setf64 0.5                    prec=0    -> 0.5                          acc=Exact back=0.5                    backacc=Exact",
    "setf64 0.5                    prec=1    -> 0.5                          acc=Exact back=0.5                    backacc=Exact",
    "setf64 0.5                    prec=2    -> 0.5                          acc=Exact back=0.5                    backacc=Exact",
    "setf64 0.5                    prec=8    -> 0.5                          acc=Exact back=0.5                    backacc=Exact",
    "setf64 0.5                    prec=24   -> 0.5                          acc=Exact back=0.5                    backacc=Exact",
    "setf64 0.5                    prec=53   -> 0.5                          acc=Exact back=0.5                    backacc=Exact",
    "setf64 0.5                    prec=100  -> 0.5                          acc=Exact back=0.5                    backacc=Exact",
    "setf64 0.1                    prec=0    -> 0.10000000000000000555       acc=Exact back=0.1                    backacc=Exact",
    "setf64 0.1                    prec=1    -> 0.125                        acc=Above back=0.125                  backacc=Exact",
    "setf64 0.1                    prec=2    -> 0.09375                      acc=Below back=0.09375                backacc=Exact",
    "setf64 0.1                    prec=8    -> 0.10009765625                acc=Above back=0.10009765625          backacc=Exact",
    "setf64 0.1                    prec=24   -> 0.10000000149011611938       acc=Above back=0.10000000149011612    backacc=Exact",
    "setf64 0.1                    prec=53   -> 0.10000000000000000555       acc=Exact back=0.1                    backacc=Exact",
    "setf64 0.1                    prec=100  -> 0.10000000000000000555       acc=Exact back=0.1                    backacc=Exact",
    "setf64 0.3333333333333333     prec=0    -> 0.33333333333333331483       acc=Exact back=0.3333333333333333     backacc=Exact",
    "setf64 0.3333333333333333     prec=1    -> 0.25                         acc=Below back=0.25                   backacc=Exact",
    "setf64 0.3333333333333333     prec=2    -> 0.375                        acc=Above back=0.375                  backacc=Exact",
    "setf64 0.3333333333333333     prec=8    -> 0.333984375                  acc=Above back=0.333984375            backacc=Exact",
    "setf64 0.3333333333333333     prec=24   -> 0.3333333432674407959        acc=Above back=0.3333333432674408     backacc=Exact",
    "setf64 0.3333333333333333     prec=53   -> 0.33333333333333331483       acc=Exact back=0.3333333333333333     backacc=Exact",
    "setf64 0.3333333333333333     prec=100  -> 0.33333333333333331483       acc=Exact back=0.3333333333333333     backacc=Exact",
    "setf64 1e+300                 prec=0    -> 1.0000000000000000525e+300   acc=Exact back=1e+300                 backacc=Exact",
    "setf64 1e+300                 prec=1    -> 6.6969287949141707559e+299   acc=Below back=6.696928794914171e+299 backacc=Exact",
    "setf64 1e+300                 prec=2    -> 1.0045393192371256134e+300   acc=Above back=1.0045393192371256e+300 backacc=Exact",
    "setf64 1e+300                 prec=8    -> 9.9930734361609891749e+299   acc=Below back=9.993073436160989e+299 backacc=Exact",
    "setf64 1e+300                 prec=24   -> 9.9999998003711984665e+299   acc=Below back=9.999999800371198e+299 backacc=Exact",
    "setf64 1e+300                 prec=53   -> 1.0000000000000000525e+300   acc=Exact back=1e+300                 backacc=Exact",
    "setf64 1e+300                 prec=100  -> 1.0000000000000000525e+300   acc=Exact back=1e+300                 backacc=Exact",
    "setf64 -1e-300                prec=0    -> -1.0000000000000000251e-300  acc=Exact back=-1e-300                backacc=Exact",
    "setf64 -1e-300                prec=1    -> -7.4661089480257510319e-301  acc=Above back=-7.466108948025751e-301 backacc=Exact",
    "setf64 -1e-300                prec=2    -> -1.1199163422038626548e-300  acc=Below back=-1.1199163422038627e-300 backacc=Exact",
    "setf64 -1e-300                prec=8    -> -9.9742549227531517692e-301  acc=Above back=-9.974254922753152e-301 backacc=Exact",
    "setf64 -1e-300                prec=24   -> -9.9999999173256234921e-301  acc=Above back=-9.999999917325623e-301 backacc=Exact",
    "setf64 -1e-300                prec=53   -> -1.0000000000000000251e-300  acc=Exact back=-1e-300                backacc=Exact",
    "setf64 -1e-300                prec=100  -> -1.0000000000000000251e-300  acc=Exact back=-1e-300                backacc=Exact",
    "setf64 3.141592653589793      prec=0    -> 3.141592653589793116         acc=Exact back=3.141592653589793      backacc=Exact",
    "setf64 3.141592653589793      prec=1    -> 4                            acc=Above back=4                      backacc=Exact",
    "setf64 3.141592653589793      prec=2    -> 3                            acc=Below back=3                      backacc=Exact",
    "setf64 3.141592653589793      prec=8    -> 3.140625                     acc=Below back=3.140625               backacc=Exact",
    "setf64 3.141592653589793      prec=24   -> 3.1415927410125732422        acc=Above back=3.1415927410125732     backacc=Exact",
    "setf64 3.141592653589793      prec=53   -> 3.141592653589793116         acc=Exact back=3.141592653589793      backacc=Exact",
    "setf64 3.141592653589793      prec=100  -> 3.141592653589793116         acc=Exact back=3.141592653589793      backacc=Exact",
    "setf64 12345.6789             prec=0    -> 12345.678900000000795        acc=Exact back=12345.6789             backacc=Exact",
    "setf64 12345.6789             prec=1    -> 16384                        acc=Above back=16384                  backacc=Exact",
    "setf64 12345.6789             prec=2    -> 12288                        acc=Below back=12288                  backacc=Exact",
    "setf64 12345.6789             prec=8    -> 12352                        acc=Above back=12352                  backacc=Exact",
    "setf64 12345.6789             prec=24   -> 12345.6787109375             acc=Below back=12345.6787109375       backacc=Exact",
    "setf64 12345.6789             prec=53   -> 12345.678900000000795        acc=Exact back=12345.6789             backacc=Exact",
    "setf64 12345.6789             prec=100  -> 12345.678900000000795        acc=Exact back=12345.6789             backacc=Exact",
    "mode ToNearestEven  sign=1  -> 0.33349609375            acc=Above",
    "mode ToNearestEven  sign=-1 -> -0.33349609375           acc=Below",
    "mode ToNearestAway  sign=1  -> 0.33349609375            acc=Above",
    "mode ToNearestAway  sign=-1 -> -0.33349609375           acc=Below",
    "mode ToZero         sign=1  -> 0.3330078125             acc=Below",
    "mode ToZero         sign=-1 -> -0.3330078125            acc=Above",
    "mode AwayFromZero   sign=1  -> 0.33349609375            acc=Above",
    "mode AwayFromZero   sign=-1 -> -0.33349609375           acc=Below",
    "mode ToNegativeInf  sign=1  -> 0.3330078125             acc=Below",
    "mode ToNegativeInf  sign=-1 -> -0.33349609375           acc=Below",
    "mode ToPositiveInf  sign=1  -> 0.33349609375            acc=Above",
    "mode ToPositiveInf  sign=-1 -> -0.3330078125            acc=Above",
    "tie ToNearestEven  3->3      acc=Exact 5->4      acc=Below -5->-4     acc=Above",
    "tie ToNearestAway  3->3      acc=Exact 5->6      acc=Above -5->-6     acc=Below",
    "tie ToZero         3->3      acc=Exact 5->4      acc=Below -5->-4     acc=Above",
    "tie AwayFromZero   3->3      acc=Exact 5->6      acc=Above -5->-6     acc=Below",
    "tie ToNegativeInf  3->3      acc=Exact 5->4      acc=Below -5->-6     acc=Below",
    "tie ToPositiveInf  3->3      acc=Exact 5->6      acc=Above -5->-4     acc=Above",
    "recvprec z0.prec=200 z10.prec=10 z0=0.333333333333333 z10=0.33349609375",
    "arith add  1        2        prec=53   -> 3                          acc=Exact",
    "arith add  0.1      0.2      prec=53   -> 0.300000000000000044       acc=Above",
    "arith add  1        1e-30    prec=53   -> 1                          acc=Below",
    "arith add  1        1e-30    prec=200  -> 1                          acc=Exact",
    "arith sub  1        1        prec=53   -> 0                          acc=Exact",
    "arith sub  1        3        prec=10   -> -2                         acc=Exact",
    "arith mul  3        7        prec=53   -> 21                         acc=Exact",
    "arith mul  0.1      0.1      prec=10   -> 0.0099945068359375         acc=Below",
    "arith quo  1        3        prec=53   -> 0.333333333333333315       acc=Below",
    "arith quo  1        3        prec=4    -> 0.34375                    acc=Above",
    "arith quo  10       4        prec=53   -> 2.5                        acc=Exact",
    "arith quo  1        0        prec=53   -> +Inf                       acc=Exact",
    "arith quo  -1       0        prec=53   -> -Inf                       acc=Exact",
    "sqrt 4          prec=53   -> 2                          acc=Exact",
    "sqrt 2          prec=53   -> 1.41421356237309515        acc=Exact",
    "sqrt 2          prec=10   -> 1.4140625                  acc=Exact",
    "sqrt 0          prec=53   -> 0                          acc=Exact",
    "sqrt 1e+300     prec=53   -> 9.99999999999999981e+149   acc=Exact",
    "text e prec=-1   third=3.333333333333333333333333333333333333333333333333333333333334e-01 big=1e+20",
    "text e prec=0    third=3e-01                                          big=1e+20",
    "text e prec=3    third=3.333e-01                                      big=1.000e+20",
    "text e prec=10   third=3.3333333333e-01                               big=1.0000000000e+20",
    "text e prec=30   third=3.333333333333333333333333333333e-01           big=1.000000000000000000000000000000e+20",
    "text E prec=-1   third=3.333333333333333333333333333333333333333333333333333333333334E-01 big=1E+20",
    "text E prec=0    third=3E-01                                          big=1E+20",
    "text E prec=3    third=3.333E-01                                      big=1.000E+20",
    "text E prec=10   third=3.3333333333E-01                               big=1.0000000000E+20",
    "text E prec=30   third=3.333333333333333333333333333333E-01           big=1.000000000000000000000000000000E+20",
    "text f prec=-1   third=0.3333333333333333333333333333333333333333333333333333333333334 big=100000000000000000000",
    "text f prec=0    third=0                                              big=100000000000000000000",
    "text f prec=3    third=0.333                                          big=100000000000000000000.000",
    "text f prec=10   third=0.3333333333                                   big=100000000000000000000.0000000000",
    "text f prec=30   third=0.333333333333333333333333333333               big=100000000000000000000.000000000000000000000000000000",
    "text g prec=-1   third=0.3333333333333333333333333333333333333333333333333333333333334 big=1e+20",
    "text g prec=0    third=0.3                                            big=1e+20",
    "text g prec=3    third=0.333                                          big=1e+20",
    "text g prec=10   third=0.3333333333                                   big=1e+20",
    "text g prec=30   third=0.333333333333333333333333333333               big=100000000000000000000",
    "text G prec=-1   third=0.3333333333333333333333333333333333333333333333333333333333334 big=1E+20",
    "text G prec=0    third=0.3                                            big=1E+20",
    "text G prec=3    third=0.333                                          big=1E+20",
    "text G prec=10   third=0.3333333333                                   big=1E+20",
    "text G prec=30   third=0.333333333333333333333333333333               big=100000000000000000000",
    "text x prec=-1   third=0x1.55555555555555555555555555555555555555555555555556p-02 big=0x1.5af1d78b58c4p+66",
    "text x prec=0    third=0x1p-02                                        big=0x1p+66",
    "text x prec=3    third=0x1.555p-02                                    big=0x1.5afp+66",
    "text x prec=10   third=0x1.5555555555p-02                             big=0x1.5af1d78b59p+66",
    "text x prec=30   third=0x1.555555555555555555555555555555p-02         big=0x1.5af1d78b58c4000000000000000000p+66",
    "text p prec=-1   third=0x.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabp-1 big=0x.ad78ebc5ac62p+67",
    "text p prec=0    third=0x.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabp-1 big=0x.ad78ebc5ac62p+67",
    "text p prec=3    third=0x.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabp-1 big=0x.ad78ebc5ac62p+67",
    "text p prec=10   third=0x.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabp-1 big=0x.ad78ebc5ac62p+67",
    "text p prec=30   third=0x.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabp-1 big=0x.ad78ebc5ac62p+67",
    "text b prec=-1   third=1071292029505993517027974728227441735014801995855195223534251p-201 big=1088903574147003083082798743781658276659200000000000000000000p-133",
    "text b prec=0    third=1071292029505993517027974728227441735014801995855195223534251p-201 big=1088903574147003083082798743781658276659200000000000000000000p-133",
    "text b prec=3    third=1071292029505993517027974728227441735014801995855195223534251p-201 big=1088903574147003083082798743781658276659200000000000000000000p-133",
    "text b prec=10   third=1071292029505993517027974728227441735014801995855195223534251p-201 big=1088903574147003083082798743781658276659200000000000000000000p-133",
    "text b prec=30   third=1071292029505993517027974728227441735014801995855195223534251p-201 big=1088903574147003083082798743781658276659200000000000000000000p-133",
    "string third=0.3333333333",
    "string big=1e+20",
    "parse \"0\"        base=10  -> 0                        base=10 acc=Exact",
    "parse \"1\"        base=10  -> 1                        base=10 acc=Exact",
    "parse \"-1.5\"     base=10  -> -1.5                     base=10 acc=Exact",
    "parse \"+1.5\"     base=10  -> 1.5                      base=10 acc=Exact",
    "parse \"1e10\"     base=10  -> 10000000000              base=10 acc=Exact",
    "parse \"1E10\"     base=10  -> 10000000000              base=10 acc=Exact",
    "parse \"1.5e-3\"   base=10  -> 0.00150000000000000003   base=10 acc=Above",
    "parse \".5\"       base=10  -> 0.5                      base=10 acc=Exact",
    "parse \"5.\"       base=10  -> 5                        base=10 acc=Exact",
    "parse \"\"         base=10  -> err=\"EOF\"",
    "parse \"x\"        base=10  -> err=\"number has no digits\"",
    "parse \"1.2.3\"    base=10  -> err=\"expected end of string, found '.'\"",
    "parse \"0x1p4\"    base=0   -> 16                       base=16 acc=Exact",
    "parse \"0x1.8p1\"  base=0   -> 3                        base=16 acc=Exact",
    "parse \"0b101\"    base=0   -> 5                        base=2 acc=Exact",
    "parse \"0o17\"     base=0   -> 15                       base=8 acc=Exact",
    "parse \"1_000\"    base=0   -> 1000                     base=10 acc=Exact",
    "parse \"Inf\"      base=10  -> +Inf                     base=0 acc=Exact",
    "parse \"+Inf\"     base=10  -> +Inf                     base=0 acc=Exact",
    "parse \"-Inf\"     base=10  -> -Inf                     base=0 acc=Exact",
    "parse \"inf\"      base=10  -> +Inf                     base=0 acc=Exact",
    "parse \"NaN\"      base=10  -> err=\"number has no digits\"",
    "parse \"1p10\"     base=2   -> 1024                     base=2 acc=Exact",
    "mantexp 0          -> mant=0                        exp=0      back=0",
    "mantexp 1          -> mant=0.5                      exp=1      back=1",
    "mantexp -1         -> mant=-0.5                     exp=1      back=-1",
    "mantexp 0.5        -> mant=0.5                      exp=0      back=0.5",
    "mantexp 1024       -> mant=0.5                      exp=11     back=1024",
    "mantexp 1e+300     -> mant=0.746610894802575142     exp=997    back=1.00000000000000005e+300",
    "mantexp 0.1        -> mant=0.800000000000000044     exp=-3     back=0.100000000000000006",
    "conv 0        -> isint=true  int=0                      iacc=Exact rat=0                        racc=Exact",
    "conv 1        -> isint=true  int=1                      iacc=Exact rat=1                        racc=Exact",
    "conv -1       -> isint=true  int=-1                     iacc=Exact rat=-1                       racc=Exact",
    "conv 1.5      -> isint=false int=1                      iacc=Below rat=3/2                      racc=Exact",
    "conv -1.5     -> isint=false int=-1                     iacc=Above rat=-3/2                     racc=Exact",
    "conv 2.5      -> isint=false int=2                      iacc=Below rat=5/2                      racc=Exact",
    "conv 1e20     -> isint=true  int=100000000000000000000  iacc=Exact rat=100000000000000000000    racc=Exact",
    "conv 1e30     -> isint=true  int=1000000000000000019884624838656 iacc=Exact rat=1000000000000000019884624838656 racc=Exact",
    "conv 0.0001   -> isint=false int=0                      iacc=Below rat=7378697629483821/73786976294838206464 racc=Exact",
    "bound 0                     -> i64=0                     iacc=Exact u64=0                     uacc=Exact f32=0              f32acc=Exact",
    "bound 1                     -> i64=1                     iacc=Exact u64=1                     uacc=Exact f32=1              f32acc=Exact",
    "bound -1                    -> i64=-1                    iacc=Exact u64=0                     uacc=Above f32=-1             f32acc=Exact",
    "bound 1.5                   -> i64=1                     iacc=Below u64=1                     uacc=Exact f32=1.5            f32acc=Exact",
    "bound -1.5                  -> i64=-1                    iacc=Above u64=0                     uacc=Above f32=-1.5           f32acc=Exact",
    "bound 9223372036854775807   -> i64=9223372036854775807   iacc=Exact u64=9223372036854775807   uacc=Exact f32=9.223372e+18   f32acc=Above",
    "bound 9223372036854775808   -> i64=9223372036854775807   iacc=Below u64=9223372036854775808   uacc=Exact f32=9.223372e+18   f32acc=Exact",
    "bound -9223372036854775808  -> i64=-9223372036854775808  iacc=Exact u64=0                     uacc=Above f32=-9.223372e+18  f32acc=Exact",
    "bound -9223372036854775809  -> i64=-9223372036854775808  iacc=Above u64=0                     uacc=Above f32=-9.223372e+18  f32acc=Above",
    "bound 18446744073709551615  -> i64=9223372036854775807   iacc=Below u64=18446744073709551615  uacc=Exact f32=1.8446744e+19  f32acc=Above",
    "bound 18446744073709551616  -> i64=9223372036854775807   iacc=Below u64=18446744073709551615  uacc=Below f32=1.8446744e+19  f32acc=Exact",
    "bound 1e40                  -> i64=9223372036854775807   iacc=Below u64=18446744073709551615  uacc=Below f32=+Inf           f32acc=Above",
    "bound -1e40                 -> i64=-9223372036854775808  iacc=Above u64=0                     uacc=Above f32=-Inf           f32acc=Below",
    "setprec 200  -> 0.333333333333333333     acc=Exact prec=200",
    "setprec 100  -> 0.333333333333333333     acc=Above prec=100",
    "setprec 53   -> 0.333333333333333315     acc=Below prec=53",
    "setprec 10   -> 0.33349609375            acc=Above prec=10",
    "setprec 2    -> 0.375                    acc=Above prec=2",
    "setprec 1    -> 0.25                     acc=Below prec=1",
    "setprec 0    -> 0                        acc=Below prec=0",
    "props -Inf  sign=-1 signbit=true  isinf=true  isint=false minprec=0",
    "fcmp -Inf  -Inf  -> 0",
    "fcmp -Inf  -1    -> -1",
    "fcmp -Inf  -0    -> -1",
    "fcmp -Inf  0     -> -1",
    "fcmp -Inf  1     -> -1",
    "fcmp -Inf  Inf   -> -1",
    "props -1    sign=-1 signbit=true  isinf=false isint=true  minprec=1",
    "fcmp -1    -Inf  -> 1",
    "fcmp -1    -1    -> 0",
    "fcmp -1    -0    -> -1",
    "fcmp -1    0     -> -1",
    "fcmp -1    1     -> -1",
    "fcmp -1    Inf   -> -1",
    "props -0    sign=0  signbit=true  isinf=false isint=true  minprec=0",
    "fcmp -0    -Inf  -> 1",
    "fcmp -0    -1    -> 1",
    "fcmp -0    -0    -> 0",
    "fcmp -0    0     -> 0",
    "fcmp -0    1     -> -1",
    "fcmp -0    Inf   -> -1",
    "props 0     sign=0  signbit=false isinf=false isint=true  minprec=0",
    "fcmp 0     -Inf  -> 1",
    "fcmp 0     -1    -> 1",
    "fcmp 0     -0    -> 0",
    "fcmp 0     0     -> 0",
    "fcmp 0     1     -> -1",
    "fcmp 0     Inf   -> -1",
    "props 1     sign=1  signbit=false isinf=false isint=true  minprec=1",
    "fcmp 1     -Inf  -> 1",
    "fcmp 1     -1    -> 1",
    "fcmp 1     -0    -> 1",
    "fcmp 1     0     -> 1",
    "fcmp 1     1     -> 0",
    "fcmp 1     Inf   -> -1",
    "props Inf   sign=1  signbit=false isinf=true  isint=false minprec=0",
    "fcmp Inf   -Inf  -> 1",
    "fcmp Inf   -1    -> 1",
    "fcmp Inf   -0    -> 1",
    "fcmp Inf   0     -> 1",
    "fcmp Inf   1     -> 1",
    "fcmp Inf   Inf   -> 0",
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

    let modes = [
        RoundingMode::ToNearestEven,
        RoundingMode::ToNearestAway,
        RoundingMode::ToZero,
        RoundingMode::AwayFromZero,
        RoundingMode::ToNegativeInf,
        RoundingMode::ToPositiveInf,
    ];
    // 1
    {
        let z = nf();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "zero prec=%d mode=%v acc=%v sign=%d signbit=%v inf=%v s=%q",
                z.Prec() as i64,
                z.Mode().String(),
                z.Acc().String(),
                z.Sign(),
                z.Signbit(),
                z.IsInf(),
                z.String()
            ),
        );
        let mut p = nf();
        p.SetInf(false);
        let mut m = nf();
        m.SetInf(true);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "inf +=%q -=%q +sign=%d -sign=%d +isinf=%v -signbit=%v",
                p.String(),
                m.String(),
                p.Sign(),
                m.Sign(),
                p.IsInf(),
                m.Signbit()
            ),
        );
    }
    // 2
    for v in [
        0.0f64,
        1.0,
        -1.0,
        0.5,
        0.1,
        1.0 / 3.0,
        1e300,
        -1e-300,
        3.141592653589793,
        12345.6789,
    ] {
        for prec in [0u64, 1, 2, 8, 24, 53, 100] {
            let mut z = nf();
            z.SetPrec(prec as uint);
            z.SetFloat64(v);
            let (g, acc) = z.Float64();
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "setf64 %-22g prec=%-4d -> %-28s acc=%-5v back=%-22g backacc=%v",
                    v,
                    prec as i64,
                    z.Text(b'g', 20),
                    z.Acc().String(),
                    g,
                    acc.String()
                ),
            );
        }
    }
    // 3
    for mode in modes.iter() {
        for sign in [1i64, -1] {
            let mut z = nf();
            z.SetPrec(10);
            z.SetMode(*mode);
            z.Quo(&f(sign as f64), &f(3.0));
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "mode %-14v sign=%-2d -> %-24s acc=%v",
                    mode.String(),
                    sign,
                    z.Text(b'g', 12),
                    z.Acc().String()
                ),
            );
        }
    }
    for mode in modes.iter() {
        let mut z = nf();
        z.SetPrec(2);
        z.SetMode(*mode);
        z.SetFloat64(3.0);
        let mut w = nf();
        w.SetPrec(2);
        w.SetMode(*mode);
        w.SetFloat64(5.0);
        let mut v = nf();
        v.SetPrec(2);
        v.SetMode(*mode);
        v.SetFloat64(-5.0);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "tie %-14v 3->%-6s acc=%-5v 5->%-6s acc=%-5v -5->%-6s acc=%v",
                mode.String(),
                z.Text(b'g', 8),
                z.Acc().String(),
                w.Text(b'g', 8),
                w.Acc().String(),
                v.Text(b'g', 8),
                v.Acc().String()
            ),
        );
    }
    // 4
    {
        let mut x = nf();
        x.SetPrec(53);
        x.SetFloat64(1.0);
        let mut y = nf();
        y.SetPrec(200);
        y.SetFloat64(3.0);
        let mut z0 = nf();
        z0.Quo(&x, &y);
        let mut z10 = nf();
        z10.SetPrec(10);
        z10.Quo(&x, &y);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "recvprec z0.prec=%d z10.prec=%d z0=%s z10=%s",
                z0.Prec() as i64,
                z10.Prec() as i64,
                z0.Text(b'g', 15),
                z10.Text(b'g', 15)
            ),
        );
    }
    // 5
    let ops: [(&str, f64, f64, u64); 13] = [
        ("add", 1.0, 2.0, 53),
        ("add", 0.1, 0.2, 53),
        ("add", 1.0, 1e-30, 53),
        ("add", 1.0, 1e-30, 200),
        ("sub", 1.0, 1.0, 53),
        ("sub", 1.0, 3.0, 10),
        ("mul", 3.0, 7.0, 53),
        ("mul", 0.1, 0.1, 10),
        ("quo", 1.0, 3.0, 53),
        ("quo", 1.0, 3.0, 4),
        ("quo", 10.0, 4.0, 53),
        ("quo", 1.0, 0.0, 53),
        ("quo", -1.0, 0.0, 53),
    ];
    for (op, a, b, prec) in ops.iter() {
        let (x, y) = (f(*a), f(*b));
        let mut z = nf();
        z.SetPrec(*prec as uint);
        match *op {
            "add" => {
                z.Add(&x, &y);
            }
            "sub" => {
                z.Sub(&x, &y);
            }
            "mul" => {
                z.Mul(&x, &y);
            }
            _ => {
                z.Quo(&x, &y);
            }
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "arith %-4s %-8g %-8g prec=%-4d -> %-26s acc=%v",
                s(op),
                *a,
                *b,
                *prec as i64,
                z.Text(b'g', 18),
                z.Acc().String()
            ),
        );
    }
    // 6
    for (v, prec) in [
        (4.0f64, 53u64),
        (2.0, 53),
        (2.0, 10),
        (0.0, 53),
        (1e300, 53),
    ]
    .iter()
    {
        let mut z = nf();
        z.SetPrec(*prec as uint);
        z.Sqrt(&f(*v));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "sqrt %-10g prec=%-4d -> %-26s acc=%v",
                *v,
                *prec as i64,
                z.Text(b'g', 18),
                z.Acc().String()
            ),
        );
    }
    // 7
    let mut third = nf();
    third.SetPrec(200);
    third.Quo(&f(1.0), &f(3.0));
    let mut big1 = nf();
    big1.SetPrec(200);
    big1.SetFloat64(1e20);
    for format in [b'e', b'E', b'f', b'g', b'G', b'x', b'p', b'b'] {
        for prec in [-1 as int, 0, 3, 10, 30] {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "text %c prec=%-4d third=%-46s big=%s",
                    format as i64,
                    prec,
                    third.Text(format, prec),
                    big1.Text(format, prec)
                ),
            );
        }
    }
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!("string third=%s", third.String()),
    );
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!("string big=%s", big1.String()),
    );
    // 8
    let pcases: [(&str, int); 23] = [
        ("0", 10),
        ("1", 10),
        ("-1.5", 10),
        ("+1.5", 10),
        ("1e10", 10),
        ("1E10", 10),
        ("1.5e-3", 10),
        (".5", 10),
        ("5.", 10),
        ("", 10),
        ("x", 10),
        ("1.2.3", 10),
        ("0x1p4", 0),
        ("0x1.8p1", 0),
        ("0b101", 0),
        ("0o17", 0),
        ("1_000", 0),
        ("Inf", 10),
        ("+Inf", 10),
        ("-Inf", 10),
        ("inf", 10),
        ("NaN", 10),
        ("1p10", 2),
    ];
    for (st, base) in pcases.iter() {
        let mut z = nf();
        z.SetPrec(53);
        let (b, err) = {
            let (_, b, err) = z.Parse(*st, *base);
            (b, err)
        };
        if err != goish::errors::nil {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("parse %-10q base=%-3d -> err=%q", s(st), *base, err.Error()),
            );
            continue;
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "parse %-10q base=%-3d -> %-24s base=%d acc=%v",
                s(st),
                *base,
                z.Text(b'g', 18),
                b,
                z.Acc().String()
            ),
        );
    }
    // 9
    for v in [0.0f64, 1.0, -1.0, 0.5, 1024.0, 1e300, 0.1] {
        let mut x = nf();
        x.SetPrec(53);
        x.SetFloat64(v);
        let mut mant = nf();
        let exp = x.MantExp(&mut mant);
        let mut back = nf();
        back.SetPrec(53);
        back.SetMantExp(&mant, exp);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "mantexp %-10g -> mant=%-24s exp=%-6d back=%s",
                v,
                mant.Text(b'g', 18),
                exp,
                back.Text(b'g', 18)
            ),
        );
    }
    // 10
    for (st, prec) in [
        ("0", 53u64),
        ("1", 53),
        ("-1", 53),
        ("1.5", 53),
        ("-1.5", 53),
        ("2.5", 53),
        ("1e20", 53),
        ("1e30", 53),
        ("0.0001", 53),
    ]
    .iter()
    {
        let mut x = nf();
        x.SetPrec(*prec as uint);
        let _ = x.Parse(*st, 10);
        let (i, iacc) = x.Int(nil);
        let (r, racc) = x.Rat(nil);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "conv %-8s -> isint=%-5v int=%-22s iacc=%-5v rat=%-24s racc=%v",
                s(st),
                x.IsInt(),
                i.String(),
                iacc.String(),
                r.RatString(),
                racc.String()
            ),
        );
    }
    // 11
    for st in [
        "0",
        "1",
        "-1",
        "1.5",
        "-1.5",
        "9223372036854775807",
        "9223372036854775808",
        "-9223372036854775808",
        "-9223372036854775809",
        "18446744073709551615",
        "18446744073709551616",
        "1e40",
        "-1e40",
    ] {
        let mut x = nf();
        x.SetPrec(200);
        let _ = x.Parse(st, 10);
        let (i, iacc) = x.Int64();
        let (u, uacc) = x.Uint64();
        let (f32v, f32acc) = x.Float32();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "bound %-21s -> i64=%-21d iacc=%-5v u64=%-21d uacc=%-5v f32=%-14g f32acc=%v",
                s(st),
                i,
                iacc.String(),
                u,
                uacc.String(),
                f32v,
                f32acc.String()
            ),
        );
    }
    // 12
    {
        let mut x = nf();
        x.SetPrec(200);
        x.Quo(&f(1.0), &f(3.0));
        for p in [200u64, 100, 53, 10, 2, 1, 0] {
            let mut y = nf();
            y.Set(&x);
            y.SetPrec(p as uint);
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "setprec %-4d -> %-24s acc=%v prec=%d",
                    p as i64,
                    y.Text(b'g', 18),
                    y.Acc().String(),
                    y.Prec() as i64
                ),
            );
        }
    }
    // 13
    let vals = ["-Inf", "-1", "-0", "0", "1", "Inf"];
    for a in vals.iter() {
        let mut x = nf();
        x.SetPrec(53);
        let _ = x.Parse(*a, 10);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "props %-5s sign=%-2d signbit=%-5v isinf=%-5v isint=%-5v minprec=%d",
                s(a),
                x.Sign(),
                x.Signbit(),
                x.IsInf(),
                x.IsInt(),
                x.MinPrec() as i64
            ),
        );
        for b in vals.iter() {
            let mut y = nf();
            y.SetPrec(53);
            let _ = y.Parse(*b, 10);
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("fcmp %-5s %-5s -> %d", s(a), s(b), x.Cmp(&y)),
            );
        }
    }
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
