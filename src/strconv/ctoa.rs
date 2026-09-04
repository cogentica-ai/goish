// go: file strconv/ctoa.go decls: FormatComplex
//
// ctoa.go — formatting a complex number.

#![allow(non_snake_case)]

use super::ftoa::FormatFloat;
use crate::gostring::string;
use crate::types::{byte, int};

// go: sdk 1.25.5 strconv/ctoa.go:14-26 FormatComplex
/// Go: "FormatComplex converts the complex number c to a string of the
/// form (a+bi) where a and b are the real and imaginary parts,
/// formatted according to the format fmt and precision prec."
///
/// Two details that are easy to lose: the result is ALWAYS
/// parenthesised, and the imaginary part ALWAYS carries a sign — so a
/// positive imaginary part gets a '+' inserted that FormatFloat did not
/// produce, and `(0+0i)` rather than `(0 0i)` is the zero.
///
/// `bitSize` is the COMPLEX width (64 or 128) and is halved before
/// being handed to FormatFloat, because a complex64 is two float32s.
pub fn FormatComplex(c: crate::types::complex128, fmt_b: byte, prec: int, bitSize: int) -> string {
    if bitSize != 64 && bitSize != 128 {
        panic!("invalid bitSize");
    }
    // Go: bitSize >>= 1 — "complex 128 uses float64 internally".
    let half = bitSize >> 1;

    // Go: "Check if imaginary part has a sign. If not, add one."
    let mut im = FormatFloat(c.1, fmt_b, prec, half);
    let imb = im.as_bytes();
    if imb.is_empty() || (imb[0] != b'+' && imb[0] != b'-') {
        im = string::from_static("+") + im;
    }

    return string::from_static("(")
        + FormatFloat(c.0, fmt_b, prec, half)
        + im
        + string::from_static("i)");
}
