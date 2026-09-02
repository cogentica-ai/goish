// go: file strconv/atoc.go decls: convErr, ParseComplex
//
// atoc.go — parsing a complex number.
//
// ParseComplex accepts a good deal more than FormatComplex produces: a
// bare real ("1"), a bare imaginary ("2i"), and the parenthesised form
// as well as the plain one. It also does NOT accept several things that
// look reasonable — "i" alone, "1+2" with no 'i', "1+2j", or spaces
// anywhere — and every refusal names ParseComplex and quotes the
// ORIGINAL string rather than the fragment that failed.

#![allow(non_snake_case)]

use super::atof::parseFloatPrefix;
use super::atoi::{syntaxError, NumError};
use crate::errors::{self, error, nil};
use crate::gostring::string;
use crate::types::{complex128, int};

// go: none — goish idiom: Go names the function in a package-level
//     `const fnParseComplex = "ParseComplex"` shared with its error
//     constructors; goish's `syntaxError`/`rangeError` take the name as
//     an argument, so it is spelled here.
const fnParseComplex: &str = "ParseComplex";

// go: sdk 1.25.5 strconv/atoc.go:11-21 convErr
/// Go: "convErr splits an error returned by parseFloatPrefix into a
/// syntax or range error for ParseComplex."
///
/// The split matters: a SYNTAX error aborts the parse and is returned
/// on its own, while a RANGE error is held as `pending` and returned
/// alongside the value — so `ParseComplex("1e400+1i")` hands back both
/// ±Inf and the error, and a caller that only checks the error still
/// sees a usable number.
fn convErr(err: error, s: &string) -> (error, error) {
    if let Some(x) = errors::AsConcrete::<NumError>(&err) {
        let rebuilt = errors::Wrap(NumError {
            Func: string::from_bytes(fnParseComplex.as_bytes()),
            Num: s.clone(),
            Err: x.Err.clone(),
        });
        if errors::Is(x.Err.clone(), super::ErrRange) {
            return (nil, rebuilt);
        }
        return (rebuilt, nil);
    }
    return (err, nil);
}

// go: sdk 1.25.5 strconv/atoc.go:23-107 ParseComplex
/// Go: "ParseComplex converts the string s to a complex number with the
/// precision specified by bitSize: 64 for complex64, or 128 for
/// complex128. When bitSize=64, the result still has type complex128,
/// but it will be convertible to complex64 without changing its value."
pub fn ParseComplex<S: Into<string>>(s: S, bitSize: int) -> (complex128, error) {
    let orig: string = s.into();
    // Go: size := 64; if bitSize == 64 { size = 32 } — "complex64 uses
    // float32 parts".
    let size: int = if bitSize == 64 { 32 } else { 64 };

    let ob = orig.as_bytes().to_vec();
    let mut s: &[u8] = &ob;

    // Go: "Remove parentheses, if any."
    if s.len() >= 2 && s[0] == b'(' && s[s.len() - 1] == b')' {
        s = &s[1..s.len() - 1];
    }

    // Go: pending range error, or nil.
    let mut pending: error = nil;

    // Go: "Read real part (possibly imaginary part if followed by 'i')."
    let (re, n, err) = parseFloatPrefix(&string::from_bytes(s), size);
    if err != nil {
        let (e, p) = convErr(err, &orig);
        pending = p;
        if e != nil {
            return ((0.0, 0.0), e);
        }
    }
    s = &s[n..];

    // Go: "If we have nothing left, we're done."
    if s.is_empty() {
        return ((re, 0.0), pending);
    }

    // Go: "Otherwise, look at the next character."
    if s[0] == b'+' {
        // Go: "Consume the '+' to avoid an error if we have "+NaNi",
        // but do this only if we don't have a "++" (don't hide that
        // error)."
        if s.len() > 1 && s[1] != b'+' {
            s = &s[1..];
        }
    } else if s[0] == b'-' {
        // Go: ok — the '-' belongs to the imaginary part's own parse.
    } else if s[0] == b'i' && s.len() == 1 {
        // Go: "If 'i' is the last character, we only have an imaginary
        // part." Note this is the ONLY way to reach a bare imaginary:
        // "i" on its own never gets here, because parseFloatPrefix
        // consumes nothing and fails first.
        return ((0.0, re), pending);
    } else {
        // Go: the `fallthrough` from a non-final 'i' lands here too.
        return ((0.0, 0.0), syntaxError(fnParseComplex, orig));
    }

    // Go: "Read imaginary part."
    let (im, n2, err2) = parseFloatPrefix(&string::from_bytes(s), size);
    if err2 != nil {
        let (e, p) = convErr(err2, &orig);
        pending = p;
        if e != nil {
            return ((0.0, 0.0), e);
        }
    }
    s = &s[n2..];
    if s != b"i" {
        return ((0.0, 0.0), syntaxError(fnParseComplex, orig));
    }
    return ((re, im), pending);
}
