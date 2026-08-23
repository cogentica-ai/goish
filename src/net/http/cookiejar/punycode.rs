// go: package net/http/cookiejar
//
// go: file net/http/cookiejar/punycode.go decls: encode, encodeDigit, adapt, toASCII
//
// Go: "This file implements the Punycode algorithm from RFC 3492."
//
// Go: "All computation is done with int32s, so that overflow behavior
// is identical regardless of whether int is 32-bit or 64-bit." goish
// keeps that: every intermediate below is `int32`, and the two places
// Go relies on signed overflow to detect a hostile label use wrapping
// arithmetic explicitly rather than Rust's debug-build panic.

#![allow(non_snake_case)]

extern crate alloc;
use alloc::vec::Vec;

use crate::error;
use crate::gostring::string;
use crate::strings;
use crate::types::{byte, int, int32};
use crate::unicode::utf8;

use super::super::internal::ascii;

// go: sdk 1.25.5 net/http/cookiejar/punycode.go:20-28 base
/// Go: "These parameter values are specified in section 5."
const base: int32 = 36;
// go: sdk 1.25.5 net/http/cookiejar/punycode.go:20-28 damp
const damp: int32 = 700;
// go: sdk 1.25.5 net/http/cookiejar/punycode.go:20-28 initialBias
const initialBias: int32 = 72;
// go: sdk 1.25.5 net/http/cookiejar/punycode.go:20-28 initialN
const initialN: int32 = 128;
// go: sdk 1.25.5 net/http/cookiejar/punycode.go:20-28 skew
const skew: int32 = 38;
// go: sdk 1.25.5 net/http/cookiejar/punycode.go:20-28 tmax
const tmax: int32 = 26;
// go: sdk 1.25.5 net/http/cookiejar/punycode.go:20-28 tmin
const tmin: int32 = 1;

// go: sdk 1.25.5 net/http/cookiejar/punycode.go:131-131 acePrefix
/// Go: "acePrefix is the ASCII Compatible Encoding prefix."
const acePrefix: &str = "xn--";

// go: sdk 1.25.5 net/http/cookiejar/punycode.go:35-99 encode
/// Go: "encode encodes a string as specified in section 6.3 and
/// prepends prefix to the result. The "while h < length(input)" line in
/// the specification becomes "for remaining != 0" in the Go code,
/// because len(s) in Go is in bytes, not runes."
pub fn encode(prefix: &string, s: &string) -> (string, error) {
    let prefix_bytes = crate::gostring::__crate_as_bytes(prefix);
    let mut output: Vec<byte> =
        Vec::with_capacity(prefix_bytes.len() + 1 + 2 * crate::gostring::__crate_as_bytes(s).len());
    output.extend_from_slice(prefix_bytes);

    let mut delta: int32 = 0;
    let mut n: int32 = initialN;
    let mut bias: int32 = initialBias;

    let mut b: int32 = 0;
    let mut remaining: int32 = 0;
    for (_, r) in crate::range!(s.clone()) {
        if r < crate::int32(utf8::RuneSelf) {
            b += 1;
            output.push(crate::byte(r));
        } else {
            remaining += 1;
        }
    }
    let mut h: int32 = b;
    if b > 0 {
        output.push(b'-');
    }
    while remaining != 0 {
        let mut m: int32 = 0x7fffffff;
        for (_, r) in crate::range!(s.clone()) {
            if m > r && r >= n {
                m = r;
            }
        }
        // Go leans on int32 overflow going negative to reject a label
        // that would need more than 2^31 steps; wrapping keeps that in
        // a debug build, where Rust would otherwise panic first.
        delta = delta.wrapping_add(m.wrapping_sub(n).wrapping_mul(h + 1));
        if delta < 0 {
            return (string::new(), invalidLabel(s));
        }
        n = m;
        for (_, r) in crate::range!(s.clone()) {
            if r < n {
                delta = delta.wrapping_add(1);
                if delta < 0 {
                    return (string::new(), invalidLabel(s));
                }
                continue;
            }
            if r > n {
                continue;
            }
            let mut q: int32 = delta;
            let mut k: int32 = base;
            loop {
                let mut t: int32 = k - bias;
                if t < tmin {
                    t = tmin;
                } else if t > tmax {
                    t = tmax;
                }
                if q < t {
                    break;
                }
                output.push(encodeDigit(t + (q - t) % (base - t)));
                q = (q - t) / (base - t);
                k += base;
            }
            output.push(encodeDigit(q));
            bias = adapt(delta, h + 1, h == b);
            delta = 0;
            h += 1;
            remaining -= 1;
        }
        delta = delta.wrapping_add(1);
        n = n.wrapping_add(1);
    }
    return (string::__from_vec(output), crate::errors::nil);
}

// go: none — goish-only: Go writes `fmt.Errorf("cookiejar: invalid
// label %q", s)` inline at both call sites. Named here because the two
// sites are inside a loop that already borrows `s`.
fn invalidLabel(s: &string) -> error {
    return crate::fmt::Errorf!("cookiejar: invalid label %q", s.clone());
}

// go: sdk 1.25.5 net/http/cookiejar/punycode.go:101-109 encodeDigit
fn encodeDigit(digit: int32) -> byte {
    if 0 <= digit && digit < 26 {
        return crate::byte(digit + crate::int32(b'a'));
    }
    if 26 <= digit && digit < 36 {
        return crate::byte(digit + (crate::int32(b'0') - 26));
    }
    panic!("cookiejar: internal error in punycode encoding");
}

// go: sdk 1.25.5 net/http/cookiejar/punycode.go:112-125 adapt
/// Go: "adapt is the bias adaptation function specified in section
/// 6.1."
fn adapt(mut delta: int32, numPoints: int32, firstTime: bool) -> int32 {
    if firstTime {
        delta /= damp;
    } else {
        delta /= 2;
    }
    delta += delta / numPoints;
    let mut k: int32 = 0;
    while delta > ((base - tmin) * tmax) / 2 {
        delta /= base - tmin;
        k += base;
    }
    return k + (base - tmin + 1) * delta / (delta + skew);
}

// Go: "Strictly speaking, the remaining code below deals with IDNA (RFC
// 5890 and friends) and not Punycode (RFC 3492) per se."

// go: sdk 1.25.5 net/http/cookiejar/punycode.go:136-151 toASCII
/// Go: "toASCII converts a domain or domain label to its ASCII form.
/// For example, toASCII("bücher.example.com") is
/// "xn--bcher-kva.example.com", and toASCII("golang") is "golang"."
pub fn toASCII<S: Into<string>>(s: S) -> (string, error) {
    let s: string = s.into();
    if ascii::Is(s.clone()) {
        return (s, crate::errors::nil);
    }
    let labels = strings::Split(s.clone(), string::from_static("."));
    // Go assigns back into `labels[i]`; goish's slice indexing does not
    // hand out a place expression, so the rewritten labels accumulate
    // here and Join reads this instead.
    let mut out: Vec<string> = Vec::with_capacity(crate::builtin::__make_size(labels.Len()));
    let mut i: int = 0;
    while i < labels.Len() {
        let label = labels[i].clone();
        if !ascii::Is(label.clone()) {
            let (a, err) = encode(&string::from_static(acePrefix), &label);
            if !err.IsNil() {
                return (string::new(), err);
            }
            out.push(a);
        } else {
            out.push(label);
        }
        i += 1;
    }
    return (
        strings::Join(
            crate::goslice::slice::__from_vec(out),
            string::from_static("."),
        ),
        crate::errors::nil,
    );
}
