// net/http/cookiejar/punycode — RFC 3492 + IDNA toASCII
//
// Line-by-line port of:
//   /nix/store/60z37432vmgkg54krwr1z057bqwp7583-go-1.25.5/share/go/src/
//     net/http/cookiejar/punycode.go
//
// All computation is done with int32s, so overflow behaviour is identical
// regardless of whether the host int is 32-bit or 64-bit (Go comment at
// punycode.go:18-19).

#![allow(non_snake_case)]

extern crate alloc;
use alloc::vec::Vec;

use crate::errors::error;
use crate::gostring::string;
use crate::strings;
use crate::types::{byte, int};

use super::super::internal::ascii;

// Go: punycode.go:20-28 — RFC 3492 §5 parameter values.
const base: i32 = 36;
const damp: i32 = 700;
const initialBias: i32 = 72;
const initialN: i32 = 128;
const skew: i32 = 38;
const tmax: i32 = 26;
const tmin: i32 = 1;

// Go: punycode.go:131
const acePrefix: &str = "xn--";

// Go: punycode.go:35 — encode a single label (no dots).
//
//   func encode(prefix, s string) (string, error)
//
// The "while h < length(input)" line in the spec becomes "for remaining != 0"
// in Go because len(s) is in bytes not runes.
pub fn encode(prefix: &string, s: &string) -> (string, error) {
    // Go: output := make([]byte, len(prefix), len(prefix)+1+2*len(s))
    let mut output: Vec<byte> = Vec::with_capacity(
        crate::builtin::len(prefix) as usize + 1 + 2 * crate::builtin::len(s) as usize,
    );
    // Go: copy(output, prefix)
    let prefix_bytes = crate::gostring::__crate_as_bytes(prefix);
    output.extend_from_slice(prefix_bytes);

    // Go: delta, n, bias := int32(0), initialN, initialBias
    let mut delta: i32 = 0;
    let mut n: i32 = initialN;
    let mut bias: i32 = initialBias;

    // Go: b, remaining := int32(0), int32(0)
    let mut b: i32 = 0;
    let mut remaining: i32 = 0;

    // Go: for _, r := range s { ... } — first pass: emit basic (ASCII) runes
    // verbatim; count rest.
    for (_, r) in crate::range!(s.clone()) {
        // Go: if r < utf8.RuneSelf
        if (r as u32) < 0x80 {
            b += 1;
            output.push(r as byte);
        } else {
            remaining += 1;
        }
    }

    // Go: h := b
    let mut h: i32 = b;
    // Go: if b > 0 { output = append(output, '-') }
    if b > 0 {
        output.push(b'-');
    }

    // Go: for remaining != 0
    while remaining != 0 {
        // Go: m := int32(0x7fffffff)
        let mut m: i32 = 0x7fffffff;
        // Go: for _, r := range s { if m > r && r >= n { m = r } }
        for (_, r) in crate::range!(s.clone()) {
            let r32 = r as i32;
            if m > r32 && r32 >= n {
                m = r32;
            }
        }
        // Go: delta += (m - n) * (h + 1)
        delta = delta.wrapping_add(m.wrapping_sub(n).wrapping_mul(h + 1));
        // Go: if delta < 0 { return "", fmt.Errorf("cookiejar: invalid label %q", s) }
        if delta < 0 {
            return (
                string::new(),
                crate::errors::New(string::from_static("cookiejar: invalid label")),
            );
        }
        n = m;
        // Go: for _, r := range s
        for (_, r) in crate::range!(s.clone()) {
            let r32 = r as i32;
            // Go: if r < n { delta++; if delta < 0 { ...err }; continue }
            if r32 < n {
                delta = delta.wrapping_add(1);
                if delta < 0 {
                    return (
                        string::new(),
                        crate::errors::New(string::from_static("cookiejar: invalid label")),
                    );
                }
                continue;
            }
            // Go: if r > n { continue }
            if r32 > n {
                continue;
            }
            // Go: q := delta
            let mut q: i32 = delta;
            // Go: for k := base; ; k += base
            let mut k: i32 = base;
            loop {
                // Go: t := k - bias; clamp to [tmin, tmax]
                let mut t: i32 = k - bias;
                if t < tmin {
                    t = tmin;
                } else if t > tmax {
                    t = tmax;
                }
                // Go: if q < t { break }
                if q < t {
                    break;
                }
                // Go: output = append(output, encodeDigit(t+(q-t)%(base-t)))
                output.push(encodeDigit(t + (q - t) % (base - t)));
                // Go: q = (q - t) / (base - t)
                q = (q - t) / (base - t);
                k += base;
            }
            // Go: output = append(output, encodeDigit(q))
            output.push(encodeDigit(q));
            // Go: bias = adapt(delta, h+1, h == b)
            bias = adapt(delta, h + 1, h == b);
            // Go: delta = 0; h++; remaining--
            delta = 0;
            h += 1;
            remaining -= 1;
        }
        // Go: delta++; n++
        delta = delta.wrapping_add(1);
        n = n.wrapping_add(1);
    }

    // Go: return string(output), nil
    (string::__from_vec(output), crate::errors::nil)
}

// Go: punycode.go:101 — encodeDigit
fn encodeDigit(digit: i32) -> byte {
    // Go: case 0 <= digit && digit < 26: return byte(digit + 'a')
    if (0..26).contains(&digit) {
        return (digit + b'a' as i32) as byte;
    }
    // Go: case 26 <= digit && digit < 36: return byte(digit + ('0' - 26))
    if (26..36).contains(&digit) {
        return (digit + (b'0' as i32 - 26)) as byte;
    }
    // Go: panic("cookiejar: internal error in punycode encoding")
    panic!("cookiejar: internal error in punycode encoding");
}

// Go: punycode.go:111 — adapt is the bias adaptation function (RFC 3492 §6.1).
fn adapt(mut delta: i32, numPoints: i32, firstTime: bool) -> i32 {
    // Go: if firstTime { delta /= damp } else { delta /= 2 }
    if firstTime {
        delta /= damp;
    } else {
        delta /= 2;
    }
    // Go: delta += delta / numPoints
    delta += delta / numPoints;
    // Go: k := int32(0)
    let mut k: i32 = 0;
    // Go: for delta > ((base - tmin) * tmax) / 2
    while delta > ((base - tmin) * tmax) / 2 {
        delta /= base - tmin;
        k += base;
    }
    // Go: return k + (base-tmin+1)*delta/(delta+skew)
    k + (base - tmin + 1) * delta / (delta + skew)
}

// Go: punycode.go:136 — toASCII converts a domain (or single label) to its
// ASCII form via Punycode/IDNA.
//
//   toASCII("bücher.example.com") == "xn--bcher-kva.example.com"
//   toASCII("golang")             == "golang"
pub fn toASCII(s: string) -> (string, error) {
    // Go: if ascii.Is(s) { return s, nil }
    if ascii::Is(s.clone()) {
        return (s, crate::errors::nil);
    }
    // Go: labels := strings.Split(s, ".")
    let labels = strings::Split(s.clone(), string::from_static("."));
    let mut out: alloc::vec::Vec<string> = alloc::vec::Vec::with_capacity(labels.Len() as usize);
    // Go: for i, label := range labels
    let mut i: int = 0;
    while i < labels.Len() {
        let label = labels[i].clone();
        // Go: if !ascii.Is(label) { a, err := encode(acePrefix, label); ... labels[i] = a }
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
    // Go: return strings.Join(labels, "."), nil
    (
        strings::Join(crate::goslice::slice::__from_vec(out), string::from_static(".")),
        crate::errors::nil,
    )
}
