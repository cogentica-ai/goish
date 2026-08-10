// go: file crypto/internal/fips140/subtle/xor_generic.go decls: xorBytes, aligned, words, xorLoop
//
// Go builds this file only for architectures with no XOR assembly
// (`//go:build (!amd64 && ...) || purego`); on amd64 it uses xor_amd64.s.
// goish has no crypto assembly, so the generic path IS the implementation
// for x86_64 — the same code Go runs under `purego`.
//
// Deviations, both forced by goish `slice<byte>` not exposing raw pointer
// arithmetic:
//
//   * `xorBytes` takes slices directly rather than `(*byte, *byte, *byte, n)`
//     plus `unsafe.Slice` to rebuild them. Go's pointer signature exists to
//     match the assembly calling convention; there is no assembly here.
//   * `aligned` derives the three addresses from `as_ptr()` instead of
//     `unsafe.Pointer`. `words` returns owned `uintptr`s rather than a view
//     aliasing the byte slice (`unsafe.Slice((*uintptr)(...))`), so xorBytes
//     stores the XORed words back explicitly. Same values, same word count,
//     one extra copy.

#![allow(non_snake_case)]

extern crate alloc;

use crate::types::{byte, int, uintptr};

// go: sdk 1.25.5 crypto/internal/fips140/subtle/xor_generic.go:14 wordSize
//
//   const wordSize = unsafe.Sizeof(uintptr(0))
const wordSize: usize = core::mem::size_of::<uintptr>();

// go: sdk 1.25.5 crypto/internal/fips140/subtle/xor_generic.go:16-20 supportsUnaligned
//
//   const supportsUnaligned = runtime.GOARCH == "386" || ... "amd64" ...
// goish is x86_64-only, so this is statically true.
const supportsUnaligned: bool = true;

// go: sdk 1.25.5 crypto/internal/fips140/subtle/xor_generic.go:22-39 xorBytes
pub(crate) fn xorBytes(dst: &mut [byte], x: &[byte], y: &[byte], n: int) {
    let n = usize::try_from(n).unwrap_or(0);
    let dst = &mut dst[..n];
    let x = &x[..n];
    let y = &y[..n];

    // Go: if supportsUnaligned || aligned(dstb, xb, yb) { ... }
    if supportsUnaligned || aligned(dst, x, y) {
        // Go: xorLoop(words(dst), words(x), words(y))
        let nw = words_len(dst.len());
        if nw > 0 {
            let mut wdst: alloc::vec::Vec<uintptr> = words(&dst[..nw * wordSize]);
            let wx = words(&x[..nw * wordSize]);
            let wy = words(&y[..nw * wordSize]);
            xorLoop(&mut wdst, &wx, &wy);
            // Write the word results back (Go aliases the same memory; goish
            // cannot alias a &mut [byte] as &mut [uintptr] without unsafe, so
            // the words are materialised and stored back).
            let mut i: usize = 0;
            while i < nw {
                let off = i * wordSize;
                dst[off..off + wordSize].copy_from_slice(&wdst[i].to_ne_bytes());
                i += 1;
            }
        }
        // Go: if uintptr(n)%wordSize == 0 { return }
        if n % wordSize == 0 {
            return;
        }
        // Go: done := n &^ int(wordSize-1); dst, x, y = dst[done:], ...
        let done = n & !(wordSize - 1);
        xorLoop(&mut dst[done..], &x[done..], &y[done..]);
        return;
    }
    // Go: xorLoop(dst, x, y)
    xorLoop(dst, x, y);
}

// go: sdk 1.25.5 crypto/internal/fips140/subtle/xor_generic.go:42-44 aligned
//
/// Report whether `dst`, `x` and `y` are all word-aligned.
fn aligned(dst: &[byte], x: &[byte], y: &[byte]) -> bool {
    // Go: return (uintptr(dst)|uintptr(x)|uintptr(y))&(wordSize-1) == 0
    let d = dst.as_ptr() as usize;
    let xa = x.as_ptr() as usize;
    let ya = y.as_ptr() as usize;
    return (d | xa | ya) & (wordSize - 1) == 0;
}

// go: sdk 1.25.5 crypto/internal/fips140/subtle/xor_generic.go:48-56 words
//
/// Return the `uintptr` words of `x`, with any trailing partial word
/// removed. Go returns a view aliasing `x`; goish returns owned words
/// (see the module deviation note) — same values, same count.
fn words(x: &[byte]) -> alloc::vec::Vec<uintptr> {
    // Go: n := uintptr(len(x)) / wordSize; if n == 0 { return nil }
    let n = x.len() / wordSize;
    let mut out: alloc::vec::Vec<uintptr> = alloc::vec::Vec::with_capacity(n);
    let mut i: usize = 0;
    while i < n {
        let off = i * wordSize;
        let mut buf = [0u8; wordSize];
        buf.copy_from_slice(&x[off..off + wordSize]);
        out.push(uintptr::from_ne_bytes(buf));
        i += 1;
    }
    return out;
}

// go: none — helper: the word count Go computes inline inside `words`
// (`n := uintptr(len(x)) / wordSize`); split out because goish's `words`
// returns owned words and xorBytes needs the count before allocating.
#[inline]
fn words_len(byte_len: usize) -> usize {
    return byte_len / wordSize;
}

// go: sdk 1.25.5 crypto/internal/fips140/subtle/xor_generic.go:58-64 xorLoop
//
//   func xorLoop[T byte | uintptr](dst, x, y []T)
fn xorLoop<T: Copy + core::ops::BitXor<Output = T>>(dst: &mut [T], x: &[T], y: &[T]) {
    // Go: x = x[:len(dst)]; y = y[:len(dst)]  — bounds-check elision.
    let n = dst.len();
    // Go: for i := range dst { dst[i] = x[i] ^ y[i] }
    let mut i: usize = 0;
    while i < n {
        dst[i] = x[i] ^ y[i];
        i += 1;
    }
}
