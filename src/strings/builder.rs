// go: file strings/builder.go decls: new, default, Builder.String, Builder.Len, Builder.Cap, Builder.Reset, Builder.Grow, Builder.Write, Builder.WriteByte, Builder.WriteRune, Builder.WriteString
//
// goishlint:ignore GOISH018 Builder.grow — Go's unexported `grow` is the
//     reallocation half of `Grow`: it makes a `2*cap+n` buffer and copies
//     into it. Rust's `Vec::reserve(n)` guarantees room for n MORE
//     elements past the current length, which is exactly what `grow`
//     leaves behind, so `Grow` calls it directly and there is no second
//     function to name.
//
// goishlint:ignore GOISH018 copyCheck — see the waiver below; the
//     `// go: waived` line takes it out of the coverage denominator,
//     this takes it out of the dropped-function check.
//
// go: waived copyCheck — Go's Builder holds an `addr *Builder` self
//     pointer and copyCheck panics when it finds the Builder has been
//     copied, using `noescape` to keep that pointer off the heap. A
//     goish Builder owns its Vec and a copy is a deep copy, so there is
//     no aliasing bug to detect and no self pointer to compare.
//
// strings/builder.go — an append-only byte buffer that hands out a
// `string` without copying.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;
use alloc::vec::Vec;

use crate::convert::int as toint;
use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::gostring::string;
use crate::io;
use crate::types::{byte, int, rune};
use crate::unicode::utf8;

// ─── Builder ──────────────────────────────────────────────────────────
//
// Append-only buffer.
//
// Differences from Go's strings.Builder:
//
//   * `String` copies. Go's is zero-copy (`unsafe.String` over the live
//     buffer), which is why Go needs `copyCheck` and why a Go caller
//     must not copy a used Builder. goish returns an owned `string`
//     instead: no alias to the buffer escapes, so there is nothing to
//     check, at the price of one copy per call.
//
//     `String` used to consume the builder, which made calling it twice
//     a compile error. That is safe, but it is not Go's contract:
//     `func (b *Builder) String() string` takes a POINTER, so writing
//     more after reading is ordinary, and code that does
//     `if b.Len() > 0 { log(b.String()) }` and then keeps building is
//     idiomatic. Taking `&self` restores that and removes the alias
//     hazard by copying, so both properties hold at once.
//   * No `addr` self-pointer / copyCheck — see above; there is no
//     borrowed buffer to protect.

pub struct Builder {
    buf: Vec<byte>,
}

impl Builder {
    // go: none — goish idiom: Go's zero `Builder` is ready to use, so
    //     `var b strings.Builder` needs no constructor. A goish
    //     `Builder` owns a `Vec`, so the zero value is spelled here and
    //     by the `Default` impl below.
    pub fn new() -> Self {
        return Self { buf: Vec::new() };
    }

    // go: sdk 1.25.5 strings/builder.go:51-51 Builder.Len
    pub fn Len(&self) -> int {
        return toint(self.buf.len());
    }

    // go: sdk 1.25.5 strings/builder.go:56-56 Builder.Cap
    pub fn Cap(&self) -> int {
        return toint(self.buf.capacity());
    }

    // go: sdk 1.25.5 strings/builder.go:59-62 Builder.Reset
    pub fn Reset(&mut self) {
        self.buf.clear();
    }

    // go: sdk 1.25.5 strings/builder.go:75-83 Builder.Grow
    pub fn Grow(&mut self, n: int) {
        if n < 0 {
            panic!("strings.Builder.Grow: negative count");
        }
        // Go: if cap(b.buf)-len(b.buf) < n { b.grow(n) }, and `grow`
        // leaves "at least n bytes of capacity beyond len(b.buf)".
        //
        // Rust's `Vec::reserve(additional)` means exactly that — room
        // for `additional` MORE elements past the current length — so
        // it is the whole of Go's Grow. Subtracting the already
        // available headroom first, as this used to, under-reserved by
        // that amount: Grow(64) on a Builder holding "abc" with
        // capacity 8 reserved 56 and left `Cap()` at 56, so a caller
        // who grew to avoid a reallocation still got one.
        let extra = n as usize;
        if self.buf.capacity() - self.buf.len() < extra {
            self.buf.reserve(extra);
        }
    }

    // go: sdk 1.25.5 strings/builder.go:46-48 Builder.String
    /// Go: "String returns the accumulated string."
    ///
    /// Takes `&self`, as Go's pointer receiver does, so the builder can
    /// be read and then written to again. See the module note for why
    /// this copies where Go does not.
    pub fn String(&self) -> string {
        return string::from_bytes(&self.buf);
    }

    // go: sdk 1.25.5 strings/builder.go:112-116 Builder.WriteString
    pub fn WriteString<S: Into<string>>(&mut self, s: S) -> (int, error) {
        let s = s.into();
        let bytes = s.as_bytes();
        self.buf.extend_from_slice(bytes);
        return (toint(bytes.len()), nil);
    }

    // go: sdk 1.25.5 strings/builder.go:95-99 Builder.WriteByte
    pub fn WriteByte(&mut self, c: byte) -> error {
        self.buf.push(c);
        return nil;
    }

    // go: sdk 1.25.5 strings/builder.go:103-108 Builder.WriteRune
    pub fn WriteRune(&mut self, r: rune) -> (int, error) {
        let mut tmp = [0u8; 4];
        let n = utf8::EncodeRune(&mut tmp, r);
        self.buf.extend_from_slice(&tmp[..n as usize]);
        return (n, nil);
    }
}

impl Default for Builder {
    // go: none — goish idiom: the same zero value as `new`, reachable
    //     through `Default` so a `Builder` can sit in a `#[derive]`d
    //     struct. Go gets this from its zero-value rule.
    fn default() -> Self {
        return Self::new();
    }
}

// `io.Writer` impl — consumes the slice, writes its bytes, returns
// `(len(p), nil)`. Lets `Fprintf!(b, ...)` target a Builder.
impl io::Writer for Builder {
    // go: sdk 1.25.5 strings/builder.go:87-91 Builder.Write
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        let n = p.Len();
        self.buf.extend_from_slice(&p);
        return (n, nil);
    }
}

// go: waived Builder.grow — the reallocation half of `Grow`, which here is `Vec::reserve(n)`: same guarantee, no second function to name.
