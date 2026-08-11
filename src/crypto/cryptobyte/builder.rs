// go: file vendor/golang.org/x/crypto/cryptobyte/builder.go decls: NewBuilder, NewFixedBuilder, Builder.SetError, Builder.Bytes, Builder.BytesOrPanic, Builder.AddUint8, Builder.AddUint16, Builder.AddUint24, Builder.AddUint32, Builder.AddUint48, Builder.AddUint64, Builder.AddBytes, Builder.AddUint8LengthPrefixed, Builder.AddUint16LengthPrefixed, Builder.AddUint24LengthPrefixed, Builder.AddUint32LengthPrefixed, Builder.callContinuation, Builder.addLengthPrefixed, Builder.flushChild, Builder.add, Builder.Unwrite, Builder.AddValue
//
// The Builder type is for constructing messages. It provides helper
// functions for appending values and also for appending length-prefixed
// submessages — without having to worry about calculating the length
// prefix ahead of time.
//
// Deviations from builder[go] @ Go 1.25.5:
//
//   * **No child Builder.** Go's `addLengthPrefixed` allocates a
//     `child *Builder` sharing the parent's `result` slice, hands it to
//     the continuation, and reconciles in `flushChild`. Two Rust `&mut`
//     borrows of the same buffer cannot coexist, so the continuation is
//     handed `self` and the four fields the child would have owned
//     (`offset`, `pendingLenLen`, `pendingIsASN1`) are saved and restored
//     around it. `flushChild` then reads them exactly where Go reads
//     `child.*`. The bytes produced are identical; what is gone is a
//     heap allocation per nesting level — and Go's "attempted write while
//     child is pending" guard, which catches writing to the *parent*
//     mid-continuation. With one builder there is no parent to write to,
//     so that state cannot be reached rather than being unchecked.
//   * **No panic/recover.** Go's `callContinuation` installs a `defer`
//     that recovers a `BuildError` panic and turns it into `b.err`, so a
//     continuation can abort the build by panicking. goish runs
//     `panic = abort` with per-goroutine isolation, so that channel does
//     not exist; a continuation reports failure with `SetError`, which is
//     the same end state. `BuildError` is kept as a type so the shape is
//     visible, and nothing in the crypto tree panics from a continuation.
//   * `BuilderContinuation` is `impl FnOnce(&mut Builder)` at each call
//     site rather than a named func type: Go's is a function *value*, and
//     goish has no closure-value carrier for this shape (unlike
//     `hash::HashFunc`, nothing stores one in a field).
//   * `add(bytes ...byte)` is variadic; goish takes `&[byte]`.
//
// goishlint:ignore GOISH021 — `BuilderContinuation` is Go's named func
// type for the continuation parameter; see the deviation above.

#![allow(non_snake_case)]

extern crate alloc;
use alloc::vec::Vec;

use crate::errors;
use crate::goslice::slice;
use crate::types::byte;
use crate::{int, uint16, uint32, uint64};
use crate::{error, int64, uint8};

// Go: builder.go:23-33
//   type Builder struct { err error; result []byte; fixedSize bool;
//                         child *Builder; offset int; pendingLenLen int;
//                         pendingIsASN1 bool; inContinuation *bool }
/// Builds byte strings from padded, length-prefixed values.
pub struct Builder {
    err: error,
    result: Vec<byte>,
    fixedSize: bool,
    /// Go's `child *Builder`. The continuation runs against `self` here,
    /// so there is no separate parent to write to while a child is
    /// pending — the state Go's flag exists to catch is unrepresentable,
    /// and the flag stays false. `add` and `Unwrite` keep their checks so
    /// the Go control flow is visible.
    child: bool,
    offset: usize,
    pendingLenLen: int,
    pendingIsASN1: bool,
}

// go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/builder.go:35-42 NewBuilder
/// Create a Builder that appends its output to the given buffer.
pub fn NewBuilder(buffer: slice<byte>) -> Builder {
    let r: &[byte] = &buffer;
    return Builder {
        err: crate::nil.into(),
        result: r.to_vec(),
        fixedSize: false,
        child: false,
        offset: 0,
        pendingLenLen: 0,
        pendingIsASN1: false,
    };
}

// go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/builder.go:44-52 NewFixedBuilder
/// Create a Builder that appends its output into the given buffer. This
/// builder does not reallocate the output buffer. Writes that would exceed
/// the buffer's capacity are treated as an error.
pub fn NewFixedBuilder(buffer: slice<byte>) -> Builder {
    let mut b = NewBuilder(buffer);
    b.fixedSize = true;
    return b;
}

// Go: builder.go:135 — `type BuilderContinuation func(child *Builder)`
//
// Kept as a doc anchor only; see the file header for why the parameter is
// `impl FnOnce(&mut Builder)` at each call site.

// Go: builder.go:138-142
//   type BuildError struct { Err error }
/// Wraps an error. In Go, a continuation may panic with this value and
/// `Builder.Bytes` returns the inner error; goish has no recover path, so
/// a continuation calls `SetError` instead.
pub struct BuildError {
    pub Err: error,
}

impl Builder {
    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/builder.go:54-58 SetError
    /// Set the value to be returned as the error from Bytes. Writes
    /// performed after calling SetError are ignored.
    pub fn SetError(&mut self, err: error) {
        self.err = err;
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/builder.go:60-67 Bytes
    /// Return the bytes written by the builder, or an error if one has
    /// occurred during building.
    pub fn Bytes(&self) -> (slice<byte>, error) {
        if self.err != crate::nil {
            return (
                slice::__from_vec(Vec::<byte>::new()),
                self.err.clone(),
            );
        }
        return (
            slice::__from_vec(self.result[self.offset..].to_vec()),
            crate::nil.into(),
        );
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/builder.go:69-76 BytesOrPanic
    /// Return the bytes written by the builder, or panic if an error has
    /// occurred during building.
    pub fn BytesOrPanic(&self) -> slice<byte> {
        if self.err != crate::nil {
            panic!("cryptobyte: Builder error");
        }
        return slice::__from_vec(self.result[self.offset..].to_vec());
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/builder.go:78-81 AddUint8
    /// Append an 8-bit value to the byte string.
    pub fn AddUint8(&mut self, v: uint8) {
        self.add(&[v]);
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/builder.go:83-86 AddUint16
    /// Append a big-endian, 16-bit value to the byte string.
    pub fn AddUint16(&mut self, v: uint16) {
        self.add(&[uint8(v >> 8), uint8(v)]);
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/builder.go:88-92 AddUint24
    /// Append a big-endian, 24-bit value to the byte string. The highest
    /// byte of the 32-bit input value is silently truncated.
    pub fn AddUint24(&mut self, v: uint32) {
        self.add(&[uint8(v >> 16), uint8(v >> 8), uint8(v)]);
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/builder.go:94-97 AddUint32
    /// Append a big-endian, 32-bit value to the byte string.
    pub fn AddUint32(&mut self, v: uint32) {
        self.add(&[uint8(v >> 24), uint8(v >> 16), uint8(v >> 8), uint8(v)]);
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/builder.go:99-102 AddUint48
    /// Append a big-endian, 48-bit value to the byte string.
    pub fn AddUint48(&mut self, v: uint64) {
        self.add(&[
            uint8(v >> 40),
            uint8(v >> 32),
            uint8(v >> 24),
            uint8(v >> 16),
            uint8(v >> 8),
            uint8(v),
        ]);
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/builder.go:104-107 AddUint64
    /// Append a big-endian, 64-bit value to the byte string.
    pub fn AddUint64(&mut self, v: uint64) {
        self.add(&[
            uint8(v >> 56),
            uint8(v >> 48),
            uint8(v >> 40),
            uint8(v >> 32),
            uint8(v >> 24),
            uint8(v >> 16),
            uint8(v >> 8),
            uint8(v),
        ]);
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/builder.go:109-112 AddBytes
    /// Append a sequence of bytes to the byte string.
    pub fn AddBytes(&mut self, v: &slice<byte>) {
        let r: &[byte] = v;
        self.add(r);
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/builder.go:144-148 AddUint8LengthPrefixed
    /// Add an 8-bit length-prefixed byte sequence.
    pub fn AddUint8LengthPrefixed<F: FnOnce(&mut Builder)>(&mut self, f: F) {
        self.addLengthPrefixed(1, false, f);
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/builder.go:150-153 AddUint16LengthPrefixed
    /// Add a big-endian, 16-bit length-prefixed byte sequence.
    pub fn AddUint16LengthPrefixed<F: FnOnce(&mut Builder)>(&mut self, f: F) {
        self.addLengthPrefixed(2, false, f);
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/builder.go:155-158 AddUint24LengthPrefixed
    /// Add a big-endian, 24-bit length-prefixed byte sequence.
    pub fn AddUint24LengthPrefixed<F: FnOnce(&mut Builder)>(&mut self, f: F) {
        self.addLengthPrefixed(3, false, f);
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/builder.go:160-162 AddUint32LengthPrefixed
    /// Add a big-endian, 32-bit length-prefixed byte sequence.
    pub fn AddUint32LengthPrefixed<F: FnOnce(&mut Builder)>(&mut self, f: F) {
        self.addLengthPrefixed(4, false, f);
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/builder.go:164-185 callContinuation
    //
    // Go wraps the call in a `defer` that recovers a `BuildError` panic;
    // see the file header for why goish calls the continuation directly.
    // goishlint:ignore GOISH020 — Go's second parameter is `arg *Builder`,
    // always `b.child`; with no child, it is the receiver.
    fn callContinuation<F: FnOnce(&mut Builder)>(&mut self, f: F) {
        f(self);
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/builder.go:187-214 addLengthPrefixed
    pub(super) fn addLengthPrefixed<F: FnOnce(&mut Builder)>(
        &mut self,
        lenLen: int,
        isASN1: bool,
        f: F,
    ) {
        // Subsequent writes can be ignored if the builder has encountered
        // an error.
        if self.err != crate::nil {
            return;
        }

        let offset = self.result.len();
        self.add(&alloc::vec![0u8; lenLen as usize]);

        // Go allocates a child Builder sharing `result`; goish saves the
        // fields that child would have owned and runs the continuation
        // against self.
        let savedOffset = self.offset;
        let savedLenLen = self.pendingLenLen;
        let savedIsASN1 = self.pendingIsASN1;
        self.offset = offset;
        self.pendingLenLen = lenLen;
        self.pendingIsASN1 = isASN1;

        self.callContinuation(f);
        self.flushChild();

        self.offset = savedOffset;
        self.pendingLenLen = savedLenLen;
        self.pendingIsASN1 = savedIsASN1;
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/builder.go:216-292 flushChild
    //
    // Go reads `child.*`; here the pending state is on self, set by
    // addLengthPrefixed. The arithmetic is unchanged.
    fn flushChild(&mut self) {
        if self.err != crate::nil {
            return;
        }

        let mut length = int64(self.result.len()) - self.pendingLenLen - int64(self.offset);

        if length < 0 {
            panic!("cryptobyte: internal error"); // result unexpectedly shrunk
        }

        if self.pendingIsASN1 {
            // For ASN.1, we reserved a single byte for the length. If that
            // turned out to be incorrect, we have to move the contents
            // along in order to make space.
            if self.pendingLenLen != 1 {
                panic!("cryptobyte: internal error");
            }
            let lenLen: uint8;
            let lenByte: uint8;
            if length > 0xfffffffe {
                self.err = errors::New("pending ASN.1 child too long");
                return;
            } else if length > 0xffffff {
                lenLen = 5;
                lenByte = 0x80 | 4;
            } else if length > 0xffff {
                lenLen = 4;
                lenByte = 0x80 | 3;
            } else if length > 0xff {
                lenLen = 3;
                lenByte = 0x80 | 2;
            } else if length > 0x7f {
                lenLen = 2;
                lenByte = 0x80 | 1;
            } else {
                lenLen = 1;
                lenByte = uint8(length);
                length = 0;
            }

            // Insert the initial length byte, make space for successive
            // length bytes, and adjust the offset.
            self.result[self.offset] = lenByte;
            let extraBytes = (lenLen - 1) as usize;
            if extraBytes != 0 {
                self.add(&alloc::vec![0u8; extraBytes]);
                let childStart = self.offset + self.pendingLenLen as usize;
                let n = self.result.len() - (childStart + extraBytes);
                self.result
                    .copy_within(childStart..childStart + n, childStart + extraBytes);
            }
            self.offset += 1;
            self.pendingLenLen = int(extraBytes);
        }

        let mut l = length;
        let mut i = self.pendingLenLen - 1;
        while i >= 0 {
            self.result[self.offset + i as usize] = uint8(l);
            l >>= 8;
            i -= 1;
        }
        if l != 0 {
            self.err = crate::fmt::Errorf!(
                "cryptobyte: pending child length %d exceeds %d-byte length prefix",
                length,
                self.pendingLenLen
            );
            return;
        }
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/builder.go:294-312 add
    fn add(&mut self, bytes: &[byte]) {
        if self.err != crate::nil {
            return;
        }
        if self.child {
            panic!("cryptobyte: attempted write while child is pending");
        }
        if self.result.len() + bytes.len() < bytes.len() {
            self.err = errors::New("cryptobyte: length overflow");
        }
        if self.fixedSize && self.result.len() + bytes.len() > self.result.capacity() {
            self.err = errors::New("cryptobyte: Builder is exceeding its fixed-size buffer");
            return;
        }
        self.result.extend_from_slice(bytes);
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/builder.go:314-333 Unwrite
    /// Roll back non-negative n bytes written directly to the Builder.
    pub fn Unwrite(&mut self, n: int) {
        if self.err != crate::nil {
            return;
        }
        if self.child {
            panic!("cryptobyte: attempted unwrite while child is pending");
        }
        let length = int64(self.result.len()) - self.pendingLenLen - int64(self.offset);
        if length < 0 {
            panic!("cryptobyte: internal error");
        }
        if n < 0 {
            panic!("cryptobyte: attempted to unwrite negative number of bytes");
        }
        if n > length {
            panic!("cryptobyte: attempted to unwrite more than was written");
        }
        let keep = self.result.len() - n as usize;
        self.result.truncate(keep);
    }

    // go: sdk 1.25.5 vendor/golang.org/x/crypto/cryptobyte/builder.go:342-348 AddValue
    /// Call Marshal on v, passing a pointer to the builder to append to.
    /// If Marshal returns an error, it is set on the Builder so that
    /// subsequent appends don't have an effect.
    pub fn AddValue<V: MarshalingValue>(&mut self, v: &V) {
        let err = v.Marshal(self);
        if err != crate::nil {
            self.err = err;
        }
    }
}

// Go: builder.go:335-340
//   type MarshalingValue interface { Marshal(b *Builder) error }
/// A value that marshals itself into a Builder.
pub trait MarshalingValue {
    /// Called by Builder.AddValue. It receives the builder to marshal
    /// itself into. It may return an error that occurred during
    /// marshaling, such as unset or invalid values.
    fn Marshal(&self, b: &mut Builder) -> error;
}
