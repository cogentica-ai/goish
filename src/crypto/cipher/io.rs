// crypto/cipher/io — wrap a cipher::Stream into io::Reader / io::Writer.
//
// Reference: /share/go/src/crypto/cipher/io.go (53 LOC).
//
// The Go file lives in the `cipher` package; goish puts it in a sibling
// submodule and re-exports the public surface from `crypto/cipher/mod.rs`
// so users still write `cipher::StreamReader{...}`.
//
// Slim deviations:
//
//   * Goish has static dispatch — `StreamReader<S, R>` and
//     `StreamWriter<S, W>` are generic over their inner types instead of
//     holding boxed trait objects. This means the type name carries the
//     pair, e.g. `cipher::StreamReader<rc4::Cipher, bytes::Reader>`.
//
//   * Go does `if c, ok := w.W.(io.Closer); ok { return c.Close() }` —
//     a runtime type assertion. Goish has no equivalent, so
//     `Closer` is implemented for `StreamWriter<S, W>` only when
//     `W: io::Closer`. Users with a non-Closer W simply don't get a
//     `Close` method — which matches Go's "returns nil" behavior, since
//     they wouldn't have called it anyway.
//
//   * `XORKeyStream(dst[:n], dst[:n])` (Go) becomes
//     `self.S.XORKeyStream(dst, src_copy)` where `src_copy = dst.slice(0,n)`
//     — goish slices have copy semantics on subslicing, so taking a
//     `dst.slice(0,n)` produces an independent input buffer; the trait
//     contract "if len(dst) > len(src), only dst[..src.Len()] is updated"
//     handles the partial-fill case identically to Go's `dst[:n]`.

#![allow(non_snake_case)]

extern crate alloc;

use crate::crypto::cipher::Stream;
use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::io;
use crate::types::{byte, int};

// Go: io.go:13
//   // The Stream* objects are so simple that all their members are public.
//   // Users can create them themselves.
//
// Go: io.go:15
//   type StreamReader struct {
//       S Stream
//       R io.Reader
//   }
/// `cipher.StreamReader` — wraps a [`Stream`] into an [`io::Reader`].
/// It calls `XORKeyStream` to process each slice of data which passes
/// through.
pub struct StreamReader<S: Stream, R: io::Reader> {
    pub S: S,
    pub R: R,
}

// Go: io.go:20
//   func (r StreamReader) Read(dst []byte) (n int, err error) {
//       n, err = r.R.Read(dst)
//       r.S.XORKeyStream(dst[:n], dst[:n])
//       return
//   }
impl<S: Stream, R: io::Reader> io::Reader for StreamReader<S, R> {
    fn Read(&mut self, dst: &mut slice<byte>) -> (int, error) {
        // Go: n, err = r.R.Read(dst)
        let (n, err) = self.R.Read(dst);
        // Go: r.S.XORKeyStream(dst[:n], dst[:n])
        // Take an independent copy of the freshly-read bytes as src,
        // then have the cipher overwrite dst[..n] in place.
        if n > 0 {
            let src_copy = dst.slice(0, n);
            self.S.XORKeyStream(dst, src_copy);
        }
        // Go: return
        (n, err)
    }
}

// Go: io.go:26
//   type StreamWriter struct {
//       S   Stream
//       W   io.Writer
//       Err error // unused
//   }
/// `cipher.StreamWriter` — wraps a [`Stream`] into an [`io::Writer`].
/// It calls `XORKeyStream` to process each slice of data which passes
/// through. If any [`StreamWriter::Write`] call returns short then the
/// `StreamWriter` is out of sync and must be discarded.
///
/// A `StreamWriter` has no internal buffering; [`StreamWriter::Close`]
/// does not need to be called to flush write data.
pub struct StreamWriter<S: Stream, W: io::Writer> {
    pub S: S,
    pub W: W,
    /// Go's `Err` field — unused, kept for surface compatibility.
    pub Err: error,
}

// Go: io.go:38
//   func (w StreamWriter) Write(src []byte) (n int, err error) {
//       c := make([]byte, len(src))
//       w.S.XORKeyStream(c, src)
//       n, err = w.W.Write(c)
//       if n != len(src) && err == nil { // should never happen
//           err = io.ErrShortWrite
//       }
//       return
//   }
impl<S: Stream, W: io::Writer> io::Writer for StreamWriter<S, W> {
    fn Write(&mut self, src: slice<byte>) -> (int, error) {
        let n_src = src.Len();
        // Go: c := make([]byte, len(src))
        let mut c: slice<byte> =
            slice::__from_vec(alloc::vec![0u8; n_src as usize]);
        // Go: w.S.XORKeyStream(c, src)
        self.S.XORKeyStream(&mut c, src);
        // Go: n, err = w.W.Write(c)
        let (n, err) = self.W.Write(c);
        // Go: if n != len(src) && err == nil { err = io.ErrShortWrite }
        if n != n_src && err.IsNil() {
            return (n, io::ErrShortWrite());
        }
        // Go: return
        (n, err)
    }
}

// Go: io.go:48
//   func (w StreamWriter) Close() error {
//       if c, ok := w.W.(io.Closer); ok {
//           return c.Close()
//       }
//       return nil
//   }
//
// Goish has no runtime type assertion. We implement `io::Closer` only
// when the underlying writer is itself a `Closer`. Holders of a
// non-Closer W see no `Close` method (matching Go's "returns nil"
// short-circuit — the call would have been a no-op anyway).
impl<S: Stream, W: io::Writer + io::Closer> io::Closer for StreamWriter<S, W> {
    fn Close(&mut self) -> error {
        // Go: return c.Close()
        let _ = nil; // keep `nil` import live for parity comments
        self.W.Close()
    }
}
