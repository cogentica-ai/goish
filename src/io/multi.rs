// go: file io/multi.go decls: eofReader.Read, multiReader.Read, multiReader.WriteTo, multiReader.writeToWithBuffer, MultiReader, multiWriter.Write, multiWriter.WriteString, MultiWriter
//
// multi.go — MultiReader and MultiWriter.

use crate::error;
use crate::errors::nil;
use crate::goslice::slice;
use crate::types::{byte, int};

use crate::d;

use super::*;

// go: sdk 1.25.5 io/multi.go:7-7 eofReader
/// A `Reader` that is always at EOF.
///
/// Go parks one of these in a slot it has finished with instead of
/// `nil`, so a later read of that slot returns EOF rather than panicking
/// (Issue 18232). goish's slots hold a `Box<dyn Reader>`, which cannot
/// be nil, so this is what goes in them.
struct eofReader;

impl Reader for eofReader {
    // go: sdk 1.25.5 io/multi.go:9-11 eofReader.Read
    fn Read(&mut self, _p: &mut slice<byte>) -> (int, error) {
        return (0, EOF.into());
    }
}

// ─── MultiReader ─────────────────────────────────────────────────────
//
// Slim port of multi.go:13 (`multiReader`). Public surface accepts a
// `slice<Box<dyn Reader>>` — Go's variadic `...Reader` becomes a slice
// of trait-object readers. Internal storage is `Vec<Box<dyn Reader>>`
// because Box<dyn Reader> is not Clone (slice's `.slice()` requires
// Clone, and we need pop-from-front via Vec::remove(0)).
//
// Deviations from Go: no flatten optimisation for nested multiReaders
// (multi.go:20-25); no WriteTo special case (multi.go:44-66).

/// `io.MultiReader` (multi.go:73) — concrete reader that concatenates
/// `mr.readers` sequentially. Returned by [`MultiReader`].
pub struct MultiReaderImpl {
    readers: alloc::vec::Vec<alloc::boxed::Box<dyn Reader>>,
}

impl Reader for MultiReaderImpl {
    // go: none — goish idiom: the hidden Any-view hooks every
    // `#[goish::interface]` concrete impl overrides so an assertion on
    // a `dyn io::Reader` / `dyn io::Writer` can reach this type. Go's
    // itabs make them unnecessary. Without the MUTABLE one, `io::Copy`
    // misses `src.(WriterTo)` / `dst.(ReaderFrom)` and the fast-path
    // impl on this type is unreachable through the interface.
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }
    // go: none — goish idiom: see `__goish_as_dyn_any`.
    fn __goish_as_dyn_any_mut(&mut self) -> Option<&mut (dyn core::any::Any + Send + Sync)> {
        return Some(self);
    }

    // go: sdk 1.25.5 io/multi.go:17-42 Read
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        // Go: for len(mr.readers) > 0
        let eof: error = EOF.into();
        while !self.readers.is_empty() {
            // Go: n, err = mr.readers[0].Read(p)
            let (n, err) = self.readers[0].Read(p);
            // Go: if err == EOF { mr.readers = mr.readers[1:] }
            let is_eof = err == eof;
            if is_eof {
                self.readers.remove(0);
            }
            // Go: if n > 0 || err != EOF { ... return }
            if n > 0 || !is_eof {
                // Go: if err == EOF && len(mr.readers) > 0 { err = nil }
                let mut err_out = err;
                if is_eof && !self.readers.is_empty() {
                    err_out = nil;
                }
                return (n, err_out);
            }
            // n == 0 && err == EOF: pop'd above, loop to next reader.
        }
        // Go: return 0, EOF
        return (0, EOF.into());
    }
}

impl WriterTo for MultiReaderImpl {
    // go: sdk 1.25.5 io/multi.go:44-46 multiReader.WriteTo
    fn WriteTo(&mut self, w: &mut dyn Writer) -> (i64, error) {
        return self.writeToWithBuffer(w, crate::make!([]byte, 1024 * 32));
    }
}

impl MultiReaderImpl {
    // go: sdk 1.25.5 io/multi.go:48-65 multiReader.writeToWithBuffer
    /// Drains every remaining reader into `w` through one shared
    /// buffer, and reports the total.
    ///
    /// The readers it has finished with are replaced by [`eofReader`],
    /// and on error the ones not yet reached are kept — Go slices
    /// `mr.readers` forward so a caller can resume after handling it,
    /// and the same must hold here or a retry would replay what was
    /// already written.
    fn writeToWithBuffer(&mut self, w: &mut dyn Writer, buf: slice<byte>) -> (i64, error) {
        let mut sum: i64 = 0;
        let mut i = 0usize;
        while i < self.readers.len() {
            // Go reuses the buffer through a nested multiReader's own
            // writeToWithBuffer; goish cannot downcast a `Box<dyn
            // Reader>` back to the concrete type, so a nested one is
            // drained through its `Read` instead. Same bytes, one more
            // buffer.
            let (n, err) = CopyBuffer(w, &mut *self.readers[i], buf.clone());
            sum += n;
            if !err.IsNil() {
                // Go: mr.readers = mr.readers[i:] — permit resume.
                self.readers.drain(..i);
                return (sum, err);
            }
            // Go: mr.readers[i] = nil — permit early GC.
            self.readers[i] = alloc::boxed::Box::new(eofReader);
            i += 1;
        }
        self.readers.clear();
        return (sum, nil);
    }
}

// go: sdk 1.25.5 io/multi.go:73-77 MultiReader
/// `io.MultiReader(readers...)` (multi.go:73) — slim port. Returns a
/// Reader that reads from each in sequence; EOF from one advances to
/// the next; final EOF surfaces only after the last reader is drained.
///
/// Pass readers as `slice<Box<dyn io::Reader>>` (the Go-variadic shape).
pub fn MultiReader(readers: slice<alloc::boxed::Box<dyn Reader>>) -> MultiReaderImpl {
    return MultiReaderImpl {
        readers: readers.__into_vec(),
    };
}

// ─── MultiWriter ─────────────────────────────────────────────────────
//
// Slim port of multi.go:79 (`multiWriter`). Each Write is fanned out to
// every wrapped writer; first error short-circuits. No flatten of nested
// multiWriters (multi.go:127-135) and no StringWriter optimisation
// (multi.go:97-119) — slim path always goes through Write.

/// `io.multiWriter` (multi.go:79) — concrete writer returned by
/// [`MultiWriter`]. Fans each Write out to all `t.writers`.
pub struct MultiWriterImpl {
    writers: alloc::vec::Vec<alloc::boxed::Box<dyn Writer>>,
}

impl Writer for MultiWriterImpl {
    // go: sdk 1.25.5 io/multi.go:83-95 Write
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        // Go: for _, w := range t.writers
        let plen = p.Len();
        for w in self.writers.iter_mut() {
            // Slim port: clone p per writer because goish Write consumes
            // its argument (Go shares the same []byte across writers).
            let (n, err) = w.Write(p.clone());
            // Go: if err != nil { return }
            if !err.IsNil() {
                return (n, err);
            }
            // Go: if n != len(p) { err = ErrShortWrite; return }
            if n != plen {
                return (n, ErrShortWrite.into());
            }
        }
        // Go: return len(p), nil
        return (plen, nil);
    }
}

impl StringWriter for MultiWriterImpl {
    // go: sdk 1.25.5 io/multi.go:99-119 multiWriter.WriteString
    /// Fans a string out to every wrapped writer, handing it to those
    /// that implement [`StringWriter`] as a string and encoding it once,
    /// lazily, for the rest.
    fn WriteString(&mut self, s: crate::gostring::string) -> (int, error) {
        let slen = s.Len();
        // Go: var p []byte — lazily initialized if/when needed.
        let mut p: Option<slice<byte>> = None;
        for w in self.writers.iter_mut() {
            // Go: `sw, ok := w.(StringWriter)`.
            //
            // `cast!` cannot spell this one. Its carrier must implement
            // `HasDynAnyMut`, which `#[goish::interface]` emits only for
            // `dyn Trait + Send + Sync`, and the writers here are held as
            // plain `Box<dyn Writer>` — so `cast!(&mut *w, …)` would
            // downcast the *box*, which is never a `StringWriter`, and
            // silently miss. Asking the trait's own Any-view hook and
            // then the `StringWriter` registry is the same two steps
            // `cast!` performs, minus the bound it cannot satisfy.
            //
            // The borrow of `w` that the hook hands out has to be over
            // before the `Write` fallback can touch `w` again, so the
            // assertion is asked twice rather than held across both
            // branches.
            let isStringWriter = Writer::__goish_as_dyn_any_mut(&mut **w)
                .and_then(<d!(StringWriter) as crate::any::DowncastableFromAnyMut>::from_any_mut)
                .is_some();
            let (n, err) = if isStringWriter {
                let sw = Writer::__goish_as_dyn_any_mut(&mut **w)
                    .and_then(
                        <d!(StringWriter) as crate::any::DowncastableFromAnyMut>::from_any_mut,
                    )
                    .unwrap();
                sw.WriteString(s.clone())
            } else {
                if p.is_none() {
                    p = Some(slice::__from_vec(s.as_bytes().to_vec()));
                }
                w.Write(p.clone().unwrap())
            };
            if !err.IsNil() {
                return (n, err);
            }
            if n != slen {
                return (n, ErrShortWrite.into());
            }
        }
        return (slen, nil);
    }
}

// go: sdk 1.25.5 io/multi.go:127-137 MultiWriter
/// `io.MultiWriter(writers...)` (multi.go:127) — slim port. Returns a
/// Writer that duplicates each Write to all listed writers in order.
pub fn MultiWriter(writers: slice<alloc::boxed::Box<dyn Writer>>) -> MultiWriterImpl {
    return MultiWriterImpl {
        writers: writers.__into_vec(),
    };
}
