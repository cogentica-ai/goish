// go: package bufio
//
// bufio — buffered I/O: it wraps an `io.Reader` or `io.Writer`,
// creating another object (`Reader` or `Writer`) that also implements
// the interface but provides buffering and some help for textual I/O.
//
// One Rust file per Go file, so each carries its own provenance
// anchors (GOISH015):
//
//   bufio.rs     bufio.go     — Reader, Writer, ReadWriter
//   scan.rs      scan.go      — Scanner and the split functions
//
// The package's sentinel errors and the `cached_error` helper they are
// built on live here, in the root, because Go declares them in two
// separate `var` blocks — one per file — and both files read both
// sets.
//
// Common Go idioms:
//
//   sc := bufio.NewScanner(os.Stdin)     let mut sc = bufio::NewScanner(os::Stdin());
//   for sc.Scan() {                      while sc.Scan() {
//       fmt.Println(sc.Text())               Println!(sc.Text());
//   }                                    }
//
//   r := bufio.NewReader(file)           let mut r = bufio::NewReader(file);
//   line, err := r.ReadString('\n')      let (line, err) = r.ReadString(b'\n');
//
//   w := bufio.NewWriter(os.Stdout)      let mut w = bufio::NewWriter(os::Stdout());
//   w.WriteString("hi\n")                w.WriteString(string("hi\n"));
//   w.Flush()                            let _ = w.Flush();
//
// Deviations from Go:
//
//   * `Scanner.Bytes()`, `Reader.Peek/ReadSlice/ReadLine` return *fresh*
//     `slice<byte>` clones. Go returns views into the internal buffer
//     that the next read invalidates. A goish slice owns its buffer
//     (copy-on-subslice), so cloning is the correct shape: slightly
//     more allocation, never invalidated.
//   * A split function's token is `Option<slice<byte>>`. Go's `[]byte`
//     can be nil, meaning "no token, keep reading", which an owning
//     slice cannot express. `None` is Go's nil, `Some(empty)` is a
//     genuine empty token such as a blank line.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use crate::errors::{self, error};
use crate::runtime::spin::SpinLock;

pub mod bufio;
pub mod scan;

pub(crate) use bufio::{__new_reader_with_buf, __new_writer_with_buf};
pub use bufio::{
    NewReadWriter, NewReader, NewReaderSize, NewWriter, NewWriterSize, PoolBuf, ReadWriter, Reader,
    Writer,
};
pub use scan::{
    MaxScanTokenSize, NewScanner, ScanBytes, ScanLines, ScanRunes, ScanWords, Scanner, SplitFunc,
};

pub use bufio::{
    ErrBufferFull, ErrInvalidUnreadByte, ErrInvalidUnreadRune, ErrNegativeCount, ErrNoProgress,
};
pub use scan::{ErrAdvanceTooFar, ErrBadReadCount, ErrFinalToken, ErrNegativeAdvance, ErrTooLong};
