// testing_iotest_reader_smoke — iotest.TestReader and smallByteReader.
//
// smallByteReader forwards reads in deliberately awkward 1-, 2- and
// 3-byte chunks, cycling. That is the whole idea: a caller must not
// assume Read fills the buffer it was handed. Anything that treats a
// short read as EOF, or indexes past n, breaks here and passes against
// a well-behaved reader.
//
// TestReader itself pins three properties that apply to every Reader:
//   * Read with a zero-length buffer returns (0, nil) — NOT EOF.
//   * Reading through the awkward chunks reassembles to exactly the
//     content.
//   * At EOF, a further read returns (0, io.EOF).
//
// Checks 3 and 4 supply readers that violate the first and second, and
// require TestReader to reject them — otherwise a TestReader that
// returned nil unconditionally would pass check 1.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::bytes;
use goish::gostring::string;
use goish::io::Reader;
use goish::testing::iotest::TestReader;
use goish::types::{byte, int};
use goish::{errors, fmt, slice, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

fn content() -> slice<byte> {
    return slice::__from_vec(b"hello world, this is content".to_vec());
}

/// Reports EOF for a zero-length read, which Go forbids.
struct EofOnEmpty {
    data: slice<byte>,
    off: int,
}

impl Reader for EofOnEmpty {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, errors::error) {
        if p.Len() == 0 {
            // The violation: Go requires (0, nil) here.
            return (0, goish::io::EOF.clone().into());
        }
        if self.off >= self.data.Len() {
            return (0, goish::io::EOF.clone().into());
        }
        let mut n: int = 0;
        while n < p.Len() && self.off + n < self.data.Len() {
            p[n] = self.data[self.off + n];
            n += 1;
        }
        self.off += n;
        return (n, errors::nil);
    }
}

/// Silently drops one byte, so the reassembled content is short.
struct LossyReader {
    data: slice<byte>,
    off: int,
}

impl Reader for LossyReader {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, errors::error) {
        if p.Len() == 0 {
            return (0, errors::nil);
        }
        // Skip the very first byte of the stream — a single dropped
        // byte, which only a full-content comparison catches.
        if self.off == 0 {
            self.off = 1;
        }
        if self.off >= self.data.Len() {
            return (0, goish::io::EOF.clone().into());
        }
        p[0] = self.data[self.off];
        self.off += 1;
        return (1, errors::nil);
    }
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. A well-behaved reader passes.
    {
        let r = bytes::NewReader(content());
        let err = TestReader(r, content());
        if err == errors::nil {
            fmt::Println!("[ 1] bytes.Reader passes       PASS");
        } else {
            fmt::Println!("[ 1] bytes.Reader passes       FAIL ", err.Error());
            failed += 1;
        }
    }

    // 2. Empty content is legal — the Read(0) probe is skipped, and
    //    the reader is expected to be immediately at EOF.
    {
        let empty: slice<byte> = slice::new();
        let r = bytes::NewReader(empty.clone());
        let err = TestReader(r, empty);
        if err == errors::nil {
            fmt::Println!("[ 2] empty content passes      PASS");
        } else {
            fmt::Println!("[ 2] empty content passes      FAIL ", err.Error());
            failed += 1;
        }
    }

    // 3. A reader that returns EOF for a zero-length read is rejected.
    {
        let r = EofOnEmpty {
            data: content(),
            off: 0,
        };
        let err = TestReader(r, content());
        let m = if err != errors::nil { err.Error() } else { s("") };
        let ms: &str = m.as_ref();
        if err != errors::nil && ms.starts_with("Read(0) =") {
            fmt::Println!("[ 3] EOF-on-empty rejected     PASS");
        } else {
            fmt::Println!("[ 3] EOF-on-empty rejected     FAIL");
            failed += 1;
        }
    }

    // 4. A reader that silently drops a byte is rejected, because the
    //    reassembled content is compared in full.
    {
        let r = LossyReader {
            data: content(),
            off: 0,
        };
        let err = TestReader(r, content());
        let m = if err != errors::nil { err.Error() } else { s("") };
        let ms: &str = m.as_ref();
        if err != errors::nil && ms.starts_with("ReadAll(small amounts)") {
            fmt::Println!("[ 4] lossy reader rejected     PASS");
        } else {
            fmt::Println!("[ 4] lossy reader rejected     FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 4/4");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 4");
        syscall::Exit(1);
    }
}
