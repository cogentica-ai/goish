// testing_iotest_smoke — pin the iotest writers ported from Go 1.25.5.
//
// TruncateWriter is the one with a trap in it: Go reports `len(p)` to
// its caller, not the number of bytes it actually passed through. A
// truncating writer that reported the real count would make every io
// helper above it return ErrShortWrite, which is the opposite of
// "stops silently". Both places Go does this are asserted below.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::gostring::string;
use goish::io::Writer;
use goish::testing::iotest::TruncateWriter;
use goish::types::{byte, int};
use goish::{errors, fmt, slice, syscall};

/// A Writer that records everything handed to it.
struct Recorder {
    got: Vec<byte>,
}

impl Writer for Recorder {
    fn Write(&mut self, p: slice<byte>) -> (int, errors::error) {
        let n = p.Len();
        let mut i: int = 0;
        while i < n {
            self.got.push(p[i]);
            i += 1;
        }
        return (n, errors::nil);
    }
}

fn bytes_of(x: &str) -> slice<byte> {
    return slice::__from_vec(x.as_bytes().to_vec());
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. A write inside the budget passes through whole.
    {
        let rec = Recorder { got: Vec::new() };
        let mut tw = TruncateWriter(rec, 10);
        let (n, err) = tw.Write(bytes_of("hello"));
        if n == 5 && err == errors::nil {
            fmt::Println!("[ 1] within budget             PASS");
        } else {
            fmt::Println!("[ 1] within budget             FAIL");
            failed += 1;
        }
    }

    // 2. A write that crosses the budget truncates what reaches the
    //    underlying writer, but still reports len(p) to the caller.
    {
        let rec = Recorder { got: Vec::new() };
        let mut tw = TruncateWriter(rec, 3);
        let (n, err) = tw.Write(bytes_of("hello"));
        if n == 5 && err == errors::nil {
            fmt::Println!("[ 2] over budget reports len(p) PASS");
        } else {
            fmt::Println!("[ 2] over budget reports len(p) FAIL");
            failed += 1;
        }
    }

    // 3. Once the budget is spent, further writes are dropped silently
    //    and still report success for the full slice.
    {
        let rec = Recorder { got: Vec::new() };
        let mut tw = TruncateWriter(rec, 0);
        let (n, err) = tw.Write(bytes_of("hello world"));
        if n == 11 && err == errors::nil {
            fmt::Println!("[ 3] exhausted budget silent   PASS");
        } else {
            fmt::Println!("[ 3] exhausted budget silent   FAIL");
            failed += 1;
        }
    }

    // 4. The budget is consumed across calls, not reset per call.
    {
        let rec = Recorder { got: Vec::new() };
        let mut tw = TruncateWriter(rec, 4);
        let (n1, _) = tw.Write(bytes_of("ab"));
        let (n2, _) = tw.Write(bytes_of("cd"));
        let (n3, _) = tw.Write(bytes_of("ef"));
        // Every call reports its own len(p); only the first four bytes
        // reached the writer underneath.
        if n1 == 2 && n2 == 2 && n3 == 2 {
            fmt::Println!("[ 4] budget spans calls        PASS");
        } else {
            fmt::Println!("[ 4] budget spans calls        FAIL");
            failed += 1;
        }
    }

    // 5. An empty write is a no-op that still succeeds.
    {
        let rec = Recorder { got: Vec::new() };
        let mut tw = TruncateWriter(rec, 5);
        let (n, err) = tw.Write(slice::__from_vec(Vec::new()));
        if n == 0 && err == errors::nil {
            fmt::Println!("[ 5] empty write               PASS");
        } else {
            fmt::Println!("[ 5] empty write               FAIL");
            failed += 1;
        }
    }

    let _ = string::from_static("");
    if failed == 0 {
        fmt::Println!("ok 5/5");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 5");
        syscall::Exit(1);
    }
}
