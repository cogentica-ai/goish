// testing_chattyprinter_smoke — testing's chattyPrinter.
//
// The printer exists to keep `-v` output attributable when tests
// interleave. Two methods, and the difference between them is the whole
// design:
//
//   Updatef — the message already names the test, so no heading.
//   Printf  — the message does NOT name the test, so the printer emits
//             "=== NAME  <test>" whenever the test changed since the
//             last write.
//
// Without that heading, a log line from a second test appears under the
// first test's heading and the output lies about which test produced
// it. Check 2 is that transition; check 3 is that it does NOT fire when
// the test has not changed, which is the other half — a printer that
// emitted a heading every time would pass check 2 and be useless.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use alloc::vec::Vec;
use goish::gostring::string;
use goish::sync::Mutex;
use goish::testing::{marker, newChattyPrinter};
use goish::types::byte;
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

fn buf() -> Arc<Mutex<Vec<byte>>> {
    return Arc::new(Mutex::new(Vec::new()));
}

fn read(b: &Arc<Mutex<Vec<byte>>>) -> string {
    let g = b.Lock();
    return string::from_bytes(&g);
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Updatef writes the message verbatim, with no NAME heading —
    //    the message is expected to name the test itself.
    {
        let b = buf();
        let p = newChattyPrinter(b.clone(), false);
        p.Updatef(s("TestA"), s("=== RUN   TestA\n"));
        if read(&b) == s("=== RUN   TestA\n") {
            fmt::Println!("[ 1] Updatef writes verbatim   PASS");
        } else {
            fmt::Println!("[ 1] Updatef writes verbatim   FAIL [", read(&b), "]");
            failed += 1;
        }
    }

    // 2. Printf inserts a NAME heading when the test CHANGES, so the
    //    second test's output is not attributed to the first.
    {
        let b = buf();
        let p = newChattyPrinter(b.clone(), false);
        p.Printf(s("TestA"), s("first line\n"));
        p.Printf(s("TestB"), s("second line\n"));
        let want = s("first line\n=== NAME  TestB\nsecond line\n");
        if read(&b) == want {
            fmt::Println!("[ 2] NAME on test change       PASS");
        } else {
            fmt::Println!("[ 2] NAME on test change       FAIL [", read(&b), "]");
            failed += 1;
        }
    }

    // 3. …and does NOT insert one when the test is unchanged. A printer
    //    that always emitted a heading would pass check 2 and be
    //    useless.
    {
        let b = buf();
        let p = newChattyPrinter(b.clone(), false);
        p.Printf(s("TestA"), s("one\n"));
        p.Printf(s("TestA"), s("two\n"));
        if read(&b) == s("one\ntwo\n") {
            fmt::Println!("[ 3] no NAME when unchanged    PASS");
        } else {
            fmt::Println!("[ 3] no NAME when unchanged    FAIL [", read(&b), "]");
            failed += 1;
        }
    }

    // 4. The very first Printf never emits a heading — lastName starts
    //    empty and is simply adopted.
    {
        let b = buf();
        let p = newChattyPrinter(b.clone(), false);
        p.Printf(s("TestA"), s("only\n"));
        if read(&b) == s("only\n") {
            fmt::Println!("[ 4] first Printf bare         PASS");
        } else {
            fmt::Println!("[ 4] first Printf bare         FAIL [", read(&b), "]");
            failed += 1;
        }
    }

    // 5. In json mode both the Updatef line and the NAME heading carry
    //    the 0x16 framing marker; the message body does not.
    {
        let b = buf();
        let p = newChattyPrinter(b.clone(), true);
        p.Updatef(s("TestA"), s("x\n"));
        let got = read(&b);
        let bytes = got.as_bytes();
        if bytes.len() == 3 && bytes[0] == marker && bytes[1] == b'x' {
            fmt::Println!("[ 5] json mode framing         PASS");
        } else {
            fmt::Println!("[ 5] json mode framing         FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 5/5");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 5");
        syscall::Exit(1);
    }
}
