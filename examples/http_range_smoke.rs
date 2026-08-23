// http_range_smoke — exercise net/http's parseRange (fs.go:1015).
//
// parseRange and httpRange are unexported in Go, so they are reached
// through the fs module rather than a re-export: goish had been
// carrying them as invented public `ParseRange`/`HttpRange` names with
// capitalised fields, which is API Go does not have.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::errors;
use goish::fmt;
use goish::goslice::slice;
use goish::io;
use goish::net::http::fs::{
    countingWriter, errNoOverlap, httpRange, parseRange, rangesMIMESize, sumRangesSize,
};
use goish::{string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. "bytes=0-99" on size 1000 → start=0 length=100
    {
        let (rs, err) = parseRange(string("bytes=0-99"), 1000);
        if err.IsNil() && rs.Len() == 1 && rs[0].start == 0 && rs[0].length == 100 {
            fmt::Println!("[ 1] simple range              PASS");
        } else {
            fmt::Println!("[ 1] simple range              FAIL");
            failed += 1;
        }
    }

    // 2. "bytes=200-" → start=200 length=size-200
    {
        let (rs, err) = parseRange(string("bytes=200-"), 1000);
        if err.IsNil() && rs.Len() == 1 && rs[0].start == 200 && rs[0].length == 800 {
            fmt::Println!("[ 2] open-ended range          PASS");
        } else {
            fmt::Println!("[ 2] open-ended range          FAIL");
            failed += 1;
        }
    }

    // 3. "bytes=-50" → suffix: last 50 bytes
    {
        let (rs, err) = parseRange(string("bytes=-50"), 1000);
        if err.IsNil() && rs.Len() == 1 && rs[0].start == 950 && rs[0].length == 50 {
            fmt::Println!("[ 3] suffix range              PASS");
        } else {
            fmt::Println!("[ 3] suffix range              FAIL");
            failed += 1;
        }
    }

    // 4. "bytes=0-99,200-299" → two ranges
    {
        let (rs, err) = parseRange(string("bytes=0-99,200-299"), 1000);
        if err.IsNil() && rs.Len() == 2 && rs[0].length == 100 && rs[1].start == 200 {
            fmt::Println!("[ 4] multi-range               PASS");
        } else {
            fmt::Println!("[ 4] multi-range               FAIL n={}", rs.Len());
            failed += 1;
        }
    }

    // 5. Empty header → empty list, no error.
    {
        let (rs, err) = parseRange(string(""), 1000);
        if err.IsNil() && rs.Len() == 0 {
            fmt::Println!("[ 5] empty → no ranges         PASS");
        } else {
            fmt::Println!("[ 5] empty → no ranges         FAIL");
            failed += 1;
        }
    }

    // 6. Malformed → error.
    {
        let (_rs, err) = parseRange(string("not a range"), 1000);
        if !err.IsNil() {
            fmt::Println!("[ 6] malformed → error         PASS");
        } else {
            fmt::Println!("[ 6] malformed → error         FAIL");
            failed += 1;
        }
    }

    // 7. ContentRange formatting.
    {
        let r = httpRange {
            start: 0,
            length: 100,
        };
        let s = r.contentRange(1000);
        if s == "bytes 0-99/1000" {
            fmt::Println!("[ 7] contentRange format       PASS");
        } else {
            fmt::Println!("[ 7] contentRange format       FAIL got={}", s);
            failed += 1;
        }
    }

    // Cases 8-14 are pinned to Go 1.25.5 output, captured by running
    // parseRange inside a writable GOROOT (scripts/goref.sh net/http).

    // 8. A range wholly past the end does not overlap, and the error
    //    must keep errNoOverlap IDENTITY — serveContent branches on
    //    errors.Is(err, errNoOverlap) to answer 416 rather than 500.
    {
        let (_rs, err) = parseRange(string("bytes=1000-"), 1000);
        if err != goish::nil && errors::Is(err.clone(), errNoOverlap) {
            fmt::Println!("[ 8] no-overlap keeps errNoOverlap  PASS");
        } else {
            fmt::Println!("[ 8] no-overlap keeps errNoOverlap  FAIL err=", err);
            failed += 1;
        }
    }

    // 9. A non-overlapping range beside a good one is skipped, not an
    //    error: Go returns just the overlapping range.
    {
        let (rs, err) = parseRange(string("bytes=1500-,0-99"), 1000);
        if err == goish::nil && rs.Len() == 1 && rs[0].start == 0 && rs[0].length == 100 {
            fmt::Println!("[ 9] partial overlap keeps good range  PASS");
        } else {
            fmt::Println!("[ 9] partial overlap  FAIL n=", rs.Len());
            failed += 1;
        }
    }

    // 10. textproto.TrimString trims tab and newline, so both parse.
    {
        let (a, ae) = parseRange(string("bytes=\t0-99"), 1000);
        let (b, be) = parseRange(string("bytes=\n0-99"), 1000);
        if ae == goish::nil
            && be == goish::nil
            && a.Len() == 1
            && b.Len() == 1
            && a[0].length == 100
            && b[0].length == 100
        {
            fmt::Println!("[10] tab/newline are trimmed  PASS");
        } else {
            fmt::Println!("[10] tab/newline are trimmed  FAIL");
            failed += 1;
        }
    }

    // 11. "bytes=-0" is a zero-length suffix at EOF, not an error.
    {
        let (rs, err) = parseRange(string("bytes=-0"), 1000);
        if err == goish::nil && rs.Len() == 1 && rs[0].start == 1000 && rs[0].length == 0 {
            fmt::Println!("[11] -0 is a zero-length suffix  PASS");
        } else {
            fmt::Println!("[11] -0 is a zero-length suffix  FAIL");
            failed += 1;
        }
    }

    // 12. An end past the content is clamped to size-1.
    {
        let (rs, err) = parseRange(string("bytes=0-2000"), 1000);
        if err == goish::nil && rs.Len() == 1 && rs[0].length == 1000 {
            fmt::Println!("[12] end past EOF is clamped  PASS");
        } else {
            fmt::Println!("[12] end past EOF is clamped  FAIL");
            failed += 1;
        }
    }

    // 13. sumRangesSize over a multi-range header.
    {
        let (rs, _err) = parseRange(string("bytes=0-99,200-299"), 1000);
        if sumRangesSize(&rs) == 200 {
            fmt::Println!("[13] sumRangesSize  PASS");
        } else {
            fmt::Println!("[13] sumRangesSize  FAIL got=", sumRangesSize(&rs));
            failed += 1;
        }
    }

    // 14. countingWriter counts bytes without keeping them.
    {
        let mut cw = countingWriter(0);
        let (n, err) = io::Writer::Write(&mut cw, slice::from(b"0123456789".as_slice()));
        if err == goish::nil && n == 10 && cw.0 == 10 {
            fmt::Println!("[14] countingWriter counts  PASS");
        } else {
            fmt::Println!("[14] countingWriter counts  FAIL n=", n);
            failed += 1;
        }
    }

    // 15. rangesMIMESize — the multipart Content-Length estimate.
    //     Absolute byte counts from Go 1.25.5 (goref.sh). They are
    //     comparable because both implementations use a 30-byte random
    //     boundary rendered as 60 hex chars, so the length is fixed
    //     even though the value is not.
    {
        let cases: &[(&'static str, &'static str, i64, i64)] = &[
            ("bytes=0-99", "text/plain", 1000, 292),
            ("bytes=0-99,200-299", "text/plain", 1000, 521),
            (
                "bytes=0-99,200-299,400-499",
                "application/octet-stream",
                1000,
                792,
            ),
            ("bytes=-50", "text/html; charset=utf-8", 1000, 259),
            ("bytes=0-0", "a", 1, 180),
        ];
        let mut bad = 0;
        for (hdr, ct, size, want) in cases {
            let (rs, err) = parseRange(string(*hdr), *size);
            if err != goish::nil {
                fmt::Println!("     parseRange failed: ", *hdr);
                bad += 1;
                continue;
            }
            let got = rangesMIMESize(&rs, string(*ct), *size);
            if got != *want {
                fmt::Println!("     rangesMIMESize(", *hdr, ") = ", got, " want ", *want);
                bad += 1;
            }
        }
        if bad == 0 {
            fmt::Println!("[15] rangesMIMESize, 5 cases vs Go  PASS");
        } else {
            fmt::Println!("[15] rangesMIMESize  FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 15/15");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL ", failed, " of 15");
        syscall::Exit(1);
    }
}
