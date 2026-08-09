// csv_smoke — exercise encoding/csv Reader + Writer.
// (encoding/csv/reader.go + writer.go)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::bytes;
use goish::encoding::csv;
use goish::strings;
use goish::{string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Read simple unquoted record.
    {
        let r = strings::NewReader(string("a,b,c\n"));
        let mut cr = csv::NewReader(r);
        let (rec, err) = cr.Read();
        if err.IsNil() && rec.Len() == 3 && rec[0] == "a" && rec[1] == "b" && rec[2] == "c" {
            fmt::Println!("[ 1] Read simple              PASS");
        } else {
            fmt::Println!("[ 1] Read simple              FAIL");
            failed += 1;
        }
    }

    // 2. Quoted field with comma + escaped quote.
    {
        let input = "\"hello, world\",\"a\"\"b\",c\n";
        let r = strings::NewReader(string(input));
        let mut cr = csv::NewReader(r);
        let (rec, err) = cr.Read();
        if err.IsNil() && rec.Len() == 3 && rec[0] == "hello, world" && rec[1] == "a\"b" && rec[2] == "c" {
            fmt::Println!("[ 2] Quoted comma + escape    PASS");
        } else {
            fmt::Println!("[ 2] Quoted comma + escape    FAIL");
            failed += 1;
        }
    }

    // 3. ReadAll multi-record.
    {
        let r = strings::NewReader(string("a,b\nc,d\ne,f\n"));
        let mut cr = csv::NewReader(r);
        let (recs, err) = cr.ReadAll();
        if err.IsNil() && recs.Len() == 3 && recs[0][0] == "a" && recs[2][1] == "f" {
            fmt::Println!("[ 3] ReadAll                  PASS");
        } else {
            fmt::Println!("[ 3] ReadAll                  FAIL n={}", recs.Len());
            failed += 1;
        }
    }

    // 4. CRLF normalization.
    {
        let r = strings::NewReader(string("a,b\r\nc,d\r\n"));
        let mut cr = csv::NewReader(r);
        let (recs, err) = cr.ReadAll();
        if err.IsNil() && recs.Len() == 2 && recs[0][1] == "b" && recs[1][1] == "d" {
            fmt::Println!("[ 4] CRLF normalize           PASS");
        } else {
            fmt::Println!("[ 4] CRLF normalize           FAIL");
            failed += 1;
        }
    }

    // 5. Comment lines skipped.
    {
        let r = strings::NewReader(string("# header\na,b\n# mid\nc,d\n"));
        let mut cr = csv::NewReader(r);
        cr.Comment = '#' as goish::types::rune;
        let (recs, err) = cr.ReadAll();
        if err.IsNil() && recs.Len() == 2 {
            fmt::Println!("[ 5] Comment skip             PASS");
        } else {
            fmt::Println!("[ 5] Comment skip             FAIL n={}", recs.Len());
            failed += 1;
        }
    }

    // 6. FieldsPerRecord enforcement.
    {
        let r = strings::NewReader(string("a,b,c\nx,y\n"));
        let mut cr = csv::NewReader(r);
        cr.FieldsPerRecord = 3;
        let (_, _) = cr.Read();
        let (_, err) = cr.Read();
        if !err.IsNil() {
            fmt::Println!("[ 6] FieldsPerRecord err      PASS");
        } else {
            fmt::Println!("[ 6] FieldsPerRecord err      FAIL");
            failed += 1;
        }
    }

    // 7. Bare quote fails (not LazyQuotes).
    {
        let r = strings::NewReader(string("a\"b,c\n"));
        let mut cr = csv::NewReader(r);
        let (_, err) = cr.Read();
        if !err.IsNil() {
            fmt::Println!("[ 7] Bare quote err           PASS");
        } else {
            fmt::Println!("[ 7] Bare quote err           FAIL");
            failed += 1;
        }
    }

    // 8. LazyQuotes accepts bare quote.
    {
        let r = strings::NewReader(string("a\"b,c\n"));
        let mut cr = csv::NewReader(r);
        cr.LazyQuotes = true;
        let (rec, err) = cr.Read();
        if err.IsNil() && rec.Len() == 2 && rec[0] == "a\"b" {
            fmt::Println!("[ 8] LazyQuotes accept        PASS");
        } else {
            fmt::Println!("[ 8] LazyQuotes accept        FAIL");
            failed += 1;
        }
    }

    // 9. TrimLeadingSpace.
    {
        let r = strings::NewReader(string(" a, b ,c\n"));
        let mut cr = csv::NewReader(r);
        cr.TrimLeadingSpace = true;
        let (rec, err) = cr.Read();
        if err.IsNil() && rec.Len() == 3 && rec[0] == "a" && rec[1] == "b " && rec[2] == "c" {
            fmt::Println!("[ 9] TrimLeadingSpace         PASS");
        } else {
            fmt::Println!("[ 9] TrimLeadingSpace         FAIL");
            failed += 1;
        }
    }

    // 10. Writer simple.
    {
        let mut buf = bytes::NewBuffer(goish::goslice::slice::<goish::types::byte>::__from_vec(alloc::vec![]));
        let mut w = csv::NewWriter(&mut buf);
        let recs = [string("a"), string("b"), string("c")];
        let _ = w.Write(&recs);
        w.Flush();
        let s = buf.String();
        if s == "a,b,c\n" {
            fmt::Println!("[10] Writer simple            PASS");
        } else {
            fmt::Println!("[10] Writer simple            FAIL got {}", s);
            failed += 1;
        }
    }

    // 11. Writer quotes when needed.
    {
        let mut buf = bytes::NewBuffer(goish::goslice::slice::<goish::types::byte>::__from_vec(alloc::vec![]));
        let mut w = csv::NewWriter(&mut buf);
        let recs = [string("hello, world"), string("plain")];
        let _ = w.Write(&recs);
        w.Flush();
        let s = buf.String();
        if s == "\"hello, world\",plain\n" {
            fmt::Println!("[11] Writer quote-on-comma    PASS");
        } else {
            fmt::Println!("[11] Writer quote-on-comma    FAIL got {}", s);
            failed += 1;
        }
    }

    // 12. Writer escapes embedded quote.
    {
        let mut buf = bytes::NewBuffer(goish::goslice::slice::<goish::types::byte>::__from_vec(alloc::vec![]));
        let mut w = csv::NewWriter(&mut buf);
        let recs = [string("she said \"hi\""), string("ok")];
        let _ = w.Write(&recs);
        w.Flush();
        let s = buf.String();
        if s == "\"she said \"\"hi\"\"\",ok\n" {
            fmt::Println!("[12] Writer quote escape      PASS");
        } else {
            fmt::Println!("[12] Writer quote escape      FAIL got {}", s);
            failed += 1;
        }
    }

    // 13. Writer + Reader round-trip.
    {
        let mut buf = bytes::NewBuffer(goish::goslice::slice::<goish::types::byte>::__from_vec(alloc::vec![]));
        let mut w = csv::NewWriter(&mut buf);
        let r1 = [string("a"), string("b,c")];
        let r2 = [string("\"d\""), string("e")];
        let _ = w.Write(&r1);
        let _ = w.Write(&r2);
        w.Flush();
        let raw = buf.String();
        let r = strings::NewReader(raw);
        let mut cr = csv::NewReader(r);
        let (recs, err) = cr.ReadAll();
        if err.IsNil()
            && recs.Len() == 2
            && recs[0][0] == "a"
            && recs[0][1] == "b,c"
            && recs[1][0] == "\"d\""
            && recs[1][1] == "e"
        {
            fmt::Println!("[13] Round-trip               PASS");
        } else {
            fmt::Println!("[13] Round-trip               FAIL");
            failed += 1;
        }
    }

    // 14. UseCRLF writer.
    {
        let mut buf = bytes::NewBuffer(goish::goslice::slice::<goish::types::byte>::__from_vec(alloc::vec![]));
        let mut w = csv::NewWriter(&mut buf);
        w.UseCRLF = true;
        let recs = [string("a"), string("b")];
        let _ = w.Write(&recs);
        w.Flush();
        let s = buf.String();
        if s == "a,b\r\n" {
            fmt::Println!("[14] UseCRLF                  PASS");
        } else {
            fmt::Println!("[14] UseCRLF                  FAIL got {}", s);
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 14/14");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 14");
        syscall::Exit(1);
    }
}
