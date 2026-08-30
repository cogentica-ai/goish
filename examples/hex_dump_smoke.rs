// hex_dump_smoke — exercise hex.Dump / hex.Dumper.
// (encoding/hex/hex.go:144 + 242)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::bytes;
use goish::encoding::hex::{Dump, Dumper};
use goish::fmt;
use goish::goslice::slice;
use goish::io::{Closer, Writer};
use goish::strings;
use goish::types::byte;
use goish::{convert, string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Empty input → empty string.
    {
        let s = Dump(slice::__from_vec(alloc::vec![]));
        if s == "" {
            fmt::Println!("[ 1] empty                   PASS");
        } else {
            fmt::Println!("[ 1] empty                   FAIL");
            failed += 1;
        }
    }

    // 2. Single byte: "00000000  41                                                |A|\n"
    {
        let s = Dump(slice::__from_vec(alloc::vec![b'A']));
        let want = "00000000  41                                                |A|\n";
        if s == want {
            fmt::Println!("[ 2] single byte             PASS");
        } else {
            fmt::Println!("[ 2] single byte             FAIL");
            failed += 1;
        }
    }

    // 3. 16 bytes — exactly one full line.
    {
        // ASCII: "ABCDEFGHIJKLMNOP"
        let data = convert::bytes("ABCDEFGHIJKLMNOP");
        let s = Dump(data);
        let want =
            "00000000  41 42 43 44 45 46 47 48  49 4a 4b 4c 4d 4e 4f 50  |ABCDEFGHIJKLMNOP|\n";
        if s == want {
            fmt::Println!("[ 3] 16-byte line            PASS");
        } else {
            fmt::Println!(
                "[ 3] 16-byte line            FAIL\n  got: {}\n  want: {}",
                s,
                want
            );
            failed += 1;
        }
    }

    // 4. Non-printable bytes → '.' in gutter.
    {
        let data: slice<byte> = slice::__from_vec(alloc::vec![0x00, 0x01, 0x02, 0xff, 0x7f]);
        let s = Dump(data);
        // ASCII gutter: 0x00 → '.', 0x01 → '.', 0x02 → '.', 0xff → '.', 0x7f → '.'
        // 5 hex bytes (15 chars + 1 trailing space pre-mid) padded to 16, plus gutter "|.....|"
        if strings::Contains(s.clone(), string("|.....|")) {
            fmt::Println!("[ 4] non-printable dots      PASS");
        } else {
            fmt::Println!("[ 4] non-printable dots      FAIL got {}", s);
            failed += 1;
        }
    }

    // 5. 17 bytes → two lines, second offset 0x00000010.
    {
        let mut v = alloc::vec::Vec::new();
        for i in 0..17u8 {
            v.push(b'a' + i);
        }
        let data = slice::__from_vec(v);
        let s = Dump(data);
        if strings::Contains(s.clone(), string("00000000"))
            && strings::Contains(s.clone(), string("00000010"))
        {
            fmt::Println!("[ 5] two-line offsets        PASS");
        } else {
            fmt::Println!("[ 5] two-line offsets        FAIL");
            failed += 1;
        }
    }

    // 6. Dumper write + close round-trip via Buffer.
    {
        let mut buf = bytes::NewBuffer(slice::__from_vec(alloc::vec![]));
        let mut d = Dumper(&mut buf);
        let _ = d.Write(slice::__from_vec(alloc::vec![b'X', b'Y', b'Z']));
        let _ = d.Close();
        let s = buf.String();
        let want = "00000000  58 59 5a                                          |XYZ|\n";
        if s == want {
            fmt::Println!("[ 6] Dumper Buffer           PASS");
        } else {
            fmt::Println!(
                "[ 6] Dumper Buffer           FAIL\n  got: {}\n  want: {}",
                s,
                want
            );
            failed += 1;
        }
    }

    // 7. Multi-write before Close.
    {
        let mut buf = bytes::NewBuffer(slice::__from_vec(alloc::vec![]));
        let mut d = Dumper(&mut buf);
        let _ = d.Write(slice::__from_vec(alloc::vec![b'a', b'b']));
        let _ = d.Write(slice::__from_vec(alloc::vec![b'c']));
        let _ = d.Close();
        let s = buf.String();
        let want = "00000000  61 62 63                                          |abc|\n";
        if s == want {
            fmt::Println!("[ 7] multi-write             PASS");
        } else {
            fmt::Println!("[ 7] multi-write             FAIL");
            failed += 1;
        }
    }

    // 8. Close idempotent.
    {
        let mut buf = bytes::NewBuffer(slice::__from_vec(alloc::vec![]));
        let mut d = Dumper(&mut buf);
        let _ = d.Write(slice::__from_vec(alloc::vec![b'A']));
        let e1 = d.Close();
        let e2 = d.Close();
        if e1.IsNil() && e2.IsNil() {
            fmt::Println!("[ 8] Close idempotent        PASS");
        } else {
            fmt::Println!("[ 8] Close idempotent        FAIL");
            failed += 1;
        }
    }

    // 9. Write after close → error.
    {
        let mut buf = bytes::NewBuffer(slice::__from_vec(alloc::vec![]));
        let mut d = Dumper(&mut buf);
        let _ = d.Close();
        let (n, e) = d.Write(slice::__from_vec(alloc::vec![b'A']));
        if n == 0 && !e.IsNil() {
            fmt::Println!("[ 9] write-after-close       PASS");
        } else {
            fmt::Println!("[ 9] write-after-close       FAIL");
            failed += 1;
        }
    }

    // 10. Format: middle column gap (after byte index 7) is two spaces.
    {
        let data = convert::bytes("ABCDEFGH");
        let s = Dump(data);
        // Verify the "8th byte" gap exists — after "48" (H) we expect "  " (two spaces) then padding.
        if strings::HasPrefix(s.clone(), string("00000000  41 42 43 44 45 46 47 48  ")) {
            fmt::Println!("[10] middle column gap       PASS");
        } else {
            fmt::Println!("[10] middle column gap       FAIL got {}", s);
            failed += 1;
        }
    }

    // 11. Dump's exact layout against a running Go, at every length
    //     that changes it: empty, a single byte, the 8-byte column gap,
    //     a full 16-byte line, and the 17/31/32/33 boundaries where a
    //     second line starts, fills and overflows.
    {
        fn mk(n: usize) -> slice<byte> {
            let mut v: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(n);
            let mut i: usize = 0;
            while i < n {
                v.push(((i * 7 + 3) % 256) as byte);
                i += 1;
            }
            slice::<byte>::__from_vec(v)
        }
        let cases: [(usize, &str); 9] = [
        (0, ""),
        (1, "00000000  03                                                |.|\n"),
        (7, "00000000  03 0a 11 18 1f 26 2d                              |.....&-|\n"),
        (15, "00000000  03 0a 11 18 1f 26 2d 34  3b 42 49 50 57 5e 65     |.....&-4;BIPW^e|\n"),
        (16, "00000000  03 0a 11 18 1f 26 2d 34  3b 42 49 50 57 5e 65 6c  |.....&-4;BIPW^el|\n"),
        (17, "00000000  03 0a 11 18 1f 26 2d 34  3b 42 49 50 57 5e 65 6c  |.....&-4;BIPW^el|\n00000010  73                                                |s|\n"),
        (31, "00000000  03 0a 11 18 1f 26 2d 34  3b 42 49 50 57 5e 65 6c  |.....&-4;BIPW^el|\n00000010  73 7a 81 88 8f 96 9d a4  ab b2 b9 c0 c7 ce d5     |sz.............|\n"),
        (32, "00000000  03 0a 11 18 1f 26 2d 34  3b 42 49 50 57 5e 65 6c  |.....&-4;BIPW^el|\n00000010  73 7a 81 88 8f 96 9d a4  ab b2 b9 c0 c7 ce d5 dc  |sz..............|\n"),
        (33, "00000000  03 0a 11 18 1f 26 2d 34  3b 42 49 50 57 5e 65 6c  |.....&-4;BIPW^el|\n00000010  73 7a 81 88 8f 96 9d a4  ab b2 b9 c0 c7 ce d5 dc  |sz..............|\n00000020  e3                                                |.|\n"),
        ];
        let mut bad = 0;
        let mut k: usize = 0;
        while k < cases.len() {
            let (n, want) = cases[k];
            if Dump(mk(n)) != want {
                bad += 1;
            }
            k += 1;
        }
        // The printable column maps anything outside 32..126 to '.'.
        if Dump(convert::bytes("Hello, world! ~\u{7f}\u{0}\u{1f}")) != "00000000  48 65 6c 6c 6f 2c 20 77  6f 72 6c 64 21 20 7e 7f  |Hello, world! ~.|\n00000010  00 1f                                             |..|\n" {
            bad += 1;
        }
        if bad == 0 {
            fmt::Println!("[11] Dump layout vs Go       PASS");
        } else {
            fmt::Println!("[11] Dump layout vs Go       FAIL");
            failed += 1;
        }
    }

    // 12. DecodeString's error contract: complete pairs are decoded
    //     before ErrLength is reported, and an invalid byte is named
    //     the way Go names it (%#U), not by position.
    {
        let cases: [(&str, usize, &str); 7] = [
            ("", 0, "<nil>"),
            ("0", 0, "encoding/hex: odd length hex string"),
            ("00", 1, "<nil>"),
            ("0g", 0, "encoding/hex: invalid byte: U+0067 'g'"),
            ("g0", 0, "encoding/hex: invalid byte: U+0067 'g'"),
            ("0011", 2, "<nil>"),
            ("001", 1, "encoding/hex: odd length hex string"),
        ];
        let mut bad = 0;
        let mut k: usize = 0;
        while k < cases.len() {
            let (input, wlen, werr) = cases[k];
            let (b, err) = goish::encoding::hex::DecodeString(input);
            let got = if err == goish::nil {
                string("<nil>")
            } else {
                err.Error()
            };
            if b.Len() != wlen as goish::int || got != werr {
                bad += 1;
            }
            k += 1;
        }
        if bad == 0 {
            fmt::Println!("[12] Decode errors vs Go     PASS");
        } else {
            fmt::Println!("[12] Decode errors vs Go     FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 12/12");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 12");
        syscall::Exit(1);
    }
}
