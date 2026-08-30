// pem_smoke — exercise encoding/pem.
// (encoding/pem/pem.go)
//
// Checks 1-12 are hand-written. Checks 13-16 use output printed by a
// running Go 1.25.5 (tools/gen_pem_ref.go, run through
// scripts/goref.sh): the 64-column lineBreaker either side of a line
// boundary, the RFC 1421 §4.6.1.1 header order, the colon rejection,
// and Decode over leading/trailing junk and an unterminated BEGIN.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::bytes;
use goish::convert::byte as tobyte;
use goish::encoding::pem::{self, Block, Decode, Encode, EncodeToMemory};
use goish::fmt;
use goish::gomap::map;
use goish::goslice::slice;
use goish::types::byte;
use goish::{convert, string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // Reference test certificate (10 random bytes encoded base64).
    // Bytes: \x00\x01\x02\x03\x04\x05\x06\x07\x08\x09 → "AAECAwQFBgcICQ=="
    let test_pem = "-----BEGIN TEST-----\nAAECAwQFBgcICQ==\n-----END TEST-----\n";

    // 1. Decode a basic PEM block.
    {
        let data = convert::bytes(test_pem);
        let (p_opt, _rest) = Decode(data);
        if let Some(p) = p_opt {
            let raw: &[byte] = &p.Bytes;
            let want: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
            if p.Type == "TEST" && raw == want && p.Headers.Len() == 0 {
                fmt::Println!("[ 1] basic Decode             PASS");
            } else {
                fmt::Println!("[ 1] basic Decode             FAIL");
                failed += 1;
            }
        } else {
            fmt::Println!("[ 1] basic Decode             FAIL None");
            failed += 1;
        }
    }

    // 2. Decode with leading garbage (must skip).
    {
        let mut s = alloc::string::String::from("garbage line\nmore garbage\n");
        s.push_str(test_pem);
        let data = slice::__from_vec(s.into_bytes());
        let (p_opt, _rest) = Decode(data);
        if p_opt.is_some() {
            fmt::Println!("[ 2] skip leading garbage     PASS");
        } else {
            fmt::Println!("[ 2] skip leading garbage     FAIL");
            failed += 1;
        }
    }

    // 3. Decode with no PEM data → None + original returned.
    {
        let data = convert::bytes("just plain text, no PEM here.\n");
        let (p_opt, rest) = Decode(data);
        if p_opt.is_none() && rest.len() > 0 {
            fmt::Println!("[ 3] no PEM None              PASS");
        } else {
            fmt::Println!("[ 3] no PEM None              FAIL");
            failed += 1;
        }
    }

    // 4. Decode block with headers.
    {
        let s = "-----BEGIN HEAD-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,DEADBEEF\n\nAAECAwQFBgcICQ==\n-----END HEAD-----\n";
        let data = convert::bytes(s);
        let (p_opt, _rest) = Decode(data);
        if let Some(p) = p_opt {
            let pt = p.Headers.Get(string("Proc-Type")).0;
            let di = p.Headers.Get(string("DEK-Info")).0;
            if p.Type == "HEAD" && pt == "4,ENCRYPTED" && di == "AES-256-CBC,DEADBEEF" {
                fmt::Println!("[ 4] headers parsed           PASS");
            } else {
                fmt::Println!("[ 4] headers parsed           FAIL");
                failed += 1;
            }
        } else {
            fmt::Println!("[ 4] headers parsed           FAIL None");
            failed += 1;
        }
    }

    // 5. Encode a basic block (no headers) to memory and round-trip.
    {
        let block = Block {
            Type: string("CERTIFICATE"),
            Headers: goish::gomap::map::new(),
            Bytes: slice::__from_vec(alloc::vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
        };
        let out = EncodeToMemory(&block);
        let raw: &[byte] = &out;
        let s = core::str::from_utf8(raw).unwrap();
        let want = "-----BEGIN CERTIFICATE-----\nAAECAwQFBgcICQ==\n-----END CERTIFICATE-----\n";
        if s == want {
            fmt::Println!("[ 5] EncodeToMemory           PASS");
        } else {
            fmt::Println!("[ 5] EncodeToMemory           FAIL got len={}", out.len());
            failed += 1;
        }
    }

    // 6. Encode → Decode round-trip.
    {
        let original = Block {
            Type: string("RSA PRIVATE KEY"),
            Headers: goish::gomap::map::new(),
            Bytes: slice::__from_vec(alloc::vec![
                0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
                0x11, 0x00,
            ]),
        };
        let out = EncodeToMemory(&original);
        let (decoded_opt, _rest) = Decode(out);
        if let Some(decoded) = decoded_opt {
            let a: &[byte] = &decoded.Bytes;
            let b: &[byte] = &original.Bytes;
            if decoded.Type == original.Type && a == b {
                fmt::Println!("[ 6] round-trip               PASS");
            } else {
                fmt::Println!("[ 6] round-trip               FAIL");
                failed += 1;
            }
        } else {
            fmt::Println!("[ 6] round-trip               FAIL None");
            failed += 1;
        }
    }

    // 7. Encode with header containing colon → returns error.
    {
        let mut hdrs = goish::gomap::map::new();
        hdrs.Set(string("bad:key"), string("value"));
        let block = Block {
            Type: string("X"),
            Headers: hdrs,
            Bytes: slice::__from_vec(alloc::vec![1, 2, 3]),
        };
        let mut buf = bytes::NewBuffer(slice::__from_vec(alloc::vec![]));
        let e = Encode(&mut buf, &block);
        if !e.IsNil() {
            fmt::Println!("[ 7] colon-key rejected       PASS");
        } else {
            fmt::Println!("[ 7] colon-key rejected       FAIL");
            failed += 1;
        }
    }

    // 8. Long binary content: line-wrapped at 64 cols.
    {
        // 100 bytes → 136 base64 chars → wraps to 3 lines (64+64+8).
        let mut data: alloc::vec::Vec<byte> = alloc::vec::Vec::new();
        for i in 0..100u8 {
            data.push(i);
        }
        let block = Block {
            Type: string("BIG"),
            Headers: goish::gomap::map::new(),
            Bytes: slice::__from_vec(data),
        };
        let out = EncodeToMemory(&block);
        let raw: &[byte] = &out;
        let s = core::str::from_utf8(raw).unwrap();
        // Expect 3 newlines from base64 lines + 1 from BEGIN line + 1 from END line.
        let nl_count = s.matches('\n').count();
        if nl_count == 5
            && s.starts_with("-----BEGIN BIG-----\n")
            && s.ends_with("-----END BIG-----\n")
        {
            fmt::Println!("[ 8] line wrap 64-col         PASS");
        } else {
            fmt::Println!("[ 8] line wrap 64-col         FAIL nl={}", nl_count);
            failed += 1;
        }
    }

    // 9. Empty body block.
    {
        let block = Block {
            Type: string("EMPTY"),
            Headers: goish::gomap::map::new(),
            Bytes: slice::__from_vec(alloc::vec![]),
        };
        let out = EncodeToMemory(&block);
        let (decoded_opt, _rest) = Decode(out);
        if let Some(decoded) = decoded_opt {
            if decoded.Bytes.len() == 0 && decoded.Type == "EMPTY" {
                fmt::Println!("[ 9] empty body               PASS");
            } else {
                fmt::Println!("[ 9] empty body               FAIL");
                failed += 1;
            }
        } else {
            fmt::Println!("[ 9] empty body               FAIL None");
            failed += 1;
        }
    }

    // 10. Multiple blocks: Decode returns first, rest contains second.
    {
        let mut all = alloc::string::String::new();
        all.push_str(test_pem);
        all.push_str("-----BEGIN OTHER-----\nAAECAwQFBgcICQ==\n-----END OTHER-----\n");
        let data = slice::__from_vec(all.into_bytes());
        let (p1_opt, rest) = Decode(data);
        let (p2_opt, _) = Decode(rest);
        match (p1_opt, p2_opt) {
            (Some(p1), Some(p2)) if p1.Type == "TEST" && p2.Type == "OTHER" => {
                fmt::Println!("[10] multi-block             PASS");
            }
            _ => {
                fmt::Println!("[10] multi-block             FAIL");
                failed += 1;
            }
        }
    }

    // 11. Whitespace inside base64 stripped.
    {
        let s = "-----BEGIN WS-----\nAAEC AwQF BgcI CQ==\n-----END WS-----\n";
        let data = convert::bytes(s);
        let (p_opt, _rest) = Decode(data);
        if let Some(p) = p_opt {
            let raw: &[byte] = &p.Bytes;
            let want: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
            if raw == want {
                fmt::Println!("[11] whitespace stripped     PASS");
            } else {
                fmt::Println!("[11] whitespace stripped     FAIL");
                failed += 1;
            }
        } else {
            fmt::Println!("[11] whitespace stripped     FAIL None");
            failed += 1;
        }
    }

    // 12. CRLF line endings accepted.
    {
        let s = "-----BEGIN CRLF-----\r\nAAECAwQFBgcICQ==\r\n-----END CRLF-----\r\n";
        let data = convert::bytes(s);
        let (p_opt, _rest) = Decode(data);
        if let Some(p) = p_opt {
            let raw: &[byte] = &p.Bytes;
            let want: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
            if raw == want {
                fmt::Println!("[12] CRLF accepted           PASS");
            } else {
                fmt::Println!("[12] CRLF accepted           FAIL");
                failed += 1;
            }
        } else {
            fmt::Println!("[12] CRLF accepted           FAIL None");
            failed += 1;
        }
    }

    // 13. Encode's 64-column line breaking, against Go. 36 raw bytes
    //     make 48 base64 chars, so 47/48/49 land just under, on, and
    //     just over a line boundary — the three branches of
    //     lineBreaker.Write.
    {
        fn mk(n: usize) -> slice<byte> {
            let mut v: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(n);
            let mut i: usize = 0;
            while i < n {
                v.push(tobyte((i * 7 + 3) % 251));
                i += 1;
            }
            slice::<byte>::__from_vec(v)
        }
        let cases: [(usize, &str); 7] = [
            (0, "-----BEGIN TEST-----\n-----END TEST-----\n"),
            (1, "-----BEGIN TEST-----\nAw==\n-----END TEST-----\n"),
            (47, "-----BEGIN TEST-----\nAwoRGB8mLTQ7QklQV15lbHN6gYiPlp2kq7K5wMfO1dzj6vH4BAsSGSAnLjU8Q0o=\n-----END TEST-----\n"),
            (48, "-----BEGIN TEST-----\nAwoRGB8mLTQ7QklQV15lbHN6gYiPlp2kq7K5wMfO1dzj6vH4BAsSGSAnLjU8Q0pR\n-----END TEST-----\n"),
            (49, "-----BEGIN TEST-----\nAwoRGB8mLTQ7QklQV15lbHN6gYiPlp2kq7K5wMfO1dzj6vH4BAsSGSAnLjU8Q0pR\nWA==\n-----END TEST-----\n"),
            (96, "-----BEGIN TEST-----\nAwoRGB8mLTQ7QklQV15lbHN6gYiPlp2kq7K5wMfO1dzj6vH4BAsSGSAnLjU8Q0pR\nWF9mbXR7gomQl56lrLO6wcjP1t3k6/L5BQwTGiEoLzY9REtSWWBnbnV8g4qRmJ+m\n-----END TEST-----\n"),
            (100, "-----BEGIN TEST-----\nAwoRGB8mLTQ7QklQV15lbHN6gYiPlp2kq7K5wMfO1dzj6vH4BAsSGSAnLjU8Q0pR\nWF9mbXR7gomQl56lrLO6wcjP1t3k6/L5BQwTGiEoLzY9REtSWWBnbnV8g4qRmJ+m\nrbS7wg==\n-----END TEST-----\n"),
        ];
        let mut bad = 0;
        let mut k: usize = 0;
        while k < cases.len() {
            let (n, want) = cases[k];
            let b = Block {
                Type: string::from("TEST"),
                Headers: map::<string, string>::new(),
                Bytes: mk(n),
            };
            let got = EncodeToMemory(&b);
            let gr: &[byte] = &got;
            if gr != want.as_bytes() {
                bad += 1;
            }
            k += 1;
        }
        if bad == 0 {
            fmt::Println!("[13] lineBreaker vs Go        PASS");
        } else {
            fmt::Println!("[13] lineBreaker vs Go        FAIL");
            failed += 1;
        }
    }

    // 14. Header order: Proc-Type first (RFC 1421 §4.6.1.1), the rest
    //     sorted, then a blank line before the body.
    {
        let mut h = map::<string, string>::new();
        h.Set(string::from("Zeta"), string::from("z"));
        h.Set(string::from("Alpha"), string::from("a"));
        h.Set(string::from("Proc-Type"), string::from("4,ENCRYPTED"));
        h.Set(string::from("DEK-Info"), string::from("DES-EDE3-CBC,0102"));
        let mut v: alloc::vec::Vec<byte> = alloc::vec::Vec::new();
        let mut i: usize = 0;
        while i < 10 {
            v.push(tobyte((i * 7 + 3) % 251));
            i += 1;
        }
        let b = Block {
            Type: string::from("RSA PRIVATE KEY"),
            Headers: h,
            Bytes: slice::<byte>::__from_vec(v),
        };
        let got = EncodeToMemory(&b);
        let want = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nAlpha: a\nDEK-Info: DES-EDE3-CBC,0102\nZeta: z\n\nAwoRGB8mLTQ7Qg==\n-----END RSA PRIVATE KEY-----\n";
        let gr: &[byte] = &got;
        if gr == want.as_bytes() {
            fmt::Println!("[14] header order vs Go       PASS");
        } else {
            fmt::Println!("[14] header order vs Go       FAIL");
            failed += 1;
        }
    }

    // 15. A header key containing a colon is refused, and nothing is
    //     written — Go checks before it emits any output.
    {
        let mut h = map::<string, string>::new();
        h.Set(string::from("a:b"), string::from("c"));
        let b = Block {
            Type: string::from("X"),
            Headers: h,
            Bytes: slice::<byte>::__from_vec(alloc::vec::Vec::new()),
        };
        let got = EncodeToMemory(&b);
        let mut buf = bytes::NewBuffer(slice::<byte>::__from_vec(alloc::vec::Vec::new()));
        let e = Encode(&mut buf, &b);
        let gr: &[byte] = &got;
        if gr.is_empty()
            && !e.IsNil()
            && e.Error() == "pem: cannot encode a header key that contains a colon"
        {
            fmt::Println!("[15] colon key refused        PASS");
        } else {
            fmt::Println!("[15] colon key refused        FAIL");
            failed += 1;
        }
    }

    // 16. Decode skips leading junk and an unterminated BEGIN, and
    //     hands back exactly the trailing bytes.
    {
        let mut v: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(50);
        let mut i: usize = 0;
        while i < 50 {
            v.push(tobyte((i * 7 + 3) % 251));
            i += 1;
        }
        let want_bytes = slice::<byte>::__from_vec(v);
        let enc = EncodeToMemory(&Block {
            Type: string::from("TEST"),
            Headers: map::<string, string>::new(),
            Bytes: want_bytes.clone(),
        });
        let er: &[byte] = &enc;

        let mut junk: alloc::vec::Vec<byte> = alloc::vec::Vec::new();
        junk.extend_from_slice(b"leading junk\n");
        junk.extend_from_slice(er);
        junk.extend_from_slice(b"trailing junk\n");
        let (p, rest) = Decode(slice::<byte>::__from_vec(junk));

        let mut bogus: alloc::vec::Vec<byte> = alloc::vec::Vec::new();
        bogus.extend_from_slice(b"-----BEGIN BOGUS-----\n");
        bogus.extend_from_slice(er);
        let (p2, _) = Decode(slice::<byte>::__from_vec(bogus));

        let (p3, rest3) = Decode(convert::bytes("no pem here\n"));

        let mut ok = p3.is_none();
        let r3: &[byte] = &rest3;
        ok = ok && r3 == b"no pem here\n";
        if let Some(pp) = p {
            let got: &[byte] = &pp.Bytes;
            let wr: &[byte] = &want_bytes;
            let rr: &[byte] = &rest;
            ok = ok && pp.Type == "TEST" && got == wr && rr == b"trailing junk\n";
        } else {
            ok = false;
        }
        if let Some(pp2) = p2 {
            ok = ok && pp2.Type == "TEST" && pp2.Bytes.Len() == 50;
        } else {
            ok = false;
        }
        if ok {
            fmt::Println!("[16] Decode junk/bogus vs Go  PASS");
        } else {
            fmt::Println!("[16] Decode junk/bogus vs Go  FAIL");
            failed += 1;
        }
    }

    let _ = pem::EncodeToMemory; // ensure module re-exports compile

    if failed == 0 {
        fmt::Println!("ok 16/16");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 16");
        syscall::Exit(1);
    }
}
