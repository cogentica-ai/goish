// pem_smoke — exercise encoding/pem.
// (encoding/pem/pem.go)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::bytes;
use goish::encoding::pem::{self, Block, Decode, Encode, EncodeToMemory};
use goish::goslice::slice;
use goish::types::byte;
use goish::{convert, string, syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // Reference test certificate (10 random bytes encoded base64).
    // Bytes: \x00\x01\x02\x03\x04\x05\x06\x07\x08\x09 → "AAECAwQFBgcICQ=="
    let test_pem =
        "-----BEGIN TEST-----\nAAECAwQFBgcICQ==\n-----END TEST-----\n";

    // 1. Decode a basic PEM block.
    {
        let data = convert::bytes(test_pem);
        let (p_opt, _rest) = Decode(data);
        if let Some(p) = p_opt {
            let raw: &[byte] = &p.Bytes;
            let want: &[u8] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
            if p.Type == "TEST" && raw == want && p.Headers.Len() == 0 {
                Println!("[ 1] basic Decode             PASS");
            } else {
                Println!("[ 1] basic Decode             FAIL");
                failed += 1;
            }
        } else {
            Println!("[ 1] basic Decode             FAIL None");
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
            Println!("[ 2] skip leading garbage     PASS");
        } else {
            Println!("[ 2] skip leading garbage     FAIL");
            failed += 1;
        }
    }

    // 3. Decode with no PEM data → None + original returned.
    {
        let data = convert::bytes("just plain text, no PEM here.\n");
        let (p_opt, rest) = Decode(data);
        if p_opt.is_none() && rest.len() > 0 {
            Println!("[ 3] no PEM None              PASS");
        } else {
            Println!("[ 3] no PEM None              FAIL");
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
                Println!("[ 4] headers parsed           PASS");
            } else {
                Println!("[ 4] headers parsed           FAIL");
                failed += 1;
            }
        } else {
            Println!("[ 4] headers parsed           FAIL None");
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
            Println!("[ 5] EncodeToMemory           PASS");
        } else {
            Println!("[ 5] EncodeToMemory           FAIL got len={}", out.len());
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
                Println!("[ 6] round-trip               PASS");
            } else {
                Println!("[ 6] round-trip               FAIL");
                failed += 1;
            }
        } else {
            Println!("[ 6] round-trip               FAIL None");
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
            Println!("[ 7] colon-key rejected       PASS");
        } else {
            Println!("[ 7] colon-key rejected       FAIL");
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
        if nl_count == 5 && s.starts_with("-----BEGIN BIG-----\n") && s.ends_with("-----END BIG-----\n") {
            Println!("[ 8] line wrap 64-col         PASS");
        } else {
            Println!("[ 8] line wrap 64-col         FAIL nl={}", nl_count);
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
                Println!("[ 9] empty body               PASS");
            } else {
                Println!("[ 9] empty body               FAIL");
                failed += 1;
            }
        } else {
            Println!("[ 9] empty body               FAIL None");
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
                Println!("[10] multi-block             PASS");
            }
            _ => {
                Println!("[10] multi-block             FAIL");
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
                Println!("[11] whitespace stripped     PASS");
            } else {
                Println!("[11] whitespace stripped     FAIL");
                failed += 1;
            }
        } else {
            Println!("[11] whitespace stripped     FAIL None");
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
                Println!("[12] CRLF accepted           PASS");
            } else {
                Println!("[12] CRLF accepted           FAIL");
                failed += 1;
            }
        } else {
            Println!("[12] CRLF accepted           FAIL None");
            failed += 1;
        }
    }

    let _ = pem::EncodeToMemory; // ensure module re-exports compile

    if failed == 0 {
        Println!("ok 12/12");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 12");
        syscall::Exit(1);
    }
}
