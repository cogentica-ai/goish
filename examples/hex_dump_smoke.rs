// hex_dump_smoke — exercise hex.Dump / hex.Dumper.
// (encoding/hex/hex.go:144 + 242)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::bytes;
use goish::encoding::hex::{Dump, Dumper};
use goish::goslice::slice;
use goish::io::{Closer, Writer};
use goish::types::byte;
use goish::strings;
use goish::{convert, string, syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Empty input → empty string.
    {
        let s = Dump(slice::__from_vec(alloc::vec![]));
        if s == "" {
            Println!("[ 1] empty                   PASS");
        } else {
            Println!("[ 1] empty                   FAIL");
            failed += 1;
        }
    }

    // 2. Single byte: "00000000  41                                                |A|\n"
    {
        let s = Dump(slice::__from_vec(alloc::vec![b'A']));
        let want = "00000000  41                                                |A|\n";
        if s == want {
            Println!("[ 2] single byte             PASS");
        } else {
            Println!("[ 2] single byte             FAIL");
            failed += 1;
        }
    }

    // 3. 16 bytes — exactly one full line.
    {
        // ASCII: "ABCDEFGHIJKLMNOP"
        let data = convert::bytes("ABCDEFGHIJKLMNOP");
        let s = Dump(data);
        let want = "00000000  41 42 43 44 45 46 47 48  49 4a 4b 4c 4d 4e 4f 50  |ABCDEFGHIJKLMNOP|\n";
        if s == want {
            Println!("[ 3] 16-byte line            PASS");
        } else {
            Println!("[ 3] 16-byte line            FAIL\n  got: {}\n  want: {}", s, want);
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
            Println!("[ 4] non-printable dots      PASS");
        } else {
            Println!("[ 4] non-printable dots      FAIL got {}", s);
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
            Println!("[ 5] two-line offsets        PASS");
        } else {
            Println!("[ 5] two-line offsets        FAIL");
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
            Println!("[ 6] Dumper Buffer           PASS");
        } else {
            Println!("[ 6] Dumper Buffer           FAIL\n  got: {}\n  want: {}", s, want);
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
            Println!("[ 7] multi-write             PASS");
        } else {
            Println!("[ 7] multi-write             FAIL");
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
            Println!("[ 8] Close idempotent        PASS");
        } else {
            Println!("[ 8] Close idempotent        FAIL");
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
            Println!("[ 9] write-after-close       PASS");
        } else {
            Println!("[ 9] write-after-close       FAIL");
            failed += 1;
        }
    }

    // 10. Format: middle column gap (after byte index 7) is two spaces.
    {
        let data = convert::bytes("ABCDEFGH");
        let s = Dump(data);
        // Verify the "8th byte" gap exists — after "48" (H) we expect "  " (two spaces) then padding.
        if strings::HasPrefix(s.clone(), string("00000000  41 42 43 44 45 46 47 48  ")) {
            Println!("[10] middle column gap       PASS");
        } else {
            Println!("[10] middle column gap       FAIL got {}", s);
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 10/10");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 10");
        syscall::Exit(1);
    }
}
