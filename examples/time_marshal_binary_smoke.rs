// time_marshal_binary_smoke — exercise Time.AppendBinary /
// MarshalBinary / UnmarshalBinary / GobEncode / GobDecode.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::time;
use goish::{make, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. MarshalBinary produces 15 bytes (V1, no offsetSec).
    {
        let t = time::Unix(1_700_000_000, 123_456_789);
        let (b, err) = t.MarshalBinary();
        if err.IsNil() && b.Len() == 15 {
            fmt::Println!("[ 1] MarshalBinary len=15       PASS");
        } else {
            fmt::Println!("[ 1] MarshalBinary len=15       FAIL len={}", b.Len());
            failed += 1;
        }
    }

    // 2. First byte is version V1 (=1).
    {
        let t = time::Unix(0, 0);
        let (b, _) = t.MarshalBinary();
        if b[0] == 1 {
            fmt::Println!("[ 2] version byte == V1         PASS");
        } else {
            fmt::Println!("[ 2] version byte == V1         FAIL got={}", b[0]);
            failed += 1;
        }
    }

    // 3. Last two bytes encode offsetMin = -1 (0xFFFF) for UTC.
    {
        let t = time::Unix(42, 0);
        let (b, _) = t.MarshalBinary();
        if b[13] == 0xff && b[14] == 0xff {
            fmt::Println!("[ 3] offset bytes = -1          PASS");
        } else {
            fmt::Println!("[ 3] offset bytes = -1          FAIL {:x} {:x}", b[13], b[14]);
            failed += 1;
        }
    }

    // 4. Round-trip Marshal → Unmarshal preserves sec & nsec.
    {
        let t = time::Unix(1_700_000_000, 123_456_789);
        let (b, _) = t.MarshalBinary();
        let mut t2 = time::Unix(0, 0);
        let err = t2.UnmarshalBinary(b);
        if err.IsNil() && t2.Unix() == 1_700_000_000 && t2.UnixNano() == 1_700_000_000 * 1_000_000_000 + 123_456_789 {
            fmt::Println!("[ 4] round-trip preserves       PASS");
        } else {
            fmt::Println!("[ 4] round-trip preserves       FAIL");
            failed += 1;
        }
    }

    // 5. UnmarshalBinary on empty input returns "no data" error.
    {
        let mut t = time::Unix(0, 0);
        let err = t.UnmarshalBinary(make!([]goish::byte, 0));
        if !err.IsNil() {
            fmt::Println!("[ 5] empty data error           PASS");
        } else {
            fmt::Println!("[ 5] empty data error           FAIL");
            failed += 1;
        }
    }

    // 6. UnmarshalBinary rejects bad version byte (e.g., 99).
    {
        let mut t = time::Unix(0, 0);
        let mut buf = make!([]goish::byte, 15);
        buf[0] = 99;
        let err = t.UnmarshalBinary(buf);
        if !err.IsNil() {
            fmt::Println!("[ 6] bad version rejected       PASS");
        } else {
            fmt::Println!("[ 6] bad version rejected       FAIL");
            failed += 1;
        }
    }

    // 7. UnmarshalBinary rejects wrong-length buffer.
    {
        let mut t = time::Unix(0, 0);
        let mut buf = make!([]goish::byte, 7);
        buf[0] = 1; // version V1 but length is wrong
        let err = t.UnmarshalBinary(buf);
        if !err.IsNil() {
            fmt::Println!("[ 7] short buffer rejected      PASS");
        } else {
            fmt::Println!("[ 7] short buffer rejected      FAIL");
            failed += 1;
        }
    }

    // 8. AppendBinary appends to existing prefix.
    {
        let t = time::Unix(7, 0);
        let mut prefix = make!([]goish::byte, 3);
        prefix[0] = 0xAA;
        prefix[1] = 0xBB;
        prefix[2] = 0xCC;
        let (b, err) = t.AppendBinary(prefix);
        if err.IsNil() && b.Len() == 3 + 15 && b[0] == 0xAA && b[1] == 0xBB && b[2] == 0xCC && b[3] == 1 {
            fmt::Println!("[ 8] AppendBinary preserves     PASS");
        } else {
            fmt::Println!("[ 8] AppendBinary preserves     FAIL len={}", b.Len());
            failed += 1;
        }
    }

    // 9. GobEncode == MarshalBinary.
    {
        let t = time::Unix(123, 456);
        let (a, _) = t.MarshalBinary();
        let (g, _) = t.GobEncode();
        let mut equal = a.Len() == g.Len();
        for i in 0..a.Len() {
            if a[i] != g[i] {
                equal = false;
            }
        }
        if equal {
            fmt::Println!("[ 9] GobEncode == MarshalBinary PASS");
        } else {
            fmt::Println!("[ 9] GobEncode == MarshalBinary FAIL");
            failed += 1;
        }
    }

    // 10. GobDecode mirrors UnmarshalBinary on a Marshal output.
    {
        let t = time::Unix(99_999, 12_345);
        let (b, _) = t.GobEncode();
        let mut t2 = time::Unix(0, 0);
        let err = t2.GobDecode(b);
        if err.IsNil() && t2.Unix() == 99_999 && t2.UnixNano() == 99_999 * 1_000_000_000 + 12_345 {
            fmt::Println!("[10] GobDecode round-trip       PASS");
        } else {
            fmt::Println!("[10] GobDecode round-trip       FAIL");
            failed += 1;
        }
    }

    // 11. V2 input (16 bytes, version=2) is accepted; sec/nsec unchanged.
    {
        let mut buf = make!([]goish::byte, 16);
        buf[0] = 2; // V2
        // sec = 0x0000_0000_0000_002A = 42 (big-endian, bytes 1..8)
        buf[8] = 42;
        // nsec = 0; offset bytes = 0; offsetSec = 0.
        let mut t = time::Unix(0, 0);
        let err = t.UnmarshalBinary(buf);
        if err.IsNil() && t.Unix() == 42 {
            fmt::Println!("[11] V2 accepted                PASS");
        } else {
            fmt::Println!("[11] V2 accepted                FAIL");
            failed += 1;
        }
    }

    // 12. Round-trip large negative-equivalent epoch (year far past).
    {
        let t = time::Unix(0, 999_999_999);
        let (b, _) = t.MarshalBinary();
        let mut t2 = time::Unix(0, 0);
        let _ = t2.UnmarshalBinary(b);
        if t2.Unix() == 0 && t2.UnixNano() == 999_999_999 {
            fmt::Println!("[12] nano-only round-trip       PASS");
        } else {
            fmt::Println!("[12] nano-only round-trip       FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 12/12");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL {} of 12", failed);
        syscall::Exit(1);
    }
}
