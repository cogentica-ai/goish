// adler32_smoke — exercise hash/adler32.
// (hash/adler32/adler32.go)
//
// Reference values: RFC 1950 + Go 1.25's adler32. Adler-32 of "" = 1
// (s1=1, s2=0). Of "Wikipedia" = 0x11E60398.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::convert::bytes as to_bytes;
use goish::goslice::slice;
use goish::hash::adler32;
use goish::hash::{Hash, Hash32};
use goish::io::Writer as _;
use goish::types::byte;
use goish::{syscall, Println};

fn empty_buf() -> slice<byte> {
    slice::<byte>::__from_vec(Vec::new())
}

fn equal_bytes(a: slice<byte>, b: slice<byte>) -> bool {
    let aa: &[byte] = &a;
    let bb: &[byte] = &b;
    aa == bb
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Checksum("") = 1 (s1=1, s2=0 → 0x00000001).
    {
        if adler32::Checksum(to_bytes("")) == 1 {
            Println!("[ 1] empty                     PASS");
        } else {
            Println!("[ 1] empty                     FAIL");
            failed += 1;
        }
    }

    // 2. Checksum("a") = (s1=98=0x62, s2=98=0x62) → 0x00620062.
    {
        // After "a": s1=1+97=98, s2=0+98=98. So (98<<16)|98 = 0x00620062.
        if adler32::Checksum(to_bytes("a")) == 0x00620062 {
            Println!("[ 2] \"a\"                       PASS");
        } else {
            Println!("[ 2] \"a\"                       FAIL");
            failed += 1;
        }
    }

    // 3. Checksum("Wikipedia") = 0x11E60398 (canonical RFC 1950 example).
    {
        if adler32::Checksum(to_bytes("Wikipedia")) == 0x11E60398 {
            Println!("[ 3] \"Wikipedia\"               PASS");
        } else {
            Println!("[ 3] \"Wikipedia\"               FAIL");
            failed += 1;
        }
    }

    // 4. New + Write streaming equals one-shot Checksum.
    {
        let mut h = adler32::New();
        let _ = h.Write(to_bytes("Wiki"));
        let _ = h.Write(to_bytes("pedia"));
        if h.Sum32() == 0x11E60398 {
            Println!("[ 4] streaming                 PASS");
        } else {
            Println!("[ 4] streaming                 FAIL");
            failed += 1;
        }
    }

    // 5. Reset returns digest to initial state (s1=1, s2=0 → 1).
    {
        let mut h = adler32::New();
        let _ = h.Write(to_bytes("hello"));
        h.Reset();
        if h.Sum32() == 1 {
            Println!("[ 5] Reset                     PASS");
        } else {
            Println!("[ 5] Reset                     FAIL");
            failed += 1;
        }
    }

    // 6. Sum appends BE bytes — "Wikipedia" → 11 E6 03 98.
    {
        let mut h = adler32::New();
        let _ = h.Write(to_bytes("Wikipedia"));
        let out = h.Sum(empty_buf());
        let mut want_v: Vec<byte> = Vec::new();
        want_v.push(0x11);
        want_v.push(0xE6);
        want_v.push(0x03);
        want_v.push(0x98);
        let want = slice::<byte>::__from_vec(want_v);
        if equal_bytes(out, want) {
            Println!("[ 6] Sum BE append             PASS");
        } else {
            Println!("[ 6] Sum BE append             FAIL");
            failed += 1;
        }
    }

    // 7. Sum preserves dst prefix.
    {
        let mut h = adler32::New();
        let _ = h.Write(to_bytes("a"));
        let dst = to_bytes("PRE:");
        let out = h.Sum(dst);
        let raw: &[byte] = &out;
        // "PRE:" + 00 62 00 62.
        if raw.len() == 4 + 4
            && &raw[0..4] == b"PRE:"
            && raw[4] == 0x00
            && raw[5] == 0x62
            && raw[6] == 0x00
            && raw[7] == 0x62
        {
            Println!("[ 7] Sum prefix                PASS");
        } else {
            Println!("[ 7] Sum prefix                FAIL");
            failed += 1;
        }
    }

    // 8. Size + BlockSize.
    {
        let h = adler32::New();
        if h.Size() == adler32::Size && h.BlockSize() == 4 {
            Println!("[ 8] Size/BlockSize            PASS");
        } else {
            Println!("[ 8] Size/BlockSize            FAIL");
            failed += 1;
        }
    }

    // 9. Long input crosses NMAX boundary (5552 bytes triggers reduction).
    //    Verify Checksum stays consistent across two equivalent inputs.
    {
        // Build a 6000-byte input, all 'x' (0x78). Stream vs one-shot.
        let mut v: Vec<byte> = Vec::with_capacity(6000);
        let mut i = 0;
        while i < 6000 {
            v.push(b'x');
            i += 1;
        }
        let buf = slice::<byte>::__from_vec(v);
        let one_shot = adler32::Checksum(buf.clone());

        let mut h = adler32::New();
        let _ = h.Write(buf);
        let streaming = h.Sum32();

        if one_shot == streaming && one_shot != 0 {
            Println!("[ 9] >NMAX boundary            PASS");
        } else {
            Println!("[ 9] >NMAX boundary            FAIL");
            failed += 1;
        }
    }

    // 10. Multiple Resets in a row return to 1.
    {
        let mut h = adler32::New();
        let _ = h.Write(to_bytes("first"));
        h.Reset();
        let _ = h.Write(to_bytes("second"));
        h.Reset();
        if h.Sum32() == 1 {
            Println!("[10] Reset twice               PASS");
        } else {
            Println!("[10] Reset twice               FAIL");
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
