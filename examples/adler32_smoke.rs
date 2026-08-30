// adler32_smoke — exercise hash/adler32.
// (hash/adler32/adler32.go)
//
// Checks 1-10 use RFC 1950's canonical values (Adler-32 of "" = 1,
// of "Wikipedia" = 0x11E60398). Checks 11-15 use values printed by a
// running Go 1.25.5 (tools/gen_adler32_ref.go, run through
// scripts/goref.sh): the block boundary at nmax=5552 in both
// directions, and the marshal/unmarshal/Clone surface.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::convert::byte as tobyte;
use goish::convert::bytes as to_bytes;
use goish::fmt;
use goish::goslice::slice;
use goish::hash::adler32;
use goish::hash::{Hash, Hash32};
use goish::io::Writer as _;
use goish::nil;
use goish::syscall;
use goish::types::{byte, uint32};

// The Go reference corpus: byte i = (i*7+3)%251.
fn mk(n: usize) -> slice<byte> {
    let mut v: Vec<byte> = Vec::with_capacity(n);
    let mut i: usize = 0;
    while i < n {
        v.push(tobyte((i * 7 + 3) % 251));
        i += 1;
    }
    slice::<byte>::__from_vec(v)
}

fn from_hex(h: &[u8]) -> slice<byte> {
    fn nib(c: u8) -> byte {
        if c >= b'a' {
            return c - b'a' + 10;
        }
        return c - b'0';
    }
    let mut v: Vec<byte> = Vec::with_capacity(h.len() / 2);
    let mut i: usize = 0;
    while i < h.len() {
        v.push((nib(h[i]) << 4) | nib(h[i + 1]));
        i += 2;
    }
    slice::<byte>::__from_vec(v)
}

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
            fmt::Println!("[ 1] empty                     PASS");
        } else {
            fmt::Println!("[ 1] empty                     FAIL");
            failed += 1;
        }
    }

    // 2. Checksum("a") = (s1=98=0x62, s2=98=0x62) → 0x00620062.
    {
        // After "a": s1=1+97=98, s2=0+98=98. So (98<<16)|98 = 0x00620062.
        if adler32::Checksum(to_bytes("a")) == 0x00620062 {
            fmt::Println!("[ 2] \"a\"                       PASS");
        } else {
            fmt::Println!("[ 2] \"a\"                       FAIL");
            failed += 1;
        }
    }

    // 3. Checksum("Wikipedia") = 0x11E60398 (canonical RFC 1950 example).
    {
        if adler32::Checksum(to_bytes("Wikipedia")) == 0x11E60398 {
            fmt::Println!("[ 3] \"Wikipedia\"               PASS");
        } else {
            fmt::Println!("[ 3] \"Wikipedia\"               FAIL");
            failed += 1;
        }
    }

    // 4. New + Write streaming equals one-shot Checksum.
    {
        let mut h = adler32::New();
        let _ = h.Write(to_bytes("Wiki"));
        let _ = h.Write(to_bytes("pedia"));
        if h.Sum32() == 0x11E60398 {
            fmt::Println!("[ 4] streaming                 PASS");
        } else {
            fmt::Println!("[ 4] streaming                 FAIL");
            failed += 1;
        }
    }

    // 5. Reset returns digest to initial state (s1=1, s2=0 → 1).
    {
        let mut h = adler32::New();
        let _ = h.Write(to_bytes("hello"));
        h.Reset();
        if h.Sum32() == 1 {
            fmt::Println!("[ 5] Reset                     PASS");
        } else {
            fmt::Println!("[ 5] Reset                     FAIL");
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
            fmt::Println!("[ 6] Sum BE append             PASS");
        } else {
            fmt::Println!("[ 6] Sum BE append             FAIL");
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
            fmt::Println!("[ 7] Sum prefix                PASS");
        } else {
            fmt::Println!("[ 7] Sum prefix                FAIL");
            failed += 1;
        }
    }

    // 8. Size + BlockSize.
    {
        let h = adler32::New();
        if h.Size() == adler32::Size && h.BlockSize() == 4 {
            fmt::Println!("[ 8] Size/BlockSize            PASS");
        } else {
            fmt::Println!("[ 8] Size/BlockSize            FAIL");
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
            fmt::Println!("[ 9] >NMAX boundary            PASS");
        } else {
            fmt::Println!("[ 9] >NMAX boundary            FAIL");
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
            fmt::Println!("[10] Reset twice               PASS");
        } else {
            fmt::Println!("[10] Reset twice               FAIL");
            failed += 1;
        }
    }

    // 11. Go-checked corpus either side of the nmax=5552 block boundary
    //     and of the unrolled four-byte step.
    {
        let golden: [(usize, uint32); 10] = [
            (0, 0x00000001),
            (1, 0x00040004),
            (3, 0x0031001f),
            (4, 0x00680037),
            (5, 0x00be0056),
            (5551, 0xbae59452),
            (5552, 0x50149520),
            (5553, 0xe60995f5),
            (11104, 0x9a1d2b62),
            (11105, 0xc62b2c0e),
        ];
        let mut bad = 0;
        let mut k: usize = 0;
        while k < golden.len() {
            let (n, want) = golden[k];
            if adler32::Checksum(mk(n)) != want {
                bad += 1;
            }
            k += 1;
        }
        if bad == 0 {
            fmt::Println!("[11] nmax blocks vs Go         PASS");
        } else {
            fmt::Println!("[11] nmax blocks vs Go         FAIL");
            failed += 1;
        }
    }

    // 12. MarshalBinary emits the exact state Go emits.
    {
        let mut h = adler32::New();
        let _ = h.Write(to_bytes("hello world"));
        let (st, err) = h.MarshalBinary();
        let want = from_hex(b"61646c011a0b045d");
        if err == nil && equal_bytes(st, want) && h.Sum32() == 0x1a0b045d {
            fmt::Println!("[12] MarshalBinary vs Go       PASS");
        } else {
            fmt::Println!("[12] MarshalBinary vs Go       FAIL");
            failed += 1;
        }
    }

    // 13. UnmarshalBinary resumes a digest mid-stream.
    {
        let mut h = adler32::New();
        let _ = h.Write(to_bytes("hello world"));
        let (st, _) = h.MarshalBinary();
        let mut h2 = adler32::New();
        let err = h2.UnmarshalBinary(st);
        let _ = h2.Write(to_bytes("!!"));
        let _ = h.Write(to_bytes("!!"));
        if err == nil && h2.Sum32() == 0x2328049f && h.Sum32() == h2.Sum32() {
            fmt::Println!("[13] UnmarshalBinary resume    PASS");
        } else {
            fmt::Println!("[13] UnmarshalBinary resume    FAIL");
            failed += 1;
        }
    }

    // 14. A corrupt header is refused; so is a state of the wrong
    //     length. A state too short to hold the magic fails the
    //     identifier check first — Go's order, reproduced.
    {
        let mut h = adler32::New();
        let _ = h.Write(to_bytes("hello world"));
        let (st, _) = h.MarshalBinary();
        let raw: &[byte] = &st;

        let mut badv: Vec<byte> = raw.to_vec();
        badv[0] = b'x';
        let mut h3 = adler32::New();
        let bad_magic = h3.UnmarshalBinary(slice::<byte>::__from_vec(badv));

        let short = slice::<byte>::__from_vec(raw[..3].to_vec());
        let too_short = h3.UnmarshalBinary(short);

        let mut longv: Vec<byte> = raw.to_vec();
        longv.push(0);
        let too_long = h3.UnmarshalBinary(slice::<byte>::__from_vec(longv));

        if bad_magic.Error() == "hash/adler32: invalid hash state identifier"
            && too_short.Error() == "hash/adler32: invalid hash state identifier"
            && too_long.Error() == "hash/adler32: invalid hash state size"
        {
            fmt::Println!("[14] Unmarshal rejections      PASS");
        } else {
            fmt::Println!("[14] Unmarshal rejections      FAIL");
            failed += 1;
        }
    }

    // 15. Clone snapshots the state; writing on either side is
    //     invisible to the other.
    {
        let mut h4 = adler32::New();
        let _ = h4.Write(to_bytes("abc"));
        let (c, err) = h4.Clone();
        let _ = h4.Write(to_bytes("def"));
        let got = c.Sum(empty_buf());
        let want = from_hex(b"024d0127");
        if err == nil && equal_bytes(got, want) && h4.Sum32() == 0x081e0256 {
            fmt::Println!("[15] Clone independence        PASS");
        } else {
            fmt::Println!("[15] Clone independence        FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 15/15");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 15");
        syscall::Exit(1);
    }
}
