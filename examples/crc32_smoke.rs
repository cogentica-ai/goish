// crc32_smoke — exercise hash/crc32 (IEEE + Castagnoli + Koopman).
// (hash/crc32/crc32.go)
//
// Checks 1-11 use canonical CRC-32 values (of "" is 0; of "a" is
// 0xE8B7BE43 IEEE). Checks 12-16 use values printed by a running Go
// 1.25.5 (tools/gen_crc32_ref.go, run through scripts/goref.sh): both
// sides of the slicing8Cutoff=16 threshold for all three polynomials,
// and the marshal/unmarshal/Clone surface.

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
use goish::hash::crc32;
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

    // 1. ChecksumIEEE("") = 0.
    {
        if crc32::ChecksumIEEE(to_bytes("")) == 0 {
            fmt::Println!("[ 1] IEEE empty                PASS");
        } else {
            fmt::Println!("[ 1] IEEE empty                FAIL");
            failed += 1;
        }
    }

    // 2. ChecksumIEEE("a") = 0xE8B7BE43.
    {
        if crc32::ChecksumIEEE(to_bytes("a")) == 0xE8B7BE43 {
            fmt::Println!("[ 2] IEEE \"a\"                  PASS");
        } else {
            fmt::Println!("[ 2] IEEE \"a\"                  FAIL");
            failed += 1;
        }
    }

    // 3. ChecksumIEEE("123456789") = 0xCBF43926.
    {
        if crc32::ChecksumIEEE(to_bytes("123456789")) == 0xCBF43926 {
            fmt::Println!("[ 3] IEEE \"123456789\"          PASS");
        } else {
            fmt::Println!("[ 3] IEEE \"123456789\"          FAIL");
            failed += 1;
        }
    }

    // 4. New + Write streaming equals one-shot Checksum.
    {
        let mut h = crc32::NewIEEE();
        let _ = h.Write(to_bytes("123"));
        let _ = h.Write(to_bytes("456789"));
        if h.Sum32() == 0xCBF43926 {
            fmt::Println!("[ 4] IEEE streaming            PASS");
        } else {
            fmt::Println!("[ 4] IEEE streaming            FAIL");
            failed += 1;
        }
    }

    // 5. Reset zeros the running CRC.
    {
        let mut h = crc32::NewIEEE();
        let _ = h.Write(to_bytes("hello"));
        h.Reset();
        if h.Sum32() == 0 {
            fmt::Println!("[ 5] Reset                     PASS");
        } else {
            fmt::Println!("[ 5] Reset                     FAIL");
            failed += 1;
        }
    }

    // 6. Sum appends BE bytes — IEEE("123456789") = 0xCBF43926.
    {
        let mut h = crc32::NewIEEE();
        let _ = h.Write(to_bytes("123456789"));
        let out = h.Sum(empty_buf());
        // Big-endian: CB F4 39 26
        let mut want_v: Vec<byte> = Vec::new();
        want_v.push(0xCB);
        want_v.push(0xF4);
        want_v.push(0x39);
        want_v.push(0x26);
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
        let mut h = crc32::NewIEEE();
        let _ = h.Write(to_bytes("a"));
        let dst = to_bytes("PRE:");
        let out = h.Sum(dst);
        let raw: &[byte] = &out;
        // Expect "PRE:" + 4 BE bytes of 0xE8B7BE43.
        if raw.len() == 4 + 4
            && &raw[0..4] == b"PRE:"
            && raw[4] == 0xE8
            && raw[5] == 0xB7
            && raw[6] == 0xBE
            && raw[7] == 0x43
        {
            fmt::Println!("[ 7] Sum prefix                PASS");
        } else {
            fmt::Println!("[ 7] Sum prefix                FAIL");
            failed += 1;
        }
    }

    // 8. Castagnoli table — checksum of "123456789" = 0xE3069283.
    {
        let tab = crc32::MakeTable(crc32::Castagnoli);
        let v = crc32::Checksum(to_bytes("123456789"), &tab);
        if v == 0xE3069283 {
            fmt::Println!("[ 8] Castagnoli check          PASS");
        } else {
            fmt::Println!("[ 8] Castagnoli check          FAIL");
            failed += 1;
        }
    }

    // 9. Update — incremental seed produces same CRC as one-shot.
    {
        let tab = crc32::IEEETable();
        let mut crc: u32 = 0;
        crc = crc32::Update(crc, &tab, to_bytes("foo"));
        crc = crc32::Update(crc, &tab, to_bytes("bar"));
        let one_shot = crc32::ChecksumIEEE(to_bytes("foobar"));
        if crc == one_shot {
            fmt::Println!("[ 9] Update incremental        PASS");
        } else {
            fmt::Println!("[ 9] Update incremental        FAIL");
            failed += 1;
        }
    }

    // 10. IEEETable singleton — repeated calls return the same Arc payload.
    {
        let a = crc32::IEEETable();
        let b = crc32::IEEETable();
        // Compare table entries: should be byte-identical.
        if a.at(0) == b.at(0) && a.at(255) == b.at(255) {
            fmt::Println!("[10] IEEETable singleton       PASS");
        } else {
            fmt::Println!("[10] IEEETable singleton       FAIL");
            failed += 1;
        }
    }

    // 11. Size + BlockSize.
    {
        let h = crc32::NewIEEE();
        if h.Size() == crc32::Size && h.BlockSize() == 1 {
            fmt::Println!("[11] Size/BlockSize            PASS");
        } else {
            fmt::Println!("[11] Size/BlockSize            FAIL");
            failed += 1;
        }
    }

    // 12. Go-checked corpus either side of slicing8Cutoff=16 and of the
    //     eight-byte inner loop, for all three polynomials. IEEE and
    //     Castagnoli route through slicing-by-8; Koopman has no
    //     preinitialized table, so it takes the simple path — one
    //     table exercises both branches of `update`.
    {
        let ieee = crc32::MakeTable(crc32::IEEE);
        let cast = crc32::MakeTable(crc32::Castagnoli);
        let koop = crc32::MakeTable(crc32::Koopman);
        let golden: [(usize, uint32, uint32, uint32); 9] = [
            (0, 0x00000000, 0x00000000, 0x00000000),
            (1, 0x4b0bbe37, 0x412da0a5, 0x528fd171),
            (8, 0xe2e35978, 0xd225c0e8, 0x7e5215b5),
            (9, 0x3d351cfe, 0x922c64ce, 0x4e41dbd1),
            (15, 0x7c619edc, 0x9028c025, 0xb5a905d2),
            (16, 0x191f3d9f, 0x6b24bde1, 0x1cb881d8),
            (17, 0x7ba75ee3, 0x2185fb0c, 0x29b89865),
            (64, 0x4b082b09, 0x8f1ae5e8, 0x86b576fc),
            (1000, 0xa2f92763, 0xa4c0fde8, 0xf6fe6181),
        ];
        let mut bad = 0;
        let mut k: usize = 0;
        while k < golden.len() {
            let (n, wi, wc, wk) = golden[k];
            let p = mk(n);
            if crc32::Checksum(p.clone(), &ieee) != wi {
                bad += 1;
            }
            if crc32::Checksum(p.clone(), &cast) != wc {
                bad += 1;
            }
            if crc32::Checksum(p, &koop) != wk {
                bad += 1;
            }
            k += 1;
        }
        if bad == 0 {
            fmt::Println!("[12] slicing-by-8 vs Go        PASS");
        } else {
            fmt::Println!("[12] slicing-by-8 vs Go        FAIL");
            failed += 1;
        }
    }

    // 13. MarshalBinary emits the exact state Go emits, table checksum
    //     and all — different for IEEE and Castagnoli, which is what
    //     makes a cross-table restore detectable.
    {
        let mut h = crc32::New(crc32::MakeTable(crc32::IEEE));
        let _ = h.Write(to_bytes("hello world"));
        let (st, err) = h.MarshalBinary();
        let mut hc = crc32::New(crc32::MakeTable(crc32::Castagnoli));
        let _ = hc.Write(to_bytes("hello world"));
        let (stc, _) = hc.MarshalBinary();
        if err == nil
            && equal_bytes(st, from_hex(b"63726301ca87914d0d4a1185"))
            && equal_bytes(stc, from_hex(b"6372630177428481c99465aa"))
            && h.Sum32() == 0x0d4a1185
            && hc.Sum32() == 0xc99465aa
        {
            fmt::Println!("[13] MarshalBinary vs Go       PASS");
        } else {
            fmt::Println!("[13] MarshalBinary vs Go       FAIL");
            failed += 1;
        }
    }

    // 14. UnmarshalBinary resumes a digest mid-stream.
    {
        let mut h = crc32::New(crc32::MakeTable(crc32::IEEE));
        let _ = h.Write(to_bytes("hello world"));
        let (st, _) = h.MarshalBinary();
        let mut h2 = crc32::New(crc32::MakeTable(crc32::IEEE));
        let err = h2.UnmarshalBinary(st);
        let _ = h2.Write(to_bytes("!!"));
        let _ = h.Write(to_bytes("!!"));
        if err == nil && h2.Sum32() == 0xad6b56f4 && h.Sum32() == h2.Sum32() {
            fmt::Println!("[14] UnmarshalBinary resume    PASS");
        } else {
            fmt::Println!("[14] UnmarshalBinary resume    FAIL");
            failed += 1;
        }
    }

    // 15. An IEEE state is refused by a Castagnoli digest; a corrupt
    //     header and a wrong length are refused too.
    {
        let mut h = crc32::New(crc32::MakeTable(crc32::IEEE));
        let _ = h.Write(to_bytes("hello world"));
        let (st, _) = h.MarshalBinary();
        let raw: &[byte] = &st;
        let mut h3 = crc32::New(crc32::MakeTable(crc32::Castagnoli));
        let cross = h3.UnmarshalBinary(st.clone());

        let mut badv: Vec<byte> = raw.to_vec();
        badv[0] = b'x';
        let bad_magic = h3.UnmarshalBinary(slice::<byte>::__from_vec(badv));
        let short = slice::<byte>::__from_vec(raw[..11].to_vec());
        let bad_size = h3.UnmarshalBinary(short);

        if cross.Error() == "hash/crc32: tables do not match"
            && bad_magic.Error() == "hash/crc32: invalid hash state identifier"
            && bad_size.Error() == "hash/crc32: invalid hash state size"
        {
            fmt::Println!("[15] Unmarshal rejections      PASS");
        } else {
            fmt::Println!("[15] Unmarshal rejections      FAIL");
            failed += 1;
        }
    }

    // 16. Clone snapshots the state, and ChecksumIEEE agrees with a
    //     digest built the long way.
    {
        let mut h4 = crc32::NewIEEE();
        let _ = h4.Write(to_bytes("abc"));
        let (c, err) = h4.Clone();
        let _ = h4.Write(to_bytes("def"));
        let got = c.Sum(empty_buf());
        if err == nil
            && equal_bytes(got, from_hex(b"352441c2"))
            && h4.Sum32() == 0x4b8e39ef
            && crc32::ChecksumIEEE(to_bytes("hello world")) == 0x0d4a1185
        {
            fmt::Println!("[16] Clone independence        PASS");
        } else {
            fmt::Println!("[16] Clone independence        FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 16/16");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 16");
        syscall::Exit(1);
    }
}
