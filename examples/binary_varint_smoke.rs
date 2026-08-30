// binary_varint_smoke — exercise encoding/binary varint + AppendUint*.
// (encoding/binary/varint.go, binary.go AppendUint16/32/64)
//
// Checks 1-12 are hand-written. Checks 13-16 replay encodings and
// decode results printed by a running Go 1.25.5
// (tools/gen_varint_ref.go, run through scripts/goref.sh), including
// the two overflow rules that are easy to get subtly wrong: a tenth
// byte greater than 1, and refusing to look at an eleventh byte at
// all (golang.org/issue/41185).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::bytes;
use goish::encoding::binary;
use goish::fmt;
use goish::goslice::slice;
use goish::syscall;
use goish::types::{byte, int, uint};

fn empty_buf() -> slice<byte> {
    slice::<byte>::__from_vec(Vec::new())
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. AppendUvarint round-trip — small (< 0x80, single byte).
    {
        let buf = binary::AppendUvarint(empty_buf(), 0x42);
        if buf.Len() == 1 && buf[0] == 0x42 {
            fmt::Println!("[ 1] AppendUvarint small       PASS");
        } else {
            fmt::Println!("[ 1] AppendUvarint small       FAIL");
            failed += 1;
        }
    }

    // 2. AppendUvarint — 150 spans 2 bytes (0x96 0x01).
    {
        let buf = binary::AppendUvarint(empty_buf(), 150);
        if buf.Len() == 2 && buf[0] == 0x96 && buf[1] == 0x01 {
            fmt::Println!("[ 2] AppendUvarint 150         PASS");
        } else {
            fmt::Println!("[ 2] AppendUvarint 150         FAIL");
            failed += 1;
        }
    }

    // 3. AppendUvarint round-trip — verifies Uvarint decode matches.
    {
        let values: [uint; 6] = [0, 1, 127, 128, 16384, 1_000_000_000];
        let mut all_ok = true;
        for v in values {
            let buf = binary::AppendUvarint(empty_buf(), v);
            let (got, n) = binary::Uvarint(buf.clone());
            if got != v || n <= 0 || n != buf.Len() {
                all_ok = false;
                break;
            }
        }
        if all_ok {
            fmt::Println!("[ 3] Uvarint round-trip        PASS");
        } else {
            fmt::Println!("[ 3] Uvarint round-trip        FAIL");
            failed += 1;
        }
    }

    // 4. Uvarint empty buf → (0, 0).
    {
        let (v, n) = binary::Uvarint(empty_buf());
        if v == 0 && n == 0 {
            fmt::Println!("[ 4] Uvarint empty             PASS");
        } else {
            fmt::Println!("[ 4] Uvarint empty             FAIL");
            failed += 1;
        }
    }

    // 5. AppendVarint round-trip — positive + negative + zero.
    {
        let values: [int; 5] = [0, 1, -1, 100, -100];
        let mut all_ok = true;
        for v in values {
            let buf = binary::AppendVarint(empty_buf(), v);
            let (got, n) = binary::Varint(buf);
            if got != v || n <= 0 {
                all_ok = false;
                break;
            }
        }
        if all_ok {
            fmt::Println!("[ 5] Varint round-trip         PASS");
        } else {
            fmt::Println!("[ 5] Varint round-trip         FAIL");
            failed += 1;
        }
    }

    // 6. AppendVarint — zig-zag encoding (-1 → 0x01).
    {
        let buf = binary::AppendVarint(empty_buf(), -1);
        if buf.Len() == 1 && buf[0] == 0x01 {
            fmt::Println!("[ 6] AppendVarint -1           PASS");
        } else {
            fmt::Println!("[ 6] AppendVarint -1           FAIL");
            failed += 1;
        }
    }

    // 7. MaxVarintLen* constants.
    {
        if binary::MaxVarintLen16 == 3
            && binary::MaxVarintLen32 == 5
            && binary::MaxVarintLen64 == 10
        {
            fmt::Println!("[ 7] MaxVarintLenN             PASS");
        } else {
            fmt::Println!("[ 7] MaxVarintLenN             FAIL");
            failed += 1;
        }
    }

    // 8. BigEndian.AppendUint16.
    {
        let buf = binary::BigEndian.AppendUint16(empty_buf(), 0x1234);
        if buf.Len() == 2 && buf[0] == 0x12 && buf[1] == 0x34 {
            fmt::Println!("[ 8] BE.AppendUint16           PASS");
        } else {
            fmt::Println!("[ 8] BE.AppendUint16           FAIL");
            failed += 1;
        }
    }

    // 9. BigEndian.AppendUint32.
    {
        let buf = binary::BigEndian.AppendUint32(empty_buf(), 0xDEADBEEF);
        if buf.Len() == 4 && buf[0] == 0xDE && buf[1] == 0xAD && buf[2] == 0xBE && buf[3] == 0xEF {
            fmt::Println!("[ 9] BE.AppendUint32           PASS");
        } else {
            fmt::Println!("[ 9] BE.AppendUint32           FAIL");
            failed += 1;
        }
    }

    // 10. BigEndian.AppendUint64.
    {
        let buf = binary::BigEndian.AppendUint64(empty_buf(), 0x0102030405060708);
        if buf.Len() == 8 && buf[0] == 0x01 && buf[7] == 0x08 {
            fmt::Println!("[10] BE.AppendUint64           PASS");
        } else {
            fmt::Println!("[10] BE.AppendUint64           FAIL");
            failed += 1;
        }
    }

    // 11. LittleEndian.AppendUint32 (byte-order flip).
    {
        let buf = binary::LittleEndian.AppendUint32(empty_buf(), 0xDEADBEEF);
        if buf.Len() == 4 && buf[0] == 0xEF && buf[1] == 0xBE && buf[2] == 0xAD && buf[3] == 0xDE {
            fmt::Println!("[11] LE.AppendUint32           PASS");
        } else {
            fmt::Println!("[11] LE.AppendUint32           FAIL");
            failed += 1;
        }
    }

    // 12. AppendUint16 builds on existing buf (preserves prefix).
    {
        let prefix: alloc::vec::Vec<byte> = alloc::vec![0xAA, 0xBB];
        let buf = binary::BigEndian.AppendUint16(slice::__from_vec(prefix), 0x1234);
        if buf.Len() == 4 && buf[0] == 0xAA && buf[1] == 0xBB && buf[2] == 0x12 && buf[3] == 0x34 {
            fmt::Println!("[12] AppendUint16 prefix       PASS");
        } else {
            fmt::Println!("[12] AppendUint16 prefix       FAIL");
            failed += 1;
        }
    }

    // 13. Unsigned encodings against Go, across every group boundary.
    {
        let cases: [(uint, &[u8]); 10] = [
            (0, b"\x00"),
            (1, b"\x01"),
            (127, b"\x7f"),
            (128, b"\x80\x01"),
            (255, b"\xff\x01"),
            (256, b"\x80\x02"),
            (16383, b"\xff\x7f"),
            (16384, b"\x80\x80\x01"),
            (1u64 << 32, b"\x80\x80\x80\x80\x10"),
            (u64::MAX, b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01"),
        ];
        let mut bad = 0;
        let mut k: usize = 0;
        while k < cases.len() {
            let (v, want) = cases[k];
            let enc = binary::AppendUvarint(empty_buf(), v);
            let raw: &[byte] = &enc;
            if raw != want {
                bad += 1;
            }
            // Round-trips, and PutUvarint agrees with AppendUvarint.
            let (back, n) = binary::Uvarint(enc.clone());
            if back != v || n != want.len() as int {
                bad += 1;
            }
            let mut buf = slice::<byte>::__from_vec(alloc::vec![0u8; 16]);
            let m = binary::PutUvarint(&mut buf, v);
            let br: &[byte] = &buf;
            if m != want.len() as int || &br[..want.len()] != want {
                bad += 1;
            }
            k += 1;
        }
        if bad == 0 {
            fmt::Println!("[13] Uvarint vs Go            PASS");
        } else {
            fmt::Println!("[13] Uvarint vs Go            FAIL");
            failed += 1;
        }
    }

    // 14. Signed (zig-zag) encodings against Go. Small magnitudes of
    //     either sign must stay short, which is the whole point of the
    //     zig-zag: -1 is one byte, not ten.
    {
        let cases: [(int, &[u8]); 11] = [
            (0, b"\x00"),
            (1, b"\x02"),
            (-1, b"\x01"),
            (63, b"\x7e"),
            (-64, b"\x7f"),
            (64, b"\x80\x01"),
            (-65, b"\x81\x01"),
            (1i64 << 31, b"\x80\x80\x80\x80\x10"),
            (-(1i64 << 31), b"\xff\xff\xff\xff\x0f"),
            (i64::MAX, b"\xfe\xff\xff\xff\xff\xff\xff\xff\xff\x01"),
            (i64::MIN, b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01"),
        ];
        let mut bad = 0;
        let mut k: usize = 0;
        while k < cases.len() {
            let (v, want) = cases[k];
            let enc = binary::AppendVarint(empty_buf(), v);
            let raw: &[byte] = &enc;
            if raw != want {
                bad += 1;
            }
            let (back, n) = binary::Varint(enc.clone());
            if back != v || n != want.len() as int {
                bad += 1;
            }
            let mut buf = slice::<byte>::__from_vec(alloc::vec![0u8; 16]);
            let m = binary::PutVarint(&mut buf, v);
            let br: &[byte] = &buf;
            if m != want.len() as int || &br[..want.len()] != want {
                bad += 1;
            }
            k += 1;
        }
        if bad == 0 {
            fmt::Println!("[14] Varint zig-zag vs Go     PASS");
        } else {
            fmt::Println!("[14] Varint zig-zag vs Go     FAIL");
            failed += 1;
        }
    }

    // 15. The two decode overflow rules. A tenth byte greater than 1
    //     overflows even though it terminates the encoding, and an
    //     eleventh byte is never read at all (golang.org/issue/41185)
    //     — the guard returns -11 rather than reading past the longest
    //     legal encoding.
    {
        let cases: [(&[u8], uint, int, int, int); 5] = [
            (b"", 0, 0, 0, 0),
            (b"\x80", 0, 0, 0, 0),
            (b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\x02", 0, -10, 0, -10),
            (
                b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01",
                u64::MAX,
                10,
                i64::MIN,
                10,
            ),
            (
                b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01",
                0,
                -11,
                0,
                -11,
            ),
        ];
        let mut bad = 0;
        let mut k: usize = 0;
        while k < cases.len() {
            let (input, wu, wun, ws, wsn) = cases[k];
            let b = slice::<byte>::__from_vec(input.to_vec());
            let (u, un) = binary::Uvarint(b.clone());
            let (sv, sn) = binary::Varint(b);
            if u != wu || un != wun || sv != ws || sn != wsn {
                bad += 1;
            }
            k += 1;
        }
        if bad == 0 {
            fmt::Println!("[15] decode overflow vs Go    PASS");
        } else {
            fmt::Println!("[15] decode overflow vs Go    FAIL");
            failed += 1;
        }
    }

    // 16. ReadUvarint / ReadVarint error shapes. EOF only if nothing
    //     was read; an EOF part-way through becomes ErrUnexpectedEOF.
    {
        fn read_u(input: &[u8]) -> (uint, goish::string) {
            let mut r = bytes::NewReader(slice::<byte>::__from_vec(input.to_vec()));
            let (v, err) = binary::ReadUvarint(&mut r);
            if err == goish::nil {
                return (v, goish::string::from("<nil>"));
            }
            return (v, err.Error());
        }
        let overflow = "binary: varint overflows a 64-bit integer";
        let mut ok = read_u(b"") == (0, goish::string::from("EOF"));
        ok = ok && read_u(b"\x00") == (0, goish::string::from("<nil>"));
        ok = ok && read_u(b"\x80") == (0, goish::string::from("unexpected EOF"));
        ok = ok && read_u(b"\xac\x02") == (300, goish::string::from("<nil>"));
        ok = ok
            && read_u(b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01")
                == (u64::MAX, goish::string::from("<nil>"));
        ok = ok
            && read_u(b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\x02")
                == (i64::MAX as uint, goish::string::from(overflow));
        ok = ok
            && read_u(b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01")
                == (u64::MAX, goish::string::from(overflow));

        let mut r = bytes::NewReader(slice::<byte>::__from_vec(alloc::vec![0xac, 0x02]));
        let (sv, serr) = binary::ReadVarint(&mut r);
        ok = ok && sv == 150 && serr == goish::nil;
        let mut r2 = bytes::NewReader(slice::<byte>::__from_vec(alloc::vec![0x80]));
        let (sv2, serr2) = binary::ReadVarint(&mut r2);
        ok = ok && sv2 == 0 && serr2.Error() == "unexpected EOF";

        if ok {
            fmt::Println!("[16] Read*varint vs Go        PASS");
        } else {
            fmt::Println!("[16] Read*varint vs Go        FAIL");
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
