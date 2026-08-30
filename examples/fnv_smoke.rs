// fnv_smoke — exercise hash/fnv FNV-1 + FNV-1a, all three widths.
// (hash/fnv/fnv.go)
//
// Checks 1-11 use Go 1.25's hash/fnv golden tables. Checks 12-16 use
// values printed by a running Go 1.25.5 (tools/gen_fnv_ref.go, run
// through scripts/goref.sh): the 128-bit pair, whose hand-rolled
// bits.Mul64 arithmetic has no published vector, and the
// marshal/unmarshal/Clone surface across all six digests.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::convert::bytes as to_bytes;
use goish::fmt;
use goish::goslice::slice;
use goish::hash::fnv;
use goish::hash::{Hash, Hash32, Hash64};
use goish::io::Writer as _;
use goish::nil;
use goish::syscall;
use goish::types::byte;

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

    // 1. FNV-1 32 — empty input → offset32 (2166136261).
    {
        let h = fnv::New32();
        if h.Sum32() == 2166136261 && h.Size() == 4 && h.BlockSize() == 1 {
            fmt::Println!("[ 1] New32 init                PASS");
        } else {
            fmt::Println!("[ 1] New32 init                FAIL");
            failed += 1;
        }
    }

    // 2. FNV-1a 32 — empty input → offset32 (2166136261).
    {
        let h = fnv::New32a();
        if h.Sum32() == 2166136261 {
            fmt::Println!("[ 2] New32a init               PASS");
        } else {
            fmt::Println!("[ 2] New32a init               FAIL");
            failed += 1;
        }
    }

    // 3. FNV-1 32 — Write("a") → 0x050C5D7E.
    //    fnv1: hash = offset32 * prime32 ^ 'a' = 2166136261*16777619 ^ 0x61.
    {
        let mut h = fnv::New32();
        let _ = h.Write(to_bytes("a"));
        if h.Sum32() == 0x050C5D7E {
            fmt::Println!("[ 3] FNV-1 32 \"a\"              PASS");
        } else {
            fmt::Println!("[ 3] FNV-1 32 \"a\"              FAIL");
            failed += 1;
        }
    }

    // 4. FNV-1a 32 — Write("a") → 0xE40C292C.
    //    fnv1a: hash = offset32 ^ 'a' * prime32 = (2166136261 ^ 0x61)*16777619.
    {
        let mut h = fnv::New32a();
        let _ = h.Write(to_bytes("a"));
        if h.Sum32() == 0xE40C292C {
            fmt::Println!("[ 4] FNV-1a 32 \"a\"             PASS");
        } else {
            fmt::Println!("[ 4] FNV-1a 32 \"a\"             FAIL");
            failed += 1;
        }
    }

    // 5. FNV-1 64 — Write("a") → 0xAF63BD4C8601B7BE.
    {
        let mut h = fnv::New64();
        let _ = h.Write(to_bytes("a"));
        if h.Sum64() == 0xAF63BD4C8601B7BE {
            fmt::Println!("[ 5] FNV-1 64 \"a\"              PASS");
        } else {
            fmt::Println!("[ 5] FNV-1 64 \"a\"              FAIL");
            failed += 1;
        }
    }

    // 6. FNV-1a 64 — Write("a") → 0xAF63DC4C8601EC8C.
    {
        let mut h = fnv::New64a();
        let _ = h.Write(to_bytes("a"));
        if h.Sum64() == 0xAF63DC4C8601EC8C {
            fmt::Println!("[ 6] FNV-1a 64 \"a\"             PASS");
        } else {
            fmt::Println!("[ 6] FNV-1a 64 \"a\"             FAIL");
            failed += 1;
        }
    }

    // 7. FNV-1a 32 — incremental Write equivalent to single Write.
    {
        let mut a = fnv::New32a();
        let _ = a.Write(to_bytes("foo"));
        let _ = a.Write(to_bytes("bar"));
        let mut b = fnv::New32a();
        let _ = b.Write(to_bytes("foobar"));
        if a.Sum32() == b.Sum32() {
            fmt::Println!("[ 7] FNV-1a 32 incremental     PASS");
        } else {
            fmt::Println!("[ 7] FNV-1a 32 incremental     FAIL");
            failed += 1;
        }
    }

    // 8. Reset returns hash to offset.
    {
        let mut h = fnv::New64a();
        let _ = h.Write(to_bytes("hello"));
        h.Reset();
        if h.Sum64() == 14695981039346656037 {
            fmt::Println!("[ 8] Reset → offset64           PASS");
        } else {
            fmt::Println!("[ 8] Reset → offset64           FAIL");
            failed += 1;
        }
    }

    // 9. Sum appends BE bytes — FNV-1a 32 of "a" = 0xE40C292C.
    {
        let mut h = fnv::New32a();
        let _ = h.Write(to_bytes("a"));
        let out = h.Sum(empty_buf());
        // Big-endian: E4 0C 29 2C
        let mut want_v: Vec<byte> = Vec::new();
        want_v.push(0xE4);
        want_v.push(0x0C);
        want_v.push(0x29);
        want_v.push(0x2C);
        let want = slice::<byte>::__from_vec(want_v);
        if equal_bytes(out, want) {
            fmt::Println!("[ 9] Sum32a BE append          PASS");
        } else {
            fmt::Println!("[ 9] Sum32a BE append          FAIL");
            failed += 1;
        }
    }

    // 10. Sum preserves dst prefix (in[0..]; appended after).
    {
        let mut h = fnv::New32();
        let _ = h.Write(to_bytes("a"));
        // FNV-1 of "a" = 0x050C5D7E → BE = 05 0C 5D 7E.
        let dst = to_bytes("PREFIX:");
        let out = h.Sum(dst);
        let raw: &[byte] = &out;
        // Expect: "PREFIX:" + 4 BE bytes.
        if raw.len() == 7 + 4
            && &raw[0..7] == b"PREFIX:"
            && raw[7] == 0x05
            && raw[8] == 0x0C
            && raw[9] == 0x5D
            && raw[10] == 0x7E
        {
            fmt::Println!("[10] Sum prefix                PASS");
        } else {
            fmt::Println!("[10] Sum prefix                FAIL");
            failed += 1;
        }
    }

    // 11. Size + BlockSize for all 4 variants.
    {
        let h32 = fnv::New32();
        let h32a = fnv::New32a();
        let h64 = fnv::New64();
        let h64a = fnv::New64a();
        if h32.Size() == 4
            && h32a.Size() == 4
            && h64.Size() == 8
            && h64a.Size() == 8
            && h32.BlockSize() == 1
            && h64a.BlockSize() == 1
        {
            fmt::Println!("[11] Size/BlockSize            PASS");
        } else {
            fmt::Println!("[11] Size/BlockSize            FAIL");
            failed += 1;
        }
    }

    // 12. The 128-bit pair against Go, over six inputs. Nothing else
    //     exercises the shifted partial products in Write.
    {
        let cases: [(&str, &[u8], &[u8]); 6] = [
            (
                "",
                b"6c62272e07bb014262b821756295c58d",
                b"6c62272e07bb014262b821756295c58d",
            ),
            (
                "a",
                b"d228cb69101a8caf78912b704e4a141e",
                b"d228cb696f1a8caf78912b704e4a8964",
            ),
            (
                "ab",
                b"0880945aeeab1be95aa073305526c088",
                b"08809544bbab1be95aa0733055b69a62",
            ),
            (
                "abc",
                b"a68bb2a4348b5822836dbc78c6aee73b",
                b"a68d622cec8b5822836dbc7977af7f3b",
            ),
            (
                "hello world",
                b"e1b1650f0631aef5566634b6c074ac1f",
                b"6c155799fdc8eec4b91523808e7726b7",
            ),
            (
                "The quick brown fox jumps over the lazy dog",
                b"185adb693e7c97844ecfa9497cb529b6",
                b"68cce4cd885ea04239f02af30e297870",
            ),
        ];
        let mut bad = 0;
        let mut k: usize = 0;
        while k < cases.len() {
            let (input, w1, w1a) = cases[k];
            let mut h = fnv::New128();
            let _ = h.Write(to_bytes(input));
            if !equal_bytes(h.Sum(empty_buf()), from_hex(w1)) {
                bad += 1;
            }
            let mut ha = fnv::New128a();
            let _ = ha.Write(to_bytes(input));
            if !equal_bytes(ha.Sum(empty_buf()), from_hex(w1a)) {
                bad += 1;
            }
            k += 1;
        }
        if bad == 0 {
            fmt::Println!("[12] 128-bit vs Go             PASS");
        } else {
            fmt::Println!("[12] 128-bit vs Go             FAIL");
            failed += 1;
        }
    }

    // 13. MarshalBinary emits the exact state Go emits, for all six.
    //     Each digest has its own magic byte, which is what makes a
    //     state from one type unreadable by another.
    {
        let mut h32 = fnv::New32();
        let mut h32a = fnv::New32a();
        let mut h64 = fnv::New64();
        let mut h64a = fnv::New64a();
        let mut h128 = fnv::New128();
        let mut h128a = fnv::New128a();
        let _ = h32.Write(to_bytes("hello world"));
        let _ = h32a.Write(to_bytes("hello world"));
        let _ = h64.Write(to_bytes("hello world"));
        let _ = h64a.Write(to_bytes("hello world"));
        let _ = h128.Write(to_bytes("hello world"));
        let _ = h128a.Write(to_bytes("hello world"));
        let (s32, e32) = h32.MarshalBinary();
        let (s32a, _) = h32a.MarshalBinary();
        let (s64, _) = h64.MarshalBinary();
        let (s64a, _) = h64a.MarshalBinary();
        let (s128, _) = h128.MarshalBinary();
        let (s128a, _) = h128a.MarshalBinary();
        if e32 == nil
            && equal_bytes(s32, from_hex(b"666e7601548da96f"))
            && equal_bytes(s32a, from_hex(b"666e7602d58b3fa7"))
            && equal_bytes(s64, from_hex(b"666e76037dcf62cdb1910e6f"))
            && equal_bytes(s64a, from_hex(b"666e7604779a65e7023cd2e7"))
            && equal_bytes(s128, from_hex(b"666e7605e1b1650f0631aef5566634b6c074ac1f"))
            && equal_bytes(s128a, from_hex(b"666e76066c155799fdc8eec4b91523808e7726b7"))
        {
            fmt::Println!("[13] MarshalBinary vs Go       PASS");
        } else {
            fmt::Println!("[13] MarshalBinary vs Go       FAIL");
            failed += 1;
        }
    }

    // 14. UnmarshalBinary resumes a 128-bit digest mid-stream.
    {
        let mut h = fnv::New128a();
        let _ = h.Write(to_bytes("hello world"));
        let (st, _) = h.MarshalBinary();
        let mut h2 = fnv::New128a();
        let err = h2.UnmarshalBinary(st);
        let _ = h2.Write(to_bytes("!!"));
        let _ = h.Write(to_bytes("!!"));
        let want = from_hex(b"3ac85ea4b30a175d924d8f33448afa41");
        if err == nil
            && equal_bytes(h2.Sum(empty_buf()), want.clone())
            && equal_bytes(h.Sum(empty_buf()), want)
        {
            fmt::Println!("[14] UnmarshalBinary resume    PASS");
        } else {
            fmt::Println!("[14] UnmarshalBinary resume    FAIL");
            failed += 1;
        }
    }

    // 15. A corrupt magic, a wrong length, and — the one that matters —
    //     a 32-bit state fed to a 64-bit digest, which the per-type
    //     magic byte is there to catch.
    {
        let mut h = fnv::New128a();
        let _ = h.Write(to_bytes("hello world"));
        let (st, _) = h.MarshalBinary();
        let raw: &[byte] = &st;

        let mut badv: Vec<byte> = raw.to_vec();
        badv[3] = 0x09;
        let mut h3 = fnv::New128a();
        let bad_magic = h3.UnmarshalBinary(slice::<byte>::__from_vec(badv));
        let short = slice::<byte>::__from_vec(raw[..19].to_vec());
        let bad_size = h3.UnmarshalBinary(short);

        let mut h32 = fnv::New32();
        let _ = h32.Write(to_bytes("x"));
        let (st32, _) = h32.MarshalBinary();
        let mut h64 = fnv::New64();
        let cross = h64.UnmarshalBinary(st32);

        if bad_magic.Error() == "hash/fnv: invalid hash state identifier"
            && bad_size.Error() == "hash/fnv: invalid hash state size"
            && cross.Error() == "hash/fnv: invalid hash state identifier"
        {
            fmt::Println!("[15] Unmarshal rejections      PASS");
        } else {
            fmt::Println!("[15] Unmarshal rejections      FAIL");
            failed += 1;
        }
    }

    // 16. Clone snapshots the state on every one of the six digests.
    {
        let mut bad = 0;
        {
            let mut h = fnv::New32();
            let _ = h.Write(to_bytes("abc"));
            let (c, _) = h.Clone();
            let _ = h.Write(to_bytes("def"));
            if !equal_bytes(c.Sum(empty_buf()), from_hex(b"439c2f4b"))
                || !equal_bytes(h.Sum(empty_buf()), from_hex(b"9f2d4718"))
            {
                bad += 1;
            }
        }
        {
            let mut h = fnv::New32a();
            let _ = h.Write(to_bytes("abc"));
            let (c, _) = h.Clone();
            let _ = h.Write(to_bytes("def"));
            if !equal_bytes(c.Sum(empty_buf()), from_hex(b"1a47e90b"))
                || !equal_bytes(h.Sum(empty_buf()), from_hex(b"ff478a2a"))
            {
                bad += 1;
            }
        }
        {
            let mut h = fnv::New64();
            let _ = h.Write(to_bytes("abc"));
            let (c, _) = h.Clone();
            let _ = h.Write(to_bytes("def"));
            if !equal_bytes(c.Sum(empty_buf()), from_hex(b"d8dcca186bafadcb"))
                || !equal_bytes(h.Sum(empty_buf()), from_hex(b"24021f6539ec0bd8"))
            {
                bad += 1;
            }
        }
        {
            let mut h = fnv::New64a();
            let _ = h.Write(to_bytes("abc"));
            let (c, _) = h.Clone();
            let _ = h.Write(to_bytes("def"));
            if !equal_bytes(c.Sum(empty_buf()), from_hex(b"e71fa2190541574b"))
                || !equal_bytes(h.Sum(empty_buf()), from_hex(b"d80bda3fbe244a0a"))
            {
                bad += 1;
            }
        }
        {
            let mut h = fnv::New128();
            let _ = h.Write(to_bytes("abc"));
            let (c, _) = h.Clone();
            let _ = h.Write(to_bytes("def"));
            if !equal_bytes(
                c.Sum(empty_buf()),
                from_hex(b"a68bb2a4348b5822836dbc78c6aee73b"),
            ) || !equal_bytes(
                h.Sum(empty_buf()),
                from_hex(b"afb5bcd65d3c64bf6dc590c1de235dc8"),
            ) {
                bad += 1;
            }
        }
        {
            let mut h = fnv::New128a();
            let _ = h.Write(to_bytes("abc"));
            let (c, _) = h.Clone();
            let _ = h.Write(to_bytes("def"));
            if !equal_bytes(
                c.Sum(empty_buf()),
                from_hex(b"a68d622cec8b5822836dbc7977af7f3b"),
            ) || !equal_bytes(
                h.Sum(empty_buf()),
                from_hex(b"9aec6a14f63c64bf6f0f51e89fe4db02"),
            ) {
                bad += 1;
            }
        }
        if bad == 0 {
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
