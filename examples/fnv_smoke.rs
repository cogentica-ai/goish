// fnv_smoke — exercise hash/fnv FNV-1 + FNV-1a (32-bit + 64-bit).
// (hash/fnv/fnv.go:44, 51, 58, 65)
//
// Reference values verified against Go 1.25's hash/fnv test vectors
// (see hash/fnv/fnv_test.go and golden tables there).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::convert::bytes as to_bytes;
use goish::goslice::slice;
use goish::hash::fnv;
use goish::hash::{Hash, Hash32, Hash64};
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

    // 1. FNV-1 32 — empty input → offset32 (2166136261).
    {
        let h = fnv::New32();
        if h.Sum32() == 2166136261 && h.Size() == 4 && h.BlockSize() == 1 {
            Println!("[ 1] New32 init                PASS");
        } else {
            Println!("[ 1] New32 init                FAIL");
            failed += 1;
        }
    }

    // 2. FNV-1a 32 — empty input → offset32 (2166136261).
    {
        let h = fnv::New32a();
        if h.Sum32() == 2166136261 {
            Println!("[ 2] New32a init               PASS");
        } else {
            Println!("[ 2] New32a init               FAIL");
            failed += 1;
        }
    }

    // 3. FNV-1 32 — Write("a") → 0x050C5D7E.
    //    fnv1: hash = offset32 * prime32 ^ 'a' = 2166136261*16777619 ^ 0x61.
    {
        let mut h = fnv::New32();
        let _ = h.Write(to_bytes("a"));
        if h.Sum32() == 0x050C5D7E {
            Println!("[ 3] FNV-1 32 \"a\"              PASS");
        } else {
            Println!("[ 3] FNV-1 32 \"a\"              FAIL");
            failed += 1;
        }
    }

    // 4. FNV-1a 32 — Write("a") → 0xE40C292C.
    //    fnv1a: hash = offset32 ^ 'a' * prime32 = (2166136261 ^ 0x61)*16777619.
    {
        let mut h = fnv::New32a();
        let _ = h.Write(to_bytes("a"));
        if h.Sum32() == 0xE40C292C {
            Println!("[ 4] FNV-1a 32 \"a\"             PASS");
        } else {
            Println!("[ 4] FNV-1a 32 \"a\"             FAIL");
            failed += 1;
        }
    }

    // 5. FNV-1 64 — Write("a") → 0xAF63BD4C8601B7BE.
    {
        let mut h = fnv::New64();
        let _ = h.Write(to_bytes("a"));
        if h.Sum64() == 0xAF63BD4C8601B7BE {
            Println!("[ 5] FNV-1 64 \"a\"              PASS");
        } else {
            Println!("[ 5] FNV-1 64 \"a\"              FAIL");
            failed += 1;
        }
    }

    // 6. FNV-1a 64 — Write("a") → 0xAF63DC4C8601EC8C.
    {
        let mut h = fnv::New64a();
        let _ = h.Write(to_bytes("a"));
        if h.Sum64() == 0xAF63DC4C8601EC8C {
            Println!("[ 6] FNV-1a 64 \"a\"             PASS");
        } else {
            Println!("[ 6] FNV-1a 64 \"a\"             FAIL");
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
            Println!("[ 7] FNV-1a 32 incremental     PASS");
        } else {
            Println!("[ 7] FNV-1a 32 incremental     FAIL");
            failed += 1;
        }
    }

    // 8. Reset returns hash to offset.
    {
        let mut h = fnv::New64a();
        let _ = h.Write(to_bytes("hello"));
        h.Reset();
        if h.Sum64() == 14695981039346656037 {
            Println!("[ 8] Reset → offset64           PASS");
        } else {
            Println!("[ 8] Reset → offset64           FAIL");
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
            Println!("[ 9] Sum32a BE append          PASS");
        } else {
            Println!("[ 9] Sum32a BE append          FAIL");
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
            Println!("[10] Sum prefix                PASS");
        } else {
            Println!("[10] Sum prefix                FAIL");
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
            Println!("[11] Size/BlockSize            PASS");
        } else {
            Println!("[11] Size/BlockSize            FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 11/11");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 11");
        syscall::Exit(1);
    }
}
