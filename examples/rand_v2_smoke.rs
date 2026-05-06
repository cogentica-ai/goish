// rand_v2_smoke — exercise math/rand/v2 (PCG + Rand).
// (math/rand/v2/pcg.go + rand.go)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::goslice::slice;
use goish::math::rand::v2::{self as rand, Source};
use goish::types::byte;
use goish::{syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. PCG(1, 2) Uint64 sequence — verified against Go 1.25.
    {
        let mut p = rand::NewPCG(1, 2);
        let mut r = rand::New(p);
        let want: [u64; 5] = [
            14192431797130687760,
            11371241257079532652,
            14470142590855381128,
            14694613213362438554,
            4321634407747778896,
        ];
        let mut ok = true;
        for i in 0..5 {
            let got = r.Uint64();
            if got != want[i] {
                Println!("[ 1] Uint64 seq             FAIL i={} got={} want={}", i, got, want[i]);
                ok = false;
                break;
            }
        }
        if ok {
            Println!("[ 1] Uint64 sequence         PASS");
        } else {
            failed += 1;
        }
        let _ = p;
    }

    // 2. Int64N(100) sequence — verified against Go 1.25.
    {
        let p = rand::NewPCG(1, 2);
        let mut r = rand::New(p);
        let want: [i64; 5] = [76, 61, 78, 79, 23];
        let mut ok = true;
        for i in 0..5 {
            let got = r.Int64N(100);
            if got != want[i] {
                Println!("[ 2] Int64N seq             FAIL i={} got={} want={}", i, got, want[i]);
                ok = false;
                break;
            }
        }
        if ok {
            Println!("[ 2] Int64N(100) sequence    PASS");
        } else {
            failed += 1;
        }
    }

    // 3. Same seed → same output (determinism).
    {
        let mut a = rand::New(rand::NewPCG(42, 42));
        let mut b = rand::New(rand::NewPCG(42, 42));
        let mut ok = true;
        for _ in 0..20 {
            if a.Uint64() != b.Uint64() {
                ok = false;
                break;
            }
        }
        if ok {
            Println!("[ 3] determinism             PASS");
        } else {
            Println!("[ 3] determinism             FAIL");
            failed += 1;
        }
    }

    // 4. Different seed → different output.
    {
        let mut a = rand::New(rand::NewPCG(1, 2));
        let mut b = rand::New(rand::NewPCG(3, 4));
        let mut diffs = 0;
        for _ in 0..20 {
            if a.Uint64() != b.Uint64() {
                diffs += 1;
            }
        }
        if diffs == 20 {
            Println!("[ 4] seed sensitivity        PASS");
        } else {
            Println!("[ 4] seed sensitivity        FAIL diffs={}", diffs);
            failed += 1;
        }
    }

    // 5. Int64N values in [0, n).
    {
        let mut r = rand::New(rand::NewPCG(7, 7));
        let mut ok = true;
        for _ in 0..1000 {
            let v = r.Int64N(50);
            if v < 0 || v >= 50 {
                ok = false;
                break;
            }
        }
        if ok {
            Println!("[ 5] Int64N range            PASS");
        } else {
            Println!("[ 5] Int64N range            FAIL");
            failed += 1;
        }
    }

    // 6. IntN(power-of-two) — fast path.
    {
        let mut r = rand::New(rand::NewPCG(11, 11));
        let mut ok = true;
        for _ in 0..1000 {
            let v = r.IntN(1024);
            if v < 0 || v >= 1024 {
                ok = false;
                break;
            }
        }
        if ok {
            Println!("[ 6] IntN(1024) range        PASS");
        } else {
            Println!("[ 6] IntN(1024) range        FAIL");
            failed += 1;
        }
    }

    // 7. Float64 in [0.0, 1.0).
    {
        let mut r = rand::New(rand::NewPCG(0xdeadbeef, 0xcafebabe));
        let mut ok = true;
        let mut sum = 0.0f64;
        for _ in 0..1000 {
            let v = r.Float64();
            if !(v >= 0.0 && v < 1.0) {
                ok = false;
                break;
            }
            sum += v;
        }
        let mean = sum / 1000.0;
        if ok && mean > 0.4 && mean < 0.6 {
            Println!("[ 7] Float64 range + mean    PASS");
        } else {
            Println!("[ 7] Float64 range + mean    FAIL ok={} mean={}", ok, mean);
            failed += 1;
        }
    }

    // 8. Int64() is non-negative (top bit cleared).
    {
        let mut r = rand::New(rand::NewPCG(99, 99));
        let mut ok = true;
        for _ in 0..1000 {
            let v = r.Int64();
            if v < 0 {
                ok = false;
                break;
            }
        }
        if ok {
            Println!("[ 8] Int64 non-negative      PASS");
        } else {
            Println!("[ 8] Int64 non-negative      FAIL");
            failed += 1;
        }
    }

    // 9. Seed reset: Seed(a, b) should reproduce NewPCG(a, b) sequence.
    {
        let mut p = rand::NewPCG(0, 0);
        let _ = p.Uint64(); // advance state
        let _ = p.Uint64();
        p.Seed(123, 456);
        let mut r = rand::New(p);
        let mut q = rand::NewPCG(123, 456);
        let mut s = rand::New(q);
        let mut ok = true;
        for _ in 0..10 {
            if r.Uint64() != s.Uint64() {
                ok = false;
                break;
            }
        }
        if ok {
            Println!("[ 9] Seed reset              PASS");
        } else {
            Println!("[ 9] Seed reset              FAIL");
            failed += 1;
        }
    }

    // 10. MarshalBinary round-trip via UnmarshalBinary.
    {
        let mut p = rand::NewPCG(0xa5a5a5a5, 0x5a5a5a5a);
        let _ = p.Uint64();
        let _ = p.Uint64();
        let (data, e) = p.MarshalBinary();
        if !e.IsNil() || data.len() != 20 {
            Println!("[10] MarshalBinary           FAIL e={:?} len={}", e.IsNil(), data.len());
            failed += 1;
        } else {
            // First 4 bytes should be "pcg:".
            let raw: &[byte] = &data;
            if &raw[..4] == b"pcg:" {
                let mut p2 = rand::NewPCG(0, 0);
                let e2 = p2.UnmarshalBinary(&data);
                if !e2.IsNil() {
                    Println!("[10] MarshalBinary           FAIL unmarshal err");
                    failed += 1;
                } else {
                    let next1 = p.Uint64();
                    let next2 = p2.Uint64();
                    if next1 == next2 {
                        Println!("[10] MarshalBinary RT        PASS");
                    } else {
                        Println!("[10] MarshalBinary RT        FAIL");
                        failed += 1;
                    }
                }
            } else {
                Println!("[10] MarshalBinary           FAIL bad prefix");
                failed += 1;
            }
        }
    }

    // 11. UnmarshalBinary rejects bad input.
    {
        let mut p = rand::NewPCG(0, 0);
        let bad: slice<byte> = slice::__from_vec(alloc::vec![0u8; 10]);
        let e = p.UnmarshalBinary(&bad);
        if !e.IsNil() {
            Println!("[11] UnmarshalBinary err     PASS");
        } else {
            Println!("[11] UnmarshalBinary err     FAIL");
            failed += 1;
        }
    }

    // 12. Shuffle preserves multiset.
    {
        let mut r = rand::New(rand::NewPCG(13, 17));
        let mut v: alloc::vec::Vec<i64> = (0..20).collect();
        r.Shuffle(20, |i, j| {
            v.swap(i as usize, j as usize);
        });
        let mut sorted = v.clone();
        sorted.sort();
        let want: alloc::vec::Vec<i64> = (0..20).collect();
        if sorted == want && v != want {
            Println!("[12] Shuffle                 PASS");
        } else {
            Println!("[12] Shuffle                 FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 12/12");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 12");
        syscall::Exit(1);
    }
}
