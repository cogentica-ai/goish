// maphash_smoke — exercise hash/maphash.
// (hash/maphash/maphash.go + hash/maphash/maphash_purego.go)
//
// Properties tested (no fixed reference vectors — the hash is keyed by
// a per-process random hashkey, so cross-run agreement isn't possible):
//   - Same seed + same input ⇒ same hash
//   - Different seeds ⇒ very likely different hashes
//   - Bytes / String / Hash agree for ASCII inputs
//   - Hash incremental Write equals one-shot Bytes
//   - Reset preserves seed; SetSeed wipes pending bytes
//   - Sum/Size/BlockSize match contract

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::convert::{bytes as to_bytes, string as to_string};
use goish::goslice::slice;
use goish::hash::maphash;
use goish::hash::Hash;
use goish::io::Writer as _;
use goish::types::byte;
use goish::{syscall, Println};

fn empty_buf() -> slice<byte> {
    slice::<byte>::__from_vec(Vec::new())
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. MakeSeed produces non-zero seed.
    {
        let s1 = maphash::MakeSeed();
        let s2 = maphash::MakeSeed();
        // Two random seeds should be different (negligible chance equal).
        // We can't access the inner u64 directly; check via Bytes hash
        // of an empty input.
        let h1 = maphash::Bytes(s1, empty_buf());
        let h2 = maphash::Bytes(s2, empty_buf());
        if h1 != 0 && h2 != 0 && h1 != h2 {
            Println!("[ 1] MakeSeed distinct          PASS");
        } else {
            Println!("[ 1] MakeSeed distinct          FAIL");
            failed += 1;
        }
    }

    // 2. Bytes is deterministic for the same seed.
    {
        let s = maphash::MakeSeed();
        let h1 = maphash::Bytes(s, to_bytes("hello world"));
        let h2 = maphash::Bytes(s, to_bytes("hello world"));
        if h1 == h2 {
            Println!("[ 2] Bytes deterministic        PASS");
        } else {
            Println!("[ 2] Bytes deterministic        FAIL");
            failed += 1;
        }
    }

    // 3. Bytes differs across seeds (very likely).
    {
        let s1 = maphash::MakeSeed();
        let s2 = maphash::MakeSeed();
        let h1 = maphash::Bytes(s1, to_bytes("hello world"));
        let h2 = maphash::Bytes(s2, to_bytes("hello world"));
        if h1 != h2 {
            Println!("[ 3] Bytes seed-sensitive       PASS");
        } else {
            Println!("[ 3] Bytes seed-sensitive       FAIL");
            failed += 1;
        }
    }

    // 4. String == Bytes for the same input (UTF-8 byte sequence).
    {
        let s = maphash::MakeSeed();
        let h1 = maphash::Bytes(s, to_bytes("foobar"));
        let h2 = maphash::String(s, to_string("foobar"));
        if h1 == h2 {
            Println!("[ 4] String == Bytes            PASS");
        } else {
            Println!("[ 4] String == Bytes            FAIL");
            failed += 1;
        }
    }

    // 5. Bytes differs for different inputs (same seed).
    {
        let s = maphash::MakeSeed();
        let h1 = maphash::Bytes(s, to_bytes("foo"));
        let h2 = maphash::Bytes(s, to_bytes("bar"));
        if h1 != h2 {
            Println!("[ 5] Bytes input-sensitive      PASS");
        } else {
            Println!("[ 5] Bytes input-sensitive      FAIL");
            failed += 1;
        }
    }

    // 6. Empty input — Bytes(seed, "") returns the seeded state.
    {
        let s = maphash::MakeSeed();
        let h_empty1 = maphash::Bytes(s, empty_buf());
        let h_empty2 = maphash::Bytes(s, empty_buf());
        if h_empty1 == h_empty2 && h_empty1 != 0 {
            Println!("[ 6] Bytes empty stable         PASS");
        } else {
            Println!("[ 6] Bytes empty stable         FAIL");
            failed += 1;
        }
    }

    // 7. Hash.Sum64 — incremental Write equals one-shot Bytes.
    {
        let s = maphash::MakeSeed();
        let want = maphash::Bytes(s, to_bytes("abcdef"));
        let mut h = maphash::Hash::new();
        h.SetSeed(s);
        let _ = h.Write(to_bytes("abc"));
        let _ = h.Write(to_bytes("def"));
        let got = h.Sum64();
        if want == got {
            Println!("[ 7] Hash incremental == Bytes  PASS");
        } else {
            Println!("[ 7] Hash incremental == Bytes  FAIL");
            failed += 1;
        }
    }

    // 8. Hash.WriteString equals Hash.Write for ASCII content.
    {
        let s = maphash::MakeSeed();
        let mut h1 = maphash::Hash::new();
        h1.SetSeed(s);
        let _ = h1.Write(to_bytes("xyzzy"));
        let v1 = h1.Sum64();

        let mut h2 = maphash::Hash::new();
        h2.SetSeed(s);
        let _ = h2.WriteString(to_string("xyzzy"));
        let v2 = h2.Sum64();
        if v1 == v2 {
            Println!("[ 8] WriteString == Write       PASS");
        } else {
            Println!("[ 8] WriteString == Write       FAIL");
            failed += 1;
        }
    }

    // 9. Reset preserves seed; resetting after writes returns to seed-only.
    {
        let s = maphash::MakeSeed();
        let mut h = maphash::Hash::new();
        h.SetSeed(s);
        let baseline = h.Sum64();
        let _ = h.Write(to_bytes("garbage"));
        h.Reset();
        let after = h.Sum64();
        if baseline == after {
            Println!("[ 9] Reset preserves seed       PASS");
        } else {
            Println!("[ 9] Reset preserves seed       FAIL");
            failed += 1;
        }
    }

    // 10. SetSeed clears pending bytes.
    {
        let s = maphash::MakeSeed();
        let mut h = maphash::Hash::new();
        h.SetSeed(s);
        let _ = h.Write(to_bytes("garbage"));
        h.SetSeed(s);
        let v = h.Sum64();
        let want = maphash::Bytes(s, empty_buf());
        if v == want {
            Println!("[10] SetSeed clears buffer      PASS");
        } else {
            Println!("[10] SetSeed clears buffer      FAIL");
            failed += 1;
        }
    }

    // 11. Long input (>bufSize=128) — multi-flush path.
    {
        let s = maphash::MakeSeed();
        let mut v: Vec<byte> = Vec::with_capacity(500);
        let mut i = 0;
        while i < 500 {
            v.push(b'A' + ((i % 26) as byte));
            i += 1;
        }
        let buf = slice::<byte>::__from_vec(v);
        let one = maphash::Bytes(s, buf.clone());

        let mut h = maphash::Hash::new();
        h.SetSeed(s);
        let _ = h.Write(buf);
        let stream = h.Sum64();

        if one == stream {
            Println!("[11] >bufSize multi-flush       PASS");
        } else {
            Println!("[11] >bufSize multi-flush       FAIL");
            failed += 1;
        }
    }

    // 12. WriteByte equals single-byte Write.
    {
        let s = maphash::MakeSeed();
        let mut h1 = maphash::Hash::new();
        h1.SetSeed(s);
        let _ = h1.WriteByte(b'A');
        let _ = h1.WriteByte(b'B');
        let _ = h1.WriteByte(b'C');
        let v1 = h1.Sum64();

        let mut h2 = maphash::Hash::new();
        h2.SetSeed(s);
        let _ = h2.Write(to_bytes("ABC"));
        let v2 = h2.Sum64();

        if v1 == v2 {
            Println!("[12] WriteByte == Write byte    PASS");
        } else {
            Println!("[12] WriteByte == Write byte    FAIL");
            failed += 1;
        }
    }

    // 13. Size + BlockSize.
    {
        let h = maphash::Hash::new();
        if h.Size() == 8 && h.BlockSize() == 128 {
            Println!("[13] Size/BlockSize             PASS");
        } else {
            Println!("[13] Size/BlockSize             FAIL");
            failed += 1;
        }
    }

    // 14. Sum appends 8 bytes (LE u64 of Sum64).
    {
        let s = maphash::MakeSeed();
        let mut h = maphash::Hash::new();
        h.SetSeed(s);
        let _ = h.Write(to_bytes("data"));
        let v = h.Sum64();
        let out = h.Sum(empty_buf());
        let raw: &[byte] = &out;
        let recovered = (raw[0] as u64)
            | ((raw[1] as u64) << 8)
            | ((raw[2] as u64) << 16)
            | ((raw[3] as u64) << 24)
            | ((raw[4] as u64) << 32)
            | ((raw[5] as u64) << 40)
            | ((raw[6] as u64) << 48)
            | ((raw[7] as u64) << 56);
        if raw.len() == 8 && recovered == v {
            Println!("[14] Sum -> LE u64              PASS");
        } else {
            Println!("[14] Sum -> LE u64              FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 14/14");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 14");
        syscall::Exit(1);
    }
}
