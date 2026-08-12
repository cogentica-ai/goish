// crypto/rand + crypto/internal/sysrand + internal/syscall/unix smoke.
//
// Randomness cannot be diffed against Go byte-for-byte, so this checks
// the properties that matter:
//
//   * getrandom(2) fills exactly what was asked for, at every size and
//     at the buffer boundaries (no over- or under-run of a guarded buf);
//   * successive reads differ, and the bytes are not all-zero;
//   * `rand.Reader` is a real io.Reader (io.ReadFull drives it);
//   * `rand.Text` is 26 chars drawn only from the RFC 4648 base32
//     alphabet, and two calls differ;
//   * `rand.Int` is exercised against a DETERMINISTIC reader, so its
//     output IS comparable to Go. The expected values come from
//     `scripts/goref.sh crypto/rand` running the same ramp reader:
//
//         Int(max=1)     = 0
//         Int(max=2)     = 1
//         Int(max=255)   = 1
//         Int(max=256)   = 1
//         Int(max=65537) = 1286
//         Int(max=123456789012345678901234567890)
//                        = 79850778293499848189627010061
//
//   * `rand.Prime(rand, 64)` returns a 64-bit probable prime.

#![no_std]
#![no_main]
#![allow(non_camel_case_types)]

extern crate alloc;

use goish::crypto::internal::sysrand;
use goish::crypto::rand;
use goish::fmt::Stringer;
use goish::internal::syscall::unix;
use goish::io;
use goish::math::big;
use goish::{byte, error, int, slice, syscall};

static mut PASS: i32 = 0;
static mut TOTAL: i32 = 0;

fn write(fd: i32, msg: &[u8]) {
    syscall::Write(fd, msg.as_ptr(), msg.len());
}

fn check(cond: bool, name: &[u8]) {
    unsafe {
        TOTAL += 1;
        if cond {
            PASS += 1;
            write(syscall::STDOUT, b"PASS ");
        } else {
            write(syscall::STDERR, b"FAIL ");
        }
    }
    write(syscall::STDOUT, name);
    write(syscall::STDOUT, b"\n");
}

fn write_i32(n: i32) {
    let mut buf = [0u8; 12];
    let mut i = buf.len();
    if n == 0 {
        write(syscall::STDOUT, b"0");
        return;
    }
    let mut un: u32 = n as u32;
    while un > 0 {
        i -= 1;
        buf[i] = b'0' + (un % 10) as u8;
        un /= 10;
    }
    write(syscall::STDOUT, &buf[i..]);
}

fn report() -> ! {
    let (p, t) = unsafe { (PASS, TOTAL) };
    write(syscall::STDOUT, b"ok ");
    write_i32(p);
    write(syscall::STDOUT, b"/");
    write_i32(t);
    write(syscall::STDOUT, b"\n");
    syscall::Exit(if p == t { 0 } else { 1 });
}

// A deterministic io.Reader emitting an incrementing byte ramp — the
// same shape the Go reference file used, so rand::Int's output matches.
struct byteReader {
    b: u8,
}

impl io::Reader for byteReader {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        let n = p.Len();
        let raw: &mut [byte] = p;
        let mut i: usize = 0;
        while i < raw.len() {
            raw[i] = self.b;
            self.b = self.b.wrapping_add(1);
            i += 1;
        }
        (n, goish::nil.into())
    }
}

fn all_zero(b: &slice<byte>) -> bool {
    let raw: &[byte] = b;
    let mut i: usize = 0;
    while i < raw.len() {
        if raw[i] != 0 {
            return false;
        }
        i += 1;
    }
    true
}

fn differs(a: &slice<byte>, b: &slice<byte>) -> bool {
    let x: &[byte] = a;
    let y: &[byte] = b;
    if x.len() != y.len() {
        return true;
    }
    let mut i: usize = 0;
    while i < x.len() {
        if x[i] != y[i] {
            return true;
        }
        i += 1;
    }
    false
}

fn dec_eq(z: &big::Int, want: &[u8]) -> bool {
    z.String().as_bytes() == want
}

fn int_from_dec(s: &'static str) -> big::Int {
    let mut z = big::Int::new();
    z.SetString(s, 10);
    z
}

// rand::Int against the deterministic ramp reader — compare with Go.
fn check_int(max_dec: &'static str, want: &[u8], name: &[u8]) {
    let max = int_from_dec(max_dec);
    let mut r = byteReader { b: 1 };
    let (n, err) = rand::Int(&mut r, &max);
    check(err.IsNil() && dec_eq(&n, want), name);
}

#[goish::main]
fn main() {
    // ─── 1. rand::Read fills every size exactly ──────────────────────
    let sizes: [usize; 7] = [0, 1, 7, 32, 64, 256, 4096];
    let mut i: usize = 0;
    let mut ok_len = true;
    let mut ok_err = true;
    while i < sizes.len() {
        let mut b = goish::make!([]byte, sizes[i] as int);
        let (n, err) = rand::Read(&mut b);
        if n != sizes[i] as int {
            ok_len = false;
        }
        if !err.IsNil() {
            ok_err = false;
        }
        i += 1;
    }
    check(ok_len, b"rand::Read returns len(b) at every size");
    check(ok_err, b"rand::Read never returns an error");

    // ─── 2. Reads are not zero and differ from each other ────────────
    let mut a = goish::make!([]byte, 32);
    let mut c = goish::make!([]byte, 32);
    let _ = rand::Read(&mut a);
    let _ = rand::Read(&mut c);
    check(!all_zero(&a), b"rand::Read produces non-zero bytes");
    check(differs(&a, &c), b"successive rand::Read calls differ");

    // ─── 3. Buffer boundary — Read never resizes what it was given ───
    // goish slices are owned, so an over- or under-run of the caller's
    // buffer would show up as a changed length or a short count.
    let mut g = goish::make!([]byte, 32);
    let before = g.Len();
    let (gn, _) = rand::Read(&mut g);
    check(
        g.Len() == before && gn == before,
        b"rand::Read leaves len(b) unchanged",
    );

    // ─── 4. sysrand::Read — the layer underneath ─────────────────────
    let mut s1 = goish::make!([]byte, 48);
    let mut s2 = goish::make!([]byte, 48);
    sysrand::Read(&mut s1);
    sysrand::Read(&mut s2);
    check(!all_zero(&s1), b"sysrand::Read produces non-zero bytes");
    check(differs(&s1, &s2), b"successive sysrand::Read calls differ");

    // ─── 5. unix::GetRandom — the raw getrandom(2) wrapper ───────────
    let mut u1 = goish::make!([]byte, 64);
    let (un, uerr) = unix::GetRandom(&mut u1, 0);
    check(
        uerr.IsNil() && un == 64,
        b"unix::GetRandom fills the whole buffer",
    );
    check(!all_zero(&u1), b"unix::GetRandom produces non-zero bytes");
    let mut u2 = goish::make!([]byte, 64);
    let (un2, uerr2) = unix::GetRandom(&mut u2, unix::GRND_NONBLOCK);
    check(
        uerr2.IsNil() && un2 == 64,
        b"unix::GetRandom honours GRND_NONBLOCK",
    );

    // ─── 6. rand::Reader is a real io.Reader ─────────────────────────
    let mut rdr = rand::Reader;
    let mut rb = goish::make!([]byte, 100);
    let (rn, rerr) = io::ReadFull(&mut rdr, &mut rb);
    check(
        rerr.IsNil() && rn == 100 && !all_zero(&rb),
        b"io::ReadFull(rand::Reader, buf) fills the buffer",
    );

    // ─── 7. rand::Text ───────────────────────────────────────────────
    let t1 = rand::Text();
    let t2 = rand::Text();
    check(t1.Len() == 26, b"rand::Text returns 26 chars");
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let tb = t1.as_bytes();
    let mut in_alphabet = true;
    let mut k: usize = 0;
    while k < tb.len() {
        let mut found = false;
        let mut j: usize = 0;
        while j < ALPHABET.len() {
            if ALPHABET[j] == tb[k] {
                found = true;
            }
            j += 1;
        }
        if !found {
            in_alphabet = false;
        }
        k += 1;
    }
    check(in_alphabet, b"rand::Text uses only the base32 alphabet");
    check(
        t1.as_bytes() != t2.as_bytes(),
        b"successive rand::Text calls differ",
    );

    // ─── 8. rand::Int vs Go (deterministic reader) ───────────────────
    check_int("1", b"0", b"rand::Int(max=1) matches Go");
    check_int("2", b"1", b"rand::Int(max=2) matches Go");
    check_int("255", b"1", b"rand::Int(max=255) matches Go");
    check_int("256", b"1", b"rand::Int(max=256) matches Go");
    check_int("65537", b"1286", b"rand::Int(max=65537) matches Go");
    check_int(
        "123456789012345678901234567890",
        b"79850778293499848189627010061",
        b"rand::Int(max=1.23e29) matches Go",
    );

    // ─── 9. rand::Int stays in range against real entropy ────────────
    let bound = int_from_dec("1000003");
    let mut inrange = true;
    let mut m: usize = 0;
    while m < 64 {
        let mut rr = rand::Reader;
        let (v, e) = rand::Int(&mut rr, &bound);
        if !e.IsNil() || v.Sign() < 0 || v.Cmp(&bound) >= 0 {
            inrange = false;
        }
        m += 1;
    }
    check(inrange, b"rand::Int stays in [0, max) over 64 draws");

    // ─── 10. rand::Prime ─────────────────────────────────────────────
    let mut pr = rand::Reader;
    let (p, perr) = rand::Prime(&mut pr, 64);
    check(
        perr.IsNil() && p.BitLen() == 64 && p.ProbablyPrime(20),
        b"rand::Prime(64) is a 64-bit probable prime",
    );
    let mut pr2 = rand::Reader;
    let (_, perr2) = rand::Prime(&mut pr2, 1);
    check(!perr2.IsNil(), b"rand::Prime rejects bits < 2");

    report();
}
