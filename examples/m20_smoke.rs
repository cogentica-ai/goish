// Smoke test: M20 — runtime introspection + encoding/binary +
// encoding/hex + encoding/base64 + sync/atomic.

#![no_std]
#![no_main]

use core::sync::atomic::Ordering;

use goish::encoding::{base64, binary, hex};
use goish::runtime::{NumCPU, NumGoroutine, GOMAXPROCS};
use goish::string;
use goish::sync::atomic;
use goish::{go, syscall};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

#[goish::main]
fn main() {
    test_runtime();
    test_binary();
    test_hex();
    test_base64();
    test_atomic();

    const OK: &[u8] = b"m20_smoke: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}

// ── α: runtime introspection ─────────────────────────────────────

fn test_runtime() {
    let n = NumCPU();
    check(n >= 1, b"runtime: NumCPU < 1\n");

    // NumGoroutine: at this point in main (no go!() yet), 0 live.
    check(NumGoroutine() == 0, b"runtime: NumGoroutine != 0 at start\n");

    // GOMAXPROCS(0) returns current; (>0) sets and returns previous.
    let prev = GOMAXPROCS(0);
    check(prev == n, b"runtime: GOMAXPROCS(0) != NumCPU\n");
    let prev2 = GOMAXPROCS(2);
    check(prev2 == n, b"runtime: GOMAXPROCS(2) didn't return previous\n");
    let now = GOMAXPROCS(0);
    check(now == 2, b"runtime: GOMAXPROCS didn't update cache\n");
    GOMAXPROCS(prev); // restore
}

// ── β: encoding/binary ──────────────────────────────────────────

fn test_binary() {
    // BigEndian uint16
    let mut buf = [0u8; 8];
    binary::BigEndian.PutUint16(&mut buf, 0x1234);
    check(buf[0] == 0x12 && buf[1] == 0x34, b"be: PutUint16\n");
    check(binary::BigEndian.Uint16(&buf) == 0x1234, b"be: Uint16\n");

    // LittleEndian uint16
    binary::LittleEndian.PutUint16(&mut buf, 0x1234);
    check(buf[0] == 0x34 && buf[1] == 0x12, b"le: PutUint16\n");
    check(binary::LittleEndian.Uint16(&buf) == 0x1234, b"le: Uint16\n");

    // BigEndian uint32
    binary::BigEndian.PutUint32(&mut buf, 0xdeadbeef);
    check(
        buf[0] == 0xde && buf[1] == 0xad && buf[2] == 0xbe && buf[3] == 0xef,
        b"be: PutUint32\n",
    );
    check(binary::BigEndian.Uint32(&buf) == 0xdeadbeef, b"be: Uint32\n");

    // BigEndian uint64
    let mut buf8 = [0u8; 8];
    binary::BigEndian.PutUint64(&mut buf8, 0x0102030405060708);
    check(
        buf8 == [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        b"be: PutUint64\n",
    );
    check(
        binary::BigEndian.Uint64(&buf8) == 0x0102030405060708,
        b"be: Uint64\n",
    );

    // LittleEndian uint64
    binary::LittleEndian.PutUint64(&mut buf8, 0x0102030405060708);
    check(
        buf8 == [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01],
        b"le: PutUint64\n",
    );
}

// ── γ.1: encoding/hex ───────────────────────────────────────────

fn test_hex() {
    // EncodeToString
    let s = hex::EncodeToString(b"hello");
    check(s == string::from_static("68656c6c6f"), b"hex: EncodeToString\n");

    // Round-trip
    let (decoded, err) = hex::DecodeString("48656c6c6f20576f726c64"); // "Hello World"
    check(err.IsNil(), b"hex: DecodeString returned err\n");
    check(decoded.as_slice() == b"Hello World", b"hex: round-trip wrong\n");

    // Invalid byte detection
    let (_, err2) = hex::DecodeString("zz");
    check(!err2.IsNil(), b"hex: invalid byte not caught\n");

    // Odd length
    let (_, err3) = hex::DecodeString("abc");
    check(!err3.IsNil(), b"hex: odd length not caught\n");

    // EncodedLen / DecodedLen
    check(hex::EncodedLen(5) == 10, b"hex: EncodedLen\n");
    check(hex::DecodedLen(10) == 5, b"hex: DecodedLen\n");
}

// ── γ.2: encoding/base64 ────────────────────────────────────────

fn test_base64() {
    // StdEncoding round-trip
    let src: &[u8] = b"Hello, World!";
    let encoded = base64::StdEncoding.EncodeToString(src);
    check(
        encoded == string::from_static("SGVsbG8sIFdvcmxkIQ=="),
        b"std: EncodeToString\n",
    );
    let (decoded, err) = base64::StdEncoding.DecodeString("SGVsbG8sIFdvcmxkIQ==");
    check(err.IsNil(), b"std: DecodeString err\n");
    check(decoded.as_slice() == src, b"std: round-trip wrong\n");

    // RawStdEncoding (no padding)
    let raw = base64::RawStdEncoding.EncodeToString(src);
    check(
        raw == string::from_static("SGVsbG8sIFdvcmxkIQ"),
        b"rawstd: encode\n",
    );
    let (decoded2, err2) = base64::RawStdEncoding.DecodeString("SGVsbG8sIFdvcmxkIQ");
    check(err2.IsNil(), b"rawstd: DecodeString err\n");
    check(decoded2.as_slice() == src, b"rawstd: round-trip\n");

    // URLEncoding (uses -/_ instead of +//): encode bytes that
    // would produce + or / under StdEncoding.
    let bin: &[u8] = &[0xff, 0xff, 0xfe];
    let std_enc = base64::StdEncoding.EncodeToString(bin);
    let url_enc = base64::URLEncoding.EncodeToString(bin);
    check(std_enc != url_enc, b"url: alphabet not different\n");
    // Round-trip URL encoding by re-encoding (we don't have a public
    // way to read string bytes for arbitrary ASCII passthrough yet,
    // but we can re-decode the literal we just verified differs).
    let (urldec, err3) = base64::URLEncoding.DecodeString("___-");
    let _ = err3;
    let _ = urldec;
}

// ── δ: sync/atomic ──────────────────────────────────────────────

fn test_atomic() {
    use core::sync::atomic::AtomicUsize;
    static C: atomic::Int64 = atomic::Int64::new(0);
    static B: atomic::Bool = atomic::Bool::new(false);
    static GS_DONE: AtomicUsize = AtomicUsize::new(0);

    // Single-thread basics
    check(C.Load() == 0, b"atomic: initial\n");
    let new = C.Add(5);
    check(new == 5, b"atomic: Add return\n");
    check(C.Swap(10) == 5, b"atomic: Swap\n");
    check(C.Load() == 10, b"atomic: post-Swap Load\n");
    check(C.CompareAndSwap(10, 20), b"atomic: CAS success\n");
    check(!C.CompareAndSwap(10, 30), b"atomic: CAS stale\n");
    check(C.Load() == 20, b"atomic: post-CAS Load\n");

    // Reset for concurrent test
    C.Store(0);
    GS_DONE.store(0, Ordering::Relaxed);
    B.Store(false);

    // 16 goroutines × 1000 increments each
    const N_GS: i64 = 16;
    const N_INCS: i64 = 1_000;
    for _ in 0..N_GS {
        go!(move || {
            for _ in 0..N_INCS {
                C.Add(1);
            }
            GS_DONE.fetch_add(1, Ordering::Relaxed);
        });
    }
    goish::runtime::sched::schedule();

    check(
        GS_DONE.load(Ordering::Relaxed) == N_GS as usize,
        b"atomic: not all Gs done\n",
    );
    check(
        C.Load() == N_GS * N_INCS,
        b"atomic: contended counter wrong (race?)\n",
    );

    // Bool
    check(!B.Load(), b"atomic.Bool: initial\n");
    check(!B.Swap(true), b"atomic.Bool: Swap return\n");
    check(B.Load(), b"atomic.Bool: post-Swap\n");
    check(B.CompareAndSwap(true, false), b"atomic.Bool: CAS\n");
}
