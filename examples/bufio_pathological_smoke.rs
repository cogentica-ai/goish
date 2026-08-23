// bufio_pathological_smoke — verifies bufio::Reader and http::ReadResponse
// handle pathological fragment sizes correctly (the TLS record-split hypothesis).
//
// Scenarios:
//   S1. 1-byte-per-Read  — maximum fragmentation
//   S2. variable chunks  — 5, 4096, 899 byte fragments
//   S3. 0-byte returns   — Read returns (0, nil) multiple times before data
//   S4. EOF mid-headers  — premature EOF during HTTP header parsing
//   S5. ReadResponse over 1-byte fragments (full HTTP/1.1 chunked response)
//   S6. ReadResponse with Content-Length over mixed chunks
//   S7. drain_to_eof: 0-byte returns interspersed with data
//
// Expected: all scenarios print PASS.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;

use goish::bufio;
use goish::errors;
use goish::fmt;
use goish::io;
use goish::net::http;
use goish::types::byte;
use goish::{int, nil, slice, string, syscall};

// ─── MockReader implementations ─────────────────────────────────────────────

/// Returns exactly 1 byte per Read call. Returns EOF when exhausted.
struct OneByte {
    data: Vec<byte>,
    pos: usize,
}
impl OneByte {
    fn new(s: &[u8]) -> Self {
        Self {
            data: s.to_vec(),
            pos: 0,
        }
    }
}
impl io::Reader for OneByte {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, goish::error) {
        if self.pos >= self.data.len() {
            return (0, io::EOF.into());
        }
        if p.Len() == 0 {
            return (0, nil.into());
        }
        p[0] = self.data[self.pos];
        self.pos += 1;
        (1, nil.into())
    }
}

/// Returns chunks of variable size: cycles through the given sizes array.
struct ChunkedReader {
    data: Vec<byte>,
    pos: usize,
    sizes: Vec<usize>,
    size_idx: usize,
}
impl ChunkedReader {
    fn new(s: &[u8], sizes: &[usize]) -> Self {
        Self {
            data: s.to_vec(),
            pos: 0,
            sizes: sizes.to_vec(),
            size_idx: 0,
        }
    }
}
impl io::Reader for ChunkedReader {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, goish::error) {
        if self.pos >= self.data.len() {
            return (0, io::EOF.into());
        }
        let chunk_size = self.sizes[self.size_idx % self.sizes.len()];
        self.size_idx += 1;
        let avail = self.data.len() - self.pos;
        let n = chunk_size.min(avail).min(p.Len() as usize);
        for i in 0..n {
            p[i as int] = self.data[self.pos + i];
        }
        self.pos += n;
        (n as int, nil.into())
    }
}

/// Inserts zero-byte returns (n=0, err=nil) every Nth call before returning data.
/// This tests the "0 bytes without error" path which must NOT be treated as EOF.
struct ZeroByteReader {
    data: Vec<byte>,
    pos: usize,
    /// How many 0-byte returns to inject before each real byte.
    zeros_before: usize,
    zeros_remaining: usize,
}
impl ZeroByteReader {
    fn new(s: &[u8], zeros_before: usize) -> Self {
        Self {
            data: s.to_vec(),
            pos: 0,
            zeros_before,
            zeros_remaining: zeros_before,
        }
    }
}
impl io::Reader for ZeroByteReader {
    fn Read(&mut self, _p: &mut slice<byte>) -> (int, goish::error) {
        if self.pos >= self.data.len() {
            return (0, io::EOF.into());
        }
        // Inject zero-byte return first.
        if self.zeros_remaining > 0 {
            self.zeros_remaining -= 1;
            return (0, nil.into());
        }
        self.zeros_remaining = self.zeros_before;
        // Return 1 byte of data.
        _p[0] = self.data[self.pos];
        self.pos += 1;
        (1, nil.into())
    }
}

/// Returns data up to a split point, then returns EOF prematurely.
struct EarlyEOFReader {
    data: Vec<byte>,
    pos: usize,
    eof_at: usize, // byte index at which to force EOF
}
impl EarlyEOFReader {
    fn new(s: &[u8], eof_at: usize) -> Self {
        Self {
            data: s.to_vec(),
            pos: 0,
            eof_at,
        }
    }
}
impl io::Reader for EarlyEOFReader {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, goish::error) {
        if self.pos >= self.eof_at {
            return (0, io::EOF.into());
        }
        let avail = self.eof_at - self.pos;
        let n = avail.min(1).min(p.Len() as usize);
        for i in 0..n {
            p[i as int] = self.data[self.pos + i];
        }
        self.pos += n;
        (n as int, nil.into())
    }
}

// ─── Test helpers ────────────────────────────────────────────────────────────

fn pass(label: &'static str) {
    fmt::Println!(fmt::Sprintf!("  [PASS] %s", label));
}

fn fail(label: &'static str, detail: &'static str) {
    fmt::Println!(fmt::Sprintf!("  [FAIL] %s: %s", label, detail));
}

fn fail_s(label: &'static str, detail: string) {
    fmt::Println!(fmt::Sprintf!("  [FAIL] %s: %v", label, detail));
}

// ─── Scenarios ───────────────────────────────────────────────────────────────

/// S1: 1-byte-per-Read — ReadString must reassemble the full line.
fn s1_one_byte_per_read() -> bool {
    let data = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    let r = OneByte::new(data);
    let mut br = bufio::NewReader(r);

    let (line, err) = br.ReadString(b'\n');
    if err != nil {
        fail_s("S1", fmt::Sprintf!("ReadString returned err: %v", err));
        return false;
    }
    // Expected: "HTTP/1.1 200 OK\r\n"
    let expected = "HTTP/1.1 200 OK\r\n";
    if line != expected {
        fail_s("S1", fmt::Sprintf!("got %q, want %q", line, expected));
        return false;
    }
    pass("S1: 1-byte-per-Read reassembles status line");
    true
}

/// S2: variable chunk sizes 5/4096/899 — ReadString must reassemble across chunk boundaries.
fn s2_variable_chunks() -> bool {
    // Build a long line that will span multiple chunks.
    // "X-Header: " + 5000 'a' chars + "\r\n"
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(b"X-Header: ");
    for _ in 0..5000 {
        data.push(b'a');
    }
    data.extend_from_slice(b"\r\n");
    let total_len = data.len(); // 5012

    let r = ChunkedReader::new(&data, &[5, 4096, 899]);
    let mut br = bufio::NewReader(r);

    let (line, err) = br.ReadString(b'\n');
    if err != nil {
        fail_s("S2", fmt::Sprintf!("ReadString returned err: %v", err));
        return false;
    }
    if line.Len() != total_len as int {
        fail_s(
            "S2",
            fmt::Sprintf!("line.Len()=%d, want %d", line.Len(), total_len as i64),
        );
        return false;
    }
    // Last two bytes must be \r\n
    let lb = line.as_bytes();
    if lb[lb.len() - 2] != b'\r' || lb[lb.len() - 1] != b'\n' {
        fail("S2", "line does not end with CRLF");
        return false;
    }
    pass("S2: variable-chunk ReadString reassembles 5012-byte header");
    true
}

/// S3: 0-byte returns — bufio must NOT treat (0, nil) as EOF.
/// The ZeroByteReader injects zeros_before=3 zero returns before each data byte.
/// bufio's fill() has a maxConsecutiveEmptyReads guard (100 iterations).
/// Since ZeroByteReader resets the zero counter after each real byte,
/// empty reads never accumulate across the guard — bufio loops until it gets data.
fn s3_zero_byte_returns() -> bool {
    let data = b"hello\nworld\n";
    // Inject 3 zero-byte returns before each real byte. bufio fill() retries 100 times
    // total, so with only 3 zeros before each byte we never hit the limit.
    let r = ZeroByteReader::new(data, 3);
    let mut br = bufio::NewReader(r);

    let (line, err) = br.ReadString(b'\n');
    // Note: ZeroByteReader returns 0 bytes per call many times.
    // bufio::fill() will loop up to maxConsecutiveEmptyReads(100) times.
    // With 3 zeros per byte, filling the 4096-byte buffer only takes 3 zeros
    // for the FIRST byte, then data flows. The fill() loop DOES reset on first
    // non-zero read, so all bytes should arrive.
    // The key invariant: (0, nil) must not be treated as EOF.
    if errors::Is(err.clone(), io::EOF) && line.Len() == 0 {
        // This would be a bug: premature EOF
        fail("S3", "premature EOF — 0-byte return was treated as EOF");
        return false;
    }
    if err != nil && !errors::Is(err.clone(), io::EOF) {
        fail_s("S3", fmt::Sprintf!("unexpected error: %v", err));
        return false;
    }
    if line != "hello\n" {
        fail_s("S3", fmt::Sprintf!("got %q, want \"hello\\n\"", line));
        return false;
    }
    pass("S3: 0-byte returns do not cause premature EOF");
    true
}

/// S4: EOF mid-headers — ReadResponse must return an error, not a partial or panicking response.
fn s4_eof_mid_headers() -> bool {
    // Response truncated after first header line — no empty line to end headers.
    let data = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n";
    // EOF at exact end of data (no trailing \r\n blank line).
    let r = EarlyEOFReader::new(data, data.len());
    let mut br = bufio::NewReader(r);

    let (_resp, err) = http::ReadResponse(&mut br, None);
    // ReadResponse MUST return an error (unexpected EOF), not a successful parse.
    if err == nil {
        fail("S4", "expected error for truncated headers, got nil");
        return false;
    }
    pass("S4: EOF mid-headers returns error (not silent truncation)");
    true
}

/// S5: Full HTTP/1.1 response with chunked body, parsed via 1-byte-per-Read.
fn s5_readresponse_chunked_one_byte() -> bool {
    // Construct a valid chunked response:
    //   HTTP/1.1 200 OK\r\n
    //   Transfer-Encoding: chunked\r\n
    //   \r\n
    //   5\r\nhello\r\n
    //   6\r\n world\r\n
    //   0\r\n\r\n
    let data = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    let r = OneByte::new(data);
    let mut br = bufio::NewReader(r);

    let (mut resp, err) = http::ReadResponse(&mut br, None);
    if err != nil {
        fail_s("S5", fmt::Sprintf!("ReadResponse error: %v", err));
        return false;
    }
    if resp.StatusCode != 200 {
        fail_s(
            "S5",
            fmt::Sprintf!("StatusCode=%d, want 200", resp.StatusCode),
        );
        return false;
    }
    let (body_bytes, _) = io::ReadAll(&mut resp.Body);
    let _ = io::Closer::Close(&mut resp.Body);
    let body = string::from_bytes(&body_bytes);
    if body != "hello world" {
        fail_s("S5", fmt::Sprintf!("body=%q, want \"hello world\"", body));
        return false;
    }
    pass("S5: ReadResponse over 1-byte chunks parses chunked body correctly");
    true
}

/// S6: HTTP/1.1 response with Content-Length, parsed via variable chunks [5, 4096, 899].
fn s6_readresponse_content_length_mixed_chunks() -> bool {
    // Body = 2048 'z' bytes. Chunk sizes [5, 4096, 899] will deliver it in 3 reads.
    let body_len: usize = 2048;
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(b"HTTP/1.1 200 OK\r\nContent-Length: 2048\r\n\r\n");
    for _ in 0..body_len {
        data.push(b'z');
    }

    let r = ChunkedReader::new(&data, &[5, 4096, 899]);
    let mut br = bufio::NewReader(r);

    let (mut resp, err) = http::ReadResponse(&mut br, None);
    if err != nil {
        fail_s("S6", fmt::Sprintf!("ReadResponse error: %v", err));
        return false;
    }
    if resp.StatusCode != 200 {
        fail_s(
            "S6",
            fmt::Sprintf!("StatusCode=%d, want 200", resp.StatusCode),
        );
        return false;
    }
    let (body, _) = io::ReadAll(&mut resp.Body);
    let _ = io::Closer::Close(&mut resp.Body);
    if body.Len() != body_len as int {
        fail_s(
            "S6",
            fmt::Sprintf!("body.Len()=%d, want %d", body.Len(), body_len as i64),
        );
        return false;
    }
    // All bytes should be 'z'.
    for i in 0..body.Len() {
        if body[i] != b'z' {
            fail_s(
                "S6",
                fmt::Sprintf!("body[%d]=%d, want %d", i, body[i] as i64, b'z' as i64),
            );
            return false;
        }
    }
    pass("S6: ReadResponse with Content-Length over mixed chunks reads full body");
    true
}

/// S7: drain_to_eof with 0-byte returns interspersed.
/// Tests the goish drain_to_eof internal loop behavior for Connection: close bodies.
/// The drain_to_eof function MUST continue looping even when n==0 and err==nil.
fn s7_drain_to_eof_zero_bytes() -> bool {
    // Build a response with Connection: close (no Content-Length, no TE).
    // Server "sends" body in 0-byte-interspersed fashion.
    let body = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"; // 26 bytes
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n");
    data.extend_from_slice(body);

    // Inject 2 zero returns before each real byte.
    // NOTE: bufio's fill() has maxConsecutiveEmptyReads=100 guard.
    // ZeroByteReader resets the counter after each real byte, so we never
    // accumulate 100 consecutive zeros. This tests whether drain_to_eof
    // passes through the zero-reads to bufio's fill() which handles them.
    let r = ZeroByteReader::new(&data, 2);
    let mut br = bufio::NewReader(r);

    let (mut resp, err) = http::ReadResponse(&mut br, None);
    // On Connection: close, ReadResponse drains until EOF.
    // err here could be nil (drain returned full body before EOF) — depends
    // on whether drain_to_eof exits early on (0, nil).
    if err != nil && !errors::Is(err.clone(), io::EOF) {
        fail_s("S7", fmt::Sprintf!("unexpected error: %v", err));
        return false;
    }
    if resp.StatusCode != 200 {
        fail_s(
            "S7",
            fmt::Sprintf!("StatusCode=%d, want 200", resp.StatusCode),
        );
        return false;
    }
    let (got_body, _) = io::ReadAll(&mut resp.Body);
    let _ = io::Closer::Close(&mut resp.Body);
    let got_len = got_body.Len();
    let want_len = body.len() as int;
    if got_len != want_len {
        fail_s(
            "S7",
            fmt::Sprintf!(
                "body.Len()=%d, want %d (drain_to_eof stopped early on 0-byte read?)",
                got_len,
                want_len
            ),
        );
        return false;
    }
    pass("S7: drain_to_eof handles 0-byte returns correctly");
    true
}

// ─── main ────────────────────────────────────────────────────────────────────

#[goish::main]
fn main() {
    fmt::Println!("=== bufio_pathological_smoke ===");
    fmt::Println!("Hypothesis: goish bufio + http correctly reassemble fragmented reads.");
    fmt::Println!("");

    let r1 = s1_one_byte_per_read();
    let r2 = s2_variable_chunks();
    let r3 = s3_zero_byte_returns();
    let r4 = s4_eof_mid_headers();
    let r5 = s5_readresponse_chunked_one_byte();
    let r6 = s6_readresponse_content_length_mixed_chunks();
    let r7 = s7_drain_to_eof_zero_bytes();

    let passed = [r1, r2, r3, r4, r5, r6, r7].iter().filter(|&&x| x).count();
    let total = 7usize;

    fmt::Println!(fmt::Sprintf!(""));
    fmt::Println!(fmt::Sprintf!(
        "=== Result: %d/%d passed ===",
        passed as i64,
        total as i64
    )); // goishlint:ignore GOISH005
    if passed == total {
        fmt::Println!(
            "VERDICT: PASS — goish bufio + http handle all pathological splits correctly."
        );
        syscall::Exit(0);
    } else {
        fmt::Println!("VERDICT: FAIL — some pathological splits are not handled.");
        syscall::Exit(1);
    }
}
