// http_bufio_pool_smoke — server.go's bufio/textproto pools.
//
// Go pools whole bufio.Reader/Writer/textproto.Reader structs; goish
// pools their backing allocations. What must be TRUE either way, and
// what this test discriminates on:
//
//   * put → new actually REUSES the allocation. Asserted by pointer
//     identity of the backing buffer across the round trip — a
//     new/put pair that silently allocates fresh every time would
//     pass any behavioural test, so behaviour alone proves nothing.
//   * newBufioWriterSize dispatches 2k and 4k to SEPARATE pools
//     (Go's bufioWriterPool switch), and a nonstandard size bypasses
//     pooling entirely — putBufioWriter must DROP it, not feed a
//     wrong-sized buffer to a pool that promises a size.
//   * putBufioWriter discards unflushed bytes (Go's bw.Reset(nil))
//     rather than leaking them into the next user's stream.
//   * pooled readers still read correctly after a recycle.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::net::http::request::{newTextprotoReader, putTextprotoReader};
use goish::net::http::server::{
    bufioWriterPool, newBufioReader, newBufioWriterSize, putBufioReader, putBufioWriter,
};

static FAILED: AtomicUsize = AtomicUsize::new(0);

fn check(name: &'static str, ok: bool) {
    if ok {
        fmt::Printf!("PASS: %s\n", name);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("FAIL: %s\n", name);
    }
}

struct SinkWriter;
impl goish::io::Writer for SinkWriter {
    fn Write(&mut self, p: goish::slice<goish::byte>) -> (goish::int, goish::error) {
        (goish::len(&p), goish::errors::nil)
    }
}

#[goish::main]
fn main() {
    goish::go!(stack(256 * 1024), move || {
        run();
    });
    loop {
        goish::runtime::sched::Gosched();
    }
}

fn run() -> ! {
    // ── reader pool: reuse is real, and recycled readers still read ──
    {
        let br = newBufioReader(goish::bytes::NewReader(goish::bytes("GET / HTTP/1.1\r\n")));
        let p1 = br.__buf_ptr();
        putBufioReader(br);

        let mut br2 = newBufioReader(goish::bytes::NewReader(goish::bytes("hello")));
        let p2 = br2.__buf_ptr();
        check(
            "putBufioReader → newBufioReader reuses the buffer",
            p1 == p2,
        );
        let mut out = goish::make!([]goish::byte, 5);
        let (n, _) = goish::io::Reader::Read(&mut br2, &mut out);
        check(
            "a recycled reader reads correctly",
            n == 5 && &out.slice(0, 5).to_vec()[..] == b"hello",
        );
        putBufioReader(br2);
    }

    // ── writer pools: size dispatch, reuse, and unflushed discard ──
    {
        let mut bw2k = newBufioWriterSize(SinkWriter, 2048);
        let bw4k = newBufioWriterSize(SinkWriter, 4096);
        check(
            "2k and 4k report their sizes",
            bw2k.Size() == 2048 && bw4k.Size() == 4096,
        );
        // Leave unflushed bytes in the 2k writer on purpose.
        let _ = bw2k.Write(goish::bytes("UNFLUSHED"));
        let p2k = bw2k.__buf_ptr();
        let p4k = bw4k.__buf_ptr();
        putBufioWriter(bw2k);
        putBufioWriter(bw4k);

        let bw2k_b = newBufioWriterSize(SinkWriter, 2048);
        let bw4k_b = newBufioWriterSize(SinkWriter, 4096);
        check("2k pool reuses the 2k buffer", bw2k_b.__buf_ptr() == p2k);
        check("4k pool reuses the 4k buffer", bw4k_b.__buf_ptr() == p4k);
        check(
            "a recycled writer starts empty (unflushed bytes discarded)",
            bw2k_b.Buffered() == 0 && bw2k_b.Available() == 2048,
        );
        putBufioWriter(bw2k_b);
        putBufioWriter(bw4k_b);

        // Nonstandard size: no pool. Its buffer must NOT come back.
        let bw3k = newBufioWriterSize(SinkWriter, 3072);
        check(
            "bufioWriterPool(3072) is None",
            bufioWriterPool(3072).is_none(),
        );
        let p3k = bw3k.__buf_ptr();
        putBufioWriter(bw3k); // dropped, not pooled
        let bw2k_c = newBufioWriterSize(SinkWriter, 2048);
        check(
            "a dropped 3k buffer never enters the 2k pool",
            bw2k_c.__buf_ptr() != p3k,
        );
        putBufioWriter(bw2k_c);
    }

    // ── textproto pool: scratch reuse through a real header parse ──
    {
        let br = newBufioReader(goish::bytes::NewReader(goish::bytes(
            "Content-Type: text/plain\r\n  with-fold\r\n\r\n",
        )));
        let mut tp = newTextprotoReader(br);
        // Force the folded-line path so the scratch buf is actually
        // populated before the put — an empty scratch would make the
        // reuse assertion vacuous.
        let (line, _) = tp.ReadContinuedLine();
        check(
            "textproto reader parses through the pool",
            (line.as_ref() as &str).contains("with-fold"),
        );
        let p1 = tp.__scratch_ptr();
        let br_back = putTextprotoReader(tp);
        putBufioReader(br_back);

        let br2 = newBufioReader(goish::bytes::NewReader(goish::bytes("X: y\r\n\r\n")));
        let tp2 = newTextprotoReader(br2);
        check(
            "putTextprotoReader → newTextprotoReader reuses the scratch",
            p1 != core::ptr::null() && tp2.__scratch_ptr() == p1,
        );
        let br_back2 = putTextprotoReader(tp2);
        putBufioReader(br_back2);
    }

    let f = FAILED.load(Ordering::Relaxed);
    if f == 0 {
        fmt::Printf!("HTTP_BUFIO_POOL_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("HTTP_BUFIO_POOL_FAIL\n");
    goish::os::Exit(1);
}
