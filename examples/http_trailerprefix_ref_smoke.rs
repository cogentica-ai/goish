// http_trailerprefix_ref_smoke — the "Trailer:" magic prefix must not
// reach the wire as a header.
//
// A handler that cannot name a trailer up front announces it by
// setting `w.Header().Set(http.TrailerPrefix+"X-Sum", …)` while
// writing the body. Go's chunkWriter.writeHeader (server.go:1331-1344)
// does TWO things with those keys, and goish did neither:
//
//   * every one goes into excludeHeader — "Don't write out the fake
//     Trailer:foo keys" — so the head carries no `Trailer:X-Sum` line.
//     goish needs no such pass and has none: the name carries a colon,
//     so writeSubset's ValidHeaderFieldName guard already refuses it.
//     That was MEASURED by adding the exclusion and taking it away
//     again — both rows below pass either way, so the code is not
//     there.
//   * each one sets `trailers`, and `!trailers` is what suppresses the
//     automatic Content-Length (server.go:1363), which is what drops
//     the response into chunked framing. goish derived a length, so the
//     response was Content-Length framed and the trailer had nowhere to
//     go — it was dropped in silence, body intact.
//
// So the observable defect is the second bullet alone, and it is total:
//
//     goish  …Content-Length: 5\n\nhello          (no trailer at all)
//     Go     …Transfer-Encoding: chunked\n\n5\nhello\n0\nX-Sum: abc\n\n
//
// goish already honoured the OTHER route to the same flag, a declared
// `Trailer` header. That is why this stayed hidden: the feature looked
// present and the announced-up-front case worked.
//
// Read off a raw socket, because a client parses trailers away and the
// question is exactly which bytes the server wrote.
//
// GO[] is the verbatim output of tools/gen_trailerprefix_head_ref.go
// under scripts/goref.sh.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

/// Every mismatch below lands here; the process exits non-zero if it is
/// not zero (ROADMAP §2b-vii).
static FAILED: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

use alloc::sync::Arc;
use alloc::vec::Vec;
use goish::goslice::slice;
use goish::gostring::string;
use goish::io::{Closer, Reader, Writer};
use goish::net;
use goish::net::http;
use goish::types::{byte, int};
use goish::{fmt, go, time};

const GO: [&str; 2] = [
    "prefix_only          \"HTTP/1.1 200 OK\\\\nContent-Type: text/plain\\\\nDate: <elided>\\\\nConnection: close\\\\nTransfer-Encoding: chunked\\\\n\\\\n5\\\\nhello\\\\n0\\\\nX-Sum: abc\\\\n\\\\n\"",
    "declared_and_prefix  \"HTTP/1.1 200 OK\\\\nContent-Type: text/plain\\\\nTrailer: X-Declared\\\\nDate: <elided>\\\\nConnection: close\\\\nTransfer-Encoding: chunked\\\\n\\\\n5\\\\nhello\\\\n0\\\\nX-Declared: yes\\\\nX-Sum: abc\\\\n\\\\n\"",
];

fn chk(ln: &mut usize, got: &string) {
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln as int + 1, got);
        FAILED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        *ln += 1;
        return;
    }
    if got == GO[*ln] {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        fmt::Printf!("[!!] line %d\n  got  %q\n  want %q\n", *ln as int + 1, got, GO[*ln]);
        FAILED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
    *ln += 1;
}

#[goish::main]
fn main() {
    go!(stack(1024 * 1024), move || {
        run();
    });
    loop {
        goish::runtime::sched::Gosched();
    }
}

fn run() {
    let mut ln: usize = 0;
    for (name, declare) in [("prefix_only", false), ("declared_and_prefix", true)].iter() {
        let mux = http::ServeMux::new();
        let d = *declare;
        mux.HandleFunc(string::from("/"), move |w, _r| {
            if d {
                w.Header().Set(string::from("Trailer"), string::from("X-Declared"));
            }
            w.Header().Set(
                string::from(http::TrailerPrefix) + string::from("X-Sum"),
                string::from("abc"),
            );
            w.Header().Set(string::from("Content-Type"), string::from("text/plain"));
            let _ = w.Write(goish::convert::bytes(string::from("hello")));
            if d {
                w.Header().Set(string::from("X-Declared"), string::from("yes"));
            }
        });
        let mut srv = http::Server::default();
        srv.Handler = Arc::new(mux) as Arc<dyn http::Handler>;
        let srv = Arc::new(srv);

        let (l, lerr) = net::Listen(string::from("tcp"), string::from("127.0.0.1:0"));
        if !lerr.IsNil() {
            fmt::Printf!("[!!] listen: %v\n", lerr);
            goish::os::Exit(1);
        }
        let addr = l.Addr().String();
        let s2 = srv.clone();
        go!(stack(512 * 1024), move || {
            let _ = s2.Serve(l);
        });
        time::Sleep(time::Millisecond * 50);

        let (mut c, derr) = net::Dial(string::from("tcp"), addr);
        if !derr.IsNil() {
            fmt::Printf!("[!!] dial: %v\n", derr);
            goish::os::Exit(1);
        }
        let _ = c.SetReadDeadline(time::Now().Add(time::Second * 2));
        let _ = c.Write(goish::convert::bytes(string::from(
            "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        )));
        let mut raw: Vec<u8> = Vec::new();
        let mut buf: slice<byte> = slice::__from_vec(alloc::vec![0u8; 512]);
        loop {
            let (n, e) = c.Read(&mut buf);
            if n > 0 {
                raw.extend_from_slice(&buf.as_ref()[..n as usize]);
            }
            if n <= 0 || !e.IsNil() {
                break;
            }
        }
        let _ = c.Close();
        let _ = srv.Close();

        // Same rendering the Go generator uses: CRLF as \n, Date blanked.
        let text = string::from_bytes(&raw);
        let parts = goish::strings::Split(text, string::from("\r\n"));
        let mut joined = string::new();
        for (i, p) in parts.iter().enumerate() {
            if i > 0 {
                joined = joined + string::from("\\n");
            }
            if goish::strings::HasPrefix(p.clone(), string::from("Date: ")) {
                joined = joined + string::from("Date: <elided>");
            } else {
                joined = joined + p.clone();
            }
        }
        chk(&mut ln, &fmt::Sprintf!("%-20s %q", string::from(*name), joined));
    }
    if ln != GO.len() {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln as int, GO.len() as int);
        FAILED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
    let f = FAILED.load(core::sync::atomic::Ordering::Relaxed);
    if f != 0 {
        fmt::Printf!("\nFAILED %d check(s)\n", f as i64);
        goish::os::Exit(1);
    }
    fmt::Printf!("\nok %d/%d\n", ln as i64, GO.len() as i64);
    goish::os::Exit(0);
}
