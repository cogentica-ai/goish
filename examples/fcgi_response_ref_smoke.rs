// fcgi_response_ref_smoke — what net/http/fcgi puts in a RESPONSE
// head, against Go 1.25.5.
//
// fcgi_ref_smoke measures the request side: what a handler sees once
// the record parser is done. Nothing measured what goes back, and two
// things were missing.
//
//   Date       Go stamps one on every response when the handler set
//              none (child.go:116-118). goish set none at all, so a
//              FastCGI response reached the front-end server without
//              a Date — the plain server stamps its own and this path
//              had no equivalent.
//   304        Go deletes Content-Type, Content-Length and
//              Transfer-Encoding, because a 304 "must not have body"
//              (child.go:110-115). goish kept them, so a 304 went out
//              carrying `Content-Length: 5` AND
//              `Transfer-Encoding: chunked` — not merely redundant on
//              a bodyless response but a framing contradiction the
//              peer has to resolve.
//
// The `304-strips` row keeps ETag deliberately: Go removes exactly
// three headers, not every header, and a port that stripped more
// would break conditional requests.
//
// `explicit-date` is the row that stops this being vacuous. Its Date
// is a FIXED value and is NOT normalised — only a server-generated
// Date becomes DATE — so the row fails if the handler's own value is
// overwritten rather than preserved. Blanking every Date would make
// it pass either way.
//
// Reference: tools/gen_fcgi_response_ref.go via scripts/goref.sh,
// which drives the same hand-built FastCGI records as fcgi_ref_smoke.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use alloc::sync::Arc;
use alloc::vec::Vec;
use goish::goslice::slice;
use goish::gostring::string;
use goish::io::{Closer, Reader, Writer};
use goish::net::http::fcgi;
use goish::net::http::{Handler, ResponseWriter};
use goish::types::{byte, int};
use goish::{fmt, go, net, sort, strings, time};

fn s(x: &str) -> string { string::from_bytes(x.as_bytes()) }
fn zzRecord(typ: u8, reqID: u16, content: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = alloc::vec![1, typ, (reqID >> 8) as u8, reqID as u8];
    out.push((content.len() >> 8) as u8);
    out.push(content.len() as u8);
    out.push(0); out.push(0);
    out.extend_from_slice(content);
    out
}
fn zzEncodeLen(n: usize) -> Vec<u8> {
    if n < 128 { return alloc::vec![n as u8]; }
    alloc::vec![((n >> 24) as u8) | 0x80, (n >> 16) as u8, (n >> 8) as u8, n as u8]
}
fn zzEncodePairs(pairs: &[(string, string)]) -> Vec<u8> {
    let mut keys: Vec<string> = Vec::new();
    for (k, _) in pairs.iter() { keys.push(k.clone()); }
    let mut ks = slice::<string>::__from_vec(keys);
    sort::Strings(&mut ks);
    let mut out: Vec<u8> = Vec::new();
    for i in 0..ks.Len() {
        let k = ks[i].clone();
        let mut v = string::new();
        for (pk, pv) in pairs.iter() { if *pk == k { v = pv.clone(); } }
        out.extend_from_slice(&zzEncodeLen(k.as_bytes().len()));
        out.extend_from_slice(&zzEncodeLen(v.as_bytes().len()));
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(v.as_bytes());
    }
    out
}

struct H(int);
impl Handler for H {
    fn ServeHTTP(&self, w: &(dyn ResponseWriter + Send + Sync + 'static), _r: &goish::net::http::Request) {
        match self.0 {
            0 => { let _ = w.Write(goish::convert::bytes(s("ok"))); }
            1 => {
                w.Header().Set(s("Content-Type"), s("text/plain"));
                w.Header().Set(s("Content-Length"), s("5"));
                w.Header().Set(s("Transfer-Encoding"), s("chunked"));
                w.Header().Set(s("ETag"), s("\"x\""));
                w.WriteHeader(304);
            }
            2 => { w.WriteHeader(304); }
            3 => {
                w.Header().Set(s("Date"), s("Mon, 01 Jan 2024 00:00:00 GMT"));
                let _ = w.Write(goish::convert::bytes(s("ok")));
            }
            _ => {
                w.Header().Set(s("Content-Type"), s("application/json"));
                let _ = w.Write(goish::convert::bytes(s("{}")));
            }
        }
    }
    fn __goish_as_dyn_any(&self) -> Option<&(dyn core::any::Any + Send + Sync)> { Some(self) }
}

const GO: [&str; 5] = [
    "plain-200      Status: 200 OK | Content-Type: text/plain; charset=utf-8 | Date: DATE",
    "304-strips     Status: 304 Not Modified | Date: DATE | Etag: \"x\"",
    "304-bare       Status: 304 Not Modified | Date: DATE",
    "explicit-date  Status: 200 OK | Content-Type: text/plain; charset=utf-8 | Date: Mon, 01 Jan 2024 00:00:00 GMT",
    "handler-ct     Status: 200 OK | Content-Type: application/json | Date: DATE",
];

fn chk(ln: &mut usize, got: &string) {
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line: %q\n", got);
        *ln += 1;
        return;
    }
    let want = string::from(GO[*ln]);
    if got.clone() == want {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        fmt::Printf!("[!!] goish: %q\n", got);
        fmt::Printf!("     go   : %q\n", want);
    }
    *ln += 1;
}

#[goish::main]
fn main() {
    go!(stack(1024 * 1024), move || { run(); });
    loop { goish::runtime::sched::Gosched(); }
}

fn run() {
    let mut lineno: usize = 0;
    let labels = ["plain-200", "304-strips", "304-bare", "explicit-date", "handler-ct"];
    for (i, label) in labels.iter().enumerate() {
        let (ln, _) = net::Listen(s("tcp"), s("127.0.0.1:0"));
        let addr = ln.Addr().String();
        let h: Arc<dyn Handler> = Arc::new(H(i as int));
        go!(stack(1024 * 1024), move || { let _ = fcgi::Serve(ln, h); });
        time::Sleep(time::Millisecond * 40);
        let (mut c, _) = net::Dial(s("tcp"), addr);
        let params: Vec<(string, string)> = alloc::vec![
            (s("REQUEST_METHOD"), s("GET")), (s("SERVER_PROTOCOL"), s("HTTP/1.1")),
            (s("HTTP_HOST"), s("x")), (s("REQUEST_URI"), s("/")),
        ];
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&zzRecord(1, 1, &[0, 1, 0, 0, 0, 0, 0, 0]));
        buf.extend_from_slice(&zzRecord(4, 1, &zzEncodePairs(&params)));
        buf.extend_from_slice(&zzRecord(4, 1, &[]));
        buf.extend_from_slice(&zzRecord(5, 1, &[]));
        let _ = c.Write(slice::<byte>::__from_vec(buf));
        let _ = c.SetReadDeadline(time::Now().Add(time::Millisecond * 500));
        let mut raw: Vec<u8> = Vec::new();
        let mut rb: slice<byte> = slice::__from_vec(alloc::vec![0u8; 1024]);
        loop {
            let (n, e) = c.Read(&mut rb);
            if n > 0 { raw.extend_from_slice(&rb.as_ref()[..n as usize]); }
            if n <= 0 || !e.IsNil() { break; }
        }
        let _ = c.Close();
        let mut out: Vec<u8> = Vec::new();
        let mut p = 0usize;
        while p + 8 <= raw.len() {
            let typ = raw[p + 1];
            let clen = ((raw[p + 4] as usize) << 8) | raw[p + 5] as usize;
            let plen = raw[p + 6] as usize;
            let end = core::cmp::min(p + 8 + clen, raw.len());
            if typ == 6 { out.extend_from_slice(&raw[p + 8..end]); }
            p += 8 + clen + plen;
        }
        let txt = string::from_bytes(&out);
        let (head, _, _) = strings::Cut(txt, s("\r\n\r\n"));
        let mut lines: Vec<string> = Vec::new();
        for l in strings::Split(head, s("\r\n")).iter() {
            if l.Len() == 0 { continue; }
            if strings::HasPrefix(l.clone(), s("Date: "))
                && l.clone() != s("Date: Mon, 01 Jan 2024 00:00:00 GMT")
            {
                lines.push(s("Date: DATE"));
            }
            else { lines.push(l.clone()); }
        }
        let mut joined = string::new();
        for (j, l) in lines.iter().enumerate() {
            if j > 0 { joined = joined + s(" | "); }
            joined = joined + l.clone();
        }
        chk(&mut lineno, &fmt::Sprintf!("%-14s %s", s(*label), joined));
    }
    if lineno != GO.len() {
        fmt::Printf!("[!!] line count mismatch with the Go reference\n");
    }
    goish::os::Exit(0);
}
