// fcgi_ref_smoke — net/http/fcgi's record parser against a running Go.
// (net/http/fcgi/child.go, net/http/fcgi/fcgi.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_fcgi_ref.go` run in
// `package fcgi` by `scripts/goref.sh`. goish matched Go on all 8
// lines — no defects found, and the probe was checked stable across
// four runs before pinning, because it drives a real socket.
//
// FastCGI is a length-prefixed binary protocol read straight off a
// socket, which puts it in the class where a parser's handling of
// HOSTILE framing decides everything above it. A record announces its
// own content length in two bytes; a params stream announces each
// name's and value's length in one or four; and every one of those
// numbers comes from the peer.
//
// What is measured is what a HANDLER SEES once the parser is done —
// the method, the URL, the headers, the body — because that is the
// only thing the rest of the program acts on. The records are written
// by hand rather than by a client library, so the inputs include
// shapes no cooperating client would send.
//
// THE RESULT WORTH READING TWICE is the `headers` line. A peer that
// sends HTTP_CONTENT_TYPE does not have it ignored in favour of the
// real CONTENT_TYPE — both land in the SAME header, and the line reads
// Content-Type="real/type|forged/type". Anything calling Header.Get
// sees the first; anything calling Header.Values sees both, and they
// disagree. This smoke was written with a comment asserting the
// opposite, and the measurement corrected it: the guess was that a
// reserved variable could not be forged, and it can be shadowed.
//
// The two hostile-framing cases both come back <no request
// dispatched>, which is the right answer and not an obvious one:
//
//   * `truncated-pairs` inflates a parameter NAME length so it claims
//     more bytes than its record contains. A parser that read the
//     declared length without bounding it against the record would
//     walk into the following record and build a request out of the
//     wrong bytes.
//   * `oversized-record` sets a record's content length to 0xffff with
//     nothing behind it. A parser that trusted the header would block
//     forever or allocate 64K per record on a peer's say-so.
//
// Also pinned: the one/four-byte length encoding switches at 128, so
// the `long-values` case carries a 300-byte value and a 180-byte name
// and exercises the four-byte width on both; an unknown record type is
// IGNORED rather than fatal; an empty PARAMS record terminates the
// stream; and an empty parameter NAME is dropped while an empty VALUE
// is kept.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use alloc::sync::Arc;
use alloc::vec::Vec;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::io;
use goish::net;
use goish::net::http;
use goish::net::http::fcgi;
use goish::net::http::{Handler, ResponseWriter};
use goish::sort;
use goish::strings;
use goish::syscall;
use goish::time;
use goish::types::{byte, int};
use goish::{go, gochan::chan};
const GO: [&str; 8] = [
    "fcgi plain                  -> method=GET uri=\"\" host=\"example.test\" len=0 hdr=[] body=\"\"",
    "fcgi headers                -> method=GET uri=\"\" host=\"example.test\" len=0 hdr=[Content-Type=\"real/type|forged/type\" X-Simple=\"one\" X-Two-Words=\"two\"] body=\"\"",
    "fcgi post                   -> method=POST uri=\"\" host=\"example.test\" len=11 hdr=[Content-Type=\"application/x-www-form-urlencoded\"] body=\"field=value\"",
    "fcgi long-values            -> method=GET uri=\"\" host=\"example.test\" len=0 hdr=[Khttp-Khttp-Khttp-Khttp-Khttp-Khttp-Khttp-Khttp-Khttp-Khttp-Khttp-Khttp-Khttp-Khttp-Khttp-Khttp-Khttp-Khttp-Khttp-Khttp-Khttp-Khttp-Khttp-Khttp-Khttp-Khttp-Khttp-Khttp-Khttp-K=\"longname\" X-Long=\"vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv\"] body=\"\"",
    "fcgi empty-name-and-value   -> method=GET uri=\"\" host=\"example.test\" len=0 hdr=[X-Empty=\"\"] body=\"\"",
    "fcgi truncated-pairs        -> <no request dispatched>",
    "fcgi oversized-record       -> <no request dispatched>",
    "fcgi unknown-record-type    -> method=GET uri=\"\" host=\"example.test\" len=0 hdr=[] body=\"\"",
];

// Static counters: this smoke's `run` is a free function driving a
// whole socket exchange, so threading them through would reshape the
// probe the reference was generated from.
static FAILED: goish::sync::Mutex<int> = goish::sync::Mutex::new(0);
static LN: goish::sync::Mutex<int> = goish::sync::Mutex::new(0);

fn chk(got: string) {
    let mut ln = LN.Lock();
    if *ln >= GO.len() as int {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln + 1, got);
        *FAILED.Lock() += 1;
        *ln += 1;
        return;
    }
    let want = s(GO[*ln as usize]);
    *ln += 1;
    if got == want {
        return;
    }
    fmt::Printf!("[!!] line %d FAIL\n  got  %q\n  want %q\n", *ln, got, want);
    *FAILED.Lock() += 1;
}

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}
fn bs(v: Vec<u8>) -> slice<byte> {
    return slice::<byte>::__from_vec(v);
}
fn zzRecord(typ: u8, reqID: u16, content: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = alloc::vec![1, typ, (reqID >> 8) as u8, reqID as u8];
    out.push((content.len() >> 8) as u8);
    out.push(content.len() as u8);
    out.push(0);
    out.push(0);
    out.extend_from_slice(content);
    return out;
}
fn zzEncodeLen(n: usize) -> Vec<u8> {
    if n < 128 {
        return alloc::vec![n as u8];
    }
    return alloc::vec![
        ((n >> 24) as u8) | 0x80,
        (n >> 16) as u8,
        (n >> 8) as u8,
        n as u8
    ];
}
fn zzEncodePairs(pairs: &[(string, string)]) -> Vec<u8> {
    let mut keys: Vec<string> = Vec::new();
    for (k, _) in pairs.iter() {
        keys.push(k.clone());
    }
    let mut ks = slice::<string>::__from_vec(keys);
    sort::Strings(&mut ks);
    let mut out: Vec<u8> = Vec::new();
    for i in 0..ks.Len() {
        let k = ks[i].clone();
        let mut v = string::new();
        for (pk, pv) in pairs.iter() {
            if *pk == k {
                v = pv.clone();
            }
        }
        out.extend_from_slice(&zzEncodeLen(k.as_bytes().len()));
        out.extend_from_slice(&zzEncodeLen(v.as_bytes().len()));
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(v.as_bytes());
    }
    return out;
}
struct Echo(chan<string>);
impl Handler for Echo {
    fn ServeHTTP(&self, w: &(dyn ResponseWriter + Send + Sync + 'static), r: &http::Request) {
        let mut keys: Vec<string> = Vec::new();
        for (k, _) in r.Header.__inner().__iter() {
            keys.push(k.clone());
        }
        let mut ks = slice::<string>::__from_vec(keys);
        sort::Strings(&mut ks);
        let mut hs: Vec<string> = Vec::new();
        for i in 0..ks.Len() {
            let k = ks[i].clone();
            let vs = r.Header.Values(k.clone());
            let mut joined = string::new();
            for j in 0..vs.Len() {
                if j > 0 {
                    joined = joined + "|";
                }
                joined = joined + vs[j].clone();
            }
            hs.push(fmt::Sprintf!("%s=%q", k, joined));
        }
        let mut body = r.Body.clone();
        let (b, _) = io::ReadAll(&mut body);
        self.0.Send(fmt::Sprintf!(
            "method=%s uri=%q host=%q len=%d hdr=[%s] body=%q",
            r.Method.clone(),
            r.RequestURI.clone(),
            r.Host.clone(),
            r.ContentLength,
            strings::Join(slice::<string>::__from_vec(hs), s(" ")),
            string::from_bytes(&b.to_vec())
        ));
        let _ = w.Write(bs(b"ok".to_vec()));
    }
}
fn run(
    label: &str,
    params: &[(string, string)],
    stdin: &str,
    mangle: Option<fn(Vec<u8>) -> Vec<u8>>,
) {
    let (ln, lerr) = net::Listen(s("tcp"), s("127.0.0.1:0"));
    if lerr != goish::nil {
        chk(fmt::Sprintf!("[!!] listen: %q", lerr.Error()));
        return;
    }
    let addr = ln.Addr().String();
    let seen: chan<string> = chan::new_buffered(1);
    let h: Arc<dyn Handler> = Arc::new(Echo(seen.clone()));
    go!(move || {
        let _ = fcgi::Serve(ln, h);
    });
    let (mut c, derr) = net::Dial(s("tcp"), addr);
    if derr != goish::nil {
        chk(fmt::Sprintf!("[!!] dial: %q", derr.Error()));
        return;
    }
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&zzRecord(1, 1, &[0, 1, 0, 0, 0, 0, 0, 0]));
    buf.extend_from_slice(&zzRecord(4, 1, &zzEncodePairs(params)));
    buf.extend_from_slice(&zzRecord(4, 1, &[]));
    if stdin != "" {
        buf.extend_from_slice(&zzRecord(5, 1, stdin.as_bytes()));
    }
    buf.extend_from_slice(&zzRecord(5, 1, &[]));
    if let Some(f) = mangle {
        buf = f(buf);
    }
    let _ = io::Writer::Write(&mut c, bs(buf));
    let _ = c.SetReadDeadline(time::Now().Add(time::Millisecond * 300));
    let (_, _) = io::ReadAll(&mut c);
    let _ = io::Closer::Close(&mut c);
    // The handler either ran or it did not; a short poll distinguishes
    // "dispatched" from "the parser refused".
    let deadline = time::Now().Add(time::Second * 2);
    loop {
        if let Some((v, _ok)) = seen.__try_recv() {
            chk(fmt::Sprintf!("fcgi %-22s -> %s", s(label), v));
            return;
        }
        if time::Now().After(deadline.clone()) {
            chk(fmt::Sprintf!(
                "fcgi %-22s -> <no request dispatched>",
                s(label)
            ));
            return;
        }
        time::Sleep(time::Millisecond * 10);
    }
}
fn kv(k: &str, v: &str) -> (string, string) {
    return (s(k), s(v));
}
#[goish::main]
fn main() {
    let base: Vec<(string, string)> = alloc::vec![
        kv("REQUEST_METHOD", "GET"),
        kv("REQUEST_URI", "/path?q=1"),
        kv("SERVER_PROTOCOL", "HTTP/1.1"),
        kv("HTTP_HOST", "example.test"),
    ];
    run("plain", &base, "", None);
    let mut withHdrs = base.clone();
    withHdrs.push(kv("HTTP_X_SIMPLE", "one"));
    withHdrs.push(kv("HTTP_X_TWO_WORDS", "two"));
    withHdrs.push(kv("HTTP_CONTENT_TYPE", "forged/type"));
    withHdrs.push(kv("CONTENT_TYPE", "real/type"));
    run("headers", &withHdrs, "", None);
    let mut post = base.clone();
    post[0] = kv("REQUEST_METHOD", "POST");
    post.push(kv("CONTENT_TYPE", "application/x-www-form-urlencoded"));
    post.push(kv("CONTENT_LENGTH", "11"));
    run("post", &post, "field=value", None);
    let mut long = base.clone();
    long.push((s("HTTP_X_LONG"), strings::Repeat(s("v"), 300)));
    long.push((strings::Repeat(s("HTTP_K"), 30), s("longname")));
    run("long-values", &long, "", None);
    let mut empty = base.clone();
    empty.push(kv("HTTP_X_EMPTY", ""));
    empty.push(kv("", "empty-name"));
    run("empty-name-and-value", &empty, "", None);
    run(
        "truncated-pairs",
        &base,
        "",
        Some(|b: Vec<u8>| -> Vec<u8> {
            let mut out = b;
            let mut i = 0usize;
            while i + 8 < out.len() {
                let typ = out[i + 1];
                let clen = ((out[i + 4] as usize) << 8) | out[i + 5] as usize;
                let plen = out[i + 6] as usize;
                if typ == 4 && clen > 0 {
                    out[i + 8] = 0x7f;
                    break;
                }
                i += 8 + clen + plen;
            }
            return out;
        }),
    );
    run(
        "oversized-record",
        &base,
        "",
        Some(|b: Vec<u8>| -> Vec<u8> {
            let mut out = b;
            let mut i = 0usize;
            while i + 8 < out.len() {
                let typ = out[i + 1];
                let clen = ((out[i + 4] as usize) << 8) | out[i + 5] as usize;
                let plen = out[i + 6] as usize;
                if typ == 4 && clen > 0 {
                    out[i + 4] = 0xff;
                    out[i + 5] = 0xff;
                    break;
                }
                i += 8 + clen + plen;
            }
            return out;
        }),
    );
    run(
        "unknown-record-type",
        &base,
        "",
        Some(|b: Vec<u8>| -> Vec<u8> {
            let mut out = zzRecord(99, 1, b"junk");
            out.extend_from_slice(&b);
            return out;
        }),
    );
    let ln = *LN.Lock();
    let mut failed = *FAILED.Lock();
    if ln != GO.len() as int {
        fmt::Printf!(
            "[!!] produced %d lines, pinned %d
",
            ln,
            GO.len() as int
        );
        failed += 1;
    }
    if failed == 0 {
        fmt::Printf!("ok %d/%d\n", ln, ln);
        return;
    }
    fmt::Printf!("FAILED %d of %d\n", failed, ln);
    syscall::Exit(1);
}
