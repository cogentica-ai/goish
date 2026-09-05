// handlers_ref_smoke — the handler helpers, against a running Go.
//
// Reference: Go 1.25.5 net/http, measured by tools/gen_handlers_ref.go.
// Every GO[] line is Go's verbatim output for the same call.
//
// These are the five helpers an application reaches for without
// thinking: Error, Redirect, NotFound, StripPrefix, MaxBytesHandler.
// Each writes a response on the caller's behalf, so each is a place
// where a port can quietly emit something the caller never inspected.
//
// Two defects, both of the same shape — the safety behaviour was
// present in one path and missing in the path next to it.
//
//   MaxBytesHandler TRUNCATED SILENTLY. A handler under a byte cap
//   read the first n bytes and got err == nil, so it could not tell a
//   body that fitted from one that had been cut, and would go on to
//   parse, verify or store a fragment as though it were the whole
//   request. goish already had a correct MaxBytesReader — verified
//   against Go down to the read-one-extra-byte trick that separates
//   "exactly at the limit" from "one over" — and MaxBytesHandler
//   simply did not use it. It now does, layered over the materialised
//   body, so the handler gets Go's MaxBytesError.
//
//   NotFoundHandler SKIPPED ITS HEADERS. Go's NotFoundHandler is
//   literally HandlerFunc(NotFound), so it goes through Error and gets
//   Content-Type and X-Content-Type-Options: nosniff. goish's wrote
//   the status and body directly: the same visible bytes, neither
//   header. The nosniff is the point of Error setting it — an error
//   body must not be sniffed as HTML. `NotFound` itself was correct,
//   which is why this stayed hidden; it only shows through
//   `NotFoundHandler()` and StripPrefix's not-matched path, both of
//   which route through the other one.
//
// Redirect's HTML escaping was already right: the target URL is
// HTML-escaped into the `<a href>` body, so a redirect to a URL
// containing a quote and a <script> tag renders as entities rather
// than markup. The Location HEADER keeps CR and LF raw — that is Go's
// behaviour too, because it is the header writer, not Redirect, that
// neutralises them.
//
// "Redirect was already right" is what this header used to say, and
// it was wrong twice, in ways the nine cases above could not reach
// because every one of them was ASCII with no Content-Type set:
//
//   THE LOCATION HEADER WAS NOT ESCAPED. Go writes
//   hexEscapeNonASCII(url), percent-encoding every byte >= 0x80.
//   goish wrote the raw url, so a redirect to a UTF-8 path differed
//   from Go on its first non-ASCII byte. `hexEscapeNonASCII` was ported,
//   anchored, and covered by http_helpers_smoke — and Redirect, its
//   only caller in Go, did not call it. The intended call was even
//   written out in a comment at the site.
//
//   hadCT TESTED THE VALUE, NOT THE KEY. Go uses
//   `_, hadCT := h["Content-Type"]`. A handler that set an empty
//   Content-Type before redirecting had it overwritten and got an
//   HTML body appended, where Go leaves both alone. `Header::has`
//   already existed for exactly this distinction; Redirect used
//   `Get(...).Len() > 0`.
//
// Note what the escaping rule is not: space and DEL stay raw. The
// boundary is 0x80, not "non-printable", which is why redirect-space
// and redirect-del are pinned next to the ones that do change.

#![no_std]
#![no_main]
extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use goish::fmt;
use goish::net::http;
use goish::net::http::httptest;
use goish::string;

// Go's verbatim output.
const GO: [&str; 29] = [
    "error-plain                code=500 ct=\"text/plain; charset=utf-8\" loc=\"\" nosniff=\"nosniff\" body=\"boom\\n\"",
    "error-html                 code=400 ct=\"text/plain; charset=utf-8\" loc=\"\" nosniff=\"nosniff\" body=\"<script>x</script>\\n\"",
    "error-empty                code=404 ct=\"text/plain; charset=utf-8\" loc=\"\" nosniff=\"nosniff\" body=\"\\n\"",
    "error-newline              code=500 ct=\"text/plain; charset=utf-8\" loc=\"\" nosniff=\"nosniff\" body=\"a\\nb\\n\"",
    "redirect-simple            code=302 ct=\"text/html; charset=utf-8\" loc=\"/x\" nosniff=\"\" body=\"<a href=\\\"/x\\\">Found</a>.\\n\\n\"",
    "redirect-quote             code=302 ct=\"text/html; charset=utf-8\" loc=\"/x\\\"><script>alert(1)</script>\" nosniff=\"\" body=\"<a href=\\\"/x&#34;&gt;&lt;script&gt;alert(1)&lt;/script&gt;\\\">Found</a>.\\n\\n\"",
    "redirect-amp               code=302 ct=\"text/html; charset=utf-8\" loc=\"/x?a=1&b=2\" nosniff=\"\" body=\"<a href=\\\"/x?a=1&amp;b=2\\\">Found</a>.\\n\\n\"",
    "redirect-abs               code=301 ct=\"text/html; charset=utf-8\" loc=\"https://example.com/x\" nosniff=\"\" body=\"<a href=\\\"https://example.com/x\\\">Moved Permanently</a>.\\n\\n\"",
    "redirect-post              code=303 ct=\"\" loc=\"/x\" nosniff=\"\" body=\"\"",
    "redirect-307               code=307 ct=\"text/html; charset=utf-8\" loc=\"/x\" nosniff=\"\" body=\"<a href=\\\"/x\\\">Temporary Redirect</a>.\\n\\n\"",
    "redirect-empty             code=302 ct=\"text/html; charset=utf-8\" loc=\"/dir/\" nosniff=\"\" body=\"<a href=\\\"/dir/\\\">Found</a>.\\n\\n\"",
    "redirect-rel-dots          code=302 ct=\"text/html; charset=utf-8\" loc=\"/x\" nosniff=\"\" body=\"<a href=\\\"/x\\\">Found</a>.\\n\\n\"",
    "redirect-newline           code=302 ct=\"text/html; charset=utf-8\" loc=\"/x\\r\\nSet-Cookie: a=b\" nosniff=\"\" body=\"<a href=\\\"/x\\r\\nSet-Cookie: a=b\\\">Found</a>.\\n\\n\"",
    "redirect-utf8              code=302 ct=\"text/html; charset=utf-8\" loc=\"/caf%c3%a9\" nosniff=\"\" body=\"<a href=\\\"/café\\\">Found</a>.\\n\\n\"",
    "redirect-utf8-query        code=302 ct=\"text/html; charset=utf-8\" loc=\"/s?q=%c3%a9t%c3%a9\" nosniff=\"\" body=\"<a href=\\\"/s?q=été\\\">Found</a>.\\n\\n\"",
    "redirect-raw-high          code=302 ct=\"text/html; charset=utf-8\" loc=\"/%ff%fe\" nosniff=\"\" body=\"<a href=\\\"/\\xff\\xfe\\\">Found</a>.\\n\\n\"",
    "redirect-space             code=302 ct=\"text/html; charset=utf-8\" loc=\"/a b\" nosniff=\"\" body=\"<a href=\\\"/a b\\\">Found</a>.\\n\\n\"",
    "redirect-del               code=302 ct=\"text/html; charset=utf-8\" loc=\"/a\\x7fb\" nosniff=\"\" body=\"<a href=\\\"/a\\x7fb\\\">Found</a>.\\n\\n\"",
    "redirect-abs-utf8          code=302 ct=\"text/html; charset=utf-8\" loc=\"https://example.com/%c3%bc\" nosniff=\"\" body=\"<a href=\\\"https://example.com/ü\\\">Found</a>.\\n\\n\"",
    "redirect-pct-already       code=302 ct=\"text/html; charset=utf-8\" loc=\"/caf%C3%A9\" nosniff=\"\" body=\"<a href=\\\"/caf%C3%A9\\\">Found</a>.\\n\\n\"",
    "redirect-empty-ct          code=302 ct=\"\" loc=\"/x\" nosniff=\"\" body=\"\"",
    "notfound                   code=404 ct=\"text/plain; charset=utf-8\" loc=\"\" nosniff=\"nosniff\" body=\"404 page not found\\n\"",
    "strip-match                code=200 ct=\"text/plain; charset=utf-8\" loc=\"\" nosniff=\"\" body=\"path=\\\"/v1/x\\\" rawpath=\\\"\\\"\"",
    "strip-nomatch              code=404 ct=\"text/plain; charset=utf-8\" loc=\"\" nosniff=\"nosniff\" body=\"404 page not found\\n\"",
    "strip-exact                code=200 ct=\"text/plain; charset=utf-8\" loc=\"\" nosniff=\"\" body=\"path=\\\"\\\" rawpath=\\\"\\\"\"",
    "strip-empty                code=200 ct=\"text/plain; charset=utf-8\" loc=\"\" nosniff=\"\" body=\"path=\\\"/x\\\" rawpath=\\\"\\\"\"",
    "strip-escaped              code=200 ct=\"text/plain; charset=utf-8\" loc=\"\" nosniff=\"\" body=\"path=\\\"/c\\\" rawpath=\\\"\\\"\"",
    "maxbytes-under             code=200 ct=\"text/plain; charset=utf-8\" loc=\"\" nosniff=\"\" body=\"read=\\\"abc\\\" err=<nil>\"",
    "maxbytes-over              code=200 ct=\"text/plain; charset=utf-8\" loc=\"\" nosniff=\"\" body=\"read=\\\"ab\\\" err=http: request body too large\"",
];

static FAILED: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static LN: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

fn chk(got: goish::string) {
    use core::sync::atomic::Ordering;
    let i = LN.fetch_add(1, Ordering::Relaxed);
    let g: &str = got.as_ref();
    if i >= GO.len() {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("[!!] extra line %d: %s\n", i as i64, got);
        return;
    }
    if g == GO[i] {
        fmt::Printf!("ok   %s\n", got);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!(
            "[!!] line %d\n  got:  %s\n  want: %s\n",
            i as i64,
            got,
            string(GO[i])
        );
    }
}

fn dump(label: &'static str, rec: &httptest::ResponseRecorder) {
    let h = rec.HeaderMap();
    chk(fmt::Sprintf!(
        "%-26s code=%d ct=%q loc=%q nosniff=%q body=%q",
        string(label),
        rec.Code(),
        h.Get(string("Content-Type")),
        h.Get(string("Location")),
        h.Get(string("X-Content-Type-Options")),
        goish::string::from_bytes(&rec.Body())
    ));
}

#[goish::main]
fn main() {
    // ── http.Error ──
    let errs: [(&'static str, &str, goish::int); 4] = [
        ("error-plain", "boom", 500),
        ("error-html", "<script>x</script>", 400),
        ("error-empty", "", 404),
        ("error-newline", "a\nb", 500),
    ];
    for (name, msg, code) in errs.iter() {
        let rec = httptest::NewRecorder();
        http::Error(&rec, goish::string::from_bytes(msg.as_bytes()), *code);
        dump(name, &rec);
    }

    // ── http.Redirect ──
    let reds: [(&'static str, &str, goish::int, &str); 9] = [
        ("redirect-simple", "/x", 302, "GET"),
        (
            "redirect-quote",
            "/x\"><script>alert(1)</script>",
            302,
            "GET",
        ),
        ("redirect-amp", "/x?a=1&b=2", 302, "GET"),
        ("redirect-abs", "https://example.com/x", 301, "GET"),
        ("redirect-post", "/x", 303, "POST"),
        ("redirect-307", "/x", 307, "GET"),
        ("redirect-empty", "", 302, "GET"),
        ("redirect-rel-dots", "../x", 302, "GET"),
        ("redirect-newline", "/x\r\nSet-Cookie: a=b", 302, "GET"),
    ];
    for (name, url, code, method) in reds.iter() {
        let rec = httptest::NewRecorder();
        let req = httptest::NewRequest(
            goish::string::from_bytes(method.as_bytes()),
            string("/dir/page"),
            goish::nil,
        );
        http::Redirect(&rec, &req, goish::string::from_bytes(url.as_bytes()), *code);
        dump(name, &rec);
    }

    // ── Redirect with non-ASCII in the target ──
    //
    // Byte strings, not &str: `redirect-raw-high` is deliberately
    // invalid UTF-8, which is the case that separates "escape bytes
    // >= 0x80" from "escape non-ASCII characters".
    let hi: [(&'static str, &'static [u8]); 7] = [
        ("redirect-utf8", "/caf\u{e9}".as_bytes()),
        ("redirect-utf8-query", "/s?q=\u{e9}t\u{e9}".as_bytes()),
        ("redirect-raw-high", b"/\xff\xfe"),
        ("redirect-space", b"/a b"),
        ("redirect-del", b"/a\x7fb"),
        ("redirect-abs-utf8", "https://example.com/\u{fc}".as_bytes()),
        ("redirect-pct-already", b"/caf%C3%A9"),
    ];
    for (name, url) in hi.iter() {
        let rec = httptest::NewRecorder();
        let req = httptest::NewRequest(string("GET"), string("/dir/page"), goish::nil);
        http::Redirect(&rec, &req, goish::string::from_bytes(url), 302);
        dump(name, &rec);
    }

    // Content-Type present but EMPTY. Go tests key presence, so it
    // leaves the header alone and writes no body; asking whether the
    // value is non-empty gets both wrong at once.
    {
        let rec = httptest::NewRecorder();
        // Through the ResponseWriter handle, not HeaderMap(): the
        // latter hands back a snapshot, so a Set on it goes into a
        // copy and the case silently tests nothing.
        http::ResponseWriter::Header(&rec).Set(string("Content-Type"), string(""));
        let req = httptest::NewRequest(string("GET"), string("/dir/page"), goish::nil);
        http::Redirect(&rec, &req, string("/x"), 302);
        dump("redirect-empty-ct", &rec);
    }

    // ── NotFound ──
    {
        let rec = httptest::NewRecorder();
        let req = httptest::NewRequest(string("GET"), string("/nope"), goish::nil);
        http::NotFound(&rec, &req);
        dump("notfound", &rec);
    }

    // ── StripPrefix ──
    let strips: [(&'static str, &str, &str); 5] = [
        ("strip-match", "/api", "/api/v1/x"),
        ("strip-nomatch", "/api", "/other/x"),
        ("strip-exact", "/api", "/api"),
        ("strip-empty", "", "/x"),
        ("strip-escaped", "/a b", "/a%20b/c"),
    ];
    for (name, prefix, path) in strips.iter() {
        let rec = httptest::NewRecorder();
        let h = http::StripPrefix(
            goish::string::from_bytes(prefix.as_bytes()),
            http::HandlerFunc(
                move |w: &(dyn http::ResponseWriter + Send + Sync + 'static), r: &http::Request| {
                    let _ = w.Write(goish::convert::bytes(fmt::Sprintf!(
                        "path=%q rawpath=%q",
                        r.URL.Path,
                        r.URL.RawPath
                    )));
                },
            ),
        );
        let req = httptest::NewRequest(
            string("GET"),
            goish::string::from_bytes(path.as_bytes()),
            goish::nil,
        );
        h.ServeHTTP(&rec, &req);
        dump(name, &rec);
    }

    // ── MaxBytesHandler ──
    let maxb: [(&'static str, goish::int, &str); 2] = [
        ("maxbytes-under", 10, "abc"),
        ("maxbytes-over", 2, "abcdef"),
    ];
    for (name, n, body) in maxb.iter() {
        let rec = httptest::NewRecorder();
        let inner: Arc<dyn http::Handler> = Arc::new(http::HandlerFunc(
            move |w: &(dyn http::ResponseWriter + Send + Sync + 'static), r: &http::Request| {
                let mut b = r.Body.clone();
                let (data, err) = goish::io::ReadAll(&mut b);
                let _ = w.Write(goish::convert::bytes(fmt::Sprintf!(
                    "read=%q err=%v",
                    goish::string::from_bytes(&data),
                    err
                )));
            },
        ));
        let h = http::MaxBytesHandler(inner, *n);
        let req = httptest::NewRequest(
            string("POST"),
            string("/x"),
            goish::slice::<goish::byte>::__from_vec(body.as_bytes().to_vec()),
        );
        h.ServeHTTP(&rec, &req);
        dump(name, &rec);
    }

    use core::sync::atomic::Ordering;
    let f = FAILED.load(Ordering::Relaxed);
    let n = LN.load(Ordering::Relaxed);
    if f == 0 && n == GO.len() {
        fmt::Printf!("\nok %d/%d\n", n as i64, GO.len() as i64);
        goish::os::Exit(0);
    }
    fmt::Printf!(
        "\nFAILED %d of %d (%d lines)\n",
        f as i64,
        GO.len() as i64,
        n as i64
    );
    goish::os::Exit(1);
}
