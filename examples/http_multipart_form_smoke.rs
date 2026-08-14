// http_multipart_form_smoke — file uploads: multipart.Reader.ReadForm,
// Request.ParseMultipartForm and Request.FormFile.
//
// The body is built with goish's own multipart.Writer and parsed back,
// which is the round trip a real upload makes.
//
// Three properties are worth pinning, and each is a bug if it slips:
//
//   * values land in BOTH Form and PostForm. Go's comment cites issue
//     9305; a handler calling PostFormValue on a multipart upload sees
//     nothing if only Form is filled.
//   * the memory budget is enforced. goish keeps every part in memory
//     (its Reader is eager, so Go's spill-to-disk branch has nothing
//     to spill) — which makes the budget the ONLY thing standing
//     between a handler and an unbounded allocation.
//   * a missing file key is ErrMissingFile, not an empty reader that
//     silently yields zero bytes.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::errors;
use goish::fmt;
use goish::mime::multipart;
use goish::net::http;
use goish::string;

static PASSED: AtomicUsize = AtomicUsize::new(0);
static FAILED: AtomicUsize = AtomicUsize::new(0);

fn check(name: &'static str, ok: bool, detail: goish::string) {
    if ok {
        PASSED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("PASS: %s\n", name);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("FAIL: %s — %s\n", name, detail);
    }
}

/// Build a multipart body: two values (one repeated) and two files.
fn buildBody() -> (goish::string, goish::slice<goish::byte>) {
    // A shared writer: `Arc<sync::Mutex<W>>` implements io::Writer by
    // serialising each Write, which is how goish spells Go's habit of
    // passing `&buf` as an io.Writer and reading it back afterwards.
    let buf = alloc::sync::Arc::new(goish::sync::Mutex::new(goish::bytes::Buffer::new()));
    let mut w = multipart::NewWriter(buf.clone());
    let _ = w.WriteField(string("who"), string("ada"));
    let _ = w.WriteField(string("who"), string("grace"));
    let _ = w.WriteField(string("topic"), string("uploads"));
    let _ = w.WriteFile(
        string("doc"),
        string("notes.txt"),
        goish::bytes("the quick brown fox"),
    );
    let _ = w.WriteFile(
        string("doc"),
        string("second.txt"),
        goish::bytes("jumps over"),
    );
    let _ = w.Close();
    return (w.FormDataContentType(), buf.Lock().Bytes());
}

fn newUpload(ct: goish::string, body: goish::slice<goish::byte>) -> http::Request {
    let mut r = http::Request::default();
    r.Method = string("POST");
    r.Proto = string("HTTP/1.1");
    r.ProtoMajor = 1;
    r.ProtoMinor = 1;
    let (u, _) = http::url::Parse(string("http://example.com/upload"));
    r.URL = u;
    r.Header.Set(string("Content-Type"), ct);
    r.ContentLength = goish::builtin::len(&body) as i64;
    r.Body = http::Body::from_bytes(body);
    return r;
}

#[goish::main]
fn main() {
    goish::go!(stack(1024 * 1024), move || {
        run();
    });
    loop {
        goish::runtime::sched::Gosched();
    }
}

fn run() -> ! {
    let (ct, body) = buildBody();

    // ── ParseMultipartForm fills Form, PostForm and MultipartForm ──
    {
        let r = newUpload(ct.clone(), body.clone());
        let err = r.ParseMultipartForm(1 << 20);
        check(
            "ParseMultipartForm succeeds on a well-formed body",
            err.IsNil(),
            fmt::Sprintf!("%v", err),
        );
        check(
            "repeated values are kept in order",
            r.FormValue(string("who")) == "ada" && r.FormValue(string("topic")) == "uploads",
            fmt::Sprintf!("who=%q", r.FormValue(string("who"))),
        );
        check(
            "values reach PostForm too (Go issue 9305)",
            r.PostFormValue(string("who")) == "ada",
            fmt::Sprintf!("post who=%q", r.PostFormValue(string("who"))),
        );
        let f = r.MultipartForm();
        let n = match f.as_ref() {
            None => -1,
            Some(f) => {
                let (fhs, _) = f.File.Get(string("doc"));
                goish::builtin::len(&fhs) as i64
            }
        };
        check(
            "both files under one key are kept",
            n == 2,
            fmt::Sprintf!("files=%d", n),
        );
    }

    // ── FormFile opens the first file for a key ──
    {
        let r = newUpload(ct.clone(), body.clone());
        let (mut file, fh, err) = r.FormFile(string("doc"));
        let mut buf = goish::make!([]goish::byte, 64);
        let (n, _) = file.Read(&mut buf);
        let got = goish::string::from_bytes(&buf.slice(0, n));
        check(
            "FormFile returns the FIRST file, its name, size and content",
            err.IsNil()
                && fh.Filename == "notes.txt"
                && fh.Size == 19
                && got == "the quick brown fox",
            fmt::Sprintf!("name=%q size=%d got=%q", fh.Filename, fh.Size, got),
        );
        check(
            "the part's own Content-Type survives on the FileHeader",
            {
                let (v, _) = fh.Header.Get(string("Content-Type"));
                goish::builtin::len(&v) > 0
            },
            string(""),
        );
    }

    // ── a missing key is ErrMissingFile ──
    {
        let r = newUpload(ct.clone(), body.clone());
        let (_, _, err) = r.FormFile(string("nope"));
        check(
            "a missing file key is ErrMissingFile, not an empty reader",
            errors::Is(err.clone(), http::ErrMissingFile),
            fmt::Sprintf!("%v", err),
        );
    }

    // ── the memory budget is enforced ──
    //
    // With every part in memory, this bound is the only thing between
    // a handler and an unbounded allocation. maxMemory=1 leaves the
    // 10MB slop for values but nothing for a 19-byte file.
    {
        let r = newUpload(ct.clone(), body.clone());
        let err = r.ParseMultipartForm(1);
        check(
            "a file larger than maxMemory is ErrMessageTooLarge",
            errors::Is(err.clone(), multipart::formdata::ErrMessageTooLarge),
            fmt::Sprintf!("%v", err),
        );
    }

    // ── a second call is a no-op, not a re-parse ──
    {
        let r = newUpload(ct, body);
        let _ = r.ParseMultipartForm(1 << 20);
        let _ = r.ParseMultipartForm(1 << 20);
        let f = r.MultipartForm();
        let n = match f.as_ref() {
            None => -1,
            Some(f) => {
                let (v, _) = f.Value.Get(string("who"));
                goish::builtin::len(&v) as i64
            }
        };
        check(
            "parsing twice does not double the values",
            n == 2 && r.FormValue(string("who")) == "ada",
            fmt::Sprintf!("who count=%d", n),
        );
    }

    let p = PASSED.load(Ordering::Relaxed);
    let f = FAILED.load(Ordering::Relaxed);
    fmt::Printf!("\n%d passed, %d failed\n", p as i64, f as i64);
    if f == 0 {
        fmt::Printf!("HTTP_MULTIPART_FORM_SMOKE_OK\n");
        goish::os::Exit(0);
    }
    fmt::Printf!("HTTP_MULTIPART_FORM_SMOKE_FAIL\n");
    goish::os::Exit(1);
}
