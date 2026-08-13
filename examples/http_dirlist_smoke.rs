// http_dirlist_smoke — net/http's dirList (fs.go:139-178), the HTML
// directory index a FileServer serves when a request lands on a
// directory with no index.html.
//
// The expected page is Go 1.25.5 output byte for byte, produced by
// calling dirList over the same tree inside a writable GOROOT
// (scripts/goref.sh net/http).
//
// The file names are chosen to exercise the two escapes, which are
// DIFFERENT and easy to conflate:
//
//   * The href goes through url.URL{Path: name}.String(), so '?' and
//     '#' become %3F and %23. Without that, a file named "a?b#c.txt"
//     produces a link whose path stops at "a" and whose query and
//     fragment are the rest — the link simply does not work.
//   * The link TEXT goes through htmlReplacer, so "<script>.txt"
//     renders as "&lt;script&gt;.txt". Without that, a filename is an
//     XSS vector against anyone browsing the index.
//
// Entries are sorted by name, and a directory gets a trailing slash
// BEFORE both escapes are applied.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::net::http::fs::{dirList, FileSystem, NewDir};
use goish::net::http::httptest;
use goish::net::http::response::ResponseWriter;
use goish::os;
use goish::{convert, fmt, string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    let root = string("/tmp/goish_dirlist_smoke");
    let _ = os::RemoveAll(root.clone());
    let _ = os::MkdirAll(root.clone() + "/sub", 0o755);
    let _ = os::WriteFile(root.clone() + "/hello.txt", convert::bytes(string("hi")), 0o644);
    let _ = os::WriteFile(root.clone() + "/a?b#c.txt", convert::bytes(string("x")), 0o644);
    let _ = os::WriteFile(root.clone() + "/<script>.txt", convert::bytes(string("x")), 0o644);

    let want = "<!doctype html>\n\
                <meta name=\"viewport\" content=\"width=device-width\">\n\
                <pre>\n\
                <a href=\"%3Cscript%3E.txt\">&lt;script&gt;.txt</a>\n\
                <a href=\"a%3Fb%23c.txt\">a?b#c.txt</a>\n\
                <a href=\"hello.txt\">hello.txt</a>\n\
                <a href=\"sub/\">sub/</a>\n\
                </pre>\n";

    let d = NewDir(root.clone());
    let (f, oerr) = d.Open(string("/"));
    if oerr != goish::nil {
        fmt::Println!("setup: Dir.Open failed: ", oerr);
        let _ = os::RemoveAll(root);
        syscall::Exit(1);
    }

    let rec = httptest::NewRecorder();
    {
        let w: &(dyn ResponseWriter + Send + Sync + 'static) = &rec;
        dirList(w, goish::nilable_ref::nil(), &*f);
    }
    let _ = f.Close();

    // 1. The page matches Go byte for byte.
    {
        let got = string::from_bytes(&rec.Body());
        if got == want {
            fmt::Println!("[1] dirList page matches Go byte-for-byte  PASS");
        } else {
            fmt::Println!("[1] dirList page  FAIL got:\n", got);
            failed += 1;
        }
    }

    // 2. Content-Type is set before the body.
    {
        let ct = rec.Header().Get(string("Content-Type"));
        if ct == "text/html; charset=utf-8" {
            fmt::Println!("[2] Content-Type is text/html  PASS");
        } else {
            fmt::Println!("[2] Content-Type  FAIL got=", ct);
            failed += 1;
        }
    }

    // 3. The two escapes are distinct: the href is percent-encoded and
    //    the text is HTML-escaped, and neither leaks the other's form.
    {
        let got = string::from_bytes(&rec.Body());
        let href_ok = goish::strings::Contains(got.clone(), string("href=\"a%3Fb%23c.txt\""));
        let text_ok = goish::strings::Contains(got.clone(), string(">&lt;script&gt;.txt<"));
        let no_raw_script = !goish::strings::Contains(got.clone(), string(">​<script>.txt<"));
        if href_ok && text_ok && no_raw_script {
            fmt::Println!("[3] href percent-encoded, text HTML-escaped  PASS");
        } else {
            fmt::Println!("[3] escaping  FAIL href=", href_ok, " text=", text_ok);
            failed += 1;
        }
    }

    let _ = os::RemoveAll(root);

    if failed == 0 {
        fmt::Println!("ok 3/3");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL ", failed, " of 3");
        syscall::Exit(1);
    }
}
