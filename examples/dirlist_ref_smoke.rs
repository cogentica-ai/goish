// dirlist_ref_smoke — directory listings and file-server paths.
//
// Reference: Go 1.25.5 net/http, measured by tools/gen_dirlist_ref.go
// against a real temp directory. Every GO[] line is Go's verbatim
// output.
//
// Two dangerous surfaces in one handler, neither previously diffed
// against a running Go. goish matches on all 24 lines.
//
// THE LISTING IS THE XSS SURFACE, and the reason it is worth pinning
// is that each entry needs TWO DIFFERENT escapings of the same
// filename, in the same line:
//
//   <a href="%3Cscript%3Ealert%281%29.txt">&lt;script&gt;alert(1).txt</a>
//
// The href is URL-escaped; the link text is HTML-escaped. Using the
// wrong one in either slot produces something that looks almost right
// and is broken: HTML-escaping the href gives a link that 404s, and
// URL-escaping the text renders %3Cscript%3E to the reader. Using
// NEITHER on the text is a stored XSS — the filename is attacker-
// controlled wherever uploads land in a served directory.
//
// The entries are chosen so the two escapings disagree in different
// ways. "amp&sym.txt" keeps its & RAW in the href (PathEscape leaves
// it) but becomes &amp; in the text. "percent%20.txt" is DOUBLE-
// escaped in the href, to %2520, because the literal percent in the
// name must survive being read back as a URL. Quotes become &#34; and
// &#39; in the text — numeric entities, not the named ones.
//
// THE PATHS ARE THE TRAVERSAL SURFACE. Three spellings of the same
// escape attempt — "/../etc/passwd", "/..%2fetc%2fpasswd" and
// "/%2e%2e/etc/passwd" — all answer 404, which is the point: the
// second and third only work as an attack if the path is decoded
// before it is cleaned, so a port that cleans first and decodes second
// serves /etc/passwd while looking correct on the first case.
//
// The redirects are pinned because they are relative and easy to get
// subtly wrong: "/sub" -> "sub/", "/sub/index.html" -> "./" (Go hides
// the index filename), and "/plain.txt/" -> "../plain.txt".

#![no_std]
#![no_main]
extern crate alloc;
extern crate goish;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use goish::fmt;
use goish::io::{Closer, Reader, Writer};
use goish::net;
use goish::net::http;
use goish::os;
use goish::{go, string, time};

// Go's verbatim output.
const GO: [&str; 24] = [
    "list \"<a href=\\\"%3Cscript%3Ealert%281%29.txt\\\">&lt;script&gt;alert(1).txt</a>\"",
    "list \"<a href=\\\"amp&sym.txt\\\">amp&amp;sym.txt</a>\"",
    "list \"<a href=\\\"hash%23frag.txt\\\">hash#frag.txt</a>\"",
    "list \"<a href=\\\"h%C3%A9llo.txt\\\">héllo.txt</a>\"",
    "list \"<a href=\\\"percent%2520.txt\\\">percent%20.txt</a>\"",
    "list \"<a href=\\\"plain.txt\\\">plain.txt</a>\"",
    "list \"<a href=\\\"question%3Fq=1.txt\\\">question?q=1.txt</a>\"",
    "list \"<a href=\\\"quote%22and%27apos.txt\\\">quote&#34;and&#39;apos.txt</a>\"",
    "list \"<a href=\\\"sub/\\\">sub/</a>\"",
    "list \"<a href=\\\"with%20space.txt\\\">with space.txt</a>\"",
    "list-ct \"text/html; charset=utf-8\"",
    "path \"/plain.txt\"           200 loc=\"\"           body=\"x\"",
    "path \"/sub\"                 301 loc=\"sub/\"       body=\"\"",
    "path \"/sub/\"                200 loc=\"\"           body=\"INDEX\"",
    "path \"/sub/index.html\"      301 loc=\"./\"         body=\"\"",
    "path \"/../etc/passwd\"       404 loc=\"\"           body=\"404 page not found\\n\"",
    "path \"/..%2fetc%2fpasswd\"   404 loc=\"\"           body=\"404 page not found\\n\"",
    "path \"/%2e%2e/etc/passwd\"   404 loc=\"\"           body=\"404 page not found\\n\"",
    "path \"/./plain.txt\"         200 loc=\"\"           body=\"x\"",
    "path \"//plain.txt\"          200 loc=\"\"           body=\"x\"",
    "path \"/nonexistent.txt\"     404 loc=\"\"           body=\"404 page not found\\n\"",
    "path \"/plain.txt/\"          301 loc=\"../plain.txt\" body=\"\"",
    "path \"/with%20space.txt\"    200 loc=\"\"           body=\"x\"",
    "path \"/h%C3%A9llo.txt\"      200 loc=\"\"           body=\"x\"",
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
            goish::string(GO[i])
        );
    }
}

fn ascii(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len());
    for &c in b.iter() {
        s.push(c as char);
    }
    s
}

fn req_raw(port: goish::int, path: &str) -> goish::string {
    let addr = fmt::Sprintf!("127.0.0.1:%d", port as i64);
    let (mut c, e) = net::Dial(string("tcp"), addr);
    if !e.IsNil() {
        return string("");
    }
    let _ = c.SetReadDeadline(time::Now().Add(time::Duration(700 * 1_000_000)));
    let mut r = String::from("GET ");
    r.push_str(path);
    r.push_str(" HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    let _ = c.Write(goish::slice::<goish::byte>::__from_vec(r.into_bytes()));
    let mut out: Vec<u8> = Vec::new();
    let mut buf = goish::make!([]goish::byte, 4096);
    while out.len() < 16384 {
        let (n, re) = c.Read(&mut buf);
        if n > 0 {
            for i in 0..n {
                out.push(buf[i]);
            }
        }
        if !re.IsNil() || n == 0 {
            break;
        }
    }
    let _ = c.Close();
    goish::string::from_bytes(&out)
}

fn hdr(raw: &str, name: &str) -> goish::string {
    for ln in raw.split("\r\n") {
        if ln.is_empty() {
            break;
        }
        let mut want = name.to_ascii_lowercase();
        want.push(':');
        if ln.to_ascii_lowercase().starts_with(&want) {
            return goish::string::from_bytes(ln[name.len() + 1..].trim().as_bytes());
        }
    }
    string("")
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

fn run() {
    let (dir, derr) = os::MkdirTemp(string(""), string("goishdl"));
    if !derr.IsNil() {
        fmt::Printf!("mkdirtemp: %v\n", derr);
        goish::os::Exit(1);
    }
    let d: &str = dir.as_ref();

    let names: [&str; 9] = [
        "plain.txt",
        "with space.txt",
        "<script>alert(1).txt",
        "quote\"and'apos.txt",
        "amp&sym.txt",
        "h\u{e9}llo.txt",
        "hash#frag.txt",
        "question?q=1.txt",
        "percent%20.txt",
    ];
    for n in names.iter() {
        let mut p = String::from(d);
        p.push('/');
        p.push_str(n);
        let _ = os::WriteFile(
            goish::string::from_bytes(p.as_bytes()),
            b"x".as_ref(),
            os::FileMode(0o644),
        );
    }
    let mut sub = String::from(d);
    sub.push_str("/sub");
    let _ = os::Mkdir(
        goish::string::from_bytes(sub.as_bytes()),
        os::FileMode(0o755),
    );
    let mut idx = sub.clone();
    idx.push_str("/index.html");
    let _ = os::WriteFile(
        goish::string::from_bytes(idx.as_bytes()),
        b"INDEX".as_ref(),
        os::FileMode(0o644),
    );

    let fsh = http::FileServer(Arc::new(http::NewDir(dir.clone())));
    let srv = Arc::new(http::Server {
        Handler: fsh,
        ..Default::default()
    });
    let (ln, le) = net::Listen(string("tcp"), string("127.0.0.1:0"));
    if !le.IsNil() {
        fmt::Printf!("listen: %v\n", le);
        goish::os::Exit(1);
    }
    let port = ln.Addr().Port;
    {
        let s2 = srv.clone();
        go!(stack(1024 * 1024), move || {
            let _ = s2.Serve(ln);
        });
    }
    time::Sleep(time::Duration(150 * 1_000_000));

    // The listing itself — the escaping surface.
    let raw = req_raw(port, "/");
    let rs: &str = raw.as_ref();
    let body = match rs.find("\r\n\r\n") {
        Some(i) => &rs[i + 4..],
        None => "",
    };
    for ln in body.split('\n') {
        if ln.contains("<a href=") {
            chk(fmt::Sprintf!(
                "list %q",
                goish::string::from_bytes(ln.trim().as_bytes())
            ));
        }
    }
    chk(fmt::Sprintf!("list-ct %q", hdr(rs, "Content-Type")));

    let paths: [&str; 13] = [
        "/plain.txt",
        "/sub",
        "/sub/",
        "/sub/index.html",
        "/../etc/passwd",
        "/..%2fetc%2fpasswd",
        "/%2e%2e/etc/passwd",
        "/./plain.txt",
        "//plain.txt",
        "/nonexistent.txt",
        "/plain.txt/",
        "/with%20space.txt",
        "/h%C3%A9llo.txt",
    ];
    for p in paths.iter() {
        let raw = req_raw(port, p);
        let rs: &str = raw.as_ref();
        let code = match rs.find(' ') {
            Some(i) if rs.len() > i + 4 => &rs[i + 1..i + 4],
            _ => "000",
        };
        let mut b = match rs.find("\r\n\r\n") {
            Some(i) => &rs[i + 4..],
            None => "",
        };
        if b.len() > 24 {
            b = &b[..24];
        }
        chk(fmt::Sprintf!(
            "path %-22q %s loc=%-12q body=%q",
            goish::string::from_bytes(p.as_bytes()),
            goish::string::from_bytes(code.as_bytes()),
            hdr(rs, "Location"),
            goish::string::from_bytes(b.as_bytes())
        ));
    }
    let _ = os::RemoveAll(dir);

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
