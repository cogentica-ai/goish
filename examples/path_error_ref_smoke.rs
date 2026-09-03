// path_error_ref_smoke — the errors real file operations return.
//
// Reference: Go 1.25.5 os, measured by tools/gen_path_error_ref.go.
// Every GO[] line is Go's verbatim output.
//
// os_error_ref_smoke already covers os's error PREDICATES, and covers
// them well — but every value it feeds them is built by hand
// (`pathErr("open", "/x", syscall::ENOENT)`). A hand-built PathError
// carries whatever the test author put in it. This smoke performs the
// actual operations — open a missing file, open a directory for
// writing, read a directory, remove what is not there, mkdir over an
// existing name, stat a missing path — and asks about the errors `os`
// itself produced.
//
// The distinction is not academic. Twice today a smoke was fully green
// while the function under it was broken for every value its callers
// actually pass, because the smoke's inputs were all constructed
// in-file (see common_read_error_ref_smoke and
// timeout_iface_ref_smoke, both of which now carry a real case).
//
// What a real operation exercises that a built value cannot: the Op
// string os chooses, the Path it records, the errno the kernel
// returned, and the MESSAGE that errno renders as — which is the table
// that had nine socket errnos all reading "errno" until a198b33. The
// line "open DIR/nope.txt: no such file or directory" is three
// independent pieces of the port agreeing.
//
// Deliberately NOT covered: a permission error. Opening a 0000 file
// fails for an ordinary user and SUCCEEDS for root, and CI containers
// are commonly root, so that line would report who ran the suite
// rather than anything about the port.

#![no_std]
#![no_main]
extern crate alloc;
extern crate goish;

use alloc::string::String;
use goish::errors;
use goish::fmt;
use goish::io::fs;
use goish::os;
use goish::string;

// Go's verbatim output.
const GO: [&str; 6] = [
    "open-missing     err=\"open DIR/nope.txt: no such file or directory\"       pathErr=true  op=\"open\" base=\"nope.txt\"   notExist=true  perm=false",
    "openfile-dir     err=\"open DIR: is a directory\"                           pathErr=true  op=\"open\" base=\"DIRBASE\"    notExist=false perm=false",
    "read-dir         err=\"read DIR: is a directory\"                           pathErr=true  op=\"read\" base=\"DIRBASE\"    notExist=false perm=false",
    "remove-missing   err=\"remove DIR/nope.txt: no such file or directory\"     pathErr=true  op=\"remove\" base=\"nope.txt\"   notExist=true  perm=false",
    "mkdir-exists     err=\"mkdir DIR/secret: file exists\"                      pathErr=true  op=\"mkdir\" base=\"secret\"     notExist=false perm=false",
    "stat-missing     err=\"stat DIR/nope.txt: no such file or directory\"       pathErr=true  op=\"stat\" base=\"nope.txt\"   notExist=true  perm=false",
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

static mut TMPDIR: Option<String> = None;

fn norm(s: goish::string) -> goish::string {
    let d = unsafe { (*core::ptr::addr_of!(TMPDIR)).clone() }.unwrap_or_default();
    let t: &str = s.as_ref();
    if d.is_empty() {
        return s.clone();
    }
    let out = t.replace(d.as_str(), "DIR");
    goish::string::from_bytes(out.as_bytes())
}

fn show(tag: &'static str, err: goish::error) {
    let pe = errors::As::<fs::PathError>(err.clone());
    let is_pe = pe.is_some();
    let (op, base) = match pe.as_ref() {
        Some(p) => {
            let d = unsafe { (*core::ptr::addr_of!(TMPDIR)).clone() }.unwrap_or_default();
            let ps: &str = p.Path.as_ref();
            let b = if ps == d.as_str() {
                string("DIRBASE")
            } else {
                goish::path::filepath::Base(p.Path.clone())
            };
            (p.Op.clone(), b)
        }
        None => (string(""), string("")),
    };
    let msg = if err.IsNil() {
        string("<nil>")
    } else {
        norm(err.Error())
    };
    chk(fmt::Sprintf!(
        "%-16s err=%-52q pathErr=%-5v op=%-6q base=%-12q notExist=%-5v perm=%v",
        string(tag),
        msg,
        is_pe,
        op,
        base,
        errors::Is(err.clone(), fs::ErrNotExist),
        errors::Is(err.clone(), fs::ErrPermission)
    ));
}

#[goish::main]
fn main() {
    let (dir, derr) = os::MkdirTemp(string(""), string("goishpe"));
    if !derr.IsNil() {
        fmt::Printf!("mkdirtemp: %v\n", derr);
        goish::os::Exit(1);
    }
    let d: &str = dir.as_ref();
    unsafe {
        TMPDIR = Some(String::from(d));
    }

    let mut nope = String::from(d);
    nope.push_str("/nope.txt");
    let nope_s = goish::string::from_bytes(nope.as_bytes());
    let mut secret = String::from(d);
    secret.push_str("/secret");
    let secret_s = goish::string::from_bytes(secret.as_bytes());

    let (_f, e) = os::Open(nope_s.clone());
    show("open-missing", e);

    let (_f, e) = os::OpenFile(dir.clone(), os::O_WRONLY, os::FileMode(0));
    show("openfile-dir", e);

    let (mut f, oerr) = os::Open(dir.clone());
    if oerr.IsNil() {
        let f = f.MustMut();
        let mut buf = goish::make!([]goish::byte, 4);
        let (_n, e) = f.Read(&mut buf);
        show("read-dir", e);
        let _ = f.Close();
    } else {
        show("read-dir", oerr);
    }

    // No permission case: opening a 0000 file fails for an ordinary
    // user and SUCCEEDS for root, and CI containers are commonly root,
    // so the line would differ by who ran it rather than by anything
    // about the port.
    let _ = os::WriteFile(secret_s.clone(), b"x".as_ref(), os::FileMode(0o644));

    let e = os::Remove(nope_s.clone());
    show("remove-missing", e);

    let e = os::Mkdir(secret_s.clone(), os::FileMode(0o755));
    show("mkdir-exists", e);

    let (_st, e) = os::Stat(nope_s.clone());
    show("stat-missing", e);

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
