// os_dirfs_ref_smoke — os.DirFS's join is a sandbox boundary, against
// Go 1.25.5.
//
// Go enforces the boundary in dirFS.join (os/file.go) with two checks
// goish was missing:
//
//   * an EMPTY root is refused — "os: DirFS with empty root". Without
//     it the join produces "/" + name, an absolute path from the
//     filesystem ROOT rather than a contained one, so DirFS("") reads
//     anything the process can.
//
//   * the name goes through filepathlite.Localize, which is
//     fs.ValidPath AND a rejection of any embedded NUL. A name
//     carrying a NUL passes ValidPath — it checks path elements, not
//     bytes — and is then truncated at the C string boundary by the
//     kernel, so the file OPENED is not the file VALIDATED. "f\0junk"
//     validates as one name and opens "f".
//
// The dotdot and absolute rows are the checks that were already
// present, pinned so the new ones cannot be implemented by loosening
// them.
//
// Reference: tools/gen_os_dirfs_ref.go via scripts/goref.sh.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use goish::gostring::string;
use goish::{fmt, int, os};

const GO: [&str; 6] = [
    "ok                 ok \"inside\\n\"",
    "trailing-slash     ok \"inside\\n\"",
    "empty-root         err=\"open f: os: DirFS with empty root\"",
    "nul-in-name        err=\"open f\\x00ignored: invalid argument\"",
    "dotdot             err=\"open ../etc/hostname: invalid argument\"",
    "absolute           err=\"open /etc/hostname: invalid argument\"",
];

static mut BAD: usize = 0;

fn chk(ln: &mut usize, got: &string) {
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line: %q\n", got);
        unsafe { BAD += 1 };
        *ln += 1;
        return;
    }
    let want = string::from(GO[*ln]);
    if got.clone() == want {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        unsafe { BAD += 1 };
        fmt::Printf!("[!!] goish: %q\n", got);
        fmt::Printf!("     go   : %q\n", want);
    }
    *ln += 1;
}

const ROOT: &str = "/tmp/goish_os_dirfs_ref";

fn show(ln: &mut usize, name: &str, dir: &string, open: &string) {
    let fsys = os::DirFS(dir.clone());
    let (f, err) = fsys.Open(open.clone());
    if !err.IsNil() {
        chk(
            ln,
            &fmt::Sprintf!("%-18s err=%q", string::from(name), err.Error()),
        );
        return;
    }
    let mut b = goish::slice::<goish::byte>::__from_vec(alloc::vec![0u8; 32]);
    let (n, _) = f.Read(&mut b);
    let mut got: alloc::vec::Vec<goish::byte> = alloc::vec::Vec::new();
    let mut i: int = 0;
    while i < n {
        got.push(b[i]);
        i += 1;
    }
    let _ = f.Close();
    chk(
        ln,
        &fmt::Sprintf!(
            "%-18s ok %q",
            string::from(name),
            string::from_bytes(&got)
        ),
    );
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;
    let root = string::from(ROOT);
    let _ = os::MkdirAll(root.clone(), 0o755 as int);
    let werr = os::WriteFile(
        string::from(ROOT) + string::from("/f"),
        b"inside\n",
        0o644 as int,
    );
    if !werr.IsNil() {
        fmt::Printf!("[!!] setup: %v\n", werr);
        os::Exit(1);
    }

    show(&mut ln, "ok", &root, &string::from("f"));
    show(&mut ln, "trailing-slash", &(root.clone() + string::from("/")), &string::from("f"));
    show(&mut ln, "empty-root", &string::new(), &string::from("f"));
    show(&mut ln, "nul-in-name", &root, &string::from_bytes(b"f\0ignored"));
    show(&mut ln, "dotdot", &root, &string::from("../etc/hostname"));
    show(&mut ln, "absolute", &root, &string::from("/etc/hostname"));

    let _ = os::RemoveAll(root);

    if ln != GO.len() {
        fmt::Printf!("[!!] line count mismatch with the Go reference\n");
        unsafe { BAD += 1 };
    }
    let bad = unsafe { BAD };
    if bad != 0 {
        fmt::Printf!("[!!] %d row(s) diverge from Go\n", bad as i64);
        os::Exit(1);
    }
    os::Exit(0);
}
