// os_file_readdir_ref_smoke — File.ReadDir(n) batches and ends in EOF.
//
// The bounded form is the point: `f.ReadDir(2)` returns two entries,
// the NEXT call resumes where it stopped, and once the directory is
// drained it returns io.EOF. A reader that restarted, or that returned
// an empty slice with a nil error at the end, would loop forever.
//
// `n <= 0` reads everything and never returns io.EOF, which is why the
// first row asserts err=<nil> with all four entries — three files and
// a subdirectory, so IsDir is exercised in both states.
//
// goish had os.ReadDir (the package function) and File.Readdirnames,
// but not this method. It is ported through Go's own structure: ONE
// `readdir(n, mode)` walk that both Readdirnames and ReadDir delegate
// to, because the getdents buffer and its resume point must not be
// duplicated or the two callers drift apart.
//
// GO[] is the verbatim output of tools/gen_file_readdir_ref.go under
// scripts/goref.sh against Go 1.25.5.

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::os;
use goish::string;

static FAILED: AtomicUsize = AtomicUsize::new(0);
static SEEN: AtomicUsize = AtomicUsize::new(0);

static GO: [&str; 6] = [
    "all n=4 err=<nil> [a.txt:false b.txt:false c.txt:false sub:true]",
    "batch1 n=2 err=<nil>",
    "batch2 n=2 err=<nil>",
    "batch3 n=0 err=EOF (io.EOF=true)",
    "infos n=4 err=<nil> [a.txt:false:1 b.txt:false:1 c.txt:false:1 sub:true:4096]",
    "infos-after-drain n=0 err=EOF",
];

fn chk(got: goish::string) {
    let i = SEEN.fetch_add(1, Ordering::Relaxed);
    if i < GO.len() && got == string(GO[i]) {
        fmt::Printf!("ok   %s
", got);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!(
            "[!!] line %d
  got:  %s
  want: %s
",
            i as i64,
            got,
            string(if i < GO.len() { GO[i] } else { "" })
        );
    }
}

#[goish::main]
fn main() { goish::go!(stack(1024*1024), move || { run(); }); loop { goish::runtime::sched::Gosched(); } }

fn run() {
    let dir = string::from_static("/tmp/goish_rd_probe");
    let _ = os::RemoveAll(dir.clone());
    let _ = os::MkdirAll(dir.clone(), 0o755);
    for n in ["a.txt", "b.txt", "c.txt"].iter() {
        let _ = os::WriteFile(dir.clone() + string::from_static("/") + string::from_static(n),
            goish::bytes("x"), 0o644);
    }
    let _ = os::Mkdir(dir.clone() + string::from_static("/sub"), 0o755);

    let (mut f, _) = os::Open(dir.clone());
    let f = f.MustMut();
    let (all, err) = f.ReadDir(-1);
    let mut names: Vec<string> = Vec::new();
    let mut i = 0;
    while i < goish::len(&all) {
        names.push(fmt::Sprintf!("%s:%v", all[i].Name(), all[i].IsDir()));
        i += 1;
    }
    names.sort_by(|a, b| {
        let (x, y): (&str, &str) = (a.as_ref(), b.as_ref());
        x.cmp(y)
    });
    let mut joined = string::from_static("[");
    let mut k = 0;
    while k < names.len() {
        if k > 0 { joined = joined + string::from_static(" "); }
        joined = joined + names[k].clone();
        k += 1;
    }
    joined = joined + string::from_static("]");
    chk(fmt::Sprintf!("all n=%d err=%v %s", goish::len(&all) as i64, err, joined));
    let _ = f.Close();

    let (mut f2, _) = os::Open(dir.clone());
    let f2 = f2.MustMut();
    let (b1, e1) = f2.ReadDir(2);
    let (b2, e2) = f2.ReadDir(2);
    let (b3, e3) = f2.ReadDir(2);
    chk(fmt::Sprintf!("batch1 n=%d err=%v", goish::len(&b1) as i64, e1));
    chk(fmt::Sprintf!("batch2 n=%d err=%v", goish::len(&b2) as i64, e2));
    chk(fmt::Sprintf!("batch3 n=%d err=%v (io.EOF=%v)", goish::len(&b3) as i64, e3.clone(),
        goish::errors::Is(e3, goish::io::EOF)));
    let _ = f2.Close();

    // The deprecated Readdir: FileInfo values, lstat'd per entry.
    let (mut f3, _) = os::Open(dir.clone());
    let f3 = f3.MustMut();
    let (infos, ierr) = f3.Readdir(-1);
    let mut inames: Vec<string> = Vec::new();
    let mut j = 0;
    while j < goish::len(&infos) {
        inames.push(fmt::Sprintf!(
            "%s:%v:%d",
            infos[j].Name(),
            infos[j].IsDir(),
            infos[j].Size()
        ));
        j += 1;
    }
    inames.sort_by(|a, b| {
        let (x, y): (&str, &str) = (a.as_ref(), b.as_ref());
        x.cmp(y)
    });
    let mut ijoined = string::from_static("[");
    let mut m = 0;
    while m < inames.len() {
        if m > 0 {
            ijoined = ijoined + string::from_static(" ");
        }
        ijoined = ijoined + inames[m].clone();
        m += 1;
    }
    ijoined = ijoined + string::from_static("]");
    chk(fmt::Sprintf!(
        "infos n=%d err=%v %s",
        goish::len(&infos) as i64,
        ierr,
        ijoined
    ));
    let (i2, ierr2) = f3.Readdir(2);
    chk(fmt::Sprintf!(
        "infos-after-drain n=%d err=%v",
        goish::len(&i2) as i64,
        ierr2
    ));
    let _ = f3.Close();
    let _ = os::RemoveAll(dir);
    let f = FAILED.load(Ordering::Relaxed);
    let seen = SEEN.load(Ordering::Relaxed);
    // Both halves: nothing failed AND every row actually ran. Checking
    // only FAILED lets a smoke that asserts nothing report success —
    // which this one did, until the row count caught it.
    if f == 0 && seen == GO.len() {
        fmt::Printf!("\nok %d/%d\n", seen as i64, GO.len() as i64);
        goish::os::Exit(0);
    }
    fmt::Printf!("\nFAILED %d of %d (ran %d)\n", f as i64, GO.len() as i64, seen as i64);
    goish::os::Exit(1);
}
