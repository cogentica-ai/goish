// go: file io/ioutil/tempfile.go decls: TempFile, TempDir

use crate::convert::uint8 as touint8;
use crate::error;

// go: sdk 1.25.5 io/ioutil/tempfile.go:43-45 TempDir
/// `TempDir(dir, pattern) (name string, err error)` —
/// Go 1.16+ moved to `os.MkdirTemp`. Slim port: create
/// `<dir>/<pattern><N>` with a process-local counter for
/// uniqueness. Real `mkstemp(3)`-grade collision-avoidance is
/// deferred (sufficient for short-lived test/scratch dirs).
pub fn TempDir<S: Into<crate::string>, S2: Into<crate::string>>(
    dir: S,
    pattern: S2,
) -> (crate::string, error) {
    let dir: crate::string = dir.into();
    let pattern: crate::string = pattern.into();
    let base = if dir.Len() == 0 {
        crate::os::TempDir()
    } else {
        dir
    };

    static NEXT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    let n = NEXT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);

    let mut path: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    path.extend_from_slice(base.as_bytes());
    if !path.ends_with(b"/") {
        path.push(b'/');
    }
    path.extend_from_slice(pattern.as_bytes());
    append_u64(&mut path, n);

    let name = crate::string::from_bytes(&path);
    let err = crate::os::Mkdir(name.clone(), 0o700);
    return (name, err);
}

// go: sdk 1.25.5 io/ioutil/tempfile.go:26-28 TempFile
/// `TempFile(dir, pattern) (*os.File, error)` — same
/// naming caveat as `TempDir`. Deprecated in Go 1.16 (replaced by
/// `os.CreateTemp`).
pub fn TempFile<S: Into<crate::string>, S2: Into<crate::string>>(
    dir: S,
    pattern: S2,
) -> (crate::gonilable::nilable<crate::os::File>, error) {
    let dir: crate::string = dir.into();
    let pattern: crate::string = pattern.into();
    let base = if dir.Len() == 0 {
        crate::os::TempDir()
    } else {
        dir
    };

    static NEXT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    let n = NEXT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);

    let mut path: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    path.extend_from_slice(base.as_bytes());
    if !path.ends_with(b"/") {
        path.push(b'/');
    }
    path.extend_from_slice(pattern.as_bytes());
    append_u64(&mut path, n);

    let name = crate::string::from_bytes(&path);
    return crate::os::Create(name);
}

// go: none — goish idiom: Go builds the suffix with
//     `strconv.Itoa(int(uint32(...)))` inside `os.MkdirTemp`, which
//     goish's `os` does not expose. This is that decimal render,
//     spelled without an allocation.
fn append_u64(buf: &mut alloc::vec::Vec<u8>, mut n: u64) {
    let mut digits = [0u8; 20];
    let mut i = digits.len();
    if n == 0 {
        i -= 1;
        digits[i] = b'0';
    } else {
        while n > 0 {
            i -= 1;
            digits[i] = b'0' + touint8(n % 10);
            n /= 10;
        }
    }
    buf.extend_from_slice(&digits[i..]);
}
