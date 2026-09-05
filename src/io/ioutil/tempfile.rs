// go: file io/ioutil/tempfile.go decls: TempFile, TempDir

use crate::error;
use crate::gostring::string;

// go: sdk 1.25.5 io/ioutil/tempfile.go:26-28 TempFile
/// `TempFile(dir, pattern) (*os.File, error)`.
///
/// Go: "Deprecated: As of Go 1.17, this function simply calls
/// [os.CreateTemp]." So does this — and that is the fix.
///
/// It used to hand-roll `<dir>/<pattern><counter>`, which got the
/// pattern rule wrong: Go replaces the LAST `*` in the pattern with
/// the random part, so `TempFile(dir, "pre*suf")` yields a name ENDING
/// in `suf`. Appending to the pattern instead produced `pre*sufN`, and
/// a caller relying on the suffix — `"*.json"` is the common one — got
/// a file with no extension. The old note called the difference
/// "collision-avoidance deferred", which described the randomness and
/// not this.
///
/// Delegating also inherits `os::CreateTemp`'s rejection of a pattern
/// containing a path separator, and its real retry loop.
pub fn TempFile<S: Into<string>, S2: Into<string>>(
    dir: S,
    pattern: S2,
) -> (crate::gonilable::nilable<crate::os::File>, error) {
    return crate::os::CreateTemp(dir, pattern);
}

// go: sdk 1.25.5 io/ioutil/tempfile.go:43-45 TempDir
/// `TempDir(dir, pattern) (name string, err error)`.
///
/// Go: "Deprecated: As of Go 1.17, this function simply calls
/// [os.MkdirTemp]." Same story as `TempFile` above.
pub fn TempDir<S: Into<string>, S2: Into<string>>(
    dir: S,
    pattern: S2,
) -> (string, error) {
    return crate::os::MkdirTemp(dir, pattern);
}
