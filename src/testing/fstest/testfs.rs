// go: file testing/fstest/testfs.go decls: fsTester.errorf, formatEntry, formatInfoEntry, formatInfo, fsTester.checkBadPath, fsTester.checkFileRead, fsTester.checkOpen, fsTester.checkDirList, fsTester.checkStat, fsTester.checkGlob, fsTester.openDir, fsTester.checkFile, fsTester.checkDir, testFS, TestFS
//
// testfs.go — the TestFS conformance harness.

use super::mapfs::*;

use alloc::sync::Arc;

use crate::errors::{self, error};
use crate::goslice::slice;
use crate::gostring::string;
use crate::io::fs::{self, DirEntry, File, FileInfo};
use crate::types::{byte, int};

// ─── testfs.go — the TestFS conformance harness ──────────────────────
//
// Partially ported: the error accumulator and the three formatters that
// render a mismatch. The checks themselves (checkDir, checkFile,
// checkGlob, checkStat, checkBadPath) and TestFS/testFS that
// drive them still need `fs.Glob`, `fs.Sub`, `fs.WalkDir` and
// `fs.ReadDirFile` reached through interface downcasts, which goish's
// io/fs does not fully provide yet.

// goishlint:ignore GOISH019 fsTester — Go's `fsys fs.FS` field is held
// by the driver (`testFS`), which is not ported; carrying a filesystem
// this struct never reads would imply a walk that does not exist here.
// goishlint:ignore GOISH020 checkOpen, checkBadPath, checkFileRead, checkDirList, checkStat, checkGlob, checkFile, openDir, checkDir, testFS, TestFS — Go
// reads `t.fsys` off the receiver; goish's fsTester does not carry a
// filesystem (see GOISH019 above), so these take it, or the opener
// built from it, as a parameter instead. Same inputs, one hop
// explicit.
// goishlint:ignore GOISH020 errorf — Go's signature is
// `(format string, args ...any)`; goish takes the already-formatted
// string, matching how Logf/Skipf are handled in src/testing/testing.rs.
// go: sdk 1.25.5 testing/fstest/testfs.go:96-101 fsTester
/// Go: "An fsTester holds state for running the test."
///
/// Deviation: Go's `fsys fs.FS` field is carried by the driver
/// (`testFS`), which is not ported; this holds only the accumulated
/// state the formatters and `errorf` touch.
#[derive(Default)]
pub struct fsTester {
    errors: alloc::vec::Vec<error>,
    dirs: alloc::vec::Vec<string>,
    files: alloc::vec::Vec<string>,
}

impl fsTester {
    // go: sdk 1.25.5 testing/fstest/testfs.go:104-106 fsTester.errorf
    /// Go: "errorf adds an error to the list of errors."
    ///
    /// Deviation: Go is variadic over `...any`; goish takes the already
    /// formatted string, as elsewhere in this port.
    pub fn errorf(&mut self, msg: string) {
        self.errors.push(errors::New(msg));
    }

    // go: none — goish-only: read back what `errorf` accumulated. Go's
    // driver reaches the slice directly because it is in-package; the
    // field stays private here so the invariant "errors only grow via
    // errorf" holds.
    pub fn Errors(&self) -> slice<error> {
        return slice::__from_vec(self.errors.clone());
    }

    // go: none — goish-only: record a directory the walk found.
    pub fn __push_dir(&mut self, p: string) {
        self.dirs.push(p);
    }

    // go: none — goish-only: record a file the walk found.
    pub fn __push_file(&mut self, p: string) {
        self.files.push(p);
    }

    // go: none — goish-only: the walk's results, for a driver to check.
    pub fn Found(&self) -> (slice<string>, slice<string>) {
        return (
            slice::__from_vec(self.dirs.clone()),
            slice::__from_vec(self.files.clone()),
        );
    }
}

// go: sdk 1.25.5 testing/fstest/testfs.go:276-278 formatEntry
/// Go: `fmt.Sprintf("%s IsDir=%v Type=%v", entry.Name(), entry.IsDir(),
/// entry.Type())` — the rendering both sides of a DirEntry comparison
/// go through, so a mismatch prints as two directly comparable lines.
pub fn formatEntry(entry: &dyn DirEntry) -> string {
    return crate::fmt::Sprintf!(
        "%s IsDir=%v Type=%v",
        entry.Name(),
        entry.IsDir(),
        entry.Type().String()
    );
}

// go: sdk 1.25.5 testing/fstest/testfs.go:281-283 formatInfoEntry
/// Go: the same rendering as `formatEntry`, but taken from a FileInfo —
/// which is the point: a DirEntry and the FileInfo its `Info()` returns
/// must format identically, and that is what the conformance check
/// compares.
pub fn formatInfoEntry(info: &dyn FileInfo) -> string {
    return crate::fmt::Sprintf!(
        "%s IsDir=%v Type=%v",
        info.Name(),
        info.IsDir(),
        info.Mode().Type().String()
    );
}

// go: sdk 1.25.5 testing/fstest/testfs.go:286-288 formatInfo
/// Go: `fmt.Sprintf("%s IsDir=%v Mode=%v Size=%d ModTime=%v", ...)` —
/// the fuller rendering, used where the check compares a Stat against
/// an Open().Stat().
pub fn formatInfo(info: &dyn FileInfo) -> string {
    return crate::fmt::Sprintf!(
        "%s IsDir=%v Mode=%v Size=%d ModTime=%v",
        info.Name(),
        info.IsDir(),
        info.Mode().String(),
        info.Size(),
        // Go renders the Time through %v, i.e. Time.String(), which
        // goish's time does not provide. RFC3339Nano is the closest
        // stable rendering and is what matters here: the string is only
        // ever compared against another produced the same way.
        info.ModTime().Format(crate::gostring::string::from_static(
            crate::time::RFC3339Nano
        ))
    );
}

impl fsTester {
    // go: sdk 1.25.5 testing/fstest/testfs.go:610-640 fsTester.checkBadPath
    /// Go: "checkBadPath checks that various invalid forms of file's name
    /// cannot be opened using t.fsys.Open."
    ///
    /// This is the check that catches an `FS` doing its own path
    /// cleaning. Every spelling below denotes the same file on a Unix
    /// filesystem, and `fs.FS` requires all of them to be *rejected* —
    /// only the canonical unrooted slash-separated form is valid. An
    /// implementation that helpfully normalised `a//b` to `a/b` would
    /// pass every functional test and fail here, which is the point.
    ///
    /// Deviation: Go reaches `t.fsys` through the receiver; goish's
    /// `fsTester` does not carry it (see the struct), so the caller
    /// supplies the opener directly.
    pub fn checkBadPath<F: Fn(string) -> error>(&mut self, file: string, desc: &str, open: F) {
        let f: &str = file.as_ref();
        let mut bad: alloc::vec::Vec<string> = alloc::vec::Vec::new();
        // Go: bad := []string{"/" + file, file + "/."}
        bad.push(crate::fmt::Sprintf!("/%s", file.clone()));
        bad.push(crate::fmt::Sprintf!("%s/.", file.clone()));
        // Go: if file == "." { bad = append(bad, "/") }
        if f == "." {
            bad.push(string::from_static("/"));
        }
        // Go: if i := strings.Index(file, "/"); i >= 0 { ...four forms... }
        if let Some(i) = f.find('/') {
            let (head, tail) = (&f[..i], &f[i + 1..]);
            bad.push(crate::fmt::Sprintf!("%s//%s", s_of(head), s_of(tail)));
            bad.push(crate::fmt::Sprintf!("%s/./%s", s_of(head), s_of(tail)));
            bad.push(crate::fmt::Sprintf!("%s\\%s", s_of(head), s_of(tail)));
            bad.push(crate::fmt::Sprintf!("%s/../%s", s_of(head), file.clone()));
        }
        // Go: if i := strings.LastIndex(file, "/"); i >= 0 { ...four more... }
        if let Some(i) = f.rfind('/') {
            let (head, tail) = (&f[..i], &f[i + 1..]);
            bad.push(crate::fmt::Sprintf!("%s//%s", s_of(head), s_of(tail)));
            bad.push(crate::fmt::Sprintf!("%s/./%s", s_of(head), s_of(tail)));
            bad.push(crate::fmt::Sprintf!("%s\\%s", s_of(head), s_of(tail)));
            bad.push(crate::fmt::Sprintf!("%s/../%s", file.clone(), s_of(tail)));
        }

        for b in bad.iter() {
            // Go: if err := open(b); err == nil {
            //         t.errorf("%s: %s(%s) succeeded, want error", ...) }
            if open(b.clone()) == errors::nil {
                self.errorf(crate::fmt::Sprintf!(
                    "%s: %s(%s) succeeded, want error",
                    file.clone(),
                    s_of(desc),
                    b.clone()
                ));
            }
        }
    }

    // go: sdk 1.25.5 testing/fstest/testfs.go:591-596 fsTester.checkFileRead
    /// Go: report when two reads of the same file returned different
    /// bytes — e.g. `ReadFile` disagreeing with `Open`+`ReadAll`.
    pub fn checkFileRead(
        &mut self,
        file: string,
        desc: &str,
        data1: slice<byte>,
        data2: slice<byte>,
    ) {
        if string::from_bytes(data1.as_ref()) != string::from_bytes(data2.as_ref()) {
            self.errorf(crate::fmt::Sprintf!(
                "%s: %s: different data returned\n\t%q\n\t%q",
                file.clone(),
                s_of(desc),
                string::from_bytes(data1.as_ref()),
                string::from_bytes(data2.as_ref())
            ));
        }
    }

    // go: sdk 1.25.5 testing/fstest/testfs.go:599-607 fsTester.checkOpen
    /// Go: "checkOpen validates file opening behavior by attempting to
    /// open and then close the given file path."
    ///
    /// Deviation: as `checkBadPath` — the filesystem arrives as a
    /// parameter rather than through the receiver.
    pub fn checkOpen(&mut self, fsys: &(dyn fs::FS + Send + Sync + 'static), file: string) {
        self.checkBadPath(file, "Open", |name| {
            let (f, err) = fs::FS::Open(fsys, name);
            // Go: if err == nil { f.Close() }
            if err == errors::nil {
                f.Close();
            }
            return err;
        });
    }
}

// go: none — goish idiom: `&str` to `string` for the Sprintf! call
// sites above, which take owned goish strings.
fn s_of(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

impl fsTester {
    // go: sdk 1.25.5 testing/fstest/testfs.go:472-518 fsTester.checkDirList
    /// Go: "checkDirList checks that two directory lists contain the
    /// same files and file info."
    ///
    /// Two independent things happen here, and both matter:
    ///
    /// 1. `checkMode` asserts `entry.IsDir()` agrees with
    ///    `entry.Type() & ModeDir`. A DirEntry that says it is a
    ///    directory through one accessor and not the other is
    ///    internally inconsistent, and every caller picks one — so half
    ///    of them would be wrong with no way to tell which.
    /// 2. The two listings are diffed by name, and every surviving
    ///    difference is rendered as a +/- line. The diff is sorted by
    ///    name and then with `+` before `-`, so a rename reads as an
    ///    adjacent pair rather than two entries scattered apart.
    ///
    /// Deviation: Go compares `entry1 == nil` against a map lookup;
    /// goish's map returns `(value, ok)` so the presence flag is
    /// explicit rather than a nil interface.
    pub fn checkDirList(
        &mut self,
        dir: string,
        desc: &str,
        list1: &slice<Arc<dyn DirEntry + Send + Sync>>,
        list2: &slice<Arc<dyn DirEntry + Send + Sync>>,
    ) {
        // Go's `checkMode` closure, hoisted: it borrows `t` mutably and
        // the loops below also need `self`, which a closure capturing
        // `&mut self` would forbid.
        let mut mode_errs: alloc::vec::Vec<string> = alloc::vec::Vec::new();
        let mut check_mode = |entry: &(dyn DirEntry + Send + Sync)| {
            // Go: if entry.IsDir() != (entry.Type()&fs.ModeDir != 0)
            if entry.IsDir() != ((entry.Type().0 & fs::ModeDir.0) != 0) {
                if entry.IsDir() {
                    mode_errs.push(crate::fmt::Sprintf!(
                        "%s: ReadDir returned %s with IsDir() = true, Type() & ModeDir = 0",
                        dir.clone(),
                        entry.Name()
                    ));
                } else {
                    mode_errs.push(crate::fmt::Sprintf!(
                        "%s: ReadDir returned %s with IsDir() = false, Type() & ModeDir = ModeDir",
                        dir.clone(),
                        entry.Name()
                    ));
                }
            }
        };

        // Go keys this map by name to the DirEntry itself. goish's
        // `map` needs `Default` on the value to return a zero, which a
        // `dyn` trait object cannot supply — so it holds the entry's
        // index in `list1` instead. Same lookups, same deletions.
        let mut old: crate::map<string, int> = crate::map::new();
        for i in 0..list1.Len() {
            let e = list1[i].clone();
            old.Set(e.Name(), i);
            check_mode(e.as_ref());
        }

        let mut diffs: alloc::vec::Vec<string> = alloc::vec::Vec::new();
        for i in 0..list2.Len() {
            let e2 = list2[i].clone();
            let (i1, ok) = old.Get(e2.Name());
            if !ok {
                check_mode(e2.as_ref());
                diffs.push(crate::fmt::Sprintf!("+ %s", formatEntry(e2.as_ref())));
                continue;
            }
            let e1 = list1[i1].clone();
            if formatEntry(e1.as_ref()) != formatEntry(e2.as_ref()) {
                diffs.push(crate::fmt::Sprintf!("- %s", formatEntry(e1.as_ref())));
                diffs.push(crate::fmt::Sprintf!("+ %s", formatEntry(e2.as_ref())));
            }
            old.Delete(e2.Name());
        }
        // Go: for _, entry1 := range old { diffs = append(diffs, "- "+...) }
        // Go's map iteration order is randomised, but the sort below
        // makes the result deterministic either way.
        let leftover = old.Keys();
        for i in 0..leftover.Len() {
            let (i1, ok) = old.Get(leftover[i].clone());
            if ok {
                let e1 = list1[i1].clone();
                diffs.push(crate::fmt::Sprintf!("- %s", formatEntry(e1.as_ref())));
            }
        }

        drop(check_mode);
        for m in mode_errs.into_iter() {
            self.errorf(m);
        }

        if diffs.len() == 0 {
            return;
        }

        // Go: sort by name (i < j) and then +/- (j < i, because + < -).
        // The comparison key is deliberately asymmetric — it splices
        // the *other* line's sign in — so that for a given name the
        // '+' line sorts first.
        diffs.sort_by(|a, b| {
            let fa = crate::strings::Fields(a.clone());
            let fb = crate::strings::Fields(b.clone());
            if fa.Len() < 2 || fb.Len() < 2 {
                let x: &str = a.as_ref();
                let y: &str = b.as_ref();
                return x.cmp(y);
            }
            let left = crate::fmt::Sprintf!("%s %s", fa[1].clone(), fb[0].clone());
            let right = crate::fmt::Sprintf!("%s %s", fb[1].clone(), fa[0].clone());
            let c = crate::strings::Compare(left, right);
            return c.cmp(&0);
        });

        self.errorf(crate::fmt::Sprintf!(
            "%s: diff %s:\n\t%s",
            dir.clone(),
            s_of(desc),
            crate::strings::Join(slice::__from_vec(diffs), string::from_static("\n\t"))
        ));
    }
}

impl fsTester {
    // go: sdk 1.25.5 testing/fstest/testfs.go:390-468 fsTester.checkStat
    /// Go: "checkStat checks that the file's stat matches the directory
    /// entry."
    ///
    /// Four renderings of the same file have to agree, and the check
    /// exists because they are produced by four different code paths:
    /// the DirEntry from ReadDir, `entry.Info()`, `Open().Stat()`, and
    /// the free `fs.Stat`. A filesystem that assembles any one of them
    /// separately — a common shortcut — drifts here first.
    ///
    /// Symlinks are the exception threaded through the whole function:
    /// `Open` dereferences a symlink, so `file.Stat()` legitimately
    /// describes the *target* while the entry describes the link. Go
    /// therefore compares only the entry-shaped fields in that case,
    /// and this port keeps the same branch even though goish's MapFS
    /// has no symlink support yet — the logic is what is being ported.
    ///
    /// Deviation: Go's two optional-interface blocks (`fs.StatFS` and
    /// `fs.ReadLinkFS`) are absent. goish's io/fs declares neither
    /// trait, so there is nothing to type-assert to; when they arrive,
    /// so do those blocks.
    pub fn checkStat(
        &mut self,
        fsys: &(dyn fs::FS + Send + Sync + 'static),
        path: string,
        entry: &(dyn DirEntry + Send + Sync),
    ) {
        let (file, err) = fs::FS::Open(fsys, path.clone());
        if err != errors::nil {
            self.errorf(crate::fmt::Sprintf!(
                "%s: Open: %v",
                path.clone(),
                err.Error()
            ));
            return;
        }
        let (info, serr) = file.Stat();
        file.Close();
        if serr != errors::nil {
            self.errorf(crate::fmt::Sprintf!(
                "%s: Stat: %v",
                path.clone(),
                serr.Error()
            ));
            return;
        }

        let fentry = formatEntry(entry);
        let fientry = formatInfoEntry(info.as_ref());
        // Go: "Note: mismatch here is OK for symlink, because Open
        // dereferences symlink."
        let is_symlink = (entry.Type().0 & fs::ModeSymlink.0) != 0;
        if fentry != fientry && !is_symlink {
            self.errorf(crate::fmt::Sprintf!(
                "%s: mismatch:\n\tentry = %s\n\tfile.Stat() = %s",
                path.clone(),
                fentry.clone(),
                fientry.clone()
            ));
        }

        let (einfo, ierr) = entry.Info();
        if ierr != errors::nil {
            self.errorf(crate::fmt::Sprintf!(
                "%s: entry.Info: %v",
                path.clone(),
                ierr.Error()
            ));
            return;
        }
        let finfo = formatInfo(info.as_ref());
        if is_symlink {
            // Go: "For symlink, just check that entry.Info matches
            // entry on common fields. Open dereferences symlink, so
            // info itself may differ."
            let feentry = formatInfoEntry(einfo.as_ref());
            if fentry != feentry {
                self.errorf(crate::fmt::Sprintf!(
                    "%s: mismatch\n\tentry = %s\n\tentry.Info() = %s\n",
                    path.clone(),
                    fentry.clone(),
                    feentry
                ));
            }
        } else {
            let feinfo = formatInfo(einfo.as_ref());
            if feinfo != finfo {
                self.errorf(crate::fmt::Sprintf!(
                    "%s: mismatch:\n\tentry.Info() = %s\n\tfile.Stat() = %s\n",
                    path.clone(),
                    feinfo,
                    finfo.clone()
                ));
            }
        }

        // Go: "Stat should be the same as Open+Stat, even for symlinks."
        let (info2, s2err) = fs::Stat(fsys, path.clone());
        if s2err != errors::nil {
            self.errorf(crate::fmt::Sprintf!(
                "%s: fs.Stat: %v",
                path.clone(),
                s2err.Error()
            ));
            return;
        }
        let finfo2 = formatInfo(info2.as_ref());
        if finfo2 != finfo {
            self.errorf(crate::fmt::Sprintf!(
                "%s: fs.Stat(...) = %s\n\twant %s",
                path.clone(),
                finfo2,
                finfo
            ));
        }
    }
}

impl fsTester {
    // go: sdk 1.25.5 testing/fstest/testfs.go:291-386 fsTester.checkGlob
    /// Go: "checkGlob checks that various glob patterns work if the file
    /// system implements GlobFS."
    ///
    /// The pattern-mangling loop is the interesting half. For each rune
    /// of the directory name it emits one of five *equivalent* spellings
    /// — bare, `[r]`, `[r-r]`, `[\r]`, `[\r-\r]` — cycling by
    /// `(i+j) % 5`. Every one denotes the same single character, so a
    /// correct glob engine returns identical results for all of them;
    /// an engine that mishandles ranges, escapes-inside-brackets, or
    /// single-element classes diverges on exactly one spelling. That is
    /// far more searching than globbing the plain name would be.
    ///
    /// Deviation: Go opens with `if _, ok := t.fsys.(fs.GlobFS); !ok
    /// { return }` and then type-asserts three more times. goish has no
    /// `GlobFS` trait, so the glob function arrives as a parameter —
    /// which also means this check actually runs here, where in Go it
    /// silently skips any filesystem that does not implement the
    /// interface.
    pub fn checkGlob<G: Fn(string) -> (slice<string>, error)>(
        &mut self,
        dir: string,
        list: &slice<Arc<dyn DirEntry + Send + Sync>>,
        globfn: G,
    ) {
        // Go: "Make a complex glob pattern prefix that only matches dir."
        let mut glob = string::from_static("");
        let d: &str = dir.as_ref();
        if d != "." {
            let elems = crate::strings::Split(dir.clone(), string::from_static("/"));
            let mut out: alloc::vec::Vec<string> = alloc::vec::Vec::new();
            for i in 0..elems.Len() {
                let e: &str = elems[i].as_ref();
                let mut pattern: alloc::vec::Vec<char> = alloc::vec::Vec::new();
                for (j, r) in e.chars().enumerate() {
                    if r == '*' || r == '?' || r == '\\' || r == '[' || r == '-' {
                        pattern.push('\\');
                        pattern.push(r);
                        continue;
                    }
                    match (usize::try_from(i).unwrap_or(0) + j) % 5 {
                        0 => pattern.push(r),
                        1 => {
                            pattern.push('[');
                            pattern.push(r);
                            pattern.push(']');
                        }
                        2 => {
                            pattern.push('[');
                            pattern.push(r);
                            pattern.push('-');
                            pattern.push(r);
                            pattern.push(']');
                        }
                        3 => {
                            pattern.push('[');
                            pattern.push('\\');
                            pattern.push(r);
                            pattern.push(']');
                        }
                        _ => {
                            pattern.push('[');
                            pattern.push('\\');
                            pattern.push(r);
                            pattern.push('-');
                            pattern.push('\\');
                            pattern.push(r);
                            pattern.push(']');
                        }
                    }
                }
                let built: alloc::string::String = pattern.into_iter().collect();
                out.push(s_of(&built));
            }
            glob = crate::fmt::Sprintf!(
                "%s/",
                crate::strings::Join(slice::__from_vec(out), string::from_static("/"))
            );
        }

        // Go: "Test that malformed patterns are detected. The error is
        // likely path.ErrBadPattern but need not be."
        let bad = crate::fmt::Sprintf!("%snonexist/[]", glob.clone());
        let (_, berr) = globfn(bad.clone());
        if berr == errors::nil {
            self.errorf(crate::fmt::Sprintf!(
                "%s: Glob(%q): bad pattern not detected",
                dir.clone(),
                bad
            ));
        }

        // Go: "Try to find a letter that appears in only some of the
        // final names." — so the glob is genuinely selective rather
        // than matching everything or nothing.
        let mut c: char = 'a';
        while c <= 'z' {
            let (mut have, mut have_not) = (false, false);
            for i in 0..list.Len() {
                let n = list[i].Name();
                let ns: &str = n.as_ref();
                if ns.contains(c) {
                    have = true;
                } else {
                    have_not = true;
                }
            }
            if have && have_not {
                break;
            }
            c = char::from_u32(u32::from(c) + 1).unwrap_or('z');
        }
        if c > 'z' {
            c = 'a';
        }
        let mut cbuf = [0u8; 4];
        glob = crate::fmt::Sprintf!("%s*%s*", glob.clone(), s_of(c.encode_utf8(&mut cbuf)));

        let mut want: alloc::vec::Vec<string> = alloc::vec::Vec::new();
        for i in 0..list.Len() {
            let n = list[i].Name();
            let ns: &str = n.as_ref();
            if ns.contains(c) {
                want.push(crate::path::Join(slice::__from_vec(alloc::vec![
                    dir.clone(),
                    n
                ])));
            }
        }

        let (names, gerr) = globfn(glob.clone());
        if gerr != errors::nil {
            self.errorf(crate::fmt::Sprintf!(
                "%s: Glob(%q): %v",
                dir.clone(),
                glob.clone(),
                gerr.Error()
            ));
            return;
        }

        let mut got: alloc::vec::Vec<string> = alloc::vec::Vec::new();
        for i in 0..names.Len() {
            got.push(names[i].clone());
        }
        if got == want {
            return;
        }

        // Go: if !slices.IsSorted(names) { errorf(unsorted); sort }
        let mut sorted = true;
        for i in 1..got.len() {
            let (a, b): (&str, &str) = (got[i - 1].as_ref(), got[i].as_ref());
            if a > b {
                sorted = false;
                break;
            }
        }
        if !sorted {
            self.errorf(crate::fmt::Sprintf!(
                "%s: Glob(%q): unsorted output:\n%s",
                dir.clone(),
                glob.clone(),
                crate::strings::Join(slice::__from_vec(got.clone()), string::from_static("\n"))
            ));
            got.sort_by(|x, y| {
                let (a, b): (&str, &str) = (x.as_ref(), y.as_ref());
                return a.cmp(b);
            });
        }

        // Go's merge walk over the two sorted lists, reporting each
        // side's surplus as missing/extra.
        let mut problems: alloc::vec::Vec<string> = alloc::vec::Vec::new();
        let (mut wi, mut gi) = (0usize, 0usize);
        while wi < want.len() || gi < got.len() {
            if wi < want.len() && gi < got.len() && want[wi] == got[gi] {
                wi += 1;
                gi += 1;
            } else if wi < want.len()
                && (gi >= got.len() || {
                    let (a, b): (&str, &str) = (want[wi].as_ref(), got[gi].as_ref());
                    a < b
                })
            {
                problems.push(crate::fmt::Sprintf!("missing: %s", want[wi].clone()));
                wi += 1;
            } else {
                problems.push(crate::fmt::Sprintf!("extra: %s", got[gi].clone()));
                gi += 1;
            }
        }
        self.errorf(crate::fmt::Sprintf!(
            "%s: Glob(%q): wrong output:\n%s",
            dir.clone(),
            glob,
            crate::strings::Join(slice::__from_vec(problems), string::from_static("\n"))
        ));
    }
}

impl fsTester {
    // go: sdk 1.25.5 testing/fstest/testfs.go:108-121 fsTester.openDir
    /// Go: open `dir` and assert the result is an `fs.ReadDirFile`.
    ///
    /// A directory that opens but cannot be read as one is the failure
    /// this catches — an `FS` whose `Open` returns a plain file handle
    /// for a directory path passes every read test and dies the moment
    /// anything walks it.
    ///
    /// Deviation: Go returns the `fs.ReadDirFile` and nil-checks at the
    /// call site; goish returns `(entries, ok)` because the downcast
    /// goes through `__goish_as_dyn_any` and handing back a borrowed
    /// trait object would outlive the `Arc`.
    pub fn openDir(
        &mut self,
        fsys: &(dyn fs::FS + Send + Sync + 'static),
        dir: string,
    ) -> (slice<Arc<dyn DirEntry + Send + Sync>>, bool) {
        let (f, err) = fs::FS::Open(fsys, dir.clone());
        if err != errors::nil {
            self.errorf(crate::fmt::Sprintf!(
                "%s: Open: %v",
                dir.clone(),
                err.Error()
            ));
            return (slice::new(), false);
        }
        // Go: d, ok := f.(fs.ReadDirFile); if !ok { f.Close(); errorf }
        let any = match f.__goish_as_dyn_any() {
            Some(a) => a,
            None => {
                f.Close();
                self.errorf(crate::fmt::Sprintf!(
                    "%s: Open returned a File that is not a fs.ReadDirFile",
                    dir.clone()
                ));
                return (slice::new(), false);
            }
        };
        if let Some(d) = any.downcast_ref::<mapDir>() {
            let (entries, rerr) = d.read_dir(-1);
            f.Close();
            if rerr != errors::nil {
                self.errorf(crate::fmt::Sprintf!(
                    "%s: ReadDir: %v",
                    dir.clone(),
                    rerr.Error()
                ));
                return (slice::new(), false);
            }
            return (entries, true);
        }
        f.Close();
        self.errorf(crate::fmt::Sprintf!(
            "%s: Open returned a File that is not a fs.ReadDirFile",
            dir.clone()
        ));
        return (slice::new(), false);
    }

    // go: sdk 1.25.5 testing/fstest/testfs.go:521-589 fsTester.checkFile
    /// Go: "checkFile checks that basic file reading works correctly."
    ///
    /// Three things beyond "the bytes come back":
    ///
    ///  * Closing twice must not crash. Go says so explicitly and
    ///    ignores the second return value — an `FS` that panics or
    ///    double-frees on a second Close breaks every `defer f.Close()`
    ///    written next to an explicit one.
    ///  * `fs.ReadFile` must agree with `Open` + read-to-end. Two code
    ///    paths, one answer.
    ///  * Mutating the slice a `ReadFile` returned must not change what
    ///    the next call returns. An implementation handing out its
    ///    internal buffer passes every other check here and corrupts
    ///    the filesystem from the outside.
    ///
    /// Deviations: Go's `fs.ReadFileFS` block is absent — goish's io/fs
    /// has no such trait to assert on — and the closing
    /// `iotest.TestReader` call is absent because `TestReader` is the
    /// one declaration of `testing/iotest` not yet ported (it needs
    /// ReadSeeker/ReaderAt downcasts). The aliasing check that block
    /// would have performed is done here against `fs::ReadFile`
    /// instead, so the property is still covered.
    pub fn checkFile(&mut self, fsys: &(dyn fs::FS + Send + Sync + 'static), file: string) {
        self.__push_file(file.clone());

        // Go: read the entire file through Open.
        let (f, err) = fs::FS::Open(fsys, file.clone());
        if err != errors::nil {
            self.errorf(crate::fmt::Sprintf!(
                "%s: Open: %v",
                file.clone(),
                err.Error()
            ));
            return;
        }
        let (data, rerr) = read_all_file(f.as_ref());
        if rerr != errors::nil {
            f.Close();
            self.errorf(crate::fmt::Sprintf!(
                "%s: Open+ReadAll: %v",
                file.clone(),
                rerr.Error()
            ));
            return;
        }
        let cerr = f.Close();
        if cerr != errors::nil {
            self.errorf(crate::fmt::Sprintf!(
                "%s: Close: %v",
                file.clone(),
                cerr.Error()
            ));
        }
        // Go: "Check that closing twice doesn't crash. The return value
        // doesn't matter."
        f.Close();

        // Go: "Check that fs.ReadFile works with t.fsys."
        let (data2, r2err) = fs::ReadFile(fsys, file.clone());
        if r2err != errors::nil {
            self.errorf(crate::fmt::Sprintf!(
                "%s: fs.ReadFile: %v",
                file.clone(),
                r2err.Error()
            ));
            return;
        }
        self.checkFileRead(
            file.clone(),
            "ReadAll vs fs.ReadFile",
            data.clone(),
            data2.clone(),
        );

        // Go performs this aliasing check inside the ReadFileFS block:
        // "Modify the data and check it again. Modifying the returned
        // byte slice should not affect the next call."
        let mut mutated = data2.clone();
        for i in 0..mutated.Len() {
            mutated[i] = mutated[i].wrapping_add(1);
        }
        let (data3, r3err) = fs::ReadFile(fsys, file.clone());
        if r3err != errors::nil {
            self.errorf(crate::fmt::Sprintf!(
                "%s: second call to fs.ReadFile: %v",
                file.clone(),
                r3err.Error()
            ));
            return;
        }
        self.checkFileRead(file.clone(), "ReadAll vs second fs.ReadFile", data, data3);

        self.checkBadPath(file, "ReadFile", |name| {
            let (_, e) = fs::ReadFile(fsys, name);
            return e;
        });
    }
}

// go: none — goish idiom: Go calls `io.ReadAll(f)` on the `fs.File`
// interface. goish's `fs::File::Read` takes `&self` and a `&mut
// slice<byte>` rather than satisfying `io::Reader`, so the read-to-end
// loop is spelled here.
fn read_all_file(f: &(dyn File + Send + Sync)) -> (slice<byte>, error) {
    let mut out: alloc::vec::Vec<byte> = alloc::vec::Vec::new();
    let mut buf: slice<byte> = crate::make!([]byte, 512);
    return 'read: loop {
        let (n, err) = f.Read(&mut buf);
        if n > 0 {
            for i in 0..n {
                out.push(buf[i]);
            }
        }
        if err != errors::nil {
            // Go: io.ReadAll treats EOF as success.
            let eof: error = crate::io::EOF.clone().into();
            if err == eof {
                break 'read (slice::__from_vec(out), errors::nil);
            }
            break 'read (slice::__from_vec(out), err);
        }
        if n == 0 {
            break 'read (slice::__from_vec(out), errors::nil);
        }
    };
}

// go: none — goish-only: open a directory and hand back the live
// handle, which `checkDir` needs because several of its checks depend
// on ReadDir's *position* persisting across calls (read to EOF, then
// confirm ReadDir(-1) returns nothing and ReadDir(1) returns EOF).
// `openDir` above closes the handle and returns a snapshot, which is
// the right shape for its own caller but loses exactly that state.
fn open_dir_handle(
    fsys: &(dyn fs::FS + Send + Sync + 'static),
    dir: string,
) -> (Option<Arc<dyn File + Send + Sync>>, error) {
    let (f, err) = fs::FS::Open(fsys, dir);
    if err != errors::nil {
        return (None, err);
    }
    return (Some(f), errors::nil);
}

// go: none — goish-only: `ReadDir(n)` on a live handle. The downcast to
// `mapDir` stands in for Go's `f.(fs.ReadDirFile)` type assertion,
// which goish's io/fs cannot express yet.
fn handle_read_dir(
    f: &(dyn File + Send + Sync),
    n: int,
) -> (slice<Arc<dyn DirEntry + Send + Sync>>, error, bool) {
    let any = match f.__goish_as_dyn_any() {
        Some(a) => a,
        None => return (slice::new(), errors::nil, false),
    };
    return match any.downcast_ref::<mapDir>() {
        Some(d) => {
            let (e, err) = d.read_dir(n);
            (e, err, true)
        }
        None => (slice::new(), errors::nil, false),
    };
}

impl fsTester {
    // go: sdk 1.25.5 testing/fstest/testfs.go:125-273 fsTester.checkDir
    /// Go: "checkDir checks the directory dir, which is expected to
    /// exist (it is either the root or was found in a directory
    /// listing with IsDir true)."
    ///
    /// The heart of TestFS, and the only recursive check: it walks the
    /// whole tree, and for each directory reads it four different ways,
    /// requiring all four to agree —
    ///
    ///   1. `Open` + `ReadDir(-1)` (the reference listing)
    ///   2. reopen + `ReadDir(-1)`
    ///   3. reopen + `ReadDir(1)`, `ReadDir(2)`, … in pieces
    ///   4. the free `fs.ReadDir`
    ///
    /// A filesystem that caches a listing on the handle, or whose
    /// piecewise reads lose or duplicate an entry at a chunk boundary,
    /// fails only against the third. It also pins the EOF contract,
    /// which is asymmetric and easy to get wrong: at EOF `ReadDir(-1)`
    /// returns zero entries and **nil**, while `ReadDir(1)` returns
    /// zero entries and **io.EOF**.
    ///
    /// Deviations: Go's `fs.ReadDirFS` block is absent (no such trait
    /// here) — the `fs.ReadDir` block below covers the same ground, and
    /// both sort checks are kept. Symlink children are recorded without
    /// being followed, exactly as Go does, "to avoid potentially
    /// unbounded recursion".
    pub fn checkDir(&mut self, fsys: &(dyn fs::FS + Send + Sync + 'static), dir: string) {
        self.__push_dir(dir.clone());

        let (dh, oerr) = open_dir_handle(fsys, dir.clone());
        let d = match dh {
            Some(d) => d,
            None => {
                self.errorf(crate::fmt::Sprintf!(
                    "%s: Open: %v",
                    dir.clone(),
                    oerr.Error()
                ));
                return;
            }
        };
        let (list, rerr, ok) = handle_read_dir(d.as_ref(), -1);
        if !ok {
            d.Close();
            self.errorf(crate::fmt::Sprintf!(
                "%s: Open returned a File that is not a fs.ReadDirFile",
                dir.clone()
            ));
            return;
        }
        if rerr != errors::nil {
            d.Close();
            self.errorf(crate::fmt::Sprintf!(
                "%s: ReadDir(-1): %v",
                dir.clone(),
                rerr.Error()
            ));
            return;
        }

        // Go: prefix is "" for ".", else dir + "/".
        let ds: &str = dir.as_ref();
        let prefix = if ds == "." {
            string::from_static("")
        } else {
            crate::fmt::Sprintf!("%s/", dir.clone())
        };

        for i in 0..list.Len() {
            let info = list[i].clone();
            let name = info.Name();
            let ns: &str = name.as_ref();
            if ns == "." || ns == ".." || ns.is_empty() {
                self.errorf(crate::fmt::Sprintf!(
                    "%s: ReadDir: child has invalid name: %q",
                    dir.clone(),
                    name
                ));
                continue;
            }
            if ns.contains('/') {
                self.errorf(crate::fmt::Sprintf!(
                    "%s: ReadDir: child name contains slash: %q",
                    dir.clone(),
                    name
                ));
                continue;
            }
            if ns.contains('\\') {
                self.errorf(crate::fmt::Sprintf!(
                    "%s: ReadDir: child name contains backslash: %q",
                    dir.clone(),
                    name
                ));
                continue;
            }
            let path = crate::fmt::Sprintf!("%s%s", prefix.clone(), name);
            self.checkStat(fsys, path.clone(), info.as_ref());
            self.checkOpen(fsys, path.clone());
            let ty = info.Type();
            if ty.0 == fs::ModeDir.0 {
                self.checkDir(fsys, path);
            } else if ty.0 == fs::ModeSymlink.0 {
                // Go: "No further processing. Avoid following symlinks
                // to avoid potentially unbounded recursion."
                self.__push_file(path);
            } else {
                self.checkFile(fsys, path);
            }
        }

        // Go: "Check ReadDir(-1) at EOF." — zero entries and NIL.
        let (l2, e2, _) = handle_read_dir(d.as_ref(), -1);
        if l2.Len() > 0 || e2 != errors::nil {
            d.Close();
            self.errorf(crate::fmt::Sprintf!(
                "%s: ReadDir(-1) at EOF = %d entries, %v, wanted 0 entries, nil",
                dir.clone(),
                l2.Len(),
                e2.Error()
            ));
            return;
        }

        // Go: "Check ReadDir(1) at EOF (different results)." — zero
        // entries and EOF. Note the asymmetry with the case above.
        let eof: error = crate::io::EOF.clone().into();
        let (l3, e3, _) = handle_read_dir(d.as_ref(), 1);
        if l3.Len() > 0 || e3 != eof {
            d.Close();
            self.errorf(crate::fmt::Sprintf!(
                "%s: ReadDir(1) at EOF = %d entries, %v, wanted 0 entries, EOF",
                dir.clone(),
                l3.Len(),
                e3.Error()
            ));
            return;
        }

        let cerr = d.Close();
        if cerr != errors::nil {
            self.errorf(crate::fmt::Sprintf!(
                "%s: Close: %v",
                dir.clone(),
                cerr.Error()
            ));
        }
        // Go: "Check that closing twice doesn't crash."
        d.Close();

        // Go: "Reopen directory, read a second time, make sure contents
        // match."
        let (dh2, _) = open_dir_handle(fsys, dir.clone());
        let d2 = match dh2 {
            Some(x) => x,
            None => return,
        };
        let (second, serr, _) = handle_read_dir(d2.as_ref(), -1);
        if serr != errors::nil {
            d2.Close();
            self.errorf(crate::fmt::Sprintf!(
                "%s: second Open+ReadDir(-1): %v",
                dir.clone(),
                serr.Error()
            ));
            return;
        }
        d2.Close();
        self.checkDirList(
            dir.clone(),
            "first Open+ReadDir(-1) vs second Open+ReadDir(-1)",
            &list,
            &second,
        );

        // Go: "Reopen directory, read a third time in pieces, make sure
        // contents match." The chunk size alternates 1 then 2, so a
        // filesystem that mishandles a boundary shows up here.
        let (dh3, _) = open_dir_handle(fsys, dir.clone());
        let d3 = match dh3 {
            Some(x) => x,
            None => return,
        };
        let mut third: slice<Arc<dyn DirEntry + Send + Sync>> = slice::new();
        loop {
            let n: int = if third.Len() > 0 { 2 } else { 1 };
            let (frag, ferr, _) = handle_read_dir(d3.as_ref(), n);
            if frag.Len() > n {
                d3.Close();
                self.errorf(crate::fmt::Sprintf!(
                    "%s: third Open: ReadDir(%d) after %d: %d entries (too many)",
                    dir.clone(),
                    n,
                    third.Len(),
                    frag.Len()
                ));
                return;
            }
            for k in 0..frag.Len() {
                third = crate::append!(third, frag[k].clone());
            }
            if ferr == eof {
                break;
            }
            if ferr != errors::nil {
                d3.Close();
                self.errorf(crate::fmt::Sprintf!(
                    "%s: third Open: ReadDir(%d) after %d: %v",
                    dir.clone(),
                    n,
                    third.Len(),
                    ferr.Error()
                ));
                return;
            }
            if frag.Len() == 0 {
                d3.Close();
                self.errorf(crate::fmt::Sprintf!(
                    "%s: third Open: ReadDir(%d) after %d: 0 entries but nil error",
                    dir.clone(),
                    n,
                    third.Len()
                ));
                return;
            }
        }
        d3.Close();
        self.checkDirList(
            dir.clone(),
            "first Open+ReadDir(-1) vs third Open+ReadDir(1,2) loop",
            &list,
            &third,
        );

        // Go: "Check fs.ReadDir as well."
        let (fourth, r4err) = fs::ReadDir(fsys, dir.clone());
        if r4err != errors::nil {
            self.errorf(crate::fmt::Sprintf!(
                "%s: fs.ReadDir: %v",
                dir.clone(),
                r4err.Error()
            ));
            return;
        }
        self.checkDirList(
            dir.clone(),
            "first Open+ReadDir(-1) vs fs.ReadDir",
            &list,
            &fourth,
        );

        for i in 0..(fourth.Len() - 1).max(0) {
            if fourth[i].Name() >= fourth[i + 1].Name() {
                self.errorf(crate::fmt::Sprintf!(
                    "%s: fs.ReadDir: list not sorted: %s before %s",
                    dir.clone(),
                    fourth[i].Name(),
                    fourth[i + 1].Name()
                ));
            }
        }

        self.checkGlob(dir, &fourth, |pat| {
            return fs::Glob(fsys, pat);
        });
    }
}

// go: sdk 1.25.5 testing/fstest/testfs.go:65-93 testFS
/// Go: walk `fsys` from the root, run every check, and report the
/// accumulated errors as one.
///
/// The `expected` list is checked both ways: everything named must be
/// found, AND — when the list is empty — nothing may be found. That
/// second direction is what makes `TestFS(fsys)` with no arguments a
/// meaningful assertion that a filesystem is empty, rather than a
/// no-op.
///
/// Go's 15-entry truncation of the "expected empty" list is kept, as is
/// `errors.Join` — so the returned error unwraps to the individual
/// failures rather than flattening to a single string.
pub fn testFS(fsys: &(dyn fs::FS + Send + Sync + 'static), expected: &slice<string>) -> error {
    let mut t = fsTester::default();
    t.checkDir(fsys, string::from_static("."));
    t.checkOpen(fsys, string::from_static("."));

    let (dirs, files) = t.Found();
    let mut found: crate::map<string, bool> = crate::map::new();
    for i in 0..dirs.Len() {
        found.Set(dirs[i].clone(), true);
    }
    for i in 0..files.Len() {
        found.Set(files[i].clone(), true);
    }
    found.Delete(string::from_static("."));

    if expected.Len() == 0 && found.Len() > 0 {
        let keys = found.Keys();
        let mut list: alloc::vec::Vec<string> = alloc::vec::Vec::new();
        for i in 0..keys.Len() {
            list.push(keys[i].clone());
        }
        list.sort_by(|a, b| {
            let (x, y): (&str, &str) = (a.as_ref(), b.as_ref());
            return x.cmp(y);
        });
        // Go: if len(list) > 15 { list = append(list[:10], "...") }
        if list.len() > 15 {
            list.truncate(10);
            list.push(string::from_static("..."));
        }
        t.errorf(crate::fmt::Sprintf!(
            "expected empty file system but found files:\n%s",
            crate::strings::Join(slice::__from_vec(list), string::from_static("\n"))
        ));
    }

    for i in 0..expected.Len() {
        let name = expected[i].clone();
        let (ok, present) = found.Get(name.clone());
        if !present || !ok {
            t.errorf(crate::fmt::Sprintf!("expected but not found: %s", name));
        }
    }

    let errs = t.Errors();
    if errs.Len() == 0 {
        return errors::nil;
    }
    // Go: fmt.Errorf("TestFS found errors:\n%w", errors.Join(t.errors...))
    return crate::fmt::Errorf!("TestFS found errors:\n%w", errors::Join(errs));
}

// go: sdk 1.25.5 testing/fstest/testfs.go:39-63 TestFS
/// Go: "TestFS tests a file system implementation. It walks the entire
/// tree of files in fsys, opening and checking that each file behaves
/// correctly. It also checks that the file system contains at least the
/// expected files. As a special case, if no expected files are listed,
/// fsys must be empty. Otherwise, fsys must contain at least the listed
/// files; it can also contain others. The contents of fsys must not
/// change concurrently with TestFS.
///
/// If TestFS finds any misbehaviors, it returns either the first error
/// or a list of errors."
///
/// After the top-level walk it picks the first expected name containing
/// a slash, takes `fs.Sub` of that directory, and runs the whole suite
/// again against the subtree — so a `SubFS` that rewrites paths
/// incorrectly is caught. Go stops after one such subtest ("one
/// sub-test is enough") and so does this.
pub fn TestFS(fsys: Arc<dyn fs::FS + Send + Sync>, expected: &slice<string>) -> error {
    let err = testFS(fsys.as_ref(), expected);
    if err != errors::nil {
        return err;
    }
    for i in 0..expected.Len() {
        let name = expected[i].clone();
        let ns: &str = name.as_ref();
        if let Some(idx) = ns.find('/') {
            let dir = s_of(&ns[..idx]);
            let dir_slash = s_of(&ns[..idx + 1]);
            let mut sub_expected: alloc::vec::Vec<string> = alloc::vec::Vec::new();
            for j in 0..expected.Len() {
                let other = expected[j].clone();
                let os_: &str = other.as_ref();
                let dslash: &str = dir_slash.as_ref();
                if os_.starts_with(dslash) {
                    sub_expected.push(s_of(&os_[dslash.len()..]));
                }
            }
            let (sub, serr) = fs::Sub(fsys.clone(), dir.clone());
            if serr != errors::nil {
                return serr;
            }
            let suberr = testFS(sub.as_ref(), &slice::__from_vec(sub_expected));
            if suberr != errors::nil {
                return errors::New(crate::fmt::Sprintf!(
                    "testing fs.Sub(fsys, %s): %v",
                    dir,
                    suberr.Error()
                ));
            }
            // Go: "one sub-test is enough"
            break;
        }
    }
    return errors::nil;
}
