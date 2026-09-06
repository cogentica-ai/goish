// go: file os/user/lookup_unix.go decls: lookupUser, lookupUserId, lookupGroup, lookupGroupId
// goishlint:ignore GOISH018 readColonFile, matchUserIndexValue, matchGroupIndexValue, findUserId, findUsername, findGroupId, findGroupName — Go
//     streams the file through readColonFile, which takes a lineFunc
//     closure built by matchUserIndexValue / matchGroupIndexValue and
//     is entered by the four find* wrappers. goish reads the file
//     whole and scans it in `find_user_by` / `find_group_by`, so all
//     seven fold into two functions and no single Go declaration maps
//     to either. Both carry `// go: none` saying exactly that.
// goishlint:ignore GOISH021 lineFunc — Go's `type lineFunc func(line
//     []byte) (v any, err error)`, the closure readColonFile calls per
//     line. It exists to be passed to a streaming reader goish does
//     not have; the scan functions match inline instead.
//
// os/user — the /etc/passwd and /etc/group readers behind the public
// lookups.
//
// Deviations:
//   * Pure-Go variant only. Go picks between this file and the cgo
//     getpwuid_r path at build time; goish has no libc, so there is
//     nothing to pick between.
//   * Go streams the file through `readColonFile(r io.Reader, fn
//     lineFunc, readCols int)`, with `matchUserIndexValue` /
//     `matchGroupIndexValue` returning the closure it calls per line.
//     goish reads the file whole and scans it with `find_user_by` /
//     `find_group_by`, which fold readColonFile, the match* closure
//     builders and the four find* entry points into two functions.
//     Those carry `// go: none`: they are not any one Go declaration.
#![allow(non_snake_case)]

extern crate alloc;

use alloc::vec::Vec;

use crate::bytes;
use crate::errors::{self, error, ErrorTrait};
use crate::goslice::slice;
use crate::gostring::string;
use crate::strconv;
use crate::strings;
use crate::types::{byte, int};

use super::user::{Group, User, UnknownGroupError, UnknownGroupIdError, UnknownUserError, UnknownUserIdError};
use super::lookup::{GROUP_FILE, USER_FILE};

// ─── lookup_unix.go body ──────────────────────────────────────────────

// go: sdk 1.25.5 os/user/lookup_unix.go:200-207 lookupGroup
// Go: `func lookupGroup(groupname string) (*Group, error)` at lookup_unix.go line 200.
pub(super) fn lookup_group(name: string) -> (Group, error) {
    let (data, err) = crate::os::ReadFile(string::from_static(GROUP_FILE));
    if !err.IsNil() {
        return (Group::default(), err);
    }
    return find_group_by(data, name.clone(), 0, false)
        .unwrap_or_else(|| (Group::default(), UnknownGroupError::new(name)));
}

// go: sdk 1.25.5 os/user/lookup_unix.go:209-216 lookupGroupId
// Go: `func lookupGroupId(id string) (*Group, error)` at lookup_unix.go line 209.
pub(super) fn lookup_group_id(id: string) -> (Group, error) {
    let (data, err) = crate::os::ReadFile(string::from_static(GROUP_FILE));
    if !err.IsNil() {
        return (Group::default(), err);
    }
    return find_group_by(data, id.clone(), 2, false)
        .unwrap_or_else(|| (Group::default(), UnknownGroupIdError::new(id)));
}

// go: sdk 1.25.5 os/user/lookup_unix.go:218-225 lookupUser
// Go: `func lookupUser(username string) (*User, error)` at lookup_unix.go line 218.
pub(super) fn lookup_user(username: string) -> (User, error) {
    let (data, err) = crate::os::ReadFile(string::from_static(USER_FILE));
    if !err.IsNil() {
        return (User::default(), err);
    }
    return find_user_by(data, username.clone(), 0i64, false)
        .unwrap_or_else(|| (User::default(), UnknownUserError::new(username)));
}

// go: sdk 1.25.5 os/user/lookup_unix.go:227-234 lookupUserId
// Go: `func lookupUserId(uid string) (*User, error)` at lookup_unix.go line 227.
pub(super) fn lookup_user_id(uid: string) -> (User, error) {
    let (data, err) = crate::os::ReadFile(string::from_static(USER_FILE));
    if !err.IsNil() {
        return (User::default(), err);
    }
    // Go: lookup_unix.go:179 — Atoi check for numeric uid.
    let (i, e) = strconv::Atoi(uid.clone());
    if !e.IsNil() {
        return (
            User::default(),
            // Go: errors.New("user: invalid userid " + uid). The `{}`
            // was a Rust placeholder; see net/mail.
            errors::New(string::from_static("user: invalid userid ") + uid.clone()),
        );
    }
    return find_user_by(data, uid, 2i64, false)
        .unwrap_or_else(|| (User::default(), UnknownUserIdError::new(crate::int(i))));
}

// ─── /etc/passwd + /etc/group line scanner ───────────────────────────
//
// Go's lookup_unix.go uses bufio.Reader.ReadLine + lineFunc closures.
// Goish: read the whole file via os.ReadFile (already used for
// passwd) and split on '\n'.
//
// A line here used to assert the two were the same for files under
// the buffer size. That was never measured, and it is not true in
// general: they diverge on a file with no trailing newline, on one
// large enough for Go's bufio.Reader to split a line across reads,
// and in memory, which is O(file) here against O(line) in Go. For
// /etc/passwd and /etc/group none of those bite, and that is the
// reason to accept the shape — not a proof.

// go: none — goish shape. Go streams the file through readColonFile
// and never materialises the lines; goish reads it whole and splits.
fn read_lines(data: slice<byte>) -> Vec<slice<byte>> {
    let mut out: Vec<slice<byte>> = Vec::new();
    let raw = data.__into_vec();
    let mut start = 0usize;
    for i in 0..raw.len() {
        if raw[i] == b'\n' {
            // Go: bytes.TrimSpace
            let line = bytes::TrimSpace(slice::__from_vec(raw[start..i].to_vec()));
            // Go: skip empty + leading-#
            let lb = line.clone();
            let lbv = lb.__into_vec();
            if !lbv.is_empty() && lbv[0] != b'#' {
                out.push(slice::__from_vec(lbv));
            }
            start = i + 1;
        }
    }
    if start < raw.len() {
        let line = bytes::TrimSpace(slice::__from_vec(raw[start..].to_vec()));
        let lbv = line.__into_vec();
        if !lbv.is_empty() && lbv[0] != b'#' {
            out.push(slice::__from_vec(lbv));
        }
    }
    return out;
}

// go: none — goish shape: folds readColonFile, matchUserIndexValue
// Mirrors lookup_unix.go:140-176  matchUserIndexValue + findUser*.
//
// `idx` is the column to match against (0=username, 2=uid).
// and the findUserId/findUsername pair into one scan.
fn find_user_by(
    data: slice<byte>,
    value: string,
    idx: int,
    _unused: bool,
) -> Option<(User, error)> {
    for line in read_lines(data) {
        let lstr = string::from_bytes(&line.__into_vec());
        // Go: strings.SplitN(string(line), ":", 7)
        let parts = strings::SplitN(lstr, string::from_static(":"), 7);
        if parts.Len() < 6 {
            continue;
        }
        // Go: parts[idx] != value  /  parts[0] == ""  /  parts[0][0] == '+' or '-'
        let p0 = parts[0].clone();
        let p0b = p0.as_bytes();
        if p0b.is_empty() || p0b[0] == b'+' || p0b[0] == b'-' {
            continue;
        }
        if parts[idx] != value {
            continue;
        }
        // Go: strconv.Atoi(parts[2]) and parts[3] sanity checks.
        let (_uid_n, e_u) = strconv::Atoi(parts[2].clone());
        let (_gid_n, e_g) = strconv::Atoi(parts[3].clone());
        if !e_u.IsNil() || !e_g.IsNil() {
            continue;
        }
        // Go: u.Name, _, _ = strings.Cut(u.Name, ",")
        let raw_name = parts[4].clone();
        let (display, _, _) = strings::Cut(raw_name, string::from_static(","));
        let user = User {
            Username: parts[0].clone(),
            Uid: parts[2].clone(),
            Gid: parts[3].clone(),
            Name: display,
            HomeDir: parts[5].clone(),
        };
        return Some((user, errors::nil));
    }
    return None;
}

// go: none — goish shape: folds readColonFile, matchGroupIndexValue
// Mirrors lookup_unix.go:93-117  matchGroupIndexValue + findGroup*.
//
// `idx` is the column to match against (0=group name, 2=gid).
// and the findGroupId/findGroupName pair into one scan.
fn find_group_by(
    data: slice<byte>,
    value: string,
    idx: int,
    _unused: bool,
) -> Option<(Group, error)> {
    for line in read_lines(data) {
        let lstr = string::from_bytes(&line.__into_vec());
        // Go: strings.SplitN(string(line), ":", 4)
        let parts = strings::SplitN(lstr, string::from_static(":"), 4);
        if parts.Len() < 4 {
            continue;
        }
        let p0 = parts[0].clone();
        let p0b = p0.as_bytes();
        if p0b.is_empty() || p0b[0] == b'+' || p0b[0] == b'-' {
            continue;
        }
        if parts[idx] != value {
            continue;
        }
        let (_gid_n, e) = strconv::Atoi(parts[2].clone());
        if !e.IsNil() {
            continue;
        }
        let g = Group {
            Name: parts[0].clone(),
            Gid: parts[2].clone(),
        };
        return Some((g, errors::nil));
    }
    return None;
}

// go: none — goish scaffolding, not a port: it silences the
// unused-warning for the trailing-bool param kept to mirror Go's
// lineFunc shape.
#[allow(dead_code)]
fn _byte_ref(_: byte) {}
