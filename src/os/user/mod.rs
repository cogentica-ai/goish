// os/user — user account lookups via /etc/passwd and /etc/group.
//
// Reference: /share/go/src/os/user/{user.go, lookup.go, lookup_unix.go}.
//
// Slim deviations from upstream:
//
//   * Pure-Go variant only — no cgo / getpwuid_r path. Goish has no
//     libc, so the cgo branch in Go's `lookup_unix.go:5` is dropped.
//   * `User.GroupIds()` returns just the user's primary GID; the
//     supplementary-group enumeration in listgroups_unix.go (109 LOC
//     of getgrouplist parsing) is deferred — most callers only need
//     the primary gid for drop-privilege checks.
//   * `Current()` reads /etc/passwd and matches by `getuid()` (or
//     $USER as fallback). Go's `current()` has many platform-
//     specific branches; the slim version uses /etc/passwd directly.
//   * Returns `User` / `Group` by value (not `*User`/`*Group`); the
//     pointer-vs-value distinction collapses in goish.

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

// ─── User / Group structs (user.go:34-64) ────────────────────────────

// Go: user.go:34
//   type User struct { Uid, Gid, Username, Name, HomeDir string }
/// `os/user.User` — user account record. Mirrors `os/user.User`
/// (user.go:34).
#[derive(Clone, Default)]
pub struct User {
    /// Decimal user-id string (POSIX).
    pub Uid: string,
    /// Primary group-id string (POSIX).
    pub Gid: string,
    /// Login name (passwd field 1).
    pub Username: string,
    /// Display / real name (passwd field 5, GECOS — first comma field).
    pub Name: string,
    /// Home directory (passwd field 6).
    pub HomeDir: string,
}

// Go: user.go:60
//   type Group struct { Gid, Name string }
/// `os/user.Group` — group record. Mirrors `os/user.Group` (user.go:61).
#[derive(Clone, Default)]
pub struct Group {
    /// Decimal group-id string.
    pub Gid: string,
    /// Group name.
    pub Name: string,
}

// ─── Typed error sentinels (user.go:66-95) ───────────────────────────

// Go: user.go:67  type UnknownUserIdError int
/// `os/user.UnknownUserIdError` — emitted by `LookupId` when no entry
/// matches the numeric uid.
#[derive(Clone, Copy)]
pub struct UnknownUserIdError(pub int);

impl ErrorTrait for UnknownUserIdError {
    fn Error(&self) -> string {
        // Go: "user: unknown userid " + strconv.Itoa(int(e))
        let mut s = string::from_static("user: unknown userid ");
        s = s + strconv::Itoa(self.0);
        s
    }
}

impl UnknownUserIdError {
    pub fn new(id: int) -> error {
        errors::Wrap(UnknownUserIdError(id))
    }
}

// Go: user.go:75  type UnknownUserError string
/// `os/user.UnknownUserError` — emitted by `Lookup` when no entry
/// matches the username.
#[derive(Clone)]
pub struct UnknownUserError(pub string);

impl ErrorTrait for UnknownUserError {
    fn Error(&self) -> string {
        let mut s = string::from_static("user: unknown user ");
        s = s + self.0.clone();
        s
    }
}

impl UnknownUserError {
    pub fn new<N: Into<string>>(name: N) -> error {
        let name: string = name.into();
        errors::Wrap(UnknownUserError(name))
    }
}

// Go: user.go:84  type UnknownGroupIdError string
/// `os/user.UnknownGroupIdError` — emitted by `LookupGroupId` when no
/// entry matches the gid string.
#[derive(Clone)]
pub struct UnknownGroupIdError(pub string);

impl ErrorTrait for UnknownGroupIdError {
    fn Error(&self) -> string {
        let mut s = string::from_static("group: unknown groupid ");
        s = s + self.0.clone();
        s
    }
}

impl UnknownGroupIdError {
    pub fn new<I: Into<string>>(id: I) -> error {
        let id: string = id.into();
        errors::Wrap(UnknownGroupIdError(id))
    }
}

// Go: user.go:91  type UnknownGroupError string
/// `os/user.UnknownGroupError` — emitted by `LookupGroup` when no
/// entry matches the group name.
#[derive(Clone)]
pub struct UnknownGroupError(pub string);

impl ErrorTrait for UnknownGroupError {
    fn Error(&self) -> string {
        let mut s = string::from_static("group: unknown group ");
        s = s + self.0.clone();
        s
    }
}

impl UnknownGroupError {
    pub fn new<N: Into<string>>(name: N) -> error {
        let name: string = name.into();
        errors::Wrap(UnknownGroupError(name))
    }
}

// ─── /etc/passwd + /etc/group constants (lookup.go:9-11) ─────────────

const USER_FILE: &str = "/etc/passwd";
const GROUP_FILE: &str = "/etc/group";

// ─── Free fns: Lookup / LookupId / LookupGroup / LookupGroupId ───────

// Go: lookup.go:39  func Lookup(username string) (*User, error)
/// `os/user.Lookup(username)` — find user by login name.
pub fn Lookup<U: Into<string>>(username: U) -> (User, error) {
    let username: string = username.into();
    // Go: if u, err := Current(); err == nil && u.Username == username { return u, err }
    let (cur, cur_err) = Current();
    if cur_err.IsNil() && cur.Username == username {
        return (cur, errors::nil);
    }
    lookup_user(username)
}

// Go: lookup.go:48  func LookupId(uid string) (*User, error)
/// `os/user.LookupId(uid)` — find user by uid string.
pub fn LookupId<U: Into<string>>(uid: U) -> (User, error) {
    let uid: string = uid.into();
    let (cur, cur_err) = Current();
    if cur_err.IsNil() && cur.Uid == uid {
        return (cur, errors::nil);
    }
    lookup_user_id(uid)
}

// Go: lookup.go:57  func LookupGroup(name string) (*Group, error)
/// `os/user.LookupGroup(name)` — find group by name.
pub fn LookupGroup<N: Into<string>>(name: N) -> (Group, error) {
    let name: string = name.into();
    lookup_group(name)
}

// Go: lookup.go:63  func LookupGroupId(gid string) (*Group, error)
/// `os/user.LookupGroupId(gid)` — find group by gid string.
pub fn LookupGroupId<G: Into<string>>(gid: G) -> (Group, error) {
    let gid: string = gid.into();
    lookup_group_id(gid)
}

// Go: lookup.go:21  func Current() (*User, error)
//
// Slim: re-read /etc/passwd on each call (Go caches via sync.Once;
// caching is omitted for simplicity — passwd lookups are rare in
// hot paths).
/// `os/user.Current()` — return the current user.
pub fn Current() -> (User, error) {
    // Use the real getuid syscall if available; fall back to $USER env.
    let uid = crate::os::Getuid();
    let uid_str = strconv::Itoa(uid as int);
    let (u, e) = lookup_user_id(uid_str.clone());
    if e.IsNil() {
        return (u, errors::nil);
    }
    // Fallback: try $USER env.
    let user_env = crate::os::Getenv(string::from_static("USER"));
    if user_env.Len() > 0 {
        let (u2, e2) = lookup_user(user_env);
        if e2.IsNil() {
            return (u2, errors::nil);
        }
    }
    // Final: synthesize a minimal record so callers can still proceed.
    (User::default(), e)
}

// Go: user.go:68  func (u *User) GroupIds() ([]string, error)
//
// Slim: returns the primary GID only. Listing supplementary groups
// requires parsing /etc/group, which is straightforward but deferred
// for a tighter port.
impl User {
    /// Return the user's group IDs. Slim: primary GID only.
    pub fn GroupIds(&self) -> (slice<string>, error) {
        let mut out: Vec<string> = Vec::new();
        if self.Gid.Len() > 0 {
            out.push(self.Gid.clone());
        }
        (slice::__from_vec(out), errors::nil)
    }
}

// ─── lookup_unix.go body ──────────────────────────────────────────────

// Go: lookup_unix.go:200  func lookupGroup(groupname string) (*Group, error)
fn lookup_group(name: string) -> (Group, error) {
    let (data, err) = crate::os::ReadFile(string::from_static(GROUP_FILE));
    if !err.IsNil() {
        return (Group::default(), err);
    }
    find_group_by(data, name.clone(), 0, false)
        .unwrap_or_else(|| (Group::default(), UnknownGroupError::new(name)))
}

// Go: lookup_unix.go:209  func lookupGroupId(id string) (*Group, error)
fn lookup_group_id(id: string) -> (Group, error) {
    let (data, err) = crate::os::ReadFile(string::from_static(GROUP_FILE));
    if !err.IsNil() {
        return (Group::default(), err);
    }
    find_group_by(data, id.clone(), 2, false)
        .unwrap_or_else(|| (Group::default(), UnknownGroupIdError::new(id)))
}

// Go: lookup_unix.go:218  func lookupUser(username string) (*User, error)
fn lookup_user(username: string) -> (User, error) {
    let (data, err) = crate::os::ReadFile(string::from_static(USER_FILE));
    if !err.IsNil() {
        return (User::default(), err);
    }
    find_user_by(data, username.clone(), 0i64, false)
        .unwrap_or_else(|| (User::default(), UnknownUserError::new(username)))
}

// Go: lookup_unix.go:227  func lookupUserId(uid string) (*User, error)
fn lookup_user_id(uid: string) -> (User, error) {
    let (data, err) = crate::os::ReadFile(string::from_static(USER_FILE));
    if !err.IsNil() {
        return (User::default(), err);
    }
    // Go: lookup_unix.go:179 — Atoi check for numeric uid.
    let (i, e) = strconv::Atoi(uid.clone());
    if !e.IsNil() {
        return (
            User::default(),
            errors::New(crate::Sprintf!("user: invalid userid {}", uid.clone())),
        );
    }
    find_user_by(data, uid, 2i64, false)
        .unwrap_or_else(|| (User::default(), UnknownUserIdError::new(i as int)))
}

// ─── /etc/passwd + /etc/group line scanner ───────────────────────────
//
// Go's lookup_unix.go uses bufio.Reader.ReadLine + lineFunc closures.
// Goish: read the whole file via os.ReadFile (already used for
// passwd) and split on '\n'. Behaves identically for files smaller
// than the buffer; this is line-by-line semantically.

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
    out
}

// Mirrors lookup_unix.go:140-176  matchUserIndexValue + findUser*.
//
// `idx` is the column to match against (0=username, 2=uid).
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
    None
}

// Mirrors lookup_unix.go:93-117  matchGroupIndexValue + findGroup*.
//
// `idx` is the column to match against (0=group name, 2=gid).
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
    None
}

// Silence unused-warning for the trailing-bool param kept to mirror
// Go's lineFunc shape.
#[allow(dead_code)]
fn _byte_ref(_: byte) {}
