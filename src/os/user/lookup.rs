// go: file os/user/lookup.go decls: Current, Lookup, LookupId, LookupGroup, LookupGroupId, User.GroupIds
// goishlint:ignore GOISH021 cache — Go's `var cache struct{ sync.Once;
//     u *User; err error }`, memoising Current for the process. goish
//     reads /etc/passwd on each call; the file is small and the cache
//     would have to be invalidated by nothing, which is a decision
//     rather than an oversight.
// goishlint:ignore GOISH021 colon — Go's `var colon = []byte{':'}`, a
//     package-level byte slice for bytes.Split. goish splits on the
//     byte literal at the two sites that need it.
//
// os/user — the public lookup surface, and the two file paths Go
// declares beside it.
//
// Deviations:
//   * `Current()` reads /etc/passwd and matches on `getuid()`, with
//     $USER as a fallback. Go's `current()` has a cache and several
//     platform-specific branches; this reads the file directly.
//   * `User.GroupIds()` returns the primary GID alone. Go's
//     listgroups_unix.go enumerates supplementary groups through
//     getgrouplist, 109 lines that goish does not port — see the note
//     in examples/osuser_ref_smoke.rs about what that smoke can and
//     cannot catch.
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

use super::user::{Group, User};
use super::lookup_unix::{lookup_group, lookup_group_id, lookup_user, lookup_user_id};

pub(super) const USER_FILE: &str = "/etc/passwd";
pub(super) const GROUP_FILE: &str = "/etc/group";
// ─── Free fns: Lookup / LookupId / LookupGroup / LookupGroupId ───────

// go: sdk 1.25.5 os/user/lookup.go:39-44 Lookup
// Go: `func Lookup(username string) (*User, error)` at lookup.go line 39.
/// `os/user.Lookup(username)` — find user by login name.
pub fn Lookup<U: Into<string>>(username: U) -> (User, error) {
    let username: string = username.into();
    // Go: if u, err := Current(); err == nil && u.Username == username { return u, err }
    let (cur, cur_err) = Current();
    if cur_err.IsNil() && cur.Username == username {
        return (cur, errors::nil);
    }
    return lookup_user(username);
}

// go: sdk 1.25.5 os/user/lookup.go:48-53 LookupId
// Go: `func LookupId(uid string) (*User, error)` at lookup.go line 48.
/// `os/user.LookupId(uid)` — find user by uid string.
pub fn LookupId<U: Into<string>>(uid: U) -> (User, error) {
    let uid: string = uid.into();
    let (cur, cur_err) = Current();
    if cur_err.IsNil() && cur.Uid == uid {
        return (cur, errors::nil);
    }
    return lookup_user_id(uid);
}

// go: sdk 1.25.5 os/user/lookup.go:57-59 LookupGroup
// Go: `func LookupGroup(name string) (*Group, error)` at lookup.go line 57.
/// `os/user.LookupGroup(name)` — find group by name.
pub fn LookupGroup<N: Into<string>>(name: N) -> (Group, error) {
    let name: string = name.into();
    return lookup_group(name);
}

// go: sdk 1.25.5 os/user/lookup.go:63-65 LookupGroupId
// Go: `func LookupGroupId(gid string) (*Group, error)` at lookup.go line 63.
/// `os/user.LookupGroupId(gid)` — find group by gid string.
pub fn LookupGroupId<G: Into<string>>(gid: G) -> (Group, error) {
    let gid: string = gid.into();
    return lookup_group_id(gid);
}

// go: sdk 1.25.5 os/user/lookup.go:21-28 Current
// Go: `func Current() (*User, error)` at lookup.go line 21.
//
// Slim: re-read /etc/passwd on each call (Go caches via sync.Once;
// caching is omitted for simplicity — passwd lookups are rare in
// hot paths).
/// `os/user.Current()` — return the current user.
pub fn Current() -> (User, error) {
    // Use the real getuid syscall if available; fall back to $USER env.
    let uid = crate::os::Getuid();
    let uid_str = strconv::Itoa(crate::int(uid));
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
    return (User::default(), e);
}

// Go: `func (u *User) GroupIds() ([]string, error)` at user.go line 68.
//
// Slim: returns the primary GID only. Listing supplementary groups
// requires parsing /etc/group, which is straightforward but deferred
// for a tighter port.
impl User {
    // go: sdk 1.25.5 os/user/lookup.go:68-70 User.GroupIds
    /// Return the user's group IDs. Slim: primary GID only.
    pub fn GroupIds(&self) -> (slice<string>, error) {
        let mut out: Vec<string> = Vec::new();
        if self.Gid.Len() > 0 {
            out.push(self.Gid.clone());
        }
        return (slice::__from_vec(out), errors::nil);
    }
}
