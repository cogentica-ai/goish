// go: file os/user/user.go decls: UnknownUserIdError.Error, UnknownUserError.Error, UnknownGroupIdError.Error, UnknownGroupError.Error
//
// os/user — the User and Group value types and the four unknown-lookup
// errors. Go's user.go is types and their Error methods only; the
// lookups live in lookup.rs and lookup_unix.rs, one `.rs` per `.go`.
//
// Deviations:
//   * `User` and `Group` are returned by value, not `*User`/`*Group`.
//     The pointer-vs-value distinction collapses in goish.
//   * Go's error types are defined ON the underlying primitive
//     (`type UnknownUserIdError int`); goish spells them as newtypes,
//     so each also carries a small constructor.
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

// Go: at user.go line 34.
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

// Go: at user.go line 60.
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

// Go: `type UnknownUserIdError int` at user.go line 67.
/// `os/user.UnknownUserIdError` — emitted by `LookupId` when no entry
/// matches the numeric uid.
#[derive(Clone, Copy)]
pub struct UnknownUserIdError(pub int);

impl ErrorTrait for UnknownUserIdError {
    // go: sdk 1.25.5 os/user/user.go:69-71 UnknownUserIdError.Error
    fn Error(&self) -> string {
        // Go: "user: unknown userid " + strconv.Itoa(int(e))
        let mut s = string::from_static("user: unknown userid ");
        s = s + strconv::Itoa(self.0);
        return s;
    }
}

impl UnknownUserIdError {
    // go: none — goish constructor. Go's type IS the primitive
    // (`type UnknownUserIdError …`), so a Go caller writes the value
    // directly; goish's newtype needs a way in that also wraps it
    // as an error.
    pub fn new(id: int) -> error {
        return errors::Wrap(UnknownUserIdError(id));
    }
}

// Go: `type UnknownUserError string` at user.go line 75.
/// `os/user.UnknownUserError` — emitted by `Lookup` when no entry
/// matches the username.
#[derive(Clone)]
pub struct UnknownUserError(pub string);

impl ErrorTrait for UnknownUserError {
    // go: sdk 1.25.5 os/user/user.go:77-79 UnknownUserError.Error
    fn Error(&self) -> string {
        let mut s = string::from_static("user: unknown user ");
        s = s + self.0.clone();
        return s;
    }
}

impl UnknownUserError {
    // go: none — goish constructor. Go's type IS the primitive
    // (`type UnknownUserError …`), so a Go caller writes the value
    // directly; goish's newtype needs a way in that also wraps it
    // as an error.
    pub fn new<N: Into<string>>(name: N) -> error {
        let name: string = name.into();
        return errors::Wrap(UnknownUserError(name));
    }
}

// Go: `type UnknownGroupIdError string` at user.go line 84.
/// `os/user.UnknownGroupIdError` — emitted by `LookupGroupId` when no
/// entry matches the gid string.
#[derive(Clone)]
pub struct UnknownGroupIdError(pub string);

impl ErrorTrait for UnknownGroupIdError {
    // go: sdk 1.25.5 os/user/user.go:85-87 UnknownGroupIdError.Error
    fn Error(&self) -> string {
        let mut s = string::from_static("group: unknown groupid ");
        s = s + self.0.clone();
        return s;
    }
}

impl UnknownGroupIdError {
    // go: none — goish constructor. Go's type IS the primitive
    // (`type UnknownGroupIdError …`), so a Go caller writes the value
    // directly; goish's newtype needs a way in that also wraps it
    // as an error.
    pub fn new<I: Into<string>>(id: I) -> error {
        let id: string = id.into();
        return errors::Wrap(UnknownGroupIdError(id));
    }
}

// Go: `type UnknownGroupError string` at user.go line 91.
/// `os/user.UnknownGroupError` — emitted by `LookupGroup` when no
/// entry matches the group name.
#[derive(Clone)]
pub struct UnknownGroupError(pub string);

impl ErrorTrait for UnknownGroupError {
    // go: sdk 1.25.5 os/user/user.go:93-95 UnknownGroupError.Error
    fn Error(&self) -> string {
        let mut s = string::from_static("group: unknown group ");
        s = s + self.0.clone();
        return s;
    }
}

impl UnknownGroupError {
    // go: none — goish constructor. Go's type IS the primitive
    // (`type UnknownGroupError …`), so a Go caller writes the value
    // directly; goish's newtype needs a way in that also wraps it
    // as an error.
    pub fn new<N: Into<string>>(name: N) -> error {
        let name: string = name.into();
        return errors::Wrap(UnknownGroupError(name));
    }
}

// ─── /etc/passwd + /etc/group constants (lookup.go:9-11) ─────────────
