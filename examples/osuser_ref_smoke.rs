// osuser_ref_smoke — os/user against a running Go.
// (os/user/lookup_unix.go)
//
// The lines in GO are the verbatim output of `tools/gen_osuser_ref.go`
// run in `package user_test` by `scripts/goref.sh` WITH CGO_ENABLED=0,
// which matters more here than anywhere else in the tree — see below.
//
// os/user answers "who is this process, and who is this name?" by
// reading /etc/passwd and /etc/group. The lookups are what a caller
// branches on, and the interesting part is the FAILURES: a caller that
// cannot tell "no such user" from "that is not a user id at all" cannot
// decide whether to fall back or to fail.
//
// goish matched Go on all 20 lines. What is pinned:
//
//   * Lookup and LookupGroup report a missing name as UnknownUserError
//     / UnknownGroupError, and the name is in the message. Matching is
//     exact: "root " and "ROOT" are both unknown.
//   * LookupId parses the id with Atoi FIRST and reports a non-numeric
//     one as "user: invalid userid abc" — which is NOT
//     UnknownUserIdError, because a malformed id is a different failure
//     from a missing one.
//   * The id is then matched as a STRING against the file's field, so
//     "00" does not find uid 0: it reports UnknownUserIdError(0), with
//     the message carrying the PARSED number while the match used the
//     raw text. That asymmetry is Go's, and it is the kind of thing
//     only a reference settles.
//   * LookupGroupId does no Atoi at all, so a non-numeric gid is simply
//     an unknown group.
//   * GroupIds returns decimal ids including the user's primary gid.
//
// The CGO trap, recorded because it cost a full round of investigation
// and will cost the next person one too: os/user has TWO
// implementations in the Go tree. With cgo enabled, LookupId goes
// through getpwuid and parses the id NUMERICALLY, so "00" finds root
// and a non-numeric id returns strconv's own error. With cgo disabled
// it reads /etc/passwd itself, which is what goish ports. Generating
// this reference with the ambient cgo setting produced five lines that
// looked exactly like goish defects and were not; they are Go's other
// implementation. scripts/goref.sh now carries a note about it.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::errors;
use goish::errors::error;
use goish::fmt;
use goish::gostring::string;
use goish::os::user;
use goish::syscall;
use goish::types::int;

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}
// Go asks `err.(user.UnknownUserError)`; goish's errors::As does the
// same job through the concrete type.
fn is_unknown_user(e: &error) -> bool {
    return errors::As::<user::UnknownUserError>(e.clone()).is_some();
}
fn is_unknown_userid(e: &error) -> bool {
    return errors::As::<user::UnknownUserIdError>(e.clone()).is_some();
}
fn is_unknown_group(e: &error) -> bool {
    return errors::As::<user::UnknownGroupError>(e.clone()).is_some();
}
fn is_unknown_groupid(e: &error) -> bool {
    return errors::As::<user::UnknownGroupIdError>(e.clone()).is_some();
}

// go: none — goish idiom: the reference lines, in the order Go printed
//     them. Comparing whole rendered lines keeps this smoke and the
//     generator in lockstep: a case added to one is a mismatch in the
//     other, never a silent pass.
const GO: [&str; 20] = [
    "current uid-nonempty=true gid-nonempty=true name-nonempty=true home-nonempty=true",
    "lookup root uid=\"0\" gid=\"0\" username=\"root\" home=\"/root\"",
    "lookupid 0 username=\"root\" uid=\"0\"",
    "lookup \"\"                             -> err=\"user: unknown user \" unknown=true",
    "lookup \"definitely-no-such-user-xyzzy\" -> err=\"user: unknown user definitely-no-such-user-xyzzy\" unknown=true",
    "lookup \"root \"                        -> err=\"user: unknown user root \" unknown=true",
    "lookup \"ROOT\"                         -> err=\"user: unknown user ROOT\" unknown=true",
    "lookupid \"\"         -> err=\"user: invalid userid \" unknown=false",
    "lookupid \"999999\"   -> err=\"user: unknown userid 999999\" unknown=true",
    "lookupid \"-1\"       -> err=\"user: unknown userid -1\" unknown=true",
    "lookupid \"abc\"      -> err=\"user: invalid userid abc\" unknown=false",
    "lookupid \"0x0\"      -> err=\"user: invalid userid 0x0\" unknown=false",
    "lookupid \"00\"       -> err=\"user: unknown userid 0\" unknown=true",
    "group 0 gid=\"0\" name-nonempty=true",
    "lookupgroup \"\"                               -> err=\"group: unknown group \" unknown=true",
    "lookupgroup \"definitely-no-such-group-xyzzy\" -> err=\"group: unknown group definitely-no-such-group-xyzzy\" unknown=true",
    "lookupgroupid \"\"         -> err=\"group: unknown groupid \" unknown=true",
    "lookupgroupid \"999999\"   -> err=\"group: unknown groupid 999999\" unknown=true",
    "lookupgroupid \"abc\"      -> err=\"group: unknown groupid abc\" unknown=true",
    "groupids nonempty=true all-numeric=true has-primary=true",
];

// go: none — goish idiom: one comparison, printing the divergence when
//     it is one, so a FAIL says what it got and not just that it did.
fn chk(failed: &mut int, ln: &mut int, got: string) {
    if *ln >= GO.len() as int {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln + 1, got);
        *failed += 1;
        *ln += 1;
        return;
    }
    let want = s(GO[*ln as usize]);
    *ln += 1;
    if got == want {
        return;
    }
    fmt::Printf!("[!!] line %d FAIL\n  got  %q\n  want %q\n", *ln, got, want);
    *failed += 1;
}

#[goish::main]
fn main() {
    let mut failed: int = 0;
    let mut ln: int = 0;

    let (u, err) = user::Current();
    if !err.IsNil() {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("current err=%q", err.Error()),
        );
    } else {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "current uid-nonempty=%v gid-nonempty=%v name-nonempty=%v home-nonempty=%v",
                u.Uid.Len() != 0,
                u.Gid.Len() != 0,
                u.Username.Len() != 0,
                u.HomeDir.Len() != 0
            ),
        );
    }
    {
        let (r, err) = user::Lookup(s("root"));
        if !err.IsNil() {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("lookup root err=%q", err.Error()),
            );
        } else {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "lookup root uid=%q gid=%q username=%q home=%q",
                    r.Uid.clone(),
                    r.Gid.clone(),
                    r.Username.clone(),
                    r.HomeDir.clone()
                ),
            );
        }
        let (r2, err) = user::LookupId(s("0"));
        if !err.IsNil() {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("lookupid 0 err=%q", err.Error()),
            );
        } else {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "lookupid 0 username=%q uid=%q",
                    r2.Username.clone(),
                    r2.Uid.clone()
                ),
            );
        }
    }
    for name in ["", "definitely-no-such-user-xyzzy", "root ", "ROOT"] {
        let (_, err) = user::Lookup(s(name));
        if !err.IsNil() {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "lookup %-30q -> err=%q unknown=%v",
                    s(name),
                    err.Error(),
                    is_unknown_user(&err)
                ),
            );
            continue;
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("lookup %-30q -> ok", s(name)),
        );
    }
    for id in ["", "999999", "-1", "abc", "0x0", "00"] {
        let (_, err) = user::LookupId(s(id));
        if !err.IsNil() {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "lookupid %-10q -> err=%q unknown=%v",
                    s(id),
                    err.Error(),
                    is_unknown_userid(&err)
                ),
            );
            continue;
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("lookupid %-10q -> ok", s(id)),
        );
    }
    {
        let (g, err) = user::LookupGroupId(s("0"));
        if !err.IsNil() {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("group 0 err=%q", err.Error()),
            );
        } else {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "group 0 gid=%q name-nonempty=%v",
                    g.Gid.clone(),
                    g.Name.Len() != 0
                ),
            );
        }
    }
    for name in ["", "definitely-no-such-group-xyzzy"] {
        let (_, err) = user::LookupGroup(s(name));
        if !err.IsNil() {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "lookupgroup %-32q -> err=%q unknown=%v",
                    s(name),
                    err.Error(),
                    is_unknown_group(&err)
                ),
            );
            continue;
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("lookupgroup %-32q -> ok", s(name)),
        );
    }
    for id in ["", "999999", "abc"] {
        let (_, err) = user::LookupGroupId(s(id));
        if !err.IsNil() {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "lookupgroupid %-10q -> err=%q unknown=%v",
                    s(id),
                    err.Error(),
                    is_unknown_groupid(&err)
                ),
            );
            continue;
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("lookupgroupid %-10q -> ok", s(id)),
        );
    }
    {
        let (ids, err) = u.GroupIds();
        if !err.IsNil() {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("groupids err=%q", err.Error()),
            );
        } else {
            let mut all_numeric = true;
            let mut has_primary = false;
            for i in 0..ids.Len() {
                let idv = ids[i].clone();
                for c in idv.as_bytes() {
                    if *c < b'0' || *c > b'9' {
                        all_numeric = false;
                    }
                }
                if idv == u.Gid {
                    has_primary = true;
                }
            }
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "groupids nonempty=%v all-numeric=%v has-primary=%v",
                    ids.Len() > 0,
                    all_numeric,
                    has_primary
                ),
            );
        }
    }
    if ln != GO.len() as int {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln, GO.len() as int);
        failed += 1;
    }
    if failed == 0 {
        fmt::Printf!("ok %d/%d\n", ln, ln);
        return;
    }
    fmt::Printf!("FAILED %d of %d\n", failed, ln);
    syscall::Exit(1);
}
