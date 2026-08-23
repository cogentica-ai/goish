// os_user_smoke — exercise os/user package.
//
// Coverage:
//   1. Lookup("root") returns User{Username: "root", Uid: "0", ...}.
//   2. LookupId("0") returns User{Username: "root", ...}.
//   3. Lookup of non-existent user returns UnknownUserError.
//   4. LookupId of non-existent uid returns UnknownUserIdError.
//   5. LookupGroup("root") returns Group{Name: "root", Gid: "0"}.
//   6. LookupGroupId("0") returns Group{Name: "root", ...}.
//   7. LookupGroup of non-existent group returns UnknownGroupError.
//   8. LookupGroupId of non-existent gid returns UnknownGroupIdError.
//   9. Current() returns a non-empty Username.
//  10. User.GroupIds() returns at least primary GID.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::errors::{self, error};
use goish::fmt;
use goish::gostring::string;
use goish::os::user::{
    self, UnknownGroupError, UnknownGroupIdError, UnknownUserError, UnknownUserIdError,
};
use goish::runtime::sched::schedule;
use goish::{go, syscall};

static FAILED: AtomicUsize = AtomicUsize::new(0);

fn ok_line(msg: &[u8]) {
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
}

fn fail() {
    FAILED.fetch_add(1, Ordering::AcqRel);
}

#[goish::main]
fn main() {
    go!(|| {
        run_tests();
        let f = FAILED.load(Ordering::Acquire);
        if f == 0 {
            fmt::Println!("ok 10/10");
            syscall::Exit(0);
        } else {
            fmt::Println!("FAIL", f as i64, "of 10");
            syscall::Exit(1);
        }
    });
    schedule();
}

fn run_tests() {
    test_1_lookup_root_by_name();
    test_2_lookup_root_by_id();
    test_3_unknown_user_name();
    test_4_unknown_user_id();
    test_5_lookup_group_root();
    test_6_lookup_group_id_zero();
    test_7_unknown_group_name();
    test_8_unknown_group_id();
    test_9_current_returns_username();
    test_10_group_ids_includes_primary();
}

fn s(x: &'static str) -> string {
    string::from_static(x)
}

fn test_1_lookup_root_by_name() {
    let (u, e) = user::Lookup(s("root"));
    if e.IsNil() && u.Username == s("root") && u.Uid == s("0") {
        ok_line(b"[ 1] Lookup(\"root\") by name      PASS\n");
    } else {
        ok_line(b"[ 1] Lookup(\"root\") by name      FAIL\n");
        fail();
    }
}

fn test_2_lookup_root_by_id() {
    let (u, e) = user::LookupId(s("0"));
    if e.IsNil() && u.Username == s("root") && u.Uid == s("0") {
        ok_line(b"[ 2] LookupId(\"0\")               PASS\n");
    } else {
        ok_line(b"[ 2] LookupId(\"0\")               FAIL\n");
        fail();
    }
}

fn test_3_unknown_user_name() {
    let (_u, e) = user::Lookup(s("definitely_not_a_user_zzz"));
    if !e.IsNil() {
        // Verify the typed error.
        if errors::As::<UnknownUserError>(e).is_some() {
            ok_line(b"[ 3] UnknownUserError typed     PASS\n");
        } else {
            ok_line(b"[ 3] UnknownUserError typed     FAIL\n");
            fail();
        }
    } else {
        ok_line(b"[ 3] UnknownUserError typed     FAIL\n");
        fail();
    }
}

fn test_4_unknown_user_id() {
    let (_u, e) = user::LookupId(s("99999999"));
    if !e.IsNil() {
        if errors::As::<UnknownUserIdError>(e).is_some() {
            ok_line(b"[ 4] UnknownUserIdError typed   PASS\n");
        } else {
            ok_line(b"[ 4] UnknownUserIdError typed   FAIL\n");
            fail();
        }
    } else {
        ok_line(b"[ 4] UnknownUserIdError typed   FAIL\n");
        fail();
    }
}

fn test_5_lookup_group_root() {
    let (g, e) = user::LookupGroup(s("root"));
    if e.IsNil() && g.Name == s("root") && g.Gid == s("0") {
        ok_line(b"[ 5] LookupGroup(\"root\")         PASS\n");
    } else {
        ok_line(b"[ 5] LookupGroup(\"root\")         FAIL\n");
        fail();
    }
}

fn test_6_lookup_group_id_zero() {
    let (g, e) = user::LookupGroupId(s("0"));
    if e.IsNil() && g.Name == s("root") {
        ok_line(b"[ 6] LookupGroupId(\"0\")          PASS\n");
    } else {
        ok_line(b"[ 6] LookupGroupId(\"0\")          FAIL\n");
        fail();
    }
}

fn test_7_unknown_group_name() {
    let (_g, e): (user::Group, error) = user::LookupGroup(s("zzz_no_such_group"));
    if !e.IsNil() && errors::As::<UnknownGroupError>(e).is_some() {
        ok_line(b"[ 7] UnknownGroupError typed    PASS\n");
    } else {
        ok_line(b"[ 7] UnknownGroupError typed    FAIL\n");
        fail();
    }
}

fn test_8_unknown_group_id() {
    let (_g, e): (user::Group, error) = user::LookupGroupId(s("99999999"));
    if !e.IsNil() && errors::As::<UnknownGroupIdError>(e).is_some() {
        ok_line(b"[ 8] UnknownGroupIdError typed  PASS\n");
    } else {
        ok_line(b"[ 8] UnknownGroupIdError typed  FAIL\n");
        fail();
    }
}

fn test_9_current_returns_username() {
    let (u, e) = user::Current();
    if e.IsNil() && u.Username.Len() > 0 {
        ok_line(b"[ 9] Current() Username non-empty PASS\n");
    } else {
        ok_line(b"[ 9] Current() Username non-empty FAIL\n");
        fail();
    }
}

fn test_10_group_ids_includes_primary() {
    let (u, e) = user::Current();
    if e.IsNil() {
        let (gids, ge) = u.GroupIds();
        if ge.IsNil() && gids.Len() >= 1 && gids[0] == u.Gid {
            ok_line(b"[10] GroupIds primary present  PASS\n");
        } else {
            ok_line(b"[10] GroupIds primary present  FAIL\n");
            fail();
        }
    } else {
        ok_line(b"[10] GroupIds primary present  FAIL\n");
        fail();
    }
}
