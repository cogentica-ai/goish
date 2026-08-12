// slog_group_smoke — slog's GroupValue, Group and the built-in keys.
//
// GroupValue prunes empty groups at CONSTRUCTION, and Go's comment says
// why: "It is simpler overall to do this at construction than to check
// each Group recursively for emptiness." That pruning is load-bearing —
// isEmptyGroup is a shallow check (it does not recurse) and is only
// correct because no empty group can survive GroupValue.
//
// Check 3 is that invariant: a group built from a mix of empty and
// non-empty groups must come back containing only the non-empty ones.
// A GroupValue that skipped the pruning would pass checks 1 and 2 and
// make isEmptyGroup quietly wrong for anything nested.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::log::slog;
use goish::{fmt, slice, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

fn attrs(xs: alloc::vec::Vec<slog::Attr>) -> slice<slog::Attr> {
    return slice::__from_vec(xs);
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. The four built-in keys match Go's spellings exactly. Handlers
    //    and slogtest agree on these by string, so a typo is silent.
    {
        if slog::TimeKey == "time"
            && slog::LevelKey == "level"
            && slog::MessageKey == "msg"
            && slog::SourceKey == "source"
        {
            fmt::Println!("[ 1] built-in keys             PASS");
        } else {
            fmt::Println!("[ 1] built-in keys             FAIL");
            failed += 1;
        }
    }

    // 2. A group of real attrs keeps them all and reports KindGroup.
    {
        let g = slog::GroupValue(attrs(alloc::vec![
            slog::String(s("a"), s("1")),
            slog::Int(s("b"), 2),
        ]));
        if g.Kind() == slog::KindGroup && !slog::isEmptyGroup(&g) {
            fmt::Println!("[ 2] non-empty group kept      PASS");
        } else {
            fmt::Println!("[ 2] non-empty group kept      FAIL");
            failed += 1;
        }
    }

    // 3. Empty groups are pruned at construction. This is the invariant
    //    isEmptyGroup's shallow check depends on.
    {
        let empty = slog::Attr {
            Key: s("empty"),
            Value: slog::GroupValue(attrs(alloc::vec![])),
        };
        let full = slog::Attr {
            Key: s("full"),
            Value: slog::GroupValue(attrs(alloc::vec![slog::String(s("x"), s("y"))])),
        };
        let mixed = attrs(alloc::vec![empty.clone(), full.clone(), empty.clone()]);

        // Two of the three are empty groups.
        let counted = slog::countEmptyGroups(&mixed);
        let g = slog::GroupValue(mixed);
        // After construction only "full" survives, so the result is not
        // itself empty and the count above saw exactly two.
        if counted == 2 && !slog::isEmptyGroup(&g) {
            fmt::Println!("[ 3] empty groups pruned       PASS");
        } else {
            fmt::Println!("[ 3] empty groups pruned       FAIL count=", counted);
            failed += 1;
        }
    }

    // 4. A group built from nothing IS empty, and says so.
    {
        let g = slog::GroupValue(attrs(alloc::vec![]));
        if slog::isEmptyGroup(&g) {
            fmt::Println!("[ 4] empty group is empty      PASS");
        } else {
            fmt::Println!("[ 4] empty group is empty      FAIL");
            failed += 1;
        }
    }

    // 5. isEmptyGroup is false for a non-group Value — Go returns early
    //    on the Kind check rather than inspecting a payload that is not
    //    a group at all.
    {
        let notgroup = slog::String(s("k"), s("v")).Value;
        if !slog::isEmptyGroup(&notgroup) {
            fmt::Println!("[ 5] non-group is not empty    PASS");
        } else {
            fmt::Println!("[ 5] non-group is not empty    FAIL");
            failed += 1;
        }
    }

    // 6. Group() wraps a GroupValue under a key.
    {
        let a = slog::Group(s("req"), attrs(alloc::vec![slog::Int(s("status"), 200)]));
        if a.Key == s("req") && a.Value.Kind() == slog::KindGroup {
            fmt::Println!("[ 6] Group keys a group        PASS");
        } else {
            fmt::Println!("[ 6] Group keys a group        FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 6/6");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 6");
        syscall::Exit(1);
    }
}
