// http_pattern_conflict_smoke — net/http/pattern.go's relationship lattice.
//
// pattern.rs used to say conflict detection was "deferred" and that
// goish matched first-registered-wins instead. This is the machinery
// that replaces that: for any two patterns, decide whether one is more
// general, more specific, equivalent, disjoint, or genuinely
// overlapping — and only the last two of those five are a conflict.
//
// The cases below are chosen because each one distinguishes the real
// lattice from a plausible wrong implementation:
//
//   * check 4 — "/a/{x}" vs "/{y}/b" OVERLAP. Both match "/a/b", and
//     neither is more specific. An implementation that compared
//     patterns segment by segment and returned the first non-equivalent
//     answer would call this moreGeneral and let both register.
//   * check 5 — precedence rule 1: a pattern WITH a host never
//     conflicts with one without, however much their paths overlap.
//   * check 6 — GET is more general than HEAD, because a GET pattern
//     also serves HEAD. Getting this backwards is silent: both
//     directions still "look" ordered.
//   * check 7 — a trailing-slash pattern and a "{$}" pattern are
//     disjoint, because a single wildcard does not match a trailing
//     slash.
//   * check 8 — describeConflict's text. It is what a developer sees
//     when two routes collide at registration, and Go computes an
//     example path that both match plus one that only each matches.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::net::http::pattern::{
    describeConflict, disjoint, equivalent, moreGeneral, moreSpecific, overlaps, parsePattern,
};
use goish::{string, strings, syscall};

fn p(s: &'static str) -> goish::net::http::pattern::pattern {
    let (pat, err) = parsePattern(string(s));
    if !err.IsNil() {
        fmt::Println!("    parse failed for ", s, ": ", err.Error());
    }
    return pat;
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Identical patterns are equivalent, and therefore conflict.
    {
        let a = p("/a/b");
        let b = p("/a/b");
        if a.comparePathsAndMethods(&b) == equivalent && a.conflictsWith(&b) {
            fmt::Println!("[ 1] identical conflict        PASS");
        } else {
            fmt::Println!("[ 1] identical conflict        FAIL");
            failed += 1;
        }
    }

    // 2. A wildcard is more general than the literal it covers, and
    //    that is NOT a conflict — the more specific one wins.
    {
        let wild = p("/a/{x}");
        let lit = p("/a/b");
        if wild.comparePathsAndMethods(&lit) == moreGeneral
            && lit.comparePathsAndMethods(&wild) == moreSpecific
            && !wild.conflictsWith(&lit)
        {
            fmt::Println!("[ 2] wildcard > literal        PASS");
        } else {
            fmt::Println!("[ 2] wildcard > literal        FAIL");
            failed += 1;
        }
    }

    // 3. Different literals are disjoint.
    {
        let a = p("/a");
        let b = p("/b");
        if a.comparePathsAndMethods(&b) == disjoint && !a.conflictsWith(&b) {
            fmt::Println!("[ 3] distinct literals         PASS");
        } else {
            fmt::Println!("[ 3] distinct literals         FAIL");
            failed += 1;
        }
    }

    // 4. The case the lattice exists for: "/a/{x}" and "/{y}/b" both
    //    match "/a/b", and neither is more specific. Overlap IS a
    //    conflict.
    {
        let a = p("/a/{x}");
        let b = p("/{y}/b");
        let rel = a.comparePathsAndMethods(&b);
        if rel == overlaps && a.conflictsWith(&b) && b.conflictsWith(&a) {
            fmt::Println!("[ 4] genuine overlap           PASS");
        } else {
            fmt::Println!("[ 4] genuine overlap           FAIL got=", rel.String());
            failed += 1;
        }
    }

    // 5. Precedence rule 1 — a host wins outright. These two overlap on
    //    path, but the hosted one takes precedence, so no conflict.
    {
        let hosted = p("example.com/a/{x}");
        let bare = p("/{y}/b");
        if !hosted.conflictsWith(&bare) && !bare.conflictsWith(&hosted) {
            fmt::Println!("[ 5] host beats no-host        PASS");
        } else {
            fmt::Println!("[ 5] host beats no-host        FAIL");
            failed += 1;
        }
    }

    // 6. Methods: no method is most general; GET is more general than
    //    HEAD because a GET pattern also serves HEAD; two unrelated
    //    methods are disjoint.
    {
        let any = p("/a");
        let get = p("GET /a");
        let head = p("HEAD /a");
        let post = p("POST /a");
        if any.compareMethods(&get) == moreGeneral
            && get.compareMethods(&any) == moreSpecific
            && get.compareMethods(&head) == moreGeneral
            && head.compareMethods(&get) == moreSpecific
            && post.compareMethods(&get) == disjoint
        {
            fmt::Println!("[ 6] method lattice            PASS");
        } else {
            fmt::Println!("[ 6] method lattice            FAIL");
            failed += 1;
        }
    }

    // 7. "{$}" means "exactly here"; a single wildcard does not match a
    //    trailing slash, so these two are disjoint.
    {
        let dollar = p("/a/{$}");
        let wild = p("/a/{x}");
        if dollar.comparePathsAndMethods(&wild) == disjoint {
            fmt::Println!("[ 7] {$} vs wildcard disjoint  PASS");
        } else {
            fmt::Println!("[ 7] {$} vs wildcard disjoint  FAIL");
            failed += 1;
        }
    }

    // 8. describeConflict explains an overlap with a concrete example
    //    of a path both match and one that only each matches. This is
    //    the message a developer gets at registration time.
    {
        let a = p("/a/{x}");
        let b = p("/{y}/b");
        let msg = describeConflict(&a, &b);
        // Byte-for-byte against a live go1.25.5 run of describeConflict
        // on these same two patterns, not a substring approximation.
        let want = string(
            "/a/{x} and /{y}/b both match some paths, like \"/a/b\".\n\
             But neither is more specific than the other.\n\
             /a/{x} matches \"/a/x\", but /{y}/b doesn't.\n\
             /{y}/b matches \"/y/b\", but /a/{x} doesn't.",
        );
        if msg == want {
            fmt::Println!("[ 8] describeConflict text     PASS");
        } else {
            fmt::Println!("[ 8] describeConflict text     FAIL");
            fmt::Println!("     got:  ", msg);
            fmt::Println!("     want: ", want);
            failed += 1;
        }
    }

    // 9. …and for two equivalent patterns it says exactly that.
    {
        let a = p("/a/b");
        let b = p("/a/b");
        let msg = describeConflict(&a, &b);
        if strings::Contains(msg.clone(), string("matches the same requests as")) {
            fmt::Println!("[ 9] equivalent conflict text  PASS");
        } else {
            fmt::Println!("[ 9] equivalent conflict text  FAIL got=", msg);
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 9/9");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 9");
        syscall::Exit(1);
    }
}
