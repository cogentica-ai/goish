// http_routing_tree_smoke — net/http/routing_tree.go + routing_index.go
// + mapping.go.
//
// The tree IS the routing rule. matchPath tries three things in a fixed
// order — literal, then single wildcard, then multi — and every case
// below is a request where getting that order wrong changes the answer
// silently:
//
//   * "/a/b" must reach "/a/b", not "/a/{x}". Wildcard-first would
//     still route the request, just to the wrong handler.
//   * "/a/b/c/d" must fall all the way through to the multi "/a/",
//     because neither of the two-segment patterns can absorb four
//     segments.
//   * "/d/" must reach "/d/{$}" and NOT a single wildcard, because a
//     single wildcard does not match a trailing slash.
//   * HEAD /m must reach "GET /m" — Go serves HEAD from a GET pattern.
//   * a host pattern must win for its host and not leak to others.
//
// Every expectation is a live go1.25.5 run of routingNode.match on the
// same seven patterns, via scripts/goref.sh, not a reading of the spec:
//
//   GET  /a/b     -> /a/b          matches=[]
//   GET  /a/z     -> /a/{x}        matches=["z"]
//   GET  /q/c     -> /{y}/c        matches=["q"]
//   GET  /a/b/c/d -> /a/           matches=[]
//   GET  /d/      -> /d/{$}        matches=[]
//   HEAD /m       -> GET /m        matches=[]
//   example.com /h -> example.com/h
//   GET  /nope    -> <nil>
//   matchingMethods("/m") = {GET, HEAD}

#![no_std]
#![no_main]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;

use goish::fmt;
use goish::gomap::map;
use goish::goslice::slice;
use goish::gostring::string as gostring;
use goish::net::http::pattern::parsePattern;
use goish::net::http::responsewriter::ResponseWriter;
use goish::net::http::routing_index::routingIndex;
use goish::net::http::routing_tree::routingNode;
use goish::net::http::server::Handler;
use goish::net::http::request::Request;
use goish::{string, syscall};

struct nopH;

impl Handler for nopH {
    fn ServeHTTP(&self, _w: &(dyn ResponseWriter + Send + Sync + 'static), _r: &Request) {}
}

/// Build the tree Go's reference run used.
fn tree() -> routingNode {
    let mut root = routingNode::default();
    let pats: [&'static str; 7] = [
        "/a/b",
        "/a/{x}",
        "/{y}/c",
        "/a/",
        "/d/{$}",
        "GET /m",
        "example.com/h",
    ];
    for s in pats.iter() {
        let (p, err) = parsePattern(string(*s));
        if !err.IsNil() {
            fmt::Println!("    parse failed: ", *s, " ", err.Error());
        }
        root.addPattern(&p, Arc::new(nopH));
    }
    return root;
}

/// `(pattern-string, wildcard-matches-joined)` for a request, or
/// ("<nil>", "") when nothing matched.
fn hit(root: &routingNode, host: &'static str, method: &'static str, path: &'static str)
    -> (gostring, gostring)
{
    let (n, m) = root.r#match(&string(host), &string(method), &string(path));
    let pat = match n {
        Some(n) => match n.pattern.as_ref() {
            Some(p) => p.String(),
            None => string("<nil>"),
        },
        None => string("<nil>"),
    };
    return (pat, goish::strings::Join(m, string(",")));
}

#[goish::main]
fn main() {
    let mut failed = 0;
    let root = tree();

    // (host, method, path, want-pattern, want-matches)
    let cases: [(&'static str, &'static str, &'static str, &'static str, &'static str); 9] = [
        ("", "GET", "/a/b", "/a/b", ""),
        ("", "GET", "/a/z", "/a/{x}", "z"),
        ("", "GET", "/q/c", "/{y}/c", "q"),
        ("", "GET", "/a/b/c/d", "/a/", ""),
        ("", "GET", "/d/", "/d/{$}", ""),
        ("", "GET", "/m", "GET /m", ""),
        ("", "HEAD", "/m", "GET /m", ""),
        ("example.com", "GET", "/h", "example.com/h", ""),
        ("", "GET", "/nope", "<nil>", ""),
    ];

    let mut i = 1;
    for (host, method, path, wantPat, wantM) in cases.iter() {
        let (pat, m) = hit(&root, host, method, path);
        if pat == *wantPat && m == *wantM {
            fmt::Println!("[", i, "] ", *method, " ", *path, " -> ", pat, "  PASS");
        } else {
            fmt::Println!(
                "[", i, "] ", *method, " ", *path,
                " FAIL want=", *wantPat, "/", *wantM, " got=", pat, "/", m
            );
            failed += 1;
        }
        i += 1;
    }

    // 10. matchingMethods reports GET and, because GET serves HEAD,
    //     HEAD as well. Go adds HEAD explicitly after the walk.
    {
        let mut set: map<gostring, bool> = map::new();
        root.matchingMethods(&string(""), &string("/m"), &mut set);
        let (g, _) = set.Get(string("GET"));
        let (h, _) = set.Get(string("HEAD"));
        let (p, _) = set.Get(string("POST"));
        if g && h && !p {
            fmt::Println!("[10] matchingMethods GET+HEAD  PASS");
        } else {
            fmt::Println!("[10] matchingMethods GET+HEAD  FAIL");
            failed += 1;
        }
    }

    // 11. mapping switches representation above maxSlice (8) and keeps
    //     answering find correctly. The routing tree leans on this for
    //     every node with many children, and a switch that lost a pair
    //     would look like a route that stopped existing.
    {
        let mut root2 = routingNode::default();
        let keys: [&'static str; 12] = [
            "/k0", "/k1", "/k2", "/k3", "/k4", "/k5", "/k6", "/k7", "/k8", "/k9", "/k10", "/k11",
        ];
        for s in keys.iter() {
            let (p, _) = parsePattern(string(*s));
            root2.addPattern(&p, Arc::new(nopH));
        }
        let mut all = true;
        for s in keys.iter() {
            let (n, _) = root2.r#match(&string(""), &string("GET"), &string(*s));
            if n.is_none() {
                all = false;
            }
        }
        let (miss, _) = root2.r#match(&string(""), &string("GET"), &string("/k99"));
        if all && miss.is_none() {
            fmt::Println!("[11] mapping past maxSlice     PASS");
        } else {
            fmt::Println!("[11] mapping past maxSlice     FAIL");
            failed += 1;
        }
    }

    // 12. routingIndex narrows conflict checking without ever missing a
    //     real conflict. Go's own rule: "To be correct,
    //     possiblyConflictingPatterns must include all patterns that
    //     might conflict. But it may also include patterns that cannot
    //     conflict." So the assertion is a SUPERSET one — the candidate
    //     set must contain every pattern that genuinely conflicts, and
    //     is allowed to contain more.
    {
        let mut idx = routingIndex::default();
        let reg: [&'static str; 4] = ["/a/b", "/a/{x}", "/c/d", "/e/"];
        let mut regd: alloc::vec::Vec<goish::net::http::pattern::pattern> =
            alloc::vec::Vec::new();
        for s in reg.iter() {
            let (p, _) = parsePattern(string(*s));
            idx.addPattern(&p);
            regd.push(p);
        }
        // "/{y}/b" overlaps "/a/{x}" and is more specific than nothing
        // else; the multi "/e/" must also come back, since the index
        // never prunes multis.
        let (probe, _) = parsePattern(string("/{y}/b"));
        let mut seen: alloc::vec::Vec<gostring> = alloc::vec::Vec::new();
        let _ = idx.possiblyConflictingPatterns(&probe, &mut |p| {
            seen.push(p.String());
            return goish::errors::nil;
        });
        // Everything that actually conflicts must be in the candidates.
        let mut complete = true;
        for p in regd.iter() {
            if probe.conflictsWith(p) {
                let mut found = false;
                for s in seen.iter() {
                    if *s == p.String() {
                        found = true;
                    }
                }
                if !found {
                    complete = false;
                }
            }
        }
        // …and it pruned something, or the index would be pointless.
        let pruned = seen.len() < regd.len();
        if complete && pruned {
            fmt::Println!("[12] index keeps all conflicts PASS");
        } else {
            fmt::Println!("[12] index keeps all conflicts FAIL complete=", complete, " pruned=", pruned);
            failed += 1;
        }
    }

    let _ = slice::<gostring>::new();

    if failed == 0 {
        fmt::Println!("ok 12/12");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 12");
        syscall::Exit(1);
    }
}
