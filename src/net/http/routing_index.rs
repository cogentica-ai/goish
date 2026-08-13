// go: package net/http
//
// go: file net/http/routing_index.go decls: routingIndex.addPattern, routingIndex.possiblyConflictingPatterns
//
// Go: "A routingIndex optimizes conflict detection by indexing
// patterns. The basic idea is to rule out patterns that cannot conflict
// with a given pattern because they have a different literal in a
// corresponding segment."
//
// Without this, registering the Nth route costs N conflict checks
// against pattern.go's lattice, so a mux with a thousand routes does
// half a million comparisons at startup.
//
// Go states the correctness rule plainly and it is the reason the
// index is allowed to be crude: "To be correct,
// possiblyConflictingPatterns must include all patterns that might
// conflict. But it may also include patterns that cannot conflict. For
// instance, an implementation that returns all registered patterns is
// correct." So an over-broad answer is slow, never wrong — and the one
// branch that could be wrong is the dollar-pattern shortcut, which is
// justified in its own comment below.

#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

use crate::errors::error;
use crate::gomap::{map, GoHash};
use crate::gostring::string;
use crate::types::int;

use super::pattern::pattern;

// go: sdk 1.25.5 net/http/routing_index.go:26-29 routingIndexKey
pub struct routingIndexKey {
    /// Go: "0-based segment position".
    pub pos: int,
    /// Go: "literal, or empty for wildcard".
    pub s: string,
}

// go: none — goish-only: Go's compiler hashes a comparable struct key
// automatically. goish key types implement GoHash themselves; this
// mixes the two fields the same way a Go struct hash would.
impl GoHash for routingIndexKey {
    // go: none — goish-only, see the note above the impl.
    fn go_hash(&self, seed: u64) -> u64 {
        let h = self.s.go_hash(seed);
        return self.pos.go_hash(h);
    }
}

impl PartialEq for routingIndexKey {
    // go: none — goish-only: Go's struct keys are comparable by
    // construction; Rust needs the impl.
    fn eq(&self, other: &Self) -> bool {
        return self.pos == other.pos && self.s == other.s;
    }
}

impl Clone for routingIndexKey {
    // go: none — goish-only: Go copies a struct key by assignment.
    fn clone(&self) -> Self {
        return routingIndexKey {
            pos: self.pos,
            s: self.s.clone(),
        };
    }
}

impl Default for routingIndexKey {
    // go: none — goish-only: Go's zero value for the key struct.
    fn default() -> Self {
        return routingIndexKey {
            pos: 0,
            s: string::new(),
        };
    }
}

// go: sdk 1.25.5 net/http/routing_index.go:14-24 routingIndex
#[derive(Default)]
pub struct routingIndex {
    /// Go: "map from a particular segment position and value to all
    /// registered patterns with that value in that position. For
    /// example, the key {1, "b"} would hold the patterns "/a/b" and
    /// "/a/b/c" but not "/a", "b/a", "/a/c" or "/a/{x}"."
    pub segments: map<routingIndexKey, Vec<pattern>>,
    /// Go: "All patterns that end in a multi wildcard (including
    /// trailing slash). We do not try to be clever about indexing multi
    /// patterns, because there are unlikely to be many of them."
    pub multis: Vec<pattern>,
}

impl routingIndex {
    // go: sdk 1.25.5 net/http/routing_index.go:31-46 routingIndex.addPattern
    pub fn addPattern(&mut self, pat: &pattern) {
        if pat.lastSegment().multi {
            self.multis.push(pat.clone());
        } else {
            let mut pos: int = 0;
            while pos < pat.segments.Len() {
                let seg = pat.segments[pos].clone();
                let mut key = routingIndexKey {
                    pos,
                    s: string::new(),
                };
                if !seg.wild {
                    key.s = seg.s.clone();
                }
                let (mut cur, _) = self.segments.Get(key.clone());
                cur.push(pat.clone());
                self.segments.Set(key, cur);
                pos += 1;
            }
        }
    }

    // go: sdk 1.25.5 net/http/routing_index.go:57-124 routingIndex.possiblyConflictingPatterns
    /// Go: "possiblyConflictingPatterns calls f on all patterns that
    /// might conflict with pat. If f returns a non-nil error,
    /// possiblyConflictingPatterns returns immediately with that
    /// error."
    ///
    /// Terminology from Go: a *dollar pattern* ends in "{$}", a *multi
    /// pattern* in a trailing slash or "{x...}", an *ordinary pattern*
    /// is neither.
    pub fn possiblyConflictingPatterns(
        &self,
        pat: &pattern,
        f: &mut dyn FnMut(&pattern) -> error,
    ) -> error {
        // Go closes over `err` in `apply`; goish threads it.
        let mut err: error = crate::errors::nil;

        // Go: "Our simple indexing scheme doesn't try to prune multi
        // patterns; assume any of them can match the argument."
        for p in self.multis.iter() {
            err = f(p);
            if !err.IsNil() {
                return err;
            }
        }

        if pat.lastSegment().s == "/" {
            // Go: "All paths that a dollar pattern matches end in a
            // slash; no paths that an ordinary pattern matches do. So
            // only other dollar or multi patterns can conflict with a
            // dollar pattern. Furthermore, conflicting dollar patterns
            // must have the {$} in the same position."
            let key = routingIndexKey {
                pos: pat.segments.Len() - 1,
                s: string::from_static("/"),
            };
            let (pats, _) = self.segments.Get(key);
            for p in pats.iter() {
                err = f(p);
                if !err.IsNil() {
                    return err;
                }
            }
            return err;
        }

        // Go: "For ordinary and multi patterns, the only conflicts can
        // be with a multi, or a pattern that has the same literal or a
        // wildcard at some literal position. We could intersect all the
        // possible matches at each position, but we do something
        // simpler: we find the position with the fewest patterns."
        let mut lmin: Vec<pattern> = Vec::new();
        let mut wmin: Vec<pattern> = Vec::new();
        let mut min: int = crate::types::int::MAX;
        let mut hasLit = false;
        let mut i: int = 0;
        while i < pat.segments.Len() {
            let seg = pat.segments[i].clone();
            if seg.multi {
                break;
            }
            if !seg.wild {
                hasLit = true;
                let (lpats, _) = self.segments.Get(routingIndexKey {
                    pos: i,
                    s: seg.s.clone(),
                });
                let (wpats, _) = self.segments.Get(routingIndexKey {
                    pos: i,
                    s: string::new(),
                });
                let sum = crate::int(lpats.len()) + crate::int(wpats.len());
                if sum < min {
                    lmin = lpats;
                    wmin = wpats;
                    min = sum;
                }
            }
            i += 1;
        }
        if hasLit {
            for p in lmin.iter() {
                err = f(p);
                if !err.IsNil() {
                    return err;
                }
            }
            for p in wmin.iter() {
                err = f(p);
                if !err.IsNil() {
                    return err;
                }
            }
            return err;
        }

        // Go: "This pattern is all wildcards. Check it against
        // everything."
        for (_, pats) in self.segments.__iter() {
            for p in pats.iter() {
                err = f(p);
                if !err.IsNil() {
                    return err;
                }
            }
        }
        return err;
    }
}
