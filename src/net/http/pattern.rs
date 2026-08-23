// go: package net/http
//
// go: file net/http/pattern.go decls: pattern.String, pattern.lastSegment, parsePattern, isValidWildcardName, pathUnescape, pattern.conflictsWith, pattern.comparePathsAndMethods, pattern.compareMethods, pattern.comparePaths, compareSegments, combineRelationships, inverseRelationship, isLitOrSingle, describeConflict, writeMatchingPath, writeSegment, commonPath, differencePath
//
// Go: "Patterns for ServeMux routing."
//
// Every declaration in pattern.go is unexported. goish has no
// package-private visibility that a smoke test in another crate can
// still reach, so they are `pub` here; the Go names are kept exactly,
// which is what makes the divergence a visibility one and not a
// surface one.
//
// The header that used to sit here said conflict detection was
// "deferred" and that goish used first-match-wins in registration
// order. It is not deferred any more: conflictsWith and the whole
// relationship lattice under it are ported, which is what lets
// ServeMux reject two routes that overlap instead of silently
// preferring whichever was registered first.
//
// Names are Go's now. The file previously spelled the two types
// `Pattern` and `Segment` with `Str`/`Method`/`Host`/`Segments` and
// `S`/`Wild`/`Multi` fields — a rename that GOISH016 exists to catch,
// and one that made every decl in the file read as unported.
//
// `validMethod` also lived here in a second copy; Go declares it in
// request.go, so this calls that one and the duplicate is gone.
//
// What is still goish-only, and marked as such: `pattern.Match`.
// Go does matching in routing_tree.go with a routingNode trie; goish's
// ServeMux walks its patterns directly. Match is the bridge until
// routing_tree.go is ported, and it is the only function here without
// a Go counterpart.

#![allow(non_snake_case)]
#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

use crate::errors::{self, error};
use crate::gomap::map;
use crate::goslice::slice;
use crate::string;
use crate::strings;
use crate::types::{int, rune};
use crate::unicode;

// ─── pattern + segment types ────────────────────────────────────────

/// A pattern is something that can be matched against an HTTP request.
/// Mirrors Go's unexported `pattern` (pattern.go:19) with public
/// fields since goish doesn't have package-private visibility.
#[derive(Clone)]
pub struct pattern {
    /// Original string.
    pub str: string,
    /// Empty string = no method match.
    pub method: string,
    /// Empty string = no host match.
    pub host: string,
    /// Decoded path segments.
    pub segments: slice<segment>,
}

/// A segment of a pattern.
///
/// - If `wild` is false, matches a literal segment (or, if `s == "/"`,
///   a trailing slash from `{$}`).
/// - If `wild` is true and `multi` is false, matches one path segment.
/// - If `wild` and `multi` are both true, matches the rest of the path.
///
/// Mirrors `segment` (pattern.go:61).
#[derive(Clone)]
pub struct segment {
    /// Literal text (when !wild) or wildcard name (when wild).
    /// `s == "/"` is the special end-of-path marker from `{$}`.
    pub s: string,
    pub wild: bool,
    pub multi: bool,
}

impl Default for segment {
    fn default() -> Self {
        segment {
            s: string::new(),
            wild: false,
            multi: false,
        }
    }
}

// ─── parsePattern ───────────────────────────────────────────────────

// go: sdk 1.25.5 net/http/pattern.go:84-184 parsePattern
/// `parsePattern(s)` — line-by-line port of pattern.go:84.
///
/// Syntax: `[METHOD] [HOST]/[PATH]` where each PATH segment is either
/// a literal or a wildcard `{name}` / `{name...}` / `{$}`.
pub fn parsePattern<S: Into<string>>(s: S) -> (pattern, error) {
    let s: string = s.into();
    // Go: if len(s) == 0 { return nil, errors.New("empty pattern") }
    if s.Len() == 0 {
        return (defaultPattern(), errors::New(string("empty pattern")));
    }

    // Go: method, rest, found := s, "", false
    // Go: if i := strings.IndexAny(s, " \t"); i >= 0 {
    //         method, rest, found = s[:i], strings.TrimLeft(s[i+1:], " \t"), true
    //     }
    let i = strings::IndexAny(s.clone(), string(" \t"));
    let (method, rest, found) = if i >= 0 {
        let (a, b, _) = strings::Cut(s.clone(), string(" "));
        let (_, b2, _) = strings::Cut(b.clone(), string("\t"));
        // strings.IndexAny matches either; simpler: split at i then TrimLeft.
        let _ = (a, b, b2);
        let head = subStr(&s, 0, i);
        let tail = strings::TrimLeft(subStr(&s, i + 1, s.Len()), string(" \t"));
        (head, tail, true)
    } else {
        (s.clone(), string::new(), false)
    };

    // Go: if !found { rest = method; method = "" }
    let (method, mut rest) = if !found {
        (string::new(), method)
    } else {
        (method, rest)
    };

    // Go: if method != "" && !validMethod(method) { return nil, fmt.Errorf("invalid method %q", method) }
    if method.Len() > 0 && !super::request::validMethod(method.clone()) {
        return (defaultPattern(), errors::New(string("invalid method")));
    }

    // Go: p := &pattern{str: s, method: method}
    let mut p = pattern {
        str: s.clone(),
        method: method,
        host: string::new(),
        segments: slice::<segment>::__from_vec(Vec::new()),
    };

    // Go: i := strings.IndexByte(rest, '/'); if i < 0 { return nil, errors.New("host/path missing /") }
    let i = strings::IndexByte(rest.clone(), b'/');
    if i < 0 {
        return (defaultPattern(), errors::New(string("host/path missing /")));
    }
    // Go: p.host = rest[:i]; rest = rest[i:]
    p.host = subStr(&rest, 0, i);
    rest = subStr(&rest, i, rest.Len());

    // Go: if j := strings.IndexByte(p.host, '{'); j >= 0 { return nil, errors.New("host contains '{'") }
    if strings::IndexByte(p.host.clone(), b'{') >= 0 {
        return (
            defaultPattern(),
            errors::New(string("host contains '{' (missing initial '/'?)")),
        );
    }

    // Go: seenNames := map[string]bool{}
    let mut seen_names: map<string, bool> = map::<string, bool>::new();
    // Go: for len(rest) > 0 { … rest[0] == '/' invariant … }
    let mut segments: Vec<segment> = Vec::new();
    while rest.Len() > 0 {
        // Go: rest = rest[1:]
        rest = subStr(&rest, 1, rest.Len());
        // Go: if len(rest) == 0 { p.segments = append(p.segments, segment{wild: true, multi: true}); break }
        if rest.Len() == 0 {
            segments.push(segment {
                s: string::new(),
                wild: true,
                multi: true,
            });
            break;
        }
        // Go: i := strings.IndexByte(rest, '/'); if i < 0 { i = len(rest) }
        let i = strings::IndexByte(rest.clone(), b'/');
        let i = if i < 0 { rest.Len() } else { i };
        // Go: var seg string; seg, rest = rest[:i], rest[i:]
        let seg = subStr(&rest, 0, i);
        rest = subStr(&rest, i, rest.Len());

        // Go: if i := strings.IndexByte(seg, '{'); i < 0 { … literal … } else { … wildcard … }
        let lb = strings::IndexByte(seg.clone(), b'{');
        if lb < 0 {
            // Literal — Go does pathUnescape; we keep it raw.
            segments.push(segment {
                s: seg,
                wild: false,
                multi: false,
            });
        } else {
            // Wildcard.
            // Go: if i != 0 { return nil, errors.New("bad wildcard segment (must start with '{')") }
            if lb != 0 {
                return (
                    defaultPattern(),
                    errors::New(string("bad wildcard segment (must start with '{')")),
                );
            }
            // Go: if seg[len(seg)-1] != '}' { return nil, errors.New("bad wildcard segment (must end with '}')") }
            if seg[seg.Len() - 1] != b'}' {
                return (
                    defaultPattern(),
                    errors::New(string("bad wildcard segment (must end with '}')")),
                );
            }
            // Go: name := seg[1 : len(seg)-1]
            let name = subStr(&seg, 1, seg.Len() - 1);
            // Go: if name == "$" { … {$} marker … }
            if name == "$" {
                if rest.Len() != 0 {
                    return (defaultPattern(), errors::New(string("{$} not at end")));
                }
                segments.push(segment {
                    s: string("/"),
                    wild: false,
                    multi: false,
                });
                break;
            }
            // Go: name, multi := strings.CutSuffix(name, "...")
            let (name, multi) = strings::CutSuffix(name, string("..."));
            // Go: if multi && len(rest) != 0 { return nil, errors.New("{...} wildcard not at end") }
            if multi && rest.Len() != 0 {
                return (
                    defaultPattern(),
                    errors::New(string("{...} wildcard not at end")),
                );
            }
            // Go: if name == "" { return nil, errors.New("empty wildcard") }
            if name.Len() == 0 {
                return (defaultPattern(), errors::New(string("empty wildcard")));
            }
            // Go: if !isValidWildcardName(name) { return nil, fmt.Errorf("bad wildcard name %q", name) }
            if !isValidWildcardName(&name) {
                return (defaultPattern(), errors::New(string("bad wildcard name")));
            }
            // Go: if seenNames[name] { return nil, fmt.Errorf("duplicate wildcard name %q", name) }
            let (_, dup) = seen_names.Get(name.clone());
            if dup {
                return (
                    defaultPattern(),
                    errors::New(string("duplicate wildcard name")),
                );
            }
            seen_names.Set(name.clone(), true);
            // Go: p.segments = append(p.segments, segment{s: name, wild: true, multi: multi})
            segments.push(segment {
                s: name,
                wild: true,
                multi: multi,
            });
        }
    }
    p.segments = slice::<segment>::__from_vec(segments);
    (p, errors::nil)
}

// go: sdk 1.25.5 net/http/pattern.go:186-197 isValidWildcardName
/// Line-by-line port of `isValidWildcardName` (pattern.go:186).
fn isValidWildcardName(s: &string) -> bool {
    // Go: if s == "" { return false }
    if s.Len() == 0 {
        return false;
    }
    // Go: for i, c := range s { … }
    let owned = s.clone();
    for (i, c) in crate::range!(owned) {
        // Go: if !unicode.IsLetter(c) && c != '_' && (i == 0 || !unicode.IsDigit(c)) { return false }
        if !unicode::IsLetter(c) && c != ('_' as rune) && (i == 0 || !unicode::IsDigit(c)) {
            return false;
        }
    }
    true
}

// ─── pattern matching ────────────────────────────────────────────────

impl pattern {
    // go: none — goish-only: Go has no pattern.Match. Matching lives in
    // routing_tree.go, where a routingNode trie walks the segments once
    // for all registered patterns. goish's ServeMux instead asks each
    // pattern in turn, so it needs a per-pattern entry point. This is
    // the bridge until routing_tree.go is ported, and it is the only
    // function in this file with no Go counterpart.
    ///
    /// Returns `Some(bindings)` on success (a map of wildcard-name →
    /// bound-segment) or `None` on no match.
    pub fn Match(
        &self,
        method: &string,
        host: &string,
        path: &string,
    ) -> Option<map<string, string>> {
        // Method match: empty Method = any method. A `GET` pattern
        // also matches HEAD requests — Go's routing_tree.go:140
        // ("GET matches HEAD too"); the response writer suppresses
        // the body for HEAD.
        if self.method.Len() > 0 && self.method != *method {
            let get_matches_head = self.method == string("GET") && *method == string("HEAD");
            if !get_matches_head {
                return None;
            }
        }
        // Host match: empty Host = any host.
        if self.host.Len() > 0 && self.host != *host {
            return None;
        }
        // Path match: walk segments against path.
        let mut bindings: map<string, string> = map::<string, string>::new();
        let mut rest = path.clone();
        for i in 0..self.segments.Len() {
            let seg = &self.segments[i];
            // Go's path invariant: leading '/' on each iteration.
            if rest.Len() == 0 || rest[0] != b'/' {
                return None;
            }
            // Drop the leading '/'.
            rest = subStr(&rest, 1, rest.Len());

            if seg.wild && seg.multi {
                // Greedy: bind everything left (possibly empty).
                if seg.s.Len() > 0 {
                    bindings.Set(seg.s.clone(), rest.clone());
                }
                rest = string::new();
                break;
            }
            if seg.s == "/" && !seg.wild {
                // {$} marker — only matches an exact trailing '/'.
                if rest.Len() != 0 {
                    return None;
                }
                break;
            }
            // Find next '/'; segment is everything up to it.
            let j = strings::IndexByte(rest.clone(), b'/');
            let (this_seg, after) = if j < 0 {
                (rest.clone(), string::new())
            } else {
                (subStr(&rest, 0, j), subStr(&rest, j, rest.Len()))
            };
            if seg.wild {
                // Single-segment wildcard. Empty segment doesn't match
                // (matches Go's pre-1.22 behavior; Go 1.22 also rejects).
                if this_seg.Len() == 0 {
                    return None;
                }
                bindings.Set(seg.s.clone(), this_seg);
            } else {
                // Literal — exact match.
                if seg.s != this_seg {
                    return None;
                }
            }
            rest = after;
        }
        // Path fully consumed?
        if rest.Len() != 0 {
            return None;
        }
        Some(bindings)
    }
}

// go: none — goish-only: the zero pattern ServeMux falls back to.
// Go has no such value; its ServeMux keeps patterns in a routing tree
// and has nothing to name an absent one.
fn defaultPattern() -> pattern {
    pattern {
        str: string::new(),
        method: string::new(),
        host: string::new(),
        segments: slice::<segment>::__from_vec(Vec::new()),
    }
}

// go: none — goish-only: Go slices a string with s[low:high];
// goish's string needs a helper.
/// Substring helper — Go has `s[low:high]` natively; goish doesn't
/// expose a public `string.slice` so we go through bytes. Behavior:
/// returns the byte-substring `[low, high)`, panicking on
/// out-of-bounds (matching Go).
fn subStr(s: &string, low: int, high: int) -> string {
    let lo = low as usize;
    let hi = high as usize;
    let n = s.Len() as usize;
    if lo > hi || hi > n {
        panic!("string slice out of bounds");
    }
    // Use Cut/HasPrefix flow where possible; fallback to from_bytes
    // (pub(crate)) for the substring slice. crate-internal helper.
    string::from_bytes(&__as_bytes(s)[lo..hi])
}

// go: none — goish-only: raw byte view of a goish string.
#[inline]
fn __as_bytes(s: &string) -> &[u8] {
    crate::gostring::__crate_as_bytes(s)
}

// ─── relationship ───────────────────────────────────────────────────

// go: sdk 1.25.5 net/http/pattern.go:209-209 relationship
/// Go: "relationship is a relationship between two patterns, p1 and
/// p2."
///
/// Go's is `type relationship string` — the values ARE their own
/// descriptions, and describeConflict prints one with %s. A newtype
/// over a static string keeps that.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct relationship(&'static str);

impl relationship {
    // go: none — goish-only: Go prints a relationship with %s because
    // its underlying type is string. This is that conversion.
    pub fn String(self) -> string {
        return string::from_static(self.0);
    }
}

// go: sdk 1.25.5 net/http/pattern.go:211-217 equivalent
/// Go: "both match the same requests".
pub const equivalent: relationship = relationship("equivalent");
// go: sdk 1.25.5 net/http/pattern.go:211-217 moreGeneral
/// Go: "p1 matches everything p2 does & more".
pub const moreGeneral: relationship = relationship("moreGeneral");
// go: sdk 1.25.5 net/http/pattern.go:211-217 moreSpecific
/// Go: "p2 matches everything p1 does & more".
pub const moreSpecific: relationship = relationship("moreSpecific");
// go: sdk 1.25.5 net/http/pattern.go:211-217 disjoint
/// Go: "there is no request that both match".
pub const disjoint: relationship = relationship("disjoint");
// go: sdk 1.25.5 net/http/pattern.go:211-217 overlaps
/// Go: "there is a request that both match, but neither is more
/// specific".
pub const overlaps: relationship = relationship("overlaps");

impl pattern {
    // go: sdk 1.25.5 net/http/pattern.go:37-37 pattern.String
    pub fn String(&self) -> string {
        return self.str.clone();
    }

    // go: sdk 1.25.5 net/http/pattern.go:39-41 pattern.lastSegment
    pub fn lastSegment(&self) -> segment {
        return self.segments[self.segments.Len() - 1].clone();
    }

    // go: sdk 1.25.5 net/http/pattern.go:232-241 pattern.conflictsWith
    /// Go: "conflictsWith reports whether p1 conflicts with p2, that
    /// is, whether there is a request that both match but where neither
    /// is higher precedence than the other."
    ///
    /// Go: "Precedence is defined by two rules: 1. Patterns with a host
    /// win over patterns without a host. 2. Patterns whose method and
    /// path is more specific win."
    pub fn conflictsWith(&self, p2: &pattern) -> bool {
        if self.host != p2.host {
            // Go: "Either one host is empty and the other isn't, in
            // which case the one with the host wins by rule 1, or
            // neither host is empty and they differ, so they won't
            // match the same paths."
            return false;
        }
        let rel = self.comparePathsAndMethods(p2);
        return rel == equivalent || rel == overlaps;
    }

    // go: sdk 1.25.5 net/http/pattern.go:243-251 pattern.comparePathsAndMethods
    pub fn comparePathsAndMethods(&self, p2: &pattern) -> relationship {
        let mrel = self.compareMethods(p2);
        // Go: "Optimization: avoid a call to comparePaths."
        if mrel == disjoint {
            return disjoint;
        }
        let prel = self.comparePaths(p2);
        return combineRelationships(mrel, prel);
    }

    // go: sdk 1.25.5 net/http/pattern.go:260-279 pattern.compareMethods
    /// Go: "A method can either be empty, "GET", or something else. The
    /// empty string matches any method, so it is the most general.
    /// "GET" matches both GET and HEAD. Anything else matches only
    /// itself."
    pub fn compareMethods(&self, p2: &pattern) -> relationship {
        if self.method == p2.method {
            return equivalent;
        }
        if self.method.Len() == 0 {
            // Go: "p1 matches any method, but p2 does not, so p1 is
            // more general."
            return moreGeneral;
        }
        if p2.method.Len() == 0 {
            return moreSpecific;
        }
        if self.method == "GET" && p2.method == "HEAD" {
            // Go: "p1 matches GET and HEAD; p2 matches only HEAD."
            return moreGeneral;
        }
        if p2.method == "GET" && self.method == "HEAD" {
            return moreSpecific;
        }
        return disjoint;
    }

    // go: sdk 1.25.5 net/http/pattern.go:283-315 pattern.comparePaths
    /// Go: "comparePaths determines the relationship between the path
    /// part of two patterns."
    pub fn comparePaths(&self, p2: &pattern) -> relationship {
        // Go: "Optimization: if a path pattern doesn't end in a multi
        // ("...") wildcard, then it can only match paths with the same
        // number of segments."
        if self.segments.Len() != p2.segments.Len()
            && !self.lastSegment().multi
            && !p2.lastSegment().multi
        {
            return disjoint;
        }

        // Go walks the two segment slices in lockstep by resliceing;
        // goish indexes instead, and `i` is how far both got.
        let mut rel = equivalent;
        let n1 = self.segments.Len();
        let n2 = p2.segments.Len();
        let mut i: int = 0;
        while i < n1 && i < n2 {
            rel = combineRelationships(rel, compareSegments(&self.segments[i], &p2.segments[i]));
            if rel == disjoint {
                return rel;
            }
            i += 1;
        }
        // Go: "If they have the same number of segments, then we've
        // already determined their relationship."
        if i == n1 && i == n2 {
            return rel;
        }
        // Go: "the only way they could fail to be disjoint is if the
        // shorter pattern ends in a multi. In that case, that multi is
        // more general than the remainder of the longer pattern."
        if n1 < n2 && self.lastSegment().multi {
            return combineRelationships(rel, moreGeneral);
        }
        if n2 < n1 && p2.lastSegment().multi {
            return combineRelationships(rel, moreSpecific);
        }
        return disjoint;
    }
}

// go: sdk 1.25.5 net/http/pattern.go:318-349 compareSegments
/// Go: "compareSegments determines the relationship between two
/// segments."
pub fn compareSegments(s1: &segment, s2: &segment) -> relationship {
    if s1.multi && s2.multi {
        return equivalent;
    }
    if s1.multi {
        return moreGeneral;
    }
    if s2.multi {
        return moreSpecific;
    }
    if s1.wild && s2.wild {
        return equivalent;
    }
    if s1.wild {
        if s2.s == "/" {
            // Go: "A single wildcard doesn't match a trailing slash."
            return disjoint;
        }
        return moreGeneral;
    }
    if s2.wild {
        if s1.s == "/" {
            return disjoint;
        }
        return moreSpecific;
    }
    // Go: "Both literals."
    if s1.s == s2.s {
        return equivalent;
    }
    return disjoint;
}

// go: sdk 1.25.5 net/http/pattern.go:359-382 combineRelationships
/// Go: "combineRelationships determines the overall relationship of two
/// patterns given the relationships of a partition of the patterns into
/// two parts. For example, if p1 is more general than p2 in one way but
/// equivalent in the other, then it is more general overall. Or if p1 is
/// more general in one way and more specific in the other, then they
/// overlap."
pub fn combineRelationships(r1: relationship, r2: relationship) -> relationship {
    if r1 == equivalent {
        return r2;
    }
    if r1 == disjoint {
        return disjoint;
    }
    if r1 == overlaps {
        if r2 == disjoint {
            return disjoint;
        }
        return overlaps;
    }
    if r1 == moreGeneral || r1 == moreSpecific {
        if r2 == equivalent {
            return r1;
        }
        if r2 == inverseRelationship(r1) {
            return overlaps;
        }
        return r2;
    }
    panic!("unknown relationship");
}

// go: sdk 1.25.5 net/http/pattern.go:386-395 inverseRelationship
/// Go: "If p1 has relationship `r` to p2, then p2 has
/// inverseRelationship(r) to p1."
pub fn inverseRelationship(r: relationship) -> relationship {
    if r == moreSpecific {
        return moreGeneral;
    }
    if r == moreGeneral {
        return moreSpecific;
    }
    return r;
}

// go: sdk 1.25.5 net/http/pattern.go:398-403 isLitOrSingle
/// Go: "isLitOrSingle reports whether the segment is a non-dollar
/// literal or a single wildcard."
pub fn isLitOrSingle(seg: &segment) -> bool {
    if seg.wild {
        return !seg.multi;
    }
    return seg.s != "/";
}

// go: sdk 1.25.5 net/http/pattern.go:406-430 describeConflict
/// Go: "describeConflict returns an explanation of why two patterns
/// conflict."
///
/// The text matters: it is what a developer sees when two routes
/// collide at registration, and Go went to the trouble of computing an
/// example path that both match and one that only each matches.
pub fn describeConflict(p1: &pattern, p2: &pattern) -> string {
    let mrel = p1.compareMethods(p2);
    let prel = p1.comparePaths(p2);
    let rel = combineRelationships(mrel, prel);
    if rel == equivalent {
        return crate::fmt::Sprintf!(
            "%s matches the same requests as %s",
            p1.String(),
            p2.String()
        );
    }
    if rel != overlaps {
        panic!("describeConflict called with non-conflicting patterns");
    }
    if prel == overlaps {
        return crate::fmt::Sprintf!(
            "%s and %s both match some paths, like %q.\nBut neither is more specific than the other.\n%s matches %q, but %s doesn't.\n%s matches %q, but %s doesn't.",
            p1.String(), p2.String(), commonPath(p1, p2),
            p1.String(), differencePath(p1, p2), p2.String(),
            p2.String(), differencePath(p2, p1), p1.String()
        );
    }
    if mrel == moreGeneral && prel == moreSpecific {
        return crate::fmt::Sprintf!(
            "%s matches more methods than %s, but has a more specific path pattern",
            p1.String(),
            p2.String()
        );
    }
    if mrel == moreSpecific && prel == moreGeneral {
        return crate::fmt::Sprintf!(
            "%s matches fewer methods than %s, but has a more general path pattern",
            p1.String(),
            p2.String()
        );
    }
    return crate::fmt::Sprintf!(
        "bug: unexpected way for two patterns %s and %s to conflict: methods %s, paths %s",
        p1.String(),
        p2.String(),
        mrel.String(),
        prel.String()
    );
}

// go: sdk 1.25.5 net/http/pattern.go:433-437 writeMatchingPath
/// Go: "writeMatchingPath writes to b a path that matches the
/// segments."
pub fn writeMatchingPath(b: &mut strings::Builder, segs: &slice<segment>) {
    let mut i: int = 0;
    while i < segs.Len() {
        let s = &segs[i];
        i += 1;
        writeSegment(b, s);
    }
}

// go: sdk 1.25.5 net/http/pattern.go:439-444 writeSegment
pub fn writeSegment(b: &mut strings::Builder, s: &segment) {
    let _ = b.WriteByte(b'/');
    if !s.multi && s.s != "/" {
        let _ = b.WriteString(s.s.clone());
    }
}

// go: sdk 1.25.5 net/http/pattern.go:448-464 commonPath
/// Go: "commonPath returns a path that both p1 and p2 match. It assumes
/// there is such a path."
pub fn commonPath(p1: &pattern, p2: &pattern) -> string {
    let mut b = strings::Builder::new();
    let n1 = p1.segments.Len();
    let n2 = p2.segments.Len();
    let mut i: int = 0;
    while i < n1 && i < n2 {
        let s1 = &p1.segments[i];
        if s1.wild {
            writeSegment(&mut b, &p2.segments[i]);
        } else {
            writeSegment(&mut b, s1);
        }
        i += 1;
    }
    if i < n1 {
        writeMatchingPath(&mut b, &p1.segments.slice(i, n1));
    } else if i < n2 {
        writeMatchingPath(&mut b, &p2.segments.slice(i, n2));
    }
    return b.String();
}

// go: sdk 1.25.5 net/http/pattern.go:468-532 differencePath
/// Go: "differencePath returns a path that p1 matches and p2 doesn't.
/// It assumes there is such a path."
pub fn differencePath(p1: &pattern, p2: &pattern) -> string {
    let mut b = strings::Builder::new();
    let n1 = p1.segments.Len();
    let n2 = p2.segments.Len();
    let mut i: int = 0;
    while i < n1 && i < n2 {
        let s1 = p1.segments[i].clone();
        let s2 = p2.segments[i].clone();
        if s1.multi && s2.multi {
            // Go: "From here the patterns match the same paths, so we
            // must have found a difference earlier."
            let _ = b.WriteByte(b'/');
            return b.String();
        }
        if s1.multi && !s2.multi {
            // Go: "s1 ends in a "..." wildcard but s2 does not. A
            // trailing slash will distinguish them, unless s2 ends in
            // "{$}", in which case any segment will do; prefer the
            // wildcard name if it has one."
            let _ = b.WriteByte(b'/');
            if s2.s == "/" {
                if s1.s.Len() != 0 {
                    let _ = b.WriteString(s1.s.clone());
                } else {
                    let _ = b.WriteString(string::from_static("x"));
                }
            }
            return b.String();
        }
        if !s1.multi && s2.multi {
            writeSegment(&mut b, &s1);
        } else if s1.wild && s2.wild {
            // Go: "Both patterns will match whatever we put here; use
            // the first wildcard name."
            writeSegment(&mut b, &s1);
        } else if s1.wild && !s2.wild {
            // Go: "Any segment other than s2.s will work. Prefer the
            // wildcard name, but if it's the same as the literal, tweak
            // the literal."
            if s1.s != s2.s {
                writeSegment(&mut b, &s1);
            } else {
                let _ = b.WriteByte(b'/');
                let _ = b.WriteString(s2.s.clone() + string::from_static("x"));
            }
        } else if !s1.wild && s2.wild {
            writeSegment(&mut b, &s1);
        } else {
            // Go: "Both are literals. A precondition of this function
            // is that the patterns overlap, so they must be the same
            // literal. Use it."
            if s1.s != s2.s {
                panic!("literals differ");
            }
            writeSegment(&mut b, &s1);
        }
        i += 1;
    }
    if i < n1 {
        // Go: "p1 is longer than p2, and p2 does not end in a multi.
        // Anything that matches the rest of p1 will do."
        writeMatchingPath(&mut b, &p1.segments.slice(i, n1));
    } else if i < n2 {
        writeMatchingPath(&mut b, &p2.segments.slice(i, n2));
    }
    return b.String();
}

// go: sdk 1.25.5 net/http/pattern.go:199-206 pathUnescape
/// Go: "Invalidly escaped path; use the original."
pub fn pathUnescape(path: string) -> string {
    let (u, err) = super::url::PathUnescape(path.clone());
    if !err.IsNil() {
        return path;
    }
    return u;
}
