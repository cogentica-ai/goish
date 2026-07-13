// net/http/pattern — Go 1.22 wildcard patterns for ServeMux.
//
// Slim line-by-line port of Go 1.25 src/net/http/pattern.go (532 LOC).
// Each `pub fn` / method is annotated with the corresponding Go source
// line so the two read side-by-side.
//
// What's ported (the 80/20 of Go 1.22 patterns):
//   - parsePattern with `[METHOD ]` prefix and `/host/path` segments
//   - `{name}` single-segment wildcards
//   - `{name...}` trailing multi-segment wildcards
//   - `{$}` end-of-path marker (matches only requests ending in '/')
//   - host prefix (literal only — must precede the first '/')
//
// What's deferred (matches existing ServeMux behavior):
//   - Conflict detection between patterns (Go's `conflictsWith`,
//     `comparePathsAndMethods`, routing_tree.go). v1 uses first-match-wins
//     in registration order, with the longest matched path as a
//     tiebreak — same shape as the pre-1.22 ServeMux.
//   - URL path-unescape on literal segments (we keep them raw).

#![allow(non_snake_case)]
#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

use crate::errors::{self, error};
use crate::gomap::map;
use crate::goslice::slice;
use crate::string;
use crate::strings;
use crate::types::{byte, int, rune};
use crate::unicode;

// ─── pattern + segment types ────────────────────────────────────────

/// A pattern is something that can be matched against an HTTP request.
/// Mirrors Go's unexported `pattern` (pattern.go:19) with public
/// fields since goish doesn't have package-private visibility.
#[derive(Clone)]
pub struct Pattern {
    /// Original string.
    pub Str: string,
    /// Empty string = no method match.
    pub Method: string,
    /// Empty string = no host match.
    pub Host: string,
    /// Decoded path segments.
    pub Segments: slice<Segment>,
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
pub struct Segment {
    /// Literal text (when !wild) or wildcard name (when wild).
    /// `s == "/"` is the special end-of-path marker from `{$}`.
    pub S: string,
    pub Wild: bool,
    pub Multi: bool,
}

impl Default for Segment {
    fn default() -> Self {
        Segment {
            S: string::new(),
            Wild: false,
            Multi: false,
        }
    }
}

// ─── parsePattern ───────────────────────────────────────────────────

/// `parsePattern(s)` — line-by-line port of pattern.go:84.
///
/// Syntax: `[METHOD] [HOST]/[PATH]` where each PATH segment is either
/// a literal or a wildcard `{name}` / `{name...}` / `{$}`.
pub fn parse_pattern<S: Into<string>>(s: S) -> (Pattern, error) {
    let s: string = s.into();
    // Go: if len(s) == 0 { return nil, errors.New("empty pattern") }
    if s.Len() == 0 {
        return (default_pattern(), errors::New(string("empty pattern")));
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
        let head = sub_str(&s, 0, i);
        let tail = strings::TrimLeft(sub_str(&s, i + 1, s.Len()), string(" \t"));
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
    if method.Len() > 0 && !valid_method(&method) {
        return (default_pattern(), errors::New(string("invalid method")));
    }

    // Go: p := &pattern{str: s, method: method}
    let mut p = Pattern {
        Str: s.clone(),
        Method: method,
        Host: string::new(),
        Segments: slice::<Segment>::__from_vec(Vec::new()),
    };

    // Go: i := strings.IndexByte(rest, '/'); if i < 0 { return nil, errors.New("host/path missing /") }
    let i = strings::IndexByte(rest.clone(), b'/');
    if i < 0 {
        return (default_pattern(), errors::New(string("host/path missing /")));
    }
    // Go: p.host = rest[:i]; rest = rest[i:]
    p.Host = sub_str(&rest, 0, i);
    rest = sub_str(&rest, i, rest.Len());

    // Go: if j := strings.IndexByte(p.host, '{'); j >= 0 { return nil, errors.New("host contains '{'") }
    if strings::IndexByte(p.Host.clone(), b'{') >= 0 {
        return (
            default_pattern(),
            errors::New(string("host contains '{' (missing initial '/'?)")),
        );
    }

    // Go: seenNames := map[string]bool{}
    let mut seen_names: map<string, bool> = map::<string, bool>::new();
    // Go: for len(rest) > 0 { … rest[0] == '/' invariant … }
    let mut segments: Vec<Segment> = Vec::new();
    while rest.Len() > 0 {
        // Go: rest = rest[1:]
        rest = sub_str(&rest, 1, rest.Len());
        // Go: if len(rest) == 0 { p.segments = append(p.segments, segment{wild: true, multi: true}); break }
        if rest.Len() == 0 {
            segments.push(Segment {
                S: string::new(),
                Wild: true,
                Multi: true,
            });
            break;
        }
        // Go: i := strings.IndexByte(rest, '/'); if i < 0 { i = len(rest) }
        let i = strings::IndexByte(rest.clone(), b'/');
        let i = if i < 0 { rest.Len() } else { i };
        // Go: var seg string; seg, rest = rest[:i], rest[i:]
        let seg = sub_str(&rest, 0, i);
        rest = sub_str(&rest, i, rest.Len());

        // Go: if i := strings.IndexByte(seg, '{'); i < 0 { … literal … } else { … wildcard … }
        let lb = strings::IndexByte(seg.clone(), b'{');
        if lb < 0 {
            // Literal — Go does pathUnescape; we keep it raw.
            segments.push(Segment {
                S: seg,
                Wild: false,
                Multi: false,
            });
        } else {
            // Wildcard.
            // Go: if i != 0 { return nil, errors.New("bad wildcard segment (must start with '{')") }
            if lb != 0 {
                return (
                    default_pattern(),
                    errors::New(string("bad wildcard segment (must start with '{')")),
                );
            }
            // Go: if seg[len(seg)-1] != '}' { return nil, errors.New("bad wildcard segment (must end with '}')") }
            if seg[seg.Len() - 1] != b'}' {
                return (
                    default_pattern(),
                    errors::New(string("bad wildcard segment (must end with '}')")),
                );
            }
            // Go: name := seg[1 : len(seg)-1]
            let name = sub_str(&seg, 1, seg.Len() - 1);
            // Go: if name == "$" { … {$} marker … }
            if name == "$" {
                if rest.Len() != 0 {
                    return (
                        default_pattern(),
                        errors::New(string("{$} not at end")),
                    );
                }
                segments.push(Segment {
                    S: string("/"),
                    Wild: false,
                    Multi: false,
                });
                break;
            }
            // Go: name, multi := strings.CutSuffix(name, "...")
            let (name, multi) = strings::CutSuffix(name, string("..."));
            // Go: if multi && len(rest) != 0 { return nil, errors.New("{...} wildcard not at end") }
            if multi && rest.Len() != 0 {
                return (
                    default_pattern(),
                    errors::New(string("{...} wildcard not at end")),
                );
            }
            // Go: if name == "" { return nil, errors.New("empty wildcard") }
            if name.Len() == 0 {
                return (default_pattern(), errors::New(string("empty wildcard")));
            }
            // Go: if !isValidWildcardName(name) { return nil, fmt.Errorf("bad wildcard name %q", name) }
            if !is_valid_wildcard_name(&name) {
                return (default_pattern(), errors::New(string("bad wildcard name")));
            }
            // Go: if seenNames[name] { return nil, fmt.Errorf("duplicate wildcard name %q", name) }
            let (_, dup) = seen_names.Get(name.clone());
            if dup {
                return (
                    default_pattern(),
                    errors::New(string("duplicate wildcard name")),
                );
            }
            seen_names.Set(name.clone(), true);
            // Go: p.segments = append(p.segments, segment{s: name, wild: true, multi: multi})
            segments.push(Segment {
                S: name,
                Wild: true,
                Multi: multi,
            });
        }
    }
    p.Segments = slice::<Segment>::__from_vec(segments);
    (p, errors::nil)
}

/// Line-by-line port of `isValidWildcardName` (pattern.go:186).
fn is_valid_wildcard_name(s: &string) -> bool {
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

/// Line-by-line port of `validMethod` (request.go:131 paraphrased).
/// Methods are case-sensitive RFC 7230 tokens.
fn valid_method(s: &string) -> bool {
    if s.Len() == 0 {
        return false;
    }
    for i in 0..s.Len() {
        let c: byte = s[i];
        let ok = matches!(c,
            b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' |
            b'^' | b'_' | b'`' | b'|' | b'~' |
            b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z');
        if !ok {
            return false;
        }
    }
    true
}

// ─── Pattern matching ────────────────────────────────────────────────

impl Pattern {
    /// Try to match `(method, host, path)` against this pattern.
    /// Returns `Some(bindings)` on success (a map of wildcard-name →
    /// bound-segment) or `None` on no match.
    ///
    /// Faithful to Go's match semantics from pattern.go's
    /// matching algorithm and ServeMux.handler dispatch path.
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
        if self.Method.Len() > 0 && self.Method != *method {
            let get_matches_head =
                self.Method == string("GET") && *method == string("HEAD");
            if !get_matches_head {
                return None;
            }
        }
        // Host match: empty Host = any host.
        if self.Host.Len() > 0 && self.Host != *host {
            return None;
        }
        // Path match: walk segments against path.
        let mut bindings: map<string, string> = map::<string, string>::new();
        let mut rest = path.clone();
        for i in 0..self.Segments.Len() {
            let seg = &self.Segments[i];
            // Go's path invariant: leading '/' on each iteration.
            if rest.Len() == 0 || rest[0] != b'/' {
                return None;
            }
            // Drop the leading '/'.
            rest = sub_str(&rest, 1, rest.Len());

            if seg.Wild && seg.Multi {
                // Greedy: bind everything left (possibly empty).
                if seg.S.Len() > 0 {
                    bindings.Set(seg.S.clone(), rest.clone());
                }
                rest = string::new();
                break;
            }
            if seg.S == "/" && !seg.Wild {
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
                (sub_str(&rest, 0, j), sub_str(&rest, j, rest.Len()))
            };
            if seg.Wild {
                // Single-segment wildcard. Empty segment doesn't match
                // (matches Go's pre-1.22 behavior; Go 1.22 also rejects).
                if this_seg.Len() == 0 {
                    return None;
                }
                bindings.Set(seg.S.clone(), this_seg);
            } else {
                // Literal — exact match.
                if seg.S != this_seg {
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

fn default_pattern() -> Pattern {
    Pattern {
        Str: string::new(),
        Method: string::new(),
        Host: string::new(),
        Segments: slice::<Segment>::__from_vec(Vec::new()),
    }
}

/// Substring helper — Go has `s[low:high]` natively; goish doesn't
/// expose a public `string.slice` so we go through bytes. Behavior:
/// returns the byte-substring `[low, high)`, panicking on
/// out-of-bounds (matching Go).
fn sub_str(s: &string, low: int, high: int) -> string {
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

#[inline]
fn __as_bytes(s: &string) -> &[u8] {
    crate::gostring::__crate_as_bytes(s)
}
