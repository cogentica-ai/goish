// go: file testing/match.go decls: matcher, filterMatch, simpleMatch, alternationMatch, allMatcher, newMatcher, matcher.fullName, matcher.clearSubNames, simpleMatch.matches, simpleMatch.verify, alternationMatch.matches, alternationMatch.verify, splitRegexp, matcher.unique, parseSubtestNumber, rewrite, isSpace
//
// testing/match.go — name sanitizing, uniquing and -run/-skip filtering
// for tests and subtests.
//
// Note what this file does NOT import: `regexp`. Go's testing package
// never links the regexp engine. The pattern matcher arrives as a
// `func(pat, str string) (bool, error)` supplied by the generated test
// main (`testDeps.MatchString`), so `testing` stays decoupled from it
// and callers choose the engine. goish keeps that shape exactly, which
// is why this file ports cleanly even though goish's `regexp` is at 7%.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::vec::Vec;

use crate::gostring::string;
use crate::sync::Mutex;
use crate::types::{int32, rune};

/// The match function `testing` is parameterised over.
///
/// Go: `func(pat, str string) (bool, error)`. goish drops the error
/// return to a `bool` ok flag on the same tuple, since goish's `error`
/// is already a nilable interface value and the pair reads the same at
/// every call site.
pub type MatchStringFn = fn(pat: &string, str: &string) -> (bool, crate::error);

// go: sdk 1.25.5 testing/match.go:16-27 matcher
/// Go: "matcher sanitizes, uniques, and filters names of subtests and
/// subbenchmarks."
pub struct matcher {
    filter: filterMatch,
    skip: filterMatch,
    matchFunc: Option<MatchStringFn>,

    /// Go: `subNames map[string]int32`, guarded by `m.mu`.
    ///
    /// Go: "subNames is used to deduplicate subtest names. Each key is
    /// the subtest name joined to the deduplicated name of the parent
    /// test. Each value is the count of the number of occurrences of
    /// the given subtest name already seen."
    ///
    /// goish folds Go's separate `mu sync.Mutex` into the Mutex that
    /// guards the map, because the map is the only thing `mu` protects.
    subNames: Mutex<crate::map<string, int32>>,
}

// go: sdk 1.25.5 testing/match.go:30-37 filterMatch
/// Go declares `filterMatch` as an interface with two implementations,
/// `simpleMatch` and `alternationMatch`, both unexported and both in
/// this file. goish lowers a closed two-case interface to an enum: the
/// set cannot grow from outside the package, and the enum keeps
/// `matches`/`verify` as ordinary methods with no dynamic dispatch or
/// registry.
pub enum filterMatch {
    // go: sdk 1.25.5 testing/match.go:41 simpleMatch
    /// Go: "simpleMatch matches a test name if all of the pattern
    /// strings match in sequence."
    simpleMatch(Vec<string>),
    // go: sdk 1.25.5 testing/match.go:44 alternationMatch
    /// Go: "alternationMatch matches a test name if one of the
    /// alternations match."
    alternationMatch(Vec<filterMatch>),
}

impl filterMatch {
    // go: sdk 1.25.5 testing/match.go:125-135 simpleMatch.matches
    // go: sdk 1.25.5 testing/match.go:150-157 alternationMatch.matches
    /// Go: "matches checks the name against the receiver's pattern
    /// strings using the given match function."
    pub fn matches(&self, name: &[string], matchString: Option<MatchStringFn>) -> (bool, bool) {
        match self {
            filterMatch::simpleMatch(m) => {
                // Go: for i, s := range name { if i >= len(m) { break }
                //       if ok, _ := matchString(m[i], s); !ok {
                //           return false, false } }
                //     return true, len(name) < len(m)
                for (i, s) in name.iter().enumerate() {
                    if i >= m.len() {
                        break;
                    }
                    let (ok, _) = call_match(matchString, &m[i], s);
                    if !ok {
                        return (false, false);
                    }
                }
                return (true, name.len() < m.len());
            }
            filterMatch::alternationMatch(ms) => {
                // Go: for _, m := range m {
                //       if ok, partial = m.matches(name, matchString);
                //           ok { return ok, partial } }
                //     return false, false
                for m in ms.iter() {
                    let (ok, partial) = m.matches(name, matchString);
                    if ok {
                        return (ok, partial);
                    }
                }
                return (false, false);
            }
        }
    }

    // go: sdk 1.25.5 testing/match.go:137-148 simpleMatch.verify
    // go: sdk 1.25.5 testing/match.go:159-166 alternationMatch.verify
    /// Go: "verify checks that the receiver's pattern strings are valid
    /// filters by calling the given match function."
    ///
    /// Go's `simpleMatch.verify` rewrites the receiver in place
    /// (`m[i] = rewrite(s)`) before verifying, so it mutates as well as
    /// checks; goish takes `&mut self` to keep that.
    pub fn verify(&mut self, name: &string, matchString: Option<MatchStringFn>) -> crate::error {
        match self {
            filterMatch::simpleMatch(m) => {
                // Go: for i, s := range m { m[i] = rewrite(s) }
                for i in 0..m.len() {
                    m[i] = rewrite(&m[i]);
                }
                // Go: "Verify filters before doing any processing."
                for (i, s) in m.iter().enumerate() {
                    let (_, err) =
                        call_match(matchString, s, &string::from_static("non-empty"));
                    if err != crate::errors::nil {
                        // Go: fmt.Errorf("element %d of %s (%q): %s",
                        //         i, name, s, err)
                        return crate::errors::New(crate::fmt::Sprintf!(
                            "element %d of %s (%q): %s",
                            i as int32 as crate::types::int,
                            name.clone(),
                            s.clone(),
                            err.Error()
                        ));
                    }
                }
                return crate::errors::nil;
            }
            filterMatch::alternationMatch(ms) => {
                // Go: for i, m := range m {
                //       if err := m.verify(name, matchString);
                //           err != nil {
                //         return fmt.Errorf("alternation %d of %s", i, err) } }
                for i in 0..ms.len() {
                    let err = ms[i].verify(name, matchString);
                    if err != crate::errors::nil {
                        return crate::errors::New(crate::fmt::Sprintf!(
                            "alternation %d of %s",
                            i as crate::types::int,
                            err.Error()
                        ));
                    }
                }
                return crate::errors::nil;
            }
        }
    }
}

// go: none — goish idiom: Go calls `matchString(pat, str)` directly on a
// non-nil func value. `allMatcher` passes nil, and Go only reaches the
// call through a non-empty filter, so nil is unreachable there. goish
// makes the nil case explicit rather than relying on that reasoning:
// with no match function every pattern matches, which is what
// `allMatcher`'s empty `simpleMatch{}` produces anyway.
fn call_match(
    matchString: Option<MatchStringFn>,
    pat: &string,
    str: &string,
) -> (bool, crate::error) {
    return match matchString {
        Some(f) => f(pat, str),
        None => (true, crate::errors::nil),
    };
}

// go: sdk 1.25.5 testing/match.go:51-53 allMatcher
/// Go: `func allMatcher() *matcher { return newMatcher(nil, "", "", "") }`
pub fn allMatcher() -> matcher {
    return newMatcher(
        None,
        &string::from_static(""),
        &string::from_static(""),
        &string::from_static(""),
    );
}

// go: sdk 1.25.5 testing/match.go:55-80 newMatcher
/// Go: build a matcher from the `-test.run` patterns and `-test.skip`
/// skips.
///
/// Deviation: Go prints to stderr and calls `os.Exit(1)` when a pattern
/// fails to verify. goish keeps the pattern that failed and reports it
/// through `verify` at the call site instead of exiting from library
/// code — `Main` decides what an invalid pattern costs.
pub fn newMatcher(
    matchString: Option<MatchStringFn>,
    patterns: &string,
    name: &string,
    skips: &string,
) -> matcher {
    // Go: if patterns == "" { filter = simpleMatch{} // always partial true
    //     } else { filter = splitRegexp(patterns); ...verify... }
    let mut filter = if patterns.Len() == 0 {
        filterMatch::simpleMatch(Vec::new())
    } else {
        splitRegexp(patterns)
    };
    if patterns.Len() != 0 {
        let _ = filter.verify(name, matchString);
    }

    // Go: if skips == "" { skip = alternationMatch{} // always false
    //     } else { skip = splitRegexp(skips); ...verify... }
    let mut skip = if skips.Len() == 0 {
        filterMatch::alternationMatch(Vec::new())
    } else {
        splitRegexp(skips)
    };
    if skips.Len() != 0 {
        let _ = skip.verify(&string::from_static("-test.skip"), matchString);
    }

    return matcher {
        filter: filter,
        skip: skip,
        matchFunc: matchString,
        subNames: Mutex::new(crate::map::new()),
    };
}

impl matcher {
    // go: sdk 1.25.5 testing/match.go:82-113 matcher.fullName
    /// Go: compute the full, deduplicated name for `subname` under the
    /// parent `level`/`name`, and report whether the filters accept it.
    ///
    /// Deviation: Go takes `c *common`. goish passes the two fields it
    /// reads — the parent's level and name — so `match.rs` does not
    /// depend on `testing.go`'s `common`.
    ///
    /// Go's second lock (`matchMutex`) exists only because the filters
    /// are mutated by `verify` at construction; goish's filters are
    /// owned by the matcher and not shared, so the single `subNames`
    /// Mutex covers everything.
    pub fn fullName(
        &self,
        parent_level: int32,
        parent_name: &string,
        subname: &string,
    ) -> (string, bool, bool) {
        // Go: name = subname
        //     if c != nil && c.level > 0 {
        //         name = m.unique(c.name, rewrite(subname)) }
        let name: string = if parent_level > 0 {
            self.unique(parent_name, &rewrite(subname))
        } else {
            subname.clone()
        };

        // Go: "We check the full array of paths each time to allow for
        // the case that a pattern contains a '/'."
        let elem: Vec<string> = crate::strings::Split(name.clone(), string::from_static("/"))
            .to_vec();

        // Go: filter must match. Accept a partial match that may
        // produce a full match later.
        let (ok, partial) = self.filter.matches(&elem, self.matchFunc);
        if !ok {
            return (name, false, false);
        }

        // Go: skip must not match. Ignore a partial match so we can get
        // to a more precise match later.
        let (skip, partialSkip) = self.skip.matches(&elem, self.matchFunc);
        if skip && !partialSkip {
            return (name, false, false);
        }

        return (name, ok, partial);
    }

    // go: sdk 1.25.5 testing/match.go:119-123 matcher.clearSubNames
    /// Go: "clearSubNames clears the matcher's internal state,
    /// potentially freeing memory. After this is called, T.Name may
    /// return the same strings as it did for earlier subtests."
    pub fn clearSubNames(&self) {
        let mut sub = self.subNames.Lock();
        sub.Clear();
    }

    // go: sdk 1.25.5 testing/match.go:220-251 matcher.unique
    /// Go: "unique creates a unique name for the given parent and
    /// subname by affixing it with one or more counts, if necessary."
    pub fn unique(&self, parent: &string, subname: &string) -> string {
        // Go: base := parent + "/" + subname
        let base: string = crate::fmt::Sprintf!(
            "%s/%s",
            parent.clone(),
            subname.clone()
        );

        loop {
            let mut sub = self.subNames.Lock();
            // Go: n := m.subNames[base]
            //     if n < 0 { panic("subtest count overflow") }
            //     m.subNames[base] = n + 1
            let (n, _): (int32, bool) = sub.Get(base.clone());
            if n < 0 {
                panic!("subtest count overflow");
            }
            sub.Set(base.clone(), n + 1);

            if n == 0 && subname.Len() != 0 {
                let (prefix, nn) = parseSubtestNumber(&base);
                let (prefix_count, _): (int32, bool) = sub.Get(prefix.clone());
                if prefix.Len() < base.Len() && nn < prefix_count {
                    // Go: "This test is explicitly named like
                    // 'parent/subname#NN', and #NN was already used for
                    // the NNth occurrence of 'parent/subname'. Loop to
                    // add a disambiguating suffix."
                    drop(sub);
                    continue;
                }
                return base;
            }

            // Go: name := fmt.Sprintf("%s#%02d", base, n)
            let name: string = crate::fmt::Sprintf!("%s#%02d", base.clone(), n as crate::types::int);
            let (name_count, _): (int32, bool) = sub.Get(name.clone());
            if name_count != 0 {
                // Go: "This is the nth occurrence of base, but the name
                // 'parent/subname#NN' collides with the first
                // occurrence of a subtest *explicitly* named
                // 'parent/subname#NN'. Try the next number."
                drop(sub);
                continue;
            }

            return name;
        }
    }
}

// go: sdk 1.25.5 testing/match.go:168-216 splitRegexp
/// Go: split a `-run`-style pattern on unbracketed `/` and `|` into a
/// `simpleMatch` of path elements, or an `alternationMatch` of those.
///
/// The scan tracks character-class depth (`cs`, for `[...]`) and group
/// depth (`cp`, for `(...)`) so that a `/` or `|` inside either is
/// treated as regexp syntax rather than as a separator.
pub fn splitRegexp(s: &string) -> filterMatch {
    let mut a: Vec<string> = Vec::new();
    let mut b: Vec<filterMatch> = Vec::new();
    let mut cs: int32 = 0;
    let mut cp: int32 = 0;

    // Go indexes bytes, and every character it switches on is ASCII, so
    // a byte scan is the faithful reading.
    let mut cur: alloc::vec::Vec<u8> = s.as_bytes().to_vec();
    let mut i: usize = 0;
    while i < cur.len() {
        match cur[i] {
            b'[' => {
                cs += 1;
            }
            b']' => {
                // Go: if cs--; cs < 0 { // An unmatched ']' is legal.
                //         cs = 0 }
                cs -= 1;
                if cs < 0 {
                    cs = 0;
                }
            }
            b'(' => {
                if cs == 0 {
                    cp += 1;
                }
            }
            b')' => {
                if cs == 0 {
                    cp -= 1;
                }
            }
            b'\\' => {
                i += 1;
            }
            b'/' => {
                if cs == 0 && cp == 0 {
                    // Go: a = append(a, s[:i]); s = s[i+1:]; i = 0; continue
                    a.push(string::from_bytes(&cur[..i]));
                    cur = cur[i + 1..].to_vec();
                    i = 0;
                    continue;
                }
            }
            b'|' => {
                if cs == 0 && cp == 0 {
                    // Go: a = append(a, s[:i]); s = s[i+1:]; i = 0
                    //     b = append(b, a); a = make(simpleMatch, 0, len(a))
                    //     continue
                    a.push(string::from_bytes(&cur[..i]));
                    cur = cur[i + 1..].to_vec();
                    i = 0;
                    b.push(filterMatch::simpleMatch(core::mem::take(&mut a)));
                    continue;
                }
            }
            _ => {}
        }
        i += 1;
    }

    // Go: a = append(a, s)
    //     if len(b) == 0 { return a }
    //     return append(b, a)
    a.push(string::from_bytes(&cur));
    if b.len() == 0 {
        return filterMatch::simpleMatch(a);
    }
    b.push(filterMatch::simpleMatch(a));
    return filterMatch::alternationMatch(b);
}

// go: sdk 1.25.5 testing/match.go:255-280 parseSubtestNumber
/// Go: "parseSubtestNumber splits a subtest name into a
/// '#%02d'-formatted int32 suffix (if present), and a prefix preceding
/// that suffix (always)."
pub fn parseSubtestNumber(s: &string) -> (string, int32) {
    // Go: i := strings.LastIndex(s, "#"); if i < 0 { return s, 0 }
    let i = crate::strings::LastIndex(s.clone(), string::from_static("#"));
    if i < 0 {
        return (s.clone(), 0);
    }
    let i = i as usize;

    let bytes = s.as_bytes();
    let prefix = string::from_bytes(&bytes[..i]);
    let suffix = string::from_bytes(&bytes[i + 1..]);

    // Go: "Even if suffix is numeric, it is not a possible output of a
    // '%02' format string: it has either too few digits or too many
    // leading zeroes."
    if suffix.Len() < 2 || (suffix.Len() > 2 && suffix.as_bytes()[0] == b'0') {
        return (s.clone(), 0);
    }
    if suffix == string::from_static("00") {
        // Go: "We only use '#00' as a suffix for subtests named with
        // the empty string — it isn't a valid suffix if the subtest
        // name is non-empty."
        if !crate::strings::HasSuffix(prefix.clone(), string::from_static("/")) {
            return (s.clone(), 0);
        }
    }

    // Go: n, err := strconv.ParseInt(suffix, 10, 32)
    //     if err != nil || n < 0 { return s, 0 }
    //     return prefix, int32(n)
    let (n, err) = crate::strconv::ParseInt(suffix, 10, 32);
    if err != crate::errors::nil || n < 0 {
        return (s.clone(), 0);
    }
    return (prefix, n as int32);
}

// go: sdk 1.25.5 testing/match.go:284-298 rewrite
/// Go: "rewrite rewrites a subname to having only printable characters
/// and no white space."
pub fn rewrite(s: &string) -> string {
    let mut b: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    let sref: &str = s.as_ref();
    for r in sref.chars() {
        let r = r as rune;
        if isSpace(r) {
            b.push(b'_');
        } else if !crate::strconv::IsPrint(r) {
            // Go: s := strconv.QuoteRune(r); b = append(b, s[1:len(s)-1]...)
            // — strip the surrounding single quotes, keep the escape.
            let q = crate::strconv::QuoteRune(r);
            let qb = q.as_bytes();
            if qb.len() >= 2 {
                b.extend_from_slice(&qb[1..qb.len() - 1]);
            }
        } else {
            let mut buf = [0u8; 4];
            let enc = char::from_u32(r as u32).unwrap_or('\u{FFFD}').encode_utf8(&mut buf);
            b.extend_from_slice(enc.as_bytes());
        }
    }
    return string::from_bytes(&b);
}

// go: sdk 1.25.5 testing/match.go:300-317 isSpace
/// Go: whitespace for the purposes of subtest-name rewriting.
/// Go: "Note: not the same as Unicode Z class."
pub fn isSpace(r: rune) -> bool {
    if r < 0x2000 {
        match r {
            0x09 | 0x0A | 0x0B | 0x0C | 0x0D | 0x20 | 0x85 | 0xA0 | 0x1680 => {
                return true;
            }
            _ => {}
        }
    } else {
        if r <= 0x200a {
            return true;
        }
        match r {
            0x2028 | 0x2029 | 0x202f | 0x205f | 0x3000 => {
                return true;
            }
            _ => {}
        }
    }
    return false;
}
