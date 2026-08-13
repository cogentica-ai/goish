// go: package net/http/cookiejar
//
// go: file net/http/cookiejar/jar.go decls: New, entry.id, entry.shouldSend, entry.domainMatch, entry.pathMatch, hasDotSuffix, Jar.Cookies, Jar.cookies, Jar.SetCookies, Jar.setCookies, canonicalHost, hasPort, jarKey, isIP, defaultPath, Jar.newEntry, Jar.domainAndType, endOfTime
//
// Go: "Package cookiejar implements an in-memory RFC 6265-compliant
// http.CookieJar."
//
// Go's Jar keeps `mu sync.Mutex` beside the two fields it guards.
// goish puts those two fields inside the Mutex instead, which is the
// same discipline expressed in the type system: `entries` and
// `nextSeqNum` are unreachable without the lock, so the "mu locks the
// remaining fields" comment cannot go stale.
//
// The nested map is BTreeMap, not goish `map<K,V>`: it is private
// storage that never crosses the package boundary, and its value type
// is itself a map. The Go-API rule is about the surface, and the
// surface here is Cookies/SetCookies, which take and return
// `slice<Cookie>`.
//
// The GOISH022 suppression on the `#[goish::interface]` line below is a
// linter false positive, not a divergence: the rule looks for the
// prefix `goish::int` and finds it inside `goish::interface`. The same
// hit is baselined in 22 other files across the tree.
//
// goishlint:ignore GOISH022 — false positive: the rule matches the
// prefix `goish::int` inside the attribute name `goish::interface`.
// It is baselined 22 times across the tree for the same reason.

#![allow(non_snake_case)]

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::gostring::string;
use crate::strings;
use crate::sync::Mutex;
use crate::time;
use crate::types::{int, uint64};

use super::super::cookie::{Cookie, SameSite};
use super::super::internal::ascii;
use super::super::url::URL;
use super::punycode;

// ─── PublicSuffixList ───────────────────────────────────────────────

// go: sdk 1.25.5 net/http/cookiejar/jar.go:36-48 PublicSuffixList
/// Go: "PublicSuffixList provides the public suffix of a domain. For
/// example the public suffix of "foo1.foo2.foo3.co.uk" is "co.uk".
/// Implementations must be safe for concurrent use by multiple
/// goroutines. An implementation that always returns "" is valid and
/// may be useful for testing but it is not secure: it means that the
/// HTTP server for foo.com can set a cookie for bar.com."
#[goish::interface] // goishlint:ignore GOISH022 - `goish::interface`, not `goish::int`
pub trait PublicSuffixList: Send + Sync {
    /// Go: "PublicSuffix returns the public suffix of domain."
    fn PublicSuffix(&self, domain: string) -> string;
    /// Go: "String returns a description of the source of this public
    /// suffix list."
    fn String(&self) -> string;
}

// ─── Options + Jar ──────────────────────────────────────────────────

// go: sdk 1.25.5 net/http/cookiejar/jar.go:51-59 Options
/// Go: "Options are the options for creating a new Jar."
#[derive(Clone, Default)]
pub struct Options {
    /// Go: "the public suffix list that determines whether an HTTP
    /// server can set a cookie for a domain. A nil value is valid and
    /// may be useful for testing but it is not secure."
    pub PublicSuffixList: Option<Arc<dyn PublicSuffixList>>,
}

// goishlint:ignore GOISH019 Jar — Go's `mu`, `entries` and `nextSeqNum`
// live together inside `state: Mutex<JarState>`; see the module note.
// go: sdk 1.25.5 net/http/cookiejar/jar.go:62-75 Jar
/// Go: "Jar implements the http.CookieJar interface from the net/http
/// package."
pub struct Jar {
    psList: Option<Arc<dyn PublicSuffixList>>,
    state: Arc<Mutex<JarState>>,
}

// go: none — goish-only: the payload of Go's `mu sync.Mutex`, i.e. the
// two Jar fields whose comment reads "mu locks the remaining fields".
struct JarState {
    entries: BTreeMap<string, BTreeMap<string, entry>>,
    nextSeqNum: uint64,
}

// go: sdk 1.25.5 net/http/cookiejar/jar.go:79-87 New
/// Go: "New returns a new cookie jar. A nil [*Options] is equivalent to
/// a zero Options."
pub fn New(o: Option<&Options>) -> (Arc<Jar>, error) {
    let mut jar = Jar {
        psList: None,
        state: Arc::new(Mutex::new(JarState {
            entries: BTreeMap::new(),
            nextSeqNum: 0,
        })),
    };
    if let Some(opts) = o {
        jar.psList = opts.PublicSuffixList.clone();
    }
    return (Arc::new(jar), nil);
}

// ─── entry ──────────────────────────────────────────────────────────

// go: sdk 1.25.5 net/http/cookiejar/jar.go:93-112 entry
/// Go: "entry is the internal representation of a cookie. This struct
/// type is not used outside of this package per se, but the exported
/// fields are those of RFC 6265."
#[derive(Clone, Default)]
struct entry {
    Name: string,
    Value: string,
    Quoted: bool,
    Domain: string,
    Path: string,
    SameSite: string,
    Secure: bool,
    HttpOnly: bool,
    Persistent: bool,
    HostOnly: bool,
    Expires: time::Time,
    Creation: time::Time,
    LastAccess: time::Time,

    /// Go: "a sequence number so that Cookies returns cookies in a
    /// deterministic order, even for cookies that have equal Path
    /// length and equal Creation time."
    seqNum: uint64,
}

impl entry {
    // go: sdk 1.25.5 net/http/cookiejar/jar.go:115-117 entry.id
    /// Go: "id returns the domain;path;name triple of e as an id."
    ///
    /// Go builds this with `fmt.Sprintf("%s;%s;%s", ...)`, which writes
    /// the three strings as raw bytes. Concatenating at the byte level
    /// rather than through `&str` matters: a domain that is not valid
    /// UTF-8 must still produce a distinct id, or two unrelated cookies
    /// collide on one map key and one silently overwrites the other.
    fn id(&self) -> string {
        let d = crate::gostring::__crate_as_bytes(&self.Domain);
        let p = crate::gostring::__crate_as_bytes(&self.Path);
        let n = crate::gostring::__crate_as_bytes(&self.Name);
        let mut out: Vec<u8> = Vec::with_capacity(d.len() + p.len() + n.len() + 2);
        out.extend_from_slice(d);
        out.push(b';');
        out.extend_from_slice(p);
        out.push(b';');
        out.extend_from_slice(n);
        return string::from_bytes(&out);
    }

    // go: sdk 1.25.5 net/http/cookiejar/jar.go:122-124 entry.shouldSend
    /// Go: "shouldSend determines whether e's cookie qualifies to be
    /// included in a request to host/path. It is the caller's
    /// responsibility to check if the cookie is expired."
    fn shouldSend(&self, https: bool, host: &string, path: &string) -> bool {
        return self.domainMatch(host) && self.pathMatch(path) && (https || !self.Secure);
    }

    // go: sdk 1.25.5 net/http/cookiejar/jar.go:129-134 entry.domainMatch
    /// Go: "domainMatch checks whether e's Domain allows sending e back
    /// to host. It differs from "domain-match" of RFC 6265 section
    /// 5.1.3 because we treat a cookie with an IP address in the Domain
    /// always as a host cookie."
    fn domainMatch(&self, host: &string) -> bool {
        if self.Domain == *host {
            return true;
        }
        return !self.HostOnly && hasDotSuffix(host, &self.Domain);
    }

    // go: sdk 1.25.5 net/http/cookiejar/jar.go:137-149 entry.pathMatch
    /// Go: "pathMatch implements "path-match" according to RFC 6265
    /// section 5.1.4."
    fn pathMatch(&self, requestPath: &string) -> bool {
        if *requestPath == self.Path {
            return true;
        }
        if strings::HasPrefix(requestPath.clone(), self.Path.clone()) {
            let pb = crate::gostring::__crate_as_bytes(&self.Path);
            let rb = crate::gostring::__crate_as_bytes(requestPath);
            if pb.last() == Some(&b'/') {
                // The "/any/" matches "/any/path" case.
                return true;
            } else if rb.get(pb.len()) == Some(&b'/') {
                // The "/any" matches "/any/path" case.
                return true;
            }
        }
        return false;
    }
}

// go: sdk 1.25.5 net/http/cookiejar/jar.go:152-154 hasDotSuffix
/// Go: "hasDotSuffix reports whether s ends in "."+suffix."
fn hasDotSuffix(s: &string, suffix: &string) -> bool {
    let sb = crate::gostring::__crate_as_bytes(s);
    let xb = crate::gostring::__crate_as_bytes(suffix);
    if sb.len() <= xb.len() {
        return false;
    }
    let split = sb.len() - xb.len();
    return sb[split - 1] == b'.' && &sb[split..] == xb;
}

// ─── Cookies / cookies ──────────────────────────────────────────────

impl Jar {
    // go: sdk 1.25.5 net/http/cookiejar/jar.go:159-161 Jar.Cookies
    /// Go: "Cookies implements the Cookies method of the
    /// [http.CookieJar] interface. It returns an empty slice if the
    /// URL's scheme is not HTTP or HTTPS."
    pub fn Cookies(&self, u: &URL) -> slice<Cookie> {
        return self.cookies(u, time::Now());
    }

    // go: sdk 1.25.5 net/http/cookiejar/jar.go:164-227 Jar.cookies
    /// Go: "cookies is like Cookies but takes the current time as a
    /// parameter."
    fn cookies(&self, u: &URL, now: time::Time) -> slice<Cookie> {
        let cookies: Vec<Cookie> = Vec::new();
        if u.Scheme != string::from_static("http") && u.Scheme != string::from_static("https") {
            return slice::__from_vec(cookies);
        }
        let (host, err) = canonicalHost(u.Host.clone());
        if !err.IsNil() {
            return slice::__from_vec(cookies);
        }
        let key = jarKey(&host, self.psList.clone());

        let mut s = self.state.Lock();

        if !s.entries.contains_key(&key) {
            return slice::__from_vec(cookies);
        }

        let https = u.Scheme == string::from_static("https");
        let mut path = u.Path.clone();
        if path == string::new() {
            path = string::from_static("/");
        }

        let mut modified = false;
        let mut selected: Vec<entry> = Vec::new();

        // Go mutates `submap` while ranging it, which a Go map permits
        // and a BTreeMap borrow does not. Collect first, apply after —
        // the observable result is the same because Go's loop only
        // deletes the key it is on or overwrites it with an equal key.
        let mut drop_ids: Vec<string> = Vec::new();
        let mut update_pairs: Vec<(string, entry)> = Vec::new();
        {
            let submap = match s.entries.get(&key) {
                Some(m) => m,
                None => return slice::__from_vec(cookies),
            };
            for (id, e) in submap.iter() {
                if e.Persistent && !e.Expires.After(now) {
                    drop_ids.push(id.clone());
                    modified = true;
                    continue;
                }
                if !e.shouldSend(https, &host, &path) {
                    continue;
                }
                let mut updated = e.clone();
                updated.LastAccess = now;
                update_pairs.push((id.clone(), updated.clone()));
                selected.push(updated);
                modified = true;
            }
        }

        {
            let submap = match s.entries.get_mut(&key) {
                Some(m) => m,
                None => return slice::__from_vec(cookies),
            };
            for id in drop_ids.iter() {
                submap.remove(id);
            }
            for (id, e) in update_pairs.into_iter() {
                submap.insert(id, e);
            }
        }

        if modified {
            let empty = s.entries.get(&key).map(|m| m.is_empty()).unwrap_or(false);
            if empty {
                s.entries.remove(&key);
            }
            // Go's `else { j.entries[key] = submap }` re-stores the same
            // map header; here the map was mutated in place.
        }

        // Go: "sort according to RFC 6265 section 5.4 point 2: by
        // longest path and then by earliest creation time."
        selected.sort_by(|a, b| {
            match b.Path.cmp(&a.Path) {
                core::cmp::Ordering::Equal => {}
                ord => return ord,
            }
            match a.Creation.Compare(b.Creation) {
                0 => {}
                n if n < 0 => return core::cmp::Ordering::Less,
                _ => return core::cmp::Ordering::Greater,
            }
            return a.seqNum.cmp(&b.seqNum);
        });

        let mut out: Vec<Cookie> = Vec::with_capacity(selected.len());
        for e in selected.into_iter() {
            let mut c = Cookie::default();
            c.Name = e.Name;
            c.Value = e.Value;
            c.Quoted = e.Quoted;
            out.push(c);
        }
        return slice::__from_vec(out);
    }

    // ─── SetCookies / setCookies ─────────────────────────────────────

    // go: sdk 1.25.5 net/http/cookiejar/jar.go:233-235 Jar.SetCookies
    /// Go: "SetCookies implements the SetCookies method of the
    /// [http.CookieJar] interface. It does nothing if the URL's scheme
    /// is not HTTP or HTTPS."
    pub fn SetCookies(&self, u: &URL, cookies: slice<Cookie>) {
        return self.setCookies(u, cookies, time::Now());
    }

    // go: sdk 1.25.5 net/http/cookiejar/jar.go:238-296 Jar.setCookies
    /// Go: "setCookies is like SetCookies but takes the current time as
    /// parameter."
    fn setCookies(&self, u: &URL, cookies: slice<Cookie>, now: time::Time) {
        if crate::builtin::len(&cookies) == 0 {
            return;
        }
        if u.Scheme != string::from_static("http") && u.Scheme != string::from_static("https") {
            return;
        }
        let (host, err) = canonicalHost(u.Host.clone());
        if !err.IsNil() {
            return;
        }
        let key = jarKey(&host, self.psList.clone());
        let defPath = defaultPath(&u.Path);

        let mut s = self.state.Lock();

        // Go takes `submap := j.entries[key]`, a reference into the
        // map. Rust cannot hold that borrow while also bumping
        // `nextSeqNum`, so the submap is lifted out and put back below.
        let mut submap_taken: Option<BTreeMap<string, entry>> = s.entries.remove(&key);

        let mut modified = false;
        let n = crate::builtin::len(&cookies);
        let mut ci: int = 0;
        while ci < n {
            let cookie = &cookies[ci];
            ci += 1;
            let (mut e, remove, err) = self.newEntry(cookie, now, &defPath, &host);
            if !err.IsNil() {
                continue;
            }
            let id = e.id();
            if remove {
                if let Some(ref mut submap) = submap_taken {
                    if submap.contains_key(&id) {
                        submap.remove(&id);
                        modified = true;
                    }
                }
                continue;
            }
            if submap_taken.is_none() {
                submap_taken = Some(BTreeMap::new());
            }
            let submap = submap_taken.as_mut().unwrap();
            if let Some(old) = submap.get(&id) {
                e.Creation = old.Creation;
                e.seqNum = old.seqNum;
            } else {
                e.Creation = now;
                e.seqNum = s.nextSeqNum;
                s.nextSeqNum = s.nextSeqNum.wrapping_add(1);
            }
            e.LastAccess = now;
            submap.insert(id, e);
            modified = true;
        }

        if modified {
            match submap_taken {
                Some(m) if m.is_empty() => {
                    s.entries.remove(&key);
                }
                Some(m) => {
                    s.entries.insert(key, m);
                }
                None => {}
            }
        } else if let Some(m) = submap_taken {
            // Nothing changed, so Go's map still holds it — put it back.
            s.entries.insert(key, m);
        }
    }
}

// ─── canonicalHost and friends ──────────────────────────────────────

// go: sdk 1.25.5 net/http/cookiejar/jar.go:301-317 canonicalHost
/// Go: "canonicalHost strips port from host if present and returns the
/// canonicalized host name."
fn canonicalHost(mut host: string) -> (string, error) {
    if hasPort(&host) {
        let (h, _, err) = crate::net::SplitHostPort(host.clone());
        if !err.IsNil() {
            return (string::new(), err);
        }
        host = h;
    }
    // Go: "Strip trailing dot from fully qualified domain names."
    host = strings::TrimSuffix(host, string::from_static("."));
    let (encoded, err) = punycode::toASCII(host);
    if !err.IsNil() {
        return (string::new(), err);
    }
    // Go: "We know this is ascii, no need to check."
    let (lower, _) = ascii::ToLower(encoded);
    return (lower, nil);
}

// go: sdk 1.25.5 net/http/cookiejar/jar.go:322-330 hasPort
/// Go: "hasPort reports whether host contains a port number. host may
/// be a host name, an IPv4 or an IPv6 address."
fn hasPort(host: &string) -> bool {
    let colons = strings::Count(host.clone(), string::from_static(":"));
    if colons == 0 {
        return false;
    }
    if colons == 1 {
        return true;
    }
    let hb = crate::gostring::__crate_as_bytes(host);
    // Go indexes host[0] unguarded; colons >= 2 already implies it is
    // non-empty, so the extra check cannot change the answer.
    return !hb.is_empty()
        && hb[0] == b'['
        && strings::Contains(host.clone(), string::from_static("]:"));
}

// go: sdk 1.25.5 net/http/cookiejar/jar.go:334-361 jarKey
/// Go: "jarKey returns the key to use for a jar."
fn jarKey(host: &string, psl: Option<Arc<dyn PublicSuffixList>>) -> string {
    if isIP(host) {
        return host.clone();
    }

    let hb = crate::gostring::__crate_as_bytes(host);
    let i: usize;
    match psl {
        None => {
            let li = strings::LastIndex(host.clone(), string::from_static("."));
            if li <= 0 {
                return host.clone();
            }
            i = crate::builtin::__make_size(li);
        }
        Some(p) => {
            let suffix = p.PublicSuffix(host.clone());
            if suffix == *host {
                return host.clone();
            }
            // Go: i = len(host) - len(suffix), then `i <= 0` catches
            // both an over-long suffix and an exact-length one.
            let sb_len = crate::builtin::__make_size(suffix.Len());
            if sb_len >= hb.len() {
                // The provided public suffix list psl is broken.
                // Storing cookies under host is a safe stopgap.
                return host.clone();
            }
            let ii = hb.len() - sb_len;
            if hb[ii - 1] != b'.' {
                return host.clone();
            }
            i = ii;
        }
    }
    let prev_slice = string::from_bytes(&hb[..i - 1]);
    let prev_dot = strings::LastIndex(prev_slice, string::from_static("."));
    let start = crate::builtin::__make_size(prev_dot + 1);
    return string::from_bytes(&hb[start..]);
}

// go: sdk 1.25.5 net/http/cookiejar/jar.go:365-374 isIP
/// Go: "isIP reports whether host is an IP address."
fn isIP(host: &string) -> bool {
    if strings::ContainsAny(host.clone(), string::from_static(":%")) {
        // Go: "Probable IPv6 address. Hostnames can't contain : or %,
        // so this is definitely not a valid host. Treating it as an IP
        // is the more conservative option, and avoids the risk of
        // interpreting ::1%.www.example.com as a subdomain of
        // www.example.com."
        return true;
    }
    return !crate::net::ParseIP(host.clone()).IsNil();
}

// go: sdk 1.25.5 net/http/cookiejar/jar.go:378-387 defaultPath
/// Go: "defaultPath returns the directory part of a URL's path
/// according to RFC 6265 section 5.1.4."
fn defaultPath(path: &string) -> string {
    let pb = crate::gostring::__crate_as_bytes(path);
    if pb.is_empty() || pb[0] != b'/' {
        // Path is empty or malformed.
        return string::from_static("/");
    }
    // Path starts with "/", so i != -1.
    let i = strings::LastIndex(path.clone(), string::from_static("/"));
    if i == 0 {
        // Path has the form "/abc".
        return string::from_static("/");
    }
    return string::from_bytes(&pb[..crate::builtin::__make_size(i)]);
}

// ─── newEntry / domainAndType ───────────────────────────────────────

impl Jar {
    // go: sdk 1.25.5 net/http/cookiejar/jar.go:399-446 Jar.newEntry
    /// Go: "newEntry creates an entry from an http.Cookie c. now is the
    /// current time and is compared to c.Expires to determine deletion
    /// of c. defPath and host are the default-path and the canonical
    /// host name of the URL c was received from. remove records whether
    /// the jar should delete this cookie, as it has already expired
    /// with respect to now."
    fn newEntry(
        &self,
        c: &Cookie,
        now: time::Time,
        defPath: &string,
        host: &string,
    ) -> (entry, bool, error) {
        let mut e = entry::default();
        e.Name = c.Name.clone();

        let cpath = crate::gostring::__crate_as_bytes(&c.Path);
        if cpath.is_empty() || cpath[0] != b'/' {
            e.Path = defPath.clone();
        } else {
            e.Path = c.Path.clone();
        }

        let (dom, hostOnly, err) = self.domainAndType(host, &c.Domain);
        if !err.IsNil() {
            return (e, false, err);
        }
        e.Domain = dom;
        e.HostOnly = hostOnly;

        // Go: "MaxAge takes precedence over Expires."
        if c.MaxAge < 0 {
            return (e, true, nil);
        } else if c.MaxAge > 0 {
            e.Expires = now.Add(time::Seconds(c.MaxAge));
            e.Persistent = true;
        } else {
            if c.Expires.IsZero() {
                e.Expires = endOfTime();
                e.Persistent = false;
            } else {
                if !c.Expires.After(now) {
                    return (e, true, nil);
                }
                e.Expires = c.Expires;
                e.Persistent = true;
            }
        }

        e.Value = c.Value.clone();
        e.Quoted = c.Quoted;
        e.Secure = c.Secure;
        e.HttpOnly = c.HttpOnly;

        match c.SameSite {
            SameSite::DefaultMode => {
                e.SameSite = string::from_static("SameSite");
            }
            SameSite::StrictMode => {
                e.SameSite = string::from_static("SameSite=Strict");
            }
            SameSite::LaxMode => {
                e.SameSite = string::from_static("SameSite=Lax");
            }
            _ => {}
        }

        return (e, false, nil);
    }

    // go: sdk 1.25.5 net/http/cookiejar/jar.go:460-545 Jar.domainAndType
    /// Go: "domainAndType determines the cookie's domain and hostOnly
    /// attribute."
    fn domainAndType(&self, host: &string, domain: &string) -> (string, bool, error) {
        if *domain == string::new() {
            // Go: "No domain attribute in the Set-Cookie header
            // indicates a host cookie."
            return (host.clone(), true, nil);
        }

        if isIP(host) {
            // Go: RFC 6265 says to strip an optional leading dot, which
            // makes no sense for an IP; the rest of §5.2.3 collapses to
            // this equality.
            if host != domain {
                return (string::new(), false, errIllegalDomain.into());
            }
            // Go: "Contemporary browsers (and curl) do allow such
            // cookies but treat them as host-only cookies. So do we."
            return (host.clone(), true, nil);
        }

        // Go: "From here on: If the cookie is valid, it is a domain
        // cookie (with the one exception of a public suffix below).
        // See RFC 6265 section 5.2.3."
        let domain = strings::TrimPrefix(domain.clone(), string::from_static("."));

        let db = crate::gostring::__crate_as_bytes(&domain);
        if db.is_empty() || db[0] == b'.' {
            // Received either "Domain=." or "Domain=..some.thing".
            return (string::new(), false, errMalformedDomain.into());
        }

        let (domain, isASCII) = ascii::ToLower(domain);
        if !isASCII {
            // Received non-ASCII domain, e.g. "perché.com" instead of
            // "xn--perch-fsa.com".
            return (string::new(), false, errMalformedDomain.into());
        }

        let db = crate::gostring::__crate_as_bytes(&domain);
        if db[db.len() - 1] == b'.' {
            // Received stuff like "Domain=www.example.com.".
            return (string::new(), false, errMalformedDomain.into());
        }

        // Go: "See RFC 6265 section 5.3 #5."
        if let Some(ref psl) = self.psList {
            let ps = psl.PublicSuffix(domain.clone());
            if ps != string::new() && !hasDotSuffix(&domain, &ps) {
                if *host == domain {
                    // Go: "This is the one exception in which a cookie
                    // with a domain attribute is a host cookie."
                    return (host.clone(), true, nil);
                }
                return (string::new(), false, errIllegalDomain.into());
            }
        }

        // Go: "The domain must domain-match host: www.mycompany.com
        // cannot set cookies for .ourcompetitors.com."
        if *host != domain && !hasDotSuffix(host, &domain) {
            return (string::new(), false, errIllegalDomain.into());
        }

        return (domain, false, nil);
    }
}

// ─── package vars ───────────────────────────────────────────────────

crate::var! {
    // go: sdk 1.25.5 net/http/cookiejar/jar.go:449-452 errIllegalDomain
    /// Go: `errors.New("cookiejar: illegal cookie domain attribute")`.
    ///
    /// A package-level `var`, so it is one pointer-stable value that
    /// `errors.Is` can match. Minting it per call — which is what a
    /// plain constructor function does, since goish errors compare by
    /// Arc identity — would make every such comparison quietly false.
    errIllegalDomain: error = "cookiejar: illegal cookie domain attribute";

    // go: sdk 1.25.5 net/http/cookiejar/jar.go:449-452 errMalformedDomain
    /// Go: `errors.New("cookiejar: malformed cookie domain attribute")`.
    errMalformedDomain: error = "cookiejar: malformed cookie domain attribute";
}

// go: sdk 1.25.5 net/http/cookiejar/jar.go:457-457 endOfTime
/// Go: "endOfTime is the time when session (non-persistent) cookies
/// expire. This instant is representable in most date/time formats (not
/// just Go's time.Time) and should be far enough in the future."
///
/// A `var` in Go, computed once at init; time::Date is pure, so
/// recomputing is the same value.
fn endOfTime() -> time::Time {
    return time::Date(9999, 12, 31, 23, 59, 59, 0, time::UTC);
}

// ─── http.CookieJar ─────────────────────────────────────────────────

// go: none — goish-only: Go's Jar satisfies http.CookieJar structurally
// by having the two methods; Rust needs the impl block spelled.
impl super::super::CookieJar for Jar {
    // go: none — goish-only: forwards to the inherent method.
    fn SetCookies(&self, u: &URL, cookies: slice<Cookie>) {
        return Jar::SetCookies(self, u, cookies);
    }
    // go: none — goish-only: forwards to the inherent method.
    fn Cookies(&self, u: &URL) -> slice<Cookie> {
        return Jar::Cookies(self, u);
    }
}
