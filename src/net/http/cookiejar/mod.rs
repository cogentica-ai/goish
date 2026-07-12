// net/http/cookiejar — in-memory RFC 6265-compliant http.CookieJar.
//
// Line-by-line port of:
//   /nix/store/60z37432vmgkg54krwr1z057bqwp7583-go-1.25.5/share/go/src/
//     net/http/cookiejar/jar.go
//     net/http/cookiejar/punycode.go (in punycode.rs)
//
// Slim deviations:
//   * `PublicSuffixList` is a Rust trait object (`Arc<dyn ...>`).
//   * The `entries` map uses `BTreeMap` rather than goish `map<K,V>`
//     because the value type itself is a `BTreeMap` and we never expose
//     it; private storage doesn't have to follow the goish-map rule.
//   * The Cookie field `Quoted` is preserved on round-trip; goish
//     `http::Cookie` already has it.

#![allow(non_snake_case)]

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::errors::{error, nil};
use crate::gostring::string;
use crate::strings;
use crate::sync::Mutex;
use crate::time;

use super::cookie::{Cookie, SameSite};
use super::internal::ascii;
use super::url::URL;

pub mod punycode;

// ─── PublicSuffixList trait (jar.go:36) ─────────────────────────────

/// `cookiejar.PublicSuffixList` (jar.go:36).
///
/// Implementations must be safe for concurrent use by multiple goroutines.
/// An implementation that always returns "" is valid for testing but
/// not secure (it lets foo.com set cookies for bar.com).
#[goish::interface]
pub trait PublicSuffixList: Send + Sync {
    /// Public suffix of `domain` (e.g. "co.uk" of "foo.co.uk").
    fn PublicSuffix(&self, domain: string) -> string;
    /// Description of this list (typically a version stamp).
    fn String(&self) -> string;
}

// ─── Options + Jar struct (jar.go:51, jar.go:62) ────────────────────

/// `cookiejar.Options` (jar.go:51).
#[derive(Clone, Default)]
pub struct Options {
    pub PublicSuffixList: Option<Arc<dyn PublicSuffixList>>,
}

/// `cookiejar.Jar` (jar.go:62) — implements [`super::CookieJar`].
pub struct Jar {
    psList: Option<Arc<dyn PublicSuffixList>>,
    state: Arc<Mutex<JarState>>,
}

struct JarState {
    // Go: entries map[string]map[string]entry, keyed by eTLD+1 then by
    // entry.id() (domain;path;name). Private; never exposed.
    entries: BTreeMap<string, BTreeMap<string, Entry>>,
    // Go: nextSeqNum uint64
    nextSeqNum: u64,
}

// ─── New (jar.go:79) ────────────────────────────────────────────────

/// `cookiejar.New(opts)` (jar.go:79). A nil `*Options` is equivalent to
/// a zero `Options`.
pub fn New(o: Option<&Options>) -> (Arc<Jar>, error) {
    // Go: jar := &Jar{ entries: make(map[...]map[...]entry) }
    let mut jar = Jar {
        psList: None,
        state: Arc::new(Mutex::new(JarState {
            entries: BTreeMap::new(),
            nextSeqNum: 0,
        })),
    };
    // Go: if o != nil { jar.psList = o.PublicSuffixList }
    if let Some(opts) = o {
        jar.psList = opts.PublicSuffixList.clone();
    }
    (Arc::new(jar), nil)
}

// ─── entry (jar.go:93) ──────────────────────────────────────────────

#[derive(Clone, Default)]
struct Entry {
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
    seqNum: u64,
}

impl Entry {
    // Go: jar.go:115 — id returns the domain;path;name triple.
    fn id(&self) -> string {
        // Go: fmt.Sprintf("%s;%s;%s", e.Domain, e.Path, e.Name)
        let mut out = alloc::string::String::with_capacity(
            self.Domain.Len() as usize + self.Path.Len() as usize + self.Name.Len() as usize + 2,
        );
        out.push_str(go_str(&self.Domain));
        out.push(';');
        out.push_str(go_str(&self.Path));
        out.push(';');
        out.push_str(go_str(&self.Name));
        string::from_bytes(out.as_bytes())
    }

    // Go: jar.go:122 — shouldSend(https, host, path).
    fn shouldSend(&self, https: bool, host: &string, path: &string) -> bool {
        self.domainMatch(host) && self.pathMatch(path) && (https || !self.Secure)
    }

    // Go: jar.go:129 — domainMatch (treats IP-literal Domain always as
    // host cookie).
    fn domainMatch(&self, host: &string) -> bool {
        if self.Domain == *host {
            return true;
        }
        !self.HostOnly && hasDotSuffix(host, &self.Domain)
    }

    // Go: jar.go:137 — pathMatch (RFC 6265 §5.1.4).
    fn pathMatch(&self, requestPath: &string) -> bool {
        if *requestPath == self.Path {
            return true;
        }
        if strings::HasPrefix(requestPath.clone(), self.Path.clone()) {
            let pb = crate::gostring::__crate_as_bytes(&self.Path);
            let rb = crate::gostring::__crate_as_bytes(requestPath);
            // Go: e.Path[len(e.Path)-1] == '/'
            if pb.last() == Some(&b'/') {
                return true;
            }
            // Go: requestPath[len(e.Path)] == '/'
            if rb.get(pb.len()) == Some(&b'/') {
                return true;
            }
        }
        false
    }
}

// Go: jar.go:151 — hasDotSuffix reports whether s ends in "."+suffix.
fn hasDotSuffix(s: &string, suffix: &string) -> bool {
    let sb = crate::gostring::__crate_as_bytes(s);
    let xb = crate::gostring::__crate_as_bytes(suffix);
    if sb.len() <= xb.len() {
        return false;
    }
    // Go: s[len(s)-len(suffix)-1] == '.' && s[len(s)-len(suffix):] == suffix
    let split = sb.len() - xb.len();
    sb[split - 1] == b'.' && &sb[split..] == xb
}

// ─── Cookies / cookies (jar.go:159) ─────────────────────────────────

impl Jar {
    /// `(j *Jar).Cookies(u)` (jar.go:159) — RFC 6265 §5.4 retrieval.
    pub fn Cookies(&self, u: &URL) -> Vec<Cookie> {
        self.cookies(u, time::Now())
    }

    // Go: jar.go:164
    fn cookies(&self, u: &URL, now: time::Time) -> Vec<Cookie> {
        let cookies: Vec<Cookie> = Vec::new();
        // Go: if u.Scheme != "http" && u.Scheme != "https"
        if u.Scheme != string::from_static("http") && u.Scheme != string::from_static("https") {
            return cookies;
        }
        // Go: host, err := canonicalHost(u.Host)
        let (host, err) = canonicalHost(u.Host.clone());
        if !err.IsNil() {
            return cookies;
        }
        // Go: key := jarKey(host, j.psList)
        let key = jarKey(&host, self.psList.clone());

        // Go: j.mu.Lock(); defer j.mu.Unlock()
        let mut s = self.state.Lock();

        // Go: submap := j.entries[key]; if submap == nil { return cookies }
        let submap_present = s.entries.contains_key(&key);
        if !submap_present {
            return cookies;
        }

        // Go: https := u.Scheme == "https"
        let https = u.Scheme == string::from_static("https");
        // Go: path := u.Path; if path == "" { path = "/" }
        let mut path = u.Path.clone();
        if path == string::new() {
            path = string::from_static("/");
        }

        let mut modified = false;
        // Go: var selected []entry
        let mut selected: Vec<Entry> = Vec::new();

        // Iterate, collecting drops + selections without holding a
        // borrow that conflicts with insertion.
        let mut drop_ids: Vec<string> = Vec::new();
        let mut update_pairs: Vec<(string, Entry)> = Vec::new();
        {
            let submap = s.entries.get(&key).unwrap();
            // Go: for id, e := range submap
            for (id, e) in submap.iter() {
                // Go: if e.Persistent && !e.Expires.After(now)
                if e.Persistent && !e.Expires.After(now) {
                    drop_ids.push(id.clone());
                    modified = true;
                    continue;
                }
                // Go: if !e.shouldSend(https, host, path) { continue }
                if !e.shouldSend(https, &host, &path) {
                    continue;
                }
                // Go: e.LastAccess = now; submap[id] = e
                let mut updated = e.clone();
                updated.LastAccess = now;
                update_pairs.push((id.clone(), updated.clone()));
                selected.push(updated);
                modified = true;
            }
        }

        // Apply mutations.
        {
            let submap = s.entries.get_mut(&key).unwrap();
            for id in drop_ids.iter() {
                submap.remove(id);
            }
            for (id, e) in update_pairs.into_iter() {
                submap.insert(id, e);
            }
        }

        if modified {
            // Go: if len(submap) == 0 { delete(j.entries, key) }
            let empty = s.entries.get(&key).map(|m| m.is_empty()).unwrap_or(false);
            if empty {
                s.entries.remove(&key);
            }
        }

        // Go: jar.go:214 — slices.SortFunc(selected, ...).
        selected.sort_by(|a, b| {
            // Go: if r := cmp.Compare(b.Path, a.Path); r != 0 { return r }
            match b.Path.cmp(&a.Path) {
                core::cmp::Ordering::Equal => {}
                ord => return ord,
            }
            // Go: if r := a.Creation.Compare(b.Creation); r != 0 { return r }
            match a.Creation.Compare(b.Creation) {
                0 => {}
                n if n < 0 => return core::cmp::Ordering::Less,
                _ => return core::cmp::Ordering::Greater,
            }
            // Go: return cmp.Compare(a.seqNum, b.seqNum)
            a.seqNum.cmp(&b.seqNum)
        });

        // Go: for _, e := range selected { cookies = append(cookies, &http.Cookie{...}) }
        let mut out: Vec<Cookie> = Vec::with_capacity(selected.len());
        for e in selected.into_iter() {
            let mut c = Cookie::default();
            c.Name = e.Name;
            c.Value = e.Value;
            c.Quoted = e.Quoted;
            out.push(c);
        }
        out
    }

    // ─── SetCookies / setCookies (jar.go:233) ────────────────────────

    /// `(j *Jar).SetCookies(u, cookies)` (jar.go:233).
    pub fn SetCookies(&self, u: &URL, cookies: &[Cookie]) {
        self.setCookies(u, cookies, time::Now())
    }

    // Go: jar.go:238
    fn setCookies(&self, u: &URL, cookies: &[Cookie], now: time::Time) {
        // Go: if len(cookies) == 0 { return }
        if cookies.is_empty() {
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

        // Go: submap := j.entries[key]
        let mut submap_taken: Option<BTreeMap<string, Entry>> = s.entries.remove(&key);

        let mut modified = false;
        for cookie in cookies.iter() {
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
            // No modification: put it back unchanged.
            s.entries.insert(key, m);
        }
    }
}

// ─── canonicalHost (jar.go:301) ─────────────────────────────────────

/// `cookiejar.canonicalHost` (jar.go:301).
fn canonicalHost(mut host: string) -> (string, error) {
    // Go: if hasPort(host) { host, _, err = net.SplitHostPort(host) }
    if hasPort(&host) {
        let (h, _, err) = crate::net::SplitHostPort(host.clone());
        if !err.IsNil() {
            return (string::new(), err);
        }
        host = h;
    }
    // Go: host = strings.TrimSuffix(host, ".")
    host = strings::TrimSuffix(host, string::from_static("."));
    // Go: encoded, err := toASCII(host)
    let (encoded, err) = punycode::toASCII(host);
    if !err.IsNil() {
        return (string::new(), err);
    }
    // Go: lower, _ := ascii.ToLower(encoded)
    let (lower, _) = ascii::ToLower(encoded);
    (lower, nil)
}

// Go: jar.go:322 — hasPort.
fn hasPort(host: &string) -> bool {
    let colons = strings::Count(host.clone(), string::from_static(":"));
    if colons == 0 {
        return false;
    }
    if colons == 1 {
        return true;
    }
    let hb = crate::gostring::__crate_as_bytes(host);
    !hb.is_empty()
        && hb[0] == b'['
        && strings::Contains(host.clone(), string::from_static("]:"))
}

// Go: jar.go:334 — jarKey.
fn jarKey(host: &string, psl: Option<Arc<dyn PublicSuffixList>>) -> string {
    if isIP(host) {
        return host.clone();
    }
    let hb = crate::gostring::__crate_as_bytes(host);
    let i: usize;
    if let Some(p) = psl {
        let suffix = p.PublicSuffix(host.clone());
        if suffix == *host {
            return host.clone();
        }
        // Go: i = len(host) - len(suffix); if i <= 0 || host[i-1] != '.' { return host }
        let sb_len = suffix.Len() as usize;
        if sb_len >= hb.len() {
            return host.clone();
        }
        let ii = hb.len() - sb_len;
        if ii == 0 || hb[ii - 1] != b'.' {
            return host.clone();
        }
        i = ii;
    } else {
        // Go: i = strings.LastIndex(host, "."); if i <= 0 { return host }
        let li = strings::LastIndex(host.clone(), string::from_static("."));
        if li <= 0 {
            return host.clone();
        }
        i = li as usize;
    }
    // Go: prevDot := strings.LastIndex(host[:i-1], ".")
    let prev_slice = string::from_bytes(&hb[..i - 1]);
    let prev_dot = strings::LastIndex(prev_slice, string::from_static("."));
    // Go: return host[prevDot+1:]
    let start = (prev_dot + 1) as usize;
    string::from_bytes(&hb[start..])
}

// Go: jar.go:365 — isIP.
fn isIP(host: &string) -> bool {
    if strings::ContainsAny(host.clone(), string::from_static(":%")) {
        return true;
    }
    !crate::net::ParseIP(host.clone()).IsNil()
}

// Go: jar.go:378 — defaultPath.
fn defaultPath(path: &string) -> string {
    let pb = crate::gostring::__crate_as_bytes(path);
    if pb.is_empty() || pb[0] != b'/' {
        return string::from_static("/");
    }
    let i = strings::LastIndex(path.clone(), string::from_static("/"));
    if i == 0 {
        return string::from_static("/");
    }
    string::from_bytes(&pb[..i as usize])
}

// ─── newEntry / domainAndType (jar.go:399, jar.go:460) ──────────────

impl Jar {
    // Go: jar.go:399
    fn newEntry(
        &self,
        c: &Cookie,
        now: time::Time,
        defPath: &string,
        host: &string,
    ) -> (Entry, bool, error) {
        let mut e = Entry::default();
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

        // Go: MaxAge takes precedence over Expires.
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

        // Go: switch c.SameSite { ... }
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

        (e, false, nil)
    }

    // Go: jar.go:460
    fn domainAndType(&self, host: &string, domain: &string) -> (string, bool, error) {
        if domain == &string::new() {
            return (host.clone(), true, nil);
        }

        if isIP(host) {
            // Go: if host != domain { return "", false, errIllegalDomain }
            if host != domain {
                return (string::new(), false, errIllegalDomain());
            }
            return (host.clone(), true, nil);
        }

        // Go: domain = strings.TrimPrefix(domain, ".")
        let domain = strings::TrimPrefix(domain.clone(), string::from_static("."));

        let db = crate::gostring::__crate_as_bytes(&domain);
        if db.is_empty() || db[0] == b'.' {
            return (string::new(), false, errMalformedDomain());
        }

        let (domain, isASCII) = ascii::ToLower(domain);
        if !isASCII {
            return (string::new(), false, errMalformedDomain());
        }

        let db = crate::gostring::__crate_as_bytes(&domain);
        if db[db.len() - 1] == b'.' {
            return (string::new(), false, errMalformedDomain());
        }

        // Go: if j.psList != nil { ... }
        if let Some(ref psl) = self.psList {
            let ps = psl.PublicSuffix(domain.clone());
            if ps != string::new() && !hasDotSuffix(&domain, &ps) {
                if host == &domain {
                    return (host.clone(), true, nil);
                }
                return (string::new(), false, errIllegalDomain());
            }
        }

        // Go: if host != domain && !hasDotSuffix(host, domain) { return "", false, errIllegalDomain }
        if host != &domain && !hasDotSuffix(host, &domain) {
            return (string::new(), false, errIllegalDomain());
        }

        (domain, false, nil)
    }
}

// ─── Errors (jar.go:449) + endOfTime (jar.go:457) ───────────────────

fn errIllegalDomain() -> error {
    crate::errors::New(string::from_static(
        "cookiejar: illegal cookie domain attribute",
    ))
}

fn errMalformedDomain() -> error {
    crate::errors::New(string::from_static(
        "cookiejar: malformed cookie domain attribute",
    ))
}

// Go: var endOfTime = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
fn endOfTime() -> time::Time {
    time::Date(9999, 12, 31, 23, 59, 59, 0, time::UTC)
}

// ─── String helper (avoids extra alloc for fmt.Sprintf) ──────────────

#[inline]
fn go_str(s: &string) -> &str {
    let b = crate::gostring::__crate_as_bytes(s);
    // Strings in goish hold raw bytes — but cookie names/paths/domains
    // are ASCII in practice. Treat any non-UTF-8 as best-effort
    // (Sprintf %q quotes; we use %s here).
    core::str::from_utf8(b).unwrap_or("")
}

