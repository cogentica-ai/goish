// net/http/url — slim port of Go's net/url URL type.
//
// Mirrors `runtime/url.URL` (Go 1.25 src/net/url/url.go:375) for the
// subset HTTP servers actually need:
//
//   pub struct URL {
//       pub Scheme:   string,
//       pub Host:     string,
//       pub Path:     string,   // /index.html
//       pub RawPath:  string,
//       pub RawQuery: string,
//   }
//
// `parse_request_uri` accepts only the request-target form (origin
// or absolute-URI). It does not perform full RFC 3986 parsing.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::vec::Vec;

use crate::string;

/// `net/url.URL` — slim. Only fields HTTP routing typically reads.
#[derive(Clone, Default)]
pub struct URL {
    pub Scheme: string,
    pub Host: string,
    /// Decoded path. For now we don't percent-decode — `Path` and
    /// `RawPath` carry the same bytes. Sufficient for common APIs.
    pub Path: string,
    pub RawPath: string,
    pub RawQuery: string,
    /// `#fragment` — decoded; URL.String() will percent-encode if set.
    pub Fragment: string,
    /// Encoded fragment hint (used by `EscapedFragment`).
    pub RawFragment: string,
}

impl URL {
    pub(crate) fn empty() -> Self {
        URL {
            Scheme: string::new(),
            Host: string::new(),
            Path: string::new(),
            RawPath: string::new(),
            RawQuery: string::new(),
            Fragment: string::new(),
            RawFragment: string::new(),
        }
    }

    /// `(u *URL).EscapedFragment()` (url.go:807) — fragment in the
    /// form needed for URL.String(). Slim port: returns RawFragment if
    /// non-empty, else Fragment.
    pub fn EscapedFragment(&self) -> string {
        if self.RawFragment.Len() != 0 {
            self.RawFragment.clone()
        } else {
            self.Fragment.clone()
        }
    }

    /// `(u *URL).EscapedPath()` (url.go:744) — return the escaped form
    /// of u.Path. Returns RawPath if it is a valid escaping of Path;
    /// otherwise computes a fresh escape via the encodePath mode.
    /// Special-cases `*` (Issue 11202) which is left unescaped.
    pub fn EscapedPath(&self) -> string {
        // Go: if u.RawPath != "" && validEncoded(u.RawPath, encodePath) {
        if self.RawPath.Len() != 0 && valid_encoded(self.RawPath.clone(), EncodingMode::Path) {
            // Go: p, err := unescape(u.RawPath, encodePath)
            //     if err == nil && p == u.Path { return u.RawPath }
            let (p, err) = unescape(self.RawPath.clone(), false);
            if err.IsNil() && p == self.Path {
                return self.RawPath.clone();
            }
        }
        // Go: if u.Path == "*" { return "*" }
        if self.Path == string("*") {
            return string("*");
        }
        // Go: return escape(u.Path, encodePath)
        escape(self.Path.clone(), EncodingMode::Path)
    }

    /// `(u *URL).ResolveReference(ref)` (url.go:1137) — resolve a URI
    /// reference to an absolute URI from absolute base URI `self`, per
    /// RFC 3986 §5.2. Always returns a new URL.
    ///
    /// Slim deviation: goish URL has no `User`, `Opaque`, or
    /// `ForceQuery` fields, so the corresponding Go branches are
    /// dropped — only `Scheme`, `Host`, `Path`, `RawQuery`, `Fragment`
    /// participate in the merge.
    pub fn ResolveReference(&self, reference: &URL) -> URL {
        // Go: url := *ref
        let mut url: URL = reference.clone();
        // Go: if ref.Scheme == "" { url.Scheme = u.Scheme }
        if reference.Scheme.Len() == 0 {
            url.Scheme = self.Scheme.clone();
        }
        // Go: if ref.Scheme != "" || ref.Host != "" || ref.User != nil { ... }
        // Slim: User dropped — only Scheme / Host trigger absolute-URI branch.
        if reference.Scheme.Len() != 0 || reference.Host.Len() != 0 {
            // Go: url.setPath(resolvePath(ref.EscapedPath(), ""))
            let p = ResolvePath(reference.EscapedPath(), string::new());
            url.Path = p.clone();
            url.RawPath = p;
            return url;
        }
        // Go: if ref.Opaque != "" { ... } — slim has no Opaque, skip.
        // Go: if ref.Path == "" && !ref.ForceQuery && ref.RawQuery == "" {
        // Slim: ForceQuery dropped.
        if reference.Path.Len() == 0 && reference.RawQuery.Len() == 0 {
            url.RawQuery = self.RawQuery.clone();
            // Go: if ref.Fragment == "" { url.Fragment = u.Fragment; url.RawFragment = u.RawFragment }
            if reference.Fragment.Len() == 0 {
                url.Fragment = self.Fragment.clone();
                url.RawFragment = self.RawFragment.clone();
            }
        }
        // Go: if ref.Path == "" && u.Opaque != "" — skip (no Opaque).
        // Go: url.Host = u.Host; url.User = u.User
        url.Host = self.Host.clone();
        // Go: url.setPath(resolvePath(u.EscapedPath(), ref.EscapedPath()))
        let p = ResolvePath(self.EscapedPath(), reference.EscapedPath());
        url.Path = p.clone();
        url.RawPath = p;
        url
    }

    /// `(u *URL).IsAbs()` (url.go:1116) — reports whether the URL is
    /// absolute. Absolute URLs always have a non-empty Scheme.
    pub fn IsAbs(&self) -> bool {
        // Go: return u.Scheme != ""
        self.Scheme.Len() != 0
    }

    /// `(u *URL).RequestURI()` (url.go:1186) — return the encoded
    /// path?query string used in an HTTP request line. Slim port:
    /// goish's URL has no Opaque or ForceQuery, so the choice is just
    /// RawPath (preferred when set) ?: Path, plus an optional
    /// `?<RawQuery>` suffix. An empty path is rendered as "/".
    pub fn RequestURI(&self) -> string {
        // Go: result := u.Opaque; if result == "" { result := u.EscapedPath(); if result == "" { result = "/" } }
        let mut result: string = if self.RawPath.Len() != 0 {
            self.RawPath.clone()
        } else if self.Path.Len() != 0 {
            self.Path.clone()
        } else {
            string("/")
        };
        // Go: if u.ForceQuery || u.RawQuery != "" { result += "?" + u.RawQuery }
        if self.RawQuery.Len() != 0 {
            let mut b = crate::strings::Builder::new();
            b.Grow(result.Len() + 1 + self.RawQuery.Len());
            let _ = b.WriteString(result.clone());
            let _ = b.WriteByte(b'?');
            let _ = b.WriteString(self.RawQuery.clone());
            result = b.String();
        }
        result
    }

    /// `(u *URL).Hostname()` (url.go:1208) — return u.Host with the
    /// optional `:port` suffix removed. IPv6 brackets are stripped.
    pub fn Hostname(&self) -> string {
        let (host, _) = split_host_port(self.Host.clone());
        host
    }

    /// `(u *URL).Port()` (url.go:1216) — return the numeric port from
    /// u.Host (without the leading colon), or "" if absent or invalid.
    pub fn Port(&self) -> string {
        let (_, port) = split_host_port(self.Host.clone());
        port
    }

    /// `(u *URL).Query()` (url.go:1179) — parse RawQuery and return
    /// the resulting map. Malformed pairs are silently dropped (use
    /// `ParseQuery` directly to surface errors).
    pub fn Query(&self) -> crate::gomap::map<string, crate::goslice::slice<string>> {
        let (v, _) = ParseQuery(self.RawQuery.clone());
        v
    }

    /// `(u *URL).JoinPath(elem ...string) *URL` (url.go:1262) — return
    /// a copy of `u` with `elem` appended to its path. Slim port:
    /// uses goish's `path::Join` for the heavy lifting, preserves a
    /// trailing slash if the last element ended with one.
    pub fn JoinPath(&self, elem: slice<string>) -> URL {
        // Go: elem = append([]string{u.EscapedPath()}, elem...)
        // Slim URL has no Opaque/encoded path: Path is already the
        // canonical decoded form.
        let mut all: slice<string> = slice::__from_vec(alloc::vec::Vec::new());
        all = crate::append!(all, self.Path.clone());
        let mut i: int = 0;
        while i < elem.Len() {
            all = crate::append!(all, elem[i].clone());
            i += 1;
        }
        // Go: if !strings.HasPrefix(elem[0], "/") { elem[0] = "/" + elem[0]; p = path.Join(elem...)[1:] } else { p = path.Join(elem...) }
        let p = if !crate::strings::HasPrefix(all[0].clone(), string("/")) {
            // Prefix the first segment with "/" then trim the leading
            // slash from the result.
            let mut prefixed = crate::strings::Builder::new();
            prefixed.Grow(1 + all[0].Len());
            let _ = prefixed.WriteByte(b'/');
            let _ = prefixed.WriteString(all[0].clone());
            all[0] = prefixed.String();
            let joined = crate::path::Join(all.clone());
            // Go: p = path.Join(elem...)[1:]
            string::from_bytes(&joined.as_bytes()[1..])
        } else {
            crate::path::Join(all.clone())
        };

        // Go: if strings.HasSuffix(elem[len(elem)-1], "/") && !strings.HasSuffix(p, "/") { p += "/" }
        let last = all[all.Len() - 1].clone();
        let mut p = p;
        if crate::strings::HasSuffix(last, string("/"))
            && !crate::strings::HasSuffix(p.clone(), string("/"))
        {
            let mut b = crate::strings::Builder::new();
            b.Grow(p.Len() + 1);
            let _ = b.WriteString(p.clone());
            let _ = b.WriteByte(b'/');
            p = b.String();
        }

        // Go: url := *u; url.setPath(p); return &url
        let mut out = self.clone();
        out.Path = p.clone();
        out.RawPath = p;
        out
    }

    /// Render as the request-target string. For URLs parsed from a
    /// request-target this is the inverse of `parse_request_uri`.
    pub fn String(&self) -> string {
        let mut out: Vec<u8> = Vec::with_capacity(64);
        if !self.Scheme.as_bytes().is_empty() {
            out.extend_from_slice(self.Scheme.as_bytes());
            out.extend_from_slice(b"://");
            out.extend_from_slice(self.Host.as_bytes());
        }
        out.extend_from_slice(self.Path.as_bytes());
        if !self.RawQuery.as_bytes().is_empty() {
            out.push(b'?');
            out.extend_from_slice(self.RawQuery.as_bytes());
        }
        // Go: if u.Fragment != "" { buf.WriteByte('#'); buf.WriteString(u.EscapedFragment()) }
        if self.Fragment.Len() != 0 || self.RawFragment.Len() != 0 {
            out.push(b'#');
            out.extend_from_slice(self.EscapedFragment().as_bytes());
        }
        string::from_bytes(&out)
    }

    /// `(u *URL).Redacted()` (url.go:926) — like `String()` but
    /// replaces any password in the userinfo with `xxxxx`.
    ///
    /// Slim deviation: the goish URL struct has no `User` field, so
    /// no userinfo can appear in the output. Redacted is therefore
    /// equivalent to String() until a User field is added.
    pub fn Redacted(&self) -> string {
        self.String()
    }

    /// `(u *URL).MarshalBinary()` (url.go:1242) — serialize as bytes.
    pub fn MarshalBinary(&self) -> (crate::goslice::slice<crate::types::byte>, error) {
        // return u.AppendBinary(nil)
        self.AppendBinary(crate::goslice::slice::__from_vec(
            crate::__macro_alloc::Vec::<crate::types::byte>::new(),
        ))
    }

    /// `(u *URL).AppendBinary(b)` (url.go:1246) — append the
    /// String() form to b.
    pub fn AppendBinary(
        &self,
        b: crate::goslice::slice<crate::types::byte>,
    ) -> (crate::goslice::slice<crate::types::byte>, error) {
        // return append(b, u.String()...), nil
        let mut v = b.__into_vec();
        v.extend_from_slice(self.String().as_bytes());
        (crate::goslice::slice::__from_vec(v), crate::nil)
    }

    /// `(u *URL).UnmarshalBinary(text)` (url.go:1250) — parse bytes
    /// into self in place. Returns any parse error.
    pub fn UnmarshalBinary(
        &mut self,
        text: crate::goslice::slice<crate::types::byte>,
    ) -> error {
        // u1, err := Parse(string(text))
        let s = string::from_bytes(&text);
        let (u1, err) = Parse(s);
        if !err.IsNil() {
            return err;
        }
        // *u = *u1
        *self = u1;
        crate::nil
    }
}

/// `url.ParseRequestURI` — parse a request-target.
///
/// Accepts:
///   - Origin form:  `/path?query`
///   - Absolute form: `http://host/path?query`
///   - Asterisk form: `*` (kept as Path = "*")
///   - Authority form (CONNECT): caller pre-prefixes "http://"
///
/// Does not validate UTF-8, percent-encoding, or character class.
/// HTTP routing only cares about Path / RawQuery in 99% of cases.
pub(crate) fn parse_request_uri(raw: &string) -> Result<URL, string> {
    let bytes = raw.as_bytes();
    if bytes.is_empty() {
        return Err(string("net/http: empty request-target"));
    }

    // Asterisk form (used for OPTIONS *).
    if bytes == b"*" {
        return Ok(URL {
            Scheme: string::new(),
            Host: string::new(),
            Path: string("*"),
            RawPath: string("*"),
            RawQuery: string::new(),
            Fragment: string::new(),
            RawFragment: string::new(),
        });
    }

    let (scheme, host, rest) = if let Some(idx) = find_subseq(bytes, b"://") {
        // Absolute-URI form: scheme://host/path?query
        let scheme_b = &bytes[..idx];
        let after = &bytes[idx + 3..];
        // host runs to the first '/' or '?', or end.
        let host_end = after
            .iter()
            .position(|&b| b == b'/' || b == b'?')
            .unwrap_or(after.len());
        let host_b = &after[..host_end];
        let rest = &after[host_end..];
        (scheme_b, host_b, rest)
    } else if bytes[0] == b'/' {
        // Origin form: /path?query
        (&bytes[..0], &bytes[..0], bytes)
    } else {
        // Bare authority (CONNECT) — caller wraps in "http://" first.
        // If we land here it's malformed.
        return Err(string("net/http: malformed request-target"));
    };

    // Split rest on first '?' into path / query.
    let (path, query) = match rest.iter().position(|&b| b == b'?') {
        Some(q) => (&rest[..q], &rest[q + 1..]),
        None => (rest, &rest[..0]),
    };

    let path_str = if path.is_empty() {
        if !host.is_empty() {
            string("/")
        } else {
            string::new()
        }
    } else {
        string::from_bytes(path)
    };

    Ok(URL {
        Scheme: string::from_bytes(scheme),
        Host: string::from_bytes(host),
        Path: path_str.clone(),
        RawPath: path_str,
        RawQuery: string::from_bytes(query),
        Fragment: string::new(),
        RawFragment: string::new(),
    })
}

/// Find the first index of `needle` in `hay`, or `None`.
fn find_subseq(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    'outer: for i in 0..=(hay.len() - needle.len()) {
        for j in 0..needle.len() {
            if hay[i + j] != needle[j] {
                continue 'outer;
            }
        }
        return Some(i);
    }
    None
}

// ─── ParseQuery / QueryUnescape ──────────────────────────────────────
//
// Line-by-line ports of Go 1.25 src/net/url/url.go's ParseQuery (line 879)
// and QueryUnescape (line 277). Slim — strict mode only (Go's default
// since 1.16; no semicolon separator support, errors propagate).

use crate::errors::{self, error};
use crate::gomap::map;
use crate::goslice::slice;
use crate::strings;
use crate::types::{byte, int};

/// `url.ParseQuery(query)` — parse "k1=v1&k2=v2" into Values
/// (`map<string, slice<string>>`). Mirrors url.go:879.
///
/// Reports an error for malformed escape sequences but still returns
/// whatever Values it could parse (matching Go).
pub fn ParseQuery(query: string) -> (map<string, slice<string>>, error) {
    let mut m: map<string, slice<string>> = map::<string, slice<string>>::new();
    let err = parse_query(&mut m, query);
    (m, err)
}

fn parse_query(m: &mut map<string, slice<string>>, mut query: string) -> error {
    // Go: var err error
    let mut err: error = errors::nil;
    // Go: for query != "" { … }
    while query.Len() > 0 {
        // Go: var key string
        // Go: key, query, _ = strings.Cut(query, "&")
        let (key, rest, _) = strings::Cut(query, string("&"));
        query = rest;
        // Go: if strings.Contains(key, ";") { err = fmt.Errorf(...); continue }
        if strings::Contains(key.clone(), string(";")) {
            if err.IsNil() {
                err = errors::New(string("invalid semicolon separator in query"));
            }
            continue;
        }
        // Go: if key == "" { continue }
        if key.Len() == 0 {
            continue;
        }
        // Go: key, value, _ := strings.Cut(key, "=")
        let (raw_k, raw_v, _) = strings::Cut(key, string("="));
        // Go: key, err1 := QueryUnescape(key); if err1 != nil { … continue }
        let (uk, e1) = QueryUnescape(raw_k);
        if !e1.IsNil() {
            if err.IsNil() {
                err = e1;
            }
            continue;
        }
        let (uv, e2) = QueryUnescape(raw_v);
        if !e2.IsNil() {
            if err.IsNil() {
                err = e2;
            }
            continue;
        }
        // Go: m[key] = append(m[key], value)
        let (existing, _) = m.Get(uk.clone());
        let updated = crate::append!(existing, uv);
        m.Set(uk, updated);
    }
    err
}

// ─── Userinfo (slim port of url.go:411) ──────────────────────────────

/// `url.Userinfo` — immutable username + optional password.
/// `passwordSet` distinguishes "no password" from "empty password".
#[derive(Clone)]
pub struct Userinfo {
    username: string,
    password: string,
    password_set: bool,
}

/// `url.User(username)` (url.go:391) — Userinfo with no password set.
pub fn User(username: string) -> Userinfo {
    Userinfo {
        username,
        password: string::new(),
        password_set: false,
    }
}

/// `url.UserPassword(user, pass)` (url.go:403) — Userinfo with both
/// username and password.
pub fn UserPassword(username: string, password: string) -> Userinfo {
    Userinfo {
        username,
        password,
        password_set: true,
    }
}

impl Userinfo {
    /// `(*Userinfo).Username()` (url.go:418).
    pub fn Username(&self) -> string {
        self.username.clone()
    }

    /// `(*Userinfo).Password()` (url.go:426) — `(value, isSet)`.
    pub fn Password(&self) -> (string, bool) {
        (self.password.clone(), self.password_set)
    }

    /// `(*Userinfo).String()` (url.go:435) — "user[:pass]". Slim port:
    /// uses PathEscape mode rather than encodeUserPassword.
    pub fn String(&self) -> string {
        if self.password_set {
            let mut b = crate::strings::Builder::new();
            let _ = b.WriteString(PathEscape(self.username.clone()));
            let _ = b.WriteByte(b':');
            let _ = b.WriteString(PathEscape(self.password.clone()));
            b.String()
        } else {
            PathEscape(self.username.clone())
        }
    }
}

/// `url.QueryUnescape(s)` — invert query-string percent-encoding.
/// Slim port of url.go:277 (strict mode).
pub fn QueryUnescape(s: string) -> (string, error) {
    unescape(s, true)
}

/// `url.PathUnescape(s)` — like QueryUnescape but does not turn `+`
/// into space. Mirrors url.go:303.
pub fn PathUnescape(s: string) -> (string, error) {
    unescape(s, false)
}

/// `url.resolvePath(base, ref)` (url.go:1050) — RFC 3986 §5.2.4 path
/// merging: combine a base URI's path and a reference's path,
/// resolving `.` and `..` segments. Returns the merged absolute-path.
///
/// Goish-internal scratch uses a `Vec<u8>` (rather than the consuming
/// strings.Builder) because the algorithm needs to read the buffer
/// contents while still appending — Go's strings.Builder allows that
/// via a non-consuming String(); goish v1's String() consumes.
pub fn ResolvePath(base: string, reference: string) -> string {
    // Go: var full string
    // Go: if ref == "" { full = base }
    // Go: else if ref[0] != '/' { i := strings.LastIndex(base, "/"); full = base[:i+1] + ref }
    // Go: else { full = ref }
    let full: string = if reference.Len() == 0 {
        base
    } else if reference.as_bytes()[0] != b'/' {
        let i = crate::strings::LastIndex(base.clone(), string("/"));
        let mut b = crate::strings::Builder::new();
        b.Grow((i + 1) + reference.Len());
        let _ = b.WriteString(string::from_bytes(&base.as_bytes()[..(i + 1) as usize]));
        let _ = b.WriteString(reference);
        b.String()
    } else {
        reference
    };
    // Go: if full == "" { return "" }
    if full.Len() == 0 {
        return string::new();
    }

    // Go: var elem string; var dst strings.Builder; first := true
    let mut elem: string = string::new();
    let mut dst: alloc::vec::Vec<byte> = alloc::vec::Vec::new();
    let mut first: bool = true;
    // Go: remaining := full
    let mut remaining: string = full;
    // Go: dst.WriteByte('/')
    dst.push(b'/');
    // Go: found := true; for found { elem, remaining, found = strings.Cut(remaining, "/"); ... }
    let mut found: bool = true;
    while found {
        let (e, r, f) = crate::strings::Cut(remaining.clone(), string("/"));
        elem = e;
        remaining = r;
        found = f;
        // Go: if elem == "." { first = false; continue }
        if elem == string(".") {
            first = false;
            continue;
        }
        // Go: if elem == ".." { ... }
        if elem == string("..") {
            // Go: str := dst.String()[1:]
            // Goish: snapshot dst[1:] into a fresh Vec so we can mutate
            // dst (Reset + write) below without aliasing.
            let str_bytes: alloc::vec::Vec<u8> = dst[1..].to_vec();
            // strings.LastIndexByte: -1 if not found.
            let mut index: int = -1;
            let mut k: int = (str_bytes.len() as int) - 1;
            while k >= 0 {
                if str_bytes[k as usize] == b'/' {
                    index = k;
                    break;
                }
                k -= 1;
            }
            // Go: dst.Reset(); dst.WriteByte('/')
            dst.clear();
            dst.push(b'/');
            // Go: if index == -1 { first = true } else { dst.WriteString(str[:index]) }
            if index == -1 {
                first = true;
            } else {
                dst.extend_from_slice(&str_bytes[..index as usize]);
            }
        } else {
            // Go: if !first { dst.WriteByte('/') }
            if !first {
                dst.push(b'/');
            }
            // Go: dst.WriteString(elem); first = false
            dst.extend_from_slice(elem.as_bytes());
            first = false;
        }
    }

    // Go: if elem == "." || elem == ".." { dst.WriteByte('/') }
    if elem == string(".") || elem == string("..") {
        dst.push(b'/');
    }

    // Go: r := dst.String(); if len(r) > 1 && r[1] == '/' { r = r[1:] }; return r
    if dst.len() > 1 && dst[1] == b'/' {
        // Drop the duplicate leading '/'.
        return string::from_bytes(&dst[1..]);
    }
    string::from_bytes(&dst)
}

/// `url.JoinPath(base, elem...)` (url.go:1338) — Parse `base`, append
/// `elem` to the path via `URL.JoinPath`, and return the rendered URL.
/// Returns `(result, error)` per goish convention.
pub fn JoinPath(
    base: string,
    elem: slice<string>,
) -> (string, error) {
    // Go: url, err := Parse(base); if err != nil { return }
    let (u, err) = Parse(base);
    if !err.IsNil() {
        return (string::new(), err);
    }
    // Go: result = url.JoinPath(elem...).String()
    (u.JoinPath(elem).String(), errors::nil)
}

/// `url.Parse(rawURL)` (url.go:479) — parse a URL in either absolute
/// or relative form. Slim port: handles `scheme://host/path?query#frag`,
/// `/path?query`, and `relative/path`, but doesn't model Opaque or
/// Userinfo as separate fields. Fragment IS captured into u.Fragment.
///
/// Returns `(URL, error)` per goish convention.
pub fn Parse(raw_url: string) -> (URL, error) {
    // Go: u, frag, _ := strings.Cut(rawURL, "#")
    let (u, frag, has_frag) = crate::strings::Cut(raw_url, string("#"));
    let (mut url, err) = parse(u, false);
    if !err.IsNil() {
        return (url, err);
    }
    if has_frag {
        url.Fragment = frag.clone();
        url.RawFragment = frag;
    }
    (url, errors::nil)
}

/// `url.ParseRequestURI(rawURL)` (url.go:500) — parse a URL received
/// in an HTTP request line: must be absolute-URI or absolute-path.
/// No fragment is permitted (browsers strip them client-side).
pub fn ParseRequestURI(raw_url: string) -> (URL, error) {
    parse(raw_url, true)
}

/// Line-by-line slim port of `parse` (url.go:512). Honors the
/// origin-form / absolute-URI distinction via `via_request` but
/// does not implement Opaque, host validation, IPv6 zones, or
/// %-decoding of host bytes.
fn parse(raw_url: string, via_request: bool) -> (URL, error) {
    // Go: if rawURL == "" && viaRequest { return nil, errors.New("empty url") }
    if raw_url.Len() == 0 && via_request {
        return (URL::empty(), errors::New(string("empty url")));
    }

    // Go: if rawURL == "*" { url.Path = "*"; return }
    if raw_url == "*" {
        let mut u = URL::empty();
        u.Path = string("*");
        u.RawPath = string("*");
        return (u, errors::nil);
    }

    // Go: url.Scheme, rest, err = getScheme(rawURL); url.Scheme = strings.ToLower(...)
    let (scheme, rest) = match get_scheme(raw_url.clone()) {
        Ok(t) => t,
        Err(e) => return (URL::empty(), e),
    };
    let scheme = crate::strings::ToLower(scheme);

    // Go: rest, url.RawQuery, _ = strings.Cut(rest, "?")
    let (rest, raw_query, _) = crate::strings::Cut(rest, string("?"));

    // Go: if !strings.HasPrefix(rest, "/") {
    //         if url.Scheme != "" { url.Opaque = rest; return url, nil }
    //         if viaRequest { return nil, errors.New("invalid URI for request") }
    //     }
    if !crate::strings::HasPrefix(rest.clone(), string("/")) {
        if scheme.Len() != 0 {
            // Goish has no Opaque field; render rootless paths as Path.
            let u = URL {
                Scheme: scheme,
                Host: string::new(),
                Path: rest.clone(),
                RawPath: rest,
                RawQuery: raw_query,
                Fragment: string::new(),
                RawFragment: string::new(),
            };
            return (u, errors::nil);
        }
        if via_request {
            return (
                URL::empty(),
                errors::New(string("invalid URI for request")),
            );
        }
    }

    // Go: if (url.Scheme != "" || !viaRequest && !strings.HasPrefix(rest, "///")) && strings.HasPrefix(rest, "//") { ... authority }
    let mut host = string::new();
    let mut path_rest = rest.clone();
    if (scheme.Len() != 0
        || (!via_request && !crate::strings::HasPrefix(rest.clone(), string("///"))))
        && crate::strings::HasPrefix(rest.clone(), string("//"))
    {
        // Skip the leading "//"
        let after = string::from_bytes(&rest.as_bytes()[2..]);
        // Host runs to first '/' or end.
        let host_end = match crate::bytes::IndexByte(crate::convert::bytes(after.clone()), b'/') {
            -1 => after.Len(),
            n => n,
        };
        host = string::from_bytes(&after.as_bytes()[..host_end as usize]);
        path_rest = string::from_bytes(&after.as_bytes()[host_end as usize..]);
    }

    // Empty path on absolute URL → "/".
    let mut path = path_rest;
    if host.Len() != 0 && path.Len() == 0 {
        path = string("/");
    }

    let u = URL {
        Scheme: scheme,
        Host: host,
        Path: path.clone(),
        RawPath: path,
        RawQuery: raw_query,
        Fragment: string::new(),
        RawFragment: string::new(),
    };
    (u, errors::nil)
}

/// Line-by-line port of `getScheme` (url.go:209). Returns
/// `(scheme, rest)` where `scheme` is lowercase and may be empty.
fn get_scheme(raw_url: string) -> Result<(string, string), error> {
    // Go: for i := 0; i < len(rawURL); i++ { ... }
    let mut i: int = 0;
    while i < raw_url.Len() {
        let c: byte = raw_url[i];
        // Go: switch { case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z': ... }
        if (b'a' <= c && c <= b'z') || (b'A' <= c && c <= b'Z') {
            // ok, continue
        } else if (b'0' <= c && c <= b'9') || c == b'+' || c == b'-' || c == b'.' {
            // Go: case '0' <= c && c <= '9' || c == '+' || c == '-' || c == '.':
            // First char cannot be digit/+/-/.
            if i == 0 {
                return Ok((string::new(), raw_url));
            }
        } else if c == b':' {
            // Go: case c == ':':
            if i == 0 {
                return Err(errors::New(string("missing protocol scheme")));
            }
            return Ok((
                string::from_bytes(&raw_url.as_bytes()[..i as usize]),
                string::from_bytes(&raw_url.as_bytes()[(i as usize) + 1..]),
            ));
        } else {
            // Go: default — we have encountered an invalid character,
            // so there is no valid scheme.
            return Ok((string::new(), raw_url));
        }
        i += 1;
    }
    Ok((string::new(), raw_url))
}

/// `url.QueryEscape(s)` (url.go:281) — percent-encode `s` so it is
/// safe inside the query component of a URL. Spaces become `+`.
pub fn QueryEscape(s: string) -> string {
    escape(s, EncodingMode::QueryComponent)
}

/// `(v Values).Encode()` (url.go:1028) — URL-encode `v` into the
/// `key=val&key=val` form, with keys sorted lexicographically. Each
/// key and value is escaped via `QueryEscape`. Multi-value keys
/// produce multiple `k=v` pairs in the order stored.
///
/// Free function rather than a method because goish models `Values`
/// as the bare gomap type.
pub fn ValuesEncode(v: crate::gomap::map<string, crate::goslice::slice<string>>) -> string {
    // Go: if len(v) == 0 { return "" }
    if v.Len() == 0 {
        return string::new();
    }
    // Go: var buf strings.Builder
    let mut buf = crate::strings::Builder::new();
    // Go: for _, k := range slices.Sorted(maps.Keys(v)) { ... }
    let keys = v.Keys(); // gomap::Keys returns BTreeMap-sorted slice
    let mut i: int = 0;
    while i < keys.Len() {
        let k = keys[i].clone();
        let (vs, _) = v.Get(k.clone());
        let key_escaped = QueryEscape(k);
        // Go: for _, v := range vs { ... }
        let mut j: int = 0;
        while j < vs.Len() {
            // Go: if buf.Len() > 0 { buf.WriteByte('&') }
            if buf.Len() > 0 {
                let _ = buf.WriteByte(b'&');
            }
            let _ = buf.WriteString(key_escaped.clone());
            let _ = buf.WriteByte(b'=');
            let _ = buf.WriteString(QueryEscape(vs[j].clone()));
            j += 1;
        }
        i += 1;
    }
    buf.String()
}

/// `url.PathEscape(s)` (url.go:287) — percent-encode `s` so it is
/// safe inside a single URL path segment (i.e. `/`, `;`, `,`, `?` are
/// all escaped). Spaces become `%20`.
pub fn PathEscape(s: string) -> string {
    escape(s, EncodingMode::PathSegment)
}

/// Subset of url.go's `encoding` enum (url.go:78). The full Go enum
/// also distinguishes encodePath / encodeHost / encodeZone /
/// encodeUserPassword / encodeFragment; we only ship the two modes
/// that QueryEscape + PathEscape need.
#[derive(Copy, Clone, PartialEq, Eq)]
enum EncodingMode {
    Path,
    PathSegment,
    QueryComponent,
}

/// Line-by-line port of `escape` (url.go:291).
fn escape(s: string, mode: EncodingMode) -> string {
    // Go: spaceCount, hexCount := 0, 0
    let mut space_count: int = 0;
    let mut hex_count: int = 0;
    // Go: for i := 0; i < len(s); i++ { c := s[i] ... }
    let mut i: int = 0;
    while i < s.Len() {
        let c: byte = s[i];
        if should_escape(c, mode) {
            if c == b' ' && mode == EncodingMode::QueryComponent {
                space_count += 1;
            } else {
                hex_count += 1;
            }
        }
        i += 1;
    }

    // Go: if spaceCount == 0 && hexCount == 0 { return s }
    if space_count == 0 && hex_count == 0 {
        return s;
    }

    // Go: required := len(s) + 2*hexCount; t := make([]byte, required)
    let required = (s.Len() + 2 * hex_count) as usize;
    let mut t: alloc::vec::Vec<byte> = alloc::vec::Vec::with_capacity(required);

    // Go: if hexCount == 0 { copy(t, s); for i { if s[i] == ' ' { t[i] = '+' } }
    if hex_count == 0 {
        let mut i: int = 0;
        while i < s.Len() {
            let c: byte = s[i];
            if c == b' ' {
                t.push(b'+');
            } else {
                t.push(c);
            }
            i += 1;
        }
        return string::from_bytes(&t);
    }

    // Go: j := 0; for i := 0; i < len(s); i++ { switch ... }
    let upperhex = b"0123456789ABCDEF";
    let mut i: int = 0;
    while i < s.Len() {
        let c: byte = s[i];
        if c == b' ' && mode == EncodingMode::QueryComponent {
            t.push(b'+');
        } else if should_escape(c, mode) {
            t.push(b'%');
            t.push(upperhex[(c >> 4) as usize]);
            t.push(upperhex[(c & 15) as usize]);
        } else {
            t.push(c);
        }
        i += 1;
    }
    string::from_bytes(&t)
}

/// Line-by-line port of `shouldEscape` (url.go:107). Slim mode set
/// matches `EncodingMode`.
fn should_escape(c: byte, mode: EncodingMode) -> bool {
    // Go: §2.3 Unreserved characters (alphanum)
    if (b'a' <= c && c <= b'z') || (b'A' <= c && c <= b'Z') || (b'0' <= c && c <= b'9') {
        return false;
    }
    // Go: §2.3 Unreserved characters (mark)
    match c {
        b'-' | b'_' | b'.' | b'~' => return false,
        _ => {}
    }
    // Go: §2.2 Reserved characters
    match c {
        b'$' | b'&' | b'+' | b',' | b'/' | b':' | b';' | b'=' | b'?' | b'@' => match mode {
            // Go: encodePath — only '?' must be escaped (url.go:137).
            EncodingMode::Path => {
                return c == b'?';
            }
            // Go: encodePathSegment — return c == '/' || c == ';' || c == ',' || c == '?'
            EncodingMode::PathSegment => {
                return c == b'/' || c == b';' || c == b',' || c == b'?';
            }
            // Go: encodeQueryComponent — RFC reserves everything.
            EncodingMode::QueryComponent => return true,
        },
        _ => {}
    }
    // Everything else must be escaped.
    true
}

/// Line-by-line port of `validEncoded` (url.go:760).
///
/// Reports whether `s` is a valid encoded path, according to `mode`.
/// Sub-delims, `[`, `]`, `%` are accepted directly; everything else is
/// validated via `should_escape`.
fn valid_encoded(s: string, mode: EncodingMode) -> bool {
    // Go: for i := 0; i < len(s); i++ { ... }
    let mut i: int = 0;
    while i < s.Len() {
        let c: byte = s[i];
        // Go: switch s[i] { case '!','$','&','\'','(',')','*','+',',',';','=',':','@': /* ok */
        match c {
            b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b','
            | b';' | b'=' | b':' | b'@' => { /* ok */ }
            // Go: case '[', ']': // ok — left alone by modern browsers
            b'[' | b']' => { /* ok */ }
            // Go: case '%': // ok — percent encoded, will decode
            b'%' => { /* ok */ }
            _ => {
                if should_escape(c, mode) {
                    return false;
                }
            }
        }
        i += 1;
    }
    true
}

fn unescape(s: string, query_mode: bool) -> (string, error) {
    // First pass: count '%' escapes, validate, count '+' (query only).
    let mut n: int = 0;
    let mut has_plus = false;
    let mut i: int = 0;
    while i < s.Len() {
        let c: byte = s[i];
        if c == b'%' {
            n += 1;
            if i + 2 >= s.Len() || !is_hex(s[i + 1]) || !is_hex(s[i + 2]) {
                return (string::new(), errors::New(string("invalid URL escape")));
            }
            i += 3;
        } else if c == b'+' {
            has_plus = true;
            i += 1;
        } else {
            i += 1;
        }
    }
    // Fast path.
    if n == 0 && !(query_mode && has_plus) {
        return (s, errors::nil);
    }
    // Second pass: emit decoded bytes via a goish slice<byte>.
    let mut out = crate::make!([]byte, 0);
    let mut i: int = 0;
    while i < s.Len() {
        let c: byte = s[i];
        if c == b'%' {
            let hi = unhex(s[i + 1]);
            let lo = unhex(s[i + 2]);
            out = crate::append!(out, (hi << 4) | lo);
            i += 3;
        } else if c == b'+' && query_mode {
            out = crate::append!(out, b' ');
            i += 1;
        } else {
            out = crate::append!(out, c);
            i += 1;
        }
    }
    (crate::convert::string(out), errors::nil)
}

fn is_hex(c: byte) -> bool {
    (c >= b'0' && c <= b'9') || (c >= b'a' && c <= b'f') || (c >= b'A' && c <= b'F')
}

/// Line-by-line port of `splitHostPort` (url.go:1224).
fn split_host_port(host_port: string) -> (string, string) {
    // Go: host = hostPort
    let mut host: string = host_port;
    let mut port: string = string::new();

    // Go: colon := strings.LastIndexByte(host, ':')
    let colon = crate::bytes::LastIndexByte(crate::convert::bytes(host.clone()), b':');
    if colon != -1 {
        // Go: if validOptionalPort(host[colon:]) { ... }
        let suffix = string::from_bytes(&host.as_bytes()[colon as usize..]);
        if valid_optional_port(suffix.clone()) {
            // Go: host, port = host[:colon], host[colon+1:]
            let pre = string::from_bytes(&host.as_bytes()[..colon as usize]);
            let post =
                string::from_bytes(&host.as_bytes()[(colon as usize) + 1..]);
            host = pre;
            port = post;
        }
    }

    // Go: if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
    if crate::strings::HasPrefix(host.clone(), string("["))
        && crate::strings::HasSuffix(host.clone(), string("]"))
    {
        // Go: host = host[1 : len(host)-1]
        host = string::from_bytes(&host.as_bytes()[1..host.Len() as usize - 1]);
    }

    (host, port)
}

/// Line-by-line port of `validOptionalPort` (url.go:819). Reports
/// whether `port` is "" or matches `:\d*`.
fn valid_optional_port(port: string) -> bool {
    // Go: if port == "" { return true }
    if port.Len() == 0 {
        return true;
    }
    // Go: if port[0] != ':' { return false }
    if port[0] != b':' {
        return false;
    }
    // Go: for _, b := range port[1:] { if b < '0' || b > '9' { return false } }
    let mut i: int = 1;
    while i < port.Len() {
        let b: byte = port[i];
        if b < b'0' || b > b'9' {
            return false;
        }
        i += 1;
    }
    true
}

fn unhex(c: byte) -> byte {
    if c >= b'0' && c <= b'9' {
        c - b'0'
    } else if c >= b'a' && c <= b'f' {
        c - b'a' + 10
    } else if c >= b'A' && c <= b'F' {
        c - b'A' + 10
    } else {
        0
    }
}
