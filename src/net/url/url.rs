// go: file net/url/url.go decls: JoinPath, Error.Error, Error.Unwrap, Error.Timeout, Error.Temporary, EscapeError.Error, InvalidHostError.Error, escape, unescape, shouldEscape, QueryUnescape, PathUnescape, QueryEscape, PathEscape, User, UserPassword, Userinfo.Username, Userinfo.Password, Userinfo.String, getScheme, Parse, ParseRequestURI, parse, parseAuthority, parseHost, URL.setPath, URL.EscapedPath, validEncoded, URL.setFragment, URL.EscapedFragment, URL.String, validOptionalPort, ParseQuery, parseQuery, resolvePath, URL.IsAbs, URL.Parse, URL.ResolveReference, URL.RequestURI, URL.Hostname, URL.Port, splitHostPort, URL.Redacted, validUserinfo, stringContainsCTLByte, URL.JoinPath, ParseQueryValues, ValuesGet, ValuesSet, ValuesAdd, ValuesDel, ValuesHas, SetPassword, URL.Query, URL.MarshalBinary, URL.AppendBinary, URL.UnmarshalBinary
// goishlint:ignore GOISH018 Add, Del, Get, Has, Set, Encode, MarshalBinary, UnmarshalBinary, ishex, unhex, badSetPath, shouldEscape, Encode — Go's `Values` is a NAMED map type carrying methods; goish's is a type alias for `map<string, slice<string>>`, which Rust cannot hang methods on, so the same six are free functions `ValuesAdd`/`ValuesDel`/`ValuesGet`/`ValuesHas`/`ValuesSet`/`ValuesEncode`. `Error`'s net.Error pair (Timeout, Temporary) IS ported now — see the manifest above and examples/url_error_ref_smoke.rs. `ishex`/`unhex` are ported under Rust casing as `is_hex`/`un_hex`, and `badSetPath` is a test-only helper, and `shouldEscape` is `should_escape`. `Encode` is `ValuesEncode`, for the same reason as the other five.
// goishlint:ignore GOISH021 encoding, encodePath, encodePathSegment, encodeHost, encodeZone, encodeUserPassword, encodeQueryComponent, encodeFragment — Go's `encoding` is an untyped int const set; goish's is the `Encoding` enum below, whose variants carry the same seven names in Rust casing.
//
// url.go — the whole package: parsing, escaping, the URL type and
// its methods, and the query Values.
//
// Parses URLs and implements query escaping per RFC 3986.
//
// **Public-API discipline**: every signature uses goish lowercase
// types (`string`, `slice<byte>`, `int`, multi-return tuples).
// No `Vec<u8>`, `&str`, `&[u8]`, `String` leak.

extern crate alloc;

use alloc::vec::Vec;

use crate::errors::{self, error, ErrorTrait};
use crate::gomap;
use crate::strings;
use crate::types::int;
use crate::{byte, nil, slice, string};

// ─── Error types ─────────────────────────────────────────────────────

/// `url.Error` reports an error and the operation + URL that caused it.
/// Mirrors `net/url.Error` (url.go:28-32).
#[derive(Clone)]
pub struct Error {
    pub Op: string,
    pub URL: string,
    pub Err: error,
}

impl ErrorTrait for Error {
    // go: sdk 1.25.5 net/url/url.go:35-35 Error.Error
    fn Error(&self) -> string {
        let inner = if self.Err.IsNil() {
            string::from_static("<nil>")
        } else {
            self.Err.Error()
        };
        return crate::Sprintf!("%s %q: %s", self.Op.clone(), self.URL.clone(), inner);
    }
    // go: sdk 1.25.5 net/url/url.go:34-34 Error.Unwrap
    fn Unwrap(&self) -> error {
        return self.Err.clone();
    }
}

impl Error {
    // go: sdk 1.25.5 net/url/url.go:37-42 Error.Timeout
    /// Go: `func (e *Error) Timeout() bool` — probe the wrapped error
    /// for `interface{ Timeout() bool }` and ask it.
    ///
    /// This is how a caller of `http.Client.Do` decides whether a
    /// failure is worth retrying — a timeout usually is, a refused
    /// connection usually is not — so its absence was not cosmetic.
    ///
    /// Two details, both learned the hard way elsewhere in this tree.
    /// The probe is `errors::AsIface`, NOT `cast!`: `cast!` on an
    /// `error` downcasts the HANDLE rather than what it wraps, so it
    /// can never hit (net.rs:253 records that exact bug). And the
    /// interface is `net::timeout` because Go writes an ANONYMOUS
    /// interface here — net/url does not import net — while goish
    /// needs a named trait, and the named one already exists there.
    /// Single crate, so the reference costs nothing but the layering
    /// note.
    pub fn Timeout(&self) -> bool {
        let (t, ok) = crate::errors::AsIface::<crate::d!(crate::net::net::timeout)>(&self.Err);
        return ok && t.Timeout();
    }

    // go: sdk 1.25.5 net/url/url.go:44-49 Error.Temporary
    /// Go: `func (e *Error) Temporary() bool` — as `Timeout`, for
    /// `interface{ Temporary() bool }`. Go marks the concept
    /// deprecated ("Temporary errors are not well-defined") but still
    /// implements it, and code in the wild still branches on it.
    pub fn Temporary(&self) -> bool {
        let (t, ok) = crate::errors::AsIface::<crate::d!(crate::net::net::temporary)>(&self.Err);
        return ok && t.Temporary();
    }

    // go: none — goish idiom: a helper with no Go counterpart; see the surrounding port.
    pub fn new<O: Into<string>, U: Into<string>>(op: O, url: U, err: error) -> error {
        return errors::Wrap(Error {
            Op: op.into(),
            URL: url.into(),
            Err: err,
        });
    }
}

/// `url.EscapeError` — wraps the malformed escape sequence text.
/// Mirrors `net/url.EscapeError` (url.go:90).
#[derive(Clone)]
pub struct EscapeError(pub string);

impl ErrorTrait for EscapeError {
    // go: sdk 1.25.5 net/url/url.go:92-94 EscapeError.Error
    fn Error(&self) -> string {
        let mut buf = string::from_static("invalid URL escape ");
        buf = buf + crate::strconv::Quote(self.0.clone());
        return buf;
    }
}

impl EscapeError {
    // go: none — goish idiom: a helper with no Go counterpart; see the surrounding port.
    pub fn new<S: Into<string>>(s: S) -> error {
        return errors::Wrap(EscapeError(s.into()));
    }
}

/// `url.InvalidHostError` — wraps the invalid host character.
/// Mirrors `net/url.InvalidHostError` (url.go:96).
#[derive(Clone)]
pub struct InvalidHostError(pub string);

impl ErrorTrait for InvalidHostError {
    // go: sdk 1.25.5 net/url/url.go:98-100 InvalidHostError.Error
    fn Error(&self) -> string {
        let mut buf = string::from_static("invalid character ");
        buf = buf + crate::strconv::Quote(self.0.clone());
        buf = buf + string::from_static(" in host name");
        return buf;
    }
}

impl InvalidHostError {
    // go: none — goish idiom: a helper with no Go counterpart; see the surrounding port.
    pub fn new<S: Into<string>>(s: S) -> error {
        return errors::Wrap(InvalidHostError(s.into()));
    }
}

// ─── Encoding mode ───────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
enum Encoding {
    EncodePath,
    EncodePathSegment,
    EncodeHost,
    EncodeZone,
    EncodeUserPassword,
    EncodeQueryComponent,
    EncodeFragment,
}

use Encoding::*;

const UPPER_HEX: &[u8] = b"0123456789ABCDEF";

// go: none — goish idiom: a helper with no Go counterpart; see the surrounding port.
fn is_hex(c: byte) -> bool {
    return matches!(c, b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F');
}

// go: none — goish idiom: a helper with no Go counterpart; see the surrounding port.
fn un_hex(c: byte) -> byte {
    return match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("invalid hex character"),
    };
}

// go: none — goish idiom: the port of Go's `shouldEscape`, under Rust casing.
/// Return true if the specified character should be escaped when
/// appearing in a URL string, according to RFC 3986.
fn should_escape(c: byte, mode: Encoding) -> bool {
    // §2.3 Unreserved characters (alphanum)
    if c.is_ascii_alphanumeric() {
        return false;
    }

    if mode == EncodeHost || mode == EncodeZone {
        match c {
            b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'=' | b':'
            | b'[' | b']' | b'<' | b'>' | b'"' => {
                return false;
            }
            _ => {}
        }
    }

    match c {
        b'-' | b'_' | b'.' | b'~' => return false,
        b'$' | b'&' | b'+' | b',' | b'/' | b':' | b';' | b'=' | b'?' | b'@' => match mode {
            EncodePath => return c == b'?',
            EncodePathSegment => return c == b'/' || c == b';' || c == b',' || c == b'?',
            EncodeUserPassword => return c == b'@' || c == b'/' || c == b'?' || c == b':',
            EncodeQueryComponent => return true,
            EncodeFragment => return false,
            _ => {}
        },
        _ => {}
    }

    if mode == EncodeFragment {
        match c {
            b'!' | b'(' | b')' | b'*' => return false,
            _ => {}
        }
    }

    return true;
}

// ─── Unescape / Escape ────────────────────────────────────────────────

// go: sdk 1.25.5 net/url/url.go:206-277 unescape
fn unescape(s: string, mode: Encoding) -> (string, error) {
    let s_bytes = s.as_bytes();
    let n = s_bytes.iter().filter(|&&c| c == b'%').count();
    let has_plus = s_bytes
        .iter()
        .any(|&c| c == b'+' && mode == EncodeQueryComponent);

    if n == 0 && !has_plus {
        return (s, nil.into());
    }

    // Count %, check that they're well-formed.
    let mut i = 0;
    let len = s.Len();
    while i < len {
        match s_bytes[i as usize] {
            b'%' => {
                if i + 2 >= len
                    || !is_hex(s_bytes[(i + 1) as usize])
                    || !is_hex(s_bytes[(i + 2) as usize])
                {
                    let mut sub = s.slice(i, len);
                    if sub.Len() > 3 {
                        sub = sub.slice(0, 3);
                    }
                    return (string::new(), EscapeError::new(sub));
                }
                if mode == EncodeHost
                    && un_hex(s_bytes[(i + 1) as usize]) < 8
                    && s.slice(i, i + 3) != "%25"
                {
                    return (string::new(), EscapeError::new(s.slice(i, i + 3)));
                }
                if mode == EncodeZone {
                    let v =
                        un_hex(s_bytes[(i + 1) as usize]) << 4 | un_hex(s_bytes[(i + 2) as usize]);
                    if s.slice(i, i + 3) != "%25" && v != b' ' && should_escape(v, EncodeHost) {
                        return (string::new(), EscapeError::new(s.slice(i, i + 3)));
                    }
                }
                i += 3;
            }
            b'+' => {
                i += 1;
            }
            _ => {
                if (mode == EncodeHost || mode == EncodeZone)
                    && s_bytes[i as usize] < 0x80
                    && should_escape(s_bytes[i as usize], mode)
                {
                    return (string::new(), InvalidHostError::new(s.slice(i, i + 1)));
                }
                i += 1;
            }
        }
    }

    // Build result
    let mut t = Vec::with_capacity(s_bytes.len() - 2 * n);
    let mut i = 0;
    while i < len {
        match s_bytes[i as usize] {
            b'%' => {
                t.push(un_hex(s_bytes[(i + 1) as usize]) << 4 | un_hex(s_bytes[(i + 2) as usize]));
                i += 3;
            }
            b'+' => {
                if mode == EncodeQueryComponent {
                    t.push(b' ');
                } else {
                    t.push(b'+');
                }
                i += 1;
            }
            c => {
                t.push(c);
                i += 1;
            }
        }
    }

    return (string::from_bytes(&t), nil.into());
}

// go: sdk 1.25.5 net/url/url.go:189-191 QueryUnescape
/// `QueryUnescape(s)` (url.go:189) — inverse of QueryEscape.
pub fn QueryUnescape<S: Into<string>>(s: S) -> (string, error) {
    return unescape(s.into(), EncodeQueryComponent);
}

// go: sdk 1.25.5 net/url/url.go:200-202 PathUnescape
/// `PathUnescape(s)` (url.go:200) — inverse of PathEscape.
pub fn PathUnescape<S: Into<string>>(s: S) -> (string, error) {
    return unescape(s.into(), EncodePathSegment);
}

// go: sdk 1.25.5 net/url/url.go:291-345 escape
fn escape(s: string, mode: Encoding) -> string {
    let s_bytes = s.as_bytes();
    let mut space_count = 0;
    let mut hex_count = 0;
    for &c in s_bytes.iter() {
        if should_escape(c, mode) {
            if c == b' ' && mode == EncodeQueryComponent {
                space_count += 1;
            } else {
                hex_count += 1;
            }
        }
    }

    if space_count == 0 && hex_count == 0 {
        return s;
    }

    let required = s_bytes.len() + 2 * hex_count;
    let mut t = Vec::with_capacity(required);

    if hex_count == 0 {
        for &c in s_bytes.iter() {
            if c == b' ' && mode == EncodeQueryComponent {
                t.push(b'+');
            } else {
                t.push(c);
            }
        }
        return string::from_bytes(&t);
    }

    for &c in s_bytes.iter() {
        if c == b' ' && mode == EncodeQueryComponent {
            t.push(b'+');
        } else if should_escape(c, mode) {
            t.push(b'%');
            t.push(UPPER_HEX[(c as usize) >> 4]);
            t.push(UPPER_HEX[(c as usize) & 0xf]);
        } else {
            t.push(c);
        }
    }
    return string::from_bytes(&t);
}

// go: sdk 1.25.5 net/url/url.go:281-283 QueryEscape
/// `QueryEscape(s)` (url.go:281) — escapes for URL query.
pub fn QueryEscape<S: Into<string>>(s: S) -> string {
    return escape(s.into(), EncodeQueryComponent);
}

// go: sdk 1.25.5 net/url/url.go:287-289 PathEscape
/// `PathEscape(s)` (url.go:287) — escapes for URL path segment.
pub fn PathEscape<S: Into<string>>(s: S) -> string {
    return escape(s.into(), EncodePathSegment);
}

// ─── Userinfo ───────────────────────────────────────────────────────

/// `url.Userinfo` (url.go:401) — username and password information.
#[derive(Clone, Default)]
pub struct Userinfo {
    username: string,
    password: string,
    passwordSet: bool,
}

// go: sdk 1.25.5 net/url/url.go:391-393 User
/// Go: "User returns a [Userinfo] containing the provided username and
/// no password set."
///
/// Go declares this at PACKAGE level (`url.User(name)`), not as a
/// method; goish used to have it as an associated function on
/// `Userinfo`, which is a different spelling for callers and is why
/// net/http could not simply re-export it.
pub fn User<U: Into<string>>(username: U) -> Userinfo {
    return Userinfo {
        username: username.into(),
        password: string::new(),
        passwordSet: false,
    };
}

// go: sdk 1.25.5 net/url/url.go:403-405 UserPassword
/// Go: "UserPassword returns a [Userinfo] containing the provided
/// username and password."
pub fn UserPassword<U: Into<string>, P: Into<string>>(username: U, password: P) -> Userinfo {
    return Userinfo {
        username: username.into(),
        password: password.into(),
        passwordSet: true,
    };
}

impl Userinfo {
    // go: sdk 1.25.5 net/url/url.go:418-423 Userinfo.Username
    /// `u.Username()` (url.go:407) — returns the username.
    pub fn Username(&self) -> string {
        return self.username.clone();
    }

    // go: sdk 1.25.5 net/url/url.go:426-431 Userinfo.Password
    /// `u.Password()` (url.go:410) — returns (password, ok).
    pub fn Password(&self) -> (string, bool) {
        return (self.password.clone(), self.passwordSet);
    }

    // go: sdk 1.25.5 net/url/url.go:435-444 Userinfo.String
    /// `u.String()` (url.go:419) — returns the encoded userinfo string.
    pub fn String(&self) -> string {
        let mut s = escape(self.username.clone(), EncodeUserPassword);
        if self.passwordSet {
            s = s + ":";
            s = s + escape(self.password.clone(), EncodeUserPassword);
        }
        return s;
    }

    // go: none — goish idiom: a goish-only setter; Go's Userinfo is immutable.
    /// `u.SetPassword(password)` — internal helper.
    pub fn SetPassword<P: Into<string>>(&mut self, password: P) {
        self.password = password.into();
        self.passwordSet = true;
    }
}

// Nil support for *Userinfo
impl PartialEq<crate::nilval::Nil> for Userinfo {
    // go: none — goish idiom: a helper with no Go counterpart; see the surrounding port.
    fn eq(&self, _: &crate::nilval::Nil) -> bool {
        return self.username.Len() == 0 && !self.passwordSet;
    }
}
impl PartialEq<Userinfo> for crate::nilval::Nil {
    // go: none — goish idiom: a helper with no Go counterpart; see the surrounding port.
    fn eq(&self, other: &Userinfo) -> bool {
        return other.username.Len() == 0 && !other.passwordSet;
    }
}
impl From<crate::nilval::Nil> for Userinfo {
    // go: none — goish idiom: a helper with no Go counterpart; see the surrounding port.
    fn from(_: crate::nilval::Nil) -> Self {
        return Userinfo::default();
    }
}

// ─── URL ──────────────────────────────────────────────────────────────

/// `url.URL` (url.go:375) — represents a parsed URL (URI reference).
#[derive(Clone, Default)]
pub struct URL {
    pub Scheme: string,
    pub Opaque: string,
    pub User: Userinfo,
    pub Host: string,
    pub Path: string,
    pub RawPath: string,
    pub OmitHost: bool,
    pub ForceQuery: bool,
    pub RawQuery: string,
    pub Fragment: string,
    pub RawFragment: string,
}

impl URL {
    // go: sdk 1.25.5 net/url/url.go:855-922 URL.String
    /// `u.String()` (url.go:804) — reassembles the URL into a valid URL string.
    pub fn String(&self) -> string {
        let mut buf = strings::Builder::new();

        if self.Scheme.Len() != 0 {
            buf.WriteString(self.Scheme.clone());
            buf.WriteString(":");
        }

        if self.Opaque.Len() != 0 {
            buf.WriteString(self.Opaque.clone());
        } else {
            // Go: `if u.Scheme != "" || u.Host != "" || u.User != nil`
            // — the PATH is not part of that test, and the inner one is
            // `u.Host != "" || u.Path != "" || u.User != nil`. goish had
            // `u.Path != ""` in the outer test and `u.Scheme != ""` in
            // the inner, so a bare path got a "//" in front of it:
            // `/just/a/path` rendered as `///just/a/path` and
            // `just/a/path` as `//just/a/path`, which is a different URL
            // — the second reads as an authority.
            if self.Scheme.Len() != 0 || self.Host.Len() != 0 || self.User != nil {
                if self.OmitHost && self.Host.Len() == 0 && self.User == nil {
                    // Go: omit empty host
                } else {
                    if self.Host.Len() != 0 || self.Path.Len() != 0 || self.User != nil {
                        buf.WriteString("//");
                    }
                    let ui = self.User.clone();
                    if ui != nil {
                        buf.WriteString(ui.String());
                        buf.WriteString("@");
                    }
                    if self.Host.Len() != 0 {
                        buf.WriteString(escape(self.Host.clone(), EncodeHost));
                    }
                }
            }
            let path = self.EscapedPath();
            if path.Len() != 0 && path.as_bytes()[0] != b'/' && self.Host.Len() != 0 {
                buf.WriteString("/");
            }
            if buf.Len() == 0 {
                // Go, RFC 3986 §4.2: "A path segment that contains a
                // colon character … cannot be used as the first segment
                // of a relative-path reference, as it would be mistaken
                // for a scheme name. Such a segment must be preceded by
                // a dot-segment."
                let (segment, _, _) = cut(&path, b'/');
                if strings::Contains(segment, ":") {
                    buf.WriteString("./");
                }
            }
            buf.WriteString(path);
        }

        if self.ForceQuery || self.RawQuery.Len() != 0 {
            buf.WriteString("?");
            buf.WriteString(self.RawQuery.clone());
        }

        if self.Fragment.Len() != 0 {
            buf.WriteString("#");
            buf.WriteString(self.EscapedFragment());
        }

        return buf.String();
    }

    // go: sdk 1.25.5 net/url/url.go:744-755 URL.EscapedPath
    /// `u.EscapedPath()` (url.go:681) — returns the escaped form of u.Path.
    /// Returns u.RawPath only when it is a valid escaping of u.Path
    /// (i.e., unescape(RawPath) == Path). Otherwise ignores RawPath.
    pub fn EscapedPath(&self) -> string {
        if self.RawPath.Len() != 0 && validEncoded(&self.RawPath, EncodePath) {
            let (p, err) = unescape(self.RawPath.clone(), EncodePath);
            if err == nil && p == self.Path {
                return self.RawPath.clone();
            }
        }
        if self.Path == string("*") {
            return self.Path.clone();
        }
        return escape(self.Path.clone(), EncodePath);
    }

    // go: sdk 1.25.5 net/url/url.go:807-815 URL.EscapedFragment
    /// `u.EscapedFragment()` (url.go:714) — returns the escaped form of u.Fragment.
    pub fn EscapedFragment(&self) -> string {
        // Go also checks that the RawFragment DECODES back to Fragment
        // before trusting it; goish returned it on the encoding check
        // alone, so a RawFragment left stale by a caller's edit to
        // Fragment would win over the field that was actually changed.
        if self.RawFragment.Len() != 0 && validEncoded(&self.RawFragment, EncodeFragment) {
            let (f, err) = unescape(self.RawFragment.clone(), EncodeFragment);
            if err.IsNil() && f == self.Fragment {
                return self.RawFragment.clone();
            }
        }
        return escape(self.Fragment.clone(), EncodeFragment);
    }

    // go: sdk 1.25.5 net/url/url.go:1208-1211 URL.Hostname
    /// `u.Hostname()` (url.go:1138) — returns u.Host, stripping any port number.
    pub fn Hostname(&self) -> string {
        // Go: host, _ := splitHostPort(u.Host)
        let (host, _) = splitHostPort(&self.Host);
        return host;
    }

    // go: sdk 1.25.5 net/url/url.go:1216-1219 URL.Port
    /// `u.Port()` (url.go:1155) — returns the port part of u.Host, without the leading colon.
    pub fn Port(&self) -> string {
        // Go: _, port := splitHostPort(u.Host)
        let (_, port) = splitHostPort(&self.Host);
        return port;
    }

    // go: sdk 1.25.5 net/url/url.go:1116-1118 URL.IsAbs
    /// `u.IsAbs()` (url.go:1124) — reports whether URL is absolute.
    pub fn IsAbs(&self) -> bool {
        return self.Scheme.Len() != 0;
    }

    // go: sdk 1.25.5 net/url/url.go:1123-1129 URL.Parse
    /// `u.Parse(ref)` (url.go:1084) — parses a URL reference in the context of u.
    pub fn Parse(&self, ref_: string) -> (URL, error) {
        let (refurl, err) = Parse(ref_);
        if err != nil {
            return (URL::default(), err);
        }
        return (self.ResolveReference(&refurl), nil.into());
    }

    // go: sdk 1.25.5 net/url/url.go:1137-1174 URL.ResolveReference
    /// `u.ResolveReference(ref)` (url.go:1094) — resolves a URI reference.
    /// Go: "ResolveReference resolves a URI reference to an absolute
    /// URI from an absolute base URI u, per RFC 3986 Section 5.2."
    ///
    /// goish's did the field copying and then stopped: it never called
    /// `resolvePath`, so no dot-segment was ever removed and a relative
    /// reference was simply appended. `..` against `http://a/b/c/d;p?q`
    /// gave `http://a/b/c/..`, and `.` gave `http://a/b/c/.` — every
    /// one of RFC 3986's own worked examples came out wrong. It also
    /// carried the base's RawQuery onto a reference that HAD one, and
    /// dropped the base path when the reference was a bare `#frag`.
    ///
    /// The signature keeps goish's `(URL, error)` shape; Go returns a
    /// single `*URL` because `setPath` cannot fail on an
    /// already-escaped path, and the error here is always nil for the
    /// same reason.
    ///
    /// Go returns `*URL` and no error; goish's port returned an error
    /// that was always nil, which every caller then had to unpack.
    pub fn ResolveReference(&self, ref_: &URL) -> URL {
        let mut url = ref_.clone();
        if ref_.Scheme.Len() == 0 {
            url.Scheme = self.Scheme.clone();
        }
        if ref_.Scheme.Len() != 0 || ref_.Host.Len() != 0 || ref_.User != nil {
            // Go: "The 'absoluteURI' or 'net_path' cases."
            let _ = url.setPath(resolvePath(ref_.EscapedPath(), string::new()));
            return url;
        }
        if ref_.Opaque.Len() != 0 {
            url.User = Userinfo::default();
            url.Host = string::new();
            url.Path = string::new();
            return url;
        }
        if ref_.Path.Len() == 0 && !ref_.ForceQuery && ref_.RawQuery.Len() == 0 {
            url.RawQuery = self.RawQuery.clone();
            if ref_.Fragment.Len() == 0 {
                url.Fragment = self.Fragment.clone();
                url.RawFragment = self.RawFragment.clone();
            }
        }
        if ref_.Path.Len() == 0 && self.Opaque.Len() != 0 {
            url.Opaque = self.Opaque.clone();
            url.User = Userinfo::default();
            url.Host = string::new();
            url.Path = string::new();
            return url;
        }
        // Go: "The 'abs_path' or 'rel_path' cases."
        url.Host = self.Host.clone();
        url.User = self.User.clone();
        let _ = url.setPath(resolvePath(self.EscapedPath(), ref_.EscapedPath()));
        return url;
    }

    // go: sdk 1.25.5 net/url/url.go:1186-1202 URL.RequestURI
    /// `u.RequestURI()` (url.go:820) — returns the encoded path?query or opaque?query.
    pub fn RequestURI(&self) -> string {
        // Go: result := u.Opaque; if result == "" { result =
        // u.EscapedPath(); if result == "" { result = "/" } } else { if
        // strings.HasPrefix(result, "//") { result = u.Scheme + ":" +
        // result } }
        //
        // goish had no "/" default, so a URL with an empty path — every
        // `http://host` — produced an EMPTY request URI, which is not a
        // valid request line.
        let mut result = self.Opaque.clone();
        if result.Len() == 0 {
            result = self.EscapedPath();
            if result.Len() == 0 {
                result = string::from_static("/");
            }
        } else if strings::HasPrefix(result.clone(), "//") {
            result = self.Scheme.clone() + string::from_static(":") + result;
        }
        if self.ForceQuery || self.RawQuery.Len() != 0 {
            result = result + "?";
            result = result + self.RawQuery.clone();
        }
        return result;
    }

    // go: sdk 1.25.5 net/url/url.go:926-936 URL.Redacted
    /// `u.Redacted()` (url.go:832) — returns the URL string with any password replaced.
    pub fn Redacted(&self) -> string {
        let mut u = self.clone();
        if u.User.passwordSet {
            u.User.SetPassword("xxxxx");
        }
        return u.String();
    }

    // go: sdk 1.25.5 net/url/url.go:1179-1182 URL.Query
    /// Go: "Query parses RawQuery and returns the corresponding values.
    /// It silently discards malformed value pairs. To check errors use
    /// ParseQuery."
    ///
    /// This is the most-used method on a URL after `String()`, and it
    /// was not ported: a caller had to reach for `ParseQuery` and pass
    /// `RawQuery` by hand, which is also the only way they would have
    /// noticed it was missing.
    pub fn Query(&self) -> Values {
        // Go: v, _ := ParseQuery(u.RawQuery); return v
        let (v, _) = ParseQuery(self.RawQuery.clone());
        return v;
    }

    // go: sdk 1.25.5 net/url/url.go:1242-1244 URL.MarshalBinary
    /// Go: the `encoding.BinaryMarshaler` half — a URL marshals as the
    /// text `String()` produces, and unmarshals by parsing it back.
    pub fn MarshalBinary(&self) -> (slice<byte>, error) {
        return self.AppendBinary(slice::new());
    }

    // go: sdk 1.25.5 net/url/url.go:1246-1248 URL.AppendBinary
    pub fn AppendBinary(&self, b: slice<byte>) -> (slice<byte>, error) {
        // Go: return append(b, u.String()...), nil
        let mut v: Vec<byte> = b.__into_vec();
        v.extend_from_slice(self.String().as_bytes());
        return (slice::__from_vec(v), nil.into());
    }

    // go: sdk 1.25.5 net/url/url.go:1250-1257 URL.UnmarshalBinary
    pub fn UnmarshalBinary(&mut self, text: slice<byte>) -> error {
        // Go: u1, err := Parse(string(text)); if err != nil { return err }
        //     *u = *u1
        let (u1, err) = Parse(string::from_bytes(text.as_ref()));
        if !err.IsNil() {
            return err;
        }
        *self = u1;
        return nil.into();
    }

    // go: sdk 1.25.5 net/url/url.go:1262-1281 URL.JoinPath
    /// `u.JoinPath(elem ...)` (url.go:1205) — appends path elements.
    /// Go: "JoinPath returns a new URL with the provided path elements
    /// joined to any existing path and the resulting path cleaned of any
    /// ./ or ../ elements. Any sequences of multiple / characters will
    /// be reduced to a single /."
    ///
    /// Go returns `*URL` and no error; goish's port returned an error
    /// that was always nil, which every caller then had to unpack.
    pub fn JoinPath(&self, elem: slice<string>) -> URL {
        let mut url = self.clone();
        // Go: elem = append([]string{u.EscapedPath()}, elem...)
        let mut parts: Vec<string> = Vec::with_capacity(elem.Len() as usize + 1);
        parts.push(self.EscapedPath());
        for e in elem.iter() {
            parts.push(e.clone());
        }
        let last = parts[parts.len() - 1].clone();
        let p;
        if !strings::HasPrefix(parts[0].clone(), "/") {
            // Go: "Return a relative path if u is relative, but ensure
            // that it contains no ../ elements."
            parts[0] = string::from_static("/") + parts[0].clone();
            let joined = crate::path::Join(slice::__from_vec(parts));
            p = joined.slice(1, joined.Len());
        } else {
            p = crate::path::Join(slice::__from_vec(parts));
        }
        // Go: "path.Join will remove any trailing slashes. Preserve at
        // least one." goish did not, so joining "c/" onto "/a/b" gave
        // "/a/b/c" — a different resource to every server that treats a
        // directory path as distinct from a file one.
        let p = if strings::HasSuffix(last, "/") && !strings::HasSuffix(p.clone(), "/") {
            p + string::from_static("/")
        } else {
            p
        };
        let _ = url.setPath(p);
        return url;
    }
}

// Nil support for URL
impl PartialEq<crate::nilval::Nil> for URL {
    // go: none — goish idiom: a helper with no Go counterpart; see the surrounding port.
    fn eq(&self, _: &crate::nilval::Nil) -> bool {
        return self.Scheme.Len() == 0
            && self.Opaque.Len() == 0
            && self.User == nil
            && self.Host.Len() == 0
            && self.Path.Len() == 0;
    }
}
impl PartialEq<URL> for crate::nilval::Nil {
    // go: none — goish idiom: a helper with no Go counterpart; see the surrounding port.
    fn eq(&self, other: &URL) -> bool {
        return other.Scheme.Len() == 0
            && other.Opaque.Len() == 0
            && other.User == nil
            && other.Host.Len() == 0
            && other.Path.Len() == 0;
    }
}
impl From<crate::nilval::Nil> for URL {
    // go: none — goish idiom: a helper with no Go counterpart; see the surrounding port.
    fn from(_: crate::nilval::Nil) -> Self {
        return URL::default();
    }
}

// ─── Parse ───────────────────────────────────────────────────────────

impl URL {
    // go: sdk 1.25.5 net/url/url.go:714-731 URL.setPath
    /// Go: "setPath sets the Path and RawPath fields of the URL based on
    /// the provided escaped path p. It maintains the invariant that
    /// RawPath is only specified when it differs from the default
    /// encoding of the path."
    ///
    /// goish never set RawPath at all, so a path written with an
    /// escaped separator lost the distinction: `/a%2Fb/c` unescaped to
    /// `/a/b/c` and then re-escaped to `/a%252Fb/c` on the way out. The
    /// URL no longer round-tripped, and a router matching on the
    /// re-rendered form saw two segments where the sender meant one.
    fn setPath(&mut self, p: string) -> error {
        let (path, err) = unescape(p.clone(), EncodePath);
        if !err.IsNil() {
            return err;
        }
        self.Path = path.clone();
        let escp = escape(path, EncodePath);
        if p == escp {
            // Go: "Default encoding is fine."
            self.RawPath = string::new();
        } else {
            self.RawPath = p;
        }
        return nil.into();
    }

    // go: sdk 1.25.5 net/url/url.go:784-797 URL.setFragment
    fn setFragment(&mut self, f: string) -> error {
        let (frag, err) = unescape(f.clone(), EncodeFragment);
        if !err.IsNil() {
            return err;
        }
        self.Fragment = frag.clone();
        let escf = escape(frag, EncodeFragment);
        if f == escf {
            self.RawFragment = string::new();
        } else {
            self.RawFragment = f;
        }
        return nil.into();
    }
}

// go: sdk 1.25.5 net/url/url.go:1050-1112 resolvePath
/// Go: "resolvePath applies special path segments from refs and applies
/// them to base, per RFC 3986."
///
/// This is the dot-segment removal `ResolveReference` needs and goish
/// never had. Go's loop is deliberately written to keep a trailing
/// slash when the last element was "." or "..", which is why
/// `resolve "."` against `.../c/d;p` is `.../c/` and not `.../c`.
pub fn resolvePath(base: string, ref_: string) -> string {
    let full;
    if ref_.Len() == 0 {
        full = base;
    } else if ref_.as_bytes()[0] != b'/' {
        let i = strings::LastIndex(base.clone(), "/");
        full = base.slice(0, i + 1) + ref_;
    } else {
        full = ref_;
    }
    if full.Len() == 0 {
        return string::new();
    }

    let mut elem = string::new();
    let mut dst = strings::Builder::new();
    let mut first = true;
    let mut remaining = full;
    // Go: "We want to return a leading '/', so write it now."
    dst.WriteString("/");
    let mut found = true;
    while found {
        let (e, rest, f) = cut(&remaining, b'/');
        elem = e;
        remaining = rest;
        found = f;
        if elem == string::from_static(".") {
            first = false;
            // Go: drop
            continue;
        }
        if elem == string::from_static("..") {
            // Go: "Ignore the leading '/' we already wrote."
            let s = dst.String();
            let str_ = s.slice(1, s.Len());
            let index = strings::LastIndexByte(str_.clone(), b'/');
            dst = strings::Builder::new();
            dst.WriteString("/");
            if index == -1 {
                first = true;
            } else {
                dst.WriteString(str_.slice(0, index));
            }
        } else {
            if !first {
                dst.WriteString("/");
            }
            dst.WriteString(elem.clone());
            first = false;
        }
    }

    if elem == string::from_static(".") || elem == string::from_static("..") {
        dst.WriteString("/");
    }

    // Go: "We wrote an initial '/', but we don't want two."
    let r = dst.String();
    if r.Len() > 1 && r.as_bytes()[1] == b'/' {
        return r.slice(1, r.Len());
    }
    return r;
}

// go: sdk 1.25.5 net/url/url.go:760-781 validEncoded
/// Go: "reports whether s is a valid encoded path or fragment,
/// according to mode. It must not contain any bytes that require
/// escaping during encoding."
fn validEncoded(s: &string, mode: Encoding) -> bool {
    for &c in s.as_bytes() {
        match c {
            // Go: RFC 3986 Appendix A's sub-delims, ':' and '@' —
            // "shouldEscape is not quite compliant with the RFC, so we
            // check the sub-delims ourselves".
            b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'=' | b':'
            | b'@' => {}
            // Go: "ok - not specified in RFC 3986 but left alone by
            // modern browsers".
            b'[' | b']' => {}
            // Go: "ok - percent encoded, will decode".
            b'%' => {}
            _ => {
                if should_escape(c, mode) {
                    return false;
                }
            }
        }
    }
    return true;
}

// go: sdk 1.25.5 net/url/url.go:479-493 Parse
/// Go: "Parse parses a raw url into a URL structure. The url may be
/// relative (a path, without a host) or absolute (starting with a
/// scheme). Trying to parse a hostname and path without a scheme is
/// invalid but may not necessarily return an error, due to parsing
/// ambiguities."
pub fn Parse<S: Into<string>>(rawurl: S) -> (URL, error) {
    let rawurl: string = rawurl.into();
    // Go: u, frag, _ := strings.Cut(rawURL, "#")
    let (u_str, frag, had_frag) = cut(&rawurl, b'#');
    let (mut u, err) = parse(u_str.clone(), false);
    if !err.IsNil() {
        return (URL::default(), Error::new("parse", u_str, err));
    }
    if !had_frag || frag.Len() == 0 {
        return (u, nil.into());
    }
    let ferr = u.setFragment(frag);
    if !ferr.IsNil() {
        return (URL::default(), Error::new("parse", rawurl, ferr));
    }
    return (u, nil.into());
}

// go: sdk 1.25.5 net/url/url.go:500-506 ParseRequestURI
/// Go: "ParseRequestURI parses a raw url into a URL structure. It
/// assumes that url was received in an HTTP request, so the url is
/// interpreted only as an absolute URI or an absolute path. The string
/// url is assumed not to have a #fragment suffix."
pub fn ParseRequestURI<S: Into<string>>(rawurl: S) -> (URL, error) {
    let rawurl: string = rawurl.into();
    let (u, err) = parse(rawurl.clone(), true);
    if !err.IsNil() {
        return (URL::default(), Error::new("parse", rawurl, err));
    }
    return (u, nil.into());
}

// go: none — goish idiom: Go's `strings.Cut(s, sep)`, for a
//     single-byte separator. Returns (before, after, found).
fn cut(s: &string, sep: byte) -> (string, string, bool) {
    let i = strings::IndexByte(s.clone(), sep);
    if i < 0 {
        return (s.clone(), string::new(), false);
    }
    return (s.slice(0, i), s.slice(i + 1, s.Len()), true);
}

// go: sdk 1.25.5 net/url/url.go:449-471 getScheme
/// Go: split off a leading "http:", "mailto:" etc. An invalid character
/// means there is no scheme at all — NOT an error.
fn getScheme(rawurl: &string) -> (string, string, error) {
    let b = rawurl.as_bytes();
    let n = rawurl.Len();
    let mut i: int = 0;
    while i < n {
        let c = b[i as usize];
        if c.is_ascii_alphabetic() {
            // Go: do nothing
        } else if c.is_ascii_digit() || c == b'+' || c == b'-' || c == b'.' {
            if i == 0 {
                return (string::new(), rawurl.clone(), nil.into());
            }
        } else if c == b':' {
            if i == 0 {
                return (
                    string::new(),
                    string::new(),
                    errors::New("missing protocol scheme"),
                );
            }
            return (rawurl.slice(0, i), rawurl.slice(i + 1, n), nil.into());
        } else {
            // Go: "we have encountered an invalid character, so there is
            // no valid scheme"
            return (string::new(), rawurl.clone(), nil.into());
        }
        i += 1;
    }
    return (string::new(), rawurl.clone(), nil.into());
}

// go: sdk 1.25.5 net/url/url.go:512-590 parse
/// The shared body of [`Parse`] and [`ParseRequestURI`], ported from
/// Go step for step.
///
/// goish's had the same shape and a different order, and the order is
/// the whole thing: it cut the fragment inside `parse` rather than in
/// `Parse`, never split the query off before deciding what the rest
/// was, and only looked for an authority when a scheme was present. So
/// `//host/path` parsed with an EMPTY host and the authority left in
/// Path, `?query-only` put the query in Path, and `scheme:opaque?q=1`
/// kept the query inside Opaque.
fn parse(rawurl: string, via_request: bool) -> (URL, error) {
    // Go: if stringContainsCTLByte(rawURL) { … }
    if stringContainsCTLByte(&rawurl) {
        return (
            URL::default(),
            errors::New("net/url: invalid control character in URL"),
        );
    }
    if rawurl.Len() == 0 && via_request {
        return (URL::default(), errors::New("empty url"));
    }
    let mut url = URL::default();

    if rawurl == string::from_static("*") {
        url.Path = string::from_static("*");
        return (url, nil.into());
    }

    // Go: if url.Scheme, rest, err = getScheme(rawURL); err != nil
    let (scheme, mut rest, serr) = getScheme(&rawurl);
    if !serr.IsNil() {
        return (URL::default(), serr);
    }
    url.Scheme = strings::ToLower(scheme);

    // Go: a lone trailing '?' is ForceQuery, not an empty query.
    if strings::HasSuffix(rest.clone(), "?") && strings::Count(rest.clone(), "?") == 1 {
        url.ForceQuery = true;
        rest = rest.slice(0, rest.Len() - 1);
    } else {
        let (before, after, _) = cut(&rest, b'?');
        rest = before;
        url.RawQuery = after;
    }

    if !strings::HasPrefix(rest.clone(), "/") {
        if url.Scheme.Len() != 0 {
            // Go: "We consider rootless paths per RFC 3986 as opaque."
            url.Opaque = rest;
            return (url, nil.into());
        }
        if via_request {
            return (URL::default(), errors::New("invalid URI for request"));
        }
        // Go: "Avoid confusion with malformed schemes, like
        // cache_object:foo/bar." — RFC 3986 §3.3: the first segment of
        // a relative-path reference cannot contain a colon.
        let (segment, _, _) = cut(&rest, b'/');
        if strings::Contains(segment, ":") {
            return (
                URL::default(),
                errors::New("first path segment in URL cannot contain colon"),
            );
        }
    }

    // Go: if (url.Scheme != "" || !viaRequest && !strings.HasPrefix(rest, "///")) &&
    //         strings.HasPrefix(rest, "//")
    if (url.Scheme.Len() != 0 || (!via_request && !strings::HasPrefix(rest.clone(), "///")))
        && strings::HasPrefix(rest.clone(), "//")
    {
        let mut authority = rest.slice(2, rest.Len());
        rest = string::new();
        let i = strings::Index(authority.clone(), "/");
        if i >= 0 {
            rest = authority.slice(i, authority.Len());
            authority = authority.slice(0, i);
        }
        let (user, host, aerr) = parseAuthority(authority);
        if !aerr.IsNil() {
            return (URL::default(), aerr);
        }
        url.User = user;
        url.Host = host;
    } else if url.Scheme.Len() != 0 && strings::HasPrefix(rest.clone(), "/") {
        // Go: "OmitHost is set to true when rawURL has an empty host
        // (authority)."
        url.OmitHost = true;
    }

    // Go: set Path and, optionally, RawPath.
    let perr = url.setPath(rest);
    if !perr.IsNil() {
        return (URL::default(), perr);
    }
    return (url, nil.into());
}

// go: sdk 1.25.5 net/url/url.go:592-625 parseAuthority
fn parseAuthority(authority: string) -> (Userinfo, string, error) {
    let i = strings::LastIndex(authority.clone(), "@");
    let host_src = if i < 0 {
        authority.clone()
    } else {
        authority.slice(i + 1, authority.Len())
    };
    let (host, herr) = parseHost(host_src);
    if !herr.IsNil() {
        return (Userinfo::default(), string::new(), herr);
    }
    if i < 0 {
        return (Userinfo::default(), host, nil.into());
    }
    let userinfo = authority.slice(0, i);
    if !validUserinfo(&userinfo) {
        return (
            Userinfo::default(),
            string::new(),
            errors::New("net/url: invalid userinfo"),
        );
    }
    if !strings::Contains(userinfo.clone(), ":") {
        let (u, uerr) = unescape(userinfo, EncodeUserPassword);
        if !uerr.IsNil() {
            return (Userinfo::default(), string::new(), uerr);
        }
        return (User(u), host, nil.into());
    }
    let (uname, pw, _) = cut(&userinfo, b':');
    let (uname, uerr) = unescape(uname, EncodeUserPassword);
    if !uerr.IsNil() {
        return (Userinfo::default(), string::new(), uerr);
    }
    let (pw, perr) = unescape(pw, EncodeUserPassword);
    if !perr.IsNil() {
        return (Userinfo::default(), string::new(), perr);
    }
    return (UserPassword(uname, pw), host, nil.into());
}

// go: sdk 1.25.5 net/url/url.go:629-697 parseHost
/// Go: parse an IP-literal per RFC 3986 and RFC 6874, or an ordinary
/// host with an optional port.
///
/// goish never decoded the zone identifier, so `[fe80::1%25eth0]` kept
/// its `%25` in `Host` and `Hostname()` returned `fe80::1%25eth0`
/// instead of `fe80::1%eth0` — the escaped form where the caller wants
/// the real one.
// goishlint:ignore GOISH018 netip.ParseAddr — Go validates the bracketed
//     literal with `netip.ParseAddr` and rejects an IPv4 in brackets.
//     goish has no `net/netip` (0% ported), and `net`'s own `ParseIP`
//     would make `net/url` depend on `net`, which Go's does not. The
//     check here is the weaker "an IPv6 literal contains a colon",
//     which accepts every address Go accepts and a few malformed ones
//     Go would reject.
fn parseHost(host: string) -> (string, error) {
    let open_bracket = strings::LastIndex(host.clone(), "[");
    if open_bracket != -1 {
        let close_bracket = strings::LastIndex(host.clone(), "]");
        if close_bracket < 0 {
            return (string::new(), errors::New("missing ']' in host"));
        }
        let colon_port = host.slice(close_bracket + 1, host.Len());
        if !validOptionalPort(&colon_port) {
            return (
                string::new(),
                errors::New(
                    string::from_static("invalid port ")
                        + crate::fmt::Sprintf!("%q", colon_port.clone())
                        + string::from_static(" after host"),
                ),
            );
        }
        let (unescaped_colon_port, cerr) = unescape(colon_port, EncodeHost);
        if !cerr.IsNil() {
            return (string::new(), cerr);
        }
        let hostname = host.slice(open_bracket + 1, close_bracket);
        // Go: "RFC 6874 defines that %25 (%-encoded percent) introduces
        // the zone identifier, and the zone identifier can use basically
        // any %-encoding it likes."
        let zone_idx = strings::Index(hostname.clone(), "%25");
        let unescaped_hostname;
        if zone_idx >= 0 {
            let (host_part, e1) = unescape(hostname.slice(0, zone_idx), EncodeHost);
            if !e1.IsNil() {
                return (string::new(), e1);
            }
            let (zone_part, e2) = unescape(hostname.slice(zone_idx, hostname.Len()), EncodeZone);
            if !e2.IsNil() {
                return (string::new(), e2);
            }
            unescaped_hostname = host_part + zone_part;
        } else {
            let (h, e) = unescape(hostname, EncodeHost);
            if !e.IsNil() {
                return (string::new(), e);
            }
            unescaped_hostname = h;
        }
        // See the waiver above: Go asks netip.ParseAddr here.
        if !strings::Contains(unescaped_hostname.clone(), ":") {
            return (string::new(), errors::New("invalid IP-literal"));
        }
        return (
            string::from_static("[")
                + unescaped_hostname
                + string::from_static("]")
                + unescaped_colon_port,
            nil.into(),
        );
    } else {
        let i = strings::LastIndex(host.clone(), ":");
        if i != -1 {
            let colon_port = host.slice(i, host.Len());
            if !validOptionalPort(&colon_port) {
                return (
                    string::new(),
                    errors::New(
                        string::from_static("invalid port ")
                            + crate::fmt::Sprintf!("%q", colon_port.clone())
                            + string::from_static(" after host"),
                    ),
                );
            }
        }
    }
    let (h, e) = unescape(host, EncodeHost);
    if !e.IsNil() {
        return (string::new(), e);
    }
    return (h, nil.into());
}

// go: sdk 1.25.5 net/url/url.go:819-832 validOptionalPort
/// Go: "reports whether port is either an empty string or matches
/// /^:\d*$/".
fn validOptionalPort(port: &string) -> bool {
    if port.Len() == 0 {
        return true;
    }
    let b = port.as_bytes();
    if b[0] != b':' {
        return false;
    }
    let mut i = 1usize;
    while i < b.len() {
        if b[i] < b'0' || b[i] > b'9' {
            return false;
        }
        i += 1;
    }
    return true;
}

// go: sdk 1.25.5 net/url/url.go:1292-1323 validUserinfo
/// Go: "reports whether s is a valid userinfo string per RFC 3986."
/// Note Go's deliberate exception for '@', which RFC 3986 forbids —
/// see go.dev/issue/3439 and go.dev/issue/22655.
fn validUserinfo(s: &string) -> bool {
    // Go ranges over RUNES; every character it allows is ASCII, and a
    // multi-byte rune is rejected either way, so a byte walk agrees.
    for &r in s.as_bytes() {
        if r.is_ascii_alphanumeric() {
            continue;
        }
        match r {
            b'-' | b'.' | b'_' | b':' | b'~' | b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*'
            | b'+' | b',' | b';' | b'=' | b'%' | b'@' => continue,
            _ => return false,
        }
    }
    return true;
}

// go: sdk 1.25.5 net/url/url.go:1326-1334 stringContainsCTLByte
fn stringContainsCTLByte(s: &string) -> bool {
    for &b in s.as_bytes() {
        if b < b' ' || b == 0x7f {
            return true;
        }
    }
    return false;
}

// go: sdk 1.25.5 net/url/url.go:1224-1237 splitHostPort
/// Go: "separates host and port. If the port is not valid, it returns
/// the entire input as host, and it doesn't check the validity of the
/// host. Unlike net.SplitHostPort, but per RFC 3986, it requires ports
/// to be numeric."
fn splitHostPort(host_port: &string) -> (string, string) {
    let mut host = host_port.clone();
    let mut port = string::new();
    let colon = strings::LastIndexByte(host.clone(), b':');
    if colon != -1 && validOptionalPort(&host.slice(colon, host.Len())) {
        port = host.slice(colon + 1, host.Len());
        host = host.slice(0, colon);
    }
    if strings::HasPrefix(host.clone(), "[") && strings::HasSuffix(host.clone(), "]") {
        host = host.slice(1, host.Len() - 1);
    }
    return (host, port);
}

// ─── Values / query parsing ──────────────────────────────────────────

/// `url.Values` (url.go:858) — map[string][]string for query parameters.
pub type Values = gomap::map<string, slice<string>>;
// go: sdk 1.25.5 net/url/url.go:989-993 ParseQuery
/// Go: "ParseQuery parses the URL-encoded query string and returns a
/// map listing the values specified for each key. ParseQuery always
/// returns a non-nil map containing all the valid query parameters
/// found; err describes the first decoding error encountered, if any.
///
/// Query is expected to be a list of key=value settings separated by
/// ampersands. A setting without an equals sign is interpreted as a key
/// set to an empty value. Settings containing a non-URL-encoded
/// semicolon are considered invalid."
pub fn ParseQuery<S: Into<string>>(query: S) -> (Values, error) {
    let mut m = Values::new();
    let err = parseQuery(&mut m, query.into());
    return (m, err);
}

// go: sdk 1.25.5 net/url/url.go:995-1024 parseQuery
/// goish's version split on `;` as WELL as `&`, which is the behaviour
/// Go removed in 1.17 (CVE-2021-... class: a proxy and an origin that
/// disagree about the separator disagree about the request). Go now
/// REJECTS a setting containing a semicolon and drops it. goish also
/// dropped a setting with an empty key, where Go keeps `=1` as the
/// empty key mapped to "1", and it kept the values it had already
/// decoded when a later one failed, where Go drops only the failing
/// setting and reports the FIRST error.
fn parseQuery(m: &mut Values, query: string) -> error {
    let mut err: error = nil.into();
    let mut query = query;
    while query.Len() != 0 {
        // Go: key, query, _ = strings.Cut(query, "&")
        let (mut key, rest, _) = cut(&query, b'&');
        query = rest;
        if strings::Contains(key.clone(), ";") {
            if err.IsNil() {
                err = errors::New("invalid semicolon separator in query");
            }
            continue;
        }
        if key.Len() == 0 {
            continue;
        }
        // Go: key, value, _ := strings.Cut(key, "=")
        let (k, value, _) = cut(&key, b'=');
        key = k;
        let (key_dec, err1) = QueryUnescape(key);
        if !err1.IsNil() {
            if err.IsNil() {
                err = err1;
            }
            continue;
        }
        let (value_dec, err2) = QueryUnescape(value);
        if !err2.IsNil() {
            if err.IsNil() {
                err = err2;
            }
            continue;
        }
        // Go: m[key] = append(m[key], value)
        let (existing, ok) = m.Get(key_dec.clone());
        let mut v: Vec<string> = Vec::new();
        if ok {
            for j in 0..existing.Len() {
                v.push(existing[j].clone());
            }
        }
        v.push(value_dec);
        m.Set(key_dec, slice::__from_vec(v));
    }
    return err;
}

// go: none — goish idiom: an ordered-map variant of `ParseQuery` this
//     tree's HTTP code uses; Go has no counterpart.
/// `ParseQueryValues(query)` — parses into an ordered map.
pub fn ParseQueryValues<S: Into<string>>(query: S) -> (Values, error) {
    return ParseQuery(query);
}

// ─── Values helper functions ─────────────────────────────────────────

// go: none — goish idiom: Go's `Values` is a NAMED map type with methods; goish's is a type alias, so the same method is a free function.
/// `v.Get(key)` (url.go:920) — returns the first value for key, or "".
pub fn ValuesGet(v: &Values, key: string) -> string {
    let (vals, ok) = v.Get(key);
    if !ok || vals.Len() == 0 {
        return string::new();
    }
    return vals[0].clone();
}

// go: none — goish idiom: see `ValuesGet`.
/// `v.Set(key, value)` (url.go:930) — sets key to single value.
pub fn ValuesSet(v: &mut Values, key: string, value: string) {
    let mut s = Vec::with_capacity(1);
    s.push(value);
    v.Set(key, slice::__from_vec(s));
}

// go: none — goish idiom: see `ValuesGet`.
/// `v.Add(key, value)` (url.go:940) — appends value to key's slice.
pub fn ValuesAdd(v: &mut Values, key: string, value: string) {
    let (existing, ok) = v.Get(key.clone());
    if ok {
        let mut s = Vec::with_capacity(existing.Len() as usize + 1);
        for j in 0..existing.Len() {
            s.push(existing[j].clone());
        }
        s.push(value);
        v.Set(key, slice::__from_vec(s));
    } else {
        let mut s = Vec::with_capacity(1);
        s.push(value);
        v.Set(key, slice::__from_vec(s));
    }
}

// go: none — goish idiom: see `ValuesGet`.
/// `v.Del(key)` (url.go:950) — deletes the key.
pub fn ValuesDel(v: &mut Values, key: string) {
    v.Delete(key);
}

// go: none — goish idiom: see `ValuesGet`.
/// `v.Has(key)` (url.go:960) — reports whether key exists.
pub fn ValuesHas(v: &Values, key: string) -> bool {
    return v.Has(key);
}

// go: none — goish idiom: a goish-only helper; see the ported functions it serves.
// go: sdk 1.25.5 net/url/url.go:1028-1046 Values.Encode
/// Go: "Encode encodes the values into 'URL encoded' form
/// ('bar=baz&foo=quux') sorted by key." The sort is what makes the
/// output reproducible, since a map's iteration order is randomised.
pub fn ValuesEncode(v: &Values) -> string {
    let mut buf = strings::Builder::new();
    let mut keys: Vec<string> = Vec::new();
    for (k, _) in v.__iter() {
        keys.push(k.clone());
    }
    keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

    let mut first = true;
    for key in keys {
        let (vals, _) = v.Get(key.clone());
        for j in 0..vals.Len() {
            if !first {
                buf.WriteString("&");
            }
            first = false;
            buf.WriteString(QueryEscape(key.clone()));
            buf.WriteString("=");
            buf.WriteString(QueryEscape(vals[j].clone()));
        }
    }
    return buf.String();
}

// go: sdk 1.25.5 net/url/url.go:1338-1345 JoinPath
/// Go: "JoinPath returns a URL string with the provided path elements
/// joined to the existing path of base and the resulting path cleaned
/// of any ./ or ../ elements."
pub fn JoinPath<B: Into<string>>(base: B, elem: slice<string>) -> (string, error) {
    let (url, err) = Parse(base.into());
    if !err.IsNil() {
        return (string::new(), err);
    }
    return (url.JoinPath(elem).String(), nil.into());
}
