// go: file mime/mediatype.go decls: FormatMediaType, checkMediaTypeDisposition, ErrInvalidMediaParameter, ParseMediaType, decode2231Enc, consumeToken, consumeValue, consumeMediaParam, percentHexUnescape, ishex, unhex
//
// `ErrInvalidMediaParameter` is a package-level `var` in Go, not a
// func. It is listed in the manifest anyway because goish spells it as
// a `fn` — `errors::New` is not `const` — and GOISH017 matches a
// manifest entry against Rust `fn` items.
//
// mime/mediatype.go — RFC 1521 / RFC 2045 media types, as they appear
// in Content-Type and Content-Disposition headers (RFC 2183).
//
// Most of the file is the RFC 2231 continuation machinery: a parameter
// whose value is too long, or not ASCII, may be split across
// `name*0`, `name*1`, … and any piece may be percent-encoded by
// suffixing a further `*`. `ParseMediaType` therefore parses into two
// maps — the plain parameters, and a per-base-name map of the starred
// pieces — and stitches the second into the first at the end.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;
use alloc::vec::Vec;

use crate::errors::{self, error};
use crate::gomap::map;
use crate::gostring::string;
use crate::strings;
use crate::types::{byte, int};

use super::grammar::{isTSpecial, isToken, isTokenChar};

// go: none — goish idiom: mediatype.go reads `upperhex` from
//     encodedword.go, in the same Go package. GOISH015 gives each Go
//     file its own Rust file, so the constant is spelled here too
//     rather than making one file reach into the other's private half.
const upperhex: &[byte] = b"0123456789ABCDEF";

// go: sdk 1.25.5 mime/mediatype.go:16-93 FormatMediaType
/// Serialises media type `t` and the parameters `param` as a media type
/// conforming to RFC 2045 and RFC 2616.
///
/// The type and parameter names are written in lower case. Any argument
/// that would produce a standard violation makes this return "".
pub fn FormatMediaType<T: Into<string>>(t: T, param: map<string, string>) -> string {
    let t: string = t.into();
    let mut b = strings::Builder::new();
    let (major, sub, ok) = strings::Cut(t.clone(), "/");
    if !ok {
        if !isToken(t.clone()) {
            return string::new();
        }
        let _ = b.WriteString(strings::ToLower(t.clone()));
    } else {
        if !isToken(major.clone()) || !isToken(sub.clone()) {
            return string::new();
        }
        let _ = b.WriteString(strings::ToLower(major));
        let _ = b.WriteByte(b'/');
        let _ = b.WriteString(strings::ToLower(sub));
    }

    // Go: for _, attribute := range slices.Sorted(maps.Keys(param))
    let mut attributes: Vec<string> = Vec::new();
    for (k, _) in param.__iter() {
        attributes.push(k.clone());
    }
    attributes.sort_by(|a, c| a.as_bytes().cmp(c.as_bytes()));

    for attribute in attributes.iter() {
        let (value, _) = param.Get(attribute.clone());
        let _ = b.WriteByte(b';');
        let _ = b.WriteByte(b' ');
        if !isToken(attribute.clone()) {
            return string::new();
        }
        let _ = b.WriteString(strings::ToLower(attribute.clone()));

        let needEnc = needsEncoding(&value);
        if needEnc {
            // RFC 2231 section 4
            let _ = b.WriteByte(b'*');
        }
        let _ = b.WriteByte(b'=');

        let raw = value.as_bytes();
        if needEnc {
            let _ = b.WriteString("utf-8''");

            let mut offset: usize = 0;
            let mut index: usize = 0;
            while index < raw.len() {
                let ch = raw[index];
                // {RFC 2231 section 7}
                // attribute-char := <any (US-ASCII) CHAR except SPACE,
                //                    CTLs, "*", "'", "%", or tspecials>
                if ch <= b' '
                    || ch >= 0x7F
                    || ch == b'*'
                    || ch == b'\''
                    || ch == b'%'
                    || isTSpecial(ch)
                {
                    let _ = b.WriteString(string::from_bytes(&raw[offset..index]));
                    offset = index + 1;

                    let _ = b.WriteByte(b'%');
                    let _ = b.WriteByte(upperhex[(ch >> 4) as usize]);
                    let _ = b.WriteByte(upperhex[(ch & 0x0F) as usize]);
                }
                index += 1;
            }
            let _ = b.WriteString(string::from_bytes(&raw[offset..]));
            continue;
        }

        if isToken(value.clone()) {
            let _ = b.WriteString(value.clone());
            continue;
        }

        let _ = b.WriteByte(b'"');
        let mut offset: usize = 0;
        let mut index: usize = 0;
        while index < raw.len() {
            let character = raw[index];
            if character == b'"' || character == b'\\' {
                let _ = b.WriteString(string::from_bytes(&raw[offset..index]));
                offset = index;
                let _ = b.WriteByte(b'\\');
            }
            index += 1;
        }
        let _ = b.WriteString(string::from_bytes(&raw[offset..]));
        let _ = b.WriteByte(b'"');
    }
    return b.String();
}

// go: none — goish idiom: `needsEncoding` lives in encodedword.go, in
//     the same Go package. GOISH015 gives each Go file its own Rust
//     file, so `FormatMediaType`'s one caller re-states the three-line
//     test rather than reaching into encodedword.rs's private half.
fn needsEncoding(s: &string) -> bool {
    for b in s.as_bytes().iter() {
        if (*b < b' ' || *b > b'~') && *b != b'\t' {
            return true;
        }
    }
    return false;
}

// go: sdk 1.25.5 mime/mediatype.go:95-114 checkMediaTypeDisposition
fn checkMediaTypeDisposition(s: string) -> error {
    let (typ, rest) = consumeToken(s);
    if typ.Len() == 0 {
        return errors::New(string::from_static("mime: no media type"));
    }
    if rest.Len() == 0 {
        return errors::nil;
    }
    if !strings::HasPrefix(rest.clone(), "/") {
        return errors::New(string::from_static(
            "mime: expected slash after first token",
        ));
    }
    let (subtype, rest) = consumeToken(string::from_bytes(&rest.as_bytes()[1..]));
    if subtype.Len() == 0 {
        return errors::New(string::from_static("mime: expected token after slash"));
    }
    if rest.Len() != 0 {
        return errors::New(string::from_static(
            "mime: unexpected content after media subtype",
        ));
    }
    return errors::nil;
}

// go: sdk 1.25.5 mime/mediatype.go:116-119 ErrInvalidMediaParameter
/// Returned by [`ParseMediaType`] when the media type value was found
/// but its optional parameters would not parse.
///
/// Go declares this as a package-level `var`; goish spells it as a
/// function because `errors::New` is not `const`.
pub fn ErrInvalidMediaParameter() -> error {
    return errors::New(string::from_static("mime: invalid media parameter"));
}

// go: sdk 1.25.5 mime/mediatype.go:121-225 ParseMediaType
/// Parses a media type value and any optional parameters, per RFC 1521.
///
/// On success returns the media type lower-cased and trimmed of white
/// space, and a non-nil map from the lower-cased attribute to the
/// attribute value with its case preserved. If the optional parameters
/// fail to parse, the media type comes back alongside
/// [`ErrInvalidMediaParameter`].
pub fn ParseMediaType<V: Into<string>>(v: V) -> (string, map<string, string>, error) {
    let mut v: string = v.into();
    let (base, _, _) = strings::Cut(v.clone(), ";");
    let mediatype = strings::TrimSpace(strings::ToLower(base.clone()));

    let err = checkMediaTypeDisposition(mediatype.clone());
    if !err.IsNil() {
        return (string::new(), map::new(), err);
    }

    let mut params: map<string, string> = map::new();

    // Map of base parameter name -> parameter name -> value, for
    // parameters containing a '*'. Go initialises it lazily.
    let mut continuation: map<string, map<string, string>> = map::new();

    v = string::from_bytes(&v.as_bytes()[base.Len() as usize..]);
    while v.Len() > 0 {
        v = strings::TrimLeftFunc(v.clone(), |r| {
            return crate::unicode::IsSpace(r);
        });
        if v.Len() == 0 {
            break;
        }
        let (key, value, rest) = consumeMediaParam(v.clone());
        if key.Len() == 0 {
            if strings::TrimSpace(rest.clone()) == string::from_static(";") {
                // Ignore trailing semicolons. Not an error.
                break;
            }
            // Parse error.
            return (mediatype, map::new(), ErrInvalidMediaParameter());
        }

        // Go: pmap := params; if baseName, _, ok := strings.Cut(key, "*"); ok { … }
        //
        // Go aliases `pmap` to one of the two maps; goish cannot hold
        // two mutable aliases, so the branch is on which map to touch.
        let (baseName, _, starred) = strings::Cut(key.clone(), "*");
        if starred {
            if !continuation.Has(baseName.clone()) {
                continuation.Set(baseName.clone(), map::new());
            }
            let (mut pmap, _) = continuation.Get(baseName.clone());
            let (existing, exists) = pmap.Get(key.clone());
            if exists && existing != value {
                // Duplicate parameter names are incorrect, but Go
                // allows them when the values are equal.
                return (
                    string::new(),
                    map::new(),
                    errors::New(string::from_static("mime: duplicate parameter name")),
                );
            }
            pmap.Set(key.clone(), value.clone());
            continuation.Set(baseName, pmap);
        } else {
            let (existing, exists) = params.Get(key.clone());
            if exists && existing != value {
                return (
                    string::new(),
                    map::new(),
                    errors::New(string::from_static("mime: duplicate parameter name")),
                );
            }
            params.Set(key.clone(), value.clone());
        }
        v = rest;
    }

    // Stitch together any continuations or things with stars — RFC 2231
    // things with stars: "foo*0" or "foo*".
    let mut cont_keys: Vec<string> = Vec::new();
    for (k, _) in continuation.__iter() {
        cont_keys.push(k.clone());
    }
    for key in cont_keys.iter() {
        let (pieceMap, _) = continuation.Get(key.clone());
        let mut singlePartKey = key.clone();
        singlePartKey = singlePartKey + string::from_static("*");
        let (single, ok) = pieceMap.Get(singlePartKey.clone());
        if ok {
            let (decv, ok) = decode2231Enc(single);
            if ok {
                params.Set(key.clone(), decv);
            }
            continue;
        }

        // Go declares one `buf` outside the loop and `Reset()`s it here
        // to reuse the allocation; goish's `Builder::String` consumes
        // the builder, so each round gets a fresh one. Same contents.
        let mut buf = strings::Builder::new();
        let mut valid = false;
        let mut n: int = 0;
        loop {
            // Go: simplePart := fmt.Sprintf("%s*%d", key, n)
            let simplePart = key.clone() + string::from_static("*") + crate::strconv::Itoa(n);
            let (piece, ok) = pieceMap.Get(simplePart.clone());
            if ok {
                valid = true;
                let _ = buf.WriteString(piece);
                n += 1;
                continue;
            }
            let encodedPart = simplePart + string::from_static("*");
            let (piece, ok) = pieceMap.Get(encodedPart);
            if !ok {
                break;
            }
            valid = true;
            if n == 0 {
                let (decv, ok) = decode2231Enc(piece);
                if ok {
                    let _ = buf.WriteString(decv);
                }
            } else {
                let (decv, _) = percentHexUnescape(piece);
                let _ = buf.WriteString(decv);
            }
            n += 1;
        }
        if valid {
            params.Set(key.clone(), buf.String());
        }
    }

    return (mediatype, params, errors::nil);
}

// go: sdk 1.25.5 mime/mediatype.go:227-248 decode2231Enc
fn decode2231Enc(v: string) -> (string, bool) {
    let sv = strings::SplitN(v, "'", 3);
    if sv.Len() != 3 {
        return (string::new(), false);
    }
    // Go: TODO — ignoring lang in sv[1] for now.
    let charset = strings::ToLower(sv[0].clone());
    if charset.Len() == 0 {
        return (string::new(), false);
    }
    if charset != string::from_static("us-ascii") && charset != string::from_static("utf-8") {
        // Go: TODO — unsupported encoding.
        return (string::new(), false);
    }
    let (encv, err) = percentHexUnescape(sv[2].clone());
    if !err.IsNil() {
        return (string::new(), false);
    }
    return (encv, true);
}

// go: sdk 1.25.5 mime/mediatype.go:250-259 consumeToken
/// Consumes a token from the front of `v`, per RFC 2045 §5.1
/// (referenced from RFC 2183), returning the token and the rest.
/// Returns `("", v)` when it cannot consume even one character.
fn consumeToken(v: string) -> (string, string) {
    let raw = v.as_bytes();
    let mut i = 0usize;
    while i < raw.len() {
        if !isTokenChar(raw[i]) {
            return (string::from_bytes(&raw[..i]), string::from_bytes(&raw[i..]));
        }
        i += 1;
    }
    return (v.clone(), string::new());
}

// go: sdk 1.25.5 mime/mediatype.go:261-299 consumeValue
/// Consumes a "value" per RFC 2045 — either a token or a
/// quoted-string — returning it de-quoted and unescaped along with the
/// rest. Returns `("", v)` on failure.
fn consumeValue(v: string) -> (string, string) {
    if v.Len() == 0 {
        return (string::new(), string::new());
    }
    let raw = v.as_bytes();
    if raw[0] != b'"' {
        return consumeToken(v);
    }

    // Parse a quoted-string.
    let mut buffer = strings::Builder::new();
    let mut i = 1usize;
    while i < raw.len() {
        let r = raw[i];
        if r == b'"' {
            return (buffer.String(), string::from_bytes(&raw[i + 1..]));
        }
        // When MSIE sends a full file path (in "intranet mode") it does
        // not escape backslashes: "C:\dev\go\foo.txt", not
        // "C:\\dev\\go\\foo.txt". No known MIME generator emits an
        // unnecessary backslash escape for a plain token character, so
        // an unnecessary one is assumed to be MSIE's literal backslash.
        if r == b'\\' && i + 1 < raw.len() && isTSpecial(raw[i + 1]) {
            let _ = buffer.WriteByte(raw[i + 1]);
            i += 2;
            continue;
        }
        if r == b'\r' || r == b'\n' {
            return (string::new(), v.clone());
        }
        let _ = buffer.WriteByte(raw[i]);
        i += 1;
    }
    // Did not find end quote.
    return (string::new(), v.clone());
}

// go: sdk 1.25.5 mime/mediatype.go:301-324 consumeMediaParam
fn consumeMediaParam(v: string) -> (string, string, string) {
    let mut rest = strings::TrimLeftFunc(v.clone(), |r| {
        return crate::unicode::IsSpace(r);
    });
    if !strings::HasPrefix(rest.clone(), ";") {
        return (string::new(), string::new(), v);
    }

    // Consume the semicolon.
    rest = string::from_bytes(&rest.as_bytes()[1..]);
    rest = strings::TrimLeftFunc(rest, |r| {
        return crate::unicode::IsSpace(r);
    });
    let (param, r2) = consumeToken(rest);
    let param = strings::ToLower(param);
    rest = r2;
    if param.Len() == 0 {
        return (string::new(), string::new(), v);
    }

    rest = strings::TrimLeftFunc(rest, |r| {
        return crate::unicode::IsSpace(r);
    });
    if !strings::HasPrefix(rest.clone(), "=") {
        return (string::new(), string::new(), v);
    }
    // Consume the equals sign.
    rest = string::from_bytes(&rest.as_bytes()[1..]);
    rest = strings::TrimLeftFunc(rest, |r| {
        return crate::unicode::IsSpace(r);
    });
    let (value, rest2) = consumeValue(rest.clone());
    if value.Len() == 0 && rest2 == rest {
        return (string::new(), string::new(), v);
    }
    return (param, value, rest2);
}

// go: sdk 1.25.5 mime/mediatype.go:326-364 percentHexUnescape
fn percentHexUnescape(s: string) -> (string, error) {
    let raw = s.as_bytes();
    // Count %, and check that each is well formed.
    let mut percents = 0usize;
    let mut i = 0usize;
    while i < raw.len() {
        if raw[i] != b'%' {
            i += 1;
            continue;
        }
        percents += 1;
        if i + 2 >= raw.len() || !ishex(raw[i + 1]) || !ishex(raw[i + 2]) {
            let mut bad = &raw[i..];
            if bad.len() > 3 {
                bad = &bad[..3];
            }
            return (
                string::new(),
                crate::fmt::Errorf!(
                    "mime: bogus characters after %%: %q",
                    string::from_bytes(bad)
                ),
            );
        }
        i += 3;
    }
    if percents == 0 {
        return (s, errors::nil);
    }

    let mut t: Vec<byte> = alloc::vec![0; raw.len() - 2 * percents];
    let mut j = 0usize;
    let mut i = 0usize;
    while i < raw.len() {
        if raw[i] == b'%' {
            t[j] = unhex(raw[i + 1]) << 4 | unhex(raw[i + 2]);
            j += 1;
            i += 3;
        } else {
            t[j] = raw[i];
            j += 1;
            i += 1;
        }
    }
    return (string::from_bytes(&t), errors::nil);
}

// go: sdk 1.25.5 mime/mediatype.go:366-376 ishex
fn ishex(c: byte) -> bool {
    if b'0' <= c && c <= b'9' {
        return true;
    }
    if b'a' <= c && c <= b'f' {
        return true;
    }
    if b'A' <= c && c <= b'F' {
        return true;
    }
    return false;
}

// go: sdk 1.25.5 mime/mediatype.go:378-389 unhex
fn unhex(c: byte) -> byte {
    if b'0' <= c && c <= b'9' {
        return c - b'0';
    }
    if b'a' <= c && c <= b'f' {
        return c - b'a' + 10;
    }
    if b'A' <= c && c <= b'F' {
        return c - b'A' + 10;
    }
    return 0;
}
