// badutf8_ref_smoke — what seven packages do with a string that is not
// valid UTF-8, against a running Go 1.25.5 via scripts/goref.sh.
//
// A Go string is a byte sequence. `string(b)` for any []byte is legal,
// and a byte-offset slice can cut a multi-byte rune in half, so every
// package that decodes runes has to answer for these inputs. Go's
// answer is uniform: a byte that cannot begin or continue a sequence
// decodes to U+FFFD and advances exactly one byte. What differs is
// whether a package DECODES at all — `%s`, `%x` and Quote pass the
// bytes through untouched, while ToUpper, Map and json.Marshal decode
// and therefore substitute.
//
// That split is the reason for pinning both kinds side by side:
//
//   Quote("a\xffb")   -> "a\xffb"      bytes preserved, escaped
//   ToUpper("a\xffb") -> "A\uFFFDB"    decoded, byte replaced
//   json("a\xffb")    -> "a\ufffdb"    decoded, byte replaced
//
// Getting one of those to behave like the other is a plausible mistake
// and a silent one — no error is returned on either path.
//
// All 36 lines matched Go on the first run; nothing here is a fix.
// They are pinned because three defects in this exact area were found
// and fixed just before it (the utf8 *InString signatures, xxh3
// hashing a truncated prefix, and strings.SplitSeq advancing by a
// leading-byte length table), and because in each case a passing test
// already existed whose inputs could not reach the fault.
#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::encoding::json;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::net::url;
use goish::regexp;
use goish::strconv;
use goish::strings;
use goish::types::{byte, int, rune};
use goish::unicode;
use goish::unicode::utf8;

const GO: [&str; 35] = [
    "q-bad                  \"a\\xffb\"",
    "q-trunc                \"\\xe4\\xb8\"",
    "q-lone                 \"\\xff\"",
    "s-bad                  61ff62",
    "x-bad                  61ff62",
    "plusq-bad              \"a\\xffb\"",
    "Quote-bad              \"a\\xffb\"",
    "QuoteToASCII           \"a\\xffb\"",
    "CanBackquote           false",
    "ToUpper-bad            41efbfbd42",
    "ToLower-trunc          efbfbdefbfbd",
    "Map-identity           61efbfbd62",
    "Map-drop-bad           6162",
    "TrimFunc               61ff62",
    "IndexFunc              1",
    "Fields-trunc           1",
    "EqualFold              true",
    "ContainsRune           true",
    "ToValidUTF8            a?b",
    "json-bad               22615c75666666646222 err=<nil>",
    "json-trunc             225c75666666645c756666666422 err=<nil>",
    "quote-roundtrip          61ff62 err=<nil> same=true",
    "unquote-hex              ff err=<nil>",
    "QueryEscape              a%FFb",
    "QueryUnescape            61ff62 err=<nil>",
    "PathEscape               a%FFb",
    "re-findall               3",
    "re-dot-matches-bad       true",
    "re-fffd-matches          true",
    "re-trunc-count           2",
    "replace-ff               615a62",
    "split-on-ff              2",
    "index-ff                 1",
    "count-empty-bad          4",
    "runecount-vs-len         3 3",
];

fn chk(ln: &mut usize, got: &string) {
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln as int + 1, got);
        *ln += 1;
        return;
    }
    if got == GO[*ln] {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        fmt::Printf!("[!!] line %d\n  got  %q\n  want %q\n", *ln as int + 1, got, GO[*ln]);
    }
    *ln += 1;
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;

    let bad = string::from_bytes(&[0x61, 0xff, 0x62]);
    let trunc = string::from_bytes(&[0xe4, 0xb8]);
    let lone = string::from_bytes(&[0xff]);

    chk(&mut ln, &fmt::Sprintf!("%-22s %s", "q-bad", fmt::Sprintf!("%q", &bad)));
    chk(&mut ln, &fmt::Sprintf!("%-22s %s", "q-trunc", fmt::Sprintf!("%q", &trunc)));
    chk(&mut ln, &fmt::Sprintf!("%-22s %s", "q-lone", fmt::Sprintf!("%q", &lone)));
    chk(&mut ln, &fmt::Sprintf!("%-22s %x", "s-bad", fmt::Sprintf!("%s", &bad)));
    chk(&mut ln, &fmt::Sprintf!("%-22s %s", "x-bad", fmt::Sprintf!("%x", &bad)));
    chk(&mut ln, &fmt::Sprintf!("%-22s %s", "plusq-bad", fmt::Sprintf!("%+q", &bad)));

    chk(&mut ln, &fmt::Sprintf!("%-22s %s", "Quote-bad", strconv::Quote(&bad)));
    chk(&mut ln, &fmt::Sprintf!("%-22s %s", "QuoteToASCII", strconv::QuoteToASCII(&bad)));
    chk(&mut ln, &fmt::Sprintf!("%-22s %v", "CanBackquote", strconv::CanBackquote(&bad)));

    chk(&mut ln, &fmt::Sprintf!("%-22s %x", "ToUpper-bad", strings::ToUpper(&bad)));
    chk(&mut ln, &fmt::Sprintf!("%-22s %x", "ToLower-trunc", strings::ToLower(&trunc)));
    chk(&mut ln, &fmt::Sprintf!("%-22s %x", "Map-identity", strings::Map(|r: rune| -> rune { return r; }, &bad)));
    chk(&mut ln, &fmt::Sprintf!("%-22s %x", "Map-drop-bad", strings::Map(|r: rune| -> rune {
        if r == 0xFFFD { return -1; }
        return r;
    }, &bad)));
    chk(&mut ln, &fmt::Sprintf!("%-22s %x", "TrimFunc",
        strings::TrimFunc(&bad, |r: rune| -> bool { return !unicode::IsLetter(r); })));
    chk(&mut ln, &fmt::Sprintf!("%-22s %d", "IndexFunc",
        strings::IndexFunc(&bad, |r: rune| -> bool { return r == 0xFFFD; })));
    chk(&mut ln, &fmt::Sprintf!("%-22s %v", "Fields-trunc", strings::Fields(&trunc).Len() as int));
    chk(&mut ln, &fmt::Sprintf!("%-22s %v", "EqualFold", strings::EqualFold(&bad, &bad)));
    chk(&mut ln, &fmt::Sprintf!("%-22s %v", "ContainsRune", strings::ContainsRune(&bad, 0xFFFD)));
    chk(&mut ln, &fmt::Sprintf!("%-22s %v", "ToValidUTF8", strings::ToValidUTF8(&bad, "?")));

    let (b, err) = json::Marshal(&bad);
    chk(&mut ln, &fmt::Sprintf!("%-22s %x err=%v", "json-bad", b, err));
    let (b, err) = json::Marshal(&trunc);
    chk(&mut ln, &fmt::Sprintf!("%-22s %x err=%v", "json-trunc", b, err));

    let bad = string::from_bytes(&[0x61, 0xff, 0x62]);
    let trunc = string::from_bytes(&[0xe4, 0xb8]);
    let ff = string::from_bytes(&[0xff]);

    let q = strconv::Quote(&bad);
    let (u, err) = strconv::Unquote(&q);
    chk(&mut ln, &fmt::Sprintf!("%-24s %x err=%v same=%v", "quote-roundtrip", &u, err, u == bad));
    let (u2, err2) = strconv::Unquote("\"\\xff\"");
    chk(&mut ln, &fmt::Sprintf!("%-24s %x err=%v", "unquote-hex", u2, err2));

    chk(&mut ln, &fmt::Sprintf!("%-24s %s", "QueryEscape", url::QueryEscape(&bad)));
    let (v, err) = url::QueryUnescape("a%FFb");
    chk(&mut ln, &fmt::Sprintf!("%-24s %x err=%v", "QueryUnescape", v, err));
    chk(&mut ln, &fmt::Sprintf!("%-24s %s", "PathEscape", url::PathEscape(&bad)));

    let re = regexp::MustCompile(".");
    chk(&mut ln, &fmt::Sprintf!("%-24s %v", "re-findall", re.FindAllString(&bad, -1).Len() as int));
    let re2 = regexp::MustCompile("a.b");
    chk(&mut ln, &fmt::Sprintf!("%-24s %v", "re-dot-matches-bad", re2.MatchString(&bad)));
    let re3 = regexp::MustCompile("^a\\x{FFFD}b$");
    chk(&mut ln, &fmt::Sprintf!("%-24s %v", "re-fffd-matches", re3.MatchString(&bad)));
    chk(&mut ln, &fmt::Sprintf!("%-24s %v", "re-trunc-count",
        regexp::MustCompile(".").FindAllString(&trunc, -1).Len() as int));

    chk(&mut ln, &fmt::Sprintf!("%-24s %x", "replace-ff", strings::ReplaceAll(&bad, &ff, "Z")));
    chk(&mut ln, &fmt::Sprintf!("%-24s %v", "split-on-ff", strings::Split(&bad, &ff).Len() as int));
    chk(&mut ln, &fmt::Sprintf!("%-24s %v", "index-ff", strings::Index(&bad, &ff)));
    chk(&mut ln, &fmt::Sprintf!("%-24s %v", "count-empty-bad", strings::Count(&bad, "")));
    chk(&mut ln, &fmt::Sprintf!("%-24s %v %v", "runecount-vs-len",
        utf8::RuneCountInString(&bad), bad.Len()));
    if ln != GO.len() {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln as int, GO.len() as int);
    }
}
