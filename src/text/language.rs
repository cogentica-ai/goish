// text/language — BCP 47 language tags + matching, ported from
// golang.org/x/text@v0.38.0 language (the version typescript-go pins).
// Goish stays dependency-free, so this is a port, not a wrap.
//
// Surface (what typescript-go's locale/diagnostics layer consumes,
// plus the natural core): Tag (comparable, map-key-able), Parse,
// MustParse, canned tags (Und, English, ...), Confidence
// (No/Low/High/Exact), NewMatcher, Matcher.Match.
//
// The matcher is a faithful port of x/text language/match.go —
// per-language index expanded with CLDR languageMatch equivalences and
// alias entries, maximize via likely subtags, bestMatch with the exact
// confidence rules and tie-breakers (origLang/origReg/regionGroupDist/
// paradigm/origScript). Data tables (`language_tables.rs`) are the
// string-keyed forms of x/text's compact-ID tables, extracted from the
// module cache via dump shims plus a behavioral likely-subtags dump
// (internal Tag.Maximize over the full id space); regen recipe in the
// scratch harness (xtext_ref/).
//
// Documented deviations from x/text:
//   * Match returns the matched supported tag as-is: the region-
//     containment rewrite, `-u-rg-`/extension grafting onto the result
//     tag are not ported (typescript-go ignores the returned tag; it
//     uses only index and confidence).
//   * Maximize of a language-less tag with BOTH script and region set
//     resolves the language from the script entry alone (x/text has a
//     handful of (script, region) pair entries).
//   * Unknown-but-well-formed script/region subtags outside the
//     registered + private-use set are dropped with an error (x/text
//     keeps a few historic codes goish's registry dump excludes).
//   * ParseAcceptLanguage / MatchStrings / Comprehends / MatchOption:
//     not ported (unused by typescript-go); Matcher is a concrete
//     struct, not an interface.
//
// Validation: differential vs real x/text v0.38.0 — every valid base
// language (2930) parsed and matched against two candidate lists, plus
// 118 hand-picked tags covering scripts/regions/variants/extensions/
// legacy aliases/grandfathered/malformed input; exact (index,
// confidence, canonical string) agreement. See text_language_smoke for
// the embedded subset and the scratch language_differential runner for
// the full sweep.

use crate::errors::{self, error};
use crate::gomap::{hash_bytes, GoHash};
use crate::gostring::string;
use crate::types::int;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

#[path = "language_tables.rs"]
mod tables;

// ─── Tag ────────────────────────────────────────────────────────────

/// Tag is a BCP 47 language tag: `und`, `en`, `de-DE`, `zh-Hant`,
/// `sr-Latn-RS`, ... Comparable with `==` and usable as a map key,
/// like Go's language.Tag.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Tag {
    // NUL-padded subtags in canonical case; all-NUL = absent.
    lang: [u8; 3],
    script: [u8; 4],
    region: [u8; 3],
    // Canonical "-"-joined variants + extensions + private use, or None.
    rest: Option<Arc<str>>,
}

const fn sub3(s: &str) -> [u8; 3] {
    let b = s.as_bytes();
    let mut out = [0u8; 3];
    let mut i = 0;
    while i < b.len() {
        out[i] = b[i];
        i += 1;
    }
    out
}

const fn sub4(s: &str) -> [u8; 4] {
    let b = s.as_bytes();
    let mut out = [0u8; 4];
    let mut i = 0;
    while i < b.len() {
        out[i] = b[i];
        i += 1;
    }
    out
}

const fn tag(lang: &str, script: &str, region: &str) -> Tag {
    Tag { lang: sub3(lang), script: sub4(script), region: sub3(region), rest: None }
}

fn sub_str(b: &[u8]) -> &str {
    let mut n = 0;
    while n < b.len() && b[n] != 0 {
        n += 1;
    }
    // Subtags are always ASCII.
    core::str::from_utf8(&b[..n]).unwrap_or("")
}

impl Tag {
    fn lang_str(&self) -> &str {
        sub_str(&self.lang)
    }
    fn script_str(&self) -> &str {
        sub_str(&self.script)
    }
    fn region_str(&self) -> &str {
        sub_str(&self.region)
    }

    fn canonical(&self) -> String {
        let mut s = String::new();
        let lang = self.lang_str();
        let priv_only = lang.is_empty()
            && self.script_str().is_empty()
            && self.region_str().is_empty()
            && self.rest.as_deref().map(|r| r.starts_with("x-")).unwrap_or(false);
        if !priv_only {
            s.push_str(if lang.is_empty() { "und" } else { lang });
            if !self.script_str().is_empty() {
                s.push('-');
                s.push_str(self.script_str());
            }
            if !self.region_str().is_empty() {
                s.push('-');
                s.push_str(self.region_str());
            }
        }
        if let Some(rest) = self.rest.as_deref() {
            if !priv_only {
                s.push('-');
            }
            s.push_str(rest);
        }
        s
    }

    /// String returns the canonical string representation.
    pub fn String(&self) -> string {
        self.canonical().as_str().into()
    }

    /// IsRoot reports whether t is the root (und) tag.
    pub fn IsRoot(&self) -> bool {
        *self == Und
    }

    // Variants + private-use portion of rest (extensions excluded) —
    // x/text VariantOrPrivateUseTags, used by equalsRest.
    fn variant_or_private(&self) -> String {
        let mut out = String::new();
        let Some(rest) = self.rest.as_deref() else {
            return out;
        };
        let mut in_ext = false;
        let mut it = rest.split('-').peekable();
        while let Some(tok) = it.next() {
            if tok.len() == 1 {
                if tok == "x" {
                    out.push_str("x-");
                    let mut first = true;
                    for t in it {
                        if !first {
                            out.push('-');
                        }
                        first = false;
                        out.push_str(t);
                    }
                    return out;
                }
                in_ext = true;
                continue;
            }
            if !in_ext {
                if !out.is_empty() {
                    out.push('-');
                }
                out.push_str(tok);
            }
        }
        out
    }
}

impl GoHash for Tag {
    fn go_hash(&self, seed: u64) -> u64 {
        let mut h = hash_bytes(&self.lang, seed);
        h = hash_bytes(&self.script, h);
        h = hash_bytes(&self.region, h);
        if let Some(rest) = self.rest.as_deref() {
            h = hash_bytes(rest.as_bytes(), h);
        }
        h
    }
}

impl crate::fmt::Stringer for Tag {
    fn String(&self) -> string {
        Tag::String(self)
    }
}

// ─── Canned tags (x/text tags.go) ───────────────────────────────────

pub const Und: Tag = tag("", "", "");

pub const Afrikaans: Tag = tag("af", "", "");
pub const Amharic: Tag = tag("am", "", "");
pub const Arabic: Tag = tag("ar", "", "");
pub const ModernStandardArabic: Tag = tag("ar", "", "001");
pub const Azerbaijani: Tag = tag("az", "", "");
pub const Bulgarian: Tag = tag("bg", "", "");
pub const Bengali: Tag = tag("bn", "", "");
pub const Catalan: Tag = tag("ca", "", "");
pub const Czech: Tag = tag("cs", "", "");
pub const Danish: Tag = tag("da", "", "");
pub const German: Tag = tag("de", "", "");
pub const Greek: Tag = tag("el", "", "");
pub const English: Tag = tag("en", "", "");
pub const AmericanEnglish: Tag = tag("en", "", "US");
pub const BritishEnglish: Tag = tag("en", "", "GB");
pub const Spanish: Tag = tag("es", "", "");
pub const EuropeanSpanish: Tag = tag("es", "", "ES");
pub const LatinAmericanSpanish: Tag = tag("es", "", "419");
pub const Estonian: Tag = tag("et", "", "");
pub const Persian: Tag = tag("fa", "", "");
pub const Finnish: Tag = tag("fi", "", "");
pub const Filipino: Tag = tag("fil", "", "");
pub const French: Tag = tag("fr", "", "");
pub const CanadianFrench: Tag = tag("fr", "", "CA");
pub const Gujarati: Tag = tag("gu", "", "");
pub const Hebrew: Tag = tag("he", "", "");
pub const Hindi: Tag = tag("hi", "", "");
pub const Croatian: Tag = tag("hr", "", "");
pub const Hungarian: Tag = tag("hu", "", "");
pub const Armenian: Tag = tag("hy", "", "");
pub const Indonesian: Tag = tag("id", "", "");
pub const Icelandic: Tag = tag("is", "", "");
pub const Italian: Tag = tag("it", "", "");
pub const Japanese: Tag = tag("ja", "", "");
pub const Georgian: Tag = tag("ka", "", "");
pub const Kazakh: Tag = tag("kk", "", "");
pub const Khmer: Tag = tag("km", "", "");
pub const Kannada: Tag = tag("kn", "", "");
pub const Korean: Tag = tag("ko", "", "");
pub const Kirghiz: Tag = tag("ky", "", "");
pub const Lao: Tag = tag("lo", "", "");
pub const Lithuanian: Tag = tag("lt", "", "");
pub const Latvian: Tag = tag("lv", "", "");
pub const Macedonian: Tag = tag("mk", "", "");
pub const Malayalam: Tag = tag("ml", "", "");
pub const Mongolian: Tag = tag("mn", "", "");
pub const Marathi: Tag = tag("mr", "", "");
pub const Malay: Tag = tag("ms", "", "");
pub const Burmese: Tag = tag("my", "", "");
pub const Nepali: Tag = tag("ne", "", "");
pub const Dutch: Tag = tag("nl", "", "");
pub const Norwegian: Tag = tag("no", "", "");
pub const Punjabi: Tag = tag("pa", "", "");
pub const Polish: Tag = tag("pl", "", "");
pub const Portuguese: Tag = tag("pt", "", "");
pub const BrazilianPortuguese: Tag = tag("pt", "", "BR");
pub const EuropeanPortuguese: Tag = tag("pt", "", "PT");
pub const Romanian: Tag = tag("ro", "", "");
pub const Russian: Tag = tag("ru", "", "");
pub const Sinhala: Tag = tag("si", "", "");
pub const Slovak: Tag = tag("sk", "", "");
pub const Slovenian: Tag = tag("sl", "", "");
pub const Albanian: Tag = tag("sq", "", "");
pub const Serbian: Tag = tag("sr", "", "");
pub const SerbianLatin: Tag = tag("sr", "Latn", "");
pub const Swedish: Tag = tag("sv", "", "");
pub const Swahili: Tag = tag("sw", "", "");
pub const Tamil: Tag = tag("ta", "", "");
pub const Telugu: Tag = tag("te", "", "");
pub const Thai: Tag = tag("th", "", "");
pub const Turkish: Tag = tag("tr", "", "");
pub const Ukrainian: Tag = tag("uk", "", "");
pub const Urdu: Tag = tag("ur", "", "");
pub const Uzbek: Tag = tag("uz", "", "");
pub const Vietnamese: Tag = tag("vi", "", "");
pub const Chinese: Tag = tag("zh", "", "");
pub const SimplifiedChinese: Tag = tag("zh", "Hans", "");
pub const TraditionalChinese: Tag = tag("zh", "Hant", "");
pub const Zulu: Tag = tag("zu", "", "");

// ─── Confidence ─────────────────────────────────────────────────────

/// Confidence indicates the level of certainty for a given match.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Confidence(u8);

/// No indicates a match was impossible.
pub const No: Confidence = Confidence(0);
/// Low indicates a match with a low level of comprehension.
pub const Low: Confidence = Confidence(1);
/// High indicates a match with a high level of comprehension.
pub const High: Confidence = Confidence(2);
/// Exact indicates an exact match or a match assumed fully comprehensible.
pub const Exact: Confidence = Confidence(3);

impl Confidence {
    pub fn String(&self) -> string {
        match self.0 {
            0 => "No".into(),
            1 => "Low".into(),
            2 => "High".into(),
            _ => "Exact".into(),
        }
    }
}

// ─── Table lookups ──────────────────────────────────────────────────

fn lookup2<'a>(t: &'a [(&str, &str)], key: &str) -> Option<&'a str> {
    t.binary_search_by_key(&key, |e| e.0).ok().map(|i| t[i].1)
}

fn lookup3<'a>(t: &'a [(&str, &str, &str)], k0: &str, k1: &str) -> Option<&'a str> {
    t.binary_search_by(|e| (e.0, e.1).cmp(&(k0, k1))).ok().map(|i| t[i].2)
}

fn lookup3_pair<'a>(t: &'a [(&str, &str, &str)], key: &str) -> Option<(&'a str, &'a str)> {
    t.binary_search_by_key(&key, |e| e.0).ok().map(|i| (t[i].1, t[i].2))
}

fn region_group(region: &str) -> u8 {
    match tables::REGION_GROUPS.binary_search_by_key(&region, |e| e.0) {
        Ok(i) => tables::REGION_GROUPS[i].1,
        Err(_) => 0,
    }
}

// Grandfathered tags (RFC 5646 §2.2.8), canonical replacements as
// produced by x/text Parse (probed against v0.38.0).
static GRANDFATHERED: &[(&str, &str)] = &[
    ("art-lojban", "jbo"),
    ("cel-gaulish", "xtg-x-cel-gaulish"),
    ("en-gb-oed", "en-GB-oxendict"),
    ("i-ami", "ami"),
    ("i-bnn", "bnn"),
    ("i-default", "en-x-i-default"),
    ("i-enochian", "und-x-i-enochian"),
    ("i-hak", "hak"),
    ("i-klingon", "tlh"),
    ("i-lux", "lb"),
    ("i-mingo", "see-x-i-mingo"),
    ("i-navajo", "nv"),
    ("i-pwn", "pwn"),
    ("i-tao", "tao"),
    ("i-tay", "tay"),
    ("i-tsu", "tsu"),
    ("no-bok", "nb"),
    ("no-nyn", "nn"),
    ("sgn-be-fr", "sfb"),
    ("sgn-be-nl", "vgt"),
    ("sgn-ch-de", "sgg"),
    ("zh-guoyu", "cmn"),
    ("zh-hakka", "hak"),
    ("zh-min", "nan-x-zh-min"),
    ("zh-min-nan", "nan"),
    ("zh-xiang", "hsn"),
];

// ─── Parse ──────────────────────────────────────────────────────────

// Working representation during parse/match: unpacked subtag strings.
#[derive(Clone, Default, PartialEq)]
struct WTag {
    lang: String,
    script: String,
    region: String,
    variants: Vec<String>,
    extensions: Vec<String>, // each "u-co-phonebk" style, singleton first
    private: String,         // "x-..." or empty
}

impl WTag {
    fn from_tag(t: &Tag) -> WTag {
        let mut w = WTag {
            lang: String::from(t.lang_str()),
            script: String::from(t.script_str()),
            region: String::from(t.region_str()),
            ..WTag::default()
        };
        if let Some(rest) = t.rest.as_deref() {
            let mut toks = rest.split('-').peekable();
            while let Some(tok) = toks.peek().copied() {
                if tok.len() == 1 {
                    break;
                }
                w.variants.push(String::from(tok));
                toks.next();
            }
            let mut cur: Option<String> = None;
            for tok in toks {
                if tok.len() == 1 {
                    if let Some(c) = cur.take() {
                        w.extensions.push(c);
                    }
                    cur = Some(String::from(tok));
                } else if let Some(c) = cur.as_mut() {
                    c.push('-');
                    c.push_str(tok);
                }
            }
            if let Some(c) = cur {
                if let Some(stripped) = c.strip_prefix("x-") {
                    w.private = String::from("x-");
                    w.private.push_str(stripped);
                } else if c == "x" {
                    w.private = String::from("x");
                } else {
                    w.extensions.push(c);
                }
            }
        }
        w
    }

    fn to_tag(&self) -> Tag {
        let mut rest = String::new();
        for v in &self.variants {
            if !rest.is_empty() {
                rest.push('-');
            }
            rest.push_str(v);
        }
        let mut exts: Vec<&String> = self.extensions.iter().collect();
        exts.sort();
        for e in exts {
            if !rest.is_empty() {
                rest.push('-');
            }
            rest.push_str(e);
        }
        if !self.private.is_empty() {
            if !rest.is_empty() {
                rest.push('-');
            }
            rest.push_str(&self.private);
        }
        Tag {
            lang: sub3(&self.lang),
            script: sub4(&self.script),
            region: sub3(&self.region),
            rest: if rest.is_empty() { None } else { Some(Arc::from(rest.as_str())) },
        }
    }
}

fn is_alpha(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphabetic())
}

fn is_digit(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

fn is_alnum(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric())
}

// BCP 47 subtags are ASCII; ASCII-only case ops avoid pulling the
// Unicode case tables (and their unwinding paths) into no_std binaries.
fn title_case(s: &str) -> String {
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i == 0 {
            out.push(c.to_ascii_uppercase());
        } else {
            out.push(c.to_ascii_lowercase());
        }
    }
    out
}

// Canonicalize flags — mirrors x/text CanonType usage:
// Parse applies Deprecated + Legacy; the matcher additionally applies
// Macro and SuppressScript.
const CANON_DEPRECATED: u8 = 1;
const CANON_LEGACY: u8 = 2;
const CANON_MACRO: u8 = 4;
const CANON_SUPPRESS_SCRIPT: u8 = 8;

fn canonicalize(w: &mut WTag, flags: u8) {
    if flags & CANON_SUPPRESS_SCRIPT != 0 && !w.script.is_empty() {
        if let Some(ss) = lookup2(tables::SUPPRESS_SCRIPT, &w.lang) {
            if ss == w.script {
                w.script.clear();
            }
        }
    }
    // Language alias loop (x/text canonicalize canonLang).
    loop {
        let Some(i) = tables::LANG_ALIASES.binary_search_by_key(&w.lang.as_str(), |e| e.0).ok()
        else {
            break;
        };
        let (from, to, kind, _) = tables::LANG_ALIASES[i];
        let apply = match kind {
            2 => flags & CANON_LEGACY != 0,     // legacy
            1 => flags & CANON_MACRO != 0,      // macro
            _ => flags & CANON_DEPRECATED != 0, // deprecated
        };
        if !apply {
            break;
        }
        // Special cases from x/text canonicalize:
        if from == "sh" && w.script.is_empty() {
            w.script = String::from("Latn");
        }
        if from == "mo" && w.region.is_empty() {
            w.region = String::from("MD");
        }
        if to == w.lang {
            break;
        }
        w.lang = String::from(to);
    }
    // Deprecated script (Qaai -> Zinh) and region (BU -> MM).
    if !w.script.is_empty() {
        if let Some(c) = lookup2(tables::VALID_SCRIPTS, &w.script) {
            if !c.is_empty() && c != w.script {
                w.script = String::from(c);
            }
        }
    }
    if !w.region.is_empty() {
        if let Some(c) = lookup2(tables::VALID_REGIONS, &w.region) {
            if !c.is_empty() && c != w.region {
                w.region = String::from(c);
            }
        }
    }
}

fn parse_inner(input: &str) -> (WTag, bool) {
    let mut w = WTag::default();
    let mut ok = true;

    let lowered: String = input
        .chars()
        .map(|c| if c == '_' { '-' } else { c.to_ascii_lowercase() })
        .collect();

    if lowered.is_empty() {
        return (w, false);
    }
    if lowered == "und" || lowered == "root" || lowered == "*" {
        return (w, lowered != "*");
    }
    if let Some(g) = lookup2(GRANDFATHERED, &lowered) {
        let (t, _) = parse_inner(g);
        // Grandfathered replacements are already canonical-case; re-fix
        // the script/region case lost by lowering.
        let mut t = t;
        if g.contains("GB") {
            t.region = String::from("GB");
        }
        return (t, true);
    }

    let toks: Vec<&str> = lowered.split('-').filter(|t| !t.is_empty()).collect();
    if toks.iter().map(|t| t.len() + 1).sum::<usize>() != lowered.len() + 1 {
        ok = false; // empty tokens (leading/trailing/double separators)
    }
    if toks.is_empty() {
        return (w, false);
    }

    let mut i = 0;

    // Language subtag (or whole-tag private use).
    let t0 = toks[0];
    if t0 == "x" {
        // x-... : private-use-only tag.
        i = 1;
        let mut priv_parts: Vec<&str> = Vec::new();
        while i < toks.len() {
            let t = toks[i];
            if t.len() > 8 || !is_alnum(t) {
                ok = false;
                break;
            }
            priv_parts.push(t);
            i += 1;
        }
        if priv_parts.is_empty() {
            return (w, false);
        }
        let mut p = String::from("x");
        for t in priv_parts {
            p.push('-');
            p.push_str(t);
        }
        w.private = p;
        return (w, ok);
    }
    if (2..=3).contains(&t0.len()) && is_alpha(t0) {
        match lookup2(tables::VALID_LANGS, t0) {
            // The canonical form is a full tag for legacy/deprecated
            // codes whose replacement carries a script or region
            // (sh -> sr-Latn, mo/mol -> ro-MD): merge those parts.
            Some(canon) => {
                let mut parts = canon.split('-');
                w.lang = String::from(parts.next().unwrap_or(""));
                for part in parts {
                    if part.len() == 4 && w.script.is_empty() {
                        w.script = String::from(part);
                    } else if part.len() <= 3 && w.region.is_empty() {
                        w.region = String::from(part);
                    }
                }
            }
            None => ok = false, // well-formed but unknown -> und + error
        }
        i = 1;
    } else {
        // 1-letter, 4+-letter, or digit first subtag: not a language.
        return (w, false);
    }

    // Script.
    if i < toks.len() && toks[i].len() == 4 && is_alpha(toks[i]) {
        let sc = title_case(toks[i]);
        match lookup2(tables::VALID_SCRIPTS, &sc) {
            Some(canon) => w.script = String::from(if canon.is_empty() { sc.as_str() } else { canon }),
            None => ok = false, // unknown script: dropped + error
        }
        i += 1;
    }

    // Region.
    if i < toks.len()
        && ((toks[i].len() == 2 && is_alpha(toks[i])) || (toks[i].len() == 3 && is_digit(toks[i])))
    {
        let rg = toks[i].to_ascii_uppercase();
        match lookup2(tables::VALID_REGIONS, &rg) {
            Some(canon) => w.region = String::from(if canon.is_empty() { rg.as_str() } else { canon }),
            None => ok = false,
        }
        i += 1;
    }

    // Variants.
    while i < toks.len() {
        let t = toks[i];
        let is_var = (t.len() >= 5 && t.len() <= 8 && is_alnum(t))
            || (t.len() == 4 && t.as_bytes()[0].is_ascii_digit() && is_alnum(t));
        if !is_var {
            break;
        }
        if tables::VARIANTS.binary_search(&t).is_ok() && !w.variants.iter().any(|v| v == t) {
            w.variants.push(String::from(t));
        } else {
            ok = false; // unknown or duplicate variant: dropped + error
        }
        i += 1;
    }

    // Extensions + private use.
    while i < toks.len() {
        let t = toks[i];
        if t.len() != 1 {
            ok = false; // stray subtag where a singleton is expected
            i += 1;
            continue;
        }
        let singleton = t;
        i += 1;
        let mut parts: Vec<&str> = Vec::new();
        while i < toks.len() && toks[i].len() >= 2 && toks[i].len() <= 8 && is_alnum(toks[i]) {
            parts.push(toks[i]);
            i += 1;
        }
        if parts.is_empty() {
            ok = false; // bare singleton
            continue;
        }
        let mut e = String::from(singleton);
        for p in parts {
            e.push('-');
            e.push_str(p);
        }
        if singleton == "x" {
            w.private = e;
            break;
        }
        if w.extensions.iter().any(|x| x.starts_with(singleton)) {
            ok = false; // duplicate singleton
            continue;
        }
        w.extensions.push(e);
    }

    canonicalize(&mut w, CANON_DEPRECATED | CANON_LEGACY);
    (w, ok)
}

/// Parse parses the given BCP 47 string and returns a valid Tag.
/// If parsing failed it returns an error and the part of the tag
/// that could be parsed.
pub fn Parse<S: AsRef<str>>(s: S) -> (Tag, error) {
    let input = s.as_ref();
    let (w, ok) = parse_inner(input);
    let t = w.to_tag();
    if ok {
        (t, errors::nil)
    } else {
        (t, errors::New("language: tag is not well-formed"))
    }
}

/// MustParse is like Parse, but panics if the given BCP 47 string
/// cannot be parsed.
pub fn MustParse<S: AsRef<str>>(s: S) -> Tag {
    let input = s.as_ref();
    let (t, err) = Parse(input);
    if err != crate::nilval::nil {
        panic!("language: MustParse: tag is not well-formed");
    }
    t
}

// ─── Likely subtags (maximize) ──────────────────────────────────────

// addLikelySubtags — behavioral port of internal Tag.Maximize.
fn maximize(w: &WTag) -> (String, String, String) {
    let mut lang = w.lang.clone();
    let mut script = w.script.clone();
    let mut region = w.region.clone();

    if !lang.is_empty() {
        if let Some((ls, lr)) = lookup3_pair(tables::LIKELY_LANG, &lang) {
            if script.is_empty() {
                let mut s = ls;
                if !region.is_empty() {
                    if let Some(over) = lookup3(tables::LIKELY_LANG_REGION, &lang, &region) {
                        s = over;
                    }
                }
                script = String::from(s);
            }
            if region.is_empty() {
                let mut r = lr;
                if !w.script.is_empty() {
                    if let Some(over) = lookup3(tables::LIKELY_LANG_SCRIPT, &lang, &w.script) {
                        r = over;
                    }
                }
                region = String::from(r);
            }
        }
    } else if !script.is_empty() {
        if let Some((ll, lr)) = lookup3_pair(tables::LIKELY_SCRIPT, &script) {
            lang = String::from(ll);
            if region.is_empty() {
                region = String::from(lr);
            }
        }
    } else if !region.is_empty() {
        if let Some((ll, ls)) = lookup3_pair(tables::LIKELY_REGION, &region) {
            lang = String::from(ll);
            script = String::from(ls);
        }
    }
    (lang, script, region)
}

// ─── Matcher (port of x/text match.go) ──────────────────────────────

fn to_conf(d: u8) -> Confidence {
    if d <= 10 {
        return High;
    }
    if d < 30 {
        return Low;
    }
    No
}

#[derive(Clone)]
struct HaveTag {
    w: WTag,     // parse-canonical supported tag
    index: int,  // index in the original supported list
    conf: Confidence,
    max_script: String,
    max_region: String,
    alt_script: String,
    next_max: usize, // 0 = none (self-index sentinel unused, like Go)
}

fn alt_script(lang: &str, script: &str) -> String {
    for &(want_lang, want_script, have_lang, have_script, _) in tables::MATCH_SCRIPT {
        if (want_lang == lang || have_lang == lang) && have_script == script {
            return String::from(want_script);
        }
    }
    String::new()
}

fn make_have_tag(t: &Tag, index: int) -> (HaveTag, String) {
    let w = WTag::from_tag(t);
    let mut max = w.clone();
    if !(w.lang.is_empty() && w.script.is_empty() && w.region.is_empty()) {
        canonicalize(
            &mut max,
            CANON_DEPRECATED | CANON_LEGACY | CANON_MACRO | CANON_SUPPRESS_SCRIPT,
        );
        let (l, s, r) = maximize(&max);
        max.lang = l;
        max.script = s;
        max.region = r;
    }
    let alt = alt_script(&max.lang, &max.script);
    (
        HaveTag {
            w,
            index,
            conf: Exact,
            max_script: max.script,
            max_region: max.region,
            alt_script: alt,
            next_max: 0,
        },
        max.lang,
    )
}

// equalsRest — everything except the language.
fn equals_rest(a: &WTag, b: &WTag) -> bool {
    a.script == b.script && a.region == b.region && var_priv(a) == var_priv(b)
}

fn var_priv(w: &WTag) -> String {
    let mut s = String::new();
    for v in &w.variants {
        if !s.is_empty() {
            s.push('-');
        }
        s.push_str(v);
    }
    if !w.private.is_empty() {
        if !s.is_empty() {
            s.push('-');
        }
        s.push_str(&w.private);
    }
    s
}

#[derive(Default)]
struct MatchHeader {
    have: Vec<HaveTag>,
    original: bool,
}

impl MatchHeader {
    fn add_if_new(&mut self, n: HaveTag, exact: bool) {
        self.original = self.original || exact;
        for v in &self.have {
            if equals_rest(&v.w, &n.w) {
                return;
            }
        }
        let new_idx = self.have.len();
        for i in 0..self.have.len() {
            if self.have[i].max_script == n.max_script
                && self.have[i].max_region == n.max_region
                && var_priv(&self.have[i].w) == var_priv(&n.w)
            {
                let mut j = i;
                while self.have[j].next_max != 0 {
                    j = self.have[j].next_max;
                }
                self.have[j].next_max = new_idx;
                break;
            }
        }
        self.have.push(n);
    }
}

/// Matcher matches an ordered list of preferred tags against a list of
/// supported tags, ported from x/text NewMatcher (PreferSameScript
/// default of true baked in).
pub struct Matcher {
    supported: Vec<Tag>,
    // (max_script per supported tag, for the preferSameScript fallback)
    supported_max_script: Vec<String>,
    index: alloc::collections::BTreeMap<String, MatchHeader>,
    default_index: int,
}

/// NewMatcher returns a Matcher over the given list of supported tags.
/// The first element is the default. Go's variadic MatchOptions are
/// not ported.
pub fn NewMatcher<T: AsRef<[Tag]>>(supported: T) -> Matcher {
    let supported: Vec<Tag> = supported.as_ref().to_vec();
    let mut m = Matcher {
        supported: supported.clone(),
        supported_max_script: Vec::new(),
        index: alloc::collections::BTreeMap::new(),
        default_index: 0,
    };
    if supported.is_empty() {
        return m;
    }
    // Exact entries first, under the parse-canonical language.
    for (i, t) in supported.iter().enumerate() {
        let (pair, _) = make_have_tag(t, i as int);
        m.supported_max_script.push(pair.max_script.clone());
        let key = String::from(t.lang_str());
        m.index.entry(key).or_default().add_if_new(pair, true);
    }
    // Second pass: entries under the maximized language when different.
    for (i, t) in supported.iter().enumerate() {
        let (pair, max_lang) = make_have_tag(t, i as int);
        if max_lang != t.lang_str() {
            m.index.entry(max_lang).or_default().add_if_new(pair, true);
        }
    }

    // update(): add copies of `have`'s header tags under `want`.
    fn update(m: &mut Matcher, want: &str, have: &str, conf: Confidence) {
        let Some(hh) = m.index.get(have) else {
            return;
        };
        if !hh.original {
            return;
        }
        let src_original = hh.original;
        let copies: Vec<HaveTag> = hh.have.clone();
        let hw = m.index.entry(String::from(want)).or_default();
        for ht in copies {
            let mut v = ht;
            if conf < v.conf {
                v.conf = conf;
            }
            v.next_max = 0;
            if !v.alt_script.is_empty() {
                v.alt_script = alt_script(want, &v.max_script);
            }
            hw.add_if_new(v, conf == Exact && src_original);
        }
    }

    // CLDR languageMatch equivalences.
    for &(want, have, distance, oneway) in tables::MATCH_LANG {
        let conf = to_conf(distance);
        update(&mut m, want, have, conf);
        if !oneway {
            update(&mut m, have, want, conf);
        }
    }
    // Alias (deprecated/legacy/macro) entries.
    for &(from, to, kind, exact_equiv) in tables::LANG_ALIASES {
        let mut conf = Exact;
        if kind != 1 {
            // not macro
            if !exact_equiv {
                conf = High;
            }
            update(&mut m, to, from, conf);
        }
        update(&mut m, from, to, conf);
    }
    m
}

fn is_paradigm_locale(lang: &str, region: &str) -> bool {
    for &(l, r1, r2) in tables::PARADIGM_LOCALES {
        if l == lang && (region == r1 || region == r2) {
            return true;
        }
    }
    false
}

// Script inference for the preferSameScript fallback — port of
// Tag.Script(): declared script, else suppress-script, else likely
// subtags, else likely subtags of the Deprecated|Macro-canonicalized
// language (how retired codes like drh -> khk resolve).
fn infer_script(w: &WTag) -> String {
    if !w.script.is_empty() {
        return w.script.clone();
    }
    let mut sc = String::new();
    if !w.lang.is_empty() {
        if let Some(ss) = lookup2(tables::SUPPRESS_SCRIPT, &w.lang) {
            if w.region.is_empty() {
                return String::from(ss);
            }
            sc = String::from(ss);
        }
    }
    if lookup3_pair(tables::LIKELY_LANG, &w.lang).is_some() {
        let (_, s, _) = maximize(w);
        if !s.is_empty() {
            sc = s;
        }
    } else {
        let mut cw = w.clone();
        canonicalize(&mut cw, CANON_DEPRECATED | CANON_MACRO);
        if lookup3_pair(tables::LIKELY_LANG, &cw.lang).is_some() {
            let (_, s, _) = maximize(&cw);
            if !s.is_empty() {
                sc = s;
            }
        }
    }
    sc
}

// regionGroupDist — the CLDR region-group distance.
fn region_group_dist(a: &str, b: &str, script: &str, lang: &str) -> (u8, bool) {
    const DEFAULT_DISTANCE: u8 = 4;
    let a_group = (region_group(a) as u32) << 1;
    let b_group = (region_group(b) as u32) << 1;
    for &(l, sc, group, distance) in tables::MATCH_REGION {
        if l == lang && (sc.is_empty() || sc == script) {
            let g = 1u32 << (group & !0x80);
            if group & 0x80 == 0 {
                if a_group & b_group & g != 0 {
                    return (distance, distance == DEFAULT_DISTANCE);
                }
            } else if (a_group | b_group) & g == 0 {
                return (distance, distance == DEFAULT_DISTANCE);
            }
        }
    }
    (DEFAULT_DISTANCE, true)
}

#[derive(Default)]
struct BestMatch {
    have: Option<HaveTag>,
    want: WTag,
    conf: Confidence,
    pinned_region: String,
    pin_language: bool,
    same_region_group: bool,
    orig_lang: bool,
    orig_reg: bool,
    paradigm_reg: bool,
    reg_group_dist: u8,
    orig_script: bool,
}

impl BestMatch {
    #[allow(clippy::too_many_arguments)]
    fn update(&mut self, have: &HaveTag, tag: &WTag, max_script: &str, max_region: &str, pin: bool) {
        let mut c = have.conf;
        if c < self.conf {
            return;
        }
        if self.pin_language && tag.lang != self.want.lang {
            return;
        }
        if tag.lang == self.want.lang && self.same_region_group {
            let (_, same_group) =
                region_group_dist(&self.pinned_region, &have.max_region, &have.max_script, &tag.lang);
            if !same_group {
                return;
            }
        }
        if c == Exact && have.max_script == max_script {
            self.pin_language = pin;
        }
        if equals_rest(&have.w, tag) {
            // full non-language match — keep c
        } else if have.max_script != max_script {
            if Low < self.conf || have.alt_script != max_script {
                return;
            }
            c = Low;
        } else if have.max_region != max_region {
            if High < c {
                c = High;
            }
        }

        let mut beaten = false;
        if c != self.conf {
            if c < self.conf {
                return;
            }
            beaten = true;
        }

        let orig_lang = have.w.lang == tag.lang && !tag.lang.is_empty();
        if !beaten && self.orig_lang != orig_lang {
            if self.orig_lang {
                return;
            }
            beaten = true;
        }

        let orig_reg = have.w.region == tag.region && !tag.region.is_empty();
        if !beaten && self.orig_reg != orig_reg {
            if self.orig_reg {
                return;
            }
            beaten = true;
        }

        let (reg_group_dist, same_group) =
            region_group_dist(&have.max_region, max_region, max_script, &tag.lang);
        if !beaten && self.reg_group_dist != reg_group_dist {
            if reg_group_dist > self.reg_group_dist {
                return;
            }
            beaten = true;
        }

        let paradigm_reg = is_paradigm_locale(&tag.lang, &have.max_region);
        if !beaten && self.paradigm_reg != paradigm_reg {
            if !paradigm_reg {
                return;
            }
            beaten = true;
        }

        let orig_script = have.w.script == tag.script && !tag.script.is_empty();
        if !beaten && self.orig_script != orig_script {
            if self.orig_script {
                return;
            }
            beaten = true;
        }

        if beaten {
            self.have = Some(have.clone());
            self.want = tag.clone();
            self.conf = c;
            self.pinned_region = String::from(max_region);
            self.same_region_group = same_group;
            self.orig_lang = orig_lang;
            self.orig_reg = orig_reg;
            self.paradigm_reg = paradigm_reg;
            self.orig_script = orig_script;
            self.reg_group_dist = reg_group_dist;
        }
    }
}

impl Matcher {
    /// Match returns the best match among the supported tags for any of
    /// the given desired tags, its index in the supported list, and the
    /// match confidence. Go's variadic `Match(t ...Tag)` becomes a
    /// trailing slice: `m.Match([tag])`.
    pub fn Match<T: AsRef<[Tag]>>(&self, want: T) -> (Tag, int, Confidence) {
        let want = want.as_ref();
        if self.supported.is_empty() {
            return (Und, 0, No);
        }
        let (best_index, conf, got) = self.get_best(want);
        match got {
            Some(idx) => (self.supported[idx as usize].clone(), idx, conf),
            None => {
                // preferSameScript fallback (default true in x/text).
                let mut index = self.default_index;
                'outer: for w in want {
                    let ww = WTag::from_tag(w);
                    let script = infer_script(&ww);
                    if script.is_empty() {
                        continue;
                    }
                    for (i, max_script) in self.supported_max_script.iter().enumerate() {
                        if *max_script == script {
                            index = i as int;
                            break 'outer;
                        }
                    }
                }
                let _ = best_index;
                (self.supported[index as usize].clone(), index, No)
            }
        }
    }

    // getBest — returns (unused, confidence, matched supported index).
    fn get_best(&self, want: &[Tag]) -> (int, Confidence, Option<int>) {
        let mut best = BestMatch::default();
        for (wi, ww) in want.iter().enumerate() {
            let mut w = WTag::from_tag(ww);
            let max;
            let header_key;
            if !w.lang.is_empty() {
                if !self.index.contains_key(w.lang.as_str()) {
                    continue;
                }
                header_key = w.lang.clone();
                let mut cw = w.clone();
                canonicalize(&mut cw, CANON_DEPRECATED | CANON_LEGACY | CANON_MACRO);
                // A region added by canonicalization is stronger than a
                // maximized region: push it into the original.
                if w.region != cw.region {
                    w.region = cw.region.clone();
                }
                let (l, s, r) = maximize(&cw);
                max = WTag { lang: l, script: s, region: r, ..WTag::default() };
            } else {
                // No base language.
                if let Some(h) = self.index.get("") {
                    for have in &h.have {
                        if equals_rest(&have.w, &w) {
                            return (0, Exact, Some(have.index));
                        }
                    }
                }
                if w.script.is_empty() && w.region.is_empty() {
                    continue;
                }
                let (l, s, r) = maximize(&w);
                max = WTag { lang: l.clone(), script: s, region: r, ..WTag::default() };
                if !self.index.contains_key(l.as_str()) {
                    continue;
                }
                header_key = l;
            }
            let mut pin = true;
            for t in &want[wi + 1..] {
                if w.lang == t.lang_str() {
                    pin = false;
                    break;
                }
            }
            let h = &self.index[header_key.as_str()];
            for i in 0..h.have.len() {
                let have = &h.have[i];
                best.update(have, &w, &max.script, &max.region, pin);
                if best.conf == Exact {
                    let mut j = i;
                    while h.have[j].next_max != 0 {
                        j = h.have[j].next_max;
                        best.update(&h.have[j], &w, &max.script, &max.region, pin);
                    }
                    let idx = best.have.as_ref().map(|ht| ht.index);
                    return (0, best.conf, idx);
                }
            }
        }
        if best.conf <= No {
            return (0, No, None);
        }
        let idx = best.have.as_ref().map(|ht| ht.index);
        (0, best.conf, idx)
    }
}
