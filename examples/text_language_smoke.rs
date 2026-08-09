// text_language_smoke — text/language (BCP 47 tags + matching),
// ported from golang.org/x/text@v0.38.0.
//
// Covers:
//   1. Parse/MustParse canonicalization: 118 vectors (region/script
//      variants, legacy aliases iw/in/ji/tl/sh, grandfathered tags,
//      case folding, extensions, private use, malformed input) —
//      expected outputs dumped from the real x/text v0.38.0.
//   2. Matcher over typescript-go's exact 14-locale candidate list:
//      108 vectors asserting (index, confidence) — the diagnostics
//      locale-resolution path (getLocalizedMessages).
//   3. The typescript-go locale.go flow: Parse gracefully fails;
//      Tag equality with Und; Tag as a map key.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::gomap::map;
use goish::text::language;
use goish::{string, syscall};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

// (input, canonical String(), parse error?) — from real x/text v0.38.0.
static PARSE_VECS: &[(&str, &str, bool)] = &[
    ("en", "en", false),
    ("zh-CN", "zh-CN", false),
    ("zh-TW", "zh-TW", false),
    ("cs-CZ", "cs-CZ", false),
    ("de-DE", "de-DE", false),
    ("es-ES", "es-ES", false),
    ("fr-FR", "fr-FR", false),
    ("it-IT", "it-IT", false),
    ("ja-JP", "ja-JP", false),
    ("ko-KR", "ko-KR", false),
    ("pl-PL", "pl-PL", false),
    ("pt-BR", "pt-BR", false),
    ("ru-RU", "ru-RU", false),
    ("tr-TR", "tr-TR", false),
    ("zh", "zh", false),
    ("cs", "cs", false),
    ("de", "de", false),
    ("es", "es", false),
    ("fr", "fr", false),
    ("it", "it", false),
    ("ja", "ja", false),
    ("ko", "ko", false),
    ("pl", "pl", false),
    ("pt", "pt", false),
    ("ru", "ru", false),
    ("tr", "tr", false),
    ("en-US", "en-US", false),
    ("en-GB", "en-GB", false),
    ("en-AU", "en-AU", false),
    ("en-CA", "en-CA", false),
    ("en-IN", "en-IN", false),
    ("de-AT", "de-AT", false),
    ("de-CH", "de-CH", false),
    ("es-MX", "es-MX", false),
    ("es-AR", "es-AR", false),
    ("es-419", "es-419", false),
    ("fr-CA", "fr-CA", false),
    ("fr-BE", "fr-BE", false),
    ("fr-CH", "fr-CH", false),
    ("pt-PT", "pt-PT", false),
    ("pt-AO", "pt-AO", false),
    ("zh-HK", "zh-HK", false),
    ("zh-MO", "zh-MO", false),
    ("zh-SG", "zh-SG", false),
    ("ru-BY", "ru-BY", false),
    ("ru-KZ", "ru-KZ", false),
    ("tr-CY", "tr-CY", false),
    ("it-CH", "it-CH", false),
    ("cs-SK", "cs-SK", false),
    ("pl-DE", "pl-DE", false),
    ("ko-KP", "ko-KP", false),
    ("ja-US", "ja-US", false),
    ("zh-Hant", "zh-Hant", false),
    ("zh-Hans", "zh-Hans", false),
    ("zh-Hant-CN", "zh-Hant-CN", false),
    ("zh-Hans-TW", "zh-Hans-TW", false),
    ("zh-Hant-HK", "zh-Hant-HK", false),
    ("sr-Latn", "sr-Latn", false),
    ("en-Latn", "en-Latn", false),
    ("de-Latn-DE", "de-Latn-DE", false),
    ("uz-Cyrl", "uz-Cyrl", false),
    ("ar", "ar", false),
    ("he", "he", false),
    ("iw", "he", false),
    ("hi", "hi", false),
    ("th", "th", false),
    ("vi", "vi", false),
    ("uk", "uk", false),
    ("nl", "nl", false),
    ("sv", "sv", false),
    ("da", "da", false),
    ("fi", "fi", false),
    ("nb", "nb", false),
    ("no", "no", false),
    ("hu", "hu", false),
    ("el", "el", false),
    ("ro", "ro", false),
    ("bg", "bg", false),
    ("id", "id", false),
    ("in", "id", false),
    ("ms", "ms", false),
    ("fa", "fa", false),
    ("ur", "ur", false),
    ("bn", "bn", false),
    ("ta", "ta", false),
    ("tl", "fil", false),
    ("ji", "yi", false),
    ("sh", "sr-Latn", false),
    ("DE-de", "de-DE", false),
    ("ZH-cn", "zh-CN", false),
    ("EN", "en", false),
    ("Pt-Br", "pt-BR", false),
    ("zh-hant", "zh-Hant", false),
    ("SR-LATN", "sr-Latn", false),
    ("de-DE-1996", "de-DE-1996", false),
    ("en-US-u-va-posix", "en-US-u-va-posix", false),
    ("zh-CN-x-foo", "zh-CN-x-foo", false),
    ("x-private", "x-private", false),
    ("en-x-priv", "en-x-priv", false),
    ("de-u-co-phonebk", "de-u-co-phonebk", false),
    ("und", "und", false),
    ("root", "und", false),
    ("*", "und", true),
    ("", "und", true),
    ("notatag!", "und", true),
    ("a", "und", true),
    ("abcdefghij", "und", true),
    ("en_US", "en-US", false),
    ("toolonglanguage", "und", true),
    ("419", "und", true),
    ("en-", "en", true),
    ("-en", "en", true),
    ("en--US", "en-US", true),
    ("fil", "fil", false),
    ("yue", "yue", false),
    ("cmn", "cmn", false),
    ("haw", "haw", false),
    ("gsw", "gsw", false),];

// (input, index, confidence as int) matched against typescript-go's
// supported list — from real x/text v0.38.0. Confidence: 0=No 1=Low
// 2=High 3=Exact.
static MATCH_VECS: &[(&str, i64, i64)] = &[
    ("en", 0, 3),
    ("zh-CN", 1, 3),
    ("zh-TW", 2, 3),
    ("cs-CZ", 3, 3),
    ("de-DE", 4, 3),
    ("es-ES", 5, 3),
    ("fr-FR", 6, 3),
    ("it-IT", 7, 3),
    ("ja-JP", 8, 3),
    ("ko-KR", 9, 3),
    ("pl-PL", 10, 3),
    ("pt-BR", 11, 3),
    ("ru-RU", 12, 3),
    ("tr-TR", 13, 3),
    ("zh", 1, 3),
    ("cs", 3, 3),
    ("de", 4, 3),
    ("es", 5, 3),
    ("fr", 6, 3),
    ("it", 7, 3),
    ("ja", 8, 3),
    ("ko", 9, 3),
    ("pl", 10, 3),
    ("pt", 11, 3),
    ("ru", 12, 3),
    ("tr", 13, 3),
    ("en-US", 0, 3),
    ("en-GB", 0, 2),
    ("en-AU", 0, 2),
    ("en-CA", 0, 2),
    ("en-IN", 0, 2),
    ("de-AT", 4, 2),
    ("de-CH", 4, 2),
    ("es-MX", 5, 2),
    ("es-AR", 5, 2),
    ("es-419", 5, 2),
    ("fr-CA", 6, 2),
    ("fr-BE", 6, 2),
    ("fr-CH", 6, 2),
    ("pt-PT", 11, 2),
    ("pt-AO", 11, 2),
    ("zh-HK", 2, 2),
    ("zh-MO", 2, 2),
    ("zh-SG", 1, 2),
    ("ru-BY", 12, 2),
    ("ru-KZ", 12, 2),
    ("tr-CY", 13, 2),
    ("it-CH", 7, 2),
    ("cs-SK", 3, 2),
    ("pl-DE", 10, 2),
    ("ko-KP", 9, 2),
    ("ja-US", 8, 2),
    ("zh-Hant", 2, 3),
    ("zh-Hans", 1, 3),
    ("zh-Hant-CN", 2, 2),
    ("zh-Hans-TW", 1, 2),
    ("zh-Hant-HK", 2, 2),
    ("sr-Latn", 0, 0),
    ("en-Latn", 0, 3),
    ("de-Latn-DE", 4, 3),
    ("uz-Cyrl", 12, 2),
    ("ar", 0, 0),
    ("he", 0, 0),
    ("iw", 0, 0),
    ("hi", 0, 0),
    ("th", 0, 0),
    ("vi", 0, 0),
    ("uk", 12, 0),
    ("nl", 0, 0),
    ("sv", 0, 0),
    ("da", 0, 0),
    ("fi", 0, 0),
    ("nb", 0, 0),
    ("no", 0, 0),
    ("hu", 0, 0),
    ("el", 0, 0),
    ("ro", 0, 0),
    ("bg", 12, 0),
    ("id", 0, 0),
    ("in", 0, 0),
    ("ms", 0, 0),
    ("fa", 0, 0),
    ("ur", 0, 2),
    ("bn", 0, 2),
    ("ta", 0, 2),
    ("tl", 0, 0),
    ("ji", 0, 2),
    ("sh", 0, 0),
    ("DE-de", 4, 3),
    ("ZH-cn", 1, 3),
    ("EN", 0, 3),
    ("Pt-Br", 11, 3),
    ("zh-hant", 2, 3),
    ("SR-LATN", 0, 0),
    ("de-DE-1996", 4, 3),
    ("en-US-u-va-posix", 0, 3),
    ("zh-CN-x-foo", 1, 3),
    ("x-private", 0, 0),
    ("en-x-priv", 0, 3),
    ("de-u-co-phonebk", 4, 3),
    ("und", 0, 0),
    ("root", 0, 0),
    ("en_US", 0, 3),
    ("fil", 0, 0),
    ("yue", 2, 0),
    ("cmn", 1, 3),
    ("haw", 0, 2),
    ("gsw", 4, 2),];

fn conf_int(c: language::Confidence) -> i64 {
    if c == language::No {
        0
    } else if c == language::Low {
        1
    } else if c == language::High {
        2
    } else {
        3
    }
}

#[goish::main]
fn main() {
    // ─── 1. Parse canonicalization vectors ─────────────────────────
    for (input, want, want_err) in PARSE_VECS {
        let (tag, err) = language::Parse(*input);
        let got = tag.String();
        if got.as_bytes() != want.as_bytes() {
            fmt::Println!("parse:", *input, "got", got, "want", *want);
            die(b"t1: Parse canonical mismatch\n");
        }
        if (err != goish::nil) != *want_err {
            fmt::Println!("parse err:", *input);
            die(b"t1: Parse error-flag mismatch\n");
        }
    }

    // ─── 2. Matcher over the typescript-go candidate list ──────────
    // (loc_generated.go: English + 13 MustParse'd locales.)
    let mut supported = alloc::vec::Vec::new();
    supported.push(language::English);
    for s in [
        "zh-CN", "zh-TW", "cs-CZ", "de-DE", "es-ES", "fr-FR", "it-IT", "ja-JP",
        "ko-KR", "pl-PL", "pt-BR", "ru-RU", "tr-TR",
    ] {
        supported.push(language::MustParse(s));
    }
    let matcher = language::NewMatcher(supported.as_slice());
    for (input, want_idx, want_conf) in MATCH_VECS {
        let (tag, err) = language::Parse(*input);
        if err != goish::nil {
            die(b"t2: match vector failed to parse\n");
        }
        let (_, idx, conf) = matcher.Match([tag]);
        if idx != *want_idx || conf_int(conf) != *want_conf {
            fmt::Println!("match:", *input, "got", idx, conf_int(conf), "want", *want_idx, *want_conf);
            die(b"t2: Match mismatch\n");
        }
    }

    // ─── 3. The typescript-go locale.go / diagnostics flow ─────────
    // Parse gracefully fails (locale.go Parse wrapper).
    let (_, err) = language::Parse("not a locale!");
    if err == goish::nil {
        die(b"t3: malformed locale must error\n");
    }
    // `loc == language.Und` gate (diagnostics getLocalizedMessages).
    let (de, err) = language::Parse("de-AT");
    if err != goish::nil || de == language::Und {
        die(b"t3: de-AT parses and is not Und\n");
    }
    if language::Und != language::Tag::default() {
        die(b"t3: zero Tag is Und\n");
    }
    // conf >= language.Low gate.
    let (_, idx, conf) = matcher.Match([de]);
    if !(conf >= language::Low) || idx != 4 {
        die(b"t3: de-AT resolves to de-DE with conf >= Low\n");
    }
    // Tag as map key (localizedMessagesCache is keyed by Tag).
    let mut cache: map<language::Tag, string> = map::new();
    cache.Set(language::MustParse("de-DE"), "german");
    cache.Set(language::MustParse("pt-BR"), "portuguese");
    let (v, ok) = cache.Get(language::MustParse("de-DE"));
    if !ok || v.as_bytes() != b"german" {
        die(b"t3: Tag map key roundtrip\n");
    }
    let (_, ok) = cache.Get(language::MustParse("fr-FR"));
    if ok {
        die(b"t3: absent Tag key\n");
    }

    let msg = b"TEXT_LANGUAGE_OK 118 parse + 108 match vectors vs x/text v0.38.0\n";
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
    syscall::Exit(0);
}
