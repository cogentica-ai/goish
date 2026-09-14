// regexp_parse_ref_smoke — `syntax.Parse`, stage 2b-iv of §2c.
//
// The parser is complete. This runs 139 patterns through it under
// three flag sets — Perl, POSIX and Literal — and compares Go's
// canonical `String()` of the tree, its capture count, and, for the 30
// or so that do not parse, the exact error. 417 rows.
//
// `String()` is the right thing to compare rather than a tree dump: it
// is CANONICAL, so it catches a wrong flag placement, a missed
// factoring and a mis-parsed class alike, and it is what stage 2a
// already pinned independently.
//
// ─── one real gap, stated rather than hidden ─────────────────────────
//
// `\p{Han}`, `\p{L}` and every named Unicode group ERROR here with
// `invalid character class range`, where Go resolves them. `\p{Any}`
// and `\p{ASCII}` work.
//
// The reason is not in regexp: `unicodeTable` reads
// `unicode.Categories`, `unicode.Scripts` and their Fold twins, and
// goish's `unicode` has neither those maps nor the tables behind them —
// `tables.rs` exports `Mn` and `Zs` and nothing else. So the rows for
// `\pN`, `\pZ` and `\p{Nope}` are goish's OWN answers, marked below,
// and they are a refusal rather than a wrong match: a pattern using one
// fails to compile instead of silently matching the wrong runes. It is
// a `unicode` item that `regexp` inherits. ROADMAP §2c records it.
//
// ─── what the corpus is chosen to catch ──────────────────────────────
//
//   "a."                 -> "(?-s:a.)"   the flag pass, on the
//                                        simplest possible input
//   "abc|abd|aef|bcx|bcy" -> Go's own factoring example
//   "(?i)K"              -> "(?i:K)"     fold canonicalisation
//   "a**"                -> an error under Perl, because stacking a
//                                        repeat is a syntax error, and
//                                        NOT an error under POSIX
//   "[a-b-c]"            -> parses under Perl, errors under POSIX:
//                                        `-` is only positional there
//   "x{1000}" / "x{1001}" -> either side of the repeat limit
//   the ten-deep `x{2}` nest -> the size limit, which is what the
//                                        free list's numRegexp gates

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use goish::regexp::syntax;
use goish::types::int;
use goish::{fmt, string, strconv};

static mut FAILED: int = 0;
static mut RUN: int = 0;

const GO: [&str; 504] = [
    r#"  0 perl  "a"                  "a" | cap=0"#,
    r#"  0 posix "a"                  "a" | cap=0"#,
    r#"  0 lit   "a"                  "a" | cap=0"#,
    r#"  1 perl  "a."                 "(?-s:a.)" | cap=0"#,
    r#"  1 posix "a."                 "(?-s:a.)" | cap=0"#,
    r#"  1 lit   "a."                 "a\\." | cap=0"#,
    r#"  2 perl  "a.b"                "(?-s:a.b)" | cap=0"#,
    r#"  2 posix "a.b"                "(?-s:a.b)" | cap=0"#,
    r#"  2 lit   "a.b"                "a\\.b" | cap=0"#,
    r#"  3 perl  "ab"                 "ab" | cap=0"#,
    r#"  3 posix "ab"                 "ab" | cap=0"#,
    r#"  3 lit   "ab"                 "ab" | cap=0"#,
    r#"  4 perl  "a.b.c"              "(?-s:a.b.c)" | cap=0"#,
    r#"  4 posix "a.b.c"              "(?-s:a.b.c)" | cap=0"#,
    r#"  4 lit   "a.b.c"              "a\\.b\\.c" | cap=0"#,
    r#"  5 perl  "abc"                "abc" | cap=0"#,
    r#"  5 posix "abc"                "abc" | cap=0"#,
    r#"  5 lit   "abc"                "abc" | cap=0"#,
    r#"  6 perl  "a|^"                "a|\\A" | cap=0"#,
    r#"  6 posix "a|^"                "(?m:a|^)" | cap=0"#,
    r#"  6 lit   "a|^"                "a\\|\\^" | cap=0"#,
    r#"  7 perl  "a|b"                "[ab]" | cap=0"#,
    r#"  7 posix "a|b"                "[ab]" | cap=0"#,
    r#"  7 lit   "a|b"                "a\\|b" | cap=0"#,
    r#"  8 perl  "(a)"                "(a)" | cap=1"#,
    r#"  8 posix "(a)"                "(a)" | cap=1"#,
    r#"  8 lit   "(a)"                "\\(a\\)" | cap=0"#,
    r#"  9 perl  "(a)|b"              "(a)|b" | cap=1"#,
    r#"  9 posix "(a)|b"              "(a)|b" | cap=1"#,
    r#"  9 lit   "(a)|b"              "\\(a\\)\\|b" | cap=0"#,
    r#" 10 perl  "a*"                 "a*" | cap=0"#,
    r#" 10 posix "a*"                 "a*" | cap=0"#,
    r#" 10 lit   "a*"                 "a\\*" | cap=0"#,
    r#" 11 perl  "a+"                 "a+" | cap=0"#,
    r#" 11 posix "a+"                 "a+" | cap=0"#,
    r#" 11 lit   "a+"                 "a\\+" | cap=0"#,
    r#" 12 perl  "a?"                 "a?" | cap=0"#,
    r#" 12 posix "a?"                 "a?" | cap=0"#,
    r#" 12 lit   "a?"                 "a\\?" | cap=0"#,
    r#" 13 perl  "a{2}"               "a{2}" | cap=0"#,
    r#" 13 posix "a{2}"               "a{2}" | cap=0"#,
    r#" 13 lit   "a{2}"               "a\\{2\\}" | cap=0"#,
    r#" 14 perl  "a{2,3}"             "a{2,3}" | cap=0"#,
    r#" 14 posix "a{2,3}"             "a{2,3}" | cap=0"#,
    r#" 14 lit   "a{2,3}"             "a\\{2,3\\}" | cap=0"#,
    r#" 15 perl  "a{2,}"              "a{2,}" | cap=0"#,
    r#" 15 posix "a{2,}"              "a{2,}" | cap=0"#,
    r#" 15 lit   "a{2,}"              "a\\{2,\\}" | cap=0"#,
    r#" 16 perl  "a**"                err="error parsing regexp: invalid nested repetition operator: `**`""#,
    r#" 16 posix "a**"                "(?:a*)*" | cap=0"#,
    r#" 16 lit   "a**"                "a\\*\\*" | cap=0"#,
    r#" 17 perl  "a*+"                err="error parsing regexp: invalid nested repetition operator: `*+`""#,
    r#" 17 posix "a*+"                "(?:a*)+" | cap=0"#,
    r#" 17 lit   "a*+"                "a\\*\\+" | cap=0"#,
    r#" 18 perl  "a|b|c"              "[a-c]" | cap=0"#,
    r#" 18 posix "a|b|c"              "[a-c]" | cap=0"#,
    r#" 18 lit   "a|b|c"              "a\\|b\\|c" | cap=0"#,
    r#" 19 perl  "a|b|c|d"            "[a-d]" | cap=0"#,
    r#" 19 posix "a|b|c|d"            "[a-d]" | cap=0"#,
    r#" 19 lit   "a|b|c|d"            "a\\|b\\|c\\|d" | cap=0"#,
    r#" 20 perl  "abc|abd"            "ab[cd]" | cap=0"#,
    r#" 20 posix "abc|abd"            "ab[cd]" | cap=0"#,
    r#" 20 lit   "abc|abd"            "abc\\|abd" | cap=0"#,
    r#" 21 perl  "abc|abd|aef|bcx|bcy" "a(?:b[cd]|ef)|bc[xy]" | cap=0"#,
    r#" 21 posix "abc|abd|aef|bcx|bcy" "a(?:b[cd]|ef)|bc[xy]" | cap=0"#,
    r#" 21 lit   "abc|abd|aef|bcx|bcy" "abc\\|abd\\|aef\\|bcx\\|bcy" | cap=0"#,
    r#" 22 perl  "(?i)a"              "(?i:A)" | cap=0"#,
    r#" 22 posix "(?i)a"              err="error parsing regexp: missing argument to repetition operator: `?`""#,
    r#" 22 lit   "(?i)a"              "\\(\\?i\\)a" | cap=0"#,
    r#" 23 perl  "(?i)abc"            "(?i:ABC)" | cap=0"#,
    r#" 23 posix "(?i)abc"            err="error parsing regexp: missing argument to repetition operator: `?`""#,
    r#" 23 lit   "(?i)abc"            "\\(\\?i\\)abc" | cap=0"#,
    r#" 24 perl  "(?i)[a-z]"          "[A-Za-zſK]" | cap=0"#,
    r#" 24 posix "(?i)[a-z]"          err="error parsing regexp: missing argument to repetition operator: `?`""#,
    r#" 24 lit   "(?i)[a-z]"          "\\(\\?i\\)\\[a-z\\]" | cap=0"#,
    r#" 25 perl  "(?i)K"              "(?i:K)" | cap=0"#,
    r#" 25 posix "(?i)K"              err="error parsing regexp: missing argument to repetition operator: `?`""#,
    r#" 25 lit   "(?i)K"              "\\(\\?i\\)K" | cap=0"#,
    r#" 26 perl  "(?i)K"              "(?i:K)" | cap=0"#,
    r#" 26 posix "(?i)K"              err="error parsing regexp: missing argument to repetition operator: `?`""#,
    r#" 26 lit   "(?i)K"              "\\(\\?i\\)K" | cap=0"#,
    r#" 27 perl  "(?s)."              "(?s:.)" | cap=0"#,
    r#" 27 posix "(?s)."              err="error parsing regexp: missing argument to repetition operator: `?`""#,
    r#" 27 lit   "(?s)."              "\\(\\?s\\)\\." | cap=0"#,
    r#" 28 perl  "(?m)^"              "(?m:^)" | cap=0"#,
    r#" 28 posix "(?m)^"              err="error parsing regexp: missing argument to repetition operator: `?`""#,
    r#" 28 lit   "(?m)^"              "\\(\\?m\\)\\^" | cap=0"#,
    r#" 29 perl  "(?m)$"              "(?m:$)" | cap=0"#,
    r#" 29 posix "(?m)$"              err="error parsing regexp: missing argument to repetition operator: `?`""#,
    r#" 29 lit   "(?m)$"              "\\(\\?m\\)\\$" | cap=0"#,
    r#" 30 perl  "^"                  "\\A" | cap=0"#,
    r#" 30 posix "^"                  "(?m:^)" | cap=0"#,
    r#" 30 lit   "^"                  "\\^" | cap=0"#,
    r#" 31 perl  "$"                  "(?-m:$)" | cap=0"#,
    r#" 31 posix "$"                  "(?m:$)" | cap=0"#,
    r#" 31 lit   "$"                  "\\$" | cap=0"#,
    r#" 32 perl  "\\A"                "\\A" | cap=0"#,
    r#" 32 posix "\\A"                err="error parsing regexp: invalid escape sequence: `\\A`""#,
    r#" 32 lit   "\\A"                "\\\\A" | cap=0"#,
    r#" 33 perl  "\\z"                "\\z" | cap=0"#,
    r#" 33 posix "\\z"                err="error parsing regexp: invalid escape sequence: `\\z`""#,
    r#" 33 lit   "\\z"                "\\\\z" | cap=0"#,
    r#" 34 perl  "\\b"                "\\b" | cap=0"#,
    r#" 34 posix "\\b"                err="error parsing regexp: invalid escape sequence: `\\b`""#,
    r#" 34 lit   "\\b"                "\\\\b" | cap=0"#,
    r#" 35 perl  "\\B"                "\\B" | cap=0"#,
    r#" 35 posix "\\B"                err="error parsing regexp: invalid escape sequence: `\\B`""#,
    r#" 35 lit   "\\B"                "\\\\B" | cap=0"#,
    r#" 36 perl  "[a-z]"              "[a-z]" | cap=0"#,
    r#" 36 posix "[a-z]"              "[a-z]" | cap=0"#,
    r#" 36 lit   "[a-z]"              "\\[a-z\\]" | cap=0"#,
    r#" 37 perl  "[^a-z]"             "[^a-z]" | cap=0"#,
    r#" 37 posix "[^a-z]"             "[^\\na-z]" | cap=0"#,
    r#" 37 lit   "[^a-z]"             "\\[\\^a-z\\]" | cap=0"#,
    r#" 38 perl  "[a-]"               "[\\-a]" | cap=0"#,
    r#" 38 posix "[a-]"               "[\\-a]" | cap=0"#,
    r#" 38 lit   "[a-]"               "\\[a-\\]" | cap=0"#,
    r#" 39 perl  "[-a]"               "[\\-a]" | cap=0"#,
    r#" 39 posix "[-a]"               "[\\-a]" | cap=0"#,
    r#" 39 lit   "[-a]"               "\\[-a\\]" | cap=0"#,
    r#" 40 perl  "[]a]"               "[\\]a]" | cap=0"#,
    r#" 40 posix "[]a]"               "[\\]a]" | cap=0"#,
    r#" 40 lit   "[]a]"               "\\[\\]a\\]" | cap=0"#,
    r#" 41 perl  "[a^]"               "[\\^a]" | cap=0"#,
    r#" 41 posix "[a^]"               "[\\^a]" | cap=0"#,
    r#" 41 lit   "[a^]"               "\\[a\\^\\]" | cap=0"#,
    r#" 42 perl  "[[:alpha:]]"        "[A-Za-z]" | cap=0"#,
    r#" 42 posix "[[:alpha:]]"        "[A-Za-z]" | cap=0"#,
    r#" 42 lit   "[[:alpha:]]"        "\\[\\[:alpha:\\]\\]" | cap=0"#,
    r#" 43 perl  "[[:^alpha:]]"       "[^A-Za-z]" | cap=0"#,
    r#" 43 posix "[[:^alpha:]]"       "[^A-Za-z]" | cap=0"#,
    r#" 43 lit   "[[:^alpha:]]"       "\\[\\[:\\^alpha:\\]\\]" | cap=0"#,
    r#" 44 perl  "[\\d]"              "[0-9]" | cap=0"#,
    r#" 44 posix "[\\d]"              err="error parsing regexp: invalid escape sequence: `\\d`""#,
    r#" 44 lit   "[\\d]"              "\\[\\\\d\\]" | cap=0"#,
    r#" 45 perl  "[\\D]"              "[^0-9]" | cap=0"#,
    r#" 45 posix "[\\D]"              err="error parsing regexp: invalid escape sequence: `\\D`""#,
    r#" 45 lit   "[\\D]"              "\\[\\\\D\\]" | cap=0"#,
    r#" 46 perl  "[\\s\\w]"           "[\\t\\n\\f\\r 0-9A-Z_a-z]" | cap=0"#,
    r#" 46 posix "[\\s\\w]"           err="error parsing regexp: invalid escape sequence: `\\s`""#,
    r#" 46 lit   "[\\s\\w]"           "\\[\\\\s\\\\w\\]" | cap=0"#,
    r#" 47 perl  "\\d"                "[0-9]" | cap=0"#,
    r#" 47 posix "\\d"                err="error parsing regexp: invalid escape sequence: `\\d`""#,
    r#" 47 lit   "\\d"                "\\\\d" | cap=0"#,
    r#" 48 perl  "\\D"                "[^0-9]" | cap=0"#,
    r#" 48 posix "\\D"                err="error parsing regexp: invalid escape sequence: `\\D`""#,
    r#" 48 lit   "\\D"                "\\\\D" | cap=0"#,
    r#" 49 perl  "\\s"                "[\\t\\n\\f\\r ]" | cap=0"#,
    r#" 49 posix "\\s"                err="error parsing regexp: invalid escape sequence: `\\s`""#,
    r#" 49 lit   "\\s"                "\\\\s" | cap=0"#,
    r#" 50 perl  "\\w"                "[0-9A-Z_a-z]" | cap=0"#,
    r#" 50 posix "\\w"                err="error parsing regexp: invalid escape sequence: `\\w`""#,
    r#" 50 lit   "\\w"                "\\\\w" | cap=0"#,
    r#" 51 perl  "\\W"                "[^0-9A-Z_a-z]" | cap=0"#,
    r#" 51 posix "\\W"                err="error parsing regexp: invalid escape sequence: `\\W`""#,
    r#" 51 lit   "\\W"                "\\\\W" | cap=0"#,
    r#" 52 perl  "[a-b-c]"            "[\\-a-c]" | cap=0"#,
    r#" 52 posix "[a-b-c]"            err="error parsing regexp: invalid character class range: `-c`""#,
    r#" 52 lit   "[a-b-c]"            "\\[a-b-c\\]" | cap=0"#,
    r#" 53 perl  "[\\-]"              "-" | cap=0"#,
    r#" 53 posix "[\\-]"              "-" | cap=0"#,
    r#" 53 lit   "[\\-]"              "\\[\\\\-\\]" | cap=0"#,
    r#" 54 perl  "[a-c-e]"            "[\\-a-ce]" | cap=0"#,
    r#" 54 posix "[a-c-e]"            err="error parsing regexp: invalid character class range: `-e`""#,
    r#" 54 lit   "[a-c-e]"            "\\[a-c-e\\]" | cap=0"#,
    r#" 55 perl  "(?:a)"              "a" | cap=0"#,
    r#" 55 posix "(?:a)"              err="error parsing regexp: missing argument to repetition operator: `?`""#,
    r#" 55 lit   "(?:a)"              "\\(\\?:a\\)" | cap=0"#,
    r#" 56 perl  "(?:a|b)"            "[ab]" | cap=0"#,
    r#" 56 posix "(?:a|b)"            err="error parsing regexp: missing argument to repetition operator: `?`""#,
    r#" 56 lit   "(?:a|b)"            "\\(\\?:a\\|b\\)" | cap=0"#,
    r#" 57 perl  "(?P<name>a)"        "(?P<name>a)" | cap=1"#,
    r#" 57 posix "(?P<name>a)"        err="error parsing regexp: missing argument to repetition operator: `?`""#,
    r#" 57 lit   "(?P<name>a)"        "\\(\\?P<name>a\\)" | cap=0"#,
    r#" 58 perl  "(?<name>a)"         "(?P<name>a)" | cap=1"#,
    r#" 58 posix "(?<name>a)"         err="error parsing regexp: missing argument to repetition operator: `?`""#,
    r#" 58 lit   "(?<name>a)"         "\\(\\?<name>a\\)" | cap=0"#,
    r#" 59 perl  "(?P<name>a)(?P<x>b)" "(?P<name>a)(?P<x>b)" | cap=2"#,
    r#" 59 posix "(?P<name>a)(?P<x>b)" err="error parsing regexp: missing argument to repetition operator: `?`""#,
    r#" 59 lit   "(?P<name>a)(?P<x>b)" "\\(\\?P<name>a\\)\\(\\?P<x>b\\)" | cap=0"#,
    r#" 60 perl  "(?i:a)b"            "(?i:A)b" | cap=0"#,
    r#" 60 posix "(?i:a)b"            err="error parsing regexp: missing argument to repetition operator: `?`""#,
    r#" 60 lit   "(?i:a)b"            "\\(\\?i:a\\)b" | cap=0"#,
    r#" 61 perl  "(?i)a(?-i)b"        "(?i:A)b" | cap=0"#,
    r#" 61 posix "(?i)a(?-i)b"        err="error parsing regexp: missing argument to repetition operator: `?`""#,
    r#" 61 lit   "(?i)a(?-i)b"        "\\(\\?i\\)a\\(\\?-i\\)b" | cap=0"#,
    r#" 62 perl  "((a))"              "((a))" | cap=2"#,
    r#" 62 posix "((a))"              "((a))" | cap=2"#,
    r#" 62 lit   "((a))"              "\\(\\(a\\)\\)" | cap=0"#,
    r#" 63 perl  "(a)(b)"             "(a)(b)" | cap=2"#,
    r#" 63 posix "(a)(b)"             "(a)(b)" | cap=2"#,
    r#" 63 lit   "(a)(b)"             "\\(a\\)\\(b\\)" | cap=0"#,
    r#" 64 perl  "x{0}"               "x{0}" | cap=0"#,
    r#" 64 posix "x{0}"               "x{0}" | cap=0"#,
    r#" 64 lit   "x{0}"               "x\\{0\\}" | cap=0"#,
    r#" 65 perl  "x{0,}"              "x{0,}" | cap=0"#,
    r#" 65 posix "x{0,}"              "x{0,}" | cap=0"#,
    r#" 65 lit   "x{0,}"              "x\\{0,\\}" | cap=0"#,
    r#" 66 perl  "x{1,}"              "x{1,}" | cap=0"#,
    r#" 66 posix "x{1,}"              "x{1,}" | cap=0"#,
    r#" 66 lit   "x{1,}"              "x\\{1,\\}" | cap=0"#,
    r#" 67 perl  "x{1,2}"             "x{1,2}" | cap=0"#,
    r#" 67 posix "x{1,2}"             "x{1,2}" | cap=0"#,
    r#" 67 lit   "x{1,2}"             "x\\{1,2\\}" | cap=0"#,
    r#" 68 perl  "x{1000}"            "x{1000}" | cap=0"#,
    r#" 68 posix "x{1000}"            "x{1000}" | cap=0"#,
    r#" 68 lit   "x{1000}"            "x\\{1000\\}" | cap=0"#,
    r#" 69 perl  "\\Qab+\\E"          "ab\\+" | cap=0"#,
    r#" 69 posix "\\Qab+\\E"          err="error parsing regexp: invalid escape sequence: `\\Q`""#,
    r#" 69 lit   "\\Qab+\\E"          "\\\\Qab\\+\\\\E" | cap=0"#,
    r#" 70 perl  "\\Q\\E"             "(?:)" | cap=0"#,
    r#" 70 posix "\\Q\\E"             err="error parsing regexp: invalid escape sequence: `\\Q`""#,
    r#" 70 lit   "\\Q\\E"             "\\\\Q\\\\E" | cap=0"#,
    r#" 71 perl  "\\Qa"               "a" | cap=0"#,
    r#" 71 posix "\\Qa"               err="error parsing regexp: invalid escape sequence: `\\Q`""#,
    r#" 71 lit   "\\Qa"               "\\\\Qa" | cap=0"#,
    r#" 72 perl  "\\."                "\\." | cap=0"#,
    r#" 72 posix "\\."                "\\." | cap=0"#,
    r#" 72 lit   "\\."                "\\\\\\." | cap=0"#,
    r#" 73 perl  "\\*"                "\\*" | cap=0"#,
    r#" 73 posix "\\*"                "\\*" | cap=0"#,
    r#" 73 lit   "\\*"                "\\\\\\*" | cap=0"#,
    r#" 74 perl  "\\x41"              "A" | cap=0"#,
    r#" 74 posix "\\x41"              "A" | cap=0"#,
    r#" 74 lit   "\\x41"              "\\\\x41" | cap=0"#,
    r#" 75 perl  "\\x{4e00}"          "一" | cap=0"#,
    r#" 75 posix "\\x{4e00}"          "一" | cap=0"#,
    r#" 75 lit   "\\x{4e00}"          "\\\\x\\{4e00\\}" | cap=0"#,
    r#" 76 perl  "\\101"              "A" | cap=0"#,
    r#" 76 posix "\\101"              "A" | cap=0"#,
    r#" 76 lit   "\\101"              "\\\\101" | cap=0"#,
    r#" 77 perl  "\\0"                "\\x00" | cap=0"#,
    r#" 77 posix "\\0"                "\\x00" | cap=0"#,
    r#" 77 lit   "\\0"                "\\\\0" | cap=0"#,
    r#" 78 perl  "\\012"              "\\n" | cap=0"#,
    r#" 78 posix "\\012"              "\\n" | cap=0"#,
    r#" 78 lit   "\\012"              "\\\\012" | cap=0"#,
    r#" 79 perl  "\\n"                "\\n" | cap=0"#,
    r#" 79 posix "\\n"                "\\n" | cap=0"#,
    r#" 79 lit   "\\n"                "\\\\n" | cap=0"#,
    r#" 80 perl  "\\t"                "\\t" | cap=0"#,
    r#" 80 posix "\\t"                "\\t" | cap=0"#,
    r#" 80 lit   "\\t"                "\\\\t" | cap=0"#,
    r#" 81 perl  "\\a"                "\\a" | cap=0"#,
    r#" 81 posix "\\a"                "\\a" | cap=0"#,
    r#" 81 lit   "\\a"                "\\\\a" | cap=0"#,
    r#" 82 perl  "\\f"                "\\f" | cap=0"#,
    r#" 82 posix "\\f"                "\\f" | cap=0"#,
    r#" 82 lit   "\\f"                "\\\\f" | cap=0"#,
    r#" 83 perl  "\\v"                "\\v" | cap=0"#,
    r#" 83 posix "\\v"                "\\v" | cap=0"#,
    r#" 83 lit   "\\v"                "\\\\v" | cap=0"#,
    r#" 84 perl  "\\r"                "\\r" | cap=0"#,
    r#" 84 posix "\\r"                "\\r" | cap=0"#,
    r#" 84 lit   "\\r"                "\\\\r" | cap=0"#,
    r#" 85 perl  "\\p{Any}"           "(?s:.)" | cap=0"#,
    r#" 85 posix "\\p{Any}"           err="error parsing regexp: invalid escape sequence: `\\p`""#,
    r#" 85 lit   "\\p{Any}"           "\\\\p\\{Any\\}" | cap=0"#,
    r#" 86 perl  "\\p{ASCII}"         "[\\x00-\\x7f]" | cap=0"#,
    r#" 86 posix "\\p{ASCII}"         err="error parsing regexp: invalid escape sequence: `\\p`""#,
    r#" 86 lit   "\\p{ASCII}"         "\\\\p\\{ASCII\\}" | cap=0"#,
    r#" 87 perl  "(?i)\\p{ASCII}"     "[\\x00-\\x7fſK]" | cap=0"#,
    r#" 87 posix "(?i)\\p{ASCII}"     err="error parsing regexp: missing argument to repetition operator: `?`""#,
    r#" 87 lit   "(?i)\\p{ASCII}"     "\\(\\?i\\)\\\\p\\{ASCII\\}" | cap=0"#,
    r#" 88 perl  "\\P{Any}"           "[^\\x00-\\x{10FFFF}]" | cap=0"#,
    r#" 88 posix "\\P{Any}"           err="error parsing regexp: invalid escape sequence: `\\P`""#,
    r#" 88 lit   "\\P{Any}"           "\\\\P\\{Any\\}" | cap=0"#,
    r#" 89 perl  ""                   "(?:)" | cap=0"#,
    r#" 89 posix ""                   "(?:)" | cap=0"#,
    r#" 89 lit   ""                   "" | cap=0"#,
    r#" 90 perl  "()"                 "()" | cap=1"#,
    r#" 90 posix "()"                 "()" | cap=1"#,
    r#" 90 lit   "()"                 "\\(\\)" | cap=0"#,
    r#" 91 perl  "(?:)"               "(?:)" | cap=0"#,
    r#" 91 posix "(?:)"               err="error parsing regexp: missing argument to repetition operator: `?`""#,
    r#" 91 lit   "(?:)"               "\\(\\?:\\)" | cap=0"#,
    r#" 92 perl  "a**b"               err="error parsing regexp: invalid nested repetition operator: `**`""#,
    r#" 92 posix "a**b"               "(?:a*)*b" | cap=0"#,
    r#" 92 lit   "a**b"               "a\\*\\*b" | cap=0"#,
    r#" 93 perl  "|"                  "(?:)" | cap=0"#,
    r#" 93 posix "|"                  "(?:)" | cap=0"#,
    r#" 93 lit   "|"                  "\\|" | cap=0"#,
    r#" 94 perl  "|a"                 "(?:)|a" | cap=0"#,
    r#" 94 posix "|a"                 "(?:)|a" | cap=0"#,
    r#" 94 lit   "|a"                 "\\|a" | cap=0"#,
    r#" 95 perl  "a|"                 "a|(?:)" | cap=0"#,
    r#" 95 posix "a|"                 "a|(?:)" | cap=0"#,
    r#" 95 lit   "a|"                 "a\\|" | cap=0"#,
    r#" 96 perl  "||"                 "(?:)" | cap=0"#,
    r#" 96 posix "||"                 "(?:)" | cap=0"#,
    r#" 96 lit   "||"                 "\\|\\|" | cap=0"#,
    r#" 97 perl  ".*"                 "(?-s:.*)" | cap=0"#,
    r#" 97 posix ".*"                 "(?-s:.*)" | cap=0"#,
    r#" 97 lit   ".*"                 "\\.\\*" | cap=0"#,
    r#" 98 perl  ".+"                 "(?-s:.+)" | cap=0"#,
    r#" 98 posix ".+"                 "(?-s:.+)" | cap=0"#,
    r#" 98 lit   ".+"                 "\\.\\+" | cap=0"#,
    r#" 99 perl  "[^\\n]"             "(?-s:.)" | cap=0"#,
    r#" 99 posix "[^\\n]"             "(?-s:.)" | cap=0"#,
    r#" 99 lit   "[^\\n]"             "\\[\\^\\\\n\\]" | cap=0"#,
    r#"100 perl  "(?s)[^\\n]"         "(?-s:.)" | cap=0"#,
    r#"100 posix "(?s)[^\\n]"         err="error parsing regexp: missing argument to repetition operator: `?`""#,
    r#"100 lit   "(?s)[^\\n]"         "\\(\\?s\\)\\[\\^\\\\n\\]" | cap=0"#,
    r#"101 perl  "(?i)[k]"            "[KkK]" | cap=0"#,
    r#"101 posix "(?i)[k]"            err="error parsing regexp: missing argument to repetition operator: `?`""#,
    r#"101 lit   "(?i)[k]"            "\\(\\?i\\)\\[k\\]" | cap=0"#,
    r#"102 perl  "a{2}{3}"            err="error parsing regexp: invalid nested repetition operator: `{2}{3}`""#,
    r#"102 posix "a{2}{3}"            "(?:a{2}){3}" | cap=0"#,
    r#"102 lit   "a{2}{3}"            "a\\{2\\}\\{3\\}" | cap=0"#,
    r#"103 perl  "(a{2}){3}"          "(a{2}){3}" | cap=1"#,
    r#"103 posix "(a{2}){3}"          "(a{2}){3}" | cap=1"#,
    r#"103 lit   "(a{2}){3}"          "\\(a\\{2\\}\\)\\{3\\}" | cap=0"#,
    r#"104 perl  "\\Qa{2}\\E"         "a\\{2\\}" | cap=0"#,
    r#"104 posix "\\Qa{2}\\E"         err="error parsing regexp: invalid escape sequence: `\\Q`""#,
    r#"104 lit   "\\Qa{2}\\E"         "\\\\Qa\\{2\\}\\\\E" | cap=0"#,
    r#"105 perl  "("                  err="error parsing regexp: missing closing ): `(`""#,
    r#"105 posix "("                  err="error parsing regexp: missing closing ): `(`""#,
    r#"105 lit   "("                  "\\(" | cap=0"#,
    r#"106 perl  ")"                  err="error parsing regexp: unexpected ): `)`""#,
    r#"106 posix ")"                  err="error parsing regexp: unexpected ): `)`""#,
    r#"106 lit   ")"                  "\\)" | cap=0"#,
    r#"107 perl  "(a"                 err="error parsing regexp: missing closing ): `(a`""#,
    r#"107 posix "(a"                 err="error parsing regexp: missing closing ): `(a`""#,
    r#"107 lit   "(a"                 "\\(a" | cap=0"#,
    r#"108 perl  "a)"                 err="error parsing regexp: unexpected ): `a)`""#,
    r#"108 posix "a)"                 err="error parsing regexp: unexpected ): `a)`""#,
    r#"108 lit   "a)"                 "a\\)" | cap=0"#,
    r#"109 perl  "["                  err="error parsing regexp: missing closing ]: `[`""#,
    r#"109 posix "["                  err="error parsing regexp: missing closing ]: `[`""#,
    r#"109 lit   "["                  "\\[" | cap=0"#,
    r#"110 perl  "[a"                 err="error parsing regexp: missing closing ]: `[a`""#,
    r#"110 posix "[a"                 err="error parsing regexp: missing closing ]: `[a`""#,
    r#"110 lit   "[a"                 "\\[a" | cap=0"#,
    r#"111 perl  "[z-a]"              err="error parsing regexp: invalid character class range: `z-a`""#,
    r#"111 posix "[z-a]"              err="error parsing regexp: invalid character class range: `z-a`""#,
    r#"111 lit   "[z-a]"              "\\[z-a\\]" | cap=0"#,
    r#"112 perl  "a{2,1}"             err="error parsing regexp: invalid repeat count: `{2,1}`""#,
    r#"112 posix "a{2,1}"             err="error parsing regexp: invalid repeat count: `{2,1}`""#,
    r#"112 lit   "a{2,1}"             "a\\{2,1\\}" | cap=0"#,
    r#"113 perl  "a{1001}"            err="error parsing regexp: invalid repeat count: `{1001}`""#,
    r#"113 posix "a{1001}"            err="error parsing regexp: invalid repeat count: `{1001}`""#,
    r#"113 lit   "a{1001}"            "a\\{1001\\}" | cap=0"#,
    r#"114 perl  "\\"                 err="error parsing regexp: trailing backslash at end of expression: ``""#,
    r#"114 posix "\\"                 err="error parsing regexp: trailing backslash at end of expression: ``""#,
    r#"114 lit   "\\"                 "\\\\" | cap=0"#,
    r#"115 perl  "\\q"                err="error parsing regexp: invalid escape sequence: `\\q`""#,
    r#"115 posix "\\q"                err="error parsing regexp: invalid escape sequence: `\\q`""#,
    r#"115 lit   "\\q"                "\\\\q" | cap=0"#,
    r#"116 perl  "\\C"                err="error parsing regexp: invalid escape sequence: `\\C`""#,
    r#"116 posix "\\C"                err="error parsing regexp: invalid escape sequence: `\\C`""#,
    r#"116 lit   "\\C"                "\\\\C" | cap=0"#,
    r#"117 perl  "\\x"                err="error parsing regexp: invalid escape sequence: `\\x`""#,
    r#"117 posix "\\x"                err="error parsing regexp: invalid escape sequence: `\\x`""#,
    r#"117 lit   "\\x"                "\\\\x" | cap=0"#,
    r#"118 perl  "\\xg"               err="error parsing regexp: invalid escape sequence: `\\xg`""#,
    r#"118 posix "\\xg"               err="error parsing regexp: invalid escape sequence: `\\xg`""#,
    r#"118 lit   "\\xg"               "\\\\xg" | cap=0"#,
    r#"119 perl  "\\x{}"              err="error parsing regexp: invalid escape sequence: `\\x{}`""#,
    r#"119 posix "\\x{}"              err="error parsing regexp: invalid escape sequence: `\\x{}`""#,
    r#"119 lit   "\\x{}"              "\\\\x\\{\\}" | cap=0"#,
    r#"120 perl  "\\x{110000}"        err="error parsing regexp: invalid escape sequence: `\\x{110000`""#,
    r#"120 posix "\\x{110000}"        err="error parsing regexp: invalid escape sequence: `\\x{110000`""#,
    r#"120 lit   "\\x{110000}"        "\\\\x\\{110000\\}" | cap=0"#,
    r#"121 perl  "(?"                 err="error parsing regexp: invalid or unsupported Perl syntax: `(?`""#,
    r#"121 posix "(?"                 err="error parsing regexp: missing argument to repetition operator: `?`""#,
    r#"121 lit   "(?"                 "\\(\\?" | cap=0"#,
    r#"122 perl  "(?i"                err="error parsing regexp: invalid or unsupported Perl syntax: `(?i`""#,
    r#"122 posix "(?i"                err="error parsing regexp: missing argument to repetition operator: `?`""#,
    r#"122 lit   "(?i"                "\\(\\?i" | cap=0"#,
    r#"123 perl  "(?P"                err="error parsing regexp: invalid or unsupported Perl syntax: `(?P`""#,
    r#"123 posix "(?P"                err="error parsing regexp: missing argument to repetition operator: `?`""#,
    r#"123 lit   "(?P"                "\\(\\?P" | cap=0"#,
    r#"124 perl  "(?P<"               err="error parsing regexp: invalid or unsupported Perl syntax: `(?P`""#,
    r#"124 posix "(?P<"               err="error parsing regexp: missing argument to repetition operator: `?`""#,
    r#"124 lit   "(?P<"               "\\(\\?P<" | cap=0"#,
    r#"125 perl  "(?P<>a)"            err="error parsing regexp: invalid named capture: `(?P<>`""#,
    r#"125 posix "(?P<>a)"            err="error parsing regexp: missing argument to repetition operator: `?`""#,
    r#"125 lit   "(?P<>a)"            "\\(\\?P<>a\\)" | cap=0"#,
    r#"126 perl  "(?P<a b>x)"         err="error parsing regexp: invalid named capture: `(?P<a b>`""#,
    r#"126 posix "(?P<a b>x)"         err="error parsing regexp: missing argument to repetition operator: `?`""#,
    r#"126 lit   "(?P<a b>x)"         "\\(\\?P<a b>x\\)" | cap=0"#,
    r#"127 perl  "(?<>a)"             err="error parsing regexp: invalid named capture: `(?<>`""#,
    r#"127 posix "(?<>a)"             err="error parsing regexp: missing argument to repetition operator: `?`""#,
    r#"127 lit   "(?<>a)"             "\\(\\?<>a\\)" | cap=0"#,
    r#"128 perl  "[[:nope:]]"         err="error parsing regexp: invalid character class range: `[:nope:]`""#,
    r#"128 posix "[[:nope:]]"         err="error parsing regexp: invalid character class range: `[:nope:]`""#,
    r#"128 lit   "[[:nope:]]"         "\\[\\[:nope:\\]\\]" | cap=0"#,
    r#"129 perl  "\\p{Nope}"          err="error parsing regexp: invalid character class range: `\\p{Nope}`""#,
    r#"129 posix "\\p{Nope}"          err="error parsing regexp: invalid escape sequence: `\\p`""#,
    r#"129 lit   "\\p{Nope}"          "\\\\p\\{Nope\\}" | cap=0"#,
    r#"130 perl  "(?P<name>a"         err="error parsing regexp: missing closing ): `(?P<name>a`""#,
    r#"130 posix "(?P<name>a"         err="error parsing regexp: missing argument to repetition operator: `?`""#,
    r#"130 lit   "(?P<name>a"         "\\(\\?P<name>a" | cap=0"#,
    r#"131 perl  "*"                  err="error parsing regexp: missing argument to repetition operator: `*`""#,
    r#"131 posix "*"                  err="error parsing regexp: missing argument to repetition operator: `*`""#,
    r#"131 lit   "*"                  "\\*" | cap=0"#,
    r#"132 perl  "+"                  err="error parsing regexp: missing argument to repetition operator: `+`""#,
    r#"132 posix "+"                  err="error parsing regexp: missing argument to repetition operator: `+`""#,
    r#"132 lit   "+"                  "\\+" | cap=0"#,
    r#"133 perl  "?"                  err="error parsing regexp: missing argument to repetition operator: `?`""#,
    r#"133 posix "?"                  err="error parsing regexp: missing argument to repetition operator: `?`""#,
    r#"133 lit   "?"                  "\\?" | cap=0"#,
    r#"134 perl  "{1}"                err="error parsing regexp: missing argument to repetition operator: `{1}`""#,
    r#"134 posix "{1}"                err="error parsing regexp: missing argument to repetition operator: `{1}`""#,
    r#"134 lit   "{1}"                "\\{1\\}" | cap=0"#,
    r#"135 perl  "a{2,1000000}"       err="error parsing regexp: invalid repeat count: `{2,1000000}`""#,
    r#"135 posix "a{2,1000000}"       err="error parsing regexp: invalid repeat count: `{2,1000000}`""#,
    r#"135 lit   "a{2,1000000}"       "a\\{2,1000000\\}" | cap=0"#,
    r#"136 perl  "((((((((((x{2}){2}){2}){2}){2}){2}){2}){2}){2}){2})" err="error parsing regexp: invalid repeat count: `{2}`""#,
    r#"136 posix "((((((((((x{2}){2}){2}){2}){2}){2}){2}){2}){2}){2})" err="error parsing regexp: invalid repeat count: `{2}`""#,
    r#"136 lit   "((((((((((x{2}){2}){2}){2}){2}){2}){2}){2}){2}){2})" "\\(\\(\\(\\(\\(\\(\\(\\(\\(\\(x\\{2\\}\\)\\{2\\}\\)\\{2\\}\\)\\{2\\}\\)\\{2\\}\\)\\{2\\}\\)\\{2\\}\\)\\{2\\}\\)\\{2\\}\\)\\{2\\}\\)" | cap=0"#,
    r#"137 perl  "a{01}"              "a\\{01\\}" | cap=0"#,
    r#"137 posix "a{01}"              "a\\{01\\}" | cap=0"#,
    r#"137 lit   "a{01}"              "a\\{01\\}" | cap=0"#,
    r#"138 perl  "a{0,01}"            "a\\{0,01\\}" | cap=0"#,
    r#"138 posix "a{0,01}"            "a\\{0,01\\}" | cap=0"#,
    r#"138 lit   "a{0,01}"            "a\\{0,01\\}" | cap=0"#,
    r#"139 perl  "x{00}"              "x\\{00\\}" | cap=0"#,
    r#"139 posix "x{00}"              "x\\{00\\}" | cap=0"#,
    r#"139 lit   "x{00}"              "x\\{00\\}" | cap=0"#,
    r#"140 perl  "a{1,02}"            "a\\{1,02\\}" | cap=0"#,
    r#"140 posix "a{1,02}"            "a\\{1,02\\}" | cap=0"#,
    r#"140 lit   "a{1,02}"            "a\\{1,02\\}" | cap=0"#,
    r#"141 perl  "a{0}"               "a{0}" | cap=0"#,
    r#"141 posix "a{0}"               "a{0}" | cap=0"#,
    r#"141 lit   "a{0}"               "a\\{0\\}" | cap=0"#,
    r#"142 perl  "a{00,1}"            "a\\{00,1\\}" | cap=0"#,
    r#"142 posix "a{00,1}"            "a\\{00,1\\}" | cap=0"#,
    r#"142 lit   "a{00,1}"            "a\\{00,1\\}" | cap=0"#,
    r#"143 perl  "a{99999999999}"     err="error parsing regexp: invalid repeat count: `{99999999999}`""#,
    r#"143 posix "a{99999999999}"     err="error parsing regexp: invalid repeat count: `{99999999999}`""#,
    r#"143 lit   "a{99999999999}"     "a\\{99999999999\\}" | cap=0"#,
    r#"144 perl  "a{1,99999999999}"   err="error parsing regexp: invalid repeat count: `{1,99999999999}`""#,
    r#"144 posix "a{1,99999999999}"   err="error parsing regexp: invalid repeat count: `{1,99999999999}`""#,
    r#"144 lit   "a{1,99999999999}"   "a\\{1,99999999999\\}" | cap=0"#,
    r#"145 perl  "a{100000000}"       err="error parsing regexp: invalid repeat count: `{100000000}`""#,
    r#"145 posix "a{100000000}"       err="error parsing regexp: invalid repeat count: `{100000000}`""#,
    r#"145 lit   "a{100000000}"       "a\\{100000000\\}" | cap=0"#,
    r#"146 perl  "a{999999999}"       err="error parsing regexp: invalid repeat count: `{999999999}`""#,
    r#"146 posix "a{999999999}"       err="error parsing regexp: invalid repeat count: `{999999999}`""#,
    r#"146 lit   "a{999999999}"       "a\\{999999999\\}" | cap=0"#,
    r#"147 perl  "[^a]"               "[^a]" | cap=0"#,
    r#"147 posix "[^a]"               "[^\\na]" | cap=0"#,
    r#"147 lit   "[^a]"               "\\[\\^a\\]" | cap=0"#,
    r#"148 perl  "[^-a]"              "[^\\-a]" | cap=0"#,
    r#"148 posix "[^-a]"              "[^\\n\\-a]" | cap=0"#,
    r#"148 lit   "[^-a]"              "\\[\\^-a\\]" | cap=0"#,
    r#"149 perl  "[^a-]"              "[^\\-a]" | cap=0"#,
    r#"149 posix "[^a-]"              "[^\\n\\-a]" | cap=0"#,
    r#"149 lit   "[^a-]"              "\\[\\^a-\\]" | cap=0"#,
    r#"150 perl  "[^\\d]"             "[^0-9]" | cap=0"#,
    r#"150 posix "[^\\d]"             err="error parsing regexp: invalid escape sequence: `\\d`""#,
    r#"150 lit   "[^\\d]"             "\\[\\^\\\\d\\]" | cap=0"#,
    r#"151 perl  "[^[:alpha:]]"       "[^A-Za-z]" | cap=0"#,
    r#"151 posix "[^[:alpha:]]"       "[^\\nA-Za-z]" | cap=0"#,
    r#"151 lit   "[^[:alpha:]]"       "\\[\\^\\[:alpha:\\]\\]" | cap=0"#,
    r#"152 perl  "[^\\n\\r]"          "[^\\n\\r]" | cap=0"#,
    r#"152 posix "[^\\n\\r]"          "[^\\n\\r]" | cap=0"#,
    r#"152 lit   "[^\\n\\r]"          "\\[\\^\\\\n\\\\r\\]" | cap=0"#,
    r#"153 perl  "(?i)[^k]"           "[^KkK]" | cap=0"#,
    r#"153 posix "(?i)[^k]"           err="error parsing regexp: missing argument to repetition operator: `?`""#,
    r#"153 lit   "(?i)[^k]"           "\\(\\?i\\)\\[\\^k\\]" | cap=0"#,
    r#"154 perl  "(?s)[^a]"           "[^a]" | cap=0"#,
    r#"154 posix "(?s)[^a]"           err="error parsing regexp: missing argument to repetition operator: `?`""#,
    r#"154 lit   "(?s)[^a]"           "\\(\\?s\\)\\[\\^a\\]" | cap=0"#,
    r#"155 perl  "[a-z-]"             "[\\-a-z]" | cap=0"#,
    r#"155 posix "[a-z-]"             "[\\-a-z]" | cap=0"#,
    r#"155 lit   "[a-z-]"             "\\[a-z-\\]" | cap=0"#,
    r#"156 perl  "[^^]"               "[^\\^]" | cap=0"#,
    r#"156 posix "[^^]"               "[^\\n\\^]" | cap=0"#,
    r#"156 lit   "[^^]"               "\\[\\^\\^\\]" | cap=0"#,
    r#"157 perl  "[^]a]"              "[^\\]a]" | cap=0"#,
    r#"157 posix "[^]a]"              "[^\\n\\]a]" | cap=0"#,
    r#"157 lit   "[^]a]"              "\\[\\^\\]a\\]" | cap=0"#,
    r#"158 perl  "a{999999999999999999999999}" err="error parsing regexp: invalid repeat count: `{999999999999999999999999}`""#,
    r#"158 posix "a{999999999999999999999999}" err="error parsing regexp: invalid repeat count: `{999999999999999999999999}`""#,
    r#"158 lit   "a{999999999999999999999999}" "a\\{999999999999999999999999\\}" | cap=0"#,
    r#"159 perl  "a{1,999999999999999999999999}" err="error parsing regexp: invalid repeat count: `{1,999999999999999999999999}`""#,
    r#"159 posix "a{1,999999999999999999999999}" err="error parsing regexp: invalid repeat count: `{1,999999999999999999999999}`""#,
    r#"159 lit   "a{1,999999999999999999999999}" "a\\{1,999999999999999999999999\\}" | cap=0"#,
    r#"160 perl  "a{99999999999999999999999999999999}" err="error parsing regexp: invalid repeat count: `{99999999999999999999999999999999}`""#,
    r#"160 posix "a{99999999999999999999999999999999}" err="error parsing regexp: invalid repeat count: `{99999999999999999999999999999999}`""#,
    r#"160 lit   "a{99999999999999999999999999999999}" "a\\{99999999999999999999999999999999\\}" | cap=0"#,
    r#"161 perl  "\\p{^Any}"          "[^\\x00-\\x{10FFFF}]" | cap=0"#,
    r#"161 posix "\\p{^Any}"          err="error parsing regexp: invalid escape sequence: `\\p`""#,
    r#"161 lit   "\\p{^Any}"          "\\\\p\\{\\^Any\\}" | cap=0"#,
    r#"162 perl  "\\P{^Any}"          "(?s:.)" | cap=0"#,
    r#"162 posix "\\P{^Any}"          err="error parsing regexp: invalid escape sequence: `\\P`""#,
    r#"162 lit   "\\P{^Any}"          "\\\\P\\{\\^Any\\}" | cap=0"#,
    r#"163 perl  "\\p{^ASCII}"        "[\\x80-\\x{10ffff}]" | cap=0"#,
    r#"163 posix "\\p{^ASCII}"        err="error parsing regexp: invalid escape sequence: `\\p`""#,
    r#"163 lit   "\\p{^ASCII}"        "\\\\p\\{\\^ASCII\\}" | cap=0"#,
    r#"164 perl  "\\P{^ASCII}"        "[\\x00-\\x7f]" | cap=0"#,
    r#"164 posix "\\P{^ASCII}"        err="error parsing regexp: invalid escape sequence: `\\P`""#,
    r#"164 lit   "\\P{^ASCII}"        "\\\\P\\{\\^ASCII\\}" | cap=0"#,
    r#"165 perl  "(?i)\\p{^ASCII}"    "[\\x80-žƀ-℩Å-\\x{10ffff}]" | cap=0"#,
    r#"165 posix "(?i)\\p{^ASCII}"    err="error parsing regexp: missing argument to repetition operator: `?`""#,
    r#"165 lit   "(?i)\\p{^ASCII}"    "\\(\\?i\\)\\\\p\\{\\^ASCII\\}" | cap=0"#,
    r#"166 perl  "\\p{}"              err="error parsing regexp: invalid character class range: `\\p{}`""#,
    r#"166 posix "\\p{}"              err="error parsing regexp: invalid escape sequence: `\\p`""#,
    r#"166 lit   "\\p{}"              "\\\\p\\{\\}" | cap=0"#,
    r#"167 perl  "\\p{^}"             err="error parsing regexp: invalid character class range: `\\p{^}`""#,
    r#"167 posix "\\p{^}"             err="error parsing regexp: invalid escape sequence: `\\p`""#,
    r#"167 lit   "\\p{^}"             "\\\\p\\{\\^\\}" | cap=0"#,
];
/// The corpus, decoded from the reference's own source.
const PATS: [&str; 168] = [
    "a",
    "a.",
    "a.b",
    "ab",
    "a.b.c",
    "abc",
    "a|^",
    "a|b",
    "(a)",
    "(a)|b",
    "a*",
    "a+",
    "a?",
    "a{2}",
    "a{2,3}",
    "a{2,}",
    "a**",
    "a*+",
    "a|b|c",
    "a|b|c|d",
    "abc|abd",
    "abc|abd|aef|bcx|bcy",
    "(?i)a",
    "(?i)abc",
    "(?i)[a-z]",
    "(?i)K",
    "(?i)\u{212a}",
    "(?s).",
    "(?m)^",
    "(?m)$",
    "^",
    "$",
    "\\A",
    "\\z",
    "\\b",
    "\\B",
    "[a-z]",
    "[^a-z]",
    "[a-]",
    "[-a]",
    "[]a]",
    "[a^]",
    "[[:alpha:]]",
    "[[:^alpha:]]",
    "[\\d]",
    "[\\D]",
    "[\\s\\w]",
    "\\d",
    "\\D",
    "\\s",
    "\\w",
    "\\W",
    "[a-b-c]",
    "[\\-]",
    "[a-c-e]",
    "(?:a)",
    "(?:a|b)",
    "(?P<name>a)",
    "(?<name>a)",
    "(?P<name>a)(?P<x>b)",
    "(?i:a)b",
    "(?i)a(?-i)b",
    "((a))",
    "(a)(b)",
    "x{0}",
    "x{0,}",
    "x{1,}",
    "x{1,2}",
    "x{1000}",
    "\\Qab+\\E",
    "\\Q\\E",
    "\\Qa",
    "\\.",
    "\\*",
    "\\x41",
    "\\x{4e00}",
    "\\101",
    "\\0",
    "\\012",
    "\\n",
    "\\t",
    "\\a",
    "\\f",
    "\\v",
    "\\r",
    "\\p{Any}",
    "\\p{ASCII}",
    "(?i)\\p{ASCII}",
    "\\P{Any}",
    "",
    "()",
    "(?:)",
    "a**b",
    "|",
    "|a",
    "a|",
    "||",
    ".*",
    ".+",
    "[^\\n]",
    "(?s)[^\\n]",
    "(?i)[k]",
    "a{2}{3}",
    "(a{2}){3}",
    "\\Qa{2}\\E",
    "(",
    ")",
    "(a",
    "a)",
    "[",
    "[a",
    "[z-a]",
    "a{2,1}",
    "a{1001}",
    "\\",
    "\\q",
    "\\C",
    "\\x",
    "\\xg",
    "\\x{}",
    "\\x{110000}",
    "(?",
    "(?i",
    "(?P",
    "(?P<",
    "(?P<>a)",
    "(?P<a b>x)",
    "(?<>a)",
    "[[:nope:]]",
    "\\p{Nope}",
    "(?P<name>a",
    "*",
    "+",
    "?",
    "{1}",
    "a{2,1000000}",
    "((((((((((x{2}){2}){2}){2}){2}){2}){2}){2}){2}){2})",
    "a{01}",
    "a{0,01}",
    "x{00}",
    "a{1,02}",
    "a{0}",
    "a{00,1}",
    "a{99999999999}",
    "a{1,99999999999}",
    "a{100000000}",
    "a{999999999}",
    "[^a]",
    "[^-a]",
    "[^a-]",
    "[^\\d]",
    "[^[:alpha:]]",
    "[^\\n\\r]",
    "(?i)[^k]",
    "(?s)[^a]",
    "[a-z-]",
    "[^^]",
    "[^]a]",
    "a{999999999999999999999999}",
    "a{1,999999999999999999999999}",
    "a{99999999999999999999999999999999}",
    "\\p{^Any}",
    "\\P{^Any}",
    "\\p{^ASCII}",
    "\\P{^ASCII}",
    "(?i)\\p{^ASCII}",
    "\\p{}",
    "\\p{^}",
];

fn line(ln: &mut usize, got: string) {
    unsafe { RUN += 1 };
    if *ln >= GO.len() {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln as int + 1, got);
        unsafe { FAILED += 1 };
        *ln += 1;
        return;
    }
    if got == GO[*ln] {
        fmt::Printf!("[ok] %s\n", got);
    } else {
        fmt::Printf!(
            "[!!] line %d\n  got  %q\n  want %q\n",
            *ln as int + 1,
            got,
            GO[*ln]
        );
        unsafe { FAILED += 1 };
    }
    *ln += 1;
}

/// `%-Ns`, padded by RUNE count as Go's fmt measures it.
fn l(s: string, w: int) -> string {
    let mut o = s;
    while goish::len(&goish::runes(o.clone())) < w {
        o = o + string::from_static(" ");
    }
    return o;
}

/// `%Nd`
fn d(v: i64, w: int) -> string {
    let mut o = strconv::Itoa(int::from(v));
    while o.Len() < w {
        o = string::from_static(" ") + o;
    }
    return o;
}

#[goish::main]
fn main() {
    let mut ln: usize = 0;
    let sets: [(&'static str, syntax::Flags); 3] = [
        ("perl", syntax::Perl),
        ("posix", syntax::POSIX),
        ("lit", syntax::Literal),
    ];

    for (i, pat) in PATS.iter().enumerate() {
        for (name, flags) in sets.iter() {
            let src = string::from_static(pat);
            let head = d(i as i64, int::from(3))
                + string::from_static(" ")
                + l(string::from_static(name), int::from(5))
                + string::from_static(" ")
                + l(strconv::Quote(src.clone()), int::from(20))
                + string::from_static(" ");
            let (re, err) = syntax::Parse(src, *flags);
            if !err.IsNil() {
                line(
                    &mut ln,
                    head + string::from_static("err=") + strconv::Quote(err.Error()),
                );
                continue;
            }
            let re = re.MustTake();
            line(
                &mut ln,
                head + strconv::Quote(re.String())
                    + string::from_static(" | cap=")
                    + strconv::Itoa(re.MaxCap()),
            );
        }
    }

    // ── the \p{Name} gap, asserted rather than omitted ─────────────
    //
    // These are goish's OWN answers, not Go's. Go resolves both out of
    // `unicode.Categories`; goish's `unicode` has neither that map nor
    // the tables behind it, so `unicodeTable` finds nothing and the
    // caller reports Go's own ErrInvalidCharRange.
    //
    // A refusal, not a wrong match: a pattern using one fails to
    // compile rather than silently matching the wrong runes.
    //
    // WHEN THE UNICODE TABLES LAND, THESE TWO ROWS GO RED, and that is
    // the point — they are the reminder to move them back into the
    // shared corpus above. Go's answers, for whoever does that:
    //
    //   \pN  "[0-9²³¹¼-¾٠-٩۰-۹…]"  a 100-plus-range class
    //   \pZ  "[ \xa0\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}]"
    let gaps: [&str; 2] = ["\\pN", "\\pZ"];
    for g in gaps.iter() {
        let src = string::from_static(g);
        let (_, err) = syntax::Parse(src.clone(), syntax::Perl);
        let got = if err.IsNil() {
            string::from_static("<nil> — the unicode tables landed; move this row into the corpus")
        } else {
            err.Error()
        };
        let want = string::from_static("error parsing regexp: invalid character class range: `")
            + src.clone()
            + string::from_static("`");
        unsafe { RUN += 1 };
        if got == want {
            fmt::Printf!("[ok] GAP %s %q\n", src, got);
        } else {
            unsafe { FAILED += 1 };
            fmt::Printf!("[!!] GAP %s\n  got  %q\n  want %q\n", src, got, want);
        }
    }

    let run = unsafe { RUN };
    let f = unsafe { FAILED };
    if run != GO.len() as int + 2 {
        fmt::Printf!("\nFAIL ran %d of %d rows\n", run, GO.len() as int + 2);
        goish::os::Exit(1);
    }
    if f == 0 {
        fmt::Printf!("\nok %d/%d\n", run, run);
        goish::os::Exit(0);
    }
    fmt::Printf!("\nFAIL %d\n", f);
    goish::os::Exit(1);
}
