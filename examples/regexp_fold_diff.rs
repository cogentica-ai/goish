// regexp_fold_diff — differential sweep for the `(?i)` flag and the
// successive-match scan.
//
// goish's regexp rejected `(?i)` at Compile time, which made every
// pattern in typescript-go's internal/semver uncompilable; it also had
// no Split, which semver's range parser needs. This sweeps both against
// the REAL Go regexp package, byte-compared against
// examples/regexpfold_ref.txt:
//
//   30 patterns × 53 inputs × {MatchString, FindStringSubmatch}
//   12 patterns × 14 inputs × 6 counts ×
//       {FindAllString, FindAllStringIndex, FindAllStringSubmatch, Split}
//
// Regenerate the reference with:
//   go run tools/gen_regexpfold_ref.go > examples/regexpfold_ref.txt
//
// The corpus is not just "does `a` match `A`". It pins the parts of
// Go's flag semantics that are easy to get subtly wrong:
//   - scope: `^a(?i)b$` folds `b` only, and the flag dies at the
//     enclosing group's `)` — `^(a(?i)b)c$` leaves `c` case-sensitive;
//   - `(?i:...)` is group-local, `(?-i)` turns it back off;
//   - the flag persists across alternation branches inside a group;
//   - class folding happens BEFORE negation, so `(?i)[^a-f]` also
//     rejects 'A'-'F';
//   - a range straddling the two letter runs (`[Z-a]`) must clip;
//   - `\w`/`\d`/`\W` are NOT folded — Go's fold does not touch a
//     predefined class.
//
// and, for the scan, the two empty-match rules that no single-match
// sweep can reach: an empty match colliding with the previous match's
// end is DROPPED, and the scan steps one RUNE past an empty match
// (hence the UTF-8 inputs).
//
// Every one of those is mutation-checked. One fold site is NOT covered
// and cannot be: folding an ESCAPED literal needs an escaped ASCII
// letter, and Go rejects every letter escape that has a case, so no
// Go-valid pattern reaches it. Noted at the site in src/regexp/mod.rs.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::string::String as RustString;
use alloc::vec::Vec;

use goish::regexp;
use goish::string;
use goish::syscall;

const REF: &str = include_str!("regexpfold_ref.txt");

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn push_usize(out: &mut RustString, v: usize) {
    let mut d = [0u8; 20];
    let mut i = 0;
    let mut n = v;
    loop {
        d[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
        if n == 0 {
            break;
        }
    }
    while i > 0 {
        i -= 1;
        out.push(d[i] as char);
    }
}

/// The generator's `esc`: printable ASCII except `\` verbatim,
/// everything else `\xNN`, and an empty string as `-`.
fn push_esc(out: &mut RustString, s: &[u8]) {
    if s.is_empty() {
        out.push('-');
        return;
    }
    for &c in s {
        if c >= 0x21 && c < 0x7f && c != b'\\' {
            out.push(c as char);
        } else {
            out.push_str("\\x");
            let hex = b"0123456789abcdef";
            out.push(hex[(c >> 4) as usize] as char);
            out.push(hex[(c & 0xf) as usize] as char);
        }
    }
}

fn patterns() -> Vec<&'static str> {
    alloc::vec![
        r"(?i)^(0|[1-9]\d*)(?:\.(0|[1-9]\d*)(?:\.(0|[1-9]\d*)(?:-([a-z0-9-.]+))?(?:\+([a-z0-9-.]+))?)?)?$",
        r"(?i)^(?:0|[1-9]\d*|[a-z-][a-z0-9-]*)(?:\.(?:0|[1-9]\d*|[a-zA-Z-][a-zA-Z0-9-]*))*$",
        r"(?i)^(?:0|[1-9]\d*|[a-z-][a-z0-9-]*)$",
        r"(?i)^[a-z0-9-]+(?:\.[a-z0-9-]+)*$",
        r"(?i)^[a-z0-9-]+$",
        r"^a(?i)b$",
        r"^(a(?i)b)c$",
        r"^(?:a(?i)b)c$",
        r"^a(?i:b)c$",
        r"^(?i:ab)c$",
        r"^(?i)a(?-i)b$",
        r"^(?i)(?-i:a)b$",
        r"^(?i)ab|cd$",
        r"^((?i)ab|cd)$",
        r"^(?i)[a-f]+$",
        r"^(?i)[^a-f]+$",
        r"^(?i)[a-fA-F0-9]+$",
        r"^(?i)[^0-9]$",
        r"^(?i)[z]$",
        r"^(?i)[a-]$",
        r"^(?i)[Z-a]+$",
        r"^(?i)\w+$",
        r"^(?i)\d+$",
        r"^(?i)\W$",
        r"^(?i)a\.b$",
        r"^(?i)_-1$",
        r"^(?i)a*b+c?$",
        r"^(?i)(ab)+$",
        r"(?i)",
        r"^(?i)$",
    ]
}

fn inputs() -> Vec<&'static str> {
    alloc::vec![
        "",
        "a",
        "A",
        "b",
        "B",
        "ab",
        "aB",
        "Ab",
        "AB",
        "abc",
        "ABC",
        "aBc",
        "c",
        "C",
        "cd",
        "CD",
        "Cd",
        "z",
        "Z",
        "q",
        "Q",
        "_",
        "-",
        "_-1",
        "0",
        "9",
        "0.0.0",
        "1.2.3",
        "1.2.3-Alpha.1",
        "1.2.3-ALPHA.1+Build.5",
        "1.2.3+BUILD",
        "01",
        "1.2.3-",
        "abcdef",
        "ABCDEF",
        "aBcDeF",
        "gG",
        "abC",
        "aBC",
        "AbC",
        "abcD",
        "aBcD",
        "[",
        "]",
        "^",
        "a.b",
        "aXb",
        "a*b",
        "\\",
        "1",
        "12",
        "aab",
        "aaB",
    ]
}

fn allPatterns() -> Vec<&'static str> {
    alloc::vec![
        r"a*",
        r"a",
        r",",
        r"\s+",
        r"\|\|",
        r"x*",
        r"(a)(b)?",
        r"(?i)a+",
        r"(?i)[a-c]",
        r"^",
        r"$",
        // `.` is absent — see the note in tools/gen_regexpfold_ref.go.
        r"",
    ]
}

fn allInputs() -> Vec<&'static str> {
    alloc::vec![
        "",
        "a",
        "abaabaccadaaae",
        "a,b,,c",
        "  a  b ",
        "a||b||c",
        "a|b",
        ",a,",
        ",,",
        "banana",
        "AaBbCc",
        "héllo",
        "日本語",
        "aé a",
    ]
}

const ALL_COUNTS: [i64; 6] = [-1, 0, 1, 2, 3, 5];

/// Go's `qs`: `nil` for a nil slice, `[...]` otherwise. goish slices are
/// never nil, so len()==0 prints as `nil` — see the note in main() on the
/// one row shape where that is not the same thing.
fn push_strs(out: &mut RustString, ss: &goish::goslice::slice<goish::gostring::string>) {
    if ss.len() == 0 {
        out.push_str("nil");
        return;
    }
    out.push('[');
    for (i, s) in ss.as_ref().iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        push_esc(out, s.as_bytes());
    }
    out.push(']');
}

#[goish::main]
fn main() {
    let mut got = RustString::new();
    let pats = patterns();
    let ins = inputs();

    for (pi, p) in pats.iter().enumerate() {
        let re = regexp::MustCompile(*p);
        got.push_str("P ");
        push_usize(&mut got, pi);
        got.push(' ');
        push_esc(&mut got, p.as_bytes());
        got.push('\n');

        for (ii, inp) in ins.iter().enumerate() {
            got.push_str("M ");
            push_usize(&mut got, pi);
            got.push(' ');
            push_usize(&mut got, ii);
            got.push(' ');
            got.push_str(if re.MatchString(*inp) {
                "true"
            } else {
                "false"
            });
            got.push('\n');

            // Go returns nil for no-match; goish returns an empty slice,
            // and a match always yields at least the whole-match group,
            // so len()==0 is exactly Go's nil.
            let m = re.FindStringSubmatch(*inp);
            got.push_str("S ");
            push_usize(&mut got, pi);
            got.push(' ');
            push_usize(&mut got, ii);
            if m.len() == 0 {
                got.push_str(" nil\n");
                continue;
            }
            got.push(' ');
            push_usize(&mut got, m.len() as usize);
            for g in m.as_ref().iter() {
                got.push(' ');
                push_esc(&mut got, g.as_bytes());
            }
            got.push('\n');
        }
    }

    // ─── the successive-match scan ────────────────────────────────────
    for (pi, p) in allPatterns().iter().enumerate() {
        let re = regexp::MustCompile(*p);
        got.push_str("Q ");
        push_usize(&mut got, pi);
        got.push(' ');
        push_esc(&mut got, p.as_bytes());
        got.push('\n');

        for (ii, inp) in allInputs().iter().enumerate() {
            for n in ALL_COUNTS {
                for tag in ["FA", "FI", "FS", "SP"] {
                    got.push_str(tag);
                    got.push(' ');
                    push_usize(&mut got, pi);
                    got.push(' ');
                    push_usize(&mut got, ii);
                    got.push(' ');
                    if n < 0 {
                        got.push('-');
                        push_usize(&mut got, (-n) as usize);
                    } else {
                        push_usize(&mut got, n as usize);
                    }
                    got.push(' ');
                    match tag {
                        "FA" => push_strs(&mut got, &re.FindAllString(*inp, n)),
                        "SP" => push_strs(&mut got, &re.Split(*inp, n)),
                        "FI" => {
                            let idx = re.FindAllStringIndex(*inp, n);
                            if idx.len() == 0 {
                                got.push_str("nil");
                            } else {
                                got.push('[');
                                for (i, m) in idx.as_ref().iter().enumerate() {
                                    if i > 0 {
                                        got.push(' ');
                                    }
                                    push_usize(&mut got, m[0] as usize);
                                    got.push(':');
                                    push_usize(&mut got, m[1] as usize);
                                }
                                got.push(']');
                            }
                        }
                        _ => {
                            let rows = re.FindAllStringSubmatch(*inp, n);
                            if rows.len() == 0 {
                                got.push_str("nil");
                            } else {
                                got.push('[');
                                for (i, row) in rows.as_ref().iter().enumerate() {
                                    if i > 0 {
                                        got.push(' ');
                                    }
                                    push_strs(&mut got, row);
                                }
                                got.push(']');
                            }
                        }
                    }
                    got.push('\n');
                }
            }
        }
    }

    // The ONE place goish cannot match Go byte-for-byte, pinned rather
    // than hidden: `regexp.MustCompile("").Split("", n)` returns a
    // non-nil EMPTY []string in Go, and goish's slice<T> has no nil
    // state to distinguish that from nil (tracked as the nil-vs-empty
    // gap). Every other row must match exactly, and the count is
    // asserted below, so both a regression and a future fix show up.
    let mut divergences = 0usize;
    {
        let mut line = 1usize;
        let mut gi = got.lines();
        let mut ri = REF.lines();
        loop {
            match (gi.next(), ri.next()) {
                (None, None) => break,
                (Some(g), Some(r)) if g == r => line += 1,
                (Some(g), Some(r))
                    if r.starts_with("SP 11 0 ")
                        && r.ends_with(" []")
                        && g.strip_suffix("nil") == r.strip_suffix("[]") =>
                {
                    divergences += 1;
                    line += 1;
                }
                (g, r) => {
                    let mut m = RustString::from("REGEXP_FOLD MISMATCH at line ");
                    push_usize(&mut m, line);
                    m.push_str("\n want: ");
                    m.push_str(r.unwrap_or("<eof>"));
                    m.push_str("\n got:  ");
                    m.push_str(g.unwrap_or("<eof>"));
                    m.push('\n');
                    die(m.as_bytes());
                }
            }
            if line > 100000 {
                die(b"regexp_fold: runaway diff\n");
            }
        }
    }
    if divergences != 5 {
        let mut m = RustString::from("regexp_fold: expected exactly 5 nil-vs-empty rows, saw ");
        push_usize(&mut m, divergences);
        m.push('\n');
        die(m.as_bytes());
    }

    // Compile-time rejection is part of the contract: `(?s)`/`(?m)` and
    // every other `(?...)` construct must still fail loudly rather than
    // silently parsing as something else.
    for bad in [
        r"(?s)a",
        r"(?m)a",
        r"(?U)a",
        r"(?)a",
        r"(?-)a",
        r"(?=a)",
        r"(?P<n>a)",
    ] {
        let (_, err) = regexp::Compile(bad);
        if err == goish::nil {
            die(b"regexp_fold: unsupported (?...) construct compiled\n");
        }
    }
    // Go: "missing argument to repetition operator".
    let (_, err) = regexp::Compile(r"(?i)*");
    if err == goish::nil {
        die(b"regexp_fold: quantifier on a flag setter compiled\n");
    }

    let mut msg = RustString::from("REGEXP_FOLD_OK ");
    push_usize(&mut msg, REF.lines().count());
    msg.push_str(" rows byte-exact vs real Go regexp\n");
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
    let _ = string::from("");
}
