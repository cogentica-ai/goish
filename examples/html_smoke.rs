// html_smoke — exercise html::EscapeString + UnescapeString.
//
// Test vectors lifted from /share/go/src/html/escape_test.go
// (escapeTests + unescapeTests slices), supplemented with numeric-ref
// vectors from the Go source documentation.
//
// Coverage:
//   1. EscapeString — empty string round-trips to empty.
//   2. EscapeString — no special chars passes through.
//   3. EscapeString — all five entities escaped exactly once.
//   4. EscapeString — adjacent special chars.
//   5. UnescapeString — round-trip of EscapeString output.
//   6. UnescapeString — &amp; &lt; &gt; &quot; &apos; (HTML5 names).
//   7. UnescapeString — decimal numeric ref (&#225; → á).
//   8. UnescapeString — hex numeric ref (&#xE1; → á).
//   9. UnescapeString — Windows-1252 replacement (&#x80; → €).
//  10. UnescapeString — invalid numeric ref → U+FFFD.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::gostring::string;
use goish::html;
use goish::{syscall, Println};

const KB: usize = 1024;

static FAILED: AtomicUsize = AtomicUsize::new(0);

fn fail() {
    FAILED.fetch_add(1, Ordering::AcqRel);
}

fn check_str(got: &string, want: &str) -> bool {
    if got.Len() as usize != want.len() {
        return false;
    }
    let bytes = want.as_bytes();
    let mut i: goish::int = 0;
    while (i as usize) < want.len() {
        if got[i] != bytes[i as usize] {
            return false;
        }
        i += 1;
    }
    true
}

fn write_result(idx: u8, label: &[u8], pass: bool) {
    syscall::Write(syscall::STDOUT, b"[".as_ptr(), 1);
    let d2 = b'0' + (idx % 10);
    if idx >= 10 {
        let d1 = b'0' + (idx / 10);
        let buf = [d1, d2];
        syscall::Write(syscall::STDOUT, buf.as_ptr(), 2);
    } else {
        let buf = [b' ', d2];
        syscall::Write(syscall::STDOUT, buf.as_ptr(), 2);
    }
    syscall::Write(syscall::STDOUT, b"] ".as_ptr(), 2);
    syscall::Write(syscall::STDOUT, label.as_ptr(), label.len());
    if pass {
        syscall::Write(syscall::STDOUT, b" PASS\n".as_ptr(), 6);
    } else {
        syscall::Write(syscall::STDOUT, b" FAIL\n".as_ptr(), 6);
    }
}

#[goish::main]
fn main() {
    goish::go!(stack(128 * KB), || {
        run_tests();
        let f = FAILED.load(Ordering::Acquire);
        if f == 0 {
            Println!("ok 10/10");
            syscall::Exit(0);
        } else {
            Println!("FAIL", f as i64, "of 10");
            syscall::Exit(1);
        }
    });
    goish::runtime::sched::schedule();
}

fn run_tests() {
    test_1_empty();
    test_2_passthrough();
    test_3_five_entities();
    test_4_adjacent();
    test_5_round_trip();
    test_6_named_entities();
    test_7_decimal_numeric_ref();
    test_8_hex_numeric_ref();
    test_9_windows1252();
    test_10_invalid_numeric_ref();
}

fn test_1_empty() {
    let got = html::EscapeString(string::from_static(""));
    if check_str(&got, "") {
        write_result(1, b"EscapeString empty           ", true);
    } else {
        write_result(1, b"EscapeString empty           ", false);
        fail();
    }
}

fn test_2_passthrough() {
    let got = html::EscapeString(string::from_static("hello world"));
    if check_str(&got, "hello world") {
        write_result(2, b"EscapeString passthrough     ", true);
    } else {
        write_result(2, b"EscapeString passthrough     ", false);
        fail();
    }
}

fn test_3_five_entities() {
    let got = html::EscapeString(string::from_static("<>&\"'"));
    if check_str(&got, "&lt;&gt;&amp;&#34;&#39;") {
        write_result(3, b"EscapeString 5 entities      ", true);
    } else {
        write_result(3, b"EscapeString 5 entities      ", false);
        fail();
    }
}

fn test_4_adjacent() {
    let got = html::EscapeString(string::from_static("a<b>c"));
    if check_str(&got, "a&lt;b&gt;c") {
        write_result(4, b"EscapeString adjacent        ", true);
    } else {
        write_result(4, b"EscapeString adjacent        ", false);
        fail();
    }
}

fn test_5_round_trip() {
    let original = string::from_static("if x<y && z>0: print(\"a's\")");
    let escaped = html::EscapeString(original.clone());
    let unescaped = html::UnescapeString(escaped);
    if check_str(&unescaped, "if x<y && z>0: print(\"a's\")") {
        write_result(5, b"round-trip Escape->Unescape", true);
    } else {
        write_result(5, b"round-trip Escape->Unescape", false);
        fail();
    }
}

fn test_6_named_entities() {
    // Mix all 5 named entities (with semicolons).
    let got = html::UnescapeString(string::from_static("&amp;&lt;&gt;&quot;&apos;"));
    if check_str(&got, "&<>\"'") {
        write_result(6, b"UnescapeString named         ", true);
    } else {
        write_result(6, b"UnescapeString named         ", false);
        fail();
    }
}

fn test_7_decimal_numeric_ref() {
    // &#225; → á (UTF-8: 0xC3 0xA1)
    let got = html::UnescapeString(string::from_static("a&#225;b"));
    let want_bytes = [b'a', 0xC3, 0xA1, b'b'];
    if got.Len() as usize == want_bytes.len() {
        let mut ok = true;
        for i in 0..want_bytes.len() {
            if got[i as goish::int] != want_bytes[i] {
                ok = false;
                break;
            }
        }
        if ok {
            write_result(7, b"UnescapeString decimal       ", true);
            return;
        }
    }
    write_result(7, b"UnescapeString decimal       ", false);
    fail();
}

fn test_8_hex_numeric_ref() {
    // &#xE1; → á (UTF-8: 0xC3 0xA1) — same code point as test 7.
    let got = html::UnescapeString(string::from_static("a&#xE1;b"));
    let want_bytes = [b'a', 0xC3, 0xA1, b'b'];
    if got.Len() as usize == want_bytes.len() {
        let mut ok = true;
        for i in 0..want_bytes.len() {
            if got[i as goish::int] != want_bytes[i] {
                ok = false;
                break;
            }
        }
        if ok {
            write_result(8, b"UnescapeString hex           ", true);
            return;
        }
    }
    write_result(8, b"UnescapeString hex           ", false);
    fail();
}

fn test_9_windows1252() {
    // &#x80; → € (U+20AC, UTF-8: 0xE2 0x82 0xAC) via Windows-1252 map.
    let got = html::UnescapeString(string::from_static("&#x80;"));
    let want_bytes = [0xE2, 0x82, 0xAC];
    if got.Len() as usize == want_bytes.len() {
        let mut ok = true;
        for i in 0..want_bytes.len() {
            if got[i as goish::int] != want_bytes[i] {
                ok = false;
                break;
            }
        }
        if ok {
            write_result(9, b"UnescapeString Windows-1252  ", true);
            return;
        }
    }
    write_result(9, b"UnescapeString Windows-1252  ", false);
    fail();
}

fn test_10_invalid_numeric_ref() {
    // &#xD800; (surrogate) → U+FFFD (UTF-8: 0xEF 0xBF 0xBD).
    let got = html::UnescapeString(string::from_static("&#xD800;"));
    let want_bytes = [0xEF, 0xBF, 0xBD];
    if got.Len() as usize == want_bytes.len() {
        let mut ok = true;
        for i in 0..want_bytes.len() {
            if got[i as goish::int] != want_bytes[i] {
                ok = false;
                break;
            }
        }
        if ok {
            write_result(10, b"UnescapeString invalid->FFFD", true);
            return;
        }
    }
    write_result(10, b"UnescapeString invalid->FFFD", false);
    fail();
}
