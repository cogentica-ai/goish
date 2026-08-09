// bytes_runes_title_smoke — exercise bytes.Runes + bytes.Title
// (bytes/bytes.go:1159 + 836).

#![no_std]
#![no_main]
#![allow(non_snake_case)]
#![allow(deprecated)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::bytes;
use goish::convert::bytes as as_bytes;
use goish::types::rune;
use goish::{string, syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Runes("hello") → ['h','e','l','l','o'].
    {
        let r = bytes::Runes(as_bytes(string("hello")));
        let want: [rune; 5] = [b'h' as rune, b'e' as rune, b'l' as rune, b'l' as rune, b'o' as rune];
        let mut ok = r.Len() as usize == want.len();
        if ok {
            let mut i: i64 = 0;
            while (i as usize) < want.len() {
                if r[i] != want[i as usize] {
                    ok = false;
                    break;
                }
                i += 1;
            }
        }
        if ok {
            fmt::Println!("[ 1] Runes ascii              PASS");
        } else {
            fmt::Println!("[ 1] Runes ascii              FAIL");
            failed += 1;
        }
    }

    // 2. Runes("") → empty.
    {
        let r = bytes::Runes(as_bytes(string("")));
        if r.Len() == 0 {
            fmt::Println!("[ 2] Runes empty              PASS");
        } else {
            fmt::Println!("[ 2] Runes empty              FAIL");
            failed += 1;
        }
    }

    // 3. Runes("héllo") — 'é' is U+00E9 (2 UTF-8 bytes).
    {
        let r = bytes::Runes(as_bytes(string("h\u{00e9}llo")));
        if r.Len() == 5 && r[0i64] == b'h' as rune && r[1i64] == 0xE9 && r[4i64] == b'o' as rune {
            fmt::Println!("[ 3] Runes Latin-1 é         PASS");
        } else {
            fmt::Println!("[ 3] Runes Latin-1 é         FAIL len=", r.Len());
            failed += 1;
        }
    }

    // 4. Runes with multi-rune emoji-like scalar (U+1F600).
    {
        // U+1F600 in UTF-8: F0 9F 98 80
        let raw: [u8; 5] = [b'a', 0xF0, 0x9F, 0x98, 0x80];
        let r = bytes::Runes(as_bytes(string::from_bytes(&raw)));
        if r.Len() == 2 && r[0i64] == b'a' as rune && r[1i64] == 0x1F600 {
            fmt::Println!("[ 4] Runes SMP scalar         PASS");
        } else {
            fmt::Println!("[ 4] Runes SMP scalar         FAIL len=", r.Len());
            failed += 1;
        }
    }

    // 5. Title("hello world") → "Hello World".
    {
        let t = bytes::Title(as_bytes(string("hello world")));
        let s = string::from_bytes(&t.__into_vec());
        if s == "Hello World" {
            fmt::Println!("[ 5] Title two words          PASS");
        } else {
            fmt::Println!("[ 5] Title two words          FAIL got=", s);
            failed += 1;
        }
    }

    // 6. Title("HELLO world") — already-upper letters left alone.
    {
        let t = bytes::Title(as_bytes(string("HELLO world")));
        let s = string::from_bytes(&t.__into_vec());
        if s == "HELLO World" {
            fmt::Println!("[ 6] Title preserves upper    PASS");
        } else {
            fmt::Println!("[ 6] Title preserves upper    FAIL got=", s);
            failed += 1;
        }
    }

    // 7. Title("hello-world_42") — '-' is separator, '_' and digits aren't.
    {
        let t = bytes::Title(as_bytes(string("hello-world_42")));
        let s = string::from_bytes(&t.__into_vec());
        // '-' resets word boundary; '_' and digits do not. So:
        //   h → H, ... rest of word unchanged
        //   '-' separator, next 'w' → W
        //   ... 'world_42' contains '_' and digits — none start a new word.
        if s == "Hello-World_42" {
            fmt::Println!("[ 7] Title hyphen separator   PASS");
        } else {
            fmt::Println!("[ 7] Title hyphen separator   FAIL got=", s);
            failed += 1;
        }
    }

    // 8. Title("") → "".
    {
        let t = bytes::Title(as_bytes(string("")));
        if t.Len() == 0 {
            fmt::Println!("[ 8] Title empty              PASS");
        } else {
            fmt::Println!("[ 8] Title empty              FAIL");
            failed += 1;
        }
    }

    // 9. Title("a") → "A" (single ASCII letter).
    {
        let t = bytes::Title(as_bytes(string("a")));
        let s = string::from_bytes(&t.__into_vec());
        if s == "A" {
            fmt::Println!("[ 9] Title single letter      PASS");
        } else {
            fmt::Println!("[ 9] Title single letter      FAIL got=", s);
            failed += 1;
        }
    }

    // 10. Title with leading separator: " hello" → " Hello".
    {
        let t = bytes::Title(as_bytes(string(" hello")));
        let s = string::from_bytes(&t.__into_vec());
        if s == " Hello" {
            fmt::Println!("[10] Title leading space      PASS");
        } else {
            fmt::Println!("[10] Title leading space      FAIL got=", s);
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 10/10");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 10");
        syscall::Exit(1);
    }
}
