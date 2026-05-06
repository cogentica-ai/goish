// strings_title_smoke — exercise strings.Title (strings.go:868).

#![no_std]
#![no_main]
#![allow(non_snake_case)]
#![allow(deprecated)]

extern crate alloc;
extern crate goish;

use goish::strings;
use goish::{string, syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Title("hello world") → "Hello World".
    {
        let s = strings::Title(string("hello world"));
        if s == "Hello World" {
            Println!("[ 1] Title two words           PASS");
        } else {
            Println!("[ 1] Title two words           FAIL got=", s);
            failed += 1;
        }
    }

    // 2. Title("HELLO world") preserves upper.
    {
        let s = strings::Title(string("HELLO world"));
        if s == "HELLO World" {
            Println!("[ 2] Title preserves upper     PASS");
        } else {
            Println!("[ 2] Title preserves upper     FAIL got=", s);
            failed += 1;
        }
    }

    // 3. Title("hello-world_42") — '-' separator, '_' and digits aren't.
    {
        let s = strings::Title(string("hello-world_42"));
        if s == "Hello-World_42" {
            Println!("[ 3] Title hyphen sep          PASS");
        } else {
            Println!("[ 3] Title hyphen sep          FAIL got=", s);
            failed += 1;
        }
    }

    // 4. Title("") → "".
    {
        let s = strings::Title(string(""));
        if s.Len() == 0 {
            Println!("[ 4] Title empty               PASS");
        } else {
            Println!("[ 4] Title empty               FAIL");
            failed += 1;
        }
    }

    // 5. Title("a") → "A".
    {
        let s = strings::Title(string("a"));
        if s == "A" {
            Println!("[ 5] Title single letter       PASS");
        } else {
            Println!("[ 5] Title single letter       FAIL got=", s);
            failed += 1;
        }
    }

    // 6. Title leading space: " hello" → " Hello".
    {
        let s = strings::Title(string(" hello"));
        if s == " Hello" {
            Println!("[ 6] Title leading space       PASS");
        } else {
            Println!("[ 6] Title leading space       FAIL got=", s);
            failed += 1;
        }
    }

    // 7. Title preserves non-ASCII bytes (slim — no Unicode ToTitle).
    //    "héllo" → "Héllo" (h → H, é stays as is).
    {
        let s = strings::Title(string("h\u{00e9}llo"));
        if s == "H\u{00e9}llo" {
            Println!("[ 7] Title preserves non-ASCII PASS");
        } else {
            Println!("[ 7] Title preserves non-ASCII FAIL got=", s);
            failed += 1;
        }
    }

    // 8. Title with tab separator: "a\tb" → "A\tB".
    {
        let s = strings::Title(string("a\tb"));
        if s == "A\tB" {
            Println!("[ 8] Title tab separator       PASS");
        } else {
            Println!("[ 8] Title tab separator       FAIL got=", s);
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 8/8");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 8");
        syscall::Exit(1);
    }
}
