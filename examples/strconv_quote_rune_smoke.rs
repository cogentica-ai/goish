// strconv_quote_rune_smoke — exercise strconv.QuoteRune,
// AppendQuoteRune, QuoteRuneToASCII, QuoteToASCII, AppendQuoteToASCII
// (quote.go:167 + 173 + 183 + 138 + 144).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::convert::bytes as as_bytes;
use goish::strconv;
use goish::types::rune;
use goish::{string, syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. QuoteRune('a') → "'a'".
    {
        let s = strconv::QuoteRune(b'a' as rune);
        if s == "'a'" {
            Println!("[ 1] QuoteRune ASCII letter   PASS");
        } else {
            Println!("[ 1] QuoteRune ASCII letter   FAIL got=", s);
            failed += 1;
        }
    }

    // 2. QuoteRune('\n') → "'\\n'".
    {
        let s = strconv::QuoteRune(b'\n' as rune);
        if s == "'\\n'" {
            Println!("[ 2] QuoteRune \\n             PASS");
        } else {
            Println!("[ 2] QuoteRune \\n             FAIL got=", s);
            failed += 1;
        }
    }

    // 3. QuoteRune('\'') → "'\\''".
    {
        let s = strconv::QuoteRune(b'\'' as rune);
        if s == "'\\''" {
            Println!("[ 3] QuoteRune single quote   PASS");
        } else {
            Println!("[ 3] QuoteRune single quote   FAIL got=", s);
            failed += 1;
        }
    }

    // 4. QuoteRune('\\') → "'\\\\'".
    {
        let s = strconv::QuoteRune(b'\\' as rune);
        if s == "'\\\\'" {
            Println!("[ 4] QuoteRune backslash      PASS");
        } else {
            Println!("[ 4] QuoteRune backslash      FAIL got=", s);
            failed += 1;
        }
    }

    // 5. QuoteRune(0x07) → "'\\a'".
    {
        let s = strconv::QuoteRune(0x07);
        if s == "'\\a'" {
            Println!("[ 5] QuoteRune \\a (BEL)       PASS");
        } else {
            Println!("[ 5] QuoteRune \\a             FAIL got=", s);
            failed += 1;
        }
    }

    // 6. QuoteRune(0x01) → "'\\x01'".
    {
        let s = strconv::QuoteRune(0x01);
        if s == "'\\x01'" {
            Println!("[ 6] QuoteRune \\x01           PASS");
        } else {
            Println!("[ 6] QuoteRune \\x01           FAIL got=", s);
            failed += 1;
        }
    }

    // 7. QuoteRune(0x7F) (DEL) → "'\\x7f'".
    {
        let s = strconv::QuoteRune(0x7F);
        if s == "'\\x7f'" {
            Println!("[ 7] QuoteRune DEL            PASS");
        } else {
            Println!("[ 7] QuoteRune DEL            FAIL got=", s);
            failed += 1;
        }
    }

    // 8. QuoteRune(0xE9) ('é') → "'\\u00e9'".
    {
        let s = strconv::QuoteRune(0xE9);
        if s == "'\\u00e9'" {
            Println!("[ 8] QuoteRune Latin-1 é     PASS");
        } else {
            Println!("[ 8] QuoteRune Latin-1 é     FAIL got=", s);
            failed += 1;
        }
    }

    // 9. QuoteRune(0x1F600) (smiley) → "'\\U0001f600'".
    {
        let s = strconv::QuoteRune(0x1F600);
        if s == "'\\U0001f600'" {
            Println!("[ 9] QuoteRune SMP rune       PASS");
        } else {
            Println!("[ 9] QuoteRune SMP rune       FAIL got=", s);
            failed += 1;
        }
    }

    // 10. QuoteRuneToASCII = QuoteRune in slim port.
    {
        let s = strconv::QuoteRuneToASCII(0xE9);
        if s == "'\\u00e9'" {
            Println!("[10] QuoteRuneToASCII         PASS");
        } else {
            Println!("[10] QuoteRuneToASCII         FAIL got=", s);
            failed += 1;
        }
    }

    // 11. AppendQuoteRune preserves prefix: "X" + 'a' → "X'a'".
    {
        let dst = as_bytes(string("X"));
        let got = strconv::AppendQuoteRune(dst, b'a' as rune);
        let s = string::from_bytes(&got.__into_vec());
        if s == "X'a'" {
            Println!("[11] AppendQuoteRune prefix    PASS");
        } else {
            Println!("[11] AppendQuoteRune prefix    FAIL got=", s);
            failed += 1;
        }
    }

    // 12. AppendQuoteRuneToASCII preserves prefix.
    {
        let dst = as_bytes(string(""));
        let got = strconv::AppendQuoteRuneToASCII(dst, 0xE9);
        let s = string::from_bytes(&got.__into_vec());
        if s == "'\\u00e9'" {
            Println!("[12] AppendQuoteRuneToASCII   PASS");
        } else {
            Println!("[12] AppendQuoteRuneToASCII   FAIL got=", s);
            failed += 1;
        }
    }

    // 13. QuoteToASCII delegates to Quote — bytes ≥ 0x80 escaped.
    {
        let raw: [u8; 3] = [b'a', 0xC3, b'b'];
        let s = strconv::QuoteToASCII(string::from_bytes(&raw));
        if s == "\"a\\xc3b\"" {
            Println!("[13] QuoteToASCII high byte    PASS");
        } else {
            Println!("[13] QuoteToASCII high byte    FAIL got=", s);
            failed += 1;
        }
    }

    // 14. AppendQuoteToASCII preserves prefix.
    {
        let dst = as_bytes(string("X"));
        let got = strconv::AppendQuoteToASCII(dst, string("ab"));
        let s = string::from_bytes(&got.__into_vec());
        if s == "X\"ab\"" {
            Println!("[14] AppendQuoteToASCII       PASS");
        } else {
            Println!("[14] AppendQuoteToASCII       FAIL got=", s);
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 14/14");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 14");
        syscall::Exit(1);
    }
}
