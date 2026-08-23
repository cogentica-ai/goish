// unicode_predicates_smoke — exercise unicode.IsControl / IsPrint /
// IsGraphic / IsPunct / IsTitle / ToTitle (ASCII slim).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::syscall;
use goish::types::rune;
use goish::unicode;

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. IsControl: 0x00 (NUL), 0x09 (TAB), 0x1F, 0x7F (DEL), 0x80, 0x9F.
    {
        if unicode::IsControl(0x00)
            && unicode::IsControl(0x09)
            && unicode::IsControl(0x1F)
            && unicode::IsControl(0x7F)
            && unicode::IsControl(0x80)
            && unicode::IsControl(0x9F)
        {
            fmt::Println!("[ 1] IsControl ctrl chars      PASS");
        } else {
            fmt::Println!("[ 1] IsControl ctrl chars      FAIL");
            failed += 1;
        }
    }

    // 2. IsControl: NOT for printable ASCII or > 0x9F.
    {
        if !unicode::IsControl(b'A' as rune)
            && !unicode::IsControl(b' ' as rune)
            && !unicode::IsControl(0xA0)
            && !unicode::IsControl(-1)
        {
            fmt::Println!("[ 2] IsControl non-ctrl        PASS");
        } else {
            fmt::Println!("[ 2] IsControl non-ctrl        FAIL");
            failed += 1;
        }
    }

    // 3. IsPrint: ASCII printable.
    {
        if unicode::IsPrint(b' ' as rune)
            && unicode::IsPrint(b'~' as rune)
            && unicode::IsPrint(b'A' as rune)
        {
            fmt::Println!("[ 3] IsPrint ASCII             PASS");
        } else {
            fmt::Println!("[ 3] IsPrint ASCII             FAIL");
            failed += 1;
        }
    }

    // 4. IsPrint: NOT for control or out-of-range.
    {
        if !unicode::IsPrint(0x00)
            && !unicode::IsPrint(0x7F)
            && !unicode::IsPrint(-1)
            && !unicode::IsPrint(0x110000)
        {
            fmt::Println!("[ 4] IsPrint non-printable     PASS");
        } else {
            fmt::Println!("[ 4] IsPrint non-printable     FAIL");
            failed += 1;
        }
    }

    // 5. IsGraphic: includes U+00A0 (NBSP), unlike IsPrint.
    {
        if unicode::IsGraphic(0xA0) && !unicode::IsPrint(0xA0) {
            fmt::Println!("[ 5] IsGraphic vs IsPrint NBSP PASS");
        } else {
            fmt::Println!("[ 5] IsGraphic vs IsPrint NBSP FAIL");
            failed += 1;
        }
    }

    // 6. IsGraphic: agrees with IsPrint elsewhere.
    {
        if unicode::IsGraphic(b'A' as rune)
            && unicode::IsGraphic(b'!' as rune)
            && !unicode::IsGraphic(0x00)
            && !unicode::IsGraphic(0x7F)
        {
            fmt::Println!("[ 6] IsGraphic agrees w/ Print PASS");
        } else {
            fmt::Println!("[ 6] IsGraphic agrees w/ Print FAIL");
            failed += 1;
        }
    }

    // 7. IsPunct: ASCII punctuation chars.
    {
        if unicode::IsPunct(b'!' as rune)
            && unicode::IsPunct(b'.' as rune)
            && unicode::IsPunct(b':' as rune)
            && unicode::IsPunct(b'?' as rune)
            && unicode::IsPunct(b'[' as rune)
            && unicode::IsPunct(b'{' as rune)
        {
            fmt::Println!("[ 7] IsPunct ASCII punct       PASS");
        } else {
            fmt::Println!("[ 7] IsPunct ASCII punct       FAIL");
            failed += 1;
        }
    }

    // 8. IsPunct: NOT for letters/digits/space/control.
    {
        if !unicode::IsPunct(b'A' as rune)
            && !unicode::IsPunct(b'0' as rune)
            && !unicode::IsPunct(b' ' as rune)
            && !unicode::IsPunct(0x00)
        {
            fmt::Println!("[ 8] IsPunct non-punct         PASS");
        } else {
            fmt::Println!("[ 8] IsPunct non-punct         FAIL");
            failed += 1;
        }
    }

    // 9. IsTitle: ASCII slim returns false for everything.
    {
        if !unicode::IsTitle(b'A' as rune)
            && !unicode::IsTitle(b'a' as rune)
            && !unicode::IsTitle(0x01C5)
        /* LJ-titlecase */
        {
            fmt::Println!("[ 9] IsTitle ASCII slim        PASS");
        } else {
            fmt::Println!("[ 9] IsTitle ASCII slim        FAIL");
            failed += 1;
        }
    }

    // 10. ToTitle: ASCII letters titlecase = uppercase; non-letters pass-through.
    {
        if unicode::ToTitle(b'a' as rune) == b'A' as rune
            && unicode::ToTitle(b'Z' as rune) == b'Z' as rune
            && unicode::ToTitle(b'5' as rune) == b'5' as rune
            && unicode::ToTitle(b' ' as rune) == b' ' as rune
        {
            fmt::Println!("[10] ToTitle ASCII             PASS");
        } else {
            fmt::Println!("[10] ToTitle ASCII             FAIL");
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
