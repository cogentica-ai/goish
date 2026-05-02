// encodedword_smoke — exercise mime.WordEncoder / WordDecoder.
// (mime/encodedword.go)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::mime::{BEncoding, QEncoding, WordDecoder};
use goish::{string, syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. ASCII pass-through (no encoding needed).
    {
        let got = QEncoding.Encode(string("UTF-8"), string("hello"));
        if got == string("hello") {
            Println!("[ 1] QEncode ASCII unchanged PASS");
        } else {
            Println!("[ 1] QEncode ASCII unchanged FAIL got {}", got);
            failed += 1;
        }
    }

    // 2. Q-encode UTF-8 with single non-ASCII rune.
    {
        let got = QEncoding.Encode(string("UTF-8"), string("Café"));
        if got == string("=?UTF-8?q?Caf=C3=A9?=") {
            Println!("[ 2] QEncode Café           PASS");
        } else {
            Println!("[ 2] QEncode Café           FAIL got {}", got);
            failed += 1;
        }
    }

    // 3. B-encode UTF-8.
    {
        let got = BEncoding.Encode(string("UTF-8"), string("Hello, 世界"));
        if got == string("=?UTF-8?b?SGVsbG8sIOS4lueVjA==?=") {
            Println!("[ 3] BEncode Hello,世界      PASS");
        } else {
            Println!("[ 3] BEncode Hello,世界      FAIL got {}", got);
            failed += 1;
        }
    }

    // 4. Newline triggers encoding (tab passes through unchanged).
    {
        let got = QEncoding.Encode(string("UTF-8"), string("a\nb"));
        if got == string("=?UTF-8?q?a=0Ab?=") {
            Println!("[ 4] QEncode newline        PASS");
        } else {
            Println!("[ 4] QEncode newline        FAIL got {}", got);
            failed += 1;
        }
        let got2 = QEncoding.Encode(string("UTF-8"), string("a\tb"));
        if got2 == string("a\tb") {
            Println!("[ 4b] QEncode tab unchanged PASS");
        } else {
            Println!("[ 4b] QEncode tab unchanged FAIL got {}", got2);
            failed += 1;
        }
    }

    // 5. Decode Q-encoded.
    {
        let d = WordDecoder::new();
        let (got, err) = d.Decode(string("=?UTF-8?q?Caf=C3=A9?="));
        if err.IsNil() && got == string("Café") {
            Println!("[ 5] Decode Q Café          PASS");
        } else {
            Println!("[ 5] Decode Q Café          FAIL");
            failed += 1;
        }
    }

    // 6. Decode B-encoded UTF-8.
    {
        let d = WordDecoder::new();
        let (got, err) = d.Decode(string("=?UTF-8?B?SGVsbG8sIOS4lueVjA==?="));
        if err.IsNil() && got == string("Hello, 世界") {
            Println!("[ 6] Decode B 世界           PASS");
        } else {
            Println!("[ 6] Decode B 世界           FAIL");
            failed += 1;
        }
    }

    // 7. Empty encoded-word body decodes to "".
    {
        let d = WordDecoder::new();
        let (got, err) = d.Decode(string("=?UTF-8?q??="));
        if err.IsNil() && got == string("") {
            Println!("[ 7] Decode empty body      PASS");
        } else {
            Println!("[ 7] Decode empty body      FAIL");
            failed += 1;
        }
    }

    // 8. DecodeHeader mixed plain + encoded-word.
    {
        let d = WordDecoder::new();
        let (got, err) = d.DecodeHeader(string("Subject: =?UTF-8?Q?Caf=C3=A9?="));
        if err.IsNil() && got == string("Subject: Café") {
            Println!("[ 8] DecodeHeader mixed     PASS");
        } else {
            Println!("[ 8] DecodeHeader mixed     FAIL got {}", got);
            failed += 1;
        }
    }

    // 9. DecodeHeader: whitespace between two encoded-words is deleted.
    {
        let d = WordDecoder::new();
        let (got, err) =
            d.DecodeHeader(string("=?UTF-8?Q?Caf=C3=A9?= =?UTF-8?Q?_World?="));
        if err.IsNil() && got == string("Café World") {
            Println!("[ 9] DecodeHeader 2 words   PASS");
        } else {
            Println!("[ 9] DecodeHeader 2 words   FAIL got {}", got);
            failed += 1;
        }
    }

    // 10. iso-8859-1 charset decode.
    {
        let d = WordDecoder::new();
        let (got, err) = d.Decode(string("=?ISO-8859-1?Q?Caf=E9?="));
        if err.IsNil() && got == string("Café") {
            Println!("[10] Decode iso-8859-1      PASS");
        } else {
            Println!("[10] Decode iso-8859-1      FAIL");
            failed += 1;
        }
    }

    // 11. Long Q-encoded string splits into multiple words.
    {
        let long = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let mut input = alloc::string::String::new();
        input.push_str(long);
        input.push('æ');
        input.push_str(long);
        let input_s: goish::gostring::string =
            goish::gostring::string::from_bytes(input.as_bytes());
        let got = QEncoding.Encode(string("UTF-8"), input_s);
        let want = string("=?UTF-8?q?abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789?= =?UTF-8?q?=C3=A6abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234?= =?UTF-8?q?56789?=");
        if got == want {
            Println!("[11] Long QEncode split     PASS");
        } else {
            Println!("[11] Long QEncode split     FAIL got {}", got);
            failed += 1;
        }
    }

    // 12. Round-trip B-encoded long UTF-8 split into multiple words.
    {
        let long = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let mut input = alloc::string::String::new();
        input.push_str("日本語");
        input.push_str(long);
        input.push_str("αβγ");
        let input_s: goish::gostring::string =
            goish::gostring::string::from_bytes(input.as_bytes());
        let enc = BEncoding.Encode(string("UTF-8"), input_s.clone());
        let d = WordDecoder::new();
        let (decoded, err) = d.DecodeHeader(enc);
        if err.IsNil() && decoded == input_s {
            Println!("[12] BEncode round-trip     PASS");
        } else {
            Println!("[12] BEncode round-trip     FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 13/13");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 13");
        syscall::Exit(1);
    }
}
