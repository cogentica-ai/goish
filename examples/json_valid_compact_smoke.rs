// json_valid_compact_smoke — exercise json.Valid + json.Compact.
// (encoding/json/stream.go:484, indent.go:13)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::convert::bytes as to_bytes;
use goish::encoding::json;
use goish::fmt;
use goish::goslice::slice;
use goish::syscall;
use goish::types::{byte, int};

fn empty_buf() -> slice<byte> {
    slice::<byte>::__from_vec(Vec::new())
}

fn equal_bytes(a: slice<byte>, b: slice<byte>) -> bool {
    let aa: &[byte] = &a;
    let bb: &[byte] = &b;
    aa == bb
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Valid — well-formed object.
    {
        if json::Valid(to_bytes("{\"a\":1,\"b\":[true,null]}")) {
            fmt::Println!("[ 1] Valid object              PASS");
        } else {
            fmt::Println!("[ 1] Valid object              FAIL");
            failed += 1;
        }
    }

    // 2. Valid — bare values.
    {
        if json::Valid(to_bytes("42"))
            && json::Valid(to_bytes("\"hi\""))
            && json::Valid(to_bytes("true"))
            && json::Valid(to_bytes("null"))
            && json::Valid(to_bytes("[1,2,3]"))
        {
            fmt::Println!("[ 2] Valid bare                PASS");
        } else {
            fmt::Println!("[ 2] Valid bare                FAIL");
            failed += 1;
        }
    }

    // 3. Valid — surrounding whitespace OK.
    {
        if json::Valid(to_bytes("  \n\t {\"x\": 1} \r\n")) {
            fmt::Println!("[ 3] Valid whitespace          PASS");
        } else {
            fmt::Println!("[ 3] Valid whitespace          FAIL");
            failed += 1;
        }
    }

    // 4. Valid — invalid trailing junk.
    {
        if !json::Valid(to_bytes("{\"a\":1}garbage")) {
            fmt::Println!("[ 4] Valid trailing junk       PASS");
        } else {
            fmt::Println!("[ 4] Valid trailing junk       FAIL");
            failed += 1;
        }
    }

    // 5. Valid — unterminated string.
    {
        if !json::Valid(to_bytes("{\"a\":\"unterm")) {
            fmt::Println!("[ 5] Valid unterminated str    PASS");
        } else {
            fmt::Println!("[ 5] Valid unterminated str    FAIL");
            failed += 1;
        }
    }

    // 6. Valid — empty input invalid.
    {
        if !json::Valid(to_bytes("")) {
            fmt::Println!("[ 6] Valid empty               PASS");
        } else {
            fmt::Println!("[ 6] Valid empty               FAIL");
            failed += 1;
        }
    }

    // 7. Compact — strips whitespace.
    {
        let (out, err) = json::Compact(empty_buf(), to_bytes("{ \"a\" : 1 ,  \"b\" : 2 }"));
        if err.IsNil() && equal_bytes(out, to_bytes("{\"a\":1,\"b\":2}")) {
            fmt::Println!("[ 7] Compact obj               PASS");
        } else {
            fmt::Println!("[ 7] Compact obj               FAIL");
            failed += 1;
        }
    }

    // 8. Compact — array with whitespace.
    {
        let (out, err) = json::Compact(empty_buf(), to_bytes("[ 1 , 2 ,  3 ]"));
        if err.IsNil() && equal_bytes(out, to_bytes("[1,2,3]")) {
            fmt::Println!("[ 8] Compact arr               PASS");
        } else {
            fmt::Println!("[ 8] Compact arr               FAIL");
            failed += 1;
        }
    }

    // 9. Compact — preserves prefix in dst.
    {
        let prefix = to_bytes("PREFIX:");
        let (out, err) = json::Compact(prefix, to_bytes(" [1, 2] "));
        if err.IsNil() && equal_bytes(out, to_bytes("PREFIX:[1,2]")) {
            fmt::Println!("[ 9] Compact prefix            PASS");
        } else {
            fmt::Println!("[ 9] Compact prefix            FAIL");
            failed += 1;
        }
    }

    // 10. Compact — invalid JSON returns error.
    {
        let (_, err) = json::Compact(empty_buf(), to_bytes("not-json"));
        if !err.IsNil() {
            fmt::Println!("[10] Compact invalid           PASS");
        } else {
            fmt::Println!("[10] Compact invalid           FAIL");
            failed += 1;
        }
    }

    let total: int = 10;
    if failed == 0 {
        fmt::Println!("ok 10/10");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of", total);
        syscall::Exit(1);
    }
}
