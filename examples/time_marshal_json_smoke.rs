// time_marshal_json_smoke — exercise Time.MarshalJSON / UnmarshalJSON.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::time;
use goish::{string, syscall, Println};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. MarshalJSON wraps RFC3339 in double quotes.
    {
        let t = time::Unix(1_700_000_000, 0);
        let (data, err) = t.MarshalJSON();
        let s = goish::string::from_bytes(&data);
        if err.IsNil()
            && goish::strings::HasPrefix(s.clone(), string("\""))
            && goish::strings::HasSuffix(s.clone(), string("\""))
        {
            Println!("[ 1] MarshalJSON quotes        PASS");
        } else {
            Println!("[ 1] MarshalJSON quotes        FAIL got={}", s);
            failed += 1;
        }
    }

    // 2. Round-trip: marshal then unmarshal recovers the same Unix time.
    {
        let t_anchor = time::Unix(1_700_000_000, 0);
        let (data, err) = t_anchor.MarshalJSON();
        if !err.IsNil() {
            Println!("[ 2] JSON round-trip           FAIL marshal");
            failed += 1;
        } else {
            let mut got = time::Unix(0, 0);
            let uerr = got.UnmarshalJSON(data);
            if uerr.IsNil() && got.Unix() == 1_700_000_000 {
                Println!("[ 2] JSON round-trip           PASS");
            } else {
                Println!("[ 2] JSON round-trip           FAIL unix={}", got.Unix());
                failed += 1;
            }
        }
    }

    // 3. UnmarshalJSON rejects unquoted input.
    {
        let mut t = time::Unix(0, 0);
        let bad = goish::convert::bytes("2024-01-01T00:00:00Z");
        let err = t.UnmarshalJSON(bad);
        if !err.IsNil() {
            Println!("[ 3] reject unquoted           PASS");
        } else {
            Println!("[ 3] reject unquoted           FAIL");
            failed += 1;
        }
    }

    // 4. UnmarshalJSON accepts the literal "null" without modifying t.
    {
        let original = time::Unix(42, 0);
        let mut t = original;
        let null_bytes = goish::convert::bytes("null");
        let err = t.UnmarshalJSON(null_bytes);
        if err.IsNil() && t.Unix() == 42 {
            Println!("[ 4] null is no-op             PASS");
        } else {
            Println!("[ 4] null is no-op             FAIL");
            failed += 1;
        }
    }

    // 5. Empty payload is rejected.
    {
        let mut t = time::Unix(0, 0);
        let empty = goish::convert::bytes("");
        let err = t.UnmarshalJSON(empty);
        if !err.IsNil() {
            Println!("[ 5] empty rejected            PASS");
        } else {
            Println!("[ 5] empty rejected            FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 5/5");
        syscall::Exit(0);
    } else {
        Println!("FAIL {} of 5", failed);
        syscall::Exit(1);
    }
}
