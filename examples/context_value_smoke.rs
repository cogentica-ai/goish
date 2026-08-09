// context_value_smoke — exercise context.WithValue.
// (context/context.go:744-784)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::context;
use goish::time::Milliseconds;
use goish::{syscall};

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. WithValue lets Value find the key.
    {
        let ctx = context::WithValue(context::Background(), "userID", 42i64);
        let v = ctx.Value("userID");
        if let Some(any) = v {
            if let Some(n) = any.downcast_ref::<i64>() {
                if *n == 42 {
                    fmt::Println!("[ 1] WithValue + Value         PASS");
                } else {
                    fmt::Println!("[ 1] WithValue + Value         FAIL");
                    failed += 1;
                }
            } else {
                fmt::Println!("[ 1] WithValue + Value         FAIL downcast");
                failed += 1;
            }
        } else {
            fmt::Println!("[ 1] WithValue + Value         FAIL None");
            failed += 1;
        }
    }

    // 2. Missing key returns None.
    {
        let ctx = context::WithValue(context::Background(), "k", 1u32);
        if ctx.Value("missing").is_none() {
            fmt::Println!("[ 2] missing key None          PASS");
        } else {
            fmt::Println!("[ 2] missing key None          FAIL");
            failed += 1;
        }
    }

    // 3. Background.Value returns None.
    {
        let ctx = context::Background();
        if ctx.Value("anything").is_none() {
            fmt::Println!("[ 3] Background None           PASS");
        } else {
            fmt::Println!("[ 3] Background None           FAIL");
            failed += 1;
        }
    }

    // 4. Nested WithValue: child finds child key, parent key both.
    {
        let ctx1 = context::WithValue(context::Background(), "a", 100i64);
        let ctx2 = context::WithValue(ctx1, "b", 200i64);
        let va = ctx2.Value("a");
        let vb = ctx2.Value("b");
        let ok_a = va
            .as_ref()
            .and_then(|x| x.downcast_ref::<i64>())
            .map(|n| *n == 100)
            .unwrap_or(false);
        let ok_b = vb
            .as_ref()
            .and_then(|x| x.downcast_ref::<i64>())
            .map(|n| *n == 200)
            .unwrap_or(false);
        if ok_a && ok_b {
            fmt::Println!("[ 4] Nested WithValue          PASS");
        } else {
            fmt::Println!("[ 4] Nested WithValue          FAIL");
            failed += 1;
        }
    }

    // 5. Child shadows parent key.
    {
        let ctx1 = context::WithValue(context::Background(), "key", 1i64);
        let ctx2 = context::WithValue(ctx1, "key", 2i64);
        let v = ctx2.Value("key");
        let ok = v
            .as_ref()
            .and_then(|x| x.downcast_ref::<i64>())
            .map(|n| *n == 2)
            .unwrap_or(false);
        if ok {
            fmt::Println!("[ 5] Child shadows parent      PASS");
        } else {
            fmt::Println!("[ 5] Child shadows parent      FAIL");
            failed += 1;
        }
    }

    // 6. WithValue forwards Done/Err/Deadline from parent.
    {
        let (ctx, cancel) = context::WithCancel(context::Background());
        let ctx2 = context::WithValue(ctx, "k", 1i64);
        // Should not be cancelled yet.
        let pre_err = ctx2.Err().IsNil();
        cancel();
        // After cancel, Err should be non-nil.
        let post_err = !ctx2.Err().IsNil();
        if pre_err && post_err {
            fmt::Println!("[ 6] WithValue + Cancel        PASS");
        } else {
            fmt::Println!("[ 6] WithValue + Cancel        FAIL");
            failed += 1;
        }
    }

    // 7. WithValue with string-typed value.
    {
        let ctx = context::WithValue(
            context::Background(),
            "user",
            alloc::string::String::from("alice"),
        );
        let v = ctx.Value("user");
        let ok = v
            .as_ref()
            .and_then(|x| x.downcast_ref::<alloc::string::String>())
            .map(|s| s == "alice")
            .unwrap_or(false);
        if ok {
            fmt::Println!("[ 7] String value              PASS");
        } else {
            fmt::Println!("[ 7] String value              FAIL");
            failed += 1;
        }
    }

    // 8. Deadline forwarded through WithValue.
    {
        let (ctx, _cancel) =
            context::WithTimeout(context::Background(), Milliseconds(100));
        let ctx2 = context::WithValue(ctx, "k", 1i64);
        if ctx2.Deadline().is_some() {
            fmt::Println!("[ 8] Deadline forwarded        PASS");
        } else {
            fmt::Println!("[ 8] Deadline forwarded        FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 8/8");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 8");
        syscall::Exit(1);
    }
}
