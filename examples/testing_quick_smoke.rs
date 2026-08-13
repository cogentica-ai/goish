// testing_quick_smoke — the portable half of testing/quick.
//
// quick's headline, Check, needs to reflect on a function value and
// INVOKE it. goish's reflect::Value is a data-only tree with a no-op
// Call, so Check and its supporting cast are not ported. What is here
// is everything that does not need reflection.
//
// The random generators carry a detail worth pinning. Go takes the SIGN
// from a separate coin flip rather than from the magnitude, because
// rand.Float64() is [0,1) and scaling it alone would never produce a
// negative — a generator that never emits negative values silently
// halves the input space a property test explores. Checks 1 and 2.
//
// getMaxCount's precedence is the other one: MaxCount wins outright,
// and only if it is zero does MaxCountScale apply. A caller setting
// both gets the absolute count. Check 4.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::math::rand;
use goish::testing::quick::{
    randFloat64, randInt64, toString, CheckError, Config, SetupError,
};
use goish::{fmt, slice, syscall, Any};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. randFloat64 produces BOTH signs across a run. A generator that
    //    only scaled Float64() would never emit a negative, and a
    //    property test using it would never explore half its domain.
    {
        let mut r = rand::New(rand::NewSource(12345));
        let mut sawNeg = false;
        let mut sawPos = false;
        for _ in 0..200 {
            let f = randFloat64(&mut r);
            if f < 0.0 {
                sawNeg = true;
            }
            if f > 0.0 {
                sawPos = true;
            }
        }
        if sawNeg && sawPos {
            fmt::Println!("[ 1] randFloat64 spans signs   PASS");
        } else {
            fmt::Println!("[ 1] randFloat64 spans signs   FAIL");
            failed += 1;
        }
    }

    // 2. randInt64 reaches negatives too — it reinterprets a uint64
    //    rather than scaling one, so the whole signed range including
    //    the extremes is reachable.
    {
        let mut r = rand::New(rand::NewSource(999));
        let mut sawNeg = false;
        let mut sawPos = false;
        for _ in 0..200 {
            let v = randInt64(&mut r);
            if v < 0 {
                sawNeg = true;
            }
            if v > 0 {
                sawPos = true;
            }
        }
        if sawNeg && sawPos {
            fmt::Println!("[ 2] randInt64 spans signs     PASS");
        } else {
            fmt::Println!("[ 2] randInt64 spans signs     FAIL");
            failed += 1;
        }
    }

    // 3. The error types report the ITERATION number, because a
    //    property failing on the 97th random input is a different bug
    //    from one failing on the 1st.
    {
        let e = CheckError {
            Count: 97,
            In: slice::__from_vec(alloc::vec![Any::new(42i64), Any::new(s("x"))]),
        };
        let m = e.Error();
        let ms: &str = m.as_ref();
        if ms.starts_with("#97: failed on input ") {
            fmt::Println!("[ 3] CheckError names the run  PASS");
        } else {
            fmt::Println!("[ 3] CheckError names the run  FAIL [", m, "]");
            failed += 1;
        }
    }

    // 4. getMaxCount's precedence: MaxCount wins outright; scale
    //    applies only when it is zero; neither means the default 100.
    {
        let a = Config {
            MaxCount: 7,
            MaxCountScale: 5.0,
            Rand: None,
        };
        let b = Config {
            MaxCount: 0,
            MaxCountScale: 2.0,
            Rand: None,
        };
        let c = Config::default();
        if a.getMaxCount() == 7 && b.getMaxCount() == 200 && c.getMaxCount() == 100 {
            fmt::Println!("[ 4] getMaxCount precedence    PASS");
        } else {
            fmt::Println!(
                "[ 4] getMaxCount precedence    FAIL ", a.getMaxCount(),
                " ", b.getMaxCount(), " ", c.getMaxCount()
            );
            failed += 1;
        }
    }

    // 5. toString joins with ", " so a multi-argument failure reads as
    //    one input tuple rather than running together.
    {
        let got = toString(slice::__from_vec(alloc::vec![
            Any::new(1i64),
            Any::new(2i64),
            Any::new(3i64),
        ]));
        if got == s("1, 2, 3") {
            fmt::Println!("[ 5] toString joins            PASS");
        } else {
            fmt::Println!("[ 5] toString joins            FAIL [", got, "]");
            failed += 1;
        }
    }

    // 6. SetupError is its own message — it marks a misuse of quick
    //    itself, not a property failure, so it must not be dressed up
    //    with an iteration number.
    {
        let e = SetupError(s("wrong number of arguments"));
        if e.Error() == s("wrong number of arguments") {
            fmt::Println!("[ 6] SetupError is verbatim    PASS");
        } else {
            fmt::Println!("[ 6] SetupError is verbatim    FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 6/6");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 6");
        syscall::Exit(1);
    }
}
