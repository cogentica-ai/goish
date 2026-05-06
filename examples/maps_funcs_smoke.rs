// maps_funcs_smoke — exercise maps.EqualFunc + maps.DeleteFunc.
// (maps.go:31 + 69)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gomap::map;
use goish::maps;
use goish::string;
use goish::types::int;
use goish::{syscall, Println};

fn make_str_int_map(pairs: &'static [(&'static str, int)]) -> map<string, int> {
    let mut m: map<string, int> = map::new();
    for (k, v) in pairs {
        m.Set(string(*k), *v);
    }
    m
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. EqualFunc — exact equality predicate matches Equal.
    {
        let m1 = make_str_int_map(&[("a", 1), ("b", 2)]);
        let m2 = make_str_int_map(&[("a", 1), ("b", 2)]);
        if maps::EqualFunc(&m1, &m2, |a, b| a == b) {
            Println!("[ 1] EqualFunc identical       PASS");
        } else {
            Println!("[ 1] EqualFunc identical       FAIL");
            failed += 1;
        }
    }

    // 2. EqualFunc — different lengths short-circuits to false.
    {
        let m1 = make_str_int_map(&[("a", 1)]);
        let m2 = make_str_int_map(&[("a", 1), ("b", 2)]);
        if !maps::EqualFunc(&m1, &m2, |a, b| a == b) {
            Println!("[ 2] EqualFunc len mismatch    PASS");
        } else {
            Println!("[ 2] EqualFunc len mismatch    FAIL");
            failed += 1;
        }
    }

    // 3. EqualFunc — values within ±1 considered equal.
    {
        let m1 = make_str_int_map(&[("a", 10), ("b", 20)]);
        let m2 = make_str_int_map(&[("a", 11), ("b", 19)]);
        let close = |a: &int, b: &int| (*a - *b).abs() <= 1;
        if maps::EqualFunc(&m1, &m2, close) {
            Println!("[ 3] EqualFunc close-enough    PASS");
        } else {
            Println!("[ 3] EqualFunc close-enough    FAIL");
            failed += 1;
        }
    }

    // 4. EqualFunc — missing key in m2 → false.
    {
        let m1 = make_str_int_map(&[("a", 1), ("b", 2)]);
        let m2 = make_str_int_map(&[("a", 1), ("c", 2)]);
        if !maps::EqualFunc(&m1, &m2, |a, b| a == b) {
            Println!("[ 4] EqualFunc key mismatch    PASS");
        } else {
            Println!("[ 4] EqualFunc key mismatch    FAIL");
            failed += 1;
        }
    }

    // 5. DeleteFunc — drop entries with even values.
    {
        let mut m = make_str_int_map(&[("a", 1), ("b", 2), ("c", 3), ("d", 4)]);
        maps::DeleteFunc(&mut m, |_k, v| v % 2 == 0);
        if m.Len() == 2 {
            Println!("[ 5] DeleteFunc even values    PASS");
        } else {
            Println!("[ 5] DeleteFunc even values    FAIL");
            failed += 1;
        }
    }

    // 6. DeleteFunc — drop entries by key prefix.
    {
        let mut m = make_str_int_map(&[("foo_1", 1), ("bar_1", 2), ("foo_2", 3), ("baz", 4)]);
        maps::DeleteFunc(&mut m, |k, _v| {
            goish::strings::HasPrefix(k.clone(), string("foo_"))
        });
        // bar_1 + baz remain.
        if m.Len() == 2 {
            Println!("[ 6] DeleteFunc by key prefix  PASS");
        } else {
            Println!("[ 6] DeleteFunc by key prefix  FAIL");
            failed += 1;
        }
    }

    // 7. DeleteFunc — predicate that never matches keeps map intact.
    {
        let mut m = make_str_int_map(&[("a", 1), ("b", 2)]);
        maps::DeleteFunc(&mut m, |_k, _v| false);
        if m.Len() == 2 {
            Println!("[ 7] DeleteFunc no-op          PASS");
        } else {
            Println!("[ 7] DeleteFunc no-op          FAIL");
            failed += 1;
        }
    }

    // 8. DeleteFunc — predicate that always matches empties map.
    {
        let mut m = make_str_int_map(&[("a", 1), ("b", 2)]);
        maps::DeleteFunc(&mut m, |_k, _v| true);
        if m.Len() == 0 {
            Println!("[ 8] DeleteFunc clear-all      PASS");
        } else {
            Println!("[ 8] DeleteFunc clear-all      FAIL");
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
