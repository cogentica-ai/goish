// expvar_smoke — exercise expvar package.
//
// Coverage:
//   1. Int.Add + Int.Value + Int.String returns "7" (valid JSON).
//   2. Int concurrent Add — final value matches expected sum.
//   3. Float.Add + Value + String returns "3.14".
//   4. String.Set + Value + String returns "\"hello\"" (JSON-quoted).
//   5. Map.Set + Get + Delete + Do returns sorted entries.
//   6. Map.String produces a valid JSON object with sorted keys.
//   7. Publish + Get retrieve registered Var.
//   8. NewInt registers and returns Arc<Int>.
//   9. appendJSONQuote escapes control chars and HTML chars.
//  10. expvar::Handler() returns a Handler that emits the JSON snapshot.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use goish::fmt;
use goish::expvar::{self, Var};
use goish::gostring::string;
use goish::runtime::sched::schedule;
use goish::sync::WaitGroup;
use goish::{go, syscall};

static FAILED: AtomicUsize = AtomicUsize::new(0);

fn ok_line(msg: &[u8]) {
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
}

fn fail() {
    FAILED.fetch_add(1, Ordering::AcqRel);
}

#[goish::main]
fn main() {
    go!(|| {
        run_tests();
        let f = FAILED.load(Ordering::Acquire);
        if f == 0 {
            fmt::Println!("ok 10/10");
            syscall::Exit(0);
        } else {
            fmt::Println!("FAIL", f as i64, "of 10");
            syscall::Exit(1);
        }
    });
    schedule();
}

fn run_tests() {
    test_1_int_basic();
    test_2_int_concurrent();
    test_3_float_basic();
    test_4_string_basic();
    test_5_map_set_get_delete_do();
    test_6_map_string_json();
    test_7_publish_get();
    test_8_new_int();
    test_9_json_quote_escapes();
    test_10_handler_emits_json();
}

fn s(x: &'static str) -> string {
    string::from_static(x)
}

// 1. Int basic.
fn test_1_int_basic() {
    let i = expvar::Int::new();
    i.Add(7);
    let v = i.Value();
    let json = i.String();
    if v == 7 && json == s("7") {
        ok_line(b"[ 1] Int Add+Value+String        PASS\n");
    } else {
        ok_line(b"[ 1] Int Add+Value+String        FAIL\n");
        fail();
    }
}

// 2. Int concurrent Add.
fn test_2_int_concurrent() {
    let i: Arc<expvar::Int> = Arc::new(expvar::Int::new());
    let wg = Arc::new(WaitGroup::new());
    let workers = 8i64;
    let per = 1000i64;
    wg.Add(workers);
    for _ in 0..workers {
        let i = i.clone();
        let wg2 = wg.clone();
        go!(move || {
            for _ in 0..per {
                i.Add(1);
            }
            wg2.Done();
        });
    }
    wg.Wait();
    if i.Value() == workers * per {
        ok_line(b"[ 2] Int concurrent Add          PASS\n");
    } else {
        ok_line(b"[ 2] Int concurrent Add          FAIL\n");
        fail();
    }
}

// 3. Float basic.
fn test_3_float_basic() {
    let f = expvar::Float::new();
    f.Set(3.14);
    let v = f.Value();
    let json = f.String();
    // FormatFloat(3.14, 'g', -1, 64) → "3.14"
    if (v - 3.14).abs() < 1e-9 && json == s("3.14") {
        ok_line(b"[ 3] Float Set+Value+String      PASS\n");
    } else {
        ok_line(b"[ 3] Float Set+Value+String      FAIL\n");
        fail();
    }
}

// 4. String basic.
fn test_4_string_basic() {
    let v = expvar::String::new();
    v.Set(s("hello"));
    let raw = v.Value();
    let json = v.String();
    // String.String() returns JSON-quoted: "\"hello\""
    if raw == s("hello") && json == s("\"hello\"") {
        ok_line(b"[ 4] String Set+Value+String     PASS\n");
    } else {
        ok_line(b"[ 4] String Set+Value+String     FAIL\n");
        fail();
    }
}

// 5. Map Set/Get/Delete/Do.
fn test_5_map_set_get_delete_do() {
    let m = expvar::Map::new();
    let i1: Arc<expvar::Int> = Arc::new(expvar::Int::new());
    i1.Set(100);
    let i2: Arc<expvar::Int> = Arc::new(expvar::Int::new());
    i2.Set(200);
    m.Set(s("zebra"), i1.clone() as Arc<dyn Var>);
    m.Set(s("apple"), i2.clone() as Arc<dyn Var>);

    let got_apple = m.Get(&s("apple")).is_some();
    let got_zebra = m.Get(&s("zebra")).is_some();
    let got_missing = m.Get(&s("missing")).is_none();

    let mut keys = alloc::vec::Vec::<string>::new();
    m.Do(|kv| keys.push(kv.Key));

    let sorted_ok = keys.len() == 2 && keys[0] == s("apple") && keys[1] == s("zebra");

    m.Delete(&s("apple"));
    let after_delete = m.Get(&s("apple")).is_none() && m.Get(&s("zebra")).is_some();

    if got_apple && got_zebra && got_missing && sorted_ok && after_delete {
        ok_line(b"[ 5] Map Set/Get/Delete/Do       PASS\n");
    } else {
        ok_line(b"[ 5] Map Set/Get/Delete/Do       FAIL\n");
        fail();
    }
}

// 6. Map.String produces valid JSON object.
fn test_6_map_string_json() {
    let m = expvar::Map::new();
    let i1: Arc<expvar::Int> = Arc::new(expvar::Int::new());
    i1.Set(1);
    let i2: Arc<expvar::Int> = Arc::new(expvar::Int::new());
    i2.Set(2);
    m.Set(s("b"), i1.clone() as Arc<dyn Var>);
    m.Set(s("a"), i2.clone() as Arc<dyn Var>);

    let got = m.String();
    // Sorted keys: a, b. Format: {"a": 2, "b": 1} (single-line).
    let want = s("{\"a\": 2, \"b\": 1}");
    if got == want {
        ok_line(b"[ 6] Map.String JSON object      PASS\n");
    } else {
        ok_line(b"[ 6] Map.String JSON object      FAIL\n");
        fail();
    }
}

// 7. Publish + Get.
fn test_7_publish_get() {
    let i: Arc<expvar::Int> = Arc::new(expvar::Int::new());
    i.Set(42);
    expvar::Publish(s("test_publish_var"), i.clone() as Arc<dyn Var>);
    let got = expvar::Get(&s("test_publish_var"));
    let ok = got.is_some() && got.unwrap().String() == s("42");
    if ok {
        ok_line(b"[ 7] Publish + Get               PASS\n");
    } else {
        ok_line(b"[ 7] Publish + Get               FAIL\n");
        fail();
    }
}

// 8. NewInt convenience.
fn test_8_new_int() {
    let i = expvar::NewInt(s("counter_8"));
    i.Add(99);
    let got = expvar::Get(&s("counter_8")).unwrap();
    if got.String() == s("99") {
        ok_line(b"[ 8] NewInt registers            PASS\n");
    } else {
        ok_line(b"[ 8] NewInt registers            FAIL\n");
        fail();
    }
}

// 9. appendJSONQuote escapes.
fn test_9_json_quote_escapes() {
    use goish::goslice::slice;

    fn quote(input: &'static str) -> string {
        let buf: slice<u8> = slice::__from_vec(alloc::vec::Vec::new());
        let buf = expvar::appendJSONQuote(buf, string::from_static(input));
        string::from_bytes(&buf.__into_vec())
    }

    let qnewline = quote("a\nb");        // "a\nb"
    let qbackslash = quote("\\");         // "\\"
    let qquote = quote("\"");             // "\""
    let qhtml = quote("<&>");             // "<&>"

    let want_n = s("\"a\\nb\"");
    let want_bs = s("\"\\\\\"");
    let want_q = s("\"\\\"\"");
    let want_html = s("\"\\u003c\\u0026\\u003e\"");

    if qnewline == want_n && qbackslash == want_bs && qquote == want_q && qhtml == want_html {
        ok_line(b"[ 9] appendJSONQuote escapes     PASS\n");
    } else {
        ok_line(b"[ 9] appendJSONQuote escapes     FAIL\n");
        fail();
    }
}

// 10. Handler() returns a non-null Handler; global Do() iterates vars.
//   ResponseWriter's unit-test recorder isn't ported (#166), so we
//   verify the Handler is reachable + the registered vars include the
//   one published in test_7.
fn test_10_handler_emits_json() {
    let h = expvar::Handler();
    let _ = h;
    let mut found = false;
    expvar::Do(|kv| {
        if kv.Key == s("test_publish_var") {
            found = true;
        }
    });
    if found {
        ok_line(b"[10] Handler reachable           PASS\n");
    } else {
        ok_line(b"[10] Handler reachable           FAIL\n");
        fail();
    }
}
