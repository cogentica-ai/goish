// Smoke test: fmt %v via reflect + reflect.SetField mutation.
//
// %v / %+v on a #[goish::reflect] struct produces Go-faithful output
// without writing a Stringer. SetField / SetFieldByName mutate fields
// at runtime through a type-checked, no-unsafe protocol.

#![no_std]
#![no_main]

use goish::fmt;
use goish::{int, reflect, slice, string, syscall};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

#[goish::reflect]
pub struct Person {
    Name: string,
    Age: int,
}

#[goish::reflect]
pub struct Bag {
    Items: slice<string>,
    Count: int,
}

#[goish::main]
fn main() {
    // ─── #2: %v / %+v on a reflect struct ────────────────────────────
    let p = Person {
        Name: string("alice"),
        Age: 30,
    };
    let v = fmt::Sprintf!("%v", &p);
    check(v == "{alice 30}", b"reflect-v: %v body\n");

    let pv = fmt::Sprintf!("%+v", &p);
    check(pv == "{Name:alice Age:30}", b"reflect-v: %+v body\n");

    // ─── %v on nested slice<string> field ────────────────────────────
    let bag = Bag {
        Items: goish::slice!([]string{"x", "y", "z"}),
        Count: 3,
    };
    let s = fmt::Sprintf!("%v", &bag);
    check(s == "{[x y z] 3}", b"reflect-v: bag %v\n");

    let sp = fmt::Sprintf!("%+v", &bag);
    check(sp == "{Items:[x y z] Count:3}", b"reflect-v: bag %+v\n");

    // ─── #1: SetField by index ───────────────────────────────────────
    let mut p = Person {
        Name: string("orig"),
        Age: 0,
    };
    let err = reflect::SetField(&mut p, 1, reflect::Value::Int(99));
    check(err == goish::nil, b"reflect-set: SetField err\n");
    check(p.Age == 99, b"reflect-set: Age after SetField\n");

    // ─── SetFieldByName ──────────────────────────────────────────────
    let err = reflect::SetFieldByName(&mut p, "Name", reflect::Value::String(string("alice")));
    check(err == goish::nil, b"reflect-set: SetFieldByName err\n");
    check(
        p.Name == "alice",
        b"reflect-set: Name after SetFieldByName\n",
    );

    // ─── Type mismatch returns error, leaves field intact ────────────
    let err = reflect::SetFieldByName(&mut p, "Age", reflect::Value::String(string("oops")));
    check(err != goish::nil, b"reflect-set: type mismatch must err\n");
    check(p.Age == 99, b"reflect-set: Age unchanged on err\n");

    // ─── Unknown name returns error ──────────────────────────────────
    let err = reflect::SetFieldByName(&mut p, "Nonexistent", reflect::Value::Int(0));
    check(err != goish::nil, b"reflect-set: unknown field must err\n");

    // ─── SetField composite: slice<string> via Value::Slice ──────────
    let mut bag = Bag {
        Items: goish::slice!([]string{}),
        Count: 0,
    };
    let new_items = reflect::ValueOf(&goish::slice!([]string{"a", "b"}));
    let err = reflect::SetFieldByName(&mut bag, "Items", new_items);
    check(err == goish::nil, b"reflect-set: slice err\n");
    check(bag.Items.Len() == 2, b"reflect-set: slice len\n");
    check(bag.Items[0] == "a", b"reflect-set: slice[0]\n");

    // ─── %v after mutation reflects new state ────────────────────────
    let after = fmt::Sprintf!("%+v", &p);
    check(
        after == "{Name:alice Age:99}",
        b"reflect-v: after-mutation %+v\n",
    );

    const OK: &[u8] = b"reflect_v_set: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
