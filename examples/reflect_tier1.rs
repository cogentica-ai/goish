// Smoke test: Tier 1 reflect surface — Type.Elem/Key/Comparable/
// AssignableTo/String, Value.IsNil/Cap/Bytes/Slice/Slice3.

#![no_std]
#![no_main]

use goish::{int, make, reflect, slice, string, syscall};

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
pub struct Point {
    X: int,
    Y: int,
}

#[goish::main]
fn main() {
    // ─── Type.Elem on slice ──────────────────────────────────────────
    let xs: slice<int> = goish::slice!([]int{1, 2, 3});
    let t = reflect::TypeOf(&xs);
    check(t.Kind() == reflect::Kind::Slice, b"tier1: slice Kind\n");
    check(
        t.Elem().Kind() == reflect::Kind::Int,
        b"tier1: slice Elem Kind\n",
    );

    // ─── Type.Elem + Type.Key on map ─────────────────────────────────
    let mut m = make!(map[string]int);
    m.Set(string("a"), 1);
    let mt = reflect::TypeOf(&m);
    check(mt.Kind() == reflect::Kind::Map, b"tier1: map Kind\n");
    check(
        mt.Key().Kind() == reflect::Kind::String,
        b"tier1: map Key Kind\n",
    );
    check(
        mt.Elem().Kind() == reflect::Kind::Int,
        b"tier1: map Elem Kind\n",
    );

    // ─── Type.String — readable representation ───────────────────────
    check(
        reflect::TypeOf(&1i64).String() == "int",
        b"tier1: int.String\n",
    );
    check(
        reflect::TypeOf(&true).String() == "bool",
        b"tier1: bool.String\n",
    );
    check(
        reflect::TypeOf(&xs).String() == "[]int",
        b"tier1: []int.String\n",
    );
    check(
        reflect::TypeOf(&m).String() == "map[string]int",
        b"tier1: map.String\n",
    );

    let p = Point { X: 1, Y: 2 };
    check(
        reflect::TypeOf(&p).String() == "Point",
        b"tier1: Point.String\n",
    );

    // Nested: slice<Point>
    let pts: slice<Point> = goish::slice!([]Point { Point { X: 1, Y: 2 } });
    check(
        reflect::TypeOf(&pts).String() == "[]Point",
        b"tier1: []Point.String\n",
    );

    // ─── Type.Comparable ─────────────────────────────────────────────
    check(
        reflect::TypeOf(&1i64).Comparable(),
        b"tier1: int Comparable\n",
    );
    check(
        reflect::TypeOf(&string("x")).Comparable(),
        b"tier1: string Comparable\n",
    );
    check(
        reflect::TypeOf(&p).Comparable(),
        b"tier1: Point Comparable\n",
    );
    check(
        !reflect::TypeOf(&xs).Comparable(),
        b"tier1: []int !Comparable\n",
    );
    check(
        !reflect::TypeOf(&m).Comparable(),
        b"tier1: map !Comparable\n",
    );

    // ─── Type.AssignableTo — same kind + same elem chain ─────────────
    let ys: slice<int> = goish::slice!([]int{4, 5});
    let tx = reflect::TypeOf(&xs);
    let ty = reflect::TypeOf(&ys);
    check(tx.AssignableTo(&ty), b"tier1: []int AssignableTo []int\n");

    // []int is NOT assignable to []string
    let ss: slice<string> = goish::slice!([]string{"a"});
    let ts = reflect::TypeOf(&ss);
    check(
        !tx.AssignableTo(&ts),
        b"tier1: []int !AssignableTo []string\n",
    );

    // ─── Value.Cap (= Len in deep-clone goish) ───────────────────────
    let v = reflect::ValueOf(&xs);
    check(v.Cap() == v.Len(), b"tier1: Cap == Len\n");
    check(v.Cap() == 3, b"tier1: Cap value\n");

    // ─── Value.Slice — sub-slicing through reflect ───────────────────
    let sub = v.Slice(0, 2);
    check(sub.Len() == 2, b"tier1: Slice len\n");
    check(sub.Index(0).Int() == 1, b"tier1: Slice[0]\n");
    check(sub.Index(1).Int() == 2, b"tier1: Slice[1]\n");

    // Slice3 — max ignored in goish
    let sub3 = v.Slice3(1, 3, 3);
    check(sub3.Len() == 2, b"tier1: Slice3 len\n");
    check(sub3.Index(0).Int() == 2, b"tier1: Slice3[0]\n");

    // ─── Value.Bytes — Slice<byte> conversion ────────────────────────
    let bs: slice<goish::byte> = b"hello".as_slice().into();
    let bv = reflect::ValueOf(&bs);
    let got = bv.Bytes();
    check(got.Len() == 5, b"tier1: Bytes len\n");
    check(got[0] == b'h' && got[4] == b'o', b"tier1: Bytes content\n");

    // ─── Value.IsNil — slice/map are non-nil-empty in goish v1 ───────
    let empty: slice<int> = goish::slice!([]int{});
    check(
        !reflect::ValueOf(&empty).IsNil(),
        b"tier1: empty slice IsNil false\n",
    );

    let empty_map = make!(map[string]int);
    check(
        !reflect::ValueOf(&empty_map).IsNil(),
        b"tier1: empty map IsNil false\n",
    );

    // ─── String.Slice produces a substring ──────────────────────────
    let s = string("hello");
    let sv = reflect::ValueOf(&s);
    let sub = sv.Slice(1, 4);
    check(sub.String() == "ell", b"tier1: string Slice\n");

    const OK: &[u8] = b"reflect_tier1: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
