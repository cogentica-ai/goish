// Smoke test: goish::reflect first slice — Type, Kind, StructField,
// StructTag.Get / StructTag.Lookup. The struct tags are byte-identical
// to what you'd write inside backticks in Go.

#![no_std]
#![no_main]

use goish::{int, make, reflect, string, syscall};

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
    #[tag(r#"json:"name" xml:"name,attr""#)]
    Name: string,

    #[tag(r#"json:"age,omitempty""#)]
    Age: int,

    secret: int,
}

// A second struct, no tags at all — exercises the empty-tag path.
#[goish::reflect]
pub struct Point {
    X: int,
    Y: int,
}

#[goish::main]
fn main() {
    // Construct so the example actually allocates the struct (proves
    // #[goish::reflect] re-emitted a usable struct definition).
    let _p = Person { Name: string("alice"), Age: 30, secret: 7 };
    let _q = Point { X: 1, Y: 2 };

    // ─── TypeOf / Kind / Name / NumField ─────────────────────────────
    let t = reflect::TypeOf(&_p);
    check(t.Name() == "Person", b"reflect: Person Name\n");
    check(t.Kind() == reflect::Kind::Struct, b"reflect: Person Kind\n");
    check(t.NumField() == 3, b"reflect: Person NumField\n");

    // ─── Field(0) — Name + Tag.Get ───────────────────────────────────
    let f0 = t.Field(0);
    check(f0.Name == "Name", b"reflect: f0 Name\n");
    check((f0.Type)().Kind() == reflect::Kind::String, b"reflect: f0 Type.Kind\n");
    check((f0.Type)().Name() == "string", b"reflect: f0 Type.Name\n");
    check(f0.Tag.Get("json") == "name", b"reflect: f0 json tag\n");
    check(f0.Tag.Get("xml") == "name,attr", b"reflect: f0 xml tag\n");
    check(f0.Tag.Get("missing") == "", b"reflect: f0 missing tag\n");

    // ─── Field(1) — int with json:"age,omitempty" ────────────────────
    let f1 = t.Field(1);
    check(f1.Name == "Age", b"reflect: f1 Name\n");
    check((f1.Type)().Kind() == reflect::Kind::Int, b"reflect: f1 Type.Kind\n");
    let (v, ok) = f1.Tag.Lookup("json");
    check(v == "age,omitempty" && ok, b"reflect: f1 json Lookup\n");

    // ─── Field(2) — bare field, no tag (Lookup returns ok=false) ─────
    let f2 = t.Field(2);
    check(f2.Name == "secret", b"reflect: f2 Name\n");
    let (_, ok) = f2.Tag.Lookup("anything");
    check(!ok, b"reflect: f2 Lookup ok\n");

    // ─── FieldByName ─────────────────────────────────────────────────
    let (f, ok) = t.FieldByName("Age");
    check(ok && f.Name == "Age", b"reflect: FieldByName hit\n");
    let (_, ok) = t.FieldByName("Nonexistent");
    check(!ok, b"reflect: FieldByName miss\n");

    // ─── Point — second struct, all-bare fields ──────────────────────
    let pt = reflect::TypeOf(&_q);
    check(pt.Name() == "Point", b"reflect: Point Name\n");
    check(pt.NumField() == 2, b"reflect: Point NumField\n");
    let p0 = pt.Field(0);
    check(p0.Name == "X" && p0.Tag.Get("any") == "", b"reflect: Point f0\n");

    // ─── Built-in primitives via TypeOf ──────────────────────────────
    let s = string("hi");
    let n: int = 42;
    let b: bool = true;
    check(reflect::TypeOf(&s).Kind() == reflect::Kind::String, b"reflect: string Kind\n");
    check(reflect::TypeOf(&n).Kind() == reflect::Kind::Int, b"reflect: int Kind\n");
    check(reflect::TypeOf(&b).Kind() == reflect::Kind::Bool, b"reflect: bool Kind\n");

    // ─── Kind.String() — Go-faithful labels ──────────────────────────
    check(reflect::Kind::Struct.String() == "struct", b"reflect: Kind::Struct.String\n");
    check(reflect::Kind::Int.String() == "int", b"reflect: Kind::Int.String\n");
    check(reflect::Kind::String.String() == "string", b"reflect: Kind::String.String\n");

    // ─── Escape sequences in tag values (Go's strconv.Unquote rules) ─
    // \"  inside the quoted value should round-trip.
    let tag = reflect::StructTag::__new(r#"foo:"a\"b" bar:"\nhello""#);
    check(tag.Get("foo") == "a\"b", b"reflect: tag escape \"\n");
    check(tag.Get("bar") == "\nhello", b"reflect: tag escape n\n");

    // ─── DeepEqual ───────────────────────────────────────────────────

    // Primitives.
    check(reflect::DeepEqual(&1i64, &1i64), b"DeepEqual: int eq\n");
    check(!reflect::DeepEqual(&1i64, &2i64), b"DeepEqual: int neq\n");
    check(reflect::DeepEqual(&string("hi"), &string("hi")), b"DeepEqual: str eq\n");
    check(!reflect::DeepEqual(&string("hi"), &string("ho")), b"DeepEqual: str neq\n");
    check(reflect::DeepEqual(&true, &true), b"DeepEqual: bool eq\n");

    // NaN ≠ NaN, matching Go.
    let nan: goish::float64 = goish::float64::NAN;
    check(!reflect::DeepEqual(&nan, &nan), b"DeepEqual: NaN != NaN\n");

    // Different Kinds — false.
    check(!reflect::DeepEqual(&1i64, &string("hi")), b"DeepEqual: kind mismatch\n");

    // Struct: same name + equal fields → true.
    let p1 = Person { Name: string("alice"), Age: 30, secret: 7 };
    let p2 = Person { Name: string("alice"), Age: 30, secret: 7 };
    let p3 = Person { Name: string("alice"), Age: 31, secret: 7 };
    check(reflect::DeepEqual(&p1, &p2), b"DeepEqual: struct eq\n");
    check(!reflect::DeepEqual(&p1, &p3), b"DeepEqual: struct neq (field)\n");

    // Distinct struct types — false even with similar shapes.
    let pt = Point { X: 1, Y: 2 };
    check(!reflect::DeepEqual(&p1, &pt), b"DeepEqual: distinct struct types\n");

    // Slice: element-wise.
    let s1 = goish::slice!([]int{1, 2, 3});
    let s2 = goish::slice!([]int{1, 2, 3});
    let s3 = goish::slice!([]int{1, 2, 4});
    check(reflect::DeepEqual(&s1, &s2), b"DeepEqual: slice eq\n");
    check(!reflect::DeepEqual(&s1, &s3), b"DeepEqual: slice neq\n");

    // Map: key-by-key match (order-independent at the API).
    let mut m1 = make!(map[string]int);
    m1.Set(string("a"), 1);
    m1.Set(string("b"), 2);
    let mut m2 = make!(map[string]int);
    m2.Set(string("b"), 2);
    m2.Set(string("a"), 1);
    let mut m3 = make!(map[string]int);
    m3.Set(string("a"), 1);
    m3.Set(string("b"), 9);
    check(reflect::DeepEqual(&m1, &m2), b"DeepEqual: map eq (insertion order)\n");
    check(!reflect::DeepEqual(&m1, &m3), b"DeepEqual: map neq (value)\n");

    const OK: &[u8] = b"reflect: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
