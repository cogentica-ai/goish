// Smoke test: Tier 2 reflect — Indirect, FieldByIndex, FieldByNameFunc,
// OverflowInt/Uint/Float, Append/AppendSlice, VisibleFields, Value.Elem.

#![no_std]
#![no_main]

use goish::{int, reflect, slice, syscall};

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
pub struct Inner {
    A: int,
    B: int,
}

#[goish::reflect]
pub struct Outer {
    Sub: Inner,
    Tag: int,
}

#[goish::main]
fn main() {
    // ─── FieldByIndex (nested) — Outer → Sub → A ─────────────────────
    let o = Outer {
        Sub: Inner { A: 11, B: 22 },
        Tag: 99,
    };
    let v = reflect::ValueOf(&o);
    let path: &[int] = &[0, 0]; // Outer.Sub.A
    let inner_a = v.FieldByIndex(path);
    check(
        inner_a.Int() == 11,
        b"tier2: Value.FieldByIndex Outer.Sub.A\n",
    );

    let path: &[int] = &[0, 1]; // Outer.Sub.B
    let inner_b = v.FieldByIndex(path);
    check(
        inner_b.Int() == 22,
        b"tier2: Value.FieldByIndex Outer.Sub.B\n",
    );

    let path: &[int] = &[1]; // Outer.Tag
    let tag = v.FieldByIndex(path);
    check(tag.Int() == 99, b"tier2: Value.FieldByIndex Outer.Tag\n");

    // ─── Type.FieldByIndex — descriptor walk ─────────────────────────
    let t = reflect::TypeOf(&o);
    let f = t.FieldByIndex(&[0, 0]);
    check(f.Name == "A", b"tier2: Type.FieldByIndex name\n");

    // FieldByIndexErr — same as FieldByIndex in goish, no nil-deref
    let (f2, err) = t.FieldByIndexErr(&[1]);
    check(err == goish::nil, b"tier2: FieldByIndexErr nil err\n");
    check(f2.Name == "Tag", b"tier2: FieldByIndexErr name\n");

    // ─── Type.FieldByNameFunc — predicate match ──────────────────────
    let (f, ok) = t.FieldByNameFunc(|n| n == "Tag");
    check(ok && f.Name == "Tag", b"tier2: FieldByNameFunc hit\n");

    let (_, ok) = t.FieldByNameFunc(|n| n.starts_with("Z"));
    check(!ok, b"tier2: FieldByNameFunc miss\n");

    // ─── Type.OverflowInt — bounds checks ────────────────────────────
    let i8_t = reflect::TypeOf(&0i8);
    check(i8_t.OverflowInt(200), b"tier2: i8 OverflowInt(200)\n");
    check(!i8_t.OverflowInt(100), b"tier2: i8 !OverflowInt(100)\n");
    check(i8_t.OverflowInt(-200), b"tier2: i8 OverflowInt(-200)\n");

    let int_t = reflect::TypeOf(&0i64);
    check(
        !int_t.OverflowInt(i64::MAX),
        b"tier2: i64 !OverflowInt(MAX)\n",
    );

    // OverflowUint
    let u16_t = reflect::TypeOf(&0u16);
    check(
        u16_t.OverflowUint(70_000),
        b"tier2: u16 OverflowUint(70000)\n",
    );
    check(
        !u16_t.OverflowUint(65_535),
        b"tier2: u16 !OverflowUint(MAX)\n",
    );

    // OverflowFloat
    let f32_t = reflect::TypeOf(&0f32);
    check(
        f32_t.OverflowFloat(1e40),
        b"tier2: f32 OverflowFloat(1e40)\n",
    );
    check(
        !f32_t.OverflowFloat(1e10),
        b"tier2: f32 !OverflowFloat(1e10)\n",
    );

    // ─── reflect::Append / AppendSlice ───────────────────────────────
    let xs: slice<int> = goish::slice!([]int{1, 2, 3});
    let v = reflect::ValueOf(&xs);
    let extended = reflect::Append(v, &[reflect::Value::Int(4), reflect::Value::Int(5)]);
    check(extended.Len() == 5, b"tier2: Append len\n");
    check(extended.Index(3).Int() == 4, b"tier2: Append[3]\n");
    check(extended.Index(4).Int() == 5, b"tier2: Append[4]\n");

    let ys: slice<int> = goish::slice!([]int{10, 20});
    let combined = reflect::AppendSlice(reflect::ValueOf(&xs), reflect::ValueOf(&ys));
    check(combined.Len() == 5, b"tier2: AppendSlice len\n");
    check(combined.Index(4).Int() == 20, b"tier2: AppendSlice[4]\n");

    // ─── reflect::VisibleFields ─────────────────────────────────────
    let fs = reflect::VisibleFields(t);
    check(fs.len() == 2, b"tier2: VisibleFields count\n");
    check(fs[0].Name == "Sub", b"tier2: VisibleFields[0]\n");
    check(fs[1].Name == "Tag", b"tier2: VisibleFields[1]\n");

    // ─── reflect::Indirect — non-pointer is a no-op ──────────────────
    let n: int = 42;
    let v = reflect::ValueOf(&n);
    let same = reflect::Indirect(v);
    check(same.Int() == 42, b"tier2: Indirect non-ptr\n");

    // ─── Value.OverflowInt — same semantics as Type version ──────────
    let v8 = reflect::ValueOf(&0i8);
    check(v8.OverflowInt(200), b"tier2: Value.OverflowInt\n");

    const OK: &[u8] = b"reflect_tier2: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
