// goarray smoke — exercise every `array!` macro arm + method.
//
// Covers all four composite-literal shapes from Go's spec:
//   var a [N]T            (zero)
//   [N]T{e, e, e}         (full)
//   [N]T{e, e}            (partial — rest zero)
//   [...]T{e, e, e}       (length inferred)
//
// Plus methods: Len, Index/IndexMut, slice, to_slice, range!, == nil.

#![no_std]
#![no_main]

use goish::{array, byte, int, len, nil, range, syscall};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

#[goish::main]
fn main() {
    // ── array!([N]T) — zero-valued ──────────────────────────────────
    let z: array<int, 4> = goish::array!([4]int);
    check(z.Len() == 4, b"goarray: zero Len != 4\n");
    check(z[0] == 0 && z[3] == 0, b"goarray: zero values\n");
    check(len(&z) == 4, b"goarray: len(zero) != 4\n");

    // ── array!([N]T{e1, ..., eN}) — full literal ────────────────────
    let a = goish::array!([3]int{1, 2, 3});
    check(a.Len() == 3, b"goarray: full Len != 3\n");
    check(a[0] == 1 && a[1] == 2 && a[2] == 3, b"goarray: full values\n");

    // ── array!([N]T{e1, e2}) — partial (rest zero) ──────────────────
    let p = goish::array!([6]int{10, 20, 30, 40});
    check(p.Len() == 6, b"goarray: partial Len != 6\n");
    check(p[0] == 10 && p[3] == 40, b"goarray: partial front\n");
    check(p[4] == 0 && p[5] == 0, b"goarray: partial tail not zero\n");

    // ── array!([...]T{...}) — length inferred ───────────────────────
    let inf = goish::array!([...]int{7, 8, 9, 10, 11});
    check(inf.Len() == 5, b"goarray: inferred Len != 5\n");
    check(inf[0] == 7 && inf[4] == 11, b"goarray: inferred values\n");

    // ── IndexMut ────────────────────────────────────────────────────
    let mut m = goish::array!([3]int{0, 0, 0});
    m[0] = 100;
    m[1] = 200;
    m[2] = 300;
    check(m[0] == 100 && m[1] == 200 && m[2] == 300, b"goarray: IndexMut\n");

    // ── range! over array ───────────────────────────────────────────
    let mut sum: int = 0;
    let mut last_idx: int = -1;
    for (i, v) in range!(m) {
        sum += *v;
        last_idx = i;
    }
    check(sum == 600, b"goarray: range sum != 600\n");
    check(last_idx == 2, b"goarray: range last_idx != 2\n");

    // ── to_slice() — copy semantics ────────────────────────────────
    let s = a.to_slice();
    check(len(&s) == 3, b"goarray: to_slice len\n");
    check(s[0] == 1 && s[2] == 3, b"goarray: to_slice values\n");

    // ── slice(low, high) — copy semantics ──────────────────────────
    let mid = inf.slice(1, 4);
    check(len(&mid) == 3, b"goarray: slice(1,4) len\n");
    check(mid[0] == 8 && mid[1] == 9 && mid[2] == 10, b"goarray: slice values\n");

    // ── nil equality (zero-array == nil) ───────────────────────────
    check(z == nil, b"goarray: zero-array != nil\n");
    check(a != nil, b"goarray: non-zero array == nil\n");
    let from_nil: array<int, 4> = nil.into();
    check(from_nil == z, b"goarray: nil.into() != zero\n");

    // ── multi-dim composes naturally: [3][2]int ─────────────────────
    let row0 = goish::array!([2]int{1, 2});
    let row1 = goish::array!([2]int{3, 4});
    let row2 = goish::array!([2]int{5, 6});
    let grid: array<array<int, 2>, 3> = goish::array!([3]array<int, 2>{row0, row1, row2});
    check(grid.Len() == 3, b"goarray: grid outer Len\n");
    check(grid[0].Len() == 2, b"goarray: grid inner Len\n");
    check(grid[0][0] == 1 && grid[2][1] == 6, b"goarray: grid corners\n");

    // ── byte arrays — common port shape ─────────────────────────────
    let buf: array<byte, 12> = goish::array!([12]byte);
    check(buf.Len() == 12, b"goarray: byte buf Len\n");
    check(buf[0] == 0 && buf[11] == 0, b"goarray: byte buf zero\n");

    // ── &array auto-derefs to &[T] for low-level helpers ───────────
    let raw: &[int] = &*a;
    check(raw.len() == 3, b"goarray: deref to &[T] len\n");
    check(raw[1] == 2, b"goarray: deref to &[T] index\n");
}
