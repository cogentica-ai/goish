// Smoke test: iter — Go 1.23 function iterators (iter.Seq / Seq2)
// and the seq-based stdlib surface typescript-go leans on.
//
// Covers:
//   1. User-defined iterator functions (closure spelling), early
//      stop via yield-false (Go `break` semantics), recursive
//      tree-walk iterator (the ast.Node.IterChildren shape).
//   2. slices: Collect, Values, All, Backward, AppendSeq, Sorted /
//      SortedFunc over seqs — plus the `&slice` compat source.
//   3. maps: Keys / Values / All as seqs — the dominant
//      slices.Collect(maps.Keys(m)) pattern.
//   4. strings: SplitSeq / SplitAfterSeq / Lines incl. empty-sep
//      UTF-8 splitting and unterminated-final-line handling.
//   5. Iterator values as data: Arc<dyn iter::Seq> in a struct
//      field, flowing back into a seq sink.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;

use goish::gomap::map;
use goish::{int, iter, maps, slice, slices, string, strings, syscall};
use iter::{Seq, Seq2};

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond {
        die(msg);
    }
}

/// Go:
///   func Countdown(from int) iter.Seq[int] {
///       return func(yield func(int) bool) {
///           for i := from; i > 0; i-- {
///               if !yield(i) { return }
///           }
///       }
///   }
fn Countdown(from: int) -> impl iter::Seq<int> {
    move |yield_: &mut dyn FnMut(int) -> bool| {
        let mut i = from;
        while i > 0 {
            if !yield_(i) {
                return;
            }
            i -= 1;
        }
    }
}

/// Binary tree with a recursive iterator — the shape typescript-go
/// uses for ast.Node.IterChildren (ast.go:195).
struct Tree {
    value: int,
    left: Option<alloc::boxed::Box<Tree>>,
    right: Option<alloc::boxed::Box<Tree>>,
}

impl Tree {
    fn walk_inner(&self, yield_: &mut dyn FnMut(int) -> bool) -> bool {
        if let Some(l) = &self.left {
            if !l.walk_inner(yield_) {
                return false;
            }
        }
        if !yield_(self.value) {
            return false;
        }
        if let Some(r) = &self.right {
            if !r.walk_inner(yield_) {
                return false;
            }
        }
        true
    }
}

/// Iterator stored as a field — `Arc<dyn Seq>` is the storable form
/// (object-safe), and flows back into any `impl Seq` sink via the
/// forwarding impl.
struct Walker {
    visit: Arc<dyn iter::Seq<int> + Send + Sync>,
}

#[goish::main]
fn main() {
    // ─── 1. User iterators + break semantics ───────────────────────
    let collected = slices::Collect(Countdown(5));
    check(collected.as_ref() == [5, 4, 3, 2, 1], b"t1: countdown collect\n");

    // Early stop: Go `for v := range seq { if v == 3 { break } }`
    // lowers to a yield that returns false (RANGE_OVER_FUNC.md §3.4).
    let mut seen: int = 0;
    Countdown(1000).run(&mut |v| {
        seen += 1;
        v != 998 // break after 3 elements
    });
    check(seen == 3, b"t1b: early stop after 3\n");

    let tree = Tree {
        value: 2,
        left: Some(alloc::boxed::Box::new(Tree { value: 1, left: None, right: None })),
        right: Some(alloc::boxed::Box::new(Tree { value: 3, left: None, right: None })),
    };
    let mut inorder_v: alloc::vec::Vec<int> = alloc::vec::Vec::new();
    tree.walk_inner(&mut |v| {
        inorder_v.push(v);
        true
    });
    let inorder = slice::__from_vec(inorder_v);
    check(inorder.as_ref() == [1, 2, 3], b"t1c: tree walk inorder\n");

    // ─── 2. slices seq surface ─────────────────────────────────────
    let s: slice<int> = slice::__from_vec(alloc::vec![10, 20, 30]);
    check(
        slices::Collect(slices::Values(&s)).as_ref() == [10, 20, 30],
        b"t2: Values/Collect round-trip\n",
    );

    let mut idx_sum: int = 0;
    let mut val_sum: int = 0;
    slices::All(&s).run(&mut |i, v| {
        idx_sum += i;
        val_sum += v;
        true
    });
    check(idx_sum == 3 && val_sum == 60, b"t2b: All pairs\n");

    let mut backward: int = 0;
    slices::Backward(&s).run(&mut |i, v| {
        backward = i * 1000 + v; // last assignment wins = first element
        false                    // stop immediately: yields (2, 30) only
    });
    check(backward == 2030, b"t2c: Backward starts at the end\n");

    let base: slice<int> = slice::__from_vec(alloc::vec![1, 2]);
    let extended = slices::AppendSeq(base, Countdown(2));
    check(extended.as_ref() == [1, 2, 2, 1], b"t2d: AppendSeq\n");

    let sorted = slices::Sorted(Countdown(4));
    check(sorted.as_ref() == [1, 2, 3, 4], b"t2e: Sorted over seq\n");

    let desc = slices::SortedFunc(slices::Values(&s), |a, b| b - a);
    check(desc.as_ref() == [30, 20, 10], b"t2f: SortedFunc over seq\n");

    // Compat: a &slice is itself a seq source.
    let direct = slices::Sorted(&desc);
    check(direct.as_ref() == [10, 20, 30], b"t2g: Sorted(&slice) compat\n");

    // ─── 3. maps seq surface ───────────────────────────────────────
    let mut m: map<string, int> = map::new();
    m.Set("b", 2);
    m.Set("a", 1);
    m.Set("c", 3);
    let keys = slices::SortedFunc(maps::Keys(&m), |a: &string, b: &string| {
        if a.as_bytes() < b.as_bytes() { -1 } else { 1 }
    });
    check(keys.as_ref().len() == 3, b"t3: Keys count\n");
    check(
        keys.as_ref()[0].as_bytes() == b"a" && keys.as_ref()[2].as_bytes() == b"c",
        b"t3: sorted keys\n",
    );

    let vals = slices::Sorted(maps::Values(&m));
    check(vals.as_ref() == [1, 2, 3], b"t3b: Values\n");

    let mut pair_sum: int = 0;
    maps::All(&m).run(&mut |k, v| {
        pair_sum += (k.as_bytes().len() as int) * v;
        true
    });
    check(pair_sum == 6, b"t3c: All pairs\n");

    // ─── 4. strings seq surface ────────────────────────────────────
    let parts = slices::Collect(strings::SplitSeq("a,b,,c", ","));
    check(parts.as_ref().len() == 4, b"t4: SplitSeq count\n");
    check(
        parts.as_ref()[2].as_bytes() == b"" && parts.as_ref()[3].as_bytes() == b"c",
        b"t4: SplitSeq empties\n",
    );

    // Empty separator: UTF-8 sequence split (2-byte é stays whole).
    let runes = slices::Collect(strings::SplitSeq("h\u{e9}!", ""));
    check(runes.as_ref().len() == 3, b"t4b: empty-sep rune count\n");
    check(runes.as_ref()[1].as_bytes() == "\u{e9}".as_bytes(), b"t4b: rune boundaries\n");

    let after = slices::Collect(strings::SplitAfterSeq("x.y.", "."));
    check(
        after.as_ref()[0].as_bytes() == b"x." && after.as_ref()[2].as_bytes() == b"",
        b"t4c: SplitAfterSeq keeps sep\n",
    );

    let lines = slices::Collect(strings::Lines("one\ntwo\nthree"));
    check(lines.as_ref().len() == 3, b"t4d: Lines count\n");
    check(
        lines.as_ref()[0].as_bytes() == b"one\n" && lines.as_ref()[2].as_bytes() == b"three",
        b"t4d: Lines keeps newline, final line bare\n",
    );
    check(
        slices::Collect(strings::Lines("")).as_ref().is_empty(),
        b"t4e: Lines of empty string\n",
    );

    // Early stop through a lazy string seq.
    let mut first = string::new();
    strings::SplitSeq("alpha,beta,gamma", ",").run(&mut |part| {
        first = part;
        false
    });
    check(first.as_bytes() == b"alpha", b"t4f: lazy early stop\n");

    // ─── 5. Iterator values as data ────────────────────────────────
    let w = Walker { visit: Arc::new(Countdown(3)) };
    let via_field = slices::Collect(w.visit.clone());
    check(via_field.as_ref() == [3, 2, 1], b"t5: Arc<dyn Seq> field into sink\n");

    let msg = b"ITER_SEQ_OK all 5 test groups passed\n";
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
    syscall::Exit(0);
}
