// Milestone 12 smoke test: slices package.
//
// Covers Sort!/Reverse!/IsSorted, Min/Max, BinarySearch (hit + miss),
// Equal/Compare, Index/Contains, Compact, Concat, Delete, Clone.

#![no_std]
#![no_main]

use goish::{append, int, make, slice, slices, string, syscall};

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
    // ─── Sort! / IsSorted ─────────────────────────────────────────────

    let mut xs: slice<int> = slice!([]int{ 3, 1, 4, 1, 5, 9, 2, 6 });
    check(!slices::IsSorted(&xs), b"slices: IsSorted(unsorted) wrong\n");
    slices::Sort!(xs);
    check(slices::IsSorted(&xs), b"slices: Sort! must produce sorted\n");
    let want: slice<int> = slice!([]int{ 1, 1, 2, 3, 4, 5, 6, 9 });
    check(slices::Equal(&xs, &want), b"slices: Sort! result wrong\n");

    // ─── Reverse! ─────────────────────────────────────────────────────

    slices::Reverse!(xs);
    let want: slice<int> = slice!([]int{ 9, 6, 5, 4, 3, 2, 1, 1 });
    check(slices::Equal(&xs, &want), b"slices: Reverse! wrong\n");

    // ─── Min / Max ────────────────────────────────────────────────────

    let xs: slice<int> = slice!([]int{ 3, 1, 4, 1, 5, 9, 2, 6 });
    check(slices::Min(&xs) == 1, b"slices: Min wrong\n");
    check(slices::Max(&xs) == 9, b"slices: Max wrong\n");

    // ─── BinarySearch hit + miss ──────────────────────────────────────

    let sorted: slice<int> = slice!([]int{ 1, 3, 5, 7, 9 });
    let (i, ok) = slices::BinarySearch(&sorted, &5);
    check(ok && i == 2, b"slices: BinarySearch hit wrong\n");

    let (i, ok) = slices::BinarySearch(&sorted, &4);
    check(!ok && i == 2, b"slices: BinarySearch miss insertion-point wrong\n");

    let (i, ok) = slices::BinarySearch(&sorted, &10);
    check(!ok && i == 5, b"slices: BinarySearch above-end wrong\n");

    // ─── Equal / Compare ──────────────────────────────────────────────

    let a: slice<int> = slice!([]int{ 1, 2, 3 });
    let b: slice<int> = slice!([]int{ 1, 2, 3 });
    let c: slice<int> = slice!([]int{ 1, 2, 4 });
    check(slices::Equal(&a, &b), b"slices: Equal a==b wrong\n");
    check(!slices::Equal(&a, &c), b"slices: Equal a!=c wrong\n");
    check(slices::Compare(&a, &b) == 0, b"slices: Compare ==0 wrong\n");
    check(slices::Compare(&a, &c) == -1, b"slices: Compare a<c wrong\n");
    check(slices::Compare(&c, &a) == 1, b"slices: Compare c>a wrong\n");

    // String slice equality.
    let p: slice<string> = slice!([]string{ "alice", "bob" });
    let q: slice<string> = slice!([]string{ "alice", "bob" });
    check(slices::Equal(&p, &q), b"slices: Equal on strings wrong\n");

    // ─── Index / Contains ─────────────────────────────────────────────

    let xs: slice<int> = slice!([]int{ 10, 20, 30, 40 });
    check(slices::Index(&xs, &30) == 2, b"slices: Index hit wrong\n");
    check(slices::Index(&xs, &99) == -1, b"slices: Index miss wrong\n");
    check(slices::Contains(&xs, &20), b"slices: Contains hit wrong\n");
    check(!slices::Contains(&xs, &99), b"slices: Contains miss wrong\n");

    // ─── Compact ──────────────────────────────────────────────────────

    let xs: slice<int> = slice!([]int{ 1, 1, 2, 3, 3, 3, 4, 4 });
    let c = slices::Compact(xs);
    let want: slice<int> = slice!([]int{ 1, 2, 3, 4 });
    check(slices::Equal(&c, &want), b"slices: Compact wrong\n");

    // ─── Concat ───────────────────────────────────────────────────────

    let a: slice<int> = slice!([]int{ 1, 2 });
    let b: slice<int> = slice!([]int{ 3, 4 });
    let c: slice<int> = slice!([]int{ 5 });
    let cc = slices::Concat(&[&a, &b, &c]);
    let want: slice<int> = slice!([]int{ 1, 2, 3, 4, 5 });
    check(slices::Equal(&cc, &want), b"slices: Concat wrong\n");

    // ─── Delete ───────────────────────────────────────────────────────

    let xs: slice<int> = slice!([]int{ 1, 2, 3, 4, 5 });
    let d = slices::Delete(xs, 1, 4); // remove indices 1..4 → keep [1, 5]
    let want: slice<int> = slice!([]int{ 1, 5 });
    check(slices::Equal(&d, &want), b"slices: Delete wrong\n");

    // ─── Clone (free-fn form) ─────────────────────────────────────────

    let xs: slice<int> = slice!([]int{ 7, 8, 9 });
    let copy = slices::Clone(&xs);
    check(slices::Equal(&xs, &copy), b"slices: Clone equality wrong\n");

    // ─── Sort! interacts with append! correctly ───────────────────────

    let mut ys = make!([]int, 0, 4);
    ys = append!(ys, 5, 3, 8, 1);
    slices::Sort!(ys);
    let want: slice<int> = slice!([]int{ 1, 3, 5, 8 });
    check(slices::Equal(&ys, &want), b"slices: Sort! after append! wrong\n");

    const OK: &[u8] = b"slices: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
