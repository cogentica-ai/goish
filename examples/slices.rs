// Milestone 5 smoke test: slice builtins (slice!, make!, append!, copy!, cap).
//
// Exercises every M5 surface and writes "slices: ok\n" if all checks
// pass. On failure: marker on stderr + non-zero exit.

#![no_std]
#![no_main]

use goish::{
    append, byte, cap, copy, int, len, make, range, slice, slice as goish_slice, string, syscall,
};

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
    // (1) slice!([]int{...}) — typed literal.
    let xs = goish_slice!([]int{1, 2, 3});
    check(len(&xs) == 3, b"slices: literal len wrong\n");
    check(
        xs[0] == 1 && xs[1] == 2 && xs[2] == 3,
        b"slices: literal contents wrong\n",
    );

    // (2) Empty literal.
    let empty = goish_slice!([]int{});
    check(len(&empty) == 0, b"slices: empty literal len wrong\n");

    // (3) make!([]T, n) — zero-init, len == cap.
    let zeros = make!([]int, 5);
    check(len(&zeros) == 5, b"slices: make len wrong\n");
    check(cap(&zeros) == 5, b"slices: make cap wrong\n");
    check(zeros[0] == 0 && zeros[4] == 0, b"slices: make not zeroed\n");

    // (4) make!([]T, len, cap) — explicit cap.
    let buf = make!([]byte, 3, 16);
    check(len(&buf) == 3, b"slices: make len(cap) wrong\n");
    check(cap(&buf) >= 16, b"slices: make cap(cap) wrong\n");

    // (5) make!([]T, 0, cap) — empty with capacity, no Default needed.
    let empty_cap: slice<int> = make!([]int, 0, 8);
    check(len(&empty_cap) == 0, b"slices: empty-cap len wrong\n");
    check(cap(&empty_cap) >= 8, b"slices: empty-cap cap wrong\n");

    // (6) append!(s, x, y, z) — variadic.
    let xs = goish_slice!([]int{1});
    let xs = append!(xs, 2, 3, 4);
    check(len(&xs) == 4, b"slices: append len wrong\n");
    check(xs[3] == 4, b"slices: append last wrong\n");

    // (7) Single-element append.
    let xs = goish_slice!([]int{10});
    let xs = append!(xs, 20);
    check(len(&xs) == 2 && xs[1] == 20, b"slices: append-1 wrong\n");

    // (8) string-literal slice — &str → string via .into() in slice! macro.
    let names = goish_slice!([]string{"alice", "bob"});
    check(len(&names) == 2, b"slices: names len wrong\n");
    check(
        names[0] == "alice" && names[1] == "bob",
        b"slices: names contents wrong\n",
    );

    // (9) copy!(dst, src) — element copy, returns int = min(len(dst), len(src)).
    let mut dst = make!([]int, 5);
    let src = goish_slice!([]int{10, 20, 30});
    let n = copy!(dst, src);
    check(n == 3, b"slices: copy returned wrong count\n");
    check(
        dst[0] == 10 && dst[2] == 30,
        b"slices: copy contents wrong\n",
    );
    check(dst[3] == 0 && dst[4] == 0, b"slices: copy overwrote tail\n");

    // (10) copy! with src longer than dst — caps at dst.len.
    let mut small = make!([]int, 2);
    let big = goish_slice!([]int{1, 2, 3, 4, 5});
    let n = copy!(small, big);
    check(n == 2, b"slices: copy-truncate count wrong\n");
    check(
        small[0] == 1 && small[1] == 2,
        b"slices: copy-truncate contents wrong\n",
    );

    // (11) range! over slice — (int, &T).
    let xs = goish_slice!([]int{100, 200, 300});
    let mut sum: int = 0;
    let mut last_i: int = -1;
    for (i, v) in range!(xs) {
        sum += *v;
        last_i = i;
    }
    check(sum == 600, b"slices: range sum wrong\n");
    check(last_i == 2, b"slices: range last index wrong\n");

    // (12) Round-trip through string — bytes(string("hi")) should give a slice<byte>.
    let s = string("hi");
    let b: slice<byte> = goish::bytes(s.clone());
    check(
        len(&b) == 2 && b[0] == b'h' && b[1] == b'i',
        b"slices: bytes round-trip wrong\n",
    );

    const OK: &[u8] = b"slices: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
