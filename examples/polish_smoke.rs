// Smoke test: fmt width, time Y/M/D, log, flag.

#![no_std]
#![no_main]

use goish::{flag, slice, slices, string, syscall, time, Sprintf};

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
    // ─── fmt width specifiers ─────────────────────────────────────────

    // %6d — right-align, space pad
    let s = Sprintf!("[%6d]", 42 as goish::int);
    check(s == "[    42]", b"polish: %6d wrong\n");

    // %-6d — left-align, space pad
    let s = Sprintf!("[%-6d]", 42 as goish::int);
    check(s == "[42    ]", b"polish: %-6d wrong\n");

    // %06d — zero pad
    let s = Sprintf!("[%06d]", 42 as goish::int);
    check(s == "[000042]", b"polish: %06d wrong\n");

    // %10s — string right-aligned
    let s = Sprintf!("[%10s]", string("hi"));
    check(s == "[        hi]", b"polish: %10s wrong\n");

    // %-10s — string left-aligned
    let s = Sprintf!("[%-10s]", string("hi"));
    check(s == "[hi        ]", b"polish: %-10s wrong\n");

    // No padding when width is already exceeded.
    let s = Sprintf!("[%3d]", 1234 as goish::int);
    check(s == "[1234]", b"polish: width-exceeded wrong\n");

    // ─── time Y/M/D — Howard Hinnant algorithm ───────────────────────

    // Unix 0 = 1970-01-01 00:00:00 UTC, Thursday.
    let t = time::Unix(0, 0);
    let (y, m, d) = t.Date();
    check(y == 1970 && m == 1 && d == 1, b"polish: epoch Date wrong\n");
    let (hh, mm, ss) = t.Clock();
    check(hh == 0 && mm == 0 && ss == 0, b"polish: epoch Clock wrong\n");
    check(t.Weekday() == 4, b"polish: epoch Weekday wrong\n");

    // 2000-01-01 00:00:00 UTC = 946684800. Saturday.
    let t = time::Unix(946_684_800, 0);
    let (y, m, d) = t.Date();
    check(y == 2000 && m == 1 && d == 1, b"polish: 2000 Date wrong\n");
    check(t.Weekday() == 6, b"polish: 2000 Weekday wrong\n");

    // 2024-02-29 12:34:56 UTC = 1709210096. (Leap year edge case.)
    let t = time::Unix(1_709_210_096, 0);
    let (y, m, d) = t.Date();
    check(y == 2024 && m == 2 && d == 29, b"polish: leap-year Date wrong\n");
    let (hh, mm, ss) = t.Clock();
    check(hh == 12 && mm == 34 && ss == 56, b"polish: leap-year Clock wrong\n");

    check(t.Year() == 2024, b"polish: Year wrong\n");
    check(t.Month() == 2, b"polish: Month wrong\n");
    check(t.Day() == 29, b"polish: Day wrong\n");
    check(t.Hour() == 12, b"polish: Hour wrong\n");
    check(t.Minute() == 34, b"polish: Minute wrong\n");
    check(t.Second() == 56, b"polish: Second wrong\n");

    // ─── flag — basic Parse ─────────────────────────────────────────

    let mut fs = flag::NewFlagSet();
    let name = fs.String("name", "default", "name of the user");
    let count = fs.Int("count", 0, "iteration count");
    let verbose = fs.Bool("verbose", false, "verbose mode");
    let pi = fs.Float64("pi", 3.14, "circle constant");

    let argv: slice<string> = goish::slice!([]string{
        "--name=alice", "--count", "5", "--verbose=true", "--pi", "3.14159",
        "extra1", "extra2",
    });
    let err = fs.Parse(&argv);
    check(err == goish::nil, b"polish: flag Parse must succeed\n");
    check(name.Get() == "alice", b"polish: flag string wrong\n");
    check(count.Get() == 5, b"polish: flag int wrong\n");
    check(verbose.Get(), b"polish: flag bool wrong\n");
    check(pi.Get() == 3.14159, b"polish: flag float wrong\n");

    let positional = fs.Args();
    check(positional.Len() == 2, b"polish: flag positional count wrong\n");
    let want: slice<string> = goish::slice!([]string{ "extra1", "extra2" });
    check(slices::Equal(&positional, &want), b"polish: flag positional values wrong\n");

    // ─── flag — `--` separator ──────────────────────────────────────

    let mut fs = flag::NewFlagSet();
    let _ = fs.String("x", "", "");
    let argv: slice<string> = goish::slice!([]string{
        "--", "--x=should-be-positional",
    });
    let err = fs.Parse(&argv);
    check(err == goish::nil, b"polish: flag -- err\n");
    check(fs.NArg() == 1, b"polish: -- separator NArg wrong\n");

    // ─── flag — unknown flag errors ─────────────────────────────────

    let mut fs = flag::NewFlagSet();
    let _ = fs.String("known", "", "");
    let argv: slice<string> = goish::slice!([]string{ "--unknown=42" });
    let err = fs.Parse(&argv);
    check(err != goish::nil, b"polish: flag unknown must err\n");

    // log: skip live test (would write a timestamp to stderr, hard to
    // assert in CI). The bufio_smoke + json_smoke test patterns prove
    // the prefix machinery works since `log::Println!` shares the
    // fmt::fprintln_impl call path.

    const OK: &[u8] = b"polish: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
