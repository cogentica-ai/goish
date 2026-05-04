// Milestone 11a smoke test: strconv package.
//
// Covers Atoi/Itoa, ParseInt/FormatInt for non-decimal bases, ParseUint
// overflow, signed range-clamp, ParseBool/FormatBool round-trip, NumError
// chain walking via errors::Is, and Append* into a byte slice.

#![no_std]
#![no_main]

use goish::{errors, nil, slice, strconv, string, syscall, uint};

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
    // ─── Itoa / FormatInt / FormatUint ────────────────────────────────

    check(strconv::Itoa(0) == "0", b"strconv: Itoa(0) wrong\n");
    check(strconv::Itoa(42) == "42", b"strconv: Itoa(42) wrong\n");
    check(strconv::Itoa(-7) == "-7", b"strconv: Itoa(-7) wrong\n");

    check(
        strconv::FormatInt(255, 16) == "ff",
        b"strconv: FormatInt base 16 wrong\n",
    );
    check(
        strconv::FormatInt(-255, 16) == "-ff",
        b"strconv: FormatInt base 16 negative wrong\n",
    );
    check(
        strconv::FormatInt(10, 2) == "1010",
        b"strconv: FormatInt base 2 wrong\n",
    );
    check(
        strconv::FormatInt(35, 36) == "z",
        b"strconv: FormatInt base 36 wrong\n",
    );

    check(
        strconv::FormatUint(0xdeadbeef as uint, 16) == "deadbeef",
        b"strconv: FormatUint base 16 wrong\n",
    );

    // i64::MIN round-trip — exercises the wrapping_neg path.
    check(
        strconv::FormatInt(i64::MIN, 10) == "-9223372036854775808",
        b"strconv: FormatInt i64::MIN wrong\n",
    );

    // ─── Atoi happy path ──────────────────────────────────────────────

    let (n, err) = strconv::Atoi("42");
    check(err == nil, b"strconv: Atoi(42) err must be nil\n");
    check(n == 42, b"strconv: Atoi(42) value wrong\n");

    let (n, err) = strconv::Atoi("-1234");
    check(err == nil, b"strconv: Atoi(-1234) err must be nil\n");
    check(n == -1234, b"strconv: Atoi(-1234) value wrong\n");

    let (n, err) = strconv::Atoi("0");
    check(err == nil && n == 0, b"strconv: Atoi(0) wrong\n");

    // ─── Atoi failure path → NumError + ErrSyntax chain ───────────────

    let (n, err) = strconv::Atoi("abc");
    check(n == 0, b"strconv: Atoi(abc) value must be 0\n");
    check(err != nil, b"strconv: Atoi(abc) err must be non-nil\n");
    check(
        err.Error() == "strconv.Atoi: parsing \"abc\": invalid syntax",
        b"strconv: Atoi(abc) error text wrong\n",
    );
    check(
        errors::Is(err.clone(), strconv::ErrSyntax),
        b"strconv: Atoi(abc) Is(ErrSyntax) must hold\n",
    );
    check(
        !errors::Is(err.clone(), strconv::ErrRange),
        b"strconv: Atoi(abc) Is(ErrRange) must NOT hold\n",
    );

    // ─── Atoi range clamp via slow path (>= 19 digits) ────────────────

    let (n, err) = strconv::Atoi("99999999999999999999"); // 20 digits
    check(err != nil, b"strconv: Atoi big-num err must be non-nil\n");
    check(
        errors::Is(err.clone(), strconv::ErrRange),
        b"strconv: Atoi big-num Is(ErrRange) must hold\n",
    );
    check(n == i64::MAX, b"strconv: Atoi big-num clamp must be i64::MAX\n");

    // ─── ParseInt with explicit bases ─────────────────────────────────

    let (n, err) = strconv::ParseInt("ff", 16, 64);
    check(err == nil && n == 255, b"strconv: ParseInt(ff,16) wrong\n");

    let (n, err) = strconv::ParseInt("-ff", 16, 64);
    check(err == nil && n == -255, b"strconv: ParseInt(-ff,16) wrong\n");

    let (n, err) = strconv::ParseInt("0b1010", 0, 64);
    check(err == nil && n == 10, b"strconv: ParseInt(0b1010,0) wrong\n");

    let (n, err) = strconv::ParseInt("0o17", 0, 64);
    check(err == nil && n == 15, b"strconv: ParseInt(0o17,0) wrong\n");

    let (n, err) = strconv::ParseInt("0xCAFE", 0, 64);
    check(err == nil && n == 0xcafe, b"strconv: ParseInt(0xCAFE,0) wrong\n");

    // bit_size=8 clamp
    let (n, err) = strconv::ParseInt("200", 10, 8);
    check(err != nil, b"strconv: ParseInt(200,10,8) err must be non-nil\n");
    check(n == 127, b"strconv: ParseInt(200,10,8) must clamp to 127\n");

    let (n, err) = strconv::ParseInt("-200", 10, 8);
    check(err != nil, b"strconv: ParseInt(-200,10,8) err must be non-nil\n");
    check(n == -128, b"strconv: ParseInt(-200,10,8) must clamp to -128\n");

    // ─── ParseUint ────────────────────────────────────────────────────

    let (u, err) = strconv::ParseUint("18446744073709551615", 10, 64);
    check(err == nil, b"strconv: ParseUint u64::MAX err must be nil\n");
    check(u == u64::MAX as uint, b"strconv: ParseUint u64::MAX value wrong\n");

    // Underscores: only when base==0.
    let (u, err) = strconv::ParseUint("1_000_000", 0, 64);
    check(err == nil, b"strconv: ParseUint(1_000_000,0) err must be nil\n");
    check(u == 1_000_000, b"strconv: ParseUint(1_000_000,0) value wrong\n");

    let (_, err) = strconv::ParseUint("1_000", 10, 64);
    check(
        err != nil,
        b"strconv: ParseUint(1_000,10) must reject underscores when base!=0\n",
    );

    // ─── ParseBool / FormatBool ───────────────────────────────────────

    let (b, err) = strconv::ParseBool("true");
    check(err == nil && b, b"strconv: ParseBool(true) wrong\n");
    let (b, err) = strconv::ParseBool("F");
    check(err == nil && !b, b"strconv: ParseBool(F) wrong\n");
    let (_, err) = strconv::ParseBool("nope");
    check(err != nil, b"strconv: ParseBool(nope) must error\n");

    check(
        strconv::FormatBool(true) == "true",
        b"strconv: FormatBool(true) wrong\n",
    );
    check(
        strconv::FormatBool(false) == "false",
        b"strconv: FormatBool(false) wrong\n",
    );

    // ─── AppendInt / AppendUint / AppendBool ──────────────────────────

    let dst: slice<goish::byte> = slice::new();
    let dst = strconv::AppendInt(dst, 42, 10);
    let dst = strconv::AppendBool(dst, true);
    let dst = strconv::AppendUint(dst, 0xff as uint, 16);
    // Result bytes: "42" + "true" + "ff" = "42trueff"
    let result = string(dst);
    check(result == "42trueff", b"strconv: Append* concat wrong\n");

    const OK: &[u8] = b"strconv: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
