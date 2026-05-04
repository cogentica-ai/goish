// M11b-A smoke: strconv float ParseFloat + FormatFloat round-trip.

#![no_std]
#![no_main]

use goish::{errors, float64, nil, slice, strconv, syscall, Sprintf};

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
    // ─── ParseFloat happy paths ───────────────────────────────────────

    let (v, err) = strconv::ParseFloat("1.5", 64);
    check(err == nil && v == 1.5, b"floats: ParseFloat(1.5) wrong\n");

    let (v, err) = strconv::ParseFloat("0", 64);
    check(err == nil && v == 0.0, b"floats: ParseFloat(0) wrong\n");

    let (v, err) = strconv::ParseFloat("-3.14", 64);
    check(err == nil && v == -3.14, b"floats: ParseFloat(-3.14) wrong\n");

    let (v, err) = strconv::ParseFloat("1e10", 64);
    check(err == nil && v == 1e10, b"floats: ParseFloat(1e10) wrong\n");

    let (v, err) = strconv::ParseFloat("1.5E-3", 64);
    check(err == nil && v == 1.5e-3, b"floats: ParseFloat(1.5E-3) wrong\n");

    // Special values.
    let (v, err) = strconv::ParseFloat("inf", 64);
    check(err == nil && v.is_infinite() && v > 0.0, b"floats: ParseFloat(inf) wrong\n");
    let (v, err) = strconv::ParseFloat("-Inf", 64);
    check(err == nil && v.is_infinite() && v < 0.0, b"floats: ParseFloat(-Inf) wrong\n");
    let (v, err) = strconv::ParseFloat("NaN", 64);
    check(err == nil && v.is_nan(), b"floats: ParseFloat(NaN) wrong\n");

    // Hex float.
    let (v, err) = strconv::ParseFloat("0x1.8p+1", 64);
    check(err == nil && v == 3.0, b"floats: ParseFloat hex wrong\n");

    // ─── ParseFloat syntax errors ─────────────────────────────────────

    let (_, err) = strconv::ParseFloat("abc", 64);
    check(err != nil, b"floats: ParseFloat(abc) must err\n");
    check(
        errors::Is(err, strconv::ErrSyntax),
        b"floats: ParseFloat(abc) Is(ErrSyntax) wrong\n",
    );

    let (_, err) = strconv::ParseFloat("", 64);
    check(err != nil, b"floats: ParseFloat empty must err\n");

    let (_, err) = strconv::ParseFloat("1.2.3", 64);
    check(err != nil, b"floats: ParseFloat(1.2.3) must err\n");

    // ─── FormatFloat — verb 'g' (default), shortest round-trip ────────

    check(
        strconv::FormatFloat(1.5, b'g', -1, 64) == "1.5",
        b"floats: FormatFloat(1.5,'g') wrong\n",
    );
    check(
        strconv::FormatFloat(0.0, b'g', -1, 64) == "0",
        b"floats: FormatFloat(0,'g') wrong\n",
    );
    check(
        strconv::FormatFloat(-3.14, b'g', -1, 64) == "-3.14",
        b"floats: FormatFloat(-3.14,'g') wrong\n",
    );
    check(
        strconv::FormatFloat(0.1, b'g', -1, 64) == "0.1",
        b"floats: FormatFloat(0.1,'g') wrong\n",
    );

    // ─── FormatFloat — verb 'f' fixed-point ───────────────────────────

    check(
        strconv::FormatFloat(1.5, b'f', 2, 64) == "1.50",
        b"floats: FormatFloat(1.5,'f',2) wrong\n",
    );
    check(
        strconv::FormatFloat(3.14159, b'f', 4, 64) == "3.1416",
        b"floats: FormatFloat(3.14159,'f',4) wrong\n",
    );
    check(
        strconv::FormatFloat(0.5, b'f', 0, 64) == "0",
        b"floats: FormatFloat(0.5,'f',0) round-half-even must give 0\n",
    );

    // ─── FormatFloat — verb 'e' scientific ────────────────────────────

    check(
        strconv::FormatFloat(1500.0, b'e', 2, 64) == "1.50e+03",
        b"floats: FormatFloat(1500,'e',2) wrong\n",
    );
    check(
        strconv::FormatFloat(0.001, b'e', 3, 64) == "1.000e-03",
        b"floats: FormatFloat(0.001,'e',3) wrong\n",
    );

    // ─── FormatFloat — Inf / NaN ──────────────────────────────────────

    check(
        strconv::FormatFloat(float64::INFINITY, b'g', -1, 64) == "+Inf",
        b"floats: FormatFloat(+Inf) wrong\n",
    );
    check(
        strconv::FormatFloat(float64::NEG_INFINITY, b'g', -1, 64) == "-Inf",
        b"floats: FormatFloat(-Inf) wrong\n",
    );
    check(
        strconv::FormatFloat(float64::NAN, b'g', -1, 64) == "NaN",
        b"floats: FormatFloat(NaN) wrong\n",
    );

    // ─── Round-trip: ParseFloat(FormatFloat(x)) == x ─────────────────

    let test_vals: &[float64] = &[1.0, 1.5, -3.14, 1e10, 1e-10, 0.1, 0.5, 1234.5678];
    for &x in test_vals {
        let s = strconv::FormatFloat(x, b'g', -1, 64);
        let (back, err) = strconv::ParseFloat(s.clone(), 64);
        check(err == nil, b"floats: round-trip parse error\n");
        check(back == x, b"floats: round-trip mismatch\n");
    }

    // ─── AppendFloat — building a byte slice ──────────────────────────

    let dst: slice<goish::byte> = slice::new();
    let dst = strconv::AppendFloat(dst, 2.5, b'g', -1, 64);
    let dst = strconv::AppendFloat(dst, 7.0, b'g', -1, 64);
    let result = goish::string(dst);
    check(result == "2.57", b"floats: AppendFloat concat wrong\n");

    // ─── fmt::Format integration: %v / %g / %f / %e via Sprintf ───────

    let s = Sprintf!("%v", 1.5_f64);
    check(s == "1.5", b"floats: Sprintf %v wrong\n");

    let s = Sprintf!("%g", 0.001_f64);
    check(s == "0.001", b"floats: Sprintf %g wrong\n");

    let s = Sprintf!("%f", 3.14_f64);
    check(s == "3.14", b"floats: Sprintf %f wrong\n");

    let s = Sprintf!("%e", 1234.5_f64);
    check(s == "1.2345e+03", b"floats: Sprintf %e wrong\n");

    const OK: &[u8] = b"floats: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
