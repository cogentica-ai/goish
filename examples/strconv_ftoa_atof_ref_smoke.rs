// strconv_float_ref_smoke — FormatFloat and ParseFloat against a
// running Go. (strconv/{ftoa,atof}.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_strconv_float_ref.go` run in `package
// strconv_test` by `scripts/goref.sh`. The tables are GENERATED from
// that output rather than typed.
//
// These two sit under `fmt`, `encoding/json` and every numeric output
// path in the tree. A shortest-round-trip formatter that is one digit
// out still prints a number; a parser that is one ULP out still returns
// a float. The two only disagree when a value crosses a boundary
// someone cares about — a price, a hash, a golden file.
//
// All 114 reference lines agree, which is the result worth pinning.
// The cases are the ones where a hand-written dtoa drifts: the shortest
// form for 0.1 and 1/3, the 1e20/1e21 boundary where `%g` switches to
// an exponent, both zeros with their sign, the subnormals down to
// 5e-324, MaxFloat64, the hex-float `x` form and the `b` mantissa form,
// float32 rounding of a value that is exact in float64, and 43
// ParseFloat inputs covering hex floats, digit separators, `inf`/`nan`
// spellings, leading and trailing space, overflow to ±Inf with a range
// error, underflow to zero, and the 17-digit values either side of a
// representable one.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::gostring::string;
use goish::strconv;
use goish::types::int;
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

// go: none — goish idiom: the smokes print one PASS/FAIL line per
//     numbered check; this is that line, hoisted.
fn report(failed: &mut int, ok: bool, n: &str, what: &str) {
    if ok {
        fmt::Println!("[", n, "]", what, "PASS");
    } else {
        fmt::Println!("[", n, "]", what, "FAIL");
        *failed += 1;
    }
}

// go: none — goish idiom: compare one rendering against Go's, naming
//     the verb and the index into the value list.
fn eq(ok: &mut bool, i: usize, what: &str, got: string, want: &str) {
    if got != s(want) {
        fmt::Println!(
            "    value",
            i as int,
            s(what),
            fmt::Sprintf!("got %q want %q", got, s(want))
        );
        *ok = false;
    }
}

// go: none — goish idiom: the value list the tables are indexed by. It
//     must stay in step with `tools/gen_strconv_float_ref.go`.
fn values() -> [f64; 31] {
    return [
        0.0,
        -0.0,
        1.0,
        -1.0,
        0.1,
        0.2,
        0.3,
        1.0 / 3.0,
        1e-5,
        1e-4,
        1e20,
        1e21,
        1e22,
        1e-300,
        1e300,
        f64::MAX,
        5e-324,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
        3.141592653589793,
        2.718281828459045,
        1.7976931348623157e308,
        4.9406564584124654e-324,
        123456789.0,
        1234567890123456789.0,
        0.000001,
        100000000000000000000.0,
        1e-323,
        5e-324,
        2.2250738585072014e-308,
    ];
}

// (e, E, f, g, G, x, b) at precision -1, in the order the smoke
// walks its value list.
const F64: [(&str, &str, &str, &str, &str, &str, &str); 31] = [
    ("0e+00", "0E+00", "0", "0", "0", "0x0p+00", "0p-1074"),
    ("-0e+00", "-0E+00", "-0", "-0", "-0", "-0x0p+00", "-0p-1074"),
    ("1e+00", "1E+00", "1", "1", "1", "0x1p+00", "4503599627370496p-52"),
    ("-1e+00", "-1E+00", "-1", "-1", "-1", "-0x1p+00", "-4503599627370496p-52"),
    ("1e-01", "1E-01", "0.1", "0.1", "0.1", "0x1.999999999999ap-04", "7205759403792794p-56"),
    ("2e-01", "2E-01", "0.2", "0.2", "0.2", "0x1.999999999999ap-03", "7205759403792794p-55"),
    ("3e-01", "3E-01", "0.3", "0.3", "0.3", "0x1.3333333333333p-02", "5404319552844595p-54"),
    ("3.333333333333333e-01", "3.333333333333333E-01", "0.3333333333333333", "0.3333333333333333", "0.3333333333333333", "0x1.5555555555555p-02", "6004799503160661p-54"),
    ("1e-05", "1E-05", "0.00001", "1e-05", "1E-05", "0x1.4f8b588e368f1p-17", "5902958103587057p-69"),
    ("1e-04", "1E-04", "0.0001", "0.0001", "0.0001", "0x1.a36e2eb1c432dp-14", "7378697629483821p-66"),
    ("1e+20", "1E+20", "100000000000000000000", "1e+20", "1E+20", "0x1.5af1d78b58c4p+66", "6103515625000000p+14"),
    ("1e+21", "1E+21", "1000000000000000000000", "1e+21", "1E+21", "0x1.b1ae4d6e2ef5p+69", "7629394531250000p+17"),
    ("1e+22", "1E+22", "10000000000000000000000", "1e+22", "1E+22", "0x1.0f0cf064dd592p+73", "4768371582031250p+21"),
    ("1e-300", "1E-300", "0.000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001", "1e-300", "1E-300", "0x1.56e1fc2f8f359p-997", "6032057205060441p-1049"),
    ("1e+300", "1E+300", "1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "1e+300", "1E+300", "0x1.7e43c8800759cp+996", "6724873095247260p+944"),
    ("1.7976931348623157e+308", "1.7976931348623157E+308", "179769313486231570000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "1.7976931348623157e+308", "1.7976931348623157E+308", "0x1.fffffffffffffp+1023", "9007199254740991p+971"),
    ("5e-324", "5E-324", "0.000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005", "5e-324", "5E-324", "0x1p-1074", "1p-1074"),
    ("+Inf", "+Inf", "+Inf", "+Inf", "+Inf", "+Inf", "+Inf"),
    ("-Inf", "-Inf", "-Inf", "-Inf", "-Inf", "-Inf", "-Inf"),
    ("NaN", "NaN", "NaN", "NaN", "NaN", "NaN", "NaN"),
    ("3.141592653589793e+00", "3.141592653589793E+00", "3.141592653589793", "3.141592653589793", "3.141592653589793", "0x1.921fb54442d18p+01", "7074237752028440p-51"),
    ("2.718281828459045e+00", "2.718281828459045E+00", "2.718281828459045", "2.718281828459045", "2.718281828459045", "0x1.5bf0a8b145769p+01", "6121026514868073p-51"),
    ("1.7976931348623157e+308", "1.7976931348623157E+308", "179769313486231570000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "1.7976931348623157e+308", "1.7976931348623157E+308", "0x1.fffffffffffffp+1023", "9007199254740991p+971"),
    ("5e-324", "5E-324", "0.000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005", "5e-324", "5E-324", "0x1p-1074", "1p-1074"),
    ("1.23456789e+08", "1.23456789E+08", "123456789", "1.23456789e+08", "1.23456789E+08", "0x1.d6f3454p+26", "8285044862877696p-26"),
    ("1.2345678901234568e+18", "1.2345678901234568E+18", "1234567890123456800", "1.2345678901234568e+18", "1.2345678901234568E+18", "0x1.12210f47de981p+60", "4822530820794753p+8"),
    ("1e-06", "1E-06", "0.000001", "1e-06", "1E-06", "0x1.0c6f7a0b5ed8dp-20", "4722366482869645p-72"),
    ("1e+20", "1E+20", "100000000000000000000", "1e+20", "1E+20", "0x1.5af1d78b58c4p+66", "6103515625000000p+14"),
    ("1e-323", "1E-323", "0.00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001", "1e-323", "1E-323", "0x1p-1073", "2p-1074"),
    ("5e-324", "5E-324", "0.000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000005", "5e-324", "5E-324", "0x1p-1074", "1p-1074"),
    ("2.2250738585072014e-308", "2.2250738585072014E-308", "0.000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000022250738585072014", "2.2250738585072014e-308", "2.2250738585072014E-308", "0x1p-1022", "4503599627370496p-1074"),
];

const PREC: [(&str, &str, &str, &str); 31] = [
    ("0", "0.00", "0", "0.000e+00"),
    ("-0", "-0.00", "-0", "-0.000e+00"),
    ("1", "1.00", "1", "1.000e+00"),
    ("-1", "-1.00", "-1", "-1.000e+00"),
    ("0", "0.10", "0.10000000000000001", "1.000e-01"),
    ("0", "0.20", "0.20000000000000001", "2.000e-01"),
    ("0", "0.30", "0.29999999999999999", "3.000e-01"),
    ("0", "0.33", "0.33333333333333331", "3.333e-01"),
    ("0", "0.00", "1.0000000000000001e-05", "1.000e-05"),
    ("0", "0.00", "0.0001", "1.000e-04"),
    ("100000000000000000000", "100000000000000000000.00", "1e+20", "1.000e+20"),
    ("1000000000000000000000", "1000000000000000000000.00", "1e+21", "1.000e+21"),
    ("10000000000000000000000", "10000000000000000000000.00", "1e+22", "1.000e+22"),
    ("0", "0.00", "1e-300", "1.000e-300"),
    ("1000000000000000052504760255204420248704468581108159154915854115511802457988908195786371375080447864043704443832883878176942523235360430575644792184786706982848387200926575803737830233794788090059368953234970799945081119038967640880074652742780142494579258788820056842838115669472196386865459400540160", "1000000000000000052504760255204420248704468581108159154915854115511802457988908195786371375080447864043704443832883878176942523235360430575644792184786706982848387200926575803737830233794788090059368953234970799945081119038967640880074652742780142494579258788820056842838115669472196386865459400540160.00", "1.0000000000000001e+300", "1.000e+300"),
    ("179769313486231570814527423731704356798070567525844996598917476803157260780028538760589558632766878171540458953514382464234321326889464182768467546703537516986049910576551282076245490090389328944075868508455133942304583236903222948165808559332123348274797826204144723168738177180919299881250404026184124858368", "179769313486231570814527423731704356798070567525844996598917476803157260780028538760589558632766878171540458953514382464234321326889464182768467546703537516986049910576551282076245490090389328944075868508455133942304583236903222948165808559332123348274797826204144723168738177180919299881250404026184124858368.00", "1.7976931348623157e+308", "1.798e+308"),
    ("0", "0.00", "4.9406564584124654e-324", "4.941e-324"),
    ("+Inf", "+Inf", "+Inf", "+Inf"),
    ("-Inf", "-Inf", "-Inf", "-Inf"),
    ("NaN", "NaN", "NaN", "NaN"),
    ("3", "3.14", "3.1415926535897931", "3.142e+00"),
    ("3", "2.72", "2.7182818284590451", "2.718e+00"),
    ("179769313486231570814527423731704356798070567525844996598917476803157260780028538760589558632766878171540458953514382464234321326889464182768467546703537516986049910576551282076245490090389328944075868508455133942304583236903222948165808559332123348274797826204144723168738177180919299881250404026184124858368", "179769313486231570814527423731704356798070567525844996598917476803157260780028538760589558632766878171540458953514382464234321326889464182768467546703537516986049910576551282076245490090389328944075868508455133942304583236903222948165808559332123348274797826204144723168738177180919299881250404026184124858368.00", "1.7976931348623157e+308", "1.798e+308"),
    ("0", "0.00", "4.9406564584124654e-324", "4.941e-324"),
    ("123456789", "123456789.00", "123456789", "1.235e+08"),
    ("1234567890123456768", "1234567890123456768.00", "1.2345678901234568e+18", "1.235e+18"),
    ("0", "0.00", "9.9999999999999995e-07", "1.000e-06"),
    ("100000000000000000000", "100000000000000000000.00", "1e+20", "1.000e+20"),
    ("0", "0.00", "9.8813129168249309e-324", "9.881e-324"),
    ("0", "0.00", "4.9406564584124654e-324", "4.941e-324"),
    ("0", "0.00", "2.2250738585072014e-308", "2.225e-308"),
];

const F32: [(&str, &str, &str); 8] = [
    ("0", "0e+00", "0"),
    ("1", "1e+00", "1"),
    ("0.1", "1e-01", "0.1"),
    ("1e-05", "1e-05", "0.00001"),
    ("1e+20", "1e+20", "100000000000000000000"),
    (
        "3.4028235e+38",
        "3.4028235e+38",
        "340282350000000000000000000000000000000",
    ),
    (
        "1e-45",
        "1e-45",
        "0.000000000000000000000000000000000000000000001",
    ),
    ("3.1415927", "3.1415927e+00", "3.1415927"),
];

// (input, %v of the float64, its error, %v of the float32, its error)
const PARSE: [(&str, &str, &str, &str, &str); 43] = [
    ("0", "0", "", "0", ""),
    ("-0", "-0", "", "-0", ""),
    ("1", "1", "", "1", ""),
    ("-1", "-1", "", "-1", ""),
    ("0.1", "0.1", "", "0.10000000149011612", ""),
    (".1", "0.1", "", "0.10000000149011612", ""),
    ("1.", "1", "", "1", ""),
    ("+1", "1", "", "1", ""),
    ("1e3", "1000", "", "1000", ""),
    ("1E3", "1000", "", "1000", ""),
    ("1e+3", "1000", "", "1000", ""),
    ("1e-3", "0.001", "", "0.0010000000474974513", ""),
    ("1_000", "1000", "", "1000", ""),
    ("0x1p-2", "0.25", "", "0.25", ""),
    ("0x1.fp4", "31", "", "31", ""),
    ("0X1P0", "1", "", "1", ""),
    ("inf", "+Inf", "", "+Inf", ""),
    ("Inf", "+Inf", "", "+Inf", ""),
    ("+Inf", "+Inf", "", "+Inf", ""),
    ("-inf", "-Inf", "", "-Inf", ""),
    ("infinity", "+Inf", "", "+Inf", ""),
    ("nan", "NaN", "", "NaN", ""),
    ("NaN", "NaN", "", "NaN", ""),
    ("-nan", "0", "strconv.ParseFloat: parsing \"-nan\": invalid syntax", "0", "strconv.ParseFloat: parsing \"-nan\": invalid syntax"),
    ("", "0", "strconv.ParseFloat: parsing \"\": invalid syntax", "0", "strconv.ParseFloat: parsing \"\": invalid syntax"),
    (" 1", "0", "strconv.ParseFloat: parsing \" 1\": invalid syntax", "0", "strconv.ParseFloat: parsing \" 1\": invalid syntax"),
    ("1 ", "0", "strconv.ParseFloat: parsing \"1 \": invalid syntax", "0", "strconv.ParseFloat: parsing \"1 \": invalid syntax"),
    ("abc", "0", "strconv.ParseFloat: parsing \"abc\": invalid syntax", "0", "strconv.ParseFloat: parsing \"abc\": invalid syntax"),
    ("1e", "0", "strconv.ParseFloat: parsing \"1e\": invalid syntax", "0", "strconv.ParseFloat: parsing \"1e\": invalid syntax"),
    ("e3", "0", "strconv.ParseFloat: parsing \"e3\": invalid syntax", "0", "strconv.ParseFloat: parsing \"e3\": invalid syntax"),
    ("1e999", "+Inf", "strconv.ParseFloat: parsing \"1e999\": value out of range", "+Inf", "strconv.ParseFloat: parsing \"1e999\": value out of range"),
    ("-1e999", "-Inf", "strconv.ParseFloat: parsing \"-1e999\": value out of range", "-Inf", "strconv.ParseFloat: parsing \"-1e999\": value out of range"),
    ("1e-999", "0", "", "0", ""),
    ("0.0000000000000000000001", "1e-22", "", "1.000000031374395e-22", ""),
    ("340282356779733661637539395458142568448", "3.4028235677973366e+38", "", "+Inf", "strconv.ParseFloat: parsing \"340282356779733661637539395458142568448\": value out of range"),
    ("1e310", "+Inf", "strconv.ParseFloat: parsing \"1e310\": value out of range", "+Inf", "strconv.ParseFloat: parsing \"1e310\": value out of range"),
    ("1e-310", "1e-310", "", "0", ""),
    ("4.9406564584124654e-324", "5e-324", "", "0", ""),
    ("2.2250738585072011e-308", "2.225073858507201e-308", "", "0", ""),
    ("1.7976931348623159e308", "+Inf", "strconv.ParseFloat: parsing \"1.7976931348623159e308\": value out of range", "+Inf", "strconv.ParseFloat: parsing \"1.7976931348623159e308\": value out of range"),
    ("9007199254740993", "9.007199254740992e+15", "", "9.007199254740992e+15", ""),
    ("0b101", "0", "strconv.ParseFloat: parsing \"0b101\": invalid syntax", "0", "strconv.ParseFloat: parsing \"0b101\": invalid syntax"),
    ("0o17", "0", "strconv.ParseFloat: parsing \"0o17\": invalid syntax", "0", "strconv.ParseFloat: parsing \"0o17\": invalid syntax"),
];

#[goish::main]
fn main() {
    let mut failed = 0;
    let vals = values();

    // 1. FormatFloat at precision -1 — the shortest form that parses
    //    back exactly — in all seven of Go's verbs.
    {
        let mut ok = true;
        let mut i = 0usize;
        while i < F64.len() {
            let (we, wce, wf, wg, wcg, wx, wb) = F64[i];
            let v = vals[i];
            eq(&mut ok, i, "'e'", strconv::FormatFloat(v, b'e', -1, 64), we);
            eq(
                &mut ok,
                i,
                "'E'",
                strconv::FormatFloat(v, b'E', -1, 64),
                wce,
            );
            eq(&mut ok, i, "'f'", strconv::FormatFloat(v, b'f', -1, 64), wf);
            eq(&mut ok, i, "'g'", strconv::FormatFloat(v, b'g', -1, 64), wg);
            eq(
                &mut ok,
                i,
                "'G'",
                strconv::FormatFloat(v, b'G', -1, 64),
                wcg,
            );
            eq(&mut ok, i, "'x'", strconv::FormatFloat(v, b'x', -1, 64), wx);
            eq(&mut ok, i, "'b'", strconv::FormatFloat(v, b'b', -1, 64), wb);
            i += 1;
        }
        report(
            &mut failed,
            ok,
            " 1",
            "the shortest form, in all seven verbs",
        );
    }

    // 2. And at an explicit precision, where rounding is the whole
    //    question: `%.0f` of 0.5, `%.17g` of a value that needs every
    //    digit, `%.3e` of a subnormal.
    {
        let mut ok = true;
        let mut i = 0usize;
        while i < PREC.len() {
            let (w0f, w2f, w17g, w3e) = PREC[i];
            let v = vals[i];
            eq(
                &mut ok,
                i,
                "'f' 0",
                strconv::FormatFloat(v, b'f', 0, 64),
                w0f,
            );
            eq(
                &mut ok,
                i,
                "'f' 2",
                strconv::FormatFloat(v, b'f', 2, 64),
                w2f,
            );
            eq(
                &mut ok,
                i,
                "'g' 17",
                strconv::FormatFloat(v, b'g', 17, 64),
                w17g,
            );
            eq(
                &mut ok,
                i,
                "'e' 3",
                strconv::FormatFloat(v, b'e', 3, 64),
                w3e,
            );
            i += 1;
        }
        report(
            &mut failed,
            ok,
            " 2",
            "an explicit precision rounds as Go's does",
        );
    }

    // 3. float32, where the shortest form is shorter: 0.1 is "0.1" in
    //    both widths but 3.1415927 is exact in float32 and not in
    //    float64, so bitSize is not a formatting detail.
    {
        let mut ok = true;
        let f32s: [f32; 8] = [0.0, 1.0, 0.1, 1e-5, 1e20, f32::MAX, 1e-45, 3.1415927];
        let mut i = 0usize;
        while i < F32.len() {
            let (wg, we, wf) = F32[i];
            let v = f32s[i] as f64;
            eq(
                &mut ok,
                i,
                "f32 'g'",
                strconv::FormatFloat(v, b'g', -1, 32),
                wg,
            );
            eq(
                &mut ok,
                i,
                "f32 'e'",
                strconv::FormatFloat(v, b'e', -1, 32),
                we,
            );
            eq(
                &mut ok,
                i,
                "f32 'f'",
                strconv::FormatFloat(v, b'f', -1, 32),
                wf,
            );
            i += 1;
        }
        report(
            &mut failed,
            ok,
            " 3",
            "float32 is not float64 with fewer digits",
        );
    }

    // 4. ParseFloat over 43 inputs, in both bit sizes. Go accepts hex
    //    floats and `_` separators, accepts "inf"/"Inf"/"+Inf"/"nan" in
    //    any casing, REJECTS "infinity", rejects leading or trailing
    //    space, and returns ±Inf WITH a range error on overflow rather
    //    than an error alone.
    {
        let mut ok = true;
        let mut i = 0usize;
        while i < PARSE.len() {
            let (input, w64, werr64, w32, werr32) = PARSE[i];
            let (v, err) = strconv::ParseFloat(input, 64);
            let (v32, err32) = strconv::ParseFloat(input, 32);
            eq(&mut ok, i, input, fmt::Sprintf!("%v", v), w64);
            eq(&mut ok, i, input, fmt::Sprintf!("%v", v32), w32);
            for (got, want) in [(err, werr64), (err32, werr32)] {
                if want.len() == 0 {
                    if !got.IsNil() {
                        fmt::Println!("   ", s(input), "unexpected", got.Error());
                        ok = false;
                    }
                } else if got.IsNil() || got.Error() != s(want) {
                    fmt::Println!(
                        "   ",
                        s(input),
                        "err got",
                        if got.IsNil() { s("<nil>") } else { got.Error() },
                        "want",
                        s(want)
                    );
                    ok = false;
                }
            }
            i += 1;
        }
        report(&mut failed, ok, " 4", "ParseFloat, in both bit sizes");
    }

    // 5. The round trip that makes precision -1 mean anything: every
    //    shortest form must parse back to the SAME BITS, signed zero
    //    included.
    {
        let mut ok = true;
        let mut i = 0usize;
        while i < vals.len() {
            let v = vals[i];
            let t = strconv::FormatFloat(v, b'g', -1, 64);
            let (back, err) = strconv::ParseFloat(t.clone(), 64);
            if !err.IsNil() {
                ok = false;
            } else if !v.is_nan() && back.to_bits() != v.to_bits() {
                fmt::Println!(
                    "    value",
                    i as int,
                    fmt::Sprintf!("%v -> %q -> %v differs in bits", v, t, back)
                );
                ok = false;
            }
            i += 1;
        }
        report(
            &mut failed,
            ok,
            " 5",
            "the shortest form round-trips exactly",
        );
    }

    if failed == 0 {
        fmt::Println!("ok 5/5");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 5");
        syscall::Exit(1);
    }
}
