// Real SDK json/v2 oracle: tools/gen_jsonscalar_ref.go.
#![no_std]
#![no_main]
use goish::encoding::json::{jsontext, v2 as json};
use goish::gostring::string;
use goish::{fmt, nil, slice, strings, syscall};
fn encoded<T: json::MarshalerTo>(v: &T) -> string {
    let (b, e) = json::Marshal(v, []);
    if e != nil {
        syscall::Exit(1)
    };
    return string::from_bytes(&b);
}
fn options(seed: &str) -> json::Options {
    return match seed {
        "none" => json::Options::default(),
        "dup0" => jsontext::AllowDuplicateNames(false),
        "dup1" => jsontext::AllowDuplicateNames(true),
        "utf0" => jsontext::AllowInvalidUTF8(false),
        "utf1" => jsontext::AllowInvalidUTF8(true),
        "det0" => json::Deterministic(false),
        "det1" => json::Deterministic(true),
        "indent" => jsontext::WithIndent("  "),
        "prefix" => jsontext::WithIndentPrefix(" "),
        "dec-none" => jsontext::NewDecoder(strings::NewReader(string::new()), []).Options(),
        "dec-dup0" => jsontext::NewDecoder(
            strings::NewReader(string::new()),
            [jsontext::AllowDuplicateNames(false)],
        )
        .Options(),
        "dec-dup1" => jsontext::NewDecoder(
            strings::NewReader(string::new()),
            [jsontext::AllowDuplicateNames(true)],
        )
        .Options(),
        _ => syscall::Exit(1),
    };
}
#[goish::main]
fn main() {
    let mut count = 0;
    let mut failures = 0;
    for line in include_str!("jsonscalar_ref.txt").lines() {
        let mut fields = line.split('|');
        let label = fields.next().unwrap();
        let (actual, expected) = match label {
            "S" => {
                let input = fields.next().unwrap();
                let expected = &line[label.len() + input.len() + 2..];
                let mut v = string::from("old");
                let mut dec = jsontext::NewDecoder(strings::NewReader(string::from(input)), []);
                let err = json::UnmarshalDecode(&mut dec, &mut v);
                (
                    fmt::Sprintf!("%t|%s|%d", err == nil, encoded(&v), dec.StackDepth()),
                    expected,
                )
            }
            "F" => {
                let bits = fields.next().unwrap();
                let mode = fields.next().unwrap();
                let v = f64::from_bits(u64::from_str_radix(bits, 16).unwrap());
                let (b, e) = match mode {
                    "value" => json::Marshal(&v, []),
                    "array" => json::Marshal(&slice!([]f64{1.0,v}), []),
                    _ => {
                        let mut m = goish::gomap::map::<string, f64>::new();
                        m.Set(string::from("a"), 1.0);
                        m.Set(string::from("b"), v);
                        json::Marshal(&m, [json::Deterministic(true)])
                    }
                };
                (
                    fmt::Sprintf!("%t|%s", e == nil, encoded(&string::from_bytes(&b))),
                    &line[label.len() + bits.len() + mode.len() + 3..],
                )
            }
            "O" => {
                let seed = fields.next().unwrap();
                let kind = fields.next().unwrap();
                let mut calls = 0;
                let mut zero = true;
                let (value, present) = if kind == "indent" || kind == "prefix" {
                    let (v, p) = json::GetOption(options(seed), |v: string| {
                        calls += 1;
                        zero = zero && v == "";
                        if kind == "indent" {
                            return jsontext::WithIndent(v);
                        };
                        return jsontext::WithIndentPrefix(v);
                    });
                    (encoded(&v), p)
                } else {
                    let (v, p) = json::GetOption(options(seed), |v: bool| {
                        calls += 1;
                        zero = zero && !v;
                        if kind == "dup" {
                            return jsontext::AllowDuplicateNames(v);
                        };
                        if kind == "utf" {
                            return jsontext::AllowInvalidUTF8(v);
                        };
                        return json::Deterministic(v);
                    });
                    (encoded(&v), p)
                };
                (
                    fmt::Sprintf!("%s|%t|%d|%t", value, present, calls, zero),
                    &line[label.len() + seed.len() + kind.len() + 3..],
                )
            }
            _ => syscall::Exit(1),
        };
        if actual.as_bytes() != expected.as_bytes() {
            let msg = fmt::Sprintf!("%s\nactual: %s\n", line, actual);
            syscall::Write(
                syscall::STDERR,
                msg.as_bytes().as_ptr(),
                msg.as_bytes().len(),
            );
            failures += 1;
        }
        count += 1;
    }
    let msg = fmt::Sprintf!("JSON_SCALAR rows=%d failures=%d\n", count, failures);
    syscall::Write(
        syscall::STDOUT,
        msg.as_bytes().as_ptr(),
        msg.as_bytes().len(),
    );
    if count != 98 || failures != 0 {
        syscall::Exit(1)
    }
}
