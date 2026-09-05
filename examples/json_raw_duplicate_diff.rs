// Raw JSON duplicate-name differential vs Go 1.25.5 jsontext.
// Oracle: tools/gen_jsonrawdup_ref.go. Compare exact errors and StackDepth
// across ReadValue, SkipValue, and raw values nested inside token streams.
#![no_std]
#![no_main]
use goish::{bytes, convert, nil, syscall};
use goish::gostring::string;
use goish::encoding::json::{jsontext, v2};

#[goish::main]
fn main() {
    let mut rows = 0;
    for line in include_str!("jsonrawdup_ref.txt").lines() {
        let mut fields = line.split('|');
        let mode = fields.next().unwrap();
        let allow = fields.next().unwrap() == "true";
        let input = fields.next().unwrap();
        let depth = fields.next().unwrap().parse::<i64>().unwrap();
        let expected = fields.next().unwrap();
        let text = match mode {
            "array" => string::from("[") + input + ",0]",
            "object" => string::from("{\"a/b~c\":") + input + ",\"next\":0}",
            _ => string::from(input),
        };
        let mut dec = jsontext::NewDecoder(bytes::NewReader(convert::bytes(text)), [jsontext::AllowDuplicateNames(allow)]);
        if mode == "array" || mode == "object" { let _ = dec.ReadToken(); }
        if mode == "object" { let _ = dec.ReadToken(); }
        let err = if mode == "skip" { dec.SkipValue() } else { dec.ReadValue().1 };
        let text = if err == nil { string::new() } else { err.Error() };
        let (actual, encode_error) = v2::Marshal(&text, []);
        if encode_error != nil || actual.as_ref() != expected.as_bytes() || dec.StackDepth() != depth {
            syscall::Write(syscall::STDERR, line.as_ptr(), line.len());
            syscall::Write(syscall::STDERR, actual.as_ptr(), actual.len());
            syscall::Exit(1);
        }
        rows += 1;
    }
    if rows != 112 { syscall::Exit(1); }
    let msg = b"JSON_RAW_DUPLICATE_OK 112 rows: exact errors and stack depth vs real Go\n";
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
}
