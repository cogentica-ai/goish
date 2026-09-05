// Slice decode differential against real Go 1.25.5 json/v2.
// Oracle: tools/gen_jsonslice_ref.go. Check decoder depth and partial state,
// not only successful JSON output. Pointer rows exercise Option allocation.
#![no_std]
#![no_main]

extern crate alloc;
use alloc::boxed::Box;

use goish::encoding::json::{jsontext, v2 as json};
use goish::goslice::slice;
use goish::gostring::string;
use goish::{int, nil, strings, syscall};

#[goish::reflect]
#[derive(Clone, Default)]
struct Record {
    Count: int,
    Other: int,
}

fn check<T: json::UnmarshalerFrom + json::MarshalerTo>(line: &str, input: &str, ok: bool, expected: &str, depth: int, mut value: T) {
    let mut decoder = jsontext::NewDecoder(strings::NewReader(string::from(input)), []);
    let err = json::UnmarshalDecode(&mut decoder, &mut value);
    let (state, encode_error) = json::Marshal(&value, []);
    if (err == nil) != ok || encode_error != nil || state.as_ref() != expected.as_bytes() || decoder.StackDepth() != depth {
        syscall::Write(syscall::STDERR, line.as_ptr(), line.len());
        let actual = goish::fmt::Sprintf!("\nactual: %t|%s|%d\n", err == nil, state, decoder.StackDepth());
        syscall::Write(syscall::STDERR, actual.as_bytes().as_ptr(), actual.as_bytes().len());
        syscall::Exit(1);
    }
}

#[goish::main]
fn main() {
    let mut count = 0;
    let mut boxed = 0;
    for line in include_str!("jsonslice_ref.txt").lines() {
        let mut fields = line.split('|');
        let label = fields.next().unwrap();
        let input = fields.next().unwrap();
        let ok = fields.next().unwrap() == "true";
        let expected = fields.next().unwrap();
        let depth = fields.next().unwrap().parse::<int>().unwrap();
        match label {
            "empty" => check(line, input, ok, expected, depth, slice::<int>::new()),
            "old" => check(line, input, ok, expected, depth, goish::slice!([]int{91,92,93})),
            "p-nil" => check(line, input, ok, expected, depth, None::<slice<int>>),
            "p-old" => check(line, input, ok, expected, depth, Some(goish::slice!([]int{91,92,93}))),
            "nested" => check(line, input, ok, expected, depth, goish::slice!([]slice<int>{goish::slice!([]int{91,92}),goish::slice!([]int{93,94})})),
            "strings" => check(line, input, ok, expected, depth, goish::slice!([]string{string::from("old1"),string::from("old2")})),
            "record-nil" => check(line, input, ok, expected, depth, None::<Record>),
            "record-old" => check(line, input, ok, expected, depth, Some(Record { Count: 91, Other: 92 })),
            "record-slice" => check(line, input, ok, expected, depth, goish::slice!([]Record{Record { Count: 91, Other: 92 }})),
            _ => syscall::Exit(1),
        }
        // The same Go pointer oracle also applies to an owned recursive
        // pointee behind Box: decoding must not replace or clone that pointee.
        match label {
            "p-nil" => check(line, input, ok, expected, depth, None::<Box<slice<int>>>),
            "p-old" => check(line, input, ok, expected, depth, Some(Box::new(goish::slice!([]int{91,92,93})))),
            "record-nil" => check(line, input, ok, expected, depth, None::<Box<Record>>),
            "record-old" => check(line, input, ok, expected, depth, Some(Box::new(Record { Count: 91, Other: 92 }))),
            _ => { count += 1; continue; }
        }
        boxed += 1;
        count += 1;
    }
    if count != 1731 || boxed != 862 { syscall::Exit(1); }
    let mut value = Some(Box::new(Record { Count: 91, Other: 92 }));
    let address = &**value.as_ref().unwrap() as *const Record;
    let err = json::Unmarshal(br#"{"Count":1,"Other":true}"#, &mut value, []);
    if err == nil || &**value.as_ref().unwrap() as *const Record != address
        || value.as_ref().unwrap().Count != 1 || value.as_ref().unwrap().Other != 92 {
        syscall::Exit(1);
    }
    let msg = b"JSON_SLICE_OK 1731 real-Go rows + 862 boxed pointers: status, partial state, decoder depth; pointee identity retained\n";
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
}
