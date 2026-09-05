// Real-Go map contents and decoder depth: tools/gen_jsonmap_state_ref.go.
// The owned Goish map/slice representation does not model nil headers or
// shared backing-store aliases; this test does not claim to verify those.
#![no_std]
#![no_main]
use goish::encoding::json::{jsontext, v2 as json};
use goish::gomap::map;
use goish::gostring::string;
use goish::{fmt, int, nil, slice, strings, syscall};
#[goish::reflect]
#[derive(Clone, Default)]
struct Record { A: int, B: int }
fn check<T: Clone + Default + json::UnmarshalerFrom + json::MarshalerTo>(line: &str, initial: &str, input: &str, allow: bool, expected: &str) {
    let mut value = map::<string, T>::new();
    if json::Unmarshal(initial.as_bytes(), &mut value, []) != nil { syscall::Exit(1); }
    let mut dec = jsontext::NewDecoder(strings::NewReader(string::from(input)), [jsontext::AllowDuplicateNames(allow)]);
    let err = json::UnmarshalDecode(&mut dec, &mut value);
    let (state, encode_err) = json::Marshal(&value, [json::Deterministic(true)]);
    let actual = fmt::Sprintf!("%t|%s|%d", err == nil, state, dec.StackDepth());
    if encode_err != nil || actual.as_bytes() != expected.as_bytes() {
        let message = fmt::Sprintf!("%s\nactual: %s\n", line, actual);
        syscall::Write(syscall::STDERR, message.as_bytes().as_ptr(), message.as_bytes().len());
        syscall::Exit(1);
    }
}
#[goish::main]
fn main() {
    let mut count = 0;
    for line in include_str!("jsonmap_state_ref.txt").lines() {
        let mut f = line.splitn(5, '|');
        let kind = f.next().unwrap();
        let initial = f.next().unwrap();
        let input = f.next().unwrap();
        let allow = f.next().unwrap() == "true";
        let expected = f.next().unwrap();
        match kind {
            "I" => check::<int>(line, initial, input, allow, expected),
            "S" => check::<slice<int>>(line, initial, input, allow, expected),
            "R" => check::<Record>(line, initial, input, allow, expected),
            "M" => check::<map<string, int>>(line, initial, input, allow, expected),
            _ => syscall::Exit(1),
        }
        count += 1;
    }
    if count != 432 { syscall::Exit(1); }
    let message = b"JSON_MAP_STATE_OK 432 real-Go rows: existing values, null, composite partial state, duplicate options and depth\n";
    syscall::Write(syscall::STDOUT, message.as_ptr(), message.len());
}
