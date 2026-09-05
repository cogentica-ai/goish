// Fixed-array codec differential against real Go 1.25.5 json/v2.
// Oracle: tools/gen_jsonarray_ref.go; covers length errors, partial state,
// nested arrays, null, truncation, base64 bytes, and exhaustive element tuples.
#![no_std]
#![no_main]

extern crate alloc;
use goish::encoding::json::v2 as json;
use goish::goarray::array;
use goish::gostring::string;
use goish::{int, nil, syscall};

const REFERENCE: &str = include_str!("jsonarray_ref.txt");

// Go's named-byte array uses element codecs, unlike a built-in byte array.
#[derive(Default)]
struct NamedByte(u8);
impl json::MarshalerTo for NamedByte {
    fn MarshalJSONTo(&self, enc: &mut goish::encoding::json::jsontext::Encoder) -> goish::error {
        self.0.MarshalJSONTo(enc)
    }
}
impl json::UnmarshalerFrom for NamedByte {
    fn UnmarshalJSONFrom(&mut self, dec: &mut goish::encoding::json::jsontext::Decoder) -> goish::error {
        self.0.UnmarshalJSONFrom(dec)
    }
}

fn fail(line: &str, state: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, line.as_ptr(), line.len());
    syscall::Write(syscall::STDERR, b"\nactual: ".as_ptr(), 9);
    syscall::Write(syscall::STDERR, state.as_ptr(), state.len());
    syscall::Exit(1);
}

fn check<T: json::UnmarshalerFrom + json::MarshalerTo>(line: &str, input: &str, ok: bool, expected: &str, mut value: T) {
    let err = json::Unmarshal(input.as_bytes(), &mut value, []);
    let (state, encode_error) = json::Marshal(&value, []);
    if (err == nil) != ok || encode_error != nil || state.as_ref() != expected.as_bytes() {
        fail(line, state.as_ref());
    }
}

#[goish::main]
fn main() {
    for line in REFERENCE.lines() {
        let mut fields = line.split('|');
        let label = fields.next().unwrap();
        let input = fields.next().unwrap();
        let ok = fields.next().unwrap() == "true";
        let expected = fields.next().unwrap();
        match label {
            "i0" => check(line, input, ok, expected, array::<int, 0>::default()),
            "i1" => check(line, input, ok, expected, goish::array!([1]int{91})),
            "i2" => check(line, input, ok, expected, goish::array!([2]int{91, 92})),
            "i4" => check(line, input, ok, expected, goish::array!([4]int{91, 92, 93, 94})),
            "b0" => check(line, input, ok, expected, array::<u8, 0>::default()),
            "b1" => check(line, input, ok, expected, goish::array!([1]u8{91})),
            "b2" => check(line, input, ok, expected, goish::array!([2]u8{91, 92})),
            "b4" => check(line, input, ok, expected, goish::array!([4]u8{91, 92, 93, 94})),
            "b8" => check(line, input, ok, expected, array::<u8, 8>::__from_arr(::core::array::from_fn(|i| 91+i as u8))),
            "b16" => check(line, input, ok, expected, array::<u8, 16>::__from_arr(::core::array::from_fn(|i| 91+i as u8))),
            "nested" => check(line, input, ok, expected, array::__from_arr([
                goish::array!([2]int{91, 92}), goish::array!([2]int{93, 94}),
            ])),
            "strings" => check(line, input, ok, expected, goish::array!([2]string{string::from("old1"), string::from("old2")})),
            "namedByte" => check(line, input, ok, expected, array::__from_arr([NamedByte(91), NamedByte(92)])),
            _ => fail(line, b"unknown corpus label"),
        }
    }
    use json::JsonOmit;
    assert!(array::<int, 0>::default().__json_empty());
    assert!(array::<int, 2>::default().__json_zero());
    assert!(!array::<int, 2>::default().__json_empty());
    assert!(!goish::array!([2]int{0, 1}).__json_zero());
    let msg = b"JSON_ARRAY_OK byte-exact status and partial state vs real Go json/v2\n";
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
}
