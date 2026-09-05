// Exact bits, decode status, and depth against tools/gen_jsonfloat_ref.go.
#![no_std]
#![no_main]
use goish::encoding::json::{jsontext, v2 as json};
use goish::{int, nil, strings, syscall};
use goish::gostring::string;
#[goish::main]
fn main() {
    let mut count = 0;
    for line in include_str!("json_float_decode_ref.txt").lines() {
        let mut fields = line.split('|');
        let bits = fields.next().unwrap();
        let input = fields.next().unwrap();
        let ok = fields.next().unwrap() == "true";
        let expected = u64::from_str_radix(fields.next().unwrap(), 16).unwrap();
        let depth = fields.next().unwrap().parse::<int>().unwrap();
        let mut dec = jsontext::NewDecoder(strings::NewReader(string::from(input)), []);
        let (err, actual) = if bits == "64" {
            let mut v = 91.0_f64;
            let err = json::UnmarshalDecode(&mut dec, &mut v);
            (err, v.to_bits())
        } else {
            let mut v = 91.0_f32;
            let err = json::UnmarshalDecode(&mut dec, &mut v);
            (err, u64::from(v.to_bits()))
        };
        if (err == nil) != ok || actual != expected || dec.StackDepth() != depth {
            let message = goish::fmt::Sprintf!("%s\nactual: %t|%x|%d\n", line, err == nil, actual, dec.StackDepth());
            syscall::Write(syscall::STDERR, message.as_bytes().as_ptr(), message.as_bytes().len());
            syscall::Exit(1);
        }
        count += 1;
    }
    if count != 5668 { syscall::Exit(1); }
    let message = b"JSON_FLOAT_OK 5668 real-Go rows: float32/64 exact bits, range errors, receiver state, decoder depth\n";
    syscall::Write(syscall::STDOUT, message.as_ptr(), message.len());
}
