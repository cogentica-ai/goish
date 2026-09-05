// Real Go 1.25.5 amd64 conversion oracle: tools/gen_floatint_ref.go.
#![no_std]
#![no_main]
use goish::{int, int64, syscall};
use goish::convert::NumCast;
#[goish::main]
fn main() {
    let mut count = 0;
    for line in include_str!("floatint_ref.txt").lines() {
        let mut fields = line.split('|');
        let bits = u64::from_str_radix(fields.next().unwrap(), 16).unwrap();
        let value = f64::from_bits(bits);
        let f = value as f32;
        let expected = [fields.next().unwrap().parse::<i64>().unwrap(), fields.next().unwrap().parse().unwrap(), fields.next().unwrap().parse().unwrap(), fields.next().unwrap().parse().unwrap()];
        if [int(value), int64(value), int(f), int64(f)] != expected
            || <i64 as NumCast>::from_f64(value) != expected[0]
            || value.to_i64() != expected[0] || f.to_i64() != expected[2] {
            syscall::Write(syscall::STDERR, line.as_ptr(), line.len());
            syscall::Exit(1);
        }
        count += 1;
    }
    if count != 4193 { syscall::Exit(1); }
    // Same-type conversions must remain identity, including signaling NaN
    // payload bits; a gratuitous f32 -> f64 -> f32 round trip quiets them.
    for bits in [0x7f800001_u32, 0xff800001, 0x7fc00001, 0x80000000, 1] {
        let v = f32::from_bits(bits);
        if goish::float32(v).to_bits() != bits { syscall::Exit(1); }
    }
    let message = b"FLOATINT_OK 4193 real-Go amd64 rows, int/int64 and NumCast, float32/64\n";
    syscall::Write(syscall::STDOUT, message.as_ptr(), message.len());
}
