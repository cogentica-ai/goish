// Real Go 1.25.5 differential for encoding/base64/base64.go:518-584 Decode.
// Compare count, status, and the ENTIRE caller-owned destination (not dst[:n]).
// Oracle: tools/gen_base64decode_ref.go.
#![no_std]
#![no_main]
use goish::encoding::{base64, hex};
use goish::goslice::slice;
use goish::{byte, int, nil, syscall};

#[goish::main]
fn main() {
    for line in include_str!("base64decode_ref.txt").lines() {
        let mut fields = line.split('|');
        let size = fields.next().unwrap().parse::<int>().unwrap();
        let input = fields.next().unwrap();
        let expected_n = fields.next().unwrap().parse::<int>().unwrap();
        let expected_ok = fields.next().unwrap() == "true";
        let expected_hex = fields.next().unwrap();
        let mut dst = goish::make!([]byte, size);
        for i in 0..size { dst[i] = byte(91+i); }
        let (n, err) = base64::StdEncoding.Decode(&mut dst, slice::from(input.as_bytes()));
        let actual = hex::EncodeToString(&dst);
        if n != expected_n || (err == nil) != expected_ok || actual.as_bytes() != expected_hex.as_bytes() {
            syscall::Write(syscall::STDERR, line.as_ptr(), line.len());
            syscall::Write(syscall::STDERR, actual.as_bytes().as_ptr(), actual.as_bytes().len());
            syscall::Exit(1);
        }
    }
    let msg = b"BASE64_DECODE_OK full caller buffer and partial writes vs real Go\n";
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
}
