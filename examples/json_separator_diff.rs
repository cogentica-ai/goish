// JSON delimiter differential: tools/gen_jsonseparator_ref.go is the real Go
// 1.25.5 oracle. Compare accepted token prefixes and success/error, with zero,
// one, or two PeekKind calls before every ReadToken. Error prose is not compared.
#![no_std]
#![no_main]
extern crate alloc;
use alloc::string::String;
use goish::encoding::json::jsontext;
use goish::{bytes, io, nil, syscall};

#[goish::main]
fn main() {
    for line in include_str!("jsonseparator_ref.txt").lines() {
        let mut fields = line.split('|');
        let peeks = fields.next().unwrap().as_bytes()[0] - b'0';
        let input = fields.next().unwrap();
        let expected = fields.next().unwrap();
        let mut dec = jsontext::NewDecoder(bytes::NewReader(input.as_bytes()), []);
        let mut actual = String::new();
        loop {
            for _ in 0..peeks { dec.PeekKind(); }
            let (token, err) = dec.ReadToken();
            if err == io::EOF { actual.push_str(" EOF"); break; }
            if err != nil { actual.push_str(" ERROR"); break; }
            actual.push(token.Kind().0 as char);
        }
        if actual != expected {
            syscall::Write(syscall::STDERR, line.as_ptr(), line.len());
            syscall::Write(syscall::STDERR, actual.as_ptr(), actual.len());
            syscall::Exit(1);
        }
    }
    let msg = b"JSON_SEPARATOR_OK 60 rows vs real Go jsontext\n";
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
}
