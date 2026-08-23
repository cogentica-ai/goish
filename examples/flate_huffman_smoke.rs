// flate_huffman_smoke — exercise compress/flate's Huffman encoder +
// bit writer (token.go / huffman_code.go / huffman_bit_writer.go).
//
// `huffmanBitWriter`, `huffmanEncoder` and `token` are module-internal
// (`pub(crate)`), so this example drives them through the
// `flate::__huffman_writer_roundtrip` shim, which:
//   1. encodes a stored block          (writeStoredHeader + writeBytes),
//   2. encodes a literal-only block    (writeBlock, input=None),
//   3. encodes a block with a match    (writeBlock with a matchToken),
// and inflates each result back through the already-ported NewReader
// decompressor, asserting the bytes round-trip.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::compress::flate;
use goish::fmt;
use goish::runtime::sched::schedule;
use goish::{go, syscall};

#[goish::main]
fn main() {
    go!(|| {
        let (passed, total) = flate::__huffman_writer_roundtrip();
        if passed == total {
            fmt::Println!("ok", passed, "/", total);
            syscall::Exit(0);
        } else {
            fmt::Println!("FAIL", passed, "/", total);
            syscall::Exit(1);
        }
    });
    schedule();
}
