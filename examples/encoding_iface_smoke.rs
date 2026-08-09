// encoding_iface_smoke — exercise the encoding interface traits.
//
// Mirrors Go's expectation that user-defined types can implement
// BinaryMarshaler / TextMarshaler etc. directly, and that the
// signatures match Go's contract.
//
// References:
//   /share/go/src/encoding/encoding.go (interfaces)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::encoding::{
    BinaryAppender, BinaryMarshaler, BinaryUnmarshaler, TextAppender,
    TextMarshaler, TextUnmarshaler,
};
use goish::errors::{error, nil};
use goish::types::byte;
use goish::{slice, syscall};

// A pair-of-bytes type that implements BOTH binary and text variants.
// Binary form: 2 raw bytes [hi, lo].
// Text form:   "HH:LL" (uppercase hex with colon separator).
struct Pair {
    hi: byte,
    lo: byte,
}

impl BinaryMarshaler for Pair {
    fn MarshalBinary(&self) -> (slice<byte>, error) {
        let v: alloc::vec::Vec<byte> = alloc::vec![self.hi, self.lo];
        (slice::__from_vec(v), nil.into())
    }
}

impl BinaryUnmarshaler for Pair {
    fn UnmarshalBinary(&mut self, data: slice<byte>) -> error {
        if data.Len() != 2 {
            return goish::errors::New("Pair: data must be 2 bytes");
        }
        self.hi = data[0];
        self.lo = data[1];
        nil.into()
    }
}

impl BinaryAppender for Pair {
    fn AppendBinary(
        &self,
        b: slice<byte>,
    ) -> (slice<byte>, error) {
        let mut v: alloc::vec::Vec<byte> = b.__into_vec();
        v.push(self.hi);
        v.push(self.lo);
        (slice::__from_vec(v), nil.into())
    }
}

fn hex_nyb(n: byte) -> byte {
    if n < 10 {
        b'0' + n
    } else {
        b'A' + (n - 10)
    }
}

fn unhex(c: byte) -> (byte, bool) {
    match c {
        b'0'..=b'9' => (c - b'0', true),
        b'a'..=b'f' => (c - b'a' + 10, true),
        b'A'..=b'F' => (c - b'A' + 10, true),
        _ => (0, false),
    }
}

impl TextMarshaler for Pair {
    fn MarshalText(&self) -> (slice<byte>, error) {
        let v: alloc::vec::Vec<byte> = alloc::vec![
            hex_nyb(self.hi >> 4),
            hex_nyb(self.hi & 0x0f),
            b':',
            hex_nyb(self.lo >> 4),
            hex_nyb(self.lo & 0x0f),
        ];
        (slice::__from_vec(v), nil.into())
    }
}

impl TextUnmarshaler for Pair {
    fn UnmarshalText(&mut self, text: slice<byte>) -> error {
        if text.Len() != 5 || text[2] != b':' {
            return goish::errors::New("Pair: expected HH:LL form");
        }
        let (h_hi, ok1) = unhex(text[0]);
        let (h_lo, ok2) = unhex(text[1]);
        let (l_hi, ok3) = unhex(text[3]);
        let (l_lo, ok4) = unhex(text[4]);
        if !ok1 || !ok2 || !ok3 || !ok4 {
            return goish::errors::New("Pair: invalid hex digit");
        }
        self.hi = (h_hi << 4) | h_lo;
        self.lo = (l_hi << 4) | l_lo;
        nil.into()
    }
}

impl TextAppender for Pair {
    fn AppendText(
        &self,
        b: slice<byte>,
    ) -> (slice<byte>, error) {
        let mut v: alloc::vec::Vec<byte> = b.__into_vec();
        v.push(hex_nyb(self.hi >> 4));
        v.push(hex_nyb(self.hi & 0x0f));
        v.push(b':');
        v.push(hex_nyb(self.lo >> 4));
        v.push(hex_nyb(self.lo & 0x0f));
        (slice::__from_vec(v), nil.into())
    }
}

// Generic write helpers — proves the traits are usable as bounds.
fn marshal_bin<T: BinaryMarshaler>(t: &T) -> slice<byte> {
    let (b, _err) = t.MarshalBinary();
    b
}

fn marshal_text<T: TextMarshaler>(t: &T) -> slice<byte> {
    let (b, _err) = t.MarshalText();
    b
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. BinaryMarshaler — round-trip via MarshalBinary + UnmarshalBinary.
    {
        let p = Pair { hi: 0xAB, lo: 0xCD };
        let bin = marshal_bin(&p);
        let mut q = Pair { hi: 0, lo: 0 };
        let err = q.UnmarshalBinary(bin);
        if err.IsNil() && q.hi == 0xAB && q.lo == 0xCD {
            fmt::Println!("[ 1] BinaryMarshaler RT         PASS");
        } else {
            fmt::Println!("[ 1] BinaryMarshaler RT         FAIL");
            failed += 1;
        }
    }

    // 2. TextMarshaler — round-trip via MarshalText + UnmarshalText.
    {
        let p = Pair { hi: 0xAB, lo: 0xCD };
        let text = marshal_text(&p);
        let want_text: alloc::vec::Vec<byte> =
            alloc::vec![b'A', b'B', b':', b'C', b'D'];
        let text_v: alloc::vec::Vec<byte> = text.clone().__into_vec();
        if text_v != want_text {
            fmt::Println!("[ 2] TextMarshaler RT          FAIL marshal");
            failed += 1;
        } else {
            let mut q = Pair { hi: 0, lo: 0 };
            let err = q.UnmarshalText(text);
            if err.IsNil() && q.hi == 0xAB && q.lo == 0xCD {
                fmt::Println!("[ 2] TextMarshaler RT           PASS");
            } else {
                fmt::Println!("[ 2] TextMarshaler RT           FAIL unmarshal");
                failed += 1;
            }
        }
    }

    // 3. BinaryAppender — appends to existing buffer (does not clear).
    {
        let prefix: slice<byte> =
            slice::__from_vec(alloc::vec![b'>', b' ']);
        let p = Pair { hi: 0x12, lo: 0x34 };
        let (out, err) = p.AppendBinary(prefix);
        let want: alloc::vec::Vec<byte> =
            alloc::vec![b'>', b' ', 0x12, 0x34];
        let out_v: alloc::vec::Vec<byte> = out.__into_vec();
        if err.IsNil() && out_v == want {
            fmt::Println!("[ 3] BinaryAppender             PASS");
        } else {
            fmt::Println!("[ 3] BinaryAppender             FAIL");
            failed += 1;
        }
    }

    // 4. TextAppender — appends textual form.
    {
        let prefix: slice<byte> =
            slice::__from_vec(alloc::vec![b'k', b'=']);
        let p = Pair { hi: 0xAB, lo: 0xCD };
        let (out, err) = p.AppendText(prefix);
        let want: alloc::vec::Vec<byte> = alloc::vec![
            b'k', b'=', b'A', b'B', b':', b'C', b'D'
        ];
        let out_v: alloc::vec::Vec<byte> = out.__into_vec();
        if err.IsNil() && out_v == want {
            fmt::Println!("[ 4] TextAppender               PASS");
        } else {
            fmt::Println!("[ 4] TextAppender               FAIL");
            failed += 1;
        }
    }

    // 5. UnmarshalBinary — wrong-length input returns an error.
    {
        let bad: slice<byte> = slice::__from_vec(alloc::vec![0xAA]);
        let mut p = Pair { hi: 0, lo: 0 };
        let err = p.UnmarshalBinary(bad);
        if !err.IsNil() {
            fmt::Println!("[ 5] UnmarshalBinary error path PASS");
        } else {
            fmt::Println!("[ 5] UnmarshalBinary error path FAIL");
            failed += 1;
        }
    }

    // 6. UnmarshalText — wrong format returns an error.
    {
        let bad: slice<byte> = slice::__from_vec(alloc::vec![
            b'A', b'B', b'-', b'C', b'D'
        ]);
        let mut p = Pair { hi: 0, lo: 0 };
        let err = p.UnmarshalText(bad);
        if !err.IsNil() {
            fmt::Println!("[ 6] UnmarshalText error path   PASS");
        } else {
            fmt::Println!("[ 6] UnmarshalText error path   FAIL");
            failed += 1;
        }
    }

    // 7. AppendBinary(nil) ≡ MarshalBinary (Go contract from
    //    encoding.go:40–41).
    {
        let p = Pair { hi: 0x42, lo: 0x99 };
        let (m, _) = p.MarshalBinary();
        let (a, _) = p.AppendBinary(slice::new());
        if m.__into_vec() == a.__into_vec() {
            fmt::Println!("[ 7] AppendBinary(nil)≡Marshal  PASS");
        } else {
            fmt::Println!("[ 7] AppendBinary(nil)≡Marshal  FAIL");
            failed += 1;
        }
    }

    // 8. AppendText(nil) ≡ MarshalText (encoding.go:70–71).
    {
        let p = Pair { hi: 0x42, lo: 0x99 };
        let (m, _) = p.MarshalText();
        let (a, _) = p.AppendText(slice::new());
        if m.__into_vec() == a.__into_vec() {
            fmt::Println!("[ 8] AppendText(nil)≡Marshal    PASS");
        } else {
            fmt::Println!("[ 8] AppendText(nil)≡Marshal    FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 8/8");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 8");
        syscall::Exit(1);
    }
}
