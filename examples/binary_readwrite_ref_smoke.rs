// binary_readwrite_ref_smoke — encoding/binary against a running Go.
// (encoding/binary/binary.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the vectors
// are the output of `tools/gen_binary_ref.go` run in `package
// binary_test` by `scripts/goref.sh`.
//
// `binary.Read` and `binary.Write` are the whole point of the package.
// goish's were STUBS — generic over any `T`, ignoring all three
// arguments, returning nil:
//
//     pub fn Write<W, O, T>(_w: W, _order: O, _data: T) -> error {
//         let _ = (_w, _order, _data);
//         crate::errors::nil
//     }
//
// A caller writing a protocol header got success and an empty stream,
// which is indistinguishable from a correct write of nothing. Reading
// left the destination untouched and also said nil.
//
// `ByteOrder` was a one-method tag — `IsBigEndian() bool` — that no Go
// code can use and that the stubs did not consult either, so an order
// could not be passed as a parameter at all. `NativeEndian`,
// `binary.Size`, `Append`, `Encode` and `Decode` did not exist.
//
// Where Go decides a value's wire size at run time by reflecting over
// it, goish decides at compile time through a `Fixed` trait. The
// consequence is a better error: a type with no fixed-width encoding
// does not build, where Go returns "binary.Write: some values are not
// fixed-sized in type T" at run time and `binary.Size` returns -1.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::bytes;
use goish::encoding::binary::{self, BigEndian, ByteOrder, LittleEndian, NativeEndian};
use goish::gostring::string;
use goish::types::{byte, int};
use goish::{fmt, slice, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

// go: none — goish idiom: the smokes print one PASS/FAIL line per
//     numbered check; this is that line, hoisted.
fn report(failed: &mut int, ok: bool, n: &str, what: &str) {
    if ok {
        fmt::Println!("[", n, "]", what, "PASS");
    } else {
        fmt::Println!("[", n, "]", what, "FAIL");
        *failed += 1;
    }
}

// go: none — goish idiom: compare one rendering against Go's and say
//     what differed.
fn eq(ok: &mut bool, what: &str, got: string, want: &str) {
    if got != s(want) {
        fmt::Println!(
            "   ",
            s(what),
            "got",
            fmt::Sprintf!("%q", got),
            "want",
            s(want)
        );
        *ok = false;
    }
}

fn show(b: &[byte]) -> string {
    let v: slice<byte> = slice::__from_vec(b.to_vec());
    return fmt::Sprintf!("%v", v);
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. The ByteOrder interface, callable as an interface. Go:
    //    put16 big [1 2] / little [2 1]; get big 258, little 513;
    //    NativeEndian is little-endian on this target and names itself.
    {
        let mut ok = true;
        let mut b = [0u8; 8];
        ByteOrder::PutUint16(BigEndian, &mut b, 0x0102);
        eq(&mut ok, "put16 big", show(&b[..2]), "[1 2]");
        ByteOrder::PutUint32(BigEndian, &mut b, 0x0102_0304);
        eq(&mut ok, "put32 big", show(&b[..4]), "[1 2 3 4]");
        ByteOrder::PutUint64(BigEndian, &mut b, 0x0102_0304_0506_0708);
        eq(&mut ok, "put64 big", show(&b[..8]), "[1 2 3 4 5 6 7 8]");
        ByteOrder::PutUint16(LittleEndian, &mut b, 0x0102);
        eq(&mut ok, "put16 little", show(&b[..2]), "[2 1]");
        ByteOrder::PutUint64(LittleEndian, &mut b, 0x0102_0304_0506_0708);
        eq(&mut ok, "put64 little", show(&b[..8]), "[8 7 6 5 4 3 2 1]");
        ByteOrder::PutUint64(NativeEndian, &mut b, 0x0102_0304_0506_0708);
        eq(&mut ok, "put64 native", show(&b[..8]), "[8 7 6 5 4 3 2 1]");
        if ByteOrder::Uint16(BigEndian, &[1, 2]) != 258
            || ByteOrder::Uint32(BigEndian, &[1, 2, 3, 4]) != 16_909_060
            || ByteOrder::Uint64(BigEndian, &[1, 2, 3, 4, 5, 6, 7, 8]) != 72_623_859_790_382_856
        {
            ok = false;
        }
        if ByteOrder::Uint16(LittleEndian, &[1, 2]) != 513
            || ByteOrder::Uint32(LittleEndian, &[1, 2, 3, 4]) != 67_305_985
            || ByteOrder::Uint64(LittleEndian, &[1, 2, 3, 4, 5, 6, 7, 8]) != 578_437_695_752_307_201
        {
            ok = false;
        }
        // Go: str="BigEndian" / "LittleEndian" / "NativeEndian".
        eq(
            &mut ok,
            "String big",
            ByteOrder::String(BigEndian),
            "BigEndian",
        );
        eq(
            &mut ok,
            "String little",
            ByteOrder::String(LittleEndian),
            "LittleEndian",
        );
        eq(
            &mut ok,
            "String native",
            ByteOrder::String(NativeEndian),
            "NativeEndian",
        );
        report(
            &mut failed,
            ok,
            " 1",
            "ByteOrder is Go's interface, not a tag",
        );
    }

    // 2. Size, for every fixed-size shape. Go: 1 1 2 2 4 4 8 8 4 8 1,
    //    and 12 for a []int32 of three.
    {
        let mut ok = true;
        let want: [int; 11] = [1, 1, 2, 2, 4, 4, 8, 8, 4, 8, 1];
        let got: [int; 11] = [
            binary::Size(&(-1i8)),
            binary::Size(&1u8),
            binary::Size(&(-2i16)),
            binary::Size(&2u16),
            binary::Size(&(-3i32)),
            binary::Size(&3u32),
            binary::Size(&(-4i64)),
            binary::Size(&4u64),
            binary::Size(&1.5f32),
            binary::Size(&(-2.5f64)),
            binary::Size(&true),
        ];
        let mut i = 0usize;
        while i < want.len() {
            if got[i] != want[i] {
                ok = false;
            }
            i += 1;
        }
        let i32s: slice<i32> = goish::slice!([]i32{1, 2, 3});
        if binary::Size(&i32s) != 12 {
            ok = false;
        }
        report(&mut failed, ok, " 2", "Size knows every fixed width");
    }

    // 3. Write then Read, every scalar, both orders — byte for byte
    //    against Go's stream. This is the check the stubs could never
    //    have passed: they wrote nothing.
    {
        let mut ok = true;
        // Go: wrote big len=43 [...]
        let want_big = "[255 1 255 254 0 2 255 255 255 253 0 0 0 3 255 255 255 255 255 255 255 252 0 0 0 0 0 0 0 4 63 192 0 0 192 4 0 0 0 0 0 0 1]";
        let want_little = "[255 1 254 255 2 0 253 255 255 255 3 0 0 0 252 255 255 255 255 255 255 255 4 0 0 0 0 0 0 0 0 0 192 63 0 0 0 0 0 0 4 192 1]";
        for (nm, big, want) in [("big", true, want_big), ("little", false, want_little)] {
            let mut buf = bytes::Buffer::new();
            macro_rules! w {
                ($v:expr) => {{
                    let e = if big {
                        binary::Write(&mut buf, BigEndian, &$v)
                    } else {
                        binary::Write(&mut buf, LittleEndian, &$v)
                    };
                    if !e.IsNil() {
                        ok = false;
                    }
                }};
            }
            w!(-1i8);
            w!(1u8);
            w!(-2i16);
            w!(2u16);
            w!(-3i32);
            w!(3u32);
            w!(-4i64);
            w!(4u64);
            w!(1.5f32);
            w!(-2.5f64);
            w!(true);
            let all = buf.Bytes();
            if all.len() != 43 {
                ok = false;
            }
            eq(&mut ok, nm, fmt::Sprintf!("%v", all.clone()), want);

            let mut rd = bytes::NewReader(all);
            let (mut a, mut bb, mut c, mut d): (i8, u8, i16, u16) = (0, 0, 0, 0);
            let (mut e, mut f, mut g, mut h): (i32, u32, i64, u64) = (0, 0, 0, 0);
            let (mut i, mut j, mut k): (f32, f64, bool) = (0.0, 0.0, false);
            macro_rules! r {
                ($v:expr) => {{
                    let er = if big {
                        binary::Read(&mut rd, BigEndian, &mut $v)
                    } else {
                        binary::Read(&mut rd, LittleEndian, &mut $v)
                    };
                    if !er.IsNil() {
                        ok = false;
                    }
                }};
            }
            r!(a);
            r!(bb);
            r!(c);
            r!(d);
            r!(e);
            r!(f);
            r!(g);
            r!(h);
            r!(i);
            r!(j);
            r!(k);
            // Go: read big -1 1 -2 2 -3 3 -4 4 1.5 -2.5 true
            if a != -1 || bb != 1 || c != -2 || d != 2 || e != -3 || f != 3 || g != -4 || h != 4 {
                ok = false;
            }
            if i != 1.5 || j != -2.5 || !k {
                ok = false;
            }
        }
        report(
            &mut failed,
            ok,
            " 3",
            "Write then Read round-trips every scalar",
        );
    }

    // 4. A slice travels element by element. Go: slice
    //    [0 0 0 1 255 255 255 254 0 0 0 3] and back to [1 -2 3].
    {
        let mut ok = true;
        let mut sb = bytes::Buffer::new();
        let src: slice<i32> = goish::slice!([]i32{1, -2, 3});
        if !binary::Write(&mut sb, BigEndian, &src).IsNil() {
            ok = false;
        }
        eq(
            &mut ok,
            "slice",
            fmt::Sprintf!("%v", sb.Bytes()),
            "[0 0 0 1 255 255 255 254 0 0 0 3]",
        );
        let mut out: slice<i32> = goish::make!([]i32, 3);
        let mut rd = bytes::NewReader(sb.Bytes());
        if !binary::Read(&mut rd, BigEndian, &mut out).IsNil() {
            ok = false;
        }
        eq(&mut ok, "sliceback", fmt::Sprintf!("%v", out), "[1 -2 3]");
        report(
            &mut failed,
            ok,
            " 4",
            "a slice round-trips element by element",
        );
    }

    // 5. A short read is Go's two different errors: io.EOF when nothing
    //    at all was there, io.ErrUnexpectedEOF when the read stopped
    //    part way. Go: short 0 err=EOF, 1 and 3 err=unexpected EOF.
    {
        let mut ok = true;
        for (n, want) in [
            (0usize, "EOF"),
            (1, "unexpected EOF"),
            (3, "unexpected EOF"),
        ] {
            let z: slice<byte> = slice::__from_vec(alloc::vec![0u8; n]);
            let mut r = bytes::NewReader(z);
            let mut v: i32 = 0;
            let e = binary::Read(&mut r, BigEndian, &mut v);
            if e.IsNil() {
                fmt::Println!("    short", n as int, "returned nil");
                ok = false;
            } else {
                eq(&mut ok, "short", e.Error(), want);
            }
        }
        report(
            &mut failed,
            ok,
            " 5",
            "a short read says which kind of short",
        );
    }

    // 6. Append, Encode and Decode. Go: Append [255 255 255 254];
    //    Encode n=4; Decode n=4 v=-2; and Encode into a buffer that is
    //    too small is n=0 with "buffer too small", writing nothing.
    {
        let mut ok = true;
        let (ap, ae) = binary::Append(slice::new(), BigEndian, &(-2i32));
        if !ae.IsNil() {
            ok = false;
        }
        eq(
            &mut ok,
            "Append",
            fmt::Sprintf!("%v", ap),
            "[255 255 255 254]",
        );
        let mut enc: slice<byte> = goish::make!([]byte, 4);
        let (n, e) = binary::Encode(&mut enc, BigEndian, &(-2i32));
        if n != 4 || !e.IsNil() {
            ok = false;
        }
        eq(
            &mut ok,
            "Encode",
            fmt::Sprintf!("%v", enc.clone()),
            "[255 255 255 254]",
        );
        let mut dv: i32 = 0;
        let (n2, e2) = binary::Decode(&enc, BigEndian, &mut dv);
        if n2 != 4 || !e2.IsNil() || dv != -2 {
            ok = false;
        }
        let mut small: slice<byte> = goish::make!([]byte, 2);
        let (n3, e3) = binary::Encode(&mut small, BigEndian, &(-2i32));
        if n3 != 0 {
            ok = false;
        }
        eq(&mut ok, "Encode-short", e3.Error(), "buffer too small");
        // Go: "does not write to buf".
        eq(&mut ok, "untouched", fmt::Sprintf!("%v", small), "[0 0]");
        report(
            &mut failed,
            ok,
            " 6",
            "Append/Encode/Decode, and the short buffer",
        );
    }

    // 7. Floats travel as their IEEE-754 bit pattern, so a NaN keeps
    //    the payload it had. Go: f32=[63 192 0 0] f64=[192 4 0 0 0 0 0 0]
    //    nan32=[127 192 0 0].
    {
        let mut ok = true;
        let (f1, _) = binary::Append(slice::new(), BigEndian, &1.5f32);
        let (f2, _) = binary::Append(slice::new(), BigEndian, &(-2.5f64));
        let (f3, _) = binary::Append(slice::new(), BigEndian, &f32::NAN);
        eq(&mut ok, "f32", fmt::Sprintf!("%v", f1), "[63 192 0 0]");
        eq(
            &mut ok,
            "f64",
            fmt::Sprintf!("%v", f2),
            "[192 4 0 0 0 0 0 0]",
        );
        eq(&mut ok, "nan32", fmt::Sprintf!("%v", f3), "[127 192 0 0]");
        report(&mut failed, ok, " 7", "a float is its bit pattern");
    }

    if failed == 0 {
        fmt::Println!("ok 7/7");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 7");
        syscall::Exit(1);
    }
}
