// encoding/gob: the wire primitives.
//
// gob's compactness is entirely in two integer encodings, and they are
// worth reading once. An unsigned value below 128 is ONE byte. Anything
// larger is a length byte carrying the NEGATED byte count, then that
// many big-endian bytes — so 0x80 is `ff 80` and 0x100 is `fe 01 00`.
// A signed value folds into an unsigned one by shifting left and, when
// negative, COMPLEMENTING rather than negating: -1 encodes as 1, -2 as
// 3. Floats are sent byte-REVERSED so that a whole number, whose
// mantissa is zeros, ends in zeros the length prefix can drop.
//
// 88 rows from Go 1.25.5 (`scripts/goref.sh encoding/gob`).
//
// WHAT IS NOT HERE. Nothing in encoding/gob above these primitives is
// ported, and it is blocked twice over:
//
//   * the encOp/decOp ENGINES walk a reflect.Value and the decoder
//     WRITES through it. goish's reflect::Value is a read-only deep
//     clone, and there is no Implements/CanAddr/Addr, so GobEncoder and
//     GobDecoder dispatch cannot be expressed either.
//   * gob signals every internal error by PANICKING with a gobError and
//     recovering at the top of Encode/Decode. goish's `recover!()`
//     observes a panic but does not stop it, so `decodeUint`,
//     `decodeInt`, `getLength` and `float32FromBits` — which are
//     otherwise pure — cannot be ported faithfully either.
//
// So this smoke pins primitives NOTHING IN THE TREE CALLS YET. That is
// said out loud rather than left for a reader to discover from a green
// 88/88.
//
// WHAT THE ROWS ARE FOR:
//
//   * encodeUint at every byte-length boundary, both sides — 0x7f/0x80,
//     0xff/0x100, and each 0xff..ff / 0x1..00 pair up to 2^64-1. The
//     length byte is computed from LeadingZeros64, so a wrong shift is
//     invisible except exactly at a boundary.
//   * encodeInt at the fold boundaries: 63/64 and -64/-65 are where the
//     shifted value crosses 0x7f.
//   * floatBits over -0, both infinities, a NaN WITH A PAYLOAD, the
//     largest normal and the smallest subnormal — the byte reversal has
//     to be exact, and a round trip through float64FromBits has to give
//     the same bit pattern back, payload included.
//   * decodeUintReader's width, which is not "bytes consumed": an empty
//     reader reports width 1 with io.EOF because the width is set
//     BEFORE the read; a truncated 8-byte value reports the SHORT read
//     count (3, for three bytes of eight) with io.ErrUnexpectedEOF; a
//     length byte claiming nine bytes is errBadUint, not a short read;
//     and only the success path adds the +1 for the length byte.
//   * decBuffer.Read returning EOF only when it copied NOTHING AND the
//     caller asked for something — a zero-length read of an exhausted
//     buffer is (0, nil).
//   * decBuffer.Len and Bytes being about what is LEFT, so every row
//     records both after every operation.
//   * toInt over the values that distinguish complement from negate.
#![no_std]
#![no_main]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
extern crate alloc;
extern crate goish;

use goish::encoding::gob;
use goish::fmt;
use goish::gostring::string;
use goish::types::int;

static mut PASS: int = 0;
static mut FAIL: int = 0;

// go: none
fn unhex(h: &str) -> alloc::vec::Vec<u8> {
    let b = h.as_bytes();
    let mut out = alloc::vec::Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i + 1 < b.len() {
        // go: none
        fn nib(c: u8) -> u8 {
            if c >= b'0' && c <= b'9' {
                return c - b'0';
            }
            return c - b'a' + 10;
        }
        out.push(nib(b[i]) * 16 + nib(b[i + 1]));
        i += 2;
    }
    return out;
}

// go: none
fn ck(idx: int, name: &'static str, got: string, want: string) {
    unsafe {
        if got == want {
            PASS += 1;
        } else {
            FAIL += 1;
            fmt::Printf!(
                "FAIL %v %s\n     got  %s\n     want %s\n",
                idx,
                name,
                got.clone(),
                want.clone()
            );
        }
    }
}

// go: none
fn eurow(idx: int, name: &'static str, x: u64, want: &'static str) {
    let mut st = gob::encoderState::new();
    st.encodeUint(x);
    ck(
        idx,
        name,
        goish::encoding::hex::EncodeToString(&st.b.Bytes()),
        string::from_static(want),
    );
}

// go: none
fn eirow(idx: int, name: &'static str, i: i64, want: &'static str) {
    let mut st = gob::encoderState::new();
    st.encodeInt(i);
    ck(
        idx,
        name,
        goish::encoding::hex::EncodeToString(&st.b.Bytes()),
        string::from_static(want),
    );
}

// go: none — floatBits of the value whose BITS are `bits`, and the
// round trip back. Both sides are hex so a NaN payload is visible.
fn fbrow(idx: int, name: &'static str, bits: u64, wu: &'static str, wback: &'static str) {
    let f = goish::math::Float64frombits(bits);
    let u = gob::floatBits(f);
    let back = goish::math::Float64bits(gob::float64FromBits(u));
    ck(
        idx,
        name,
        fmt::Sprintf!("%016x|%016x", u, back),
        string::from_static(wu) + string::from_static("|") + string::from_static(wback),
    );
}

// go: none
fn durrow(idx: int, name: &'static str, data: &'static str, wx: u64, ww: int, werr: &'static str) {
    let mut r = goish::bytes::NewReader(goish::slice::__from_vec(unhex(data)));
    let mut buf: goish::slice<goish::byte> =
        goish::slice::__from_vec(alloc::vec![0u8; 8]);
    let (x, w, err) = gob::decodeUintReader(&mut r, &mut buf);
    let goterr = if err == goish::errors::nil {
        string::from_static("")
    } else {
        err.Error()
    };
    ck(
        idx,
        name,
        fmt::Sprintf!("%v|%v|%s", x, w, goterr),
        fmt::Sprintf!("%v|%v|%s", wx, ww, string::from_bytes(werr.as_bytes())),
    );
}

// go: none
fn ebrow(idx: int, name: &'static str, ops: &[&str], wout: &'static str, wtrace: &'static str) {
    let mut e = gob::encBuffer::new();
    let mut trace = string::from_static("");
    for op in ops.iter() {
        match *op {
            "wb" => e.writeByte(b'A'),
            "w" => {
                let (n, _) = e.Write(goish::slice!([]goish::byte{1u8, 2u8, 3u8}));
                trace = trace + fmt::Sprintf!("w=%v ", n);
            }
            "ws" => e.WriteString("xy"),
            "reset" => e.Reset(),
            _ => {}
        }
        trace = trace + fmt::Sprintf!("len=%v ", e.Len());
    }
    ck(
        idx,
        name,
        goish::encoding::hex::EncodeToString(&e.Bytes()) + string::from_static("|") + trace,
        string::from_static(wout)
            + string::from_static("|")
            + string::from_static(wtrace)
            + string::from_static(" "),
    );
}

// go: none
fn dbrow(idx: int, name: &'static str, data: &'static str, ops: &[&str], wtrace: &'static str) {
    let mut d = gob::decBuffer::new();
    d.SetBytes(goish::slice::__from_vec(unhex(data)));
    let mut trace = string::from_static("");
    for op in ops.iter() {
        match *op {
            "rb" => {
                let (c, err) = d.ReadByte();
                if err != goish::errors::nil {
                    trace = trace + string::from_static("rb=EOF ");
                } else {
                    trace = trace + fmt::Sprintf!("rb=%v ", c);
                }
            }
            "read3" => {
                let mut p = [0u8; 3];
                let (n, err) = d.Read(&mut p);
                let es = if err == goish::errors::nil {
                    string::from_static("nil")
                } else {
                    err.Error()
                };
                trace = trace
                    + fmt::Sprintf!(
                        "read=%v,%s,%s ",
                        n,
                        goish::encoding::hex::EncodeToString(&p[..n as usize]),
                        es
                    );
            }
            "read0" => {
                let mut p: [u8; 0] = [];
                let (n, err) = d.Read(&mut p);
                let es = if err == goish::errors::nil {
                    string::from_static("nil")
                } else {
                    err.Error()
                };
                trace = trace + fmt::Sprintf!("read0=%v,%s ", n, es);
            }
            "drop1" => d.Drop(1),
            "reset" => d.Reset(),
            _ => {}
        }
        trace = trace
            + fmt::Sprintf!(
                "len=%v,bytes=%s ",
                d.Len(),
                goish::encoding::hex::EncodeToString(&d.Bytes())
            );
    }
    ck(
        idx,
        name,
        trace,
        string::from_static(wtrace) + string::from_static(" "),
    );
}

// go: none
fn tirow(idx: int, x: u64, want: i64) {
    ck(
        idx,
        "toInt",
        fmt::Sprintf!("%v", gob::decoder::toInt(x)),
        fmt::Sprintf!("%v", want),
    );
}

// go: none
fn tbrow(idx: int, want: i64) {
    ck(
        idx,
        "tooBig",
        fmt::Sprintf!("%v", gob::decoder::tooBig),
        fmt::Sprintf!("%v", want),
    );
}

// go: none
fn strrow(idx: int, name: &'static str, got: string, want: &'static str) {
    ck(idx, name, got, string::from_bytes(want.as_bytes()));
}

#[goish::main]
fn main() {
    eurow(0, "0", 0u64, "00");
    eurow(1, "1", 1u64, "01");
    eurow(2, "0x7e", 126u64, "7e");
    eurow(3, "0x7f", 127u64, "7f");
    eurow(4, "0x80", 128u64, "ff80");
    eurow(5, "0xff", 255u64, "ffff");
    eurow(6, "0x100", 256u64, "fe0100");
    eurow(7, "0xffff", 65535u64, "feffff");
    eurow(8, "0x10000", 65536u64, "fd010000");
    eurow(9, "0xffffff", 16777215u64, "fdffffff");
    eurow(10, "0x1000000", 16777216u64, "fc01000000");
    eurow(11, "0xffffffff", 4294967295u64, "fcffffffff");
    eurow(12, "0x100000000", 4294967296u64, "fb0100000000");
    eurow(13, "0xffffffffff", 1099511627775u64, "fbffffffffff");
    eurow(14, "0xffffffffffff", 281474976710655u64, "faffffffffffff");
    eurow(15, "0xffffffffffffff", 72057594037927935u64, "f9ffffffffffffff");
    eurow(16, "0x100000000000000", 72057594037927936u64, "f80100000000000000");
    eurow(17, "max", 18446744073709551615u64, "f8ffffffffffffffff");
    eurow(18, "1<<63", 9223372036854775808u64, "f88000000000000000");
    eirow(19, "0", 0i64, "00");
    eirow(20, "1", 1i64, "02");
    eirow(21, "-1", -1i64, "01");
    eirow(22, "63", 63i64, "7e");
    eirow(23, "64", 64i64, "ff80");
    eirow(24, "-64", -64i64, "7f");
    eirow(25, "-65", -65i64, "ff81");
    eirow(26, "127", 127i64, "fffe");
    eirow(27, "-128", -128i64, "ffff");
    eirow(28, "32767", 32767i64, "fefffe");
    eirow(29, "-32768", -32768i64, "feffff");
    eirow(30, "maxint32", 2147483647i64, "fcfffffffe");
    eirow(31, "minint32", -2147483648i64, "fcffffffff");
    eirow(32, "maxint64", 9223372036854775807i64, "f8fffffffffffffffe");
    eirow(33, "minint64", -9223372036854775808i64, "f8ffffffffffffffff");
    fbrow(34, "0", 0x0000000000000000_u64, "0000000000000000", "0000000000000000");
    fbrow(35, "-0", 0x8000000000000000_u64, "0000000000000080", "8000000000000000");
    fbrow(36, "1", 0x3ff0000000000000_u64, "000000000000f03f", "3ff0000000000000");
    fbrow(37, "-1", 0xbff0000000000000_u64, "000000000000f0bf", "bff0000000000000");
    fbrow(38, "0.5", 0x3fe0000000000000_u64, "000000000000e03f", "3fe0000000000000");
    fbrow(39, "pi", 0x400921fb54442d18_u64, "182d4454fb210940", "400921fb54442d18");
    fbrow(40, "max", 0x7fefffffffffffff_u64, "ffffffffffffef7f", "7fefffffffffffff");
    fbrow(41, "smallest", 0x0000000000000001_u64, "0100000000000000", "0000000000000001");
    fbrow(42, "inf", 0x7ff0000000000000_u64, "000000000000f07f", "7ff0000000000000");
    fbrow(43, "-inf", 0xfff0000000000000_u64, "000000000000f0ff", "fff0000000000000");
    fbrow(44, "nan", 0x7ff8000000000001_u64, "010000000000f87f", "7ff8000000000001");
    durrow(45, "empty", "", 0u64, 1, "EOF");
    durrow(46, "zero", "00", 0u64, 1, "");
    durrow(47, "0x7f", "7f", 127u64, 1, "");
    durrow(48, "0x80", "80", 0u64, 1, "gob: encoded unsigned integer out of range");
    durrow(49, "n1", "ff2a", 42u64, 2, "");
    durrow(50, "n1-trunc", "ff", 0u64, 0, "unexpected EOF");
    durrow(51, "n8", "f80102030405060708", 72623859790382856u64, 9, "");
    durrow(52, "n8-trunc", "f8010203", 0u64, 3, "unexpected EOF");
    durrow(53, "n9", "f7010203040506070809", 0u64, 1, "gob: encoded unsigned integer out of range");
    durrow(54, "n2", "fe0100", 256u64, 3, "");
    durrow(55, "trailing", "2affff", 42u64, 1, "");
    ebrow(56, "wb", &["wb","wb"], "4141", "len=1 len=2");
    ebrow(57, "write", &["w","w"], "010203010203", "w=3 len=3 w=3 len=6");
    ebrow(58, "mixed", &["wb","w","ws"], "410102037879", "len=1 w=3 len=4 len=6");
    ebrow(59, "reset", &["wb","w","reset","wb"], "41", "len=1 w=3 len=4 len=0 len=1");
    dbrow(60, "empty", "", &["rb","read3","read0"], "rb=EOF len=0,bytes= read=0,,EOF len=0,bytes= read0=0,nil len=0,bytes=");
    dbrow(61, "read", "0102030405", &["rb","read3","rb","rb"], "rb=1 len=4,bytes=02030405 read=3,020304,nil len=1,bytes=05 rb=5 len=0,bytes= rb=EOF len=0,bytes=");
    dbrow(62, "drop", "0102030405", &["drop1","drop1","read3"], "len=4,bytes=02030405 len=3,bytes=030405 read=3,030405,nil len=0,bytes=");
    dbrow(63, "reset", "010203", &["rb","reset","rb"], "rb=1 len=2,bytes=0203 len=0,bytes= rb=EOF len=0,bytes=");
    dbrow(64, "read0-nonempty", "0102", &["read0"], "read0=0,nil len=2,bytes=0102");
    tirow(65, 0u64, 0i64);
    tirow(66, 1u64, -1i64);
    tirow(67, 2u64, 1i64);
    tirow(68, 3u64, -2i64);
    tirow(69, 4u64, 2i64);
    tirow(70, 5u64, -3i64);
    tirow(71, 126u64, 63i64);
    tirow(72, 127u64, -64i64);
    tirow(73, 128u64, 64i64);
    tirow(74, 255u64, -128i64);
    tirow(75, 4294967294u64, 2147483647i64);
    tirow(76, 4294967295u64, -2147483648i64);
    tirow(77, 4611686018427387904u64, 2305843009213693952i64);
    tirow(78, 9223372036854775808u64, 4611686018427387904i64);
    tirow(79, 18446744073709551615u64, -9223372036854775808i64);
    tirow(80, 18446744073709551614u64, 9223372036854775807i64);
    tbrow(81, 8589934592);
    strrow(82, "errBadCount", gob::decoder::errBadCount().Error(), "invalid message length");
    strrow(83, "overflow", gob::decode::overflow("int8").Error(), "value for \"int8\" out of range");
    strrow(84, "errBadUint", gob::decode::errBadUint().Error(), "gob: encoded unsigned integer out of range");
    strrow(85, "errBadType", gob::decode::errBadType().Error(), "gob: unknown type id or corrupted data");
    strrow(86, "errRange", gob::decode::errRange().Error(), "gob: bad data: field numbers out of bounds");
    strrow(87, "ErrUnexpectedEOF", { let e: goish::error = goish::io::ErrUnexpectedEOF.into(); e.Error() }, "unexpected EOF");
    unsafe {
        let (pass, fail) = (PASS, FAIL);
        if pass + fail != 88 {
            fmt::Printf!("FAIL ran %v rows, expected 88\n", pass + fail);
            FAIL += 1;
        }
        let fail = FAIL;
        fmt::Printf!("gob_wire_ref_smoke: %v checks, %v failed\n", pass + fail, fail);
        if fail > 0 {
            goish::syscall::Exit(1);
        }
    }
}
