// math/big smoke — sign, compare, mod, exp on big.Int.

#![no_std]
#![no_main]

use goish::{int, syscall};
use goish::math::big;

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1);
}

fn check(cond: bool, msg: &[u8]) {
    if !cond { die(msg); }
}

#[goish::main]
fn main() {
    // Sign
    let zero = big::NewInt(0);
    let pos  = big::NewInt(42);
    let neg  = big::NewInt(-7);
    check(zero.Sign() == 0,  b"big: Sign(0) != 0\n");
    check(pos.Sign()  == 1,  b"big: Sign(42) != 1\n");
    check(neg.Sign()  == -1, b"big: Sign(-7) != -1\n");

    // Int64 round-trip
    check(pos.Int64() == 42, b"big: Int64(42) wrong\n");
    check(neg.Int64() == -7, b"big: Int64(-7) wrong\n");

    // Cmp
    check(pos.Cmp(&zero) == 1,  b"big: Cmp(42,0) != 1\n");
    check(zero.Cmp(&pos) == -1, b"big: Cmp(0,42) != -1\n");
    check(pos.Cmp(&pos)  == 0,  b"big: Cmp(42,42) != 0\n");
    check(neg.Cmp(&pos)  == -1, b"big: Cmp(-7,42) != -1\n");

    // Mod: 100 mod 7 = 2
    let x = big::NewInt(100);
    let y = big::NewInt(7);
    let mut z = big::Int::new();
    z.Mod(&x, &y);
    check(z.Int64() == 2, b"big: 100 mod 7 != 2\n");

    // Mod: 13 mod 5 = 3
    let x2 = big::NewInt(13);
    let y2 = big::NewInt(5);
    z.Mod(&x2, &y2);
    check(z.Int64() == 3, b"big: 13 mod 5 != 3\n");

    // Exp: 2^10 mod 1000 = 24
    let base = big::NewInt(2);
    let exp  = big::NewInt(10);
    let m    = big::NewInt(1000);
    z.Exp(&base, &exp, &m);
    check(z.Int64() == 24, b"big: 2^10 mod 1000 != 24\n");

    // Exp: 3^4 mod 100 = 81
    let base2 = big::NewInt(3);
    let exp2  = big::NewInt(4);
    let m2    = big::NewInt(100);
    z.Exp(&base2, &exp2, &m2);
    check(z.Int64() == 81, b"big: 3^4 mod 100 != 81\n");

    // SetInt64
    let mut a = big::Int::new();
    a.SetInt64(999);
    check(a.Int64() == 999, b"big: SetInt64(999) wrong\n");
    a.SetInt64(-1);
    check(a.Sign() == -1, b"big: SetInt64(-1) sign wrong\n");

    const OK: &[u8] = b"math/big: ok\n";
    syscall::Write(syscall::STDOUT, OK.as_ptr(), OK.len());
}
