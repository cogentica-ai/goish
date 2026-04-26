// Multiprecision decimal numbers — port of Go 1.25 src/strconv/decimal.go.
//
// For floating-point formatting only; not general purpose.
// Only operations are assign and (binary) left/right shift.
// Can do binary floating point in multiprecision decimal precisely
// because 2 divides 10; cannot do decimal floating point in
// multiprecision binary precisely.

#![allow(non_snake_case, non_camel_case_types, dead_code)]

extern crate alloc;
use alloc::vec::Vec;

use crate::gostring::string;
use crate::types::byte;

#[derive(Clone)]
pub(crate) struct decimal {
    pub d: [byte; 800], // digits, big-endian representation
    pub nd: i32,        // number of digits used
    pub dp: i32,        // decimal point
    pub neg: bool,      // negative flag
    pub trunc: bool,    // discarded nonzero digits beyond d[:nd]
}

impl decimal {
    pub fn new() -> Self {
        Self {
            d: [0u8; 800],
            nd: 0,
            dp: 0,
            neg: false,
            trunc: false,
        }
    }

    #[allow(non_snake_case)]
    pub fn String(&self) -> string {
        let mut n = (10 + self.nd) as usize;
        if self.dp > 0 {
            n += self.dp as usize;
        }
        if self.dp < 0 {
            n += (-self.dp) as usize;
        }
        let mut buf: Vec<byte> = alloc::vec![0u8; n];
        let mut w: usize = 0;
        if self.nd == 0 {
            return string::from_static("0");
        } else if self.dp <= 0 {
            // zeros fill space between decimal point and digits
            buf[w] = b'0';
            w += 1;
            buf[w] = b'.';
            w += 1;
            w += digit_zero(&mut buf[w..w + (-self.dp) as usize]);
            let nd = self.nd as usize;
            buf[w..w + nd].copy_from_slice(&self.d[0..nd]);
            w += nd;
        } else if self.dp < self.nd {
            // decimal point in middle of digits
            let dp = self.dp as usize;
            let nd = self.nd as usize;
            buf[w..w + dp].copy_from_slice(&self.d[0..dp]);
            w += dp;
            buf[w] = b'.';
            w += 1;
            buf[w..w + nd - dp].copy_from_slice(&self.d[dp..nd]);
            w += nd - dp;
        } else {
            // zeros fill space between digits and decimal point
            let nd = self.nd as usize;
            buf[w..w + nd].copy_from_slice(&self.d[0..nd]);
            w += nd;
            w += digit_zero(&mut buf[w..w + (self.dp - self.nd) as usize]);
        }
        buf.truncate(w);
        string::__from_vec(buf)
    }

    /// Assign v to a.
    #[allow(non_snake_case)]
    pub fn Assign(&mut self, mut v: u64) {
        let mut buf = [0u8; 24];

        // Write reversed decimal in buf.
        let mut n: usize = 0;
        while v > 0 {
            let v1 = v / 10;
            v -= 10 * v1;
            buf[n] = (v + ('0' as u64)) as u8;
            n += 1;
            v = v1;
        }

        // Reverse again to produce forward decimal in self.d.
        self.nd = 0;
        let mut k = n;
        while k > 0 {
            k -= 1;
            self.d[self.nd as usize] = buf[k];
            self.nd += 1;
        }
        self.dp = self.nd;
        trim(self);
    }

    /// Binary shift left (k > 0) or right (k < 0).
    #[allow(non_snake_case)]
    pub fn Shift(&mut self, mut k: i32) {
        if self.nd == 0 {
            // nothing to do: a == 0
            return;
        }
        if k > 0 {
            while k > MAX_SHIFT as i32 {
                left_shift(self, MAX_SHIFT);
                k -= MAX_SHIFT as i32;
            }
            left_shift(self, k as u32);
        } else if k < 0 {
            while k < -(MAX_SHIFT as i32) {
                right_shift(self, MAX_SHIFT);
                k += MAX_SHIFT as i32;
            }
            right_shift(self, (-k) as u32);
        }
    }

    /// Round a to nd digits (or fewer).
    #[allow(non_snake_case)]
    pub fn Round(&mut self, nd: i32) {
        if nd < 0 || nd >= self.nd {
            return;
        }
        if should_round_up(self, nd) {
            self.RoundUp(nd);
        } else {
            self.RoundDown(nd);
        }
    }

    /// Round a down to nd digits (or fewer).
    #[allow(non_snake_case)]
    pub fn RoundDown(&mut self, nd: i32) {
        if nd < 0 || nd >= self.nd {
            return;
        }
        self.nd = nd;
        trim(self);
    }

    /// Round a up to nd digits (or fewer).
    #[allow(non_snake_case)]
    pub fn RoundUp(&mut self, nd: i32) {
        if nd < 0 || nd >= self.nd {
            return;
        }

        // round up
        let mut i = nd - 1;
        while i >= 0 {
            let c = self.d[i as usize];
            if c < b'9' {
                self.d[i as usize] += 1;
                self.nd = i + 1;
                return;
            }
            i -= 1;
        }

        // Number is all 9s. Change to single 1 with adjusted decimal point.
        self.d[0] = b'1';
        self.nd = 1;
        self.dp += 1;
    }

    /// Extract integer part, rounded appropriately.
    /// No guarantees about overflow.
    #[allow(non_snake_case)]
    pub fn RoundedInteger(&mut self) -> u64 {
        if self.dp > 20 {
            return 0xFFFFFFFFFFFFFFFFu64;
        }
        let mut i: i32 = 0;
        let mut n: u64 = 0;
        while i < self.dp && i < self.nd {
            n = n * 10 + (self.d[i as usize] - b'0') as u64;
            i += 1;
        }
        while i < self.dp {
            n *= 10;
            i += 1;
        }
        if should_round_up(self, self.dp) {
            n += 1;
        }
        n
    }
}

fn digit_zero(dst: &mut [byte]) -> usize {
    for b in dst.iter_mut() {
        *b = b'0';
    }
    dst.len()
}

/// Trim trailing zeros from number.
pub(crate) fn trim(a: &mut decimal) {
    while a.nd > 0 && a.d[(a.nd - 1) as usize] == b'0' {
        a.nd -= 1;
    }
    if a.nd == 0 {
        a.dp = 0;
    }
}

// Maximum shift that we can do in one pass without overflow.
// uint has 64 bits on amd64 (our target); we have to accommodate 9<<k.
const UINT_SIZE: u32 = 64;
const MAX_SHIFT: u32 = UINT_SIZE - 4;

/// Binary shift right (/ 2) by k bits. k <= MAX_SHIFT to avoid overflow.
fn right_shift(a: &mut decimal, k: u32) {
    let mut r: i32 = 0; // read pointer
    let mut w: i32 = 0; // write pointer

    // Pick up enough leading digits to cover first shift.
    let mut n: u64 = 0;
    loop {
        if (n >> k) != 0 {
            break;
        }
        if r >= a.nd {
            if n == 0 {
                a.nd = 0;
                return;
            }
            while (n >> k) == 0 {
                n *= 10;
                r += 1;
            }
            break;
        }
        let c = a.d[r as usize] as u64;
        n = n * 10 + c - ('0' as u64);
        r += 1;
    }
    a.dp -= r - 1;

    let mask: u64 = (1u64 << k) - 1;

    // Pick up a digit, put down a digit.
    while r < a.nd {
        let c = a.d[r as usize] as u64;
        let dig = n >> k;
        n &= mask;
        a.d[w as usize] = (dig + ('0' as u64)) as u8;
        w += 1;
        n = n * 10 + c - ('0' as u64);
        r += 1;
    }

    // Put down extra digits.
    while n > 0 {
        let dig = n >> k;
        n &= mask;
        if (w as usize) < a.d.len() {
            a.d[w as usize] = (dig + ('0' as u64)) as u8;
            w += 1;
        } else if dig > 0 {
            a.trunc = true;
        }
        n *= 10;
    }

    a.nd = w;
    trim(a);
}

// Cheat sheet for left shift: indexed by shift count giving number of
// new digits introduced by that shift. Each entry is `(delta, cutoff)`.
// `cutoff` is the leading-digits string; if a's prefix is < cutoff,
// `delta - 1` new digits are introduced instead of `delta`.
struct LeftCheat {
    delta: i32,
    cutoff: &'static [u8],
}

const LEFT_CHEATS: &[LeftCheat] = &[
    LeftCheat { delta: 0, cutoff: b"" },
    LeftCheat { delta: 1, cutoff: b"5" },
    LeftCheat { delta: 1, cutoff: b"25" },
    LeftCheat { delta: 1, cutoff: b"125" },
    LeftCheat { delta: 2, cutoff: b"625" },
    LeftCheat { delta: 2, cutoff: b"3125" },
    LeftCheat { delta: 2, cutoff: b"15625" },
    LeftCheat { delta: 3, cutoff: b"78125" },
    LeftCheat { delta: 3, cutoff: b"390625" },
    LeftCheat { delta: 3, cutoff: b"1953125" },
    LeftCheat { delta: 4, cutoff: b"9765625" },
    LeftCheat { delta: 4, cutoff: b"48828125" },
    LeftCheat { delta: 4, cutoff: b"244140625" },
    LeftCheat { delta: 4, cutoff: b"1220703125" },
    LeftCheat { delta: 5, cutoff: b"6103515625" },
    LeftCheat { delta: 5, cutoff: b"30517578125" },
    LeftCheat { delta: 5, cutoff: b"152587890625" },
    LeftCheat { delta: 6, cutoff: b"762939453125" },
    LeftCheat { delta: 6, cutoff: b"3814697265625" },
    LeftCheat { delta: 6, cutoff: b"19073486328125" },
    LeftCheat { delta: 7, cutoff: b"95367431640625" },
    LeftCheat { delta: 7, cutoff: b"476837158203125" },
    LeftCheat { delta: 7, cutoff: b"2384185791015625" },
    LeftCheat { delta: 7, cutoff: b"11920928955078125" },
    LeftCheat { delta: 8, cutoff: b"59604644775390625" },
    LeftCheat { delta: 8, cutoff: b"298023223876953125" },
    LeftCheat { delta: 8, cutoff: b"1490116119384765625" },
    LeftCheat { delta: 9, cutoff: b"7450580596923828125" },
    LeftCheat { delta: 9, cutoff: b"37252902984619140625" },
    LeftCheat { delta: 9, cutoff: b"186264514923095703125" },
    LeftCheat { delta: 10, cutoff: b"931322574615478515625" },
    LeftCheat { delta: 10, cutoff: b"4656612873077392578125" },
    LeftCheat { delta: 10, cutoff: b"23283064365386962890625" },
    LeftCheat { delta: 10, cutoff: b"116415321826934814453125" },
    LeftCheat { delta: 11, cutoff: b"582076609134674072265625" },
    LeftCheat { delta: 11, cutoff: b"2910383045673370361328125" },
    LeftCheat { delta: 11, cutoff: b"14551915228366851806640625" },
    LeftCheat { delta: 12, cutoff: b"72759576141834259033203125" },
    LeftCheat { delta: 12, cutoff: b"363797880709171295166015625" },
    LeftCheat { delta: 12, cutoff: b"1818989403545856475830078125" },
    LeftCheat { delta: 13, cutoff: b"9094947017729282379150390625" },
    LeftCheat { delta: 13, cutoff: b"45474735088646411895751953125" },
    LeftCheat { delta: 13, cutoff: b"227373675443232059478759765625" },
    LeftCheat { delta: 13, cutoff: b"1136868377216160297393798828125" },
    LeftCheat { delta: 14, cutoff: b"5684341886080801486968994140625" },
    LeftCheat { delta: 14, cutoff: b"28421709430404007434844970703125" },
    LeftCheat { delta: 14, cutoff: b"142108547152020037174224853515625" },
    LeftCheat { delta: 15, cutoff: b"710542735760100185871124267578125" },
    LeftCheat { delta: 15, cutoff: b"3552713678800500929355621337890625" },
    LeftCheat { delta: 15, cutoff: b"17763568394002504646778106689453125" },
    LeftCheat { delta: 16, cutoff: b"88817841970012523233890533447265625" },
    LeftCheat { delta: 16, cutoff: b"444089209850062616169452667236328125" },
    LeftCheat { delta: 16, cutoff: b"2220446049250313080847263336181640625" },
    LeftCheat { delta: 16, cutoff: b"11102230246251565404236316680908203125" },
    LeftCheat { delta: 17, cutoff: b"55511151231257827021181583404541015625" },
    LeftCheat { delta: 17, cutoff: b"277555756156289135105907917022705078125" },
    LeftCheat { delta: 17, cutoff: b"1387778780781445675529539585113525390625" },
    LeftCheat { delta: 18, cutoff: b"6938893903907228377647697925567626953125" },
    LeftCheat { delta: 18, cutoff: b"34694469519536141888238489627838134765625" },
    LeftCheat { delta: 18, cutoff: b"173472347597680709441192448139190673828125" },
    LeftCheat { delta: 19, cutoff: b"867361737988403547205962240695953369140625" },
];

/// Is the leading prefix of b lexicographically less than s?
fn prefix_is_less_than(b: &[byte], s: &[byte]) -> bool {
    for i in 0..s.len() {
        if i >= b.len() {
            return true;
        }
        if b[i] != s[i] {
            return b[i] < s[i];
        }
    }
    false
}

/// Binary shift left (* 2) by k bits. k <= MAX_SHIFT to avoid overflow.
fn left_shift(a: &mut decimal, k: u32) {
    let mut delta = LEFT_CHEATS[k as usize].delta;
    if prefix_is_less_than(&a.d[0..a.nd as usize], LEFT_CHEATS[k as usize].cutoff) {
        delta -= 1;
    }

    let mut r: i32 = a.nd; // read index
    let mut w: i32 = a.nd + delta; // write index

    // Pick up a digit, put down a digit.
    let mut n: u64 = 0;
    r -= 1;
    while r >= 0 {
        n += ((a.d[r as usize] - b'0') as u64) << k;
        let quo = n / 10;
        let rem = n - 10 * quo;
        w -= 1;
        if (w as usize) < a.d.len() {
            a.d[w as usize] = (rem + ('0' as u64)) as u8;
        } else if rem != 0 {
            a.trunc = true;
        }
        n = quo;
        r -= 1;
    }

    // Put down extra digits.
    while n > 0 {
        let quo = n / 10;
        let rem = n - 10 * quo;
        w -= 1;
        if (w as usize) < a.d.len() {
            a.d[w as usize] = (rem + ('0' as u64)) as u8;
        } else if rem != 0 {
            a.trunc = true;
        }
        n = quo;
    }

    a.nd += delta;
    if (a.nd as usize) >= a.d.len() {
        a.nd = a.d.len() as i32;
    }
    a.dp += delta;
    trim(a);
}

/// If we chop a at nd digits, should we round up?
fn should_round_up(a: &decimal, nd: i32) -> bool {
    if nd < 0 || nd >= a.nd {
        return false;
    }
    let nd_u = nd as usize;
    if a.d[nd_u] == b'5' && nd + 1 == a.nd {
        // exactly halfway - round to even
        if a.trunc {
            return true;
        }
        return nd > 0 && (a.d[nd_u - 1] - b'0') % 2 != 0;
    }
    a.d[nd_u] >= b'5'
}
