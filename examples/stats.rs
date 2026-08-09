// M11b-A convergence: ParseFloat + FormatFloat (slow path port).
//
//   $ printf '1.5\n2.5\n10\n0.001\n' | stats
//   count: 4
//   sum:   14.001
//   mean:  3.50025
//   min:   0.001
//   max:   10

#![no_std]
#![no_main]

use goish::fmt;
use goish::{bufio, float64, int, nil, os, strconv};

#[goish::main]
fn main() {
    let mut sc = bufio::NewScanner(os::Stdin());
    let mut n: int = 0;
    let mut sum: float64 = 0.0;
    let mut min_v: float64 = float64::INFINITY;
    let mut max_v: float64 = float64::NEG_INFINITY;
    while sc.Scan() {
        let (v, err) = strconv::ParseFloat(sc.Text(), 64);
        if err != nil {
            continue;
        }
        n += 1;
        sum += v;
        if v < min_v {
            min_v = v;
        }
        if v > max_v {
            max_v = v;
        }
    }
    if n == 0 {
        fmt::Println!("(no numbers)");
        return;
    }
    fmt::Printf!("count: %d\n", n);
    fmt::Printf!("sum:   %g\n", sum);
    fmt::Printf!("mean:  %g\n", sum / (n as float64));
    fmt::Printf!("min:   %g\n", min_v);
    fmt::Printf!("max:   %g\n", max_v);
}
