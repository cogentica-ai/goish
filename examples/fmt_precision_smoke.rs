// fmt_precision_smoke — pin `%.Nf` and friends against Go 1.25.5.
//
// goish's verb scanner used to parse width but not precision, and it
// did not skip the `.N` either: `%.2f` consumed the argument as a bare
// `%` and then emitted the `f` as a literal, so `Sprintf("%.2f", pi)`
// produced `3.141592f`. Not merely unrounded — wrong, with a stray
// verb letter glued on, and silently so.
//
// Ground truth, from running the real Go code:
//
//   scripts/goref.sh fmt fmtprec_ref.go
//     A [%.2f]   3.14159   -> [3.14]
//     B [%.0f]   1234.5    -> [1234]        (banker's rounding: to even)
//     C [%.0f]   1235.5    -> [1236]
//     D [%7.2f]  3.14159   -> [   3.14]     (width and precision together)
//     E [%10.0f] 1234.5    -> [      1234]
//     F [%.3f]   0.0005    -> [0.001]
//     G [%.7f]   0.00099995-> [0.0010000]
//     H [%8d]    42        -> [      42]    (width still works)
//     I [%.2f]   -3.14159  -> [-3.14]
//     J [%14.3f] 0.99995   -> [         1.000]
//     K [%.2fs]  1.5       -> [1.50s]       (text after the verb)
//     L [%.1f]   2.25      -> [2.2]         (to even)
//     M [%.1f]   2.35      -> [2.4]
//     N [%.2e]   1234.5    -> [1.23e+03]
//     O [%.3g]   1234.5    -> [1.23e+03]

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate goish;

use goish::gostring::string;
use goish::{fmt, syscall};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

#[goish::main]
fn main() {
    let mut failed = 0;
    let mut n = 0;

    let mut check = |got: string, want: &str, label: &str| {
        n += 1;
        if got == s(want) {
            fmt::Println!("[ok  ] ", label, " ", got);
        } else {
            fmt::Println!("[FAIL] ", label, " got ", got, " want ", want);
            failed += 1;
        }
    };

    check(fmt::Sprintf!("%.2f", 3.14159f64), "3.14", "A %.2f");
    // Go rounds half to even, so 1234.5 -> 1234 but 1235.5 -> 1236.
    check(fmt::Sprintf!("%.0f", 1234.5f64), "1234", "B %.0f even");
    check(fmt::Sprintf!("%.0f", 1235.5f64), "1236", "C %.0f odd");
    check(fmt::Sprintf!("%7.2f", 3.14159f64), "   3.14", "D %7.2f");
    check(fmt::Sprintf!("%10.0f", 1234.5f64), "      1234", "E %10.0f");
    check(fmt::Sprintf!("%.3f", 0.0005f64), "0.001", "F %.3f");
    check(fmt::Sprintf!("%.7f", 0.00099995f64), "0.0010000", "G %.7f");
    check(fmt::Sprintf!("%8d", 42i64), "      42", "H %8d");
    check(fmt::Sprintf!("%.2f", -3.14159f64), "-3.14", "I neg");
    check(
        fmt::Sprintf!("%14.3f", 0.99995f64),
        "         1.000",
        "J %14.3f",
    );
    check(fmt::Sprintf!("%.2fs", 1.5f64), "1.50s", "K trailing text");
    check(fmt::Sprintf!("%.1f", 2.25f64), "2.2", "L half-to-even");
    check(fmt::Sprintf!("%.1f", 2.35f64), "2.4", "M half-to-even");
    check(fmt::Sprintf!("%.2e", 1234.5f64), "1.23e+03", "N %.2e");
    check(fmt::Sprintf!("%.3g", 1234.5f64), "1.23e+03", "O %.3g");

    // A verb with no precision must keep the shortest-round-trip
    // default — the whole point of threading -1 through rather than
    // defaulting to some fixed number of places.
    check(fmt::Sprintf!("%f", 0.1f64), "0.1", "P %f default");
    check(fmt::Sprintf!("%v", 0.1f64), "0.1", "Q %v default");

    drop(check);
    if failed == 0 {
        fmt::Println!("ok ", n, "/", n);
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL ", failed, " of ", n);
        syscall::Exit(1);
    }
}
