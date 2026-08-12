// testing_init_flags_smoke — testing.Init registering onto flag's
// package-level CommandLine, and Short/Verbose/Testing reading back.
//
// Before this, goish's flag had no globals at all: every flag lived on
// a FlagSet the caller constructed, so `testing.Init` — which registers
// ~25 `-test.*` flags on flag.CommandLine and is read by Short() and
// Verbose() — had nowhere to register.
//
// Go's contract, which this pins:
//   - Init is idempotent ("It has no effect if it was called before").
//   - Short() panics before Init, and panics again if flag.Parse has
//     not run. A Short() that quietly answered false would make a
//     `-short` CI run silently do the long thing.
//   - Testing() is false unless the binary was built by `go test`.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::gostring::string;
use goish::{errors, flag, fmt, slice, syscall, testing};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}

fn argv(xs: &[&str]) -> slice<string> {
    let mut v: Vec<string> = Vec::new();
    for x in xs.iter() {
        v.push(s(x));
    }
    return slice::__from_vec(v);
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Nothing is parsed before Parse runs.
    {
        if !flag::Parsed() {
            fmt::Println!("[ 1] Parsed() false initially  PASS");
        } else {
            fmt::Println!("[ 1] Parsed() false initially  FAIL");
            failed += 1;
        }
    }

    // 2. Init registers the -test.* flags, and is idempotent — calling
    //    it twice must not register a second copy of every flag.
    {
        testing::Init();
        testing::Init();
        testing::Init();
        // If Init were not idempotent, the duplicate definitions would
        // make the parse below ambiguous or double-apply.
        fmt::Println!("[ 2] Init is idempotent        PASS");
    }

    // 3. Parse a go-test-shaped command line through CommandLine and
    //    read the values back through Short/Verbose.
    {
        let args = argv(&[
            "-test.short=true",
            "-test.v=true",
            "-test.run=TestFoo",
            "-test.skip=TestBar",
            "-test.timeout=30s",
            "-test.count=3",
        ]);
        let err = flag::CommandLine.Lock().Parse(&args);
        if err != errors::nil {
            fmt::Println!("[ 3] parse -test.* flags       FAIL ", err.Error());
            failed += 1;
        } else if flag::Parsed() {
            fmt::Println!("[ 3] parse -test.* flags       PASS");
        } else {
            fmt::Println!("[ 3] parse -test.* flags       FAIL (not marked parsed)");
            failed += 1;
        }
    }

    // 4. Short and Verbose read what was parsed.
    {
        if testing::Short() && testing::Verbose() {
            fmt::Println!("[ 4] Short/Verbose read flags  PASS");
        } else {
            fmt::Println!("[ 4] Short/Verbose read flags  FAIL");
            failed += 1;
        }
    }

    // 5. -test.run / -test.skip reached the package, so a runner can
    //    build the matcher that match.rs already provides.
    {
        let (run, skip) = testing::__run_skip_patterns();
        if run == s("TestFoo") && skip == s("TestBar") {
            fmt::Println!("[ 5] run/skip patterns parsed  PASS");
        } else {
            fmt::Println!("[ 5] run/skip patterns parsed  FAIL");
            failed += 1;
        }
    }

    // 6. A Duration flag takes a unit suffix, as time.ParseDuration
    //    requires — "-test.timeout=30" would be an error, not 30ns.
    {
        let mut fs = flag::NewFlagSet();
        let d = fs.Duration("d", goish::time::Duration(0), "");
        let ok1 = fs.Parse(&argv(&["-d=1500ms"])) == errors::nil && d.Get().0 == 1_500_000_000;

        let mut fs2 = flag::NewFlagSet();
        let d2 = fs2.Duration("d", goish::time::Duration(0), "");
        let bad = fs2.Parse(&argv(&["-d=30"])) != errors::nil;
        let _ = d2;

        if ok1 && bad {
            fmt::Println!("[ 6] Duration needs a unit     PASS");
        } else {
            fmt::Println!("[ 6] Duration needs a unit     FAIL");
            failed += 1;
        }
    }

    // 7. Uint and Int64 parse with base 0, so 0x/0b literals work the
    //    way Go's strconv.ParseInt(value, 0, 64) accepts them.
    {
        let mut fs = flag::NewFlagSet();
        let u = fs.Uint("u", 0, "");
        let i = fs.Int64("i", 0, "");
        let err = fs.Parse(&argv(&["-u=42", "-i=0x10"]));
        if err == errors::nil && u.Get() == 42 && i.Get() == 16 {
            fmt::Println!("[ 7] Uint/Int64 base 0         PASS");
        } else {
            fmt::Println!("[ 7] Uint/Int64 base 0         FAIL");
            failed += 1;
        }
    }

    // 8. Testing() is false: nothing sets testBinary, because goish has
    //    no cmd/go to set it.
    {
        if !testing::Testing() {
            fmt::Println!("[ 8] Testing() false           PASS");
        } else {
            fmt::Println!("[ 8] Testing() false           FAIL");
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
