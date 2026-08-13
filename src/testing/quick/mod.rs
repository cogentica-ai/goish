// go: package testing/quick
//
// testing/quick — Go's property-based check helper.
//
// **Partial port, and the missing half is the package's headline.**
// `Check` and `CheckEqual` work by reflecting on a function value,
// generating random arguments for its parameter types, and INVOKING it.
// goish's `reflect::Value` is a data-only tree: it does not model
// `Kind::Func`, and `Value::Call` is a documented no-op
// (src/reflect/mod.rs:1286). So `Check`, `CheckEqual`, `Value`,
// `sizedValue`, `arbitraryValues` and `functionAndType` have nothing to
// stand on.
//
// What is here is everything that does not need reflection: the random
// generators, the three error types a failing check reports through,
// and Config's defaulting. They are genuine ports, anchored, and the
// coverage tool reports the rest as MISSING rather than hiding it.

mod quick;

pub use quick::{
    randFloat32, randFloat64, randInt64, toString, CheckEqualError, CheckError, Config,
    SetupError,
};
