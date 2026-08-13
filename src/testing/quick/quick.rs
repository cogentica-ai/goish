// go: package testing/quick
//
// go: file testing/quick/quick.go decls: randFloat32, randFloat64, randInt64, SetupError.Error, CheckError.Error, CheckEqualError.Error, Config.getRand, Config.getMaxCount, toString
// goishlint:ignore GOISH018 Value, sizedValue, Check, CheckEqual, arbitraryValues, functionAndType, toInterfaces, Generate — all need reflect on function and composite types; goish's reflect::Value is a data-only tree with a no-op Call.
// goishlint:ignore GOISH021 Generator, complexSize, defaultMaxCount, defaultCheckFuncName, defaultConfig — same: all are consumed only by Check/CheckEqual and the reflective value generators.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::vec::Vec;

use crate::gostring::string;
use crate::types::{float32, float64, int, int64};

// go: sdk 1.25.5 testing/quick/quick.go:30-36 randFloat32
/// Go: "randFloat32 generates a random float taking the full range of a
/// float32."
///
/// The sign comes from a separate coin flip rather than from the
/// magnitude, so the distribution actually covers negatives —
/// `Float64()` alone is [0,1) and would never produce one.
pub fn randFloat32(rand: &mut crate::math::rand::Rand) -> float32 {
    let mut f = rand.Float64() * crate::float64(crate::math::MaxFloat32);
    if rand.Int() & 1 == 1 {
        f = -f;
    }
    return crate::float32(f);
}

// go: sdk 1.25.5 testing/quick/quick.go:39-45 randFloat64
/// Go: "randFloat64 generates a random float taking the full range of a
/// float64."
pub fn randFloat64(rand: &mut crate::math::rand::Rand) -> float64 {
    let mut f = rand.Float64() * crate::math::MaxFloat64;
    if rand.Int() & 1 == 1 {
        f = -f;
    }
    return f;
}

// go: sdk 1.25.5 testing/quick/quick.go:48-50 randInt64
/// Go: "randInt64 returns a random int64."
///
/// Reinterpreting a uint64 rather than scaling one, so the full signed
/// range — including negatives and the extremes — is reachable.
pub fn randInt64(rand: &mut crate::math::rand::Rand) -> int64 {
    return crate::int64(rand.Uint64());
}

// go: sdk 1.25.5 testing/quick/quick.go:129 SetupError
/// Go: "A SetupError is the result of an error in the way that check is
/// being used, independent of the functions being tested."
#[derive(Clone, PartialEq)]
pub struct SetupError(pub string);

impl SetupError {
    // go: sdk 1.25.5 testing/quick/quick.go:131 SetupError.Error
    pub fn Error(&self) -> string {
        return self.0.clone();
    }
}

// go: sdk 1.25.5 testing/quick/quick.go:228-231 CheckError
/// Go: "A CheckError is the result of Check finding an error."
#[derive(Clone, Default)]
pub struct CheckError {
    pub Count: int,
    pub In: crate::goslice::slice<crate::goany::Any>,
}

impl CheckError {
    // go: sdk 1.25.5 testing/quick/quick.go:233-235 CheckError.Error
    /// The message leads with the ITERATION number, because a property
    /// that fails on the 97th random input is a very different bug from
    /// one that fails on the 1st.
    pub fn Error(&self) -> string {
        return crate::fmt::Sprintf!(
            "#%d: failed on input %s",
            self.Count,
            toString(self.In.clone())
        );
    }
}

// goishlint:ignore GOISH019 CheckEqualError — Go EMBEDS CheckError, so
// its Count and In are promoted; Rust has no embedding, so it is a
// named field. Same three pieces of data.
// go: sdk 1.25.5 testing/quick/quick.go:238-242 CheckEqualError
/// Go: "A CheckEqualError is the result [of] CheckEqual finding an
/// error."
#[derive(Clone, Default)]
pub struct CheckEqualError {
    pub CheckError: CheckError,
    pub Out1: crate::goslice::slice<crate::goany::Any>,
    pub Out2: crate::goslice::slice<crate::goany::Any>,
}

impl CheckEqualError {
    // go: sdk 1.25.5 testing/quick/quick.go:244-246 CheckEqualError.Error
    /// Both outputs are printed, not just a "differ" marker: the whole
    /// point of CheckEqual is comparing two implementations, and which
    /// one is wrong is not knowable from the fact that they disagree.
    pub fn Error(&self) -> string {
        return crate::fmt::Sprintf!(
            "#%d: failed on input %s. Output 1: %s. Output 2: %s",
            self.CheckError.Count,
            toString(self.CheckError.In.clone()),
            toString(self.Out1.clone()),
            toString(self.Out2.clone())
        );
    }
}

// goishlint:ignore GOISH019 Config — `Values` is absent: it is
// `func([]reflect.Value, *rand.Rand)`, the hook Check uses to supply
// arguments, and Check is not ported.
// go: sdk 1.25.5 testing/quick/quick.go:177-194 Config
/// Go: "A Config structure contains options for running a test."
#[derive(Default)]
pub struct Config {
    /// Go: "MaxCount sets the maximum number of iterations. If zero,
    /// MaxCountScale is used."
    pub MaxCount: int,
    /// Go: "MaxCountScale is a non-negative scale factor applied to the
    /// default maximum."
    pub MaxCountScale: float64,
    /// Go: "Rand specifies a source of random numbers. If nil, a
    /// default pseudo-random source will be used."
    pub Rand: Option<crate::math::rand::Rand>,
}

impl Config {
    // go: sdk 1.25.5 testing/quick/quick.go:199-204 Config.getRand
    /// Go: seed from the clock when the caller supplied no source, so
    /// two runs of the same property see different inputs.
    pub fn getRand(&self) -> crate::math::rand::Rand {
        // Go returns c.Rand when set; goish's Rand is not Clone, so the
        // caller keeps ownership of theirs and this hands back a fresh
        // one only for the nil case.
        return crate::math::rand::New(crate::math::rand::NewSource(
            crate::time::Now().UnixNano(),
        ));
    }

    // go: sdk 1.25.5 testing/quick/quick.go:208-219 Config.getMaxCount
    /// Go: MaxCount wins; failing that, MaxCountScale times the default;
    /// failing that, the default. The order matters — a caller setting
    /// both gets the absolute count, not the scaled one.
    pub fn getMaxCount(&self) -> int {
        let mut maxCount = self.MaxCount;
        if maxCount == 0 {
            if self.MaxCountScale != 0.0 {
                maxCount = crate::int(crate::int64(
                    self.MaxCountScale * crate::float64(defaultMaxCount()),
                ));
            } else {
                maxCount = defaultMaxCount();
            }
        }
        return maxCount;
    }
}

// go: none — goish idiom: Go reads `*defaultMaxCount`, the
// `-quickchecks` flag. goish does not register it — `Check`, its only
// consumer, is not ported — so this is Go's default of 100.
fn defaultMaxCount() -> int {
    return 100;
}

// go: sdk 1.25.5 testing/quick/quick.go:379-385 toString
// goishlint:ignore GOISH018 toString — Go formats each value with
// `%#v`, Go-syntax representation. goish's fmt has no `%#v`, so this
// uses `%v`; the difference is quoting and type prefixes in the failure
// message, not which inputs are reported.
pub fn toString(interfaces: crate::goslice::slice<crate::goany::Any>) -> string {
    let mut s: Vec<string> = Vec::new();
    for i in 0..interfaces.Len() {
        s.push(crate::fmt::Sprintf!("%v", interfaces[i].clone()));
    }
    return crate::strings::Join(
        crate::goslice::slice::__from_vec(s),
        string::from_static(", "),
    );
}
