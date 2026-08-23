// go: package runtime/pprof
// go: file runtime/pprof/pprof.go decls: NewProfile, Lookup, Profiles, Profile.Name, Profile.Count, Profile.Add, Profile.Remove, Profile.WriteTo, printCountProfile, lostProfileEvent, StartCPUProfile, StopCPUProfile
// goishlint:ignore GOISH015 — this file ports the REGISTRY slice of
// runtime/pprof/pprof.go (the decls manifest above); the sampling
// builtins (goroutine/heap/block/mutex writers), the protobuf
// builder, and label machinery are pprof.go's other ~700 lines and
// stay on the worklist below.
// goishlint:ignore GOISH018 — per-file completeness cannot hold on a
// package slice: the builtin-profile writers need runtime sampling
// hooks (SIGPROF, mprof, blockprof) that do not exist yet; nothing
// here claims them, and this header names them so the gap is a
// ledger entry, not a silence.
// goishlint:ignore GOISH021 — same slice reasoning for pprof.go's
// remaining types/vars (countProfile, keysByCount, labelMap, the
// builtin Profile vars).
//
// runtime/pprof — the user-registry half of Go's profiler.
//
// What lands: NewProfile/Lookup/Profiles and the Profile methods,
// with Add capturing REAL stacks via runtime::Callers and WriteTo's
// debug>=1 arm printing Go's legacy text format with symbolized
// frames (runtime::CallersFrames is live symbolization). What does
// not: the six builtin profiles (each needs a runtime sampling
// substrate — SIGPROF for cpu, mprof for heap/allocs, blockprof for
// block/mutex, a G-registry walker for goroutine/threadcreate), the
// debug=0 protobuf builder, and labels. StartCPUProfile reports the
// honest unsupported error — the same shape Go itself returns on
// platforms without profiling — so net/http/pprof's Profile handler
// ports verbatim through its error arm.

#![allow(non_snake_case)]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::errors::{self, error};
use crate::gostring::string as gostring_ty;
use crate::string;
use crate::types::{int, uintptr};

// go: sdk 1.25.5 runtime/pprof/pprof.go:172-178 Profile
/// Go: "A Profile is a collection of stack traces showing the call
/// sequences that led to instances of a particular event". The
/// builtin profiles carry `count`/`write` funcs; this slice ports the
/// user-registry kind, whose stacks live in `m`.
///
/// Go keys `m` by `any` (the caller's value, compared by identity for
/// pointers); goish keys by the value's address (`usize`), which is
/// the same identity for the Arc/Box/&'static values callers use.
pub struct Profile {
    name: gostring_ty,
    m: crate::sync::Mutex<Vec<(usize, Vec<uintptr>)>>,
}

// go: none — goish-only: the process-wide registry cell (Go's
// `var profiles struct { mu sync.Mutex; m map[string]*Profile }`).
// A `static` with a Lazy ctor, NOT `var!` — var! falls back to
// `pub const` and a const registry silently rebuilds per use.
static PROFILES: crate::lazy::Lazy<
    crate::sync::Mutex<crate::gomap::map<gostring_ty, Option<Arc<Profile>>>>,
> = crate::lazy::Lazy::new(|| crate::sync::Mutex::new(crate::gomap::map::new()));

// go: sdk 1.25.5 runtime/pprof/pprof.go:247-262 NewProfile
/// Go: "NewProfile creates a new profile with the given name. If a
/// profile with that name already exists, NewProfile panics."
pub fn NewProfile(name: gostring_ty) -> Arc<Profile> {
    let mut m = PROFILES.Lock();
    if name.Len() == 0 {
        panic!("pprof: NewProfile with empty name");
    }
    if m.Get(name.clone()).1 {
        panic!("pprof: NewProfile name already in use");
    }
    let p = Arc::new(Profile {
        name: name.clone(),
        m: crate::sync::Mutex::new(Vec::new()),
    });
    m.Set(name, Some(p.clone()));
    return p;
}

// go: sdk 1.25.5 runtime/pprof/pprof.go:265-269 Lookup
/// Go: "returns the profile with the given name, or nil if no such
/// profile exists."
pub fn Lookup(name: gostring_ty) -> Option<Arc<Profile>> {
    let m = PROFILES.Lock();
    let (v, ok) = m.Get(name);
    if !ok {
        return None;
    }
    return v;
}

// go: sdk 1.25.5 runtime/pprof/pprof.go:272-285 Profiles
/// Go: "returns a slice of all the known profiles, sorted by name."
pub fn Profiles() -> crate::goslice::slice<Arc<Profile>> {
    let m = PROFILES.Lock();
    let mut all: Vec<Arc<Profile>> = Vec::new();
    for (_, v) in m.__iter() {
        if let Some(p) = v {
            all.push(p.clone());
        }
    }
    all.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
    return crate::goslice::slice::__from_vec(all);
}

impl Profile {
    // go: sdk 1.25.5 runtime/pprof/pprof.go:288-290 Profile.Name
    pub fn Name(&self) -> gostring_ty {
        return self.name.clone();
    }

    // go: sdk 1.25.5 runtime/pprof/pprof.go:293-300 Profile.Count
    /// Go consults the builtin's `count` func first; the registry
    /// kind answers the map length.
    pub fn Count(&self) -> int {
        return crate::int(crate::int64(self.m.Lock().len()));
    }

    // go: sdk 1.25.5 runtime/pprof/pprof.go:319-342 Profile.Add
    // goishlint:ignore GOISH020 Add — Go's `value any` arrives as the
    // identity address the map would have keyed it by; same arity.
    /// Go: "adds the current execution stack to the profile,
    /// associated with value … Add panics if the profile already
    /// contains a stack for value." The stack is REAL — captured via
    /// runtime::Callers with Go's skip contract.
    pub fn Add(&self, value: usize, skip: int) {
        if self.name.Len() == 0 {
            panic!("pprof: use of uninitialized Profile");
        }
        let mut stk = crate::make!([]uintptr, 32);
        let n = crate::runtime::Callers(skip + 1, &mut stk);
        let mut pcs: Vec<uintptr> = Vec::new();
        for i in 0..n {
            pcs.push(stk[i]);
        }
        if pcs.is_empty() {
            // Go: stk = []uintptr{funcPC(lostProfileEvent)}
            let lost_pc: usize = lostProfileEvent as fn() as usize;
            pcs.push(crate::uint64(lost_pc));
        }
        let mut m = self.m.Lock();
        for (k, _) in m.iter() {
            if *k == value {
                panic!("pprof: Profile.Add of duplicate value");
            }
        }
        m.push((value, pcs));
        return;
    }

    // go: sdk 1.25.5 runtime/pprof/pprof.go:345-349 Profile.Remove
    /// Go: "removes the execution stack associated with value … a
    /// no-op if the value is not in the profile."
    pub fn Remove(&self, value: usize) {
        self.m.Lock().retain(|(k, _)| *k != value);
        return;
    }

    // go: sdk 1.25.5 runtime/pprof/pprof.go:366-386 Profile.WriteTo
    /// Go: "writes a pprof-formatted snapshot of the profile to w …
    /// debug=0 writes the gzip-compressed protocol buffer …
    /// debug=1 writes the legacy text format with comments
    /// translating addresses to function names".
    ///
    /// The debug=0 protobuf arm needs the profileBuilder this slice
    /// does not carry; it reports so instead of writing a lie a
    /// pprof reader would choke on.
    pub fn WriteTo(&self, w: &mut dyn crate::io::Writer, debug: int) -> error {
        if self.name.Len() == 0 {
            panic!("pprof: use of zero Profile");
        }
        // Go: obtain a consistent snapshot under lock, process without.
        let mut all: Vec<Vec<uintptr>> = self.m.Lock().iter().map(|(_, s)| s.clone()).collect();
        // Go: "Map order is non-deterministic; make output deterministic."
        all.sort();
        return printCountProfile(w, debug, self.name.clone(), &all);
    }
}

// go: sdk 1.25.5 runtime/pprof/pprof.go:454-520 printCountProfile
/// The legacy text emitter: identical stacks are counted, ordered
/// most-frequent-first, and each unique stack prints its PCs then the
/// symbolized frames (`#\tPC\tname+offset`). The protobuf arm
/// (debug=0) awaits the profileBuilder and reports so.
fn printCountProfile(
    w: &mut dyn crate::io::Writer,
    debug: int,
    name: gostring_ty,
    stacks: &Vec<Vec<uintptr>>,
) -> error {
    if debug <= 0 {
        return errors::New(string(
            "runtime/pprof: protobuf profile encoding not supported by the goish runtime (use debug=1)",
        ));
    }
    // Go keys each stack by its rendered PC list.
    let mut keys: Vec<gostring_ty> = Vec::new();
    let mut count: crate::gomap::map<gostring_ty, int> = crate::gomap::map::new();
    let mut index: crate::gomap::map<gostring_ty, int> = crate::gomap::map::new();
    for (i, stk) in stacks.iter().enumerate() {
        let mut b = crate::strings::Builder::new();
        let _ = b.WriteString(string("@"));
        for pc in stk.iter() {
            let _ = b.WriteString(crate::fmt::Sprintf!(" 0x%x", crate::uint64(*pc)));
        }
        let k = b.String();
        let (c, seen) = count.Get(k.clone());
        if !seen || c == 0 {
            index.Set(k.clone(), crate::int(crate::int64(i)));
            keys.push(k.clone());
        }
        count.Set(k, c + 1);
    }
    // Go: sort.Sort(&keysByCount{keys, count}) — most frequent first,
    // ties broken by key order.
    keys.sort_by(|a, b| {
        let ca = count.Get(a.clone()).0;
        let cb = count.Get(b.clone()).0;
        cb.cmp(&ca).then_with(|| a.as_bytes().cmp(b.as_bytes()))
    });

    let total = stacks.len();
    let mut out = crate::strings::Builder::new();
    let _ = out.WriteString(crate::fmt::Sprintf!(
        "%s profile: total %d\n",
        name,
        crate::int64(total)
    ));
    for k in keys.iter() {
        let c = count.Get(k.clone()).0;
        let _ = out.WriteString(crate::fmt::Sprintf!("%d %s\n", c, k.clone()));
        // Go: printStackRecord — one symbolized line per frame.
        let i = index.Get(k.clone()).0;
        let stk = &stacks[i as usize];
        for pc in stk.iter() {
            let line = match crate::runtime::FuncForPC(*pc) {
                Some(f) => crate::fmt::Sprintf!(
                    "#\t0x%x\t%s+0x%x\n",
                    crate::uint64(*pc),
                    f.Name(),
                    crate::uint64(pc.saturating_sub(f.Entry()))
                ),
                None => crate::fmt::Sprintf!("#\t0x%x\n", crate::uint64(*pc)),
            };
            let _ = out.WriteString(line);
        }
    }
    let (_, err) = w.Write(crate::convert::bytes(out.String()));
    return err;
}

// go: sdk 1.25.5 runtime/pprof/proto.go:23-23 lostProfileEvent
/// Go: "the function to which lost profiling events are attributed"
/// — its PC stands in when a stack could not be captured.
pub fn lostProfileEvent() {
    return;
}

// go: sdk 1.25.5 runtime/pprof/pprof.go:825-850 StartCPUProfile
/// Go: "enables CPU profiling for the current process … Use
/// StopCPUProfile to stop". CPU profiling needs SIGPROF-driven
/// sampling the goish runtime does not have; this is the honest
/// unsupported arm — the same error-returning shape Go ships on
/// platforms without profiling support — and net/http/pprof's
/// Profile handler serves it exactly as Go serves profiler failures.
pub fn StartCPUProfile(_w: &mut dyn crate::io::Writer) -> error {
    return errors::New(string("cpu profiling not supported by the goish runtime"));
}

// go: sdk 1.25.5 runtime/pprof/pprof.go:884-894 StopCPUProfile
/// Go: "stops the current CPU profile, if any". With StartCPUProfile
/// unable to start one, there is never one to stop.
pub fn StopCPUProfile() {
    return;
}
