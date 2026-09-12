// go: package runtime/pprof
// go: file runtime/pprof/pprof.go decls: NewProfile, Lookup, Profiles, Profile.Name, Profile.Count, Profile.Add, Profile.Remove, Profile.WriteTo, printCountProfile, lostProfileEvent, StartCPUProfile, StopCPUProfile
// goishlint:ignore GOISH015 — this file ports the REGISTRY slice of
// runtime/pprof/pprof.go (the decls manifest above); the sampling
// builtins (goroutine/heap/block/mutex writers), the protobuf
// builder, and label machinery are pprof.go's other ~700 lines and
// stay on the worklist below.
// Per-file completeness cannot hold on a package slice: the
// builtin-profile writers need runtime sampling hooks (SIGPROF, mprof,
// blockprof) that do not exist yet, and pprof.go's remaining
// types and vars — countProfile, keysByCount, labelMap, the builtin
// Profile vars — go with them. Nothing here claims any of it.
//
// That paragraph carried a GOISH018 and a GOISH021 marker, each naming
// NO symbol, so neither suppressed anything. It also said the header
// "names them so the gap is a ledger entry, not a silence" — which a
// marker with an empty symbol list is exactly the opposite of. The
// ledger is this prose; the markers were the silence.
//
// runtime/pprof — the user-registry half of Go's profiler.
//
// What lands: NewProfile/Lookup/Profiles and the Profile methods,
// with Add capturing REAL stacks via runtime::Callers and WriteTo's
// debug>=1 arm printing Go's legacy text format with symbolized
// frames (runtime::CallersFrames is live symbolization). Plus the CPU
// profile end to end — StartCPUProfile arms SIGPROF and StopCPUProfile
// writes a gzipped profile.proto, pinned against Go by
// `pprof_cpu_ref_smoke`.
//
// What does not: the other five builtin profiles. Each needs a
// sampling substrate that is still absent — mprof for heap/allocs
// (the MemStats COUNTERS work; per-allocation-site stacks do not),
// blockprof for block/mutex, and a goroutine REGISTRY for
// goroutine/threadcreate (see `runtime::GoroutineProfile`, whose gap
// is the list, not the walker). Labels are also unported.
//
// This header used to say StartCPUProfile "reports the honest
// unsupported error … so net/http/pprof's Profile handler ports
// verbatim through its error arm". Both halves are now false: the
// profile starts, and that handler was rewritten to collect and
// forward the bytes.

#![allow(non_snake_case)]

#[doc(hidden)]
pub mod proto;
pub(crate) mod sample;

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

// go: none — goish-only: the CPU profiler's process-wide cell. Go's is
// `var cpu struct { sync.Mutex; profiling bool; done chan bool }` plus a
// `profileWriter` goroutine holding `w`; goish keeps `w` here because
// the drain happens in `StopCPUProfile` — see the note there.
struct CpuState {
    profiling: bool,
    w: Option<alloc::boxed::Box<dyn crate::io::Writer + Send>>,
    start_ns: int,
}

// go: none — goish-only: see `CpuState`. A `Lazy` static, not `var!`,
// for the reason spelled out on `PROFILES`.
static CPU: crate::lazy::Lazy<crate::sync::Mutex<CpuState>> = crate::lazy::Lazy::new(|| {
    crate::sync::Mutex::new(CpuState {
        profiling: false,
        w: None,
        start_ns: 0,
    })
});

// go: sdk 1.25.5 runtime/pprof/pprof.go:825-850 StartCPUProfile
/// Go: "enables CPU profiling for the current process. While profiling,
/// the profile will be buffered and written to w. StartCPUProfile
/// returns an error if profiling is already enabled." Go's rate is a
/// `const hz = 100`, and goish uses the same one.
///
/// The writer is taken BY VALUE, where Go takes an `io.Writer`
/// interface. Go can keep the interface value in a package variable
/// from Start until Stop; `&mut dyn Writer` cannot outlive this call,
/// so ownership moves in. That is the same shape `flag.SetOutput` and
/// `log.SetOutput` already use for a writer stored past the call, so
/// callers do what they do in Go — hand over the `os.File` — and read
/// the file back afterwards.
///
/// DEVIATION, and it is the one worth knowing: Go streams samples to
/// `w` from a `profileWriter` goroutine as they are produced, so a
/// long profile costs bounded memory and loses nothing. goish records
/// into the sampler's fixed 8192-entry ring and encodes the whole
/// profile in `StopCPUProfile`. At 100 Hz that is about 82 seconds of
/// wall clock; past it the ring wraps and the OLDEST samples are the
/// ones lost. `runtime::pprof::__taken` reports the true count, so a
/// caller can tell that it happened.
pub fn StartCPUProfile<W: crate::io::Writer + Send + 'static>(w: W) -> error {
    const HZ: i64 = 100;
    let mut cpu = CPU.Lock();
    if cpu.profiling {
        // Go's exact string, via fmt.Errorf; net/http/pprof shows it to
        // the user, so it is a contract and not a diagnostic.
        return errors::New(string("cpu profiling already in use"));
    }
    if !sample::start(HZ) {
        // Go cannot fail here — SetCPUProfileRate returns nothing — but
        // goish arms a real `setitimer`, and a refusal must not leave a
        // caller believing a profile is running.
        return errors::New(string("cpu profiling: could not arm the sampling timer"));
    }
    cpu.profiling = true;
    cpu.start_ns = crate::time::Now().UnixNano();
    cpu.w = Some(alloc::boxed::Box::new(w));
    return errors::nil;
}

// go: sdk 1.25.5 runtime/pprof/pprof.go:884-894 StopCPUProfile
/// Go: "stops the current CPU profile, if any. StopCPUProfile only
/// returns after all the writes for the profile have completed."
/// Stopping when nothing is running is a no-op, and so is stopping
/// twice — both verified against Go in `pprof_cpu_ref_smoke`.
///
/// The whole encode-and-write happens here, under the same lock, which
/// is what makes Go's "only returns after all the writes have
/// completed" hold trivially. A write error is DISCARDED, because
/// `StopCPUProfile` has nowhere to report one; Go does the same — a
/// writer returning an error from every Write neither panics nor
/// hangs it, which the reference test confirmed rather than assumed.
pub fn StopCPUProfile() {
    let mut cpu = CPU.Lock();
    if !cpu.profiling {
        return;
    }
    cpu.profiling = false;
    // Disarm before reading the ring: `sample::stop` clears its ACTIVE
    // flag first, so a signal already in flight declines to write.
    sample::stop();
    let stop_ns = crate::time::Now().UnixNano();
    let start_ns = cpu.start_ns;
    let mut w = match cpu.w.take() {
        Some(w) => w,
        None => return,
    };
    // Grow the stack around the encode. Go grows goroutine stacks on
    // demand, so `StopCPUProfile` costs its caller nothing; goish needs
    // the hint, and without it this faults on any caller with a small
    // stack. It is not hypothetical — `net/http/pprof.Profile` calls
    // here from a handler goroutine on the 64 KiB default, and gzip's
    // deflate windows overflowed it (SIGSEGV in gzip.rs, reported by
    // `http_pprof_smoke`). Growing HERE rather than at the handler is
    // deliberate: the requirement belongs to this function, not to
    // whoever calls it.
    let (b, err) = crate::runtime::sched::maybe_grow(64 * 1024, 4 * 1024 * 1024, || {
        let p = __build_cpu_profile(start_ns, stop_ns);
        return proto::marshal_gzip(&p);
    });
    if err != errors::nil {
        return;
    }
    let _ = w.Write(b);
}

// go: none — goish-only: Go builds the profile incrementally in
// `profileBuilder` as samples arrive (proto.go); goish has the whole
// ring in hand at Stop, so it aggregates in one pass here.
/// Turn the sampler's ring into a `profile.proto` message.
///
/// The two sample values are Go's: `[count, count*period]`, so the
/// second is CPU nanoseconds. `pprof_cpu_ref_smoke` pins that identity
/// against Go rather than against arithmetic that looks right.
fn __build_cpu_profile(start_ns: int, stop_ns: int) -> proto::Profile {
    let period = crate::int64(sample::period_ns());
    let mut p = proto::Profile::new();
    p.sample_type.push(proto::ValueType {
        ty: string("samples"),
        unit: string("count"),
    });
    p.sample_type.push(proto::ValueType {
        ty: string("cpu"),
        unit: string("nanoseconds"),
    });
    p.period_type = Some(proto::ValueType {
        ty: string("cpu"),
        unit: string("nanoseconds"),
    });
    p.period = period;
    p.time_nanos = start_ns;
    p.duration_nanos = stop_ns - start_ns;

    // One location per distinct PC (id is its 1-based index, which is
    // what `marshal` expects), and one aggregated sample per distinct
    // stack — pprof counts repeats rather than repeating them.
    let mut pcs: Vec<u64> = Vec::new();
    let mut stacks: Vec<(Vec<u64>, i64)> = Vec::new();
    sample::for_each(|frame_pcs| {
        let mut ids: Vec<u64> = Vec::new();
        for pc in frame_pcs.iter() {
            let id = match pcs.iter().position(|q| *q == *pc) {
                Some(i) => crate::uint64(i) + 1,
                None => {
                    pcs.push(*pc);
                    crate::uint64(pcs.len())
                }
            };
            ids.push(id);
        }
        match stacks.iter_mut().find(|(s, _)| *s == ids) {
            Some((_, c)) => *c += 1,
            None => stacks.push((ids, 1)),
        }
    });

    for (i, pc) in pcs.iter().enumerate() {
        let mut loc = proto::Location {
            id: crate::uint64(i) + 1,
            address: *pc,
            line: Vec::new(),
        };
        // Symbolize through the same path `Profile.WriteTo` uses, so a
        // frame that prints in the text format also names a function
        // here. An unsymbolizable PC keeps its address and no line —
        // `go tool pprof` renders that as a hex frame rather than
        // rejecting the profile.
        let mut one: Vec<uintptr> = Vec::new();
        one.push(*pc);
        let mut frames = crate::runtime::CallersFrames(crate::goslice::slice::__from_vec(one));
        let (f, _) = frames.Next();
        if f.Function.Len() > 0 {
            let name = f.Function.clone();
            let fid = match p.function.iter().position(|g| g.name == name) {
                Some(j) => p.function[j].id,
                None => {
                    let id = crate::uint64(p.function.len()) + 1;
                    p.function.push(proto::Function {
                        id: id,
                        name: name.clone(),
                        system_name: name.clone(),
                        filename: f.File.clone(),
                        start_line: 0,
                    });
                    id
                }
            };
            loc.line.push(proto::Line {
                function_id: fid,
                line: f.Line,
            });
        }
        p.location.push(loc);
    }

    for (ids, count) in stacks.into_iter() {
        let mut value: Vec<i64> = Vec::new();
        value.push(count);
        value.push(count * period);
        p.sample.push(proto::Sample {
            location_id: ids,
            value: value,
        });
    }
    return p;
}

// go: none — goish-only: test hooks onto the sampler's raw ring, so a
// smoke can assert that samples were taken and that their stacks are
// real before the protobuf path exists to show them.
#[doc(hidden)]
pub fn __taken() -> usize {
    return sample::taken();
}

// go: none — goish-only: see `__taken`.
#[doc(hidden)]
pub fn __period_ns() -> u64 {
    return sample::period_ns();
}

// go: none — goish-only: see `__taken`.
#[doc(hidden)]
pub fn __for_each<F: FnMut(&[u64])>(f: F) {
    sample::for_each(f);
}

// go: none — goish-only: see `__taken`.
#[doc(hidden)]
pub fn __sample_start(hz: i64) -> bool {
    return sample::start(hz);
}

// go: none — goish-only: see `__taken`.
#[doc(hidden)]
pub fn __sample_stop() {
    sample::stop();
}
