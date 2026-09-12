// demangle_v0_ref_smoke — the Rust v0 demangler, against
// rustc-demangle.
//
// goish's symboliser read only the LEGACY mangling (`_ZN…E`). This
// build emits rustc's v0, so it demangled nothing at all: one example
// binary here defines 19231 v0 symbols and every backtrace, panic
// report, `runtime.Callers` result and pprof text profile printed
// things like
//
//     _RNvNtNtCsc47Z2okxEDo_5goish7runtime5pprof14StopCPUProfile
//
// The reference is rustc-demangle itself, driven over every v0 symbol
// defined by seven example binaries — 24127 of them — with goish's
// parser compiled as a plain `std` program from the SAME source file so
// the comparison is against the code that ships. 24127 exact, zero
// bails, zero disagreements. That harness needs cargo and the real
// crate, so it cannot live in an example; what lives here is one row
// per GRAMMAR CONSTRUCT, selected out of that corpus by a script and
// transcribed by the same script. None of these strings was typed.
//
// Four bugs the corpus found, none of which a hand-written table
// would have:
//
//   1. the discard pass that validates the trailing instantiating
//      crate ran with a zero-length output buffer, so its first write
//      tripped the overflow check. 14363 symbols "unparseable" for a
//      buffer check, not a grammar gap.
//   2. the disambiguator is base-62 PLUS ONE. Without the `+ 1`, 1142
//      symbols named the right function and the wrong closure in it.
//   3. lifetimes. `for<'_>` for everything makes
//      `for<'a, 'b> Fn(&'a mut T<'b>)` and `Fn(&'b mut T<'a>)` print
//      identically — different types, same output.
//   4. a length prefix of `0` ends the number there. Reading digits
//      greedily merged the two empty names of nested closures, which
//      was the last 227.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};
use goish::fmt;
use goish::gostring::string;
use goish::runtime::symbolize::demangle_v0::demangle_v0;
use goish::types::uintptr;

static FAILED: AtomicUsize = AtomicUsize::new(0);
static ROWS: AtomicUsize = AtomicUsize::new(0);

/// (mangled, what rustc-demangle prints). One per construct.
static CASES: &[(&str, &str)] = &[
    // plain nested path
    ("_RNvNtNtCsc36rpYXAlPq_4core3str5count14do_count_chars",
     "core::str::count::do_count_chars"),
    // crate root only
    ("_RNvCs1KpnNCIm0x0_25testing_fstest_stat_smoke1s",
     "testing_fstest_stat_smoke::s"),
    // inherent impl
    ("_RNvMCseSQSoTMxW6j_14math_big_smokeNtB2_9TestState10with_width",
     "<math_big_smoke::TestState>::with_width"),
    // trait impl
    ("_RINvMNtNtNtNtCsc36rpYXAlPq_4core5slice4sort6stable5mergeINtB3_10MergeStateTllEE10merge_downNvYB1a_NtNtBb_3cmp10PartialOrd2ltECsc47Z2okxEDo_5goish",
     "<core::slice::sort::stable::merge::MergeState<(i32, i32)>>::merge_down::<<(i32, i32) as core::cmp::PartialOrd>::lt>"),
    // generics, value pos
    ("_RINvCskeXW6BOssG6_6goginx4failNtNtCsc47Z2okxEDo_5goish8gostring6stringEB2_",
     "goginx::fail::<goish::gostring::string>"),
    // generics, type pos
    ("_RNvMNtCsc36rpYXAlPq_4core5sliceSINtNtB4_6option6OptionINtNtCscHgRw1M2fX5_5alloc3vec3VechEE4lastCsc47Z2okxEDo_5goish",
     "<[core::option::Option<alloc::vec::Vec<u8>>]>::last"),
    // closure #0
    ("_RNCINvMNtCsc36rpYXAlPq_4core5sliceSTmmE20binary_search_by_keymNCNvNtNtCsc47Z2okxEDo_5goish7unicode6letter11case_lookup0E0B16_",
     "<[(u32, u32)]>::binary_search_by_key::<u32, goish::unicode::letter::case_lookup::{closure#0}>::{closure#0}"),
    // closure #1
    ("_RNCINvMNtNtNtCsc47Z2okxEDo_5goish7testing6fstest5mapfsNtB5_5MapFS4OpenNtNtBb_8gostring6stringEs_0Bb_",
     "<goish::testing::fstest::mapfs::MapFS>::Open::<goish::gostring::string>::{closure#1}"),
    // closure #2
    ("_RNCINvMNtNtNtCsc47Z2okxEDo_5goish7testing6fstest5mapfsNtB5_5MapFS4OpenNtNtBb_8gostring6stringEs0_0Bb_",
     "<goish::testing::fstest::mapfs::MapFS>::Open::<goish::gostring::string>::{closure#2}"),
    // nested closures
    ("_RINvMNtCsc36rpYXAlPq_4core3cmpNtB3_8Ordering9then_withNCNCNvNtNtCsc47Z2okxEDo_5goish7runtime5pprof17printCountProfile00EB10_",
     "<core::cmp::Ordering>::then_with::<goish::runtime::pprof::printCountProfile::{closure#0}::{closure#0}>"),
    // named shim
    ("_RNSNvYFlEbINtNtNtCsc36rpYXAlPq_4core3ops8function6FnOnceTlEE9call_once6vtableCsc47Z2okxEDo_5goish",
     "<fn(i32) -> bool as core::ops::function::FnOnce<(i32,)>>::call_once::{shim:vtable#0}"),
    // dyn with assoc binding
    ("_RINvNtCsc36rpYXAlPq_4core3ptr9drop_glueDINtNtNtB4_3ops8function2FnTlEEp6OutputbNtNtB4_6marker4SendNtB1h_4SyncEL_ECseSQSoTMxW6j_14math_big_smoke",
     "core::ptr::drop_glue::<dyn core::ops::function::Fn<(i32,), Output = bool> + core::marker::Send + core::marker::Sync>"),
    // dyn with auto traits
    ("_RINvMs4_NtCsc36rpYXAlPq_4core3anyDNtB6_3AnyNtNtB8_6marker4SendNtBH_4SyncEL_12downcast_mutaECsc47Z2okxEDo_5goish",
     "<dyn core::any::Any + core::marker::Send + core::marker::Sync>::downcast_mut::<i8>"),
    // mut reference
    ("_RINvMs0_NtNtNtCsc47Z2okxEDo_5goish8encoding6binary9binary_goNtB6_9BigEndian9PutUint16QShEBc_",
     "<goish::encoding::binary::binary_go::BigEndian>::PutUint16::<&mut [u8]>"),
    // slice type
    ("_RINvMNtCsc36rpYXAlPq_4core5sliceSh11copy_withinINtNtNtB5_3ops5range5RangejEECsc47Z2okxEDo_5goish",
     "<[u8]>::copy_within::<core::ops::range::Range<usize>>"),
    // tuple type
    ("_RNvXs1_NtNtNtCsc36rpYXAlPq_4core3ops8function5implsQNtNtBb_3str15BytesIsNotEmptyINtB7_5FnMutTRRShEE8call_mutCsc47Z2okxEDo_5goish",
     "<&mut core::str::BytesIsNotEmpty as core::ops::function::FnMut<(&&[u8],)>>::call_mut"),
    // primitive args
    ("_RINvMNtCsc36rpYXAlPq_4core3stre5parsehECsc47Z2okxEDo_5goish",
     "<str>::parse::<u8>"),
    // unit type
    ("_RINvMNtCsc36rpYXAlPq_4core5sliceSINtNtNtCsc47Z2okxEDo_5goish7runtime13lockfree_ring4SlotuE13get_uncheckedjEBC_",
     "<[goish::runtime::lockfree_ring::Slot<()>]>::get_unchecked::<usize>"),
    // raw pointer
    ("_RINvNtCsc36rpYXAlPq_4core3ptr4swapPINtNtNtB4_4sync6atomic6AtomicbEECsc47Z2okxEDo_5goish",
     "core::ptr::swap::<*const core::sync::atomic::Atomic<bool>>"),
    // array with const len
    ("_RINvMs3_NtNtCsc47Z2okxEDo_5goish6crypto3tlsNtB6_4Conn5WriteRAhj5_EBa_",
     "<goish::crypto::tls::Conn>::Write::<&[u8; 5]>"),
    // fn pointer
    ("_RNvMNtCsc36rpYXAlPq_4core6optionINtB2_6OptionFUINtNtNtB4_3ptr8non_null7NonNullNtNtNtNtCsc47Z2okxEDo_5goish7runtime5sched1g1GEEbE4takeB1m_",
     "<core::option::Option<unsafe fn(core::ptr::non_null::NonNull<goish::runtime::sched::g::G>) -> bool>>::take"),
    // hrtb lifetimes
    ("_RINvNtCsc36rpYXAlPq_4core3ptr9drop_glueDG0_INtNtNtB4_3ops8function2FnTQL1_INtNtNtNtNtCsc47Z2okxEDo_5goish3net4http8httputil12reverseproxy12ProxyRequestL0_EEEp6OutputuNtNtB4_6marker4SendNtB2G_4SyncEL_EB1l_",
     "core::ptr::drop_glue::<dyn for<'a, 'b> core::ops::function::Fn<(&'a mut goish::net::http::httputil::reverseproxy::ProxyRequest<'b>,), Output = ()> + core::marker::Send + core::marker::Sync>"),
    // named lifetime on ref
    ("_RINvNtCsc36rpYXAlPq_4core3ptr9drop_glueDG_INtNtNtB4_3ops8function2FnTINtNtCscHgRw1M2fX5_5alloc4sync3ArcDNtNtNtCsc47Z2okxEDo_5goish7context10context_go7ContextEL_ERL0_NtNtB1K_3net7TCPConnEEp6OutputB15_NtNtB4_6marker4SendNtB3e_4SyncEL_EB1K_",
     "core::ptr::drop_glue::<dyn for<'a> core::ops::function::Fn<(alloc::sync::Arc<dyn goish::context::context_go::Context>, &'a goish::net::TCPConn), Output = alloc::sync::Arc<dyn goish::context::context_go::Context>> + core::marker::Send + core::marker::Sync>"),
];

#[goish::main]
fn main() {
    let mut out = [0u8; 1024];
    for (sym, want) in CASES.iter() {
        ROWS.fetch_add(1, Ordering::Relaxed);
        let n = demangle_v0(sym.as_bytes(), &mut out);
        let got = &out[..n];
        if n > 0 && got == want.as_bytes() {
            fmt::Printf!("[ok] %s\n", string::from_static(want));
        } else {
            FAILED.fetch_add(1, Ordering::Relaxed);
            fmt::Printf!(
                "[!!] %s\n  got  %s\n  want %s\n",
                string::from_static(sym),
                string::from_bytes(got),
                string::from_static(want)
            );
        }
    }

    // ── the refusals ──
    //
    // A 0 return means "print the raw symbol", which is what the
    // symboliser already does for a legacy symbol it cannot read. The
    // rule this parser holds to is that it never emits a name it is
    // unsure of, so the refusals matter as much as the successes.
    let refuse: &[(&str, &str)] = &[
        ("not a mangled name at all", "main"),
        ("legacy mangling is the other demangler's job", "_ZN4main4mainE"),
        ("truncated mid-identifier", "_RNvNtCs1234_4core3st"),
        ("a length that runs past the end", "_RNvC99xyz"),
        ("punycode identifiers are refused, not guessed", "_RNvCsXXX_u8crate_ab"),
        ("a backref must point backwards", "_RB0_"),
        ("empty after the prefix", "_R"),
    ];
    for (why, sym) in refuse.iter() {
        ROWS.fetch_add(1, Ordering::Relaxed);
        let n = demangle_v0(sym.as_bytes(), &mut out);
        if n == 0 {
            fmt::Printf!("[ok] refused: %s\n", string::from_static(why));
        } else {
            FAILED.fetch_add(1, Ordering::Relaxed);
            fmt::Printf!(
                "[!!] accepted %s as %s — %s\n",
                string::from_static(sym),
                string::from_bytes(&out[..n]),
                string::from_static(why)
            );
        }
    }

    // A buffer too small must refuse rather than truncate. SymInfo's
    // name buffer is 256 bytes and 4% of real demangled names are
    // longer, so this path runs in production.
    {
        ROWS.fetch_add(1, Ordering::Relaxed);
        let mut tiny = [0u8; 8];
        let n = demangle_v0(CASES[0].0.as_bytes(), &mut tiny);
        if n == 0 {
            fmt::Printf!("[ok] refused: a name that does not fit is not truncated\n");
        } else {
            FAILED.fetch_add(1, Ordering::Relaxed);
            fmt::Printf!("[!!] truncated into an 8-byte buffer: %d bytes\n", n as i64);
        }
    }

    // And the wiring: a demangler nothing calls is worth nothing, so
    // assert that the SYMBOLISER uses it on this binary's own frames.
    {
        ROWS.fetch_add(1, Ordering::Relaxed);
        let mut pcs: goish::slice<uintptr> = goish::make!([]uintptr, 16);
        let n = goish::runtime::Callers(0, &mut pcs);
        let mut frames = goish::runtime::CallersFrames(pcs);
        let mut demangled = false;
        let mut i = 0;
        while i < n {
            let (f, more) = frames.Next();
            let s: &str = f.Function.as_ref();
            if s.starts_with("goish::") || s.starts_with("demangle_v0_ref_smoke") {
                demangled = true;
            }
            if !more {
                break;
            }
            i += 1;
        }
        if demangled {
            fmt::Printf!("[ok] the symboliser demangles this binary's own frames\n");
        } else {
            FAILED.fetch_add(1, Ordering::Relaxed);
            fmt::Printf!("[!!] symbolize() is not using the v0 demangler\n");
        }
    }

    let ran = ROWS.load(Ordering::Relaxed);
    let bad = FAILED.load(Ordering::Relaxed);
    let expect = CASES.len() + 7 + 2;
    if ran != expect {
        fmt::Printf!("\nFAILED: %d rows ran, expected %d\n", ran as i64, expect as i64);
        goish::os::Exit(1);
    }
    if bad != 0 {
        fmt::Printf!("\nFAILED %d of %d row(s)\n", bad as i64, ran as i64);
        goish::os::Exit(1);
    }
    fmt::Printf!("\nok %d/%d\n", ran as i64, ran as i64);
}
