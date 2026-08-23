// go: file testing/newcover.go decls: coverReport, registerCover, Coverage
//
// testing/newcover.go — the coverage-reporting surface.
//
// **Partial port, and permanently so.** Coverage counters are emitted
// by cmd/compile under `-cover`; a library cannot arrange that.
// `Coverage` takes Go's own "coverage not enabled" branch, and
// `registerCover` is ported in full — it is the seam the compiler's
// generated main would call through, and it correctly does nothing
// when handed the empty mode that goish's InitRuntimeCoverage returns.
//
// goishlint:ignore GOISH018 RegisterCover, InitRuntimeCoverage, ResetCoverage, SnapshotCoverage, mustBeNil — all drive counters the compiler does not emit here.
// goishlint:ignore GOISH021 goCoverTearDown, coverReport2 — same.

#![allow(non_snake_case)]

extern crate alloc;

// go: sdk 1.25.5 testing/newcover.go:54-59 Coverage
/// Go: "Coverage reports the current code coverage as a fraction in the
/// range [0, 1]. If coverage is not enabled, Coverage returns 0."
///
/// Coverage is never enabled here — see `CoverMode` — so this takes
/// Go's own `cover.mode == ""` branch and returns 0.
pub fn Coverage() -> crate::types::float64 {
    // Go: if cover.mode == "" { return 0.0 }
    return 0.0;
}

// go: sdk 1.25.5 testing/newcover.go:17-21 cover
/// Go: "cover variable stores the current coverage mode and a tear-down
/// function to be called at the end of the testing run."
/// Read by `Coverage`, `coverReport` and `M.after` in Go. None of the
/// three can be ported here, so the fields are recorded and not yet
/// consulted — the alternative is dropping them and having
/// registerCover silently lose what it was handed.
#[allow(dead_code)]
pub(crate) struct CoverState {
    pub mode: crate::gostring::string,
    pub tearDown: Option<crate::testing::testing::TearDownFunc>,
    pub snapshotcov: Option<crate::testing::testing::SnapCovFunc>,
}

pub(crate) static cover: crate::sync::Mutex<Option<CoverState>> = crate::sync::Mutex::new(None);

// go: sdk 1.25.5 testing/newcover.go:26-34 registerCover
/// Go: "registerCover is invoked during 'go test -cover' runs. It is
/// used to record a 'tear down' function (to be called when the test is
/// complete) and the coverage mode."
///
/// The empty-mode early return is the whole reason this is portable:
/// goish's `InitRuntimeCoverage` returns `("", nil, nil)`, so
/// registerCover records nothing and every later `cover.mode == ""`
/// check takes the not-enabled branch. Porting it means MainStart can
/// call it exactly as Go does rather than skipping a line.
pub(crate) fn registerCover(
    mode: crate::gostring::string,
    tearDown: Option<crate::testing::testing::TearDownFunc>,
    snapcov: Option<crate::testing::testing::SnapCovFunc>,
) {
    if mode.Len() == 0 {
        return;
    }
    *cover.Lock() = Some(CoverState {
        mode,
        tearDown,
        snapshotcov: snapcov,
    });
}

// go: sdk 1.25.5 testing/newcover.go:40-45 coverReport
/// Go: "coverReport reports the coverage percentage and writes a
/// coverage profile if requested."
///
/// Go dereferences `cover.tearDown` unconditionally, because the driver
/// only calls coverReport when `cover.mode != ""` — which, per
/// registerCover, is the only way tearDown is ever set. goish keeps the
/// same precondition and treats an unset teardown as "nothing
/// registered", the state a non-coverage build is always in.
/// Called by `M.after` in Go, which is not ported — its body is
/// profiling teardown. Kept live and anchored so that when a coverage
/// story exists there is nothing to re-derive.
#[allow(non_snake_case, dead_code)]
pub(crate) fn coverReport() {
    let g = cover.Lock();
    let st = match g.as_ref() {
        Some(st) => st,
        None => return,
    };
    let tearDown = match st.tearDown.as_ref() {
        Some(f) => f,
        None => return,
    };

    let (coverProfile, gocoverdir) = crate::testing::testing::__cover_paths();
    let (errmsg, err) = tearDown(coverProfile, gocoverdir);
    if err != crate::errors::nil {
        let msg = crate::fmt::Sprintf!("%s: %v\n", errmsg, err.Error());
        let b = msg.as_bytes().to_vec();
        crate::syscall::Write(crate::syscall::STDERR, b.as_ptr(), b.len());
        crate::syscall::Exit(2);
    }
}
