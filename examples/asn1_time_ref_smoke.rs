// asn1_time_ref_smoke — ASN.1 UTCTime and GeneralizedTime parsing.
//
// Reference: Go 1.25.5 encoding/asn1, measured by
// tools/gen_asn1_time_ref.go. Every GO[] line is Go's verbatim output,
// error text included.
//
// These two functions decide when a certificate starts and stops being
// valid. A parser that reads an offset differently from the CA that
// wrote it disagrees about the validity window by exactly that
// offset — which is how a certificate is honoured after it expires,
// or refused before it should be.
//
// This one is worth more than the other orphaned generators, because
// it guards a divergence that was FOUND AND FIXED with nothing holding
// it. asn1.rs records it as a CLOSED DIVERGENCE: both parsers used to
// reject a numeric zone offset that Go accepts. The bodies were always
// verbatim ports; the cause was underneath, in `time` — goish's Time
// carried no Location, so `Zone()` was hard-wired to ("UTC", 0), an
// offset could not be retained, and Go's own re-Format-and-compare
// guard (which both functions run) re-rendered the input as the Z form
// and rejected it. Giving time::Location a name and a fixed offset
// closed it. Until now, nothing in CI would have noticed it reopening.
//
// The `zone=("",-25200)` lines are the assertion that matters: an
// offset zone has an EMPTY name and a numeric offset, and is not
// silently normalised to UTC. Note "910506234540+0000", which Go
// REFUSES even though +0000 and Z are the same instant — the
// serialize-back guard demands the canonical spelling, so agreeing
// about the instant is not enough.
//
// The rest cover the boundaries: two-digit years either side of the
// 1950/2049 pivot, minute-precision offsets (+0607), fractional
// seconds with and without an offset, seconds-optional UTCTime, and
// the truncated forms ("+07", no zone at all) that must fail. The
// error strings are pinned verbatim because they name the layout, and
// a layout change is exactly the kind of edit that would break these
// parsers quietly.

#![no_std]
#![no_main]
extern crate alloc;
extern crate goish;

use goish::encoding::asn1;
use goish::fmt;

// Go's verbatim output.
const GO: [&str; 16] = [
    "utc  \"910506234540Z\"      unix=673573540    fmt=\"1991-05-06T23:45:40Z\" zone=(\"UTC\",0) year=1991 hour=23",
    "utc  \"910506234540-0700\"  unix=673598740    fmt=\"1991-05-06T23:45:40-07:00\" zone=(\"\",-25200) year=1991 hour=23",
    "utc  \"910506234540+0000\"  err=asn1: time did not serialize back to the original value and may be invalid: given \"910506234540+0000\", but serialized as \"910506234540Z\"",
    "utc  \"9105062345Z\"        unix=673573500    fmt=\"1991-05-06T23:45:00Z\" zone=(\"UTC\",0) year=1991 hour=23",
    "utc  \"9105062345-0700\"    unix=673598700    fmt=\"1991-05-06T23:45:00-07:00\" zone=(\"\",-25200) year=1991 hour=23",
    "utc  \"500506234540Z\"      unix=-620266460   fmt=\"1950-05-06T23:45:40Z\" zone=(\"UTC\",0) year=1950 hour=23",
    "utc  \"491231235959Z\"      unix=2524607999   fmt=\"2049-12-31T23:59:59Z\" zone=(\"UTC\",0) year=2049 hour=23",
    "utc  \"910506234540\"       err=parsing time \"910506234540\" as \"060102150405Z0700\": cannot parse \"\" as \"Z0700\"",
    "utc  \"910506234540-07\"    err=parsing time \"910506234540-07\" as \"060102150405Z0700\": cannot parse \"-07\" as \"Z0700\"",
    "gen  \"20100102030405Z\"          unix=1262401445   nano=0            fmt=\"2010-01-02T03:04:05Z\" zone=(\"UTC\",0) hour=3",
    "gen  \"20100102030405+0607\"      unix=1262379425   nano=0            fmt=\"2010-01-02T03:04:05+06:07\" zone=(\"\",22020) hour=3",
    "gen  \"20100102030405-0607\"      unix=1262423465   nano=0            fmt=\"2010-01-02T03:04:05-06:07\" zone=(\"\",-22020) hour=3",
    "gen  \"20100102030405.123Z\"      unix=1262401445   nano=123000000    fmt=\"2010-01-02T03:04:05.123Z\" zone=(\"UTC\",0) hour=3",
    "gen  \"20100102030405.123+0607\"  unix=1262379425   nano=123000000    fmt=\"2010-01-02T03:04:05.123+06:07\" zone=(\"\",22020) hour=3",
    "gen  \"20100102030405\"           err=parsing time \"20100102030405\" as \"20060102150405.999999999Z0700\": cannot parse \"\" as \"Z0700\"",
    "gen  \"20100102030405+06\"        err=parsing time \"20100102030405+06\" as \"20060102150405.999999999Z0700\": cannot parse \"+06\" as \"Z0700\"",
];

static FAILED: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
static LN: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

fn chk(got: goish::string) {
    use core::sync::atomic::Ordering;
    let i = LN.fetch_add(1, Ordering::Relaxed);
    let g: &str = got.as_ref();
    if i >= GO.len() {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!("[!!] extra line %d: %s\n", i as i64, got);
        return;
    }
    if g == GO[i] {
        fmt::Printf!("ok   %s\n", got);
    } else {
        FAILED.fetch_add(1, Ordering::Relaxed);
        fmt::Printf!(
            "[!!] line %d\n  got:  %s\n  want: %s\n",
            i as i64,
            got,
            goish::string(GO[i])
        );
    }
}

fn bs(s: &str) -> goish::slice<goish::byte> {
    goish::slice::<goish::byte>::__from_vec(s.as_bytes().to_vec())
}

#[goish::main]
fn main() {
    let utc: [&str; 9] = [
        "910506234540Z",
        "910506234540-0700",
        "910506234540+0000",
        "9105062345Z",
        "9105062345-0700",
        "500506234540Z",
        "491231235959Z",
        "910506234540",
        "910506234540-07",
    ];
    for s in utc.iter() {
        let shown = goish::string::from_bytes(s.as_bytes());
        let (tm, err) = asn1::ParseUTCTime(bs(s));
        if !err.IsNil() {
            chk(fmt::Sprintf!("utc  %-20q err=%v", shown, err));
            continue;
        }
        let (zn, zo) = tm.Zone();
        chk(fmt::Sprintf!(
            "utc  %-20q unix=%-12d fmt=%q zone=(%q,%d) year=%d hour=%d",
            shown,
            tm.Unix(),
            tm.Format(goish::string("2006-01-02T15:04:05Z07:00")),
            zn,
            zo as i64,
            tm.Year() as i64,
            tm.Hour() as i64
        ));
    }

    let gen: [&str; 7] = [
        "20100102030405Z",
        "20100102030405+0607",
        "20100102030405-0607",
        "20100102030405.123Z",
        "20100102030405.123+0607",
        "20100102030405",
        "20100102030405+06",
    ];
    for s in gen.iter() {
        let shown = goish::string::from_bytes(s.as_bytes());
        let (tm, err) = asn1::ParseGeneralizedTime(bs(s));
        if !err.IsNil() {
            chk(fmt::Sprintf!("gen  %-26q err=%v", shown, err));
            continue;
        }
        let (zn, zo) = tm.Zone();
        chk(fmt::Sprintf!(
            "gen  %-26q unix=%-12d nano=%-12d fmt=%q zone=(%q,%d) hour=%d",
            shown,
            tm.Unix(),
            tm.Nanosecond() as i64,
            tm.Format(goish::string("2006-01-02T15:04:05.999999999Z07:00")),
            zn,
            zo as i64,
            tm.Hour() as i64
        ));
    }

    use core::sync::atomic::Ordering;
    let f = FAILED.load(Ordering::Relaxed);
    let n = LN.load(Ordering::Relaxed);
    if f == 0 && n == GO.len() {
        fmt::Printf!("\nok %d/%d\n", n as i64, GO.len() as i64);
        goish::os::Exit(0);
    }
    fmt::Printf!(
        "\nFAILED %d of %d (%d lines)\n",
        f as i64,
        GO.len() as i64,
        n as i64
    );
    goish::os::Exit(1);
}
