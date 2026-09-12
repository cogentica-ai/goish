// pprof_proto_ref_smoke — profile.proto bytes, against Go's own
// encoder (issue #9).
//
// `go tool pprof` accepting a profile proves it is VALID, not that it
// matches. Two encoders can both satisfy the tool and differ: Go omits
// proto3 zero values, packs a repeated varint only above two elements,
// and — the one that actually bit — builds the string table in a fixed
// TRAVERSAL order that has nothing to do with the order a caller
// mentions strings.
//
// The first version of goish's encoder let the caller intern. Its output
// was the same 182 bytes, `go tool pprof -top` printed the correct
// numbers, and every single string index was permuted. That is why this
// file pins BYTES and not a parse: the tool resolves indexes, so it
// cannot see the difference.
//
// `Profile::pre_encode` now follows Go's order (encode.go:20) — "" at
// index 0, then every sample_type's type and unit, then mappings, then
// every function's name, system name and filename, then
// DropFrames/KeepFrames, then period_type — and the output is
// byte-identical for the profile below.
//
// GO[] is the hex from tools/gen_pprof_proto_ref.go, which builds the
// same profile through `internal/profile` under scripts/goref.sh.
// Verified out-of-band: `go tool pprof -top` on these bytes reports
// 70ms in main.work and 30ms flat / 100ms cumulative in main.main,
// which is what the two samples encode.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use goish::fmt;
use goish::gostring::string;
use goish::runtime::pprof::proto::{Function, Line, Location, Profile, Sample, ValueType};

static FAILED: AtomicUsize = AtomicUsize::new(0);

/// Go's bytes, 16 per row exactly as the generator prints them.
const GO: [&str; 12] = [
    "0a04080110020a0408031004120b0801",
    "080210071080bbb02112090802100310",
    "8087a70e220b08011880202204080110",
    "0c220b08021880402204080210162a0a",
    "0801100518052006280a2a0a08021007",
    "1807200628143200320773616d706c65",
    "733205636f756e743203637075320b6e",
    "616e6f7365636f6e647332096d61696e",
    "2e776f726b32092f746d702f782e676f",
    "32096d61696e2e6d61696e488080a8b1",
    "e39fe7cb17508094ebdc035a04080310",
    "046080ade204",
];

fn sv(s: &str) -> string {
    return string::from(s);
}

/// The same profile tools/gen_pprof_proto_ref.go builds in Go.
fn build() -> Profile {
    let mut p = Profile::new();
    p.sample_type.push(ValueType { ty: sv("samples"), unit: sv("count") });
    p.sample_type.push(ValueType { ty: sv("cpu"), unit: sv("nanoseconds") });
    p.period_type = Some(ValueType { ty: sv("cpu"), unit: sv("nanoseconds") });
    p.period = 10_000_000;
    p.time_nanos = 1_700_000_000_000_000_000;
    p.duration_nanos = 1_000_000_000;

    p.function.push(Function {
        id: 1,
        name: sv("main.work"),
        system_name: sv("main.work"),
        filename: sv("/tmp/x.go"),
        start_line: 10,
    });
    p.function.push(Function {
        id: 2,
        name: sv("main.main"),
        system_name: sv("main.main"),
        filename: sv("/tmp/x.go"),
        start_line: 20,
    });
    p.location.push(Location {
        id: 1,
        address: 0x1000,
        line: vec![Line { function_id: 1, line: 12 }],
    });
    p.location.push(Location {
        id: 2,
        address: 0x2000,
        line: vec![Line { function_id: 2, line: 22 }],
    });
    // Leaf first, as profile.proto requires: sample 1 was taken inside
    // work() called from main(); sample 2 directly in main().
    p.sample.push(Sample { location_id: vec![1, 2], value: vec![7, 70_000_000] });
    p.sample.push(Sample { location_id: vec![2], value: vec![3, 30_000_000] });
    return p;
}

fn hex_rows(b: &[u8]) -> alloc::vec::Vec<string> {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut out: alloc::vec::Vec<string> = alloc::vec::Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        let end = if i + 16 < b.len() { i + 16 } else { b.len() };
        let mut row: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        for &byte in &b[i..end] {
            row.push(D[(byte >> 4) as usize]);
            row.push(D[(byte & 0xf) as usize]);
        }
        out.push(string::from_bytes(&row));
        i = end;
    }
    return out;
}

fn fail(msg: &string) {
    fmt::Printf!("[!!] %s\n", msg);
    FAILED.fetch_add(1, Ordering::Relaxed);
}

#[goish::main]
fn main() {
    let p = build();
    let raw = p.marshal();
    let rows = hex_rows(raw.as_ref());

    if rows.len() != GO.len() {
        fail(&fmt::Sprintf!(
            "row count: got %d, Go wrote %d (len %d bytes)",
            rows.len() as i64,
            GO.len() as i64,
            raw.Len() as i64
        ));
    }
    let n = if rows.len() < GO.len() { rows.len() } else { GO.len() };
    let mut bad = 0usize;
    for i in 0..n {
        if rows[i] == GO[i] {
            fmt::Printf!("[ok] %04x %s\n", (i * 16) as i64, rows[i]);
        } else {
            bad += 1;
            fmt::Printf!(
                "[!!] %04x\n  got  %s\n  want %s\n",
                (i * 16) as i64,
                rows[i],
                GO[i]
            );
            FAILED.fetch_add(1, Ordering::Relaxed);
        }
    }
    if bad == 0 && rows.len() == GO.len() {
        fmt::Printf!("[ok] byte-identical to Go, %d bytes\n", raw.Len() as i64);
    }

    // The gzip envelope is what `Profile.WriteTo(w, 0)` must emit. pprof
    // accepts the raw form too, so a missing gzip passes every local
    // check and differs from Go on the wire — assert the magic.
    let (gz, err) = goish::runtime::pprof::proto::marshal_gzip(&p);
    if !err.IsNil() {
        fail(&fmt::Sprintf!("gzip failed: %s", err.Error()));
    } else {
        let b = gz.as_ref();
        if b.len() > 2 && b[0] == 0x1f && b[1] == 0x8b {
            fmt::Printf!("[ok] gzip envelope, %d bytes\n", b.len() as i64);
        } else {
            fail(&string::from_static("gzip magic missing"));
        }
    }

    let f = FAILED.load(Ordering::Relaxed);
    if f != 0 {
        fmt::Printf!("\nFAILED %d check(s)\n", f as i64);
        goish::os::Exit(1);
    }
    fmt::Printf!("\nok\n");
}
