// fips140_tls13_smoke — the TLS 1.3 key schedule of RFC 8446 §7.1, i.e.
// everything the crypto/internal/fips140/tls13 extraction added.
//
// Every expectation comes from an independent Python HKDF key schedule
// built straight from RFC 8446 §7.1. That reference is pinned first
// against the two widely published constants for a no-PSK SHA-256
// handshake:
//
//   Early Secret = HKDF-Extract(0, 0)
//                = 33ad0a1c…f170f92a
//   Derive-Secret(Early Secret, "derived", "")
//                = 6f2615a1…6c3611ba
//
// Both matched byte-for-byte, which validates Extract, Expand-Label and
// Derive-Secret; the rest of the chain is generated from there.
//
// The transcripts are synthetic byte strings rather than a real
// handshake — the key schedule only ever sees Transcript-Hash output, so
// what was hashed is irrelevant to what is being tested.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::crypto::internal::fips140::sha256;
use goish::crypto::internal::fips140::sha512;
use goish::crypto::internal::fips140::tls13;
use goish::encoding::hex;
use goish::fmt;
use goish::goslice::slice;
use goish::io;
use goish::types::byte;

static mut FAILED: bool = false;

fn check(name: &str, got: goish::string, want: &str) {
    if got == goish::string::from(want) {
        fmt::Printf!("PASS: %s\n", goish::string::from(name));
    } else {
        fmt::Printf!(
            "FAIL: %s\n  got  %s\n  want %s\n",
            goish::string::from(name),
            got,
            goish::string::from(want)
        );
        unsafe { FAILED = true };
    }
}

fn b(s: &str) -> slice<byte> {
    return slice::__from_vec(s.as_bytes().to_vec());
}

fn empty() -> slice<byte> {
    return slice::__from_vec(Vec::new());
}

fn hx(s: &slice<byte>) -> goish::string {
    let r: &[byte] = s;
    return hex::EncodeToString(r);
}

/// A SHA-256 transcript hash fed the given bytes.
fn tr256(msgs: &str) -> sha256::Digest {
    let mut h = sha256::New();
    let _ = io::Writer::Write(&mut h, b(msgs));
    return h;
}

fn tr384(msgs: &str) -> sha512::Digest {
    let mut h = sha512::New384();
    let _ = io::Writer::Write(&mut h, b(msgs));
    return h;
}

const CH: &str = "ClientHello bytes";
const SH: &str = "ClientHello bytes|ServerHello bytes";
const SF: &str = "ClientHello bytes|ServerHello bytes|...server Finished";
const CF: &str = "ClientHello bytes|ServerHello bytes|...server Finished|...client Finished";

#[goish::main]
fn main() {
    // ── HKDF-Expand-Label on its own ──────────────────────────────────
    let secret = slice::__from_vec((0u8..32).collect::<Vec<byte>>());
    check(
        "ExpandLabel(\"key\", 16)",
        hx(&tls13::ExpandLabel(
            sha256::NewHash,
            secret,
            "key",
            slice::__from_vec(alloc::vec![0xaau8, 0xbb]),
            16,
        )),
        "fb6ce433e76fe28edb567bc8a3cd9268",
    );

    // ── Early Secret, no PSK ──────────────────────────────────────────
    let early = tls13::NewEarlySecret(sha256::NewHash, empty());
    check(
        "ResumptionBinderKey",
        hx(&early.ResumptionBinderKey()),
        "feb866868b62f7e0d14c2547bae6c86d16c6db9d7e8af4e4ba1652b69fee9ba0",
    );

    let t = tr256(CH);
    check(
        "ClientEarlyTrafficSecret",
        hx(&early.ClientEarlyTrafficSecret(&t)),
        "925b74dabf1fe87128506ad5d259f540ade847994dc6d49c40a034ae1a3df914",
    );

    let eems = early.EarlyExporterMasterSecret(&t);
    check(
        "EarlyExporterMasterSecret",
        hx(&tls13::TestingOnlyExporterSecret(&eems)),
        "9c7e59a9d5b57640e781297b3b2896e03dc364d54755d93ec9092026212d403a",
    );

    // A non-empty PSK must take the other branch of extract().
    let psk = slice::__from_vec(alloc::vec![0x0au8; 32]);
    check(
        "ResumptionBinderKey with a PSK",
        hx(&tls13::NewEarlySecret(sha256::NewHash, psk).ResumptionBinderKey()),
        "8c7c5e1f5e438dfa6489f22cf830e3a406449f12e4163a02a8f9402233359498",
    );

    // ── Handshake Secret ──────────────────────────────────────────────
    let shared = slice::__from_vec((1u8..33).collect::<Vec<byte>>());
    let hs = early.HandshakeSecret(shared);
    let t = tr256(SH);
    check(
        "ClientHandshakeTrafficSecret",
        hx(&hs.ClientHandshakeTrafficSecret(&t)),
        "5a61fa7bda7136c8c590fafcf3d107df65306ed550ff96d2faaad8d9725f2efb",
    );
    check(
        "ServerHandshakeTrafficSecret",
        hx(&hs.ServerHandshakeTrafficSecret(&t)),
        "0c1ce505519aa7042d10d8b896a0fbc056bf38c660a1102074dc507304012347",
    );

    // ── Master Secret ─────────────────────────────────────────────────
    let ms = hs.MasterSecret();
    let t = tr256(SF);
    check(
        "ClientApplicationTrafficSecret",
        hx(&ms.ClientApplicationTrafficSecret(&t)),
        "a60be21aea49f10cfab8985bdb9d0bb5367a9c271455c6235aad4816e86f9aa4",
    );
    check(
        "ServerApplicationTrafficSecret",
        hx(&ms.ServerApplicationTrafficSecret(&t)),
        "5a564e3279c87f93af791a2756f96d903e97dc7039a34f43e43fcb6522b77218",
    );

    let tc = tr256(CF);
    check(
        "ResumptionMasterSecret",
        hx(&ms.ResumptionMasterSecret(&tc)),
        "25ae433ce2f5d371679cfad3d13251b4efd661ef2a004b6f26f0f90a3c6e1091",
    );

    // ── Exporters (RFC 8446 §7.5) ─────────────────────────────────────
    let ems = ms.ExporterMasterSecret(&t);
    check(
        "ExporterMasterSecret",
        hx(&tls13::TestingOnlyExporterSecret(&ems)),
        "d46c7fa9b7b5bd42cb5a70d03a6fa7c91d5766df4a0e4f577a0942d0620de9d4",
    );
    check(
        "Exporter, 32 bytes",
        hx(&ems.Exporter("EXPORTER-test", b("exporter context"), 32)),
        "eb01ad6e8f3e6c06a0eb187259baf9c2a451de53bb72527c97970f5e2eee79e0",
    );
    // 57 bytes crosses the HKDF-Expand block boundary twice.
    check(
        "Exporter, 57 bytes",
        hx(&ems.Exporter("EXPORTER-test", b("exporter context"), 57)),
        "767e8fc79bf1f3b3601b79cffb79a87b526b32dfa8e7b06854410c6930035692\
         d307d2643542b909d1eb22458a102f0ee1dc780f42ab1bd672",
    );

    // ── The same schedule at SHA-384 ──────────────────────────────────
    //
    // Everything above would still pass if the hash length were hard
    // coded at 32; these two would not.
    let early4 = tls13::NewEarlySecret(sha512::NewHash384, empty());
    check(
        "SHA-384 ResumptionBinderKey",
        hx(&early4.ResumptionBinderKey()),
        "51069a579b404b6885ec66bd8fc96b477c2de324814b8f945459937f004c661c\
         b533419e78789bd56551503b48217b73",
    );
    let hs4 = early4.HandshakeSecret(slice::__from_vec((1u8..49).collect::<Vec<byte>>()));
    let t4 = tr384(SH);
    check(
        "SHA-384 ServerHandshakeTrafficSecret",
        hx(&hs4.ServerHandshakeTrafficSecret(&t4)),
        "b4dad47912769cdb632a5a2998eea7e39a5e05118ed1a02c5cbc228855676518\
         cfcf7efe54f1973a099e33f8b1965227",
    );

    // A too-long context must panic rather than silently truncate the
    // one-byte length prefix — only the bound is exercised here.
    check(
        "context length bound is 255",
        fmt::Sprintf!(
            "%d",
            tls13::ExpandLabel(
                sha256::NewHash,
                b("s"),
                "l",
                slice::__from_vec(alloc::vec![0u8; 255]),
                4,
            )
            .Len()
        ),
        "4",
    );

    if unsafe { FAILED } {
        goish::syscall::Exit(1);
    }
    fmt::Printf!("fips140_tls13_smoke OK\n");
}
