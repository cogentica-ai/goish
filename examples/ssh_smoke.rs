// ssh_smoke.rs — unit tests for crypto::ssh helpers.
//
// Tests that don't require a real SSH server:
//   1. KEXINIT build / cookie presence
//   2. DH group14 with x=1 gives e=2
//   3. Key derivation produces distinct 32-byte keys
//   4. AES-128-CTR round-trip (encrypt then decrypt gives original)
//   5. HMAC-SHA2-256 produces 32-byte output
//   6. mpint encoding with high bit set adds zero prefix

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;

use goish::fmt;
use goish::syscall;
use goish::testing;
use goish::crypto::ssh;
use goish::int32;

#[goish::main]
fn main() {
    let tests: &[(&str, testing::TestFn)] = &[
        ("TestKexinitRoundtrip", test_kexinit_roundtrip),
        ("TestDhGroup14SmallExp", test_dh_group14_small_exp),
        ("TestKeyDerivation", test_key_derivation),
        ("TestPacketFraming", test_packet_framing),
        ("TestHmacSha256", test_hmac_sha256),
        ("TestMpintEncoding", test_mpint_encoding),
    ];
    let code = testing::Main(tests);
    syscall::Exit(int32(code));
}

fn test_kexinit_roundtrip(t: &mut testing::T) {
    if !ssh::test_kexinit_roundtrip() {
        t.Fatal(fmt::Sprintf!("KEXINIT roundtrip failed"));
    }
}

fn test_dh_group14_small_exp(t: &mut testing::T) {
    if !ssh::test_dh_group14_small_exp() {
        t.Fatal(fmt::Sprintf!("DH group14 small exp test failed: expected e=2 for x=1"));
    }
}

fn test_key_derivation(t: &mut testing::T) {
    if !ssh::test_key_derivation() {
        t.Fatal(fmt::Sprintf!("Key derivation test failed"));
    }
}

fn test_packet_framing(t: &mut testing::T) {
    if !ssh::test_packet_framing() {
        t.Fatal(fmt::Sprintf!("Packet framing AES-CTR round-trip failed"));
    }
}

fn test_hmac_sha256(t: &mut testing::T) {
    if !ssh::test_hmac_sha256() {
        t.Fatal(fmt::Sprintf!("HMAC-SHA2-256 test failed: unexpected output length"));
    }
}

fn test_mpint_encoding(t: &mut testing::T) {
    if !ssh::test_mpint_encoding() {
        t.Fatal(fmt::Sprintf!("mpint encoding test failed: expected [0,0,0,3, 0x00, 0x80, 0x00] for input [0x80,0x00]"));
    }
}
