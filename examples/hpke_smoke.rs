// hpke_smoke — crypto/internal/hpke, RFC 9180 Hybrid Public Key
// Encryption as used by TLS Encrypted Client Hello.
//
// SetupSender generates an ephemeral key, so its output is not comparable
// to Go's. SetupRecipient is: the encapsulated key and ciphertexts below
// are what Go produced for a fixed recipient key, and goish must decrypt
// exactly those. That exercises the whole path — X25519 ECDH, the labeled
// HKDF extract/expand chain, the key schedule, and AES-GCM — because a
// wrong byte anywhere yields authentication failure rather than a wrong
// plaintext.
//
// The second message matters on its own: it is what advances the sequence
// number through uint128 and derives a different nonce. Decrypting both in
// order is the only way to see that from outside the package.
//
// Values from scripts/goref.sh (AGENTS.md §10).

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use goish::crypto::internal::hpke;
use goish::encoding::hex;
use goish::fmt;
use goish::goslice::slice;
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

fn hx(s: &slice<byte>) -> goish::string {
    let r: &[byte] = s;
    return hex::EncodeToString(r);
}

fn unhex(h: &str) -> slice<byte> {
    let b = h.as_bytes();
    let mut out: Vec<byte> = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i < b.len() {
        out.push((nib(b[i]) << 4) | nib(b[i + 1]));
        i += 2;
    }
    return slice::__from_vec(out);
}

fn nib(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("unhex"),
    }
}

fn bytesOf(s: &str) -> slice<byte> {
    return slice::__from_vec(s.as_bytes().to_vec());
}

#[goish::main]
fn main() {
    let skR = unhex("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8");
    let (priv_, err) = hpke::ParseHPKEPrivateKey(hpke::DHKEM_X25519_HKDF_SHA256, &skR);
    check(
        "ParseHPKEPrivateKey err",
        fmt::Sprintf!("%v", err != goish::nil),
        "false",
    );
    let pubKey = priv_.PublicKey();
    check("recipient public key", hx(&pubKey.Bytes()), PKR);

    let info = bytesOf("goish hpke info");
    let aad = bytesOf("aad");

    // Decrypt what Go encrypted, in order.
    let encap = unhex(ENCAP);
    let (recip, err) = hpke::SetupRecipient(
        hpke::DHKEM_X25519_HKDF_SHA256,
        hpke::KDF_HKDF_SHA256,
        hpke::AEAD_AES_128_GCM,
        &priv_,
        &info,
        &encap,
    );
    check(
        "SetupRecipient err",
        fmt::Sprintf!("%v", err != goish::nil),
        "false",
    );
    let mut recip = recip.unwrap();

    let (pt, err) = recip.Open(&aad, &unhex(CT));
    check("Open err", fmt::Sprintf!("%v", err != goish::nil), "false");
    check(
        "decrypted Go's first message",
        goish::string::from_bytes(&pt),
        "hello hpke",
    );

    let (pt2, err) = recip.Open(&aad, &unhex(CT2));
    check(
        "Open (2nd) err",
        fmt::Sprintf!("%v", err != goish::nil),
        "false",
    );
    check(
        "decrypted Go's second message (nonce advanced)",
        goish::string::from_bytes(&pt2),
        "hello hpke",
    );

    // A wrong AAD must fail authentication, not decrypt.
    let (recip2, _) = hpke::SetupRecipient(
        hpke::DHKEM_X25519_HKDF_SHA256,
        hpke::KDF_HKDF_SHA256,
        hpke::AEAD_AES_128_GCM,
        &priv_,
        &info,
        &encap,
    );
    let mut recip2 = recip2.unwrap();
    let (_, err) = recip2.Open(&bytesOf("wrong"), &unhex(CT));
    check(
        "wrong AAD rejected",
        fmt::Sprintf!("%v", err != goish::nil),
        "true",
    );

    // goish's own round trip: the sender half is randomized, so it is
    // checked by the property that it must decrypt.
    let (encapG, sender, err) = hpke::SetupSender(
        hpke::DHKEM_X25519_HKDF_SHA256,
        hpke::KDF_HKDF_SHA256,
        hpke::AEAD_AES_128_GCM,
        &pubKey,
        &info,
    );
    check(
        "SetupSender err",
        fmt::Sprintf!("%v", err != goish::nil),
        "false",
    );
    check(
        "encapsulated key is 32 bytes",
        fmt::Sprintf!("%d", encapG.Len()),
        "32",
    );
    let mut sender = sender.unwrap();
    let (ctG, _) = sender.Seal(&aad, &bytesOf("round trip"));
    let (recipG, _) = hpke::SetupRecipient(
        hpke::DHKEM_X25519_HKDF_SHA256,
        hpke::KDF_HKDF_SHA256,
        hpke::AEAD_AES_128_GCM,
        &priv_,
        &info,
        &encapG,
    );
    let mut recipG = recipG.unwrap();
    let (ptG, err) = recipG.Open(&aad, &ctG);
    check(
        "round trip err",
        fmt::Sprintf!("%v", err != goish::nil),
        "false",
    );
    check(
        "goish sender round trip",
        goish::string::from_bytes(&ptG),
        "round trip",
    );

    // Unsupported suite ids.
    let (_, _, err) = hpke::SetupSender(
        0x9999,
        hpke::KDF_HKDF_SHA256,
        hpke::AEAD_AES_128_GCM,
        &pubKey,
        &info,
    );
    check(
        "unsupported KEM rejected",
        fmt::Sprintf!("%v", err.Error()),
        "unsupported suite ID",
    );
    let (_, _, err) = hpke::SetupSender(
        hpke::DHKEM_X25519_HKDF_SHA256,
        0x9999,
        hpke::AEAD_AES_128_GCM,
        &pubKey,
        &info,
    );
    check(
        "unsupported KDF rejected",
        fmt::Sprintf!("%v", err.Error()),
        "unsupported KDF id",
    );

    if unsafe { FAILED } {
        goish::syscall::Exit(1);
    }
    fmt::Printf!("hpke_smoke OK\n");
}

const PKR: &str = "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d";
const ENCAP: &str = "f57f5fd71d881d855dfe86c96858b05545796770ce67d801a55a3c4b43435261";
const CT: &str = "c2094a9935d08c7c89ce5d8eb4f04f1779620786b623c2b40cb3";
const CT2: &str = "7bc981fbc522131d7aded66d6e03c1b663a35a8413cdd51fcf9f";
