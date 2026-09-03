// rsa_ref_smoke — crypto/rsa against a running Go.
// (crypto/rsa/rsa.go, pkcs1v15.go, pss.go, oaep.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_rsa_ref.go` run in
// `package rsa_test` by `scripts/goref.sh`.
//
// RSA is the classic home of "accepts a forgery" bugs, because a
// PKCS#1 v1.5 signature is CHECKED by rebuilding the expected padding
// and comparing it — while an implementation that instead PARSES the
// padding, hunting for the hash somewhere inside, accepts signatures
// nobody holding the private key produced. That is Bleichenbacher's
// 2006 attack and it is still being found in new code.
//
// So the shape here is: ONE FIXED KEY, carried as PKCS#1 DER so the
// goish side loads the same key Go used, a deterministic v1.5
// signature compared BYTE FOR BYTE, and then a long list of near-miss
// byte strings that must each come back as an error. A verifier tested
// only against signatures it made itself cannot fail this kind of test,
// which is why the key is shared rather than generated on each side.
//
// One defect found, in the public-key size check. Go guards with
// `if pub.N == nil`, testing a nil *big.Int — a state distinct from a
// big.Int holding zero, which Go falls through to and reports as
// "0-bit keys are insecure". goish's `Int` is a VALUE whose
// polymorphic-nil comparison is true exactly when it is zero, so the
// two states are one, and the guard turned Go's 0-bit answer into
// "missing public modulus". A caller who built a PublicKey with an
// unset N — the reachable mistake — got a different error than Go
// gives. The nil half of Go's distinction describes a pointer goish
// cannot construct, so that is the half that was dropped.
//
// What else is pinned:
//
//   * v1.5 is DETERMINISTIC and signs with a nil random source, so the
//     signature bytes themselves are the expectation. Thirteen
//     malformed signatures follow, including the modulus itself,
//     modulus-1, and a right-shift that keeps every byte but moves
//     them — all "crypto/rsa: verification error", which is the point:
//     the message never says WHY, so a caller learns nothing a timing
//     attack could use.
//   * The hash algorithm is part of what is signed. A SHA-256
//     signature does not verify as SHA-512, and a digest of the wrong
//     length is refused with a DIFFERENT message — "input must be
//     hashed message" — before any arithmetic happens.
//   * PSS salt lengths, which decide interoperability: signing with
//     Auto and verifying with EqualsHash FAILS, because Auto uses the
//     largest salt that fits and EqualsHash demands exactly the hash
//     size. Both directions are pinned, along with the exact salt
//     length at which signing starts refusing (223 for this key).
//   * A PSS signature does not verify as v1.5 and a v1.5 signature
//     does not verify as PSS. Two schemes over one key, and the
//     schemes are not interchangeable.
//   * OAEP binds the LABEL into the ciphertext: a ciphertext made for
//     one label fails to decrypt under another, which is what stops a
//     ciphertext being replayed into a different context. The maximum
//     plaintext length is pinned exactly, and one byte over is
//     refused rather than truncated.
//   * Public keys that cannot be used: e of 0, 1, -3 and even values,
//     and moduli of 0, 1 and 3 bits, each with the exact message Go
//     returns. Note e=3 is ACCEPTED as a key and merely fails to
//     verify — small exponents are legal.
//
// What is deliberately NOT measured: `Validate` on a mutated copy of a
// generated key. It returns nil, because it short-circuits on
// `Precomputed.fips != nil` — the key was validated when it was built
// and the early-out never looks at the mutated field. That measures
// Go's cache rather than Go's rules, so the rules are reached through
// Verify instead, which is where every hostile input arrives anyway.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use alloc::vec::Vec;
use goish::crypto;
use goish::crypto::rand;
use goish::crypto::rsa;
use goish::crypto::sha256;
use goish::crypto::sha512;
use goish::crypto::x509;
use goish::encoding::hex;
use goish::errors::error;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::math::big::Int;
use goish::syscall;
use goish::types::{byte, int};
const GO: [&str; 70] = [
    "key der=308204a40201000282010100d1da40d2981174868c7cdb70b9eeedeeb30badb82976c4e2145bef66dbeed04310e3087e648df2c30db5a6aeabff299fa08a67a20958cf0c4d9a11f25e1dbe74d2143d270edb55f3f374e1901509abe00f7682cc1e5caf5e216dfa7d8e9c407a4dfb777a8c5d195c1d60bea50383b1a5ec3b1f655d937c61a3d0903c12f86de2cca374cf49a16b7b9fee79c076d217ca055524b573df0360d66b34c10d06f4ae184a6c9f81bd2b00b6170e6bd70111835a1485ee064fb538eae30f1e49c552a8728c11ede888194d27c04657446e81afaf1b2150d771d94870c91c32a045d1ee920d5e399ec1ac005bb61138ff350d8e7cf47c931893026c069c25fbf399f0f902030100010282010048f7760da3b1820e5c9ff75f394f622cdad5a7383f369c5badcf8facf8b10f7a1a4f8ebefff0b965e808eee592497d2c1352bc99035dfd541e5181870001a09d1704d18498ae5c332046563dd68acfd7ef187a7f45d95d62c205ef10a43b21524576380384f5c4211ad7ee420b3849d7530df5ab35bfd8024d46f237e932b7660127d41083b7b09725c1f7767f6b5287559f699eb57dcb9343c7ca301f8786083e12bd7b5e1cb35f750cf2e574f8d0a9e891be2fd13b2bc1a214181c1b0a28771945e00b10c82579f36480a26b8d2ed6eeb659087df42144ab5e0f94dc727278fc575ef6edbb75d5f79d69f3458cd51047291efe0a74499d17194e72b655cb5702818100e5cf520fa702859953cee3fc1c34edc95e50736dbb829d4b88ba3ff8e0dc3b796a554b17bb98b5a665bc0458fdaca939a5a1645e5d2c0ec76ca7493426d0ada273ff7d211c472aaaed0256707342c58adf755c1ad6c15ad79328ab3bb3d1b1e0f330e82962fd4a2116cfbd0aec5b25f8d886e5aaec33dcce71d48eafb67a359f02818100e9c4ae3a9a18e483e5d87e0a6c5513198d2784110f0b50a17aee4d112cfc3f2bc5041827791ea96631e8033e88e3bb6e0fd536dadff2116af93648771fdb8efc0e133c9e19613e990d7510e44ddbbf9a469077ae01c2cc2f1ac9f53b4b7b01cfb8d7898319eb6d15b0346daf69cefeb29e543b6b4e332a06bf7e4c61d3e8e26702818100c5aa4759333b961245e5e46f4b0bb3a3cabdc42b1467ca47d7f8eb617477b9a83b6fd5c13a18a5d5d4179e5db50438225f76ac500630091e3b34c0605d2a8ccef89b3ed3a5f108a030701c4d68b67c1771110f01feca1d0ae386cd91f29f6132adbad9560fd0f15bf8b502534ced3182132c248b99d31a0f7015760d691540dd02818100a7d192626f8dbf3f111a4221a973c9aa663320143f009879d48e8eb4edde885b1bacbcca59a1316b3418a37b993a23abf7a1d1277fed7fa39414ec20d8b5fe07e4f2da69853ed2797db7b4d0b1343870c087a5e33d5062d4ce1e7df67b516b137c56ff59269a644d5599cdc447e959df50da976d894e21b586735cd23e16c9b10281805e40f834d2a8e0edd940bd21a129113d699056289e916c3bd857ae5123bfa896591e9120fd6ce6bc2e591e7a4e4e2d4e6a04620b5f5bbdd41972b5af4982802c35452f09c32b92e7f9212a4718e008a4cf70fb7ee573085b773dd355045e968230769e90d1e5bd4a9888ccfa1cb6414a9862284d56a52d6368cf1f881a33a15c",
    "key bits=2048 size=256 e=65537",
    "v15 sig=2fad5257734194f8aa1a9d85248b2c38954e96e87dad2199ef4250db79f1ee2a21036d0c3332e8d4b7b3bf3b54c6c4e62549c8519f90cf4fdf1e00843b1c4ae3e042e6e213ab27b4e860edeed725dda7e6be017f0ad514eadfffa09b075550b8f2f83811b8e95b5839eabc3bb9f2655c1cbf0037ec4004ed7e040f67b8768c0b95e768c69a7138c29c3035a3b72bb627f69eabefceecb9ca1f4819537f7f41f707ddd05050683bad9a29f551cd9bb8e56a17565b941a7d7e93be5835b2d6bb2ae92fa4add0483cfb5ece190648093dddc3570fcea0a0dd84a90e7baff4fac17385c982bd5d6f79f3efcbf1083d416bc378243381b89fc3ff35d61b2706a6217e",
    "v15 deterministic=true nil-rand-ok=true",
    "v15 verify=<nil>",
    "v15bad nil                  -> err=crypto/rsa: verification error",
    "v15bad empty                -> err=crypto/rsa: verification error",
    "v15bad short-by-one         -> err=crypto/rsa: verification error",
    "v15bad long-by-one          -> err=crypto/rsa: verification error",
    "v15bad all-zero             -> err=crypto/rsa: verification error",
    "v15bad all-ff               -> err=crypto/rsa: verification error",
    "v15bad one                  -> err=crypto/rsa: verification error",
    "v15bad modulus              -> err=crypto/rsa: verification error",
    "v15bad modulus-minus-1      -> err=crypto/rsa: verification error",
    "v15bad flip-first           -> err=crypto/rsa: verification error",
    "v15bad flip-last            -> err=crypto/rsa: verification error",
    "v15bad flip-middle          -> err=crypto/rsa: verification error",
    "v15bad leading-zero-shift   -> err=crypto/rsa: verification error",
    "v15hash right                  -> err=<nil>",
    "v15hash wrong-alg-sha512       -> err=crypto/rsa: verification error",
    "v15hash wrong-alg-sha512-256d  -> err=crypto/rsa: input must be hashed message",
    "v15hash sha256-short-digest    -> err=crypto/rsa: input must be hashed message",
    "v15hash sha256-long-digest     -> err=crypto/rsa: input must be hashed message",
    "v15hash sha256-empty-digest    -> err=crypto/rsa: input must be hashed message",
    "v15hash hash-zero              -> err=crypto/rsa: verification error",
    "v15hash hash-zero-empty        -> err=crypto/rsa: verification error",
    "pss auto           -> len=256 auto=<nil> equals=crypto/rsa: verification error",
    "pss equals-hash    -> len=256 auto=<nil> equals=<nil>",
    "pss explicit-0     -> len=256 auto=<nil> equals=crypto/rsa: verification error",
    "pss explicit-32    -> len=256 auto=<nil> equals=<nil>",
    "pss explicit-222   -> len=256 auto=<nil> equals=crypto/rsa: verification error",
    "pss explicit-223   -> sign-err=crypto/rsa: message too long for RSA key size",
    "pss explicit-1000  -> sign-err=crypto/rsa: message too long for RSA key size",
    "pss nil-opts -> len=256 verify=<nil>",
    "pssbad nil              -> err=crypto/rsa: verification error",
    "pssbad empty            -> err=crypto/rsa: verification error",
    "pssbad flip-first       -> err=crypto/rsa: verification error",
    "pssbad flip-last        -> err=crypto/rsa: verification error",
    "pssbad short            -> err=crypto/rsa: verification error",
    "pssbad long             -> err=crypto/rsa: verification error",
    "pssbad all-zero         -> err=crypto/rsa: verification error",
    "pssbad v15-sig-as-pss   -> err=crypto/rsa: verification error",
    "pss as-v15=crypto/rsa: verification error",
    "oaep no-label   -> ctlen=256 same=true err=<nil>",
    "oaep no-label   -> wrong-label n=0 err=crypto/rsa: decryption error",
    "oaepbad no-label flip-first   -> err=crypto/rsa: decryption error",
    "oaepbad no-label flip-last    -> err=crypto/rsa: decryption error",
    "oaepbad no-label short        -> err=crypto/rsa: decryption error",
    "oaepbad no-label long         -> err=crypto/rsa: decryption error",
    "oaepbad no-label all-zero     -> err=crypto/rsa: decryption error",
    "oaep label-a    -> ctlen=256 same=true err=<nil>",
    "oaep label-a    -> wrong-label n=0 err=crypto/rsa: decryption error",
    "oaepbad label-a  flip-first   -> err=crypto/rsa: decryption error",
    "oaepbad label-a  flip-last    -> err=crypto/rsa: decryption error",
    "oaepbad label-a  short        -> err=crypto/rsa: decryption error",
    "oaepbad label-a  long         -> err=crypto/rsa: decryption error",
    "oaepbad label-a  all-zero     -> err=crypto/rsa: decryption error",
    "oaep too-long-err=crypto/rsa: message too long for RSA key size",
    "oaep max-len=190 err=<nil> ctlen=256",
    "oaep max-plus-1-err=crypto/rsa: message too long for RSA key size",
    "valid ok=<nil>",
    "pubkey e-one        -> verify=crypto/rsa: public exponent too small or negative",
    "pubkey e-zero       -> verify=crypto/rsa: public exponent too small or negative",
    "pubkey e-negative   -> verify=crypto/rsa: public exponent too small or negative",
    "pubkey e-even       -> verify=crypto/rsa: public exponent is even",
    "pubkey e-three      -> verify=crypto/rsa: verification error",
    "pubkey e-huge       -> verify=crypto/rsa: public exponent is even",
    "pubkey n-tiny       -> verify=crypto/rsa: 2-bit keys are insecure (see https://go.dev/pkg/crypto/rsa#hdr-Minimum_key_size)",
    "pubkey n-zero       -> verify=crypto/rsa: 0-bit keys are insecure (see https://go.dev/pkg/crypto/rsa#hdr-Minimum_key_size)",
    "pubkey n-one        -> verify=crypto/rsa: 1-bit keys are insecure (see https://go.dev/pkg/crypto/rsa#hdr-Minimum_key_size)",
];

fn chk(failed: &mut int, ln: &mut int, got: string) {
    if *ln >= GO.len() as int {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln + 1, got);
        *failed += 1;
        *ln += 1;
        return;
    }
    let want = s(GO[*ln as usize]);
    *ln += 1;
    if got == want {
        return;
    }
    fmt::Printf!("[!!] line %d FAIL\n  got  %q\n  want %q\n", *ln, got, want);
    *failed += 1;
}

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}
fn bs(v: Vec<u8>) -> slice<byte> {
    return slice::<byte>::__from_vec(v);
}
fn hx(b: &slice<byte>) -> string {
    return hex::EncodeToString(&b.to_vec());
}
fn errText(err: error) -> string {
    if err == goish::nil {
        return s("<nil>");
    }
    return err.Error();
}
fn flip(b: &slice<byte>, i: usize) -> slice<byte> {
    let mut v = b.to_vec();
    v[i] ^= 0x01;
    return bs(v);
}
// The SAME key Go used, carried as PKCS#1 DER. A verifier tested only
// against signatures it produced itself cannot fail the kind of test
// this smoke is for.
const KEY_DER: &str = "308204a40201000282010100d1da40d2981174868c7cdb70b9eeedeeb30badb82976c4e2145bef66dbeed04310e3087e648df2c30db5a6aeabff299fa08a67a20958cf0c4d9a11f25e1dbe74d2143d270edb55f3f374e1901509abe00f7682cc1e5caf5e216dfa7d8e9c407a4dfb777a8c5d195c1d60bea50383b1a5ec3b1f655d937c61a3d0903c12f86de2cca374cf49a16b7b9fee79c076d217ca055524b573df0360d66b34c10d06f4ae184a6c9f81bd2b00b6170e6bd70111835a1485ee064fb538eae30f1e49c552a8728c11ede888194d27c04657446e81afaf1b2150d771d94870c91c32a045d1ee920d5e399ec1ac005bb61138ff350d8e7cf47c931893026c069c25fbf399f0f902030100010282010048f7760da3b1820e5c9ff75f394f622cdad5a7383f369c5badcf8facf8b10f7a1a4f8ebefff0b965e808eee592497d2c1352bc99035dfd541e5181870001a09d1704d18498ae5c332046563dd68acfd7ef187a7f45d95d62c205ef10a43b21524576380384f5c4211ad7ee420b3849d7530df5ab35bfd8024d46f237e932b7660127d41083b7b09725c1f7767f6b5287559f699eb57dcb9343c7ca301f8786083e12bd7b5e1cb35f750cf2e574f8d0a9e891be2fd13b2bc1a214181c1b0a28771945e00b10c82579f36480a26b8d2ed6eeb659087df42144ab5e0f94dc727278fc575ef6edbb75d5f79d69f3458cd51047291efe0a74499d17194e72b655cb5702818100e5cf520fa702859953cee3fc1c34edc95e50736dbb829d4b88ba3ff8e0dc3b796a554b17bb98b5a665bc0458fdaca939a5a1645e5d2c0ec76ca7493426d0ada273ff7d211c472aaaed0256707342c58adf755c1ad6c15ad79328ab3bb3d1b1e0f330e82962fd4a2116cfbd0aec5b25f8d886e5aaec33dcce71d48eafb67a359f02818100e9c4ae3a9a18e483e5d87e0a6c5513198d2784110f0b50a17aee4d112cfc3f2bc5041827791ea96631e8033e88e3bb6e0fd536dadff2116af93648771fdb8efc0e133c9e19613e990d7510e44ddbbf9a469077ae01c2cc2f1ac9f53b4b7b01cfb8d7898319eb6d15b0346daf69cefeb29e543b6b4e332a06bf7e4c61d3e8e26702818100c5aa4759333b961245e5e46f4b0bb3a3cabdc42b1467ca47d7f8eb617477b9a83b6fd5c13a18a5d5d4179e5db50438225f76ac500630091e3b34c0605d2a8ccef89b3ed3a5f108a030701c4d68b67c1771110f01feca1d0ae386cd91f29f6132adbad9560fd0f15bf8b502534ced3182132c248b99d31a0f7015760d691540dd02818100a7d192626f8dbf3f111a4221a973c9aa663320143f009879d48e8eb4edde885b1bacbcca59a1316b3418a37b993a23abf7a1d1277fed7fa39414ec20d8b5fe07e4f2da69853ed2797db7b4d0b1343870c087a5e33d5062d4ce1e7df67b516b137c56ff59269a644d5599cdc447e959df50da976d894e21b586735cd23e16c9b10281805e40f834d2a8e0edd940bd21a129113d699056289e916c3bd857ae5123bfa896591e9120fd6ce6bc2e591e7a4e4e2d4e6a04620b5f5bbdd41972b5af4982802c35452f09c32b92e7f9212a4718e008a4cf70fb7ee573085b773dd355045e968230769e90d1e5bd4a9888ccfa1cb6414a9862284d56a52d6368cf1f881a33a15c";
#[goish::main]
fn main() {
    let mut failed: int = 0;
    let mut ln: int = 0;
    let (der, _) = hex::DecodeString(KEY_DER);
    let (key, kerr) = x509::ParsePKCS1PrivateKey(der.clone());
    if kerr != goish::nil {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("key parse-err=%q", kerr.Error()),
        );
        return;
    }
    chk(&mut failed, &mut ln, fmt::Sprintf!("key der=%s", hx(&der)));
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!(
            "key bits=%d size=%d e=%d",
            key.PublicKey.N.BitLen(),
            key.PublicKey.Size(),
            key.PublicKey.E
        ),
    );
    let msg = bs(b"rsa reference message".to_vec());
    let h256 = bs(sha256::Sum256(msg.clone()).to_vec());
    let h512 = bs(sha512::Sum512(msg.clone()).to_vec());
    let (sig, serr) = rsa::SignPKCS1v15(&mut rand::Reader, &key, crypto::SHA256, h256.clone());
    if serr != goish::nil {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("sign-err=%q", serr.Error()),
        );
        return;
    }
    chk(&mut failed, &mut ln, fmt::Sprintf!("v15 sig=%s", hx(&sig)));
    let (sig2, _) = rsa::SignPKCS1v15(&mut rand::Reader, &key, crypto::SHA256, h256.clone());
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!(
            "v15 deterministic=%v nil-rand-ok=%v",
            hx(&sig) == hx(&sig2),
            sig2.Len() > 0
        ),
    );
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!(
            "v15 verify=%s",
            errText(rsa::VerifyPKCS1v15(
                &key.PublicKey,
                crypto::SHA256,
                h256.clone(),
                sig.clone()
            ))
        ),
    );
    let sv = sig.to_vec();
    let n = key.PublicKey.N.clone();
    let mut one = Int::default();
    one.SetInt64(1);
    let mut nm1 = Int::default();
    nm1.Sub(&n, &one);
    let mut longer = sv.clone();
    longer.push(0);
    let mut oneAt = alloc::vec![0u8; sv.len()];
    let oneLen = oneAt.len();
    oneAt[oneLen - 1] = 1;
    let mut shifted = alloc::vec![0u8; sv.len()];
    shifted[1..].copy_from_slice(&sv[..sv.len() - 1]);
    let bad: [(&str, slice<byte>); 13] = [
        ("nil", bs(Vec::new())),
        ("empty", bs(Vec::new())),
        ("short-by-one", bs(sv[..sv.len() - 1].to_vec())),
        ("long-by-one", bs(longer)),
        ("all-zero", bs(alloc::vec![0u8; sv.len()])),
        ("all-ff", bs(alloc::vec![0xffu8; sv.len()])),
        ("one", bs(oneAt)),
        ("modulus", n.Bytes()),
        ("modulus-minus-1", nm1.Bytes()),
        ("flip-first", flip(&sig, 0)),
        ("flip-last", flip(&sig, sv.len() - 1)),
        ("flip-middle", flip(&sig, sv.len() / 2)),
        ("leading-zero-shift", bs(shifted)),
    ];
    for (name, b) in bad.iter() {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "v15bad %-20s -> err=%s",
                s(name),
                errText(rsa::VerifyPKCS1v15(
                    &key.PublicKey,
                    crypto::SHA256,
                    h256.clone(),
                    b.clone()
                ))
            ),
        );
    }
    let hv = h256.to_vec();
    let mut long33 = hv.clone();
    long33.push(0);
    let hashes: [(&str, crypto::Hash, slice<byte>); 8] = [
        ("right", crypto::SHA256, h256.clone()),
        ("wrong-alg-sha512", crypto::SHA512, h512.clone()),
        ("wrong-alg-sha512-256d", crypto::SHA512, h256.clone()),
        ("sha256-short-digest", crypto::SHA256, bs(hv[..31].to_vec())),
        ("sha256-long-digest", crypto::SHA256, bs(long33)),
        ("sha256-empty-digest", crypto::SHA256, bs(Vec::new())),
        ("hash-zero", crypto::Hash(0), h256.clone()),
        ("hash-zero-empty", crypto::Hash(0), bs(Vec::new())),
    ];
    for (name, h, d) in hashes.iter() {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "v15hash %-22s -> err=%s",
                s(name),
                errText(rsa::VerifyPKCS1v15(
                    &key.PublicKey,
                    *h,
                    d.clone(),
                    sig.clone()
                ))
            ),
        );
    }
    let pssCases: [(&str, int); 7] = [
        ("auto", rsa::PSSSaltLengthAuto),
        ("equals-hash", rsa::PSSSaltLengthEqualsHash),
        ("explicit-0", 0),
        ("explicit-32", 32),
        ("explicit-222", 222),
        ("explicit-223", 223),
        ("explicit-1000", 1000),
    ];
    for (name, sl) in pssCases.iter() {
        let opts = rsa::PSSOptions {
            SaltLength: *sl,
            Hash: crypto::SHA256,
        };
        let (ps, e) = rsa::SignPSS(
            &mut rand::Reader,
            &key,
            crypto::SHA256,
            h256.clone(),
            Some(&opts),
        );
        if e != goish::nil {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("pss %-14s -> sign-err=%s", s(name), errText(e)),
            );
            continue;
        }
        let ao = rsa::PSSOptions {
            SaltLength: rsa::PSSSaltLengthAuto,
            Hash: crypto::SHA256,
        };
        let eo = rsa::PSSOptions {
            SaltLength: rsa::PSSSaltLengthEqualsHash,
            Hash: crypto::SHA256,
        };
        let vAuto = rsa::VerifyPSS(
            &key.PublicKey,
            crypto::SHA256,
            h256.clone(),
            ps.clone(),
            Some(&ao),
        );
        let vEq = rsa::VerifyPSS(
            &key.PublicKey,
            crypto::SHA256,
            h256.clone(),
            ps.clone(),
            Some(&eo),
        );
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "pss %-14s -> len=%d auto=%s equals=%s",
                s(name),
                ps.Len(),
                errText(vAuto),
                errText(vEq)
            ),
        );
    }
    {
        let (ps, _) = rsa::SignPSS(&mut rand::Reader, &key, crypto::SHA256, h256.clone(), None);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "pss nil-opts -> len=%d verify=%s",
                ps.Len(),
                errText(rsa::VerifyPSS(
                    &key.PublicKey,
                    crypto::SHA256,
                    h256.clone(),
                    ps.clone(),
                    None
                ))
            ),
        );
        let pv = ps.to_vec();
        let mut plong = pv.clone();
        plong.push(0);
        let pbad: [(&str, slice<byte>); 8] = [
            ("nil", bs(Vec::new())),
            ("empty", bs(Vec::new())),
            ("flip-first", flip(&ps, 0)),
            ("flip-last", flip(&ps, pv.len() - 1)),
            ("short", bs(pv[..pv.len() - 1].to_vec())),
            ("long", bs(plong)),
            ("all-zero", bs(alloc::vec![0u8; pv.len()])),
            ("v15-sig-as-pss", sig.clone()),
        ];
        for (name, b) in pbad.iter() {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "pssbad %-16s -> err=%s",
                    s(name),
                    errText(rsa::VerifyPSS(
                        &key.PublicKey,
                        crypto::SHA256,
                        h256.clone(),
                        b.clone(),
                        None
                    ))
                ),
            );
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "pss as-v15=%s",
                errText(rsa::VerifyPKCS1v15(
                    &key.PublicKey,
                    crypto::SHA256,
                    h256.clone(),
                    ps
                ))
            ),
        );
    }
    let plain = bs(b"oaep secret payload".to_vec());
    for (name, label) in [("no-label", ""), ("label-a", "context-a")] {
        let lb = bs(label.as_bytes().to_vec());
        let mut h = sha256::New();
        let (ct, e) = rsa::EncryptOAEP(
            &mut h,
            &mut rand::Reader,
            &key.PublicKey,
            plain.clone(),
            lb.clone(),
        );
        if e != goish::nil {
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("oaep %-10s -> encrypt-err=%s", s(name), errText(e)),
            );
            continue;
        }
        let mut h2 = sha256::New();
        let (pt, de) = rsa::DecryptOAEP(&mut h2, &mut rand::Reader, &key, ct.clone(), lb.clone());
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "oaep %-10s -> ctlen=%d same=%v err=%s",
                s(name),
                ct.Len(),
                hx(&pt) == hx(&plain),
                errText(de)
            ),
        );
        let mut h3 = sha256::New();
        let (other, oe) = rsa::DecryptOAEP(
            &mut h3,
            &mut rand::Reader,
            &key,
            ct.clone(),
            bs(b"context-b".to_vec()),
        );
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "oaep %-10s -> wrong-label n=%d err=%s",
                s(name),
                other.Len(),
                errText(oe)
            ),
        );
        let cv = ct.to_vec();
        let mut clong = cv.clone();
        clong.push(0);
        let cbad: [(&str, slice<byte>); 5] = [
            ("flip-first", flip(&ct, 0)),
            ("flip-last", flip(&ct, cv.len() - 1)),
            ("short", bs(cv[..cv.len() - 1].to_vec())),
            ("long", bs(clong)),
            ("all-zero", bs(alloc::vec![0u8; cv.len()])),
        ];
        for (bn, b) in cbad.iter() {
            let mut hh = sha256::New();
            let (_, ee) = rsa::DecryptOAEP(&mut hh, &mut rand::Reader, &key, b.clone(), lb.clone());
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("oaepbad %-8s %-12s -> err=%s", s(name), s(bn), errText(ee)),
            );
        }
    }
    {
        let mut h = sha256::New();
        let (_, e) = rsa::EncryptOAEP(
            &mut h,
            &mut rand::Reader,
            &key.PublicKey,
            bs(alloc::vec![0u8; 512]),
            bs(Vec::new()),
        );
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("oaep too-long-err=%s", errText(e)),
        );
        let maxLen = key.PublicKey.Size() - 2 * sha256::Size - 2;
        let mut h2 = sha256::New();
        let (ct, e2) = rsa::EncryptOAEP(
            &mut h2,
            &mut rand::Reader,
            &key.PublicKey,
            bs(alloc::vec![0u8; maxLen as usize]),
            bs(Vec::new()),
        );
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "oaep max-len=%d err=%s ctlen=%d",
                maxLen,
                errText(e2),
                ct.Len()
            ),
        );
        let mut h3 = sha256::New();
        let (_, e3) = rsa::EncryptOAEP(
            &mut h3,
            &mut rand::Reader,
            &key.PublicKey,
            bs(alloc::vec![0u8; (maxLen + 1) as usize]),
            bs(Vec::new()),
        );
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("oaep max-plus-1-err=%s", errText(e3)),
        );
    }
    {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("valid ok=%s", errText(key.Validate())),
        );
        let mut n3 = Int::default();
        n3.SetInt64(3);
        let mut n0 = Int::default();
        n0.SetInt64(0);
        let mut n1 = Int::default();
        n1.SetInt64(1);
        let pubs: [(&str, int, &Int); 9] = [
            ("e-one", 1, &n),
            ("e-zero", 0, &n),
            ("e-negative", -3, &n),
            ("e-even", 4, &n),
            ("e-three", 3, &n),
            ("e-huge", 1 << 30, &n),
            ("n-tiny", 65537, &n3),
            ("n-zero", 65537, &n0),
            ("n-one", 65537, &n1),
        ];
        for (name, e, nn) in pubs.iter() {
            let p = rsa::PublicKey {
                N: (*nn).clone(),
                E: *e,
            };
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "pubkey %-12s -> verify=%s",
                    s(name),
                    errText(rsa::VerifyPKCS1v15(
                        &p,
                        crypto::SHA256,
                        h256.clone(),
                        sig.clone()
                    ))
                ),
            );
        }
    }
    if ln != GO.len() as int {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln, GO.len() as int);
        failed += 1;
    }
    if failed == 0 {
        fmt::Printf!("ok %d/%d\n", ln, ln);
        return;
    }
    fmt::Printf!("FAILED %d of %d\n", failed, ln);
    syscall::Exit(1);
}
