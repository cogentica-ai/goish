// chacha20_poly1305_ref_smoke — crypto/chacha20 and crypto/poly1305
// against a running Go.
// (vendor/golang.org/x/crypto/chacha20/chacha_generic.go,
//  vendor/golang.org/x/crypto/internal/poly1305/sum_generic.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_chacha_ref.go` run in
// `package chacha20` by `scripts/goref.sh`.
//
// ChaCha20 and Poly1305 are the two halves of the AEAD that TLS 1.3
// negotiates whenever AES hardware is absent — and goish had 740 lines
// of them with NO test of any kind. Not a vector, not a smoke. They
// were the only two packages of real size in the tree with nothing
// checking them at all.
//
// That matters more here than almost anywhere else, because neither
// primitive fails loudly. A stream cipher that is subtly wrong still
// produces ciphertext; the peer just gets plaintext that is not what
// was sent. A MAC that is subtly wrong is worse, because the thing it
// silently stops doing is AUTHENTICATION — and a round trip against
// itself passes either way. The only way to know is to compare against
// a reference, which is what this does.
//
// goish matched Go on all 44 lines, byte for byte. What is pinned:
//
//   * RFC 8439 Section 2.4.2's ChaCha20 vector and Section 2.5.2's
//     Poly1305 vector, so the published answers are in the tree.
//   * The raw keystream at counters 0, 1, 2 and 0xffffffff — the last
//     of which is where a counter that wraps differently shows up.
//   * SetCounter, which is how the AEAD reserves block 0 for the
//     Poly1305 key and starts the payload at block 1.
//   * Incremental XORKeyStream at every offset around a 64-byte block
//     boundary, which must equal the single-shot; that is how a
//     streaming writer uses it, and a mishandled partial block is
//     invisible until someone splits at 63.
//   * Every key and nonce size that must be refused, with its message.
//   * HChaCha20, the XChaCha20 key-derivation step, whose output is a
//     KEY — so a wrong one is silently a different cipher rather than
//     an error.
//   * Poly1305 across the lengths where the 16-byte padding rule bites
//     (0, 1, 15, 16, 17, 31, 32, 33), incremental writes split at each
//     of them, and that a tampered tag or a tampered message fails to
//     verify.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::crypto::chacha20;
use goish::crypto::poly1305;
use goish::errors::error;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::syscall;
use goish::types::{byte, int};

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}
fn hx(b: &[u8]) -> string {
    const H: &[u8] = b"0123456789abcdef";
    let mut v: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(b.len() * 2);
    for &x in b {
        v.push(H[(x >> 4) as usize]);
        v.push(H[(x & 0xf) as usize]);
    }
    return string::from_bytes(&v);
}
fn sl(v: alloc::vec::Vec<u8>) -> slice<byte> {
    return slice::__from_vec(v);
}
fn et(e: &error) -> string {
    if e.IsNil() {
        return s("<nil>");
    }
    return e.Error();
}

// go: none — goish idiom: the reference lines, in the order Go printed
//     them. Comparing whole rendered lines keeps this smoke and the
//     generator in lockstep: a case added to one is a mismatch in the
//     other, never a silent pass.
const GO: [&str; 44] = [
    "rfc8439 ct=6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d",
    "keystream ctr=0          af051e40bba0354981329a806a140eafd258a22a6dcb4bb9f6569cb3efe2deaf837bd87ca20b5ba12081a306af0eb35c41a239d20dfc74c81771560d9c9c1e4b",
    "keystream ctr=1          224f51f3401bd9e12fde276fb8631ded8c131f823d2c06e27e4fcaec9ef3cf788a3b0aa372600a92b57974cded2b9334794cba40c63e34cdea212c4cf07d41b7",
    "keystream ctr=2          69a6749f3f630f4122cafe28ec4dc47e26d4346d70b98c73f3e9c53ac40c5945398b6eda1a832c89c167eacd901d7e2bf363740373201aa188fbbce83991c4ed",
    "keystream ctr=4294967295 6d29da5bd16a472910e8c0bdb47edfc8499c3222cc168d3721747fc2b21266d9f15c8339f10f354d16cc9b8e118eb182bf858ce5718fa4e76389ea4eb50a9475",
    "split 0    same=true  head=af021055a7831f78b90ddccd3e4f6cc6",
    "split 1    same=true  head=af021055a7831f78b90ddccd3e4f6cc6",
    "split 31   same=true  head=af021055a7831f78b90ddccd3e4f6cc6",
    "split 63   same=true  head=af021055a7831f78b90ddccd3e4f6cc6",
    "split 64   same=true  head=af021055a7831f78b90ddccd3e4f6cc6",
    "split 65   same=true  head=af021055a7831f78b90ddccd3e4f6cc6",
    "split 100  same=true  head=af021055a7831f78b90ddccd3e4f6cc6",
    "tiny after-empty=af",
    "newcipher k=32  n=12  -> err=<nil>",
    "newcipher k=32  n=24  -> err=<nil>",
    "newcipher k=31  n=12  -> err=chacha20: wrong key size",
    "newcipher k=33  n=12  -> err=chacha20: wrong key size",
    "newcipher k=32  n=11  -> err=chacha20: wrong nonce size",
    "newcipher k=32  n=13  -> err=chacha20: wrong nonce size",
    "newcipher k=0   n=0   -> err=chacha20: wrong key size",
    "hchacha nonce=00000000000000000000000000000000 -> d484bb1b6b61f9365b90a1fd44772ade258235eab1f7a32dc22762a0485b410c err=<nil>",
    "hchacha nonce=000102030405060708090a0b0c0d0e0f -> 51e3ff45a895675c4b33b46c64f4a9ace110d34df6a2ceab486372bacbd3eff6 err=<nil>",
    "hchacha k=32  n=15  -> err=chacha20: wrong HChaCha20 nonce size",
    "hchacha k=32  n=17  -> err=chacha20: wrong HChaCha20 nonce size",
    "hchacha k=31  n=16  -> err=chacha20: wrong HChaCha20 key size",
    "poly1305 len=0    tag=1112131415161718191a1b1c1d1e1f20 verify=true",
    "poly1305 len=1    tag=11131517191a1d1f21222527292a2d2f verify=true",
    "poly1305 len=15   tag=ca576367fac8165a2931b52b2b607eb3 verify=true",
    "poly1305 len=16   tag=bdbf4349ca12d91ddb5c59d1be6d94df verify=true",
    "poly1305 len=17   tag=aad74d1055a59a0e24a5c7149e71f4f0 verify=true",
    "poly1305 len=31   tag=3e6b5abeeb24a4c8d245f8f876397648 verify=true",
    "poly1305 len=32   tag=a4872b912414486ede076f7155ce8fa4 verify=true",
    "poly1305 len=33   tag=d96adaa1533962d936d786c7ec16f7db verify=true",
    "poly1305 len=64   tag=9a292ab6ae93ddb1a60bb1b447e42abc verify=true",
    "poly1305 len=100  tag=bf30d5cb426ac501f3a49f19a00cc747 verify=true",
    "poly1305 tamper-tag verify=false",
    "poly1305 tamper-msg verify=false",
    "poly1305 split=0   same=true",
    "poly1305 split=1   same=true",
    "poly1305 split=15  same=true",
    "poly1305 split=16  same=true",
    "poly1305 split=17  same=true",
    "poly1305 split=64  same=true",
    "poly1305 rfc8439 tag=a8061dc1305136c6c22b8baf0c0127a9",
];

// go: none — goish idiom: one comparison, printing the divergence when
//     it is one, so a FAIL says what it got and not just that it did.
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

#[goish::main]
fn main() {
    let mut failed: int = 0;
    let mut ln: int = 0;

    let mut key = [0u8; 32];
    for i in 0..32 {
        key[i] = i as u8;
    }
    let nonce: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0];
    // 1
    {
        let (c, _) = chacha20::NewUnauthenticatedCipher(sl(key.to_vec()), sl(nonce.to_vec()));
        let mut c = c.unwrap();
        c.SetCounter(1);
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let mut ct = alloc::vec![0u8; pt.len()];
        c.XORKeyStream(&mut ct, pt);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("rfc8439 ct=%s", hx(&ct)),
        );
    }
    // 2
    for ctr in [0u32, 1, 2, 0xffffffff] {
        let (c, _) = chacha20::NewUnauthenticatedCipher(sl(key.to_vec()), sl(nonce.to_vec()));
        let mut c = c.unwrap();
        c.SetCounter(ctr);
        let mut out = alloc::vec![0u8; 64];
        let src = out.clone();
        c.XORKeyStream(&mut out, &src);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("keystream ctr=%-10d %s", ctr as i64, hx(&out)),
        );
    }
    // 3
    for split in [0usize, 1, 31, 63, 64, 65, 100] {
        let mut src = alloc::vec![0u8; 128];
        for i in 0..128 {
            src[i] = (i * 7) as u8;
        }
        let (c1, _) = chacha20::NewUnauthenticatedCipher(sl(key.to_vec()), sl(nonce.to_vec()));
        let mut one = c1.unwrap();
        let mut a = alloc::vec![0u8; src.len()];
        one.XORKeyStream(&mut a, &src);

        let (c2, _) = chacha20::NewUnauthenticatedCipher(sl(key.to_vec()), sl(nonce.to_vec()));
        let mut two = c2.unwrap();
        let mut b = alloc::vec![0u8; src.len()];
        {
            let (bh, bt) = b.split_at_mut(split);
            two.XORKeyStream(bh, &src[..split]);
            two.XORKeyStream(bt, &src[split..]);
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "split %-4d same=%-5v head=%s",
                split as i64,
                a == b,
                hx(&b[..16])
            ),
        );
    }
    // 4
    {
        let (c, _) = chacha20::NewUnauthenticatedCipher(sl(key.to_vec()), sl(nonce.to_vec()));
        let mut c = c.unwrap();
        c.XORKeyStream(&mut [], &[]);
        let mut one = alloc::vec![0u8; 1];
        let src = one.clone();
        c.XORKeyStream(&mut one, &src);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("tiny after-empty=%s", hx(&one)),
        );
    }
    // 5
    for (k, n) in [
        (32usize, 12usize),
        (32, 24),
        (31, 12),
        (33, 12),
        (32, 11),
        (32, 13),
        (0, 0),
    ] {
        let (_, err) =
            chacha20::NewUnauthenticatedCipher(sl(alloc::vec![0u8; k]), sl(alloc::vec![0u8; n]));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "newcipher k=%-3d n=%-3d -> err=%v",
                k as i64,
                n as i64,
                et(&err)
            ),
        );
    }
    // 6
    for n in [
        alloc::vec![0u8; 16],
        (0u8..16).collect::<alloc::vec::Vec<u8>>(),
    ] {
        let (out, err) = chacha20::HChaCha20(sl(key.to_vec()), sl(n.clone()));
        let ob: &[u8] = &out;
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("hchacha nonce=%s -> %s err=%v", hx(&n), hx(ob), et(&err)),
        );
    }
    for (k, n) in [(32usize, 15usize), (32, 17), (31, 16)] {
        let (_, err) = chacha20::HChaCha20(sl(alloc::vec![0u8; k]), sl(alloc::vec![0u8; n]));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "hchacha k=%-3d n=%-3d -> err=%v",
                k as i64,
                n as i64,
                et(&err)
            ),
        );
    }
    // 7
    let mut pkey = [0u8; 32];
    for i in 0..32 {
        pkey[i] = (i + 1) as u8;
    }
    for n in [0usize, 1, 15, 16, 17, 31, 32, 33, 64, 100] {
        let mut msg = alloc::vec![0u8; n];
        for i in 0..n {
            msg[i] = (i * 3) as u8;
        }
        let mut tag = [0u8; 16];
        poly1305::Sum(&mut tag, &msg, &pkey);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "poly1305 len=%-4d tag=%s verify=%v",
                n as i64,
                hx(&tag),
                poly1305::Verify(&tag, &msg, &pkey)
            ),
        );
    }
    {
        let msg = b"authenticated";
        let mut tag = [0u8; 16];
        poly1305::Sum(&mut tag, msg, &pkey);
        let mut bad = tag;
        bad[0] ^= 1;
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "poly1305 tamper-tag verify=%v",
                poly1305::Verify(&bad, msg, &pkey)
            ),
        );
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "poly1305 tamper-msg verify=%v",
                poly1305::Verify(&tag, b"authenticatee", &pkey)
            ),
        );
    }
    {
        let mut msg = alloc::vec![0u8; 100];
        for i in 0..100 {
            msg[i] = i as u8;
        }
        let mut want = [0u8; 16];
        poly1305::Sum(&mut want, &msg, &pkey);
        for split in [0usize, 1, 15, 16, 17, 64] {
            let mut m = poly1305::MAC::New(&pkey);
            m.Write(&msg[..split]);
            m.Write(&msg[split..]);
            let mut got: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
            m.Sum(&mut got);
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "poly1305 split=%-3d same=%v",
                    split as i64,
                    hx(&got) == hx(&want)
                ),
            );
        }
    }
    {
        let k: [u8; 32] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ];
        let msg = b"Cryptographic Forum Research Group";
        let mut tag = [0u8; 16];
        poly1305::Sum(&mut tag, msg, &k);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("poly1305 rfc8439 tag=%s", hx(&tag)),
        );
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
