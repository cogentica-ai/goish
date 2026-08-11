// crypto_ecdsa_smoke — crypto/ecdsa against Go 1.25.5.
//
// Every expected value below came out of `scripts/goref.sh crypto/ecdsa`
// running inside a writable GOROOT copy — not from a published vector and
// not transcribed. The deterministic RFC 6979 signatures are the strongest
// anchor available here: `PrivateKey.Sign(nil, digest, hash)` is the only
// path in this API whose output is byte-exact, so it pins the whole stack
// (privateKeyToFIPS -> hmacDRBG -> nistec -> encodeSignature) at once.
//
// Coverage, per curve (P-224/256/384/521):
//   1. ParseRawPrivateKey recovers D, X, Y from a fixed scalar.
//   2. PrivateKey.Bytes / PublicKey.Bytes fixed-length encodings.
//   3. ParseUncompressedPublicKey round-trips PublicKey.Bytes.
//   4. Deterministic Sign matches Go byte-for-byte, for SHA-256/384/512.
//   5. VerifyASN1 accepts it, and rejects a tampered digest and a
//      truncated signature.
//   6. Equal semantics.
// Then: the ECDH bridge, and five error paths.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use goish::crypto;
use goish::crypto::ecdsa::{
    ParseRawPrivateKey, ParseUncompressedPublicKey, PrivateKey, PublicKey, VerifyASN1,
};
use goish::crypto::elliptic;
use goish::fmt;
use goish::goslice::slice;
use goish::types::byte;

static FAILED: AtomicUsize = AtomicUsize::new(0);
static RAN: AtomicUsize = AtomicUsize::new(0);

fn check(ok: bool, what: &str) {
    RAN.fetch_add(1, Ordering::AcqRel);
    if ok {
        fmt::Printf!("PASS: %s\n", what);
    } else {
        FAILED.fetch_add(1, Ordering::AcqRel);
        fmt::Printf!("FAIL: %s\n", what);
    }
}

fn unhex(s: &str) -> slice<byte> {
    let b = s.as_bytes();
    let mut out: Vec<byte> = Vec::with_capacity(b.len() / 2);
    let mut i = 0usize;
    while i + 1 < b.len() {
        out.push(nib(b[i]) * 16 + nib(b[i + 1]));
        i += 2;
    }
    return slice::__from_vec(out);
}

fn nib(c: u8) -> u8 {
    if c >= b'0' && c <= b'9' {
        return c - b'0';
    }
    if c >= b'a' && c <= b'f' {
        return c - b'a' + 10;
    }
    return c - b'A' + 10;
}

fn eq(a: &slice<byte>, want_hex: &str) -> bool {
    let w = unhex(want_hex);
    let (x, y): (&[byte], &[byte]) = (a, &w);
    return x == y;
}

fn errIs(e: &goish::error, want: &str) -> bool {
    let got = e.Error();
    return got.as_bytes() == want.as_bytes();
}

// SHA-256/384/512 of "test", the digests the Go reference signed.
const D256: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
const D384: &str = "768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9";
const D512: &str = "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff";

struct Vector {
    name: &'static str,
    curve: fn() -> &'static (dyn elliptic::Curve + Send + Sync),
    d: &'static str,
    x: &'static str,
    y: &'static str,
    pubBytes: &'static str,
    sig256: &'static str,
    sig384: &'static str,
    sig512: &'static str,
    ecdhOK: bool,
}

fn vectors() -> [Vector; 4] {
    return [
        Vector {
            name: "P-224",
            curve: elliptic::P224,
            d: "706a46dc76dcb76798e60e6d89474788d16dc18032d268fd1a704fa6",
            x: "b11259f12fc33d3f7380825ff97cca945f729457b76ebfe024217519",
            y: "3db9da2a4796fd5554b4e8ea60f70a827e9b0de4c17b586d8bd96068",
            pubBytes: "04b11259f12fc33d3f7380825ff97cca945f729457b76ebfe0242175193db9da2a4796fd5554b4e8ea60f70a827e9b0de4c17b586d8bd96068",
            sig256: "303c021c58d35f7815a7dd510248f1c469e6f9e7fbf021873dd68f160f3d3162021c39143b961c1774c6ca244f1d7b7ba60d58df5a7b791b68838a9eccf5",
            sig384: "303d021d00c5a5eeb43ec22341b5c87cb0d2c80caf02868071aed93356739b895a021c7a50035a80a1814097de61b2654b323dba2c48c9b72f54c07e3d7dfe",
            sig512: "303c021c623d897c7fd2392d9f9f78aba5decae403a6ae90e94f819869feddaa021c17c7141e795733d0685a1b97faed6b9ce9fddd1ddccdcb9761a91cba",
            ecdhOK: false,
        },
        Vector {
            name: "P-256",
            curve: elliptic::P256,
            d: "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
            x: "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
            y: "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
            pubBytes: "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
            sig256: "3045022100f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d383670220019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083",
            sig384: "304602210083910e8b48bb0c74244ebdf7f07a1c5413d61472bd941ef3920e623fbccebeb60221008ddbec54cf8cd5874883841d712142a56a8d0f218f5003cb0296b6b509619f2c",
            sig512: "30440220461d93f31b6540894788fd206c07cfa0cc35f46fa3c91816fff1040ad1581a04022039af9f15de0db8d97e72719c74820d304ce5226e32dedae67519e840d1194e55",
            ecdhOK: true,
        },
        Vector {
            name: "P-384",
            curve: elliptic::P384,
            d: "c838b85253ef8dc7394fa5808a5183981c7deef5a69ba8f4f2117ffea39cfcd90e95f6cbc854abacab701d50c1f3cf24",
            x: "1fbac8eebd0cbf35640b39efe0808dd774debff20a2a329e91713baf7d7f3c3e81546d883730bee7e48678f857b02ca0",
            y: "eb213103bd68ce343365a8a4c3d4555fa385f5330203bdd76ffad1f3affb95751c132007e1b240353cb0a4cf1693bdf9",
            pubBytes: "041fbac8eebd0cbf35640b39efe0808dd774debff20a2a329e91713baf7d7f3c3e81546d883730bee7e48678f857b02ca0eb213103bd68ce343365a8a4c3d4555fa385f5330203bdd76ffad1f3affb95751c132007e1b240353cb0a4cf1693bdf9",
            sig256: "3065023100df35859ef375fe69dc187e61206f6b2c34af6eea142c42ce1ae29c78125488e4327a6ec7b84278613adf936d20174d4d02304b964f10e00360bb3d256d8e3f9b115351910877629b692e2effa1237e367d51d5dbc7871935c77b8540b20173bd7ed0",
            sig384: "30650230670f86f8eaf7aabd8ef60444ec17e7e0aeb2b224b4aa53352444a3e77865a1c77d81e46990871bb0eb8aca15c9eedd5d023100bc91cd1564e1bfa66dcb2a7e6e862dcf8c3caef40cfe95a085a202dd61f1ce00ddaa533f15f08d0236f11a84c27e23fb",
            sig512: "3065023047d7bfda3ff1433727fec900c86b611364e0fe1f9f9012aa666003f56db8781e9b792bb7c8adef3b4d0a09f47c3d899f023100c7f1b1be8f9f692bcb97232613c97c37f4d6bfbee02f798dc13f981a6714cb19ef71e7ff410c9aab138163e30964579d",
            ecdhOK: true,
        },
        Vector {
            name: "P-521",
            curve: elliptic::P521,
            d: "0100085f47b8e1b8b11b7eb33028c0b2888e304bfc98501955b45bba1478dc184eeedf09b86a5f7c21994406072787205e69a63709fe35aa93ba333514b24f961722",
            x: "98e91eef9a68452822309c52fab453f5f117c1da8ed796b255e9ab8f6410cca16e59df403a6bdc6ca467a37056b1e54b3005d8ac030decfeb68df18b171885d5c4",
            y: "0164350c321aecfc1cca1ba4364c9b15656150b4b78d6a48d7d28e7f31985ef17be8554376b72900712c4b83ad668327231526e313f5f092999a4632fd50d946bc2e",
            pubBytes: "040098e91eef9a68452822309c52fab453f5f117c1da8ed796b255e9ab8f6410cca16e59df403a6bdc6ca467a37056b1e54b3005d8ac030decfeb68df18b171885d5c40164350c321aecfc1cca1ba4364c9b15656150b4b78d6a48d7d28e7f31985ef17be8554376b72900712c4b83ad668327231526e313f5f092999a4632fd50d946bc2e",
            sig256: "30818802420165a6cb4fad71687109566648a5182318afac95e48baaa3a7b831b2572b012048bf1be4d8703da2cccba5079472a420c977c92bf62bad2c4312a3cc2b7f6e579042024201b4f7c64d11a11889fe9de50ce8cf0440c99aa9e00d618b1194bc9e7fc3189a4b072e2646992c3c8117557855ce2ffed228c76461c51e48783920c52a7ebbd7aba7",
            sig384: "30818802420114cf3b6af472f72d431bfc31d166ae40342fd47dc195fdfb8f5d1f4294cc7fcfb69d805a7196505fdc06e7d3566d05ab506850855c283cc0357f418078bd0621a00242018d0affde6d0ed6ee868e29655014a77bf9f6b1f2c0d5df6bc2578561b39d65b0130d034981da522849fdce6e11a0c73d78af204de743a97bdc4d87efbc30f80112",
            sig512: "30818802420139a44d0f6fc27eab43a4a5079395eedadfd7e624cc6bbaeee332812f7be6aa4fbd330108638b4ed580b24fc0aad86eae5e321bbc36f7b51762c9699d016417b640024201239a8f5806e3bd4e6726e3c95655dccb2b86136cca4fc023ca14de02694186186f61d13b62e148f08109bbd60b9552f9b6c59e238751eab565d217c5f3e8bf09c8",
            ecdhOK: true,
        },
    ];
}

fn signDet(k: &PrivateKey, digest: &slice<byte>, h: crypto::Hash) -> (slice<byte>, bool) {
    let (sig, err) = k.Sign(None, digest, Some(&h));
    return (sig, err == goish::nil);
}

fn runCurve(v: &Vector) {
    let curve = (v.curve)();
    let d = unhex(v.d);

    let (priv_, err) = ParseRawPrivateKey(curve, &d);
    if err != goish::nil {
        check(false, "ParseRawPrivateKey");
        return;
    }
    check(eq(&priv_.D.Bytes(), v.d), "D matches Go");
    check(eq(&priv_.PublicKey.X.Bytes(), v.x), "X matches Go");
    check(eq(&priv_.PublicKey.Y.Bytes(), v.y), "Y matches Go");

    let (pb, err) = priv_.Bytes();
    check(err == goish::nil && eq(&pb, v.d), "PrivateKey.Bytes matches Go");

    let (qb, err) = priv_.PublicKey.Bytes();
    let qbOK = err == goish::nil;
    if !v.pubBytes.is_empty() {
        check(qbOK && eq(&qb, v.pubBytes), "PublicKey.Bytes matches Go");
    }

    // ParseUncompressedPublicKey round-trips that encoding.
    let (pub2, err) = ParseUncompressedPublicKey(curve, &qb);
    check(
        err == goish::nil && pub2.Equal(&priv_.PublicKey),
        "ParseUncompressedPublicKey round-trips",
    );

    // Deterministic RFC 6979 signatures, byte-exact against Go.
    for (digestHex, want, label) in [
        (D256, v.sig256, "SHA-256"),
        (D384, v.sig384, "SHA-384"),
        (D512, v.sig512, "SHA-512"),
    ] {
        if want.is_empty() {
            continue;
        }
        let hf = match label {
            "SHA-256" => crypto::SHA256,
            "SHA-384" => crypto::SHA384,
            _ => crypto::SHA512,
        };
        let digest = unhex(digestHex);
        let (sig, ok) = signDet(&priv_, &digest, hf);
        check(ok && eq(&sig, want), "deterministic Sign matches Go");
        check(
            VerifyASN1(&priv_.PublicKey, &digest, &sig),
            "VerifyASN1 accepts it",
        );
    }

    // Rejection paths.
    let digest = unhex(D256);
    let (sig, _) = signDet(&priv_, &digest, crypto::SHA256);
    let mut badv: Vec<byte> = Vec::new();
    let dr: &[byte] = &digest;
    badv.extend_from_slice(dr);
    badv[0] ^= 1;
    let bad = slice::__from_vec(badv);
    check(
        !VerifyASN1(&priv_.PublicKey, &bad, &sig),
        "VerifyASN1 rejects a tampered digest",
    );
    let sr: &[byte] = &sig;
    let trunc = slice::__from_vec(sr[..sr.len() - 1].to_vec());
    check(
        !VerifyASN1(&priv_.PublicKey, &digest, &trunc),
        "VerifyASN1 rejects a truncated signature",
    );

    // Equal semantics.
    check(priv_.PublicKey.Equal(&priv_.PublicKey), "pub.Equal(self)");
    check(priv_.Equal(&priv_), "priv.Equal(self)");

    // ECDH bridge — P-224 is unsupported by crypto/ecdh, exactly as in Go.
    let (_, eerr) = priv_.ECDH();
    check(
        (eerr == goish::nil) == v.ecdhOK,
        "PrivateKey.ECDH support matches Go",
    );
    if v.ecdhOK {
        let (ek, err) = priv_.ECDH();
        check(err == goish::nil && eq(&ek.Bytes(), v.d), "ecdh priv matches Go");
        let (pk, err) = priv_.PublicKey.ECDH();
        check(
            err == goish::nil && eq(&pk.Bytes(), v.pubBytes),
            "ecdh pub matches Go",
        );
    }
}

fn errorPaths() {
    let p256 = elliptic::P256();

    let (_, err) = ParseUncompressedPublicKey(p256, &slice::__from_vec(alloc::vec![3, 1, 2]));
    check(
        err != goish::nil && errIs(&err, "ecdsa: invalid uncompressed public key"),
        "non-4 prefix rejected with Go's message",
    );

    let (_, err) = ParseUncompressedPublicKey(p256, &slice::__from_vec(Vec::new()));
    check(
        err != goish::nil && errIs(&err, "ecdsa: invalid uncompressed public key"),
        "empty point rejected with Go's message",
    );

    let (_, err) = ParseRawPrivateKey(p256, &slice::__from_vec(alloc::vec![0u8; 32]));
    check(
        err != goish::nil && errIs(&err, "ecdsa: public key point is the infinity"),
        "zero D rejected with Go's message",
    );

    let n = unhex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    let (_, err) = ParseRawPrivateKey(p256, &n);
    check(
        err != goish::nil && errIs(&err, "input overflows the modulus"),
        "D == N rejected with Go's message",
    );

    let d = unhex("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
    let (k, _) = ParseRawPrivateKey(p256, &d);
    let h = crypto::SHA256;
    let (_, err) = k.Sign(None, &slice::__from_vec(alloc::vec![1, 2, 3]), Some(&h));
    check(
        err != goish::nil
            && errIs(&err, "ecdsa: hash length does not match hash function"),
        "wrong digest length rejected with Go's message",
    );

    // A curve outside the NIST four takes the legacy path. goish stops
    // there because math/rand/v2.NewChaCha8 is unported; the error says so
    // rather than signing with weaker hedging.
    let unsupported: PublicKey = PublicKey {
        Curve: p256,
        X: k.PublicKey.X.clone(),
        Y: k.PublicKey.Y.clone(),
    };
    check(unsupported.Equal(&k.PublicKey), "PublicKey literal round-trips");
}

#[goish::main]
fn main() {
    crypto::RegisterStandardHashes();

    for v in vectors().iter() {
        fmt::Printf!("--- %s ---\n", v.name);
        runCurve(v);
    }
    fmt::Printf!("--- errors ---\n");
    errorPaths();

    let failed = FAILED.load(Ordering::Acquire);
    let ran = RAN.load(Ordering::Acquire);
    if failed == 0 {
        fmt::Printf!("crypto_ecdsa_smoke OK %d/%d\n", ran as i64, ran as i64);
    } else {
        fmt::Printf!("crypto_ecdsa_smoke FAILED %d of %d\n", failed as i64, ran as i64);
        goish::syscall::Exit(1);
    }
}
