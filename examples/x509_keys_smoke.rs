// x509_keys_smoke — encoding/asn1's DECODE half, and crypto/x509's
// private/public key serialisation, against Go 1.25.5.
//
// EVERY expectation in this file is `scripts/goref.sh` output, emitted by
// a `TestGoishRef` and copied in mechanically. Nothing is transcribed
// from a spec or from memory. Two runs produced it:
//
//   scripts/goref.sh crypto/x509     <ref building fresh RSA/EC/Ed25519 keys>
//   scripts/goref.sh encoding/asn1   <ref calling parseUTCTime directly>
//
// The first generates a fresh RSA-1024, ECDSA P-256 and Ed25519 key and
// prints Go's own MarshalPKCS1PrivateKey / MarshalPKCS1PublicKey /
// MarshalPKCS8PrivateKey / MarshalECPrivateKey / MarshalPKIXPublicKey
// output for each, plus every scalar the parse side has to recover. The
// second reaches asn1's unexported parseUTCTime / parseGeneralizedTime,
// including the two inputs Go *rejects*.
//
// Why the DER blobs earn their keep as decode tests: getting them to
// parse exercises nearly every arm of `parseField`, which is the whole
// reflective decode layer.
//
//   pkcs1PrivateKey    Kind::Int, big::Int matched by type identity, an
//                      OPTIONAL slice-of-struct
//   pkcs8              a nested struct (pkix.AlgorithmIdentifier), an
//                      OPTIONAL RawValue, a []byte octet string
//   ecPrivateKey       `optional,explicit,tag:0` ObjectIdentifier and
//                      `optional,explicit,tag:1` BitString — the two
//                      explicit-tag branches, one of which is *absent*
//                      in the PKCS#8-embedded form and so also drives
//                      setDefaultValue's optional path
//   publicKeyInfo      a leading `asn1.RawContent` field, filled from the
//                      element's own DER rather than parsed
//   bare big::Int      the top-level non-struct path, with trailing data
//                      returned in `rest`
//
// What it does NOT cover, stated so the gap is not mistaken for
// coverage: the ANY (`Kind::Interface`) arm of parseField, and the
// string arms. Both are ported; neither is exercised here, because no
// x509 key shape contains an `any` or a text field.

#![no_std]
#![no_main]
#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicUsize, Ordering};

use goish::crypto::ecdsa;
use goish::crypto::ed25519;
use goish::crypto::rsa;
use goish::crypto::x509::{
    MarshalECPrivateKey, MarshalPKCS1PrivateKey, MarshalPKCS1PublicKey, MarshalPKCS8PrivateKey,
    ParseECPrivateKey, ParsePKCS1PrivateKey, ParsePKCS1PublicKey, ParsePKCS8PrivateKey,
    ParsePKIXPublicKey,
};
use goish::encoding::asn1;
use goish::encoding::hex;
use goish::fmt::Stringer;
use goish::goany::Any;
use goish::goslice::slice;
use goish::math::big;
use goish::time;
use goish::types::byte;
use goish::{bytes, fmt, int, string};

static RAN: AtomicUsize = AtomicUsize::new(0);
static FAILED: AtomicUsize = AtomicUsize::new(0);

fn check(ok: bool, label: &'static str) {
    RAN.fetch_add(1, Ordering::AcqRel);
    if ok {
        fmt::Printf!("PASS: %s\n", string(label));
    } else {
        FAILED.fetch_add(1, Ordering::AcqRel);
        fmt::Printf!("FAIL: %s\n", string(label));
    }
}

fn checkHex(got: string, want: &'static str, label: &'static str) {
    RAN.fetch_add(1, Ordering::AcqRel);
    if got == want {
        fmt::Printf!("PASS: %s\n", string(label));
    } else {
        FAILED.fetch_add(1, Ordering::AcqRel);
        fmt::Printf!(
            "FAIL: %s\n  got  %s\n  want %s\n",
            string(label),
            got,
            string(want)
        );
    }
}

fn unhex(s: &str) -> slice<byte> {
    let (b, err) = hex::DecodeString(s);
    if err != goish::nil {
        fmt::Printf!("FATAL: bad hex constant\n");
    }
    return b;
}

fn tohex(b: &slice<byte>) -> string {
    return hex::EncodeToString(&b.clone().__into_vec());
}

// ─── goref.sh output — do not hand-edit ───────────────────────────────

pub const RSA_PKCS1_PRIV: &str = "3082025c020100028181009ee6a1f2ee9cf2292ee5e3579aa60bcc5c385b3bcffc3d36dd9d0b44c04b1593b3c3b287ae502bfd8115110b744d00d0f964d7adfaa0973eba53d4d3873607f4690675f21987fcf68684405429ab126b2e598fca9ab14f36cc3bb62da5606bde0ca13a3a9a6b62e356bcd2459520c35fd232c48d435192e87315b90292c43f4f0203010001028180069fbea88de1e5066a7a12dc180a4bfb9cec8c8115ce820ec376447dfd362414202e4c46f3b14be42979635882e4a2e013456ce847c66207af64c73e7a287a74590a2f0da504e7316d8d2d6498a01297843108e81c05129e6246b914ed83755b7f1aaa44cb941a2a3b8340b86ea24a729ac2ebf1d5f15c7e7766dfbd3408e9c1024100c47a3b8d6a36ad0aa57c69fcb62e321ad4cc12e29549c12e6e2bb65a8cfcfa04115c36a01597c077c3d3ee8dca3c60e470b30a24309b960a69dec6f5e04a5239024100cf0a286b0cc87bee6ed795b4f75c572b5b60083b24c742bed1c6f85c68f01b5ddfb494b555240e860756b065c4a3d09820e32d08917969f488e6d0af039cfdc702400b5bf9c7724598f98d99c4d2ec817d3a19e5768e0d0d8792b4a1e85811e0aa5fc3d52dff516045ab66f200cfc7ca77db9d3c6cb0acf2c1d8f647fffec529e6d902410086f6d636429506c4fd98a7ccda5b65afabd7444659c953675514e19e4c0209b4fe39979f45ab459475803b697bf055f075afe2116dd3ba106096267f90596ccd024046902d542dcbe33bf5da0008afaf4e7db6737de1edd47650fe8b89c64607632b135fe505471346940f814eaf3e1bdc2632bf9254b4e3c4c68139a03e3c16bba0";
pub const RSA_PKCS1_PUB: &str = "308189028181009ee6a1f2ee9cf2292ee5e3579aa60bcc5c385b3bcffc3d36dd9d0b44c04b1593b3c3b287ae502bfd8115110b744d00d0f964d7adfaa0973eba53d4d3873607f4690675f21987fcf68684405429ab126b2e598fca9ab14f36cc3bb62da5606bde0ca13a3a9a6b62e356bcd2459520c35fd232c48d435192e87315b90292c43f4f0203010001";
pub const RSA_PKCS8: &str = "30820276020100300d06092a864886f70d0101010500048202603082025c020100028181009ee6a1f2ee9cf2292ee5e3579aa60bcc5c385b3bcffc3d36dd9d0b44c04b1593b3c3b287ae502bfd8115110b744d00d0f964d7adfaa0973eba53d4d3873607f4690675f21987fcf68684405429ab126b2e598fca9ab14f36cc3bb62da5606bde0ca13a3a9a6b62e356bcd2459520c35fd232c48d435192e87315b90292c43f4f0203010001028180069fbea88de1e5066a7a12dc180a4bfb9cec8c8115ce820ec376447dfd362414202e4c46f3b14be42979635882e4a2e013456ce847c66207af64c73e7a287a74590a2f0da504e7316d8d2d6498a01297843108e81c05129e6246b914ed83755b7f1aaa44cb941a2a3b8340b86ea24a729ac2ebf1d5f15c7e7766dfbd3408e9c1024100c47a3b8d6a36ad0aa57c69fcb62e321ad4cc12e29549c12e6e2bb65a8cfcfa04115c36a01597c077c3d3ee8dca3c60e470b30a24309b960a69dec6f5e04a5239024100cf0a286b0cc87bee6ed795b4f75c572b5b60083b24c742bed1c6f85c68f01b5ddfb494b555240e860756b065c4a3d09820e32d08917969f488e6d0af039cfdc702400b5bf9c7724598f98d99c4d2ec817d3a19e5768e0d0d8792b4a1e85811e0aa5fc3d52dff516045ab66f200cfc7ca77db9d3c6cb0acf2c1d8f647fffec529e6d902410086f6d636429506c4fd98a7ccda5b65afabd7444659c953675514e19e4c0209b4fe39979f45ab459475803b697bf055f075afe2116dd3ba106096267f90596ccd024046902d542dcbe33bf5da0008afaf4e7db6737de1edd47650fe8b89c64607632b135fe505471346940f814eaf3e1bdc2632bf9254b4e3c4c68139a03e3c16bba0";
pub const RSA_PKIX_PUB: &str = "30819f300d06092a864886f70d010101050003818d00308189028181009ee6a1f2ee9cf2292ee5e3579aa60bcc5c385b3bcffc3d36dd9d0b44c04b1593b3c3b287ae502bfd8115110b744d00d0f964d7adfaa0973eba53d4d3873607f4690675f21987fcf68684405429ab126b2e598fca9ab14f36cc3bb62da5606bde0ca13a3a9a6b62e356bcd2459520c35fd232c48d435192e87315b90292c43f4f0203010001";
pub const RSA_N: &str = "111584012732170261499487311283998266553766051513061294730306554523795980085741130640311465212305549444625750965685516780454900426173851950345882677691909618155962532121569042538724681307671784146629441183106963916801834922382386829963322127768684408029696325344343605768059216975952540408084231758001796824911";
pub const RSA_E: int = 65537;
pub const RSA_D: &str = "4651533069629204181097690379905751929824203926540480296675122556098244008640077649409202785602312603303745237625354102937314615626393694071210941536144422525661122218191047652736243889430580811044889499925892446785039115560337016209079968242984440704722777858995776668759606657752141718272045150137311881665";
pub const RSA_P: &str = "10290360142099362002050968952836205778428847206180045617472513990422504505936518674170399871852675862188650462573757037204195191598435434846047177412334137";
pub const RSA_Q: &str = "10843547863370088925547281637775414770500560813642650214202358448996042666021082102613759562449034135493741828976542318373860884619941026024435367207042503";
pub const RSA_DP: &str = "594933771433152000027024754906333577894424555048540409915061042002393603201145448470812596158655245767014001292277116956325367059317208029535571588802265";
pub const RSA_DQ: &str = "7068649035184658117967422465615473241456352275515225024812749403512655977199943079296657400048028386050073064338249247380381840986513275154735916471905485";
pub const RSA_QINV: &str = "3695694221643378904847426960563219200599745419166114986006963865245321560740431624867497269882352850906016466879761992370601768662236229862331600898276256";
pub const EC_SEC1: &str = "30770201010420940ba408fd695f8b5de889aafd0366e6e6db701532b4d33efaeb71bc613da10ea00a06082a8648ce3d030107a144034200046283d58def679dec57d86bdbeb36cd0ce655228f7f54ce3a25acb54df9199c25f7f52ec591c6d81c8e233eab2ddec5f4740962018c9800294ae0b3b9574c201a";
pub const EC_PKCS8: &str = "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420940ba408fd695f8b5de889aafd0366e6e6db701532b4d33efaeb71bc613da10ea144034200046283d58def679dec57d86bdbeb36cd0ce655228f7f54ce3a25acb54df9199c25f7f52ec591c6d81c8e233eab2ddec5f4740962018c9800294ae0b3b9574c201a";
pub const EC_PKIX_PUB: &str = "3059301306072a8648ce3d020106082a8648ce3d030107034200046283d58def679dec57d86bdbeb36cd0ce655228f7f54ce3a25acb54df9199c25f7f52ec591c6d81c8e233eab2ddec5f4740962018c9800294ae0b3b9574c201a";
pub const EC_D: &str =
    "66962869036803792517252271411794185920904369633174339968503819875414808830222";
pub const EC_X: &str =
    "44559590025182684090047224048952823820761123113194172351827877841355163671589";
pub const EC_Y: &str =
    "112154473937731029928959042955816822867270053756587384329823820875103166275610";
pub const ED_PKCS8: &str = "302e020100300506032b65700422042065f45a6006942ec426a1667d42e02fbce8ed73436dd444cac275f58b50982aa1";
pub const ED_SEED: &str = "65f45a6006942ec426a1667d42e02fbce8ed73436dd444cac275f58b50982aa1";
pub const ED_PKIX_PUB: &str =
    "302a300506032b657003210044864760e04b5f4a5ae44b1d5c0663f1376891efd5e725c2e7181f2372eb513e";
pub const BIGINT_DER: &str = "020d018ee90ff6c373e0ee4e3f0ad2";
pub const BIGINT_BACK: &str = "123456789012345678901234567890";
pub const BIGINT_REST: int = 2;
pub const TIME_SET_UNIX: int = 1262401445;
pub const TIME_SET_DER: &str = "170d3130303130323033303430355a";
pub const BIG_SEVEN_DER: &str = "020107";

// asn1's own parseUTCTime / parseGeneralizedTime. "910506234540+0000"
// and a zone-less GeneralizedTime are the two Go *rejects*.
// Go's values for the two numeric-offset inputs goish rejects; kept so
// the divergence is recorded next to the behaviour that replaces it.
pub const UTC_910506234540M0700: int = 673598740;
pub const UTC_9105062345Z: int = 673573500;
pub const UTC_500506234540Z: int = -620266460;
pub const UTC_491231235959Z: int = 2524607999;
pub const GEN_Z_SEC: int = 1262401445;
pub const GEN_OFFSET_SEC: int = 1262379425;
pub const GEN_FRAC_SEC: int = 1262401445;
pub const GEN_FRAC_NSEC: int = 123456789;

// ─── end goref.sh output ──────────────────────────────────────────────

fn testPKCS1Private() {
    let der = unhex(RSA_PKCS1_PRIV);
    let (key, err) = ParsePKCS1PrivateKey(der.clone());
    check(err == goish::nil, "ParsePKCS1PrivateKey: no error");
    check(key.PublicKey.N.String() == RSA_N, "pkcs1 priv: N");
    check(key.PublicKey.E == RSA_E, "pkcs1 priv: E");
    check(key.D.String() == RSA_D, "pkcs1 priv: D");
    check(key.Primes.Len() == 2, "pkcs1 priv: 2 primes");
    check(key.Primes[0i64].String() == RSA_P, "pkcs1 priv: P");
    check(key.Primes[1i64].String() == RSA_Q, "pkcs1 priv: Q");
    check(key.Precomputed.Dp.String() == RSA_DP, "pkcs1 priv: Dp");
    check(key.Precomputed.Dq.String() == RSA_DQ, "pkcs1 priv: Dq");
    check(
        key.Precomputed.Qinv.String() == RSA_QINV,
        "pkcs1 priv: Qinv",
    );

    // Round trip: re-marshal must be byte-identical to Go's own output.
    let mut k2 = key.clone();
    let out = MarshalPKCS1PrivateKey(&mut k2);
    check(
        tohex(&out) == RSA_PKCS1_PRIV,
        "MarshalPKCS1PrivateKey round trip",
    );

    // Trailing data must be rejected.
    let mut withTrailer = der.clone().__into_vec();
    withTrailer.push(0xAA);
    let (_, err) = ParsePKCS1PrivateKey(slice::__from_vec(withTrailer));
    check(err != goish::nil, "pkcs1 priv: trailing data rejected");
}

fn testPKCS1Public() {
    let der = unhex(RSA_PKCS1_PUB);
    let (key, err) = ParsePKCS1PublicKey(der);
    check(err == goish::nil, "ParsePKCS1PublicKey: no error");
    check(key.N.String() == RSA_N, "pkcs1 pub: N");
    check(key.E == RSA_E, "pkcs1 pub: E");

    let out = MarshalPKCS1PublicKey(&key);
    check(
        tohex(&out) == RSA_PKCS1_PUB,
        "MarshalPKCS1PublicKey round trip",
    );

    // A PKIX SubjectPublicKeyInfo must be diagnosed, not silently parsed.
    let (_, err) = ParsePKCS1PublicKey(unhex(RSA_PKIX_PUB));
    check(err != goish::nil, "pkcs1 pub: rejects PKIX input");
}

fn testPKCS8RSA() {
    let (key, err) = ParsePKCS8PrivateKey(unhex(RSA_PKCS8));
    check(err == goish::nil, "ParsePKCS8PrivateKey(RSA): no error");
    match key.As::<rsa::PrivateKey>() {
        Some(k) => {
            check(k.PublicKey.N.String() == RSA_N, "pkcs8 RSA: N");
            check(k.D.String() == RSA_D, "pkcs8 RSA: D");
            let (out, err) = MarshalPKCS8PrivateKey(&Any::new_fn(k.clone()));
            check(err == goish::nil, "MarshalPKCS8PrivateKey(RSA): no error");
            check(
                tohex(&out) == RSA_PKCS8,
                "MarshalPKCS8PrivateKey(RSA) round trip",
            );
        }
        None => check(false, "pkcs8 RSA: wrong dynamic type"),
    }
}

fn testPKCS8EC() {
    let (key, err) = ParsePKCS8PrivateKey(unhex(EC_PKCS8));
    check(err == goish::nil, "ParsePKCS8PrivateKey(EC): no error");
    match key.As::<ecdsa::PrivateKey>() {
        Some(k) => {
            check(k.D.String() == EC_D, "pkcs8 EC: D");
            check(k.PublicKey.X.String() == EC_X, "pkcs8 EC: X");
            check(k.PublicKey.Y.String() == EC_Y, "pkcs8 EC: Y");
            let (out, err) = MarshalPKCS8PrivateKey(&Any::new_fn(k.clone()));
            check(err == goish::nil, "MarshalPKCS8PrivateKey(EC): no error");
            check(
                tohex(&out) == EC_PKCS8,
                "MarshalPKCS8PrivateKey(EC) round trip",
            );
        }
        None => check(false, "pkcs8 EC: wrong dynamic type"),
    }
}

fn testPKCS8Ed25519() {
    let (key, err) = ParsePKCS8PrivateKey(unhex(ED_PKCS8));
    check(err == goish::nil, "ParsePKCS8PrivateKey(Ed25519): no error");
    match key.As::<ed25519::PrivateKey>() {
        Some(k) => {
            check(tohex(&k.Seed()) == ED_SEED, "pkcs8 Ed25519: seed");
            let (out, err) = MarshalPKCS8PrivateKey(&Any::new_fn(k.clone()));
            check(
                err == goish::nil,
                "MarshalPKCS8PrivateKey(Ed25519): no error",
            );
            checkHex(
                tohex(&out),
                ED_PKCS8,
                "MarshalPKCS8PrivateKey(Ed25519) round trip",
            );
        }
        None => check(false, "pkcs8 Ed25519: wrong dynamic type"),
    }
}

fn testSEC1() {
    let (key, err) = ParseECPrivateKey(unhex(EC_SEC1));
    check(err == goish::nil, "ParseECPrivateKey: no error");
    check(key.D.String() == EC_D, "sec1: D");
    check(key.PublicKey.X.String() == EC_X, "sec1: X");
    check(key.PublicKey.Y.String() == EC_Y, "sec1: Y");

    let (out, err) = MarshalECPrivateKey(&key);
    check(err == goish::nil, "MarshalECPrivateKey: no error");
    check(tohex(&out) == EC_SEC1, "MarshalECPrivateKey round trip");

    // A PKCS#8 blob must be diagnosed, not silently parsed.
    let (_, err) = ParseECPrivateKey(unhex(EC_PKCS8));
    check(err != goish::nil, "sec1: rejects PKCS#8 input");
}

fn testPKIXPublicKey() {
    let (k, err) = ParsePKIXPublicKey(unhex(RSA_PKIX_PUB));
    check(err == goish::nil, "ParsePKIXPublicKey(RSA): no error");
    match k.As::<rsa::PublicKey>() {
        Some(p) => {
            check(p.N.String() == RSA_N, "pkix RSA: N");
            check(p.E == RSA_E, "pkix RSA: E");
        }
        None => check(false, "pkix RSA: wrong dynamic type"),
    }

    let (k, err) = ParsePKIXPublicKey(unhex(EC_PKIX_PUB));
    check(err == goish::nil, "ParsePKIXPublicKey(EC): no error");
    match k.As::<ecdsa::PublicKey>() {
        Some(p) => {
            check(p.X.String() == EC_X, "pkix EC: X");
            check(p.Y.String() == EC_Y, "pkix EC: Y");
        }
        None => check(false, "pkix EC: wrong dynamic type"),
    }

    let (k, err) = ParsePKIXPublicKey(unhex(ED_PKIX_PUB));
    check(err == goish::nil, "ParsePKIXPublicKey(Ed25519): no error");
    match k.As::<ed25519::PublicKey>() {
        Some(_) => check(true, "pkix Ed25519: dynamic type"),
        None => check(false, "pkix Ed25519: wrong dynamic type"),
    }

    // Trailing data after the SubjectPublicKeyInfo must be rejected.
    let mut withTrailer = unhex(RSA_PKIX_PUB).__into_vec();
    withTrailer.push(0xAA);
    let (_, err) = ParsePKIXPublicKey(slice::__from_vec(withTrailer));
    check(err != goish::nil, "pkix: trailing data rejected");

    // A PKCS#1 public key must be diagnosed, not silently parsed.
    let (_, err) = ParsePKIXPublicKey(unhex(RSA_PKCS1_PUB));
    check(err != goish::nil, "pkix: rejects PKCS#1 input");
}

fn testUnmarshalBareBigInt() {
    // Top-level non-struct recipient, plus trailing data returned in
    // `rest` — the two things `Unmarshal`'s own body is responsible for.
    let mut withTrailer = unhex(BIGINT_DER).__into_vec();
    withTrailer.push(0xAA);
    withTrailer.push(0xBB);
    let mut n = big::Int::new();
    let (rest, err) = asn1::Unmarshal(slice::__from_vec(withTrailer), &mut n);
    check(err == goish::nil, "Unmarshal(big::Int): no error");
    check(n.String() == BIGINT_BACK, "Unmarshal(big::Int): value");
    check(
        rest.Len() == BIGINT_REST,
        "Unmarshal(big::Int): rest length",
    );
}

// The OPTIONAL-omission invariant `asn1::makeField` runs — `v ==
// Zero(v.Type())` — for the two types whose reflect descriptor is
// hand-written outside asn1: `time::Time` and `big::Int`. Both declared
// zero fields in `__reflect_type` while emitting two in
// `__reflect_value`, which made their zero unmatchable, so an absent
// OPTIONAL field of either was *encoded* where Go omits it. That is the
// same silent-wrong-DER class as the `reflect::Zero` composite bug, one
// level further in, and it reaches `pkcs1PrivateKey`'s three OPTIONAL
// CRT parameters.
//
// goref.sh encoding/asn1, `MarshalWithParams(x, "optional")`:
//   time.Time{}                        -> "" (omitted)
//   time.Unix(1262401445,0).UTC()      -> 170d3130303130323033303430355a
//   0                                  -> "" (omitted)
//
// and the struct form, `asn1.Marshal` of the pkcs1PrivateKey shape with
// all three CRT parameters nil:
//   CRT_ABSENT -> 30130201000202010102010302010502010702010b
fn testOptionalZeroOmission() {
    let (b, err) = asn1::MarshalWithParams(&time::Time::default(), "optional");
    check(err == goish::nil, "optional zero time::Time: no error");
    check(b.Len() == 0, "optional zero time::Time is omitted");

    let (b, err) = asn1::MarshalWithParams(&time::Unix(TIME_SET_UNIX, 0).UTC(), "optional");
    check(err == goish::nil, "optional set time::Time: no error");
    checkHex(
        tohex(&b),
        TIME_SET_DER,
        "optional set time::Time is emitted",
    );

    // KNOWN DIVERGENCE, recorded rather than hidden: Go's `*big.Int` is a
    // pointer, so it distinguishes a nil one (omitted) from a present
    // pointer to zero (emitted as 020100). goish's `big::Int` is a value
    // with no nil — `== nil` *is* "is zero", the convention crypto/rsa
    // already relies on — so only one branch is expressible, and this is
    // the one that occurs: `pkcs1PrivateKey` with no CRT values must omit
    // Dp/Dq/Qinv, which is Go's CRT_ABSENT above.
    let (b, err) = asn1::MarshalWithParams(&big::Int::new(), "optional");
    check(err == goish::nil, "optional zero big::Int: no error");
    check(
        b.Len() == 0,
        "optional zero big::Int is omitted (KNOWN DIVERGENCE: Go emits 020100 for a non-nil *big.Int)",
    );

    let (b, err) = asn1::MarshalWithParams(&big::NewInt(7), "optional");
    check(err == goish::nil, "optional set big::Int: no error");
    checkHex(tohex(&b), BIG_SEVEN_DER, "optional set big::Int is emitted");

    // The plain-int control: this one always worked, and pins that the
    // fix did not make omission fire too eagerly.
    let (b, err) = asn1::MarshalWithParams(&int(0), "optional");
    check(err == goish::nil, "optional zero int: no error");
    check(b.Len() == 0, "optional zero int is omitted");
}

fn testTimeParsers() {
    // KNOWN DIVERGENCE, pinned rather than hidden: Go parses a numeric
    // zone offset and returns Unix UTC_910506234540M0700 (673598740);
    // goish rejects it. `time::Time` has no Location — `Zone()` is
    // hard-wired to ("UTC", 0) — so an offset cannot be retained, and
    // asn1's own re-Format-and-compare check could never pass. RFC 5280
    //4.1.2.5.1 requires `Z` in certificates, so no conforming
    // certificate reaches this path. See parse_asn1_utc in src/time.
    let (_, err) = asn1::ParseUTCTime(bytes("910506234540-0700"));
    check(
        err != goish::nil,
        "parseUTCTime: numeric offset rejected (KNOWN DIVERGENCE from Go)",
    );

    let (t, err) = asn1::ParseUTCTime(bytes("9105062345Z"));
    check(err == goish::nil, "parseUTCTime: short form no error");
    check(
        t.UTC().Unix() == UTC_9105062345Z,
        "parseUTCTime: short form",
    );

    let (t, err) = asn1::ParseUTCTime(bytes("500506234540Z"));
    check(err == goish::nil, "parseUTCTime: 2050 rollback no error");
    check(
        t.UTC().Unix() == UTC_500506234540Z,
        "parseUTCTime: year >= 2050 rolls back a century",
    );

    let (t, err) = asn1::ParseUTCTime(bytes("491231235959Z"));
    check(err == goish::nil, "parseUTCTime: 2049 no error");
    check(t.UTC().Unix() == UTC_491231235959Z, "parseUTCTime: 2049");

    // Go rejects this one: it parses, but does not serialize back to the
    // original string ("+0000" round-trips as "Z").
    let (_, err) = asn1::ParseUTCTime(bytes("910506234540+0000"));
    check(err != goish::nil, "parseUTCTime: +0000 rejected like Go");

    let (t, err) = asn1::ParseGeneralizedTime(bytes("20100102030405Z"));
    check(err == goish::nil, "parseGeneralizedTime: Z no error");
    check(t.UTC().Unix() == GEN_Z_SEC, "parseGeneralizedTime: Z");

    // KNOWN DIVERGENCE, same cause and same shape as the UTCTime one
    // above: Go returns Unix GEN_OFFSET_SEC (1262379425) here.
    let (_, err) = asn1::ParseGeneralizedTime(bytes("20100102030405+0607"));
    check(
        err != goish::nil,
        "parseGeneralizedTime: numeric offset rejected (KNOWN DIVERGENCE from Go)",
    );

    let (t, err) = asn1::ParseGeneralizedTime(bytes("20100102030405.123456789Z"));
    check(err == goish::nil, "parseGeneralizedTime: fraction no error");
    check(
        t.UTC().Unix() == GEN_FRAC_SEC,
        "parseGeneralizedTime: fraction sec",
    );
    check(
        t.UTC().Nanosecond() == GEN_FRAC_NSEC,
        "parseGeneralizedTime: fraction nsec",
    );

    // Go rejects a GeneralizedTime with no zone.
    let (_, err) = asn1::ParseGeneralizedTime(bytes("20100102030405"));
    check(
        err != goish::nil,
        "parseGeneralizedTime: no-zone rejected like Go",
    );
}

#[goish::main]
fn main() {
    testPKCS1Private();
    testPKCS1Public();
    testPKCS8RSA();
    testPKCS8EC();
    testPKCS8Ed25519();
    testSEC1();
    testPKIXPublicKey();
    testUnmarshalBareBigInt();
    testOptionalZeroOmission();
    testTimeParsers();

    let ran = RAN.load(Ordering::Acquire);
    let failed = FAILED.load(Ordering::Acquire);
    fmt::Printf!("\n%d checks, %d failures\n", int(ran), int(failed));
    if failed != 0 {
        goish::syscall::Exit(1);
    }
}
