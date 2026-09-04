// tls_ref_smoke — crypto/tls handshakes against a running Go.
// (crypto/tls: handshake_client.go, handshake_server.go, conn.go, tls.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_tls_ref.go` run in
// `package tls` by `scripts/goref.sh`.
//
// TLS is the one package where a port being "close" is
// indistinguishable from being wrong: two implementations that each
// talk happily to themselves can still disagree about which connections
// are SAFE. So what is measured is not that a handshake completes — it
// is which handshakes are REFUSED, what the refusal says, and what the
// connection reports about itself afterwards.
//
// A client and a server run in the same process over a loopback socket,
// on both sides of the comparison. That does not test interop and is
// not meant to; it tests the RULES. A negotiation rule one version too
// permissive, a certificate check skipped when ServerName is empty, an
// ALPN mismatch that silently falls back to no protocol — each is a
// same-stack behaviour, and each is a hole.
//
// FOUR DEFECTS, and the first three are one chain that made goish
// unable to serve TLS with the modern default key type at all:
//
//   * `X509KeyPair` could not parse an EC private key. Its own error
//     said as much — "PKCS#1/PKCS#8 RSA and PKCS#8 Ed25519 supported" —
//     and a comment said "no ECDSA signer yet". Go accepts PKCS#8 EC
//     and SEC 1; both arms are ported now.
//   * `crypto::Signer` was not implemented for `ecdsa::PrivateKey`.
//     crypto/tls finds a certificate's signer by downcasting to that
//     trait, so even a parsed EC key failed every handshake with
//     "certificate private key does not implement crypto.Signer".
//   * The signer registry did not list it. Rust's traits are nominal,
//     so `#[goish::interface]` resolves the assertion through a runtime
//     registry that must be told about each impl.
//
//     Together: an ECDSA server certificate — what essentially every
//     modern deployment uses — could not complete a TLS handshake.
//
//   * A remote alert lost its "remote error: " prefix. Go wraps a
//     RECEIVED alert in a net.OpError; goish stored the alert itself.
//     The prefix is not decoration: a locally generated alert prints
//     the same words, so without it a caller cannot tell whether its
//     own stack refused the handshake or the peer did — the first
//     question anyone asks of a failed TLS connection. An existing
//     smoke had encoded the missing prefix as its expectation, with a
//     comment reasoning that goish had no OpError; it has one, and that
//     expectation has been corrected to Go's answer.
//
// A fifth, smaller: the "client offered only unsupported versions"
// message flattened the versions into BYTES before `%x`, printing
// "0304" where Go prints "[304]". That workaround predated fmt handling
// `%x` on a non-byte slice, which it now does.
//
// What is pinned, beyond the fixes:
//
//   * Every certificate refusal reaches the client as an x509 message
//     and the server as "remote error: tls: bad certificate" — the two
//     ends see different things, and both are pinned.
//   * `InsecureSkipVerify` completes the handshake with VerifiedChains
//     EMPTY. The connection works and nothing was verified; a caller
//     reading that field can tell, and one that doesn't, can't.
//   * An RC4-only client is REFUSED rather than negotiated down to.
//   * A version mismatch, an ALPN mismatch and a suite mismatch each
//     produce a distinct pair of errors, client side and server side.
//   * `RequireAndVerifyClientCert` against a client holding a
//     certificate from the WRONG CA reports "client didn't provide a
//     certificate" — not "wrong CA". The client, seeing no acceptable
//     CA in the request, sends nothing at all. Worth pinning because
//     the message misdescribes the cause and an operator will chase it.
//
// Two things are deliberately NOT pinned by name. The negotiated TLS
// 1.3 suite depends on whether the CPU has AES hardware, so its
// security CLASS is pinned instead — a handshake must never land on a
// suite Go itself calls insecure — while the two TLS 1.2 cases that
// offer exactly one suite DO pin the name, because there the config
// decides. And the expiry message quotes the wall clock, so timestamps
// are replaced with <T>: the message is the measurement, the instants
// are not.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use goish::crypto::tls;
use goish::crypto::x509;
use goish::encoding::hex;
use goish::encoding::pem;
use goish::errors::error;
use goish::fmt;
use goish::go;
use goish::gochan::chan;
use goish::goslice::slice;
use goish::gostring::string;
use goish::io;
use goish::net;
use goish::strings;
use goish::syscall;
use goish::types::{byte, int, uint16};
const GO: [&str; 70] = [
    "key pkcs8=308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420e5d028741df393d49158e0ffed9b6a6ac27ddb3312fec052cd80195c19678aeba144034200047f5b4349d9bab25969a0db99e25093bca067a4920702cc2fa47b522f7b55c843a8a9f27393564579d7461f62f59e70b9ccc31ba27de57bea6df27f5baac2bfbe",
    "der ca           308201523081f9a003020102020101300a06082a8648ce3d0403023011310f300d06035504031306746c732d6361301e170d3236303930333034353032385a170d3237303930333036353032385a3011310f300d06035504031306746c732d63613059301306072a8648ce3d020106082a8648ce3d030107034200047f5b4349d9bab25969a0db99e25093bca067a4920702cc2fa47b522f7b55c843a8a9f27393564579d7461f62f59e70b9ccc31ba27de57bea6df27f5baac2bfbea3423040300e0603551d0f0101ff040403020204300f0603551d130101ff040530030101ff301d0603551d0e041604143588e9a6b8d3aaf209ea09f9f137428db008b628300a06082a8648ce3d0403020348003045022100ea110659ccba25eefa15be6a0364bd9a042ad00d896e89c5f9ec6401271774e602205107a9c3dddfc6eaa52aff4ceee456aa22fd1300170170ee6244e7304bd5ea35",
    "der leaf         3082017a30820120a003020102020102300a06082a8648ce3d0403023011310f300d06035504031306746c732d6361301e170d3236303930333034353032385a170d3237303930333036353032385a301431123010060355040313096c6f63616c686f73743059301306072a8648ce3d020106082a8648ce3d030107034200047f5b4349d9bab25969a0db99e25093bca067a4920702cc2fa47b522f7b55c843a8a9f27393564579d7461f62f59e70b9ccc31ba27de57bea6df27f5baac2bfbea3663064301d0603551d250416301406082b0601050507030106082b06010505070302301f0603551d230418301680143588e9a6b8d3aaf209ea09f9f137428db008b62830220603551d11041b301982096c6f63616c686f7374820c6578616d706c652e74657374300a06082a8648ce3d0403020348003045022016a82da37743cdbe058332ed176d4a3d42a7bdaf2517705ca56a6a41e9fb680b022100feaa535c67b63483e06847e763a26ea05d1b8e223263d78a1df6e5d1f34c3714",
    "der expired-leaf 3082016a30820110a003020102020103300a06082a8648ce3d0403023011310f300d06035504031306746c732d6361301e170d3236303930313036353032385a170d3236303930323036353032385a30123110300e06035504031307657870697265643059301306072a8648ce3d020106082a8648ce3d030107034200047f5b4349d9bab25969a0db99e25093bca067a4920702cc2fa47b522f7b55c843a8a9f27393564579d7461f62f59e70b9ccc31ba27de57bea6df27f5baac2bfbea3583056301d0603551d250416301406082b0601050507030106082b06010505070302301f0603551d230418301680143588e9a6b8d3aaf209ea09f9f137428db008b62830140603551d11040d300b82096c6f63616c686f7374300a06082a8648ce3d04030203480030450221008e7b17e0f0054c976bb6139433ac98eff3e73436d9ea2a943d79c9327e7c4b7a0220092e4d65694b1a230677fe722a1c34565ea632335903a3755ca0081daa2b733e",
    "der other-ca     308201563081fda003020102020104300a06082a8648ce3d04030230133111300f060355040313086f746865722d6361301e170d3236303930333034353032385a170d3237303930333036353032385a30133111300f060355040313086f746865722d63613059301306072a8648ce3d020106082a8648ce3d030107034200047f5b4349d9bab25969a0db99e25093bca067a4920702cc2fa47b522f7b55c843a8a9f27393564579d7461f62f59e70b9ccc31ba27de57bea6df27f5baac2bfbea3423040300e0603551d0f0101ff040403020204300f0603551d130101ff040530030101ff301d0603551d0e041604143588e9a6b8d3aaf209ea09f9f137428db008b628300a06082a8648ce3d040302034800304502204def1f1d690262c5e0b16540ba052139e6169d5c702fb1ea561360fea051ec1b022100ce066fa92dab5139cec55b16d37f36d3d9b88c6a5e74f3d92485bf1a254159f2",
    "der other-leaf   3082016f30820114a003020102020105300a06082a8648ce3d04030230133111300f060355040313086f746865722d6361301e170d3236303930333034353032385a170d3237303930333036353032385a301431123010060355040313096c6f63616c686f73743059301306072a8648ce3d020106082a8648ce3d030107034200047f5b4349d9bab25969a0db99e25093bca067a4920702cc2fa47b522f7b55c843a8a9f27393564579d7461f62f59e70b9ccc31ba27de57bea6df27f5baac2bfbea3583056301d0603551d250416301406082b0601050507030106082b06010505070302301f0603551d230418301680143588e9a6b8d3aaf209ea09f9f137428db008b62830140603551d11040d300b82096c6f63616c686f7374300a06082a8648ce3d0403020349003046022100d1a790bd147708292b3466f09f17b8d227892c30644a548b23bd7d00ca1fbdd70221008f592971821b3964398ce196720739d9f03c6447e635aaa37f858f07b95000db",
    "hs verified                       -> cerr=<nil> serr=<nil>",
    "st verified                       -> ver=TLS1.3 suite-secure=true suite-insecure=false alpn=\"\" sni=\"localhost\" resumed=false peercerts=2 chains=1 body=\"hi\"",
    "hs alpn-overlap                   -> cerr=<nil> serr=<nil>",
    "st alpn-overlap                   -> ver=TLS1.3 suite-secure=true suite-insecure=false alpn=\"http/1.1\" sni=\"localhost\" resumed=false peercerts=2 chains=1 body=\"hi\"",
    "hs sni-alt-name                   -> cerr=<nil> serr=<nil>",
    "st sni-alt-name                   -> ver=TLS1.3 suite-secure=true suite-insecure=false alpn=\"\" sni=\"example.test\" resumed=false peercerts=2 chains=1 body=\"hi\"",
    "hs tls12-both                     -> cerr=<nil> serr=<nil>",
    "st tls12-both                     -> ver=TLS1.2 suite-secure=true suite-insecure=false alpn=\"\" sni=\"localhost\" resumed=false peercerts=2 chains=1 body=\"hi\"",
    "hs tls13-both                     -> cerr=<nil> serr=<nil>",
    "st tls13-both                     -> ver=TLS1.3 suite-secure=true suite-insecure=false alpn=\"\" sni=\"localhost\" resumed=false peercerts=2 chains=1 body=\"hi\"",
    "hs insecure-skip-verify           -> cerr=<nil> serr=<nil>",
    "st insecure-skip-verify           -> ver=TLS1.3 suite-secure=true suite-insecure=false alpn=\"\" sni=\"localhost\" resumed=false peercerts=2 chains=0 body=\"hi\"",
    "hs tls12-one-suite                -> cerr=<nil> serr=<nil>",
    "st tls12-one-suite                -> ver=TLS1.2 suite-secure=true suite-insecure=false alpn=\"\" sni=\"localhost\" resumed=false peercerts=2 chains=1 body=\"hi\"",
    "pinned tls12-one-suite             -> suite=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "hs tls12-one-suite-chacha         -> cerr=<nil> serr=<nil>",
    "st tls12-one-suite-chacha         -> ver=TLS1.2 suite-secure=true suite-insecure=false alpn=\"\" sni=\"localhost\" resumed=false peercerts=2 chains=1 body=\"hi\"",
    "pinned tls12-one-suite-chacha      -> suite=TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "hs tls12-rc4-only                 -> cerr=remote error: tls: handshake failure serr=tls: no cipher suite supported by both client and server; client offered: [5]",
    "hs unknown-authority              -> cerr=tls: failed to verify certificate: x509: certificate signed by unknown authority serr=remote error: tls: bad certificate",
    "hs wrong-hostname                 -> cerr=tls: failed to verify certificate: x509: certificate is valid for localhost, example.test, not wrong.test serr=remote error: tls: bad certificate",
    "hs expired-cert                   -> cerr=tls: failed to verify certificate: x509: certificate has expired or is not yet valid: current time <T> is after <T> serr=remote error: tls: bad certificate",
    "hs wrong-ca                       -> cerr=tls: failed to verify certificate: x509: certificate signed by unknown authority serr=remote error: tls: bad certificate",
    "hs version-mismatch               -> cerr=remote error: tls: protocol version not supported serr=tls: client offered only unsupported versions: [304]",
    "hs alpn-mismatch                  -> cerr=remote error: tls: no application protocol serr=tls: client requested unsupported application protocols ([\"h2\"])",
    "hs server-no-cert                 -> cerr=remote error: tls: unrecognized name serr=tls: no certificates configured",
    "hs suite-mismatch                 -> cerr=remote error: tls: handshake failure serr=tls: no cipher suite supported by both client and server; client offered: [c02f]",
    "hs client-auth-missing            -> cerr=<nil> serr=tls: client didn't provide a certificate",
    "hs client-auth-ok                 -> cerr=<nil> serr=<nil>",
    "st client-auth-ok                 -> ver=TLS1.3 suite-secure=true suite-insecure=false alpn=\"\" sni=\"localhost\" resumed=false peercerts=2 chains=1 body=\"hi\"",
    "hs client-auth-wrong-ca           -> cerr=<nil> serr=tls: client didn't provide a certificate",
    "suite TLS_AES_128_GCM_SHA256                         id=0x1301 insecure=false vers=[772]",
    "suite TLS_AES_256_GCM_SHA384                         id=0x1302 insecure=false vers=[772]",
    "suite TLS_CHACHA20_POLY1305_SHA256                   id=0x1303 insecure=false vers=[772]",
    "suite TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA           id=0xc009 insecure=false vers=[769 770 771]",
    "suite TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA           id=0xc00a insecure=false vers=[769 770 771]",
    "suite TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA             id=0xc013 insecure=false vers=[769 770 771]",
    "suite TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA             id=0xc014 insecure=false vers=[769 770 771]",
    "suite TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256        id=0xc02b insecure=false vers=[771]",
    "suite TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384        id=0xc02c insecure=false vers=[771]",
    "suite TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256          id=0xc02f insecure=false vers=[771]",
    "suite TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384          id=0xc030 insecure=false vers=[771]",
    "suite TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256    id=0xcca8 insecure=false vers=[771]",
    "suite TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256  id=0xcca9 insecure=false vers=[771]",
    "insecure TLS_RSA_WITH_RC4_128_SHA                    id=0x0005 insecure=true",
    "insecure TLS_RSA_WITH_3DES_EDE_CBC_SHA               id=0x000a insecure=true",
    "insecure TLS_RSA_WITH_AES_128_CBC_SHA                id=0x002f insecure=true",
    "insecure TLS_RSA_WITH_AES_256_CBC_SHA                id=0x0035 insecure=true",
    "insecure TLS_RSA_WITH_AES_128_CBC_SHA256             id=0x003c insecure=true",
    "insecure TLS_RSA_WITH_AES_128_GCM_SHA256             id=0x009c insecure=true",
    "insecure TLS_RSA_WITH_AES_256_GCM_SHA384             id=0x009d insecure=true",
    "insecure TLS_ECDHE_ECDSA_WITH_RC4_128_SHA            id=0xc007 insecure=true",
    "insecure TLS_ECDHE_RSA_WITH_RC4_128_SHA              id=0xc011 insecure=true",
    "insecure TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA         id=0xc012 insecure=true",
    "insecure TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256     id=0xc023 insecure=true",
    "insecure TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256       id=0xc027 insecure=true",
    "name 0x0000 -> \"0x0000\"",
    "name 0x1301 -> \"TLS_AES_128_GCM_SHA256\"",
    "name 0x1302 -> \"TLS_AES_256_GCM_SHA384\"",
    "name 0x1303 -> \"TLS_CHACHA20_POLY1305_SHA256\"",
    "name 0xc02f -> \"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\"",
    "name 0xc02b -> \"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256\"",
    "name 0x002f -> \"TLS_RSA_WITH_AES_128_CBC_SHA\"",
    "name 0xffff -> \"0xFFFF\"",
];

// The counters are statics because this smoke prints from free helper
// functions — `run` drives a whole handshake and emits two lines — so
// threading them through every call site would reshape the probe the
// reference was generated from.
static FAILED: goish::sync::Mutex<int> = goish::sync::Mutex::new(0);
static LN: goish::sync::Mutex<int> = goish::sync::Mutex::new(0);

fn chk(got: string) {
    let mut ln = LN.Lock();
    if *ln >= GO.len() as int {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln + 1, got);
        *FAILED.Lock() += 1;
        *ln += 1;
        return;
    }
    let want = s(GO[*ln as usize]);
    *ln += 1;
    if got == want {
        return;
    }
    fmt::Printf!("[!!] line %d FAIL\n  got  %q\n  want %q\n", *ln, got, want);
    *FAILED.Lock() += 1;
}

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}
fn bs(v: Vec<u8>) -> slice<byte> {
    return slice::<byte>::__from_vec(v);
}
const KEY_PKCS8: &str = "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420e5d028741df393d49158e0ffed9b6a6ac27ddb3312fec052cd80195c19678aeba144034200047f5b4349d9bab25969a0db99e25093bca067a4920702cc2fa47b522f7b55c843a8a9f27393564579d7461f62f59e70b9ccc31ba27de57bea6df27f5baac2bfbe";
const DER_CA: &str = "308201523081f9a003020102020101300a06082a8648ce3d0403023011310f300d06035504031306746c732d6361301e170d3236303930333034353032385a170d3237303930333036353032385a3011310f300d06035504031306746c732d63613059301306072a8648ce3d020106082a8648ce3d030107034200047f5b4349d9bab25969a0db99e25093bca067a4920702cc2fa47b522f7b55c843a8a9f27393564579d7461f62f59e70b9ccc31ba27de57bea6df27f5baac2bfbea3423040300e0603551d0f0101ff040403020204300f0603551d130101ff040530030101ff301d0603551d0e041604143588e9a6b8d3aaf209ea09f9f137428db008b628300a06082a8648ce3d0403020348003045022100ea110659ccba25eefa15be6a0364bd9a042ad00d896e89c5f9ec6401271774e602205107a9c3dddfc6eaa52aff4ceee456aa22fd1300170170ee6244e7304bd5ea35";
const DER_LEAF: &str = "3082017a30820120a003020102020102300a06082a8648ce3d0403023011310f300d06035504031306746c732d6361301e170d3236303930333034353032385a170d3237303930333036353032385a301431123010060355040313096c6f63616c686f73743059301306072a8648ce3d020106082a8648ce3d030107034200047f5b4349d9bab25969a0db99e25093bca067a4920702cc2fa47b522f7b55c843a8a9f27393564579d7461f62f59e70b9ccc31ba27de57bea6df27f5baac2bfbea3663064301d0603551d250416301406082b0601050507030106082b06010505070302301f0603551d230418301680143588e9a6b8d3aaf209ea09f9f137428db008b62830220603551d11041b301982096c6f63616c686f7374820c6578616d706c652e74657374300a06082a8648ce3d0403020348003045022016a82da37743cdbe058332ed176d4a3d42a7bdaf2517705ca56a6a41e9fb680b022100feaa535c67b63483e06847e763a26ea05d1b8e223263d78a1df6e5d1f34c3714";
const DER_EXPIRED_LEAF: &str = "3082016a30820110a003020102020103300a06082a8648ce3d0403023011310f300d06035504031306746c732d6361301e170d3236303930313036353032385a170d3236303930323036353032385a30123110300e06035504031307657870697265643059301306072a8648ce3d020106082a8648ce3d030107034200047f5b4349d9bab25969a0db99e25093bca067a4920702cc2fa47b522f7b55c843a8a9f27393564579d7461f62f59e70b9ccc31ba27de57bea6df27f5baac2bfbea3583056301d0603551d250416301406082b0601050507030106082b06010505070302301f0603551d230418301680143588e9a6b8d3aaf209ea09f9f137428db008b62830140603551d11040d300b82096c6f63616c686f7374300a06082a8648ce3d04030203480030450221008e7b17e0f0054c976bb6139433ac98eff3e73436d9ea2a943d79c9327e7c4b7a0220092e4d65694b1a230677fe722a1c34565ea632335903a3755ca0081daa2b733e";
const DER_OTHER_CA: &str = "308201563081fda003020102020104300a06082a8648ce3d04030230133111300f060355040313086f746865722d6361301e170d3236303930333034353032385a170d3237303930333036353032385a30133111300f060355040313086f746865722d63613059301306072a8648ce3d020106082a8648ce3d030107034200047f5b4349d9bab25969a0db99e25093bca067a4920702cc2fa47b522f7b55c843a8a9f27393564579d7461f62f59e70b9ccc31ba27de57bea6df27f5baac2bfbea3423040300e0603551d0f0101ff040403020204300f0603551d130101ff040530030101ff301d0603551d0e041604143588e9a6b8d3aaf209ea09f9f137428db008b628300a06082a8648ce3d040302034800304502204def1f1d690262c5e0b16540ba052139e6169d5c702fb1ea561360fea051ec1b022100ce066fa92dab5139cec55b16d37f36d3d9b88c6a5e74f3d92485bf1a254159f2";
const DER_OTHER_LEAF: &str = "3082016f30820114a003020102020105300a06082a8648ce3d04030230133111300f060355040313086f746865722d6361301e170d3236303930333034353032385a170d3237303930333036353032385a301431123010060355040313096c6f63616c686f73743059301306072a8648ce3d020106082a8648ce3d030107034200047f5b4349d9bab25969a0db99e25093bca067a4920702cc2fa47b522f7b55c843a8a9f27393564579d7461f62f59e70b9ccc31ba27de57bea6df27f5baac2bfbea3583056301d0603551d250416301406082b0601050507030106082b06010505070302301f0603551d230418301680143588e9a6b8d3aaf209ea09f9f137428db008b62830140603551d11040d300b82096c6f63616c686f7374300a06082a8648ce3d0403020349003046022100d1a790bd147708292b3466f09f17b8d227892c30644a548b23bd7d00ca1fbdd70221008f592971821b3964398ce196720739d9f03c6447e635aaa37f858f07b95000db";

fn dehex(h: &str) -> slice<byte> {
    let (b, _) = hex::DecodeString(h);
    return b;
}
fn cert(h: &str) -> x509::Certificate {
    let (c, e) = x509::ParseCertificate(dehex(h));
    if e != goish::nil {
        chk(fmt::Sprintf!("[!!] parse-err=%q", e.Error()));
    }
    return c;
}
fn pemBlock(typ: &str, der: &slice<byte>) -> slice<byte> {
    let mut b = pem::Block {
        Type: s(typ),
        Headers: goish::gomap::map::<string, string>::new(),
        Bytes: der.clone(),
    };
    return pem::EncodeToMemory(&mut b);
}
// A tls.Certificate over the given chain, built through X509KeyPair so
// the PKCS#8 key parses the same way Go's does.
fn chainFor(leafHex: &str, caHex: &str) -> tls::Certificate {
    let mut p = pemBlock("CERTIFICATE", &dehex(leafHex)).to_vec();
    p.extend_from_slice(&pemBlock("CERTIFICATE", &dehex(caHex)).to_vec());
    let k = pemBlock("PRIVATE KEY", &dehex(KEY_PKCS8));
    let (c, e) = tls::X509KeyPair(bs(p), k.to_vec());
    if e != goish::nil {
        chk(fmt::Sprintf!("[!!] keypair-err=%q", e.Error()));
    }
    return c;
}
fn pool(cs: &[&x509::Certificate]) -> x509::CertPool {
    let mut p = x509::NewCertPool();
    for c in cs.iter() {
        p.AddCert((*c).clone());
    }
    return p;
}
fn errText(err: error) -> string {
    if err == goish::nil {
        return s("<nil>");
    }
    let e = err.Error();
    if strings::Contains(e.clone(), s("use of closed network connection"))
        || strings::Contains(e.clone(), s("connection reset by peer"))
        || strings::Contains(e.clone(), s("broken pipe"))
        || e == "EOF"
    {
        return s("<closed>");
    }
    // The expiry message quotes the wall clock and the certificate's
    // notAfter, both of which move with the run.
    let mut out = string::new();
    let b = e.as_bytes();
    let mut i = 0usize;
    while i < b.len() {
        if i + 20 <= b.len() && isStamp(&b[i..i + 20]) {
            out = out + "<T>";
            i += 20;
            continue;
        }
        out = out + string::from_bytes(&b[i..i + 1]);
        i += 1;
    }
    return out;
}
fn isStamp(w: &[u8]) -> bool {
    // YYYY-MM-DDTHH:MM:SSZ
    let d = |c: u8| c.is_ascii_digit();
    return d(w[0])
        && d(w[1])
        && d(w[2])
        && d(w[3])
        && w[4] == b'-'
        && d(w[5])
        && d(w[6])
        && w[7] == b'-'
        && d(w[8])
        && d(w[9])
        && w[10] == b'T'
        && d(w[11])
        && d(w[12])
        && w[13] == b':'
        && d(w[14])
        && d(w[15])
        && w[16] == b':'
        && d(w[17])
        && d(w[18])
        && w[19] == b'Z';
}
fn suiteIsSecure(id: uint16) -> bool {
    let all = tls::CipherSuites();
    for i in 0..all.Len() {
        if all[i].ID == id {
            return true;
        }
    }
    return false;
}
fn suiteIsInsecure(id: uint16) -> bool {
    let all = tls::InsecureCipherSuites();
    for i in 0..all.Len() {
        if all[i].ID == id {
            return true;
        }
    }
    return false;
}
fn versionName(v: uint16) -> string {
    if v == tls::VersionTLS10 {
        return s("TLS1.0");
    }
    if v == tls::VersionTLS11 {
        return s("TLS1.1");
    }
    if v == tls::VersionTLS12 {
        return s("TLS1.2");
    }
    if v == tls::VersionTLS13 {
        return s("TLS1.3");
    }
    return fmt::Sprintf!("0x%04x", v);
}
fn run(label: &str, cc: tls::Config, sc: tls::Config) {
    let (ln, lerr) = net::Listen(s("tcp"), s("127.0.0.1:0"));
    if lerr != goish::nil {
        chk(fmt::Sprintf!("[!!] listen-err=%q", lerr.Error()));
        return;
    }
    let addr = ln.Addr().String();
    let done: chan<(string, uint16, string, int)> = chan::new_buffered(1);
    let d2 = done.clone();
    let scc = sc.clone();
    go!(move || {
        let (raw, aerr) = ln.Accept();
        if aerr != goish::nil {
            d2.Send((s("<accept-err>"), 0, string::new(), 0));
            return;
        }
        let mut sv = tls::Server(Box::new(raw), &scc);
        let herr = sv.Handshake();
        let st = sv.ConnectionState();
        if herr == goish::nil {
            let _ = io::Writer::Write(&mut sv, bs(b"hi".to_vec()));
        }
        let _ = io::Closer::Close(&mut sv);
        d2.Send((errText(herr), st.CipherSuite, st.ServerName.clone(), 0));
    });
    let (raw, derr) = net::Dial(s("tcp"), addr);
    if derr != goish::nil {
        chk(fmt::Sprintf!("[!!] dial-err=%q", derr.Error()));
        return;
    }
    let mut cl = tls::Client(Box::new(raw), &cc);
    let cerr = cl.Handshake();
    let cstate = cl.ConnectionState();
    let mut got = string::new();
    if cerr == goish::nil {
        let mut buf = bs(alloc::vec![0u8; 2]);
        let (n, _) = io::ReadFull(&mut cl, &mut buf);
        got = string::from_bytes(&buf.to_vec()[..n as usize]);
    }
    let _ = io::Closer::Close(&mut cl);
    let ((serrText, _ssuite, sni, _z), _ok) = done.Recv();
    chk(fmt::Sprintf!(
        "hs %-30s -> cerr=%s serr=%s",
        s(label),
        errText(cerr.clone()),
        serrText.clone()
    ));
    if cerr == goish::nil && serrText == "<nil>" {
        chk(fmt::Sprintf!(
            "st %-30s -> ver=%s suite-secure=%v suite-insecure=%v alpn=%q sni=%q resumed=%v peercerts=%d chains=%d body=%q",
            s(label), versionName(cstate.Version),
            suiteIsSecure(cstate.CipherSuite), suiteIsInsecure(cstate.CipherSuite),
            cstate.NegotiatedProtocol.clone(), sni, cstate.DidResume,
            cstate.PeerCertificates.Len(), cstate.VerifiedChains.Len(), got
        ));
        if cc.CipherSuites.Len() == 1 {
            chk(fmt::Sprintf!(
                "pinned %-27s -> suite=%s",
                s(label),
                tls::CipherSuiteName(cstate.CipherSuite)
            ));
        }
    }
}
#[goish::main]
fn main() {
    let ca = cert(DER_CA);
    let otherCA = cert(DER_OTHER_CA);
    chk(fmt::Sprintf!("key pkcs8=%s", s(KEY_PKCS8)));
    for (n, h) in [
        ("ca", DER_CA),
        ("leaf", DER_LEAF),
        ("expired-leaf", DER_EXPIRED_LEAF),
        ("other-ca", DER_OTHER_CA),
        ("other-leaf", DER_OTHER_LEAF),
    ] {
        chk(fmt::Sprintf!("der %-12s %s", s(n), s(h)));
    }
    let leafChain = chainFor(DER_LEAF, DER_CA);
    let expiredChain = chainFor(DER_EXPIRED_LEAF, DER_CA);
    let otherChain = chainFor(DER_OTHER_LEAF, DER_OTHER_CA);
    let base = |ca: &x509::Certificate, chain: &tls::Certificate| -> (tls::Config, tls::Config) {
        let mut cc = tls::Config::default();
        cc.RootCAs = Some(pool(&[ca]));
        cc.ServerName = s("localhost");
        let mut sc = tls::Config::default();
        sc.Certificates = slice::__from_vec(alloc::vec![chain.clone()]);
        return (cc, sc);
    };
    {
        let (cc, sc) = base(&ca, &leafChain);
        run("verified", cc, sc);
    }
    {
        let (mut cc, mut sc) = base(&ca, &leafChain);
        cc.NextProtos = slice::__from_vec(alloc::vec![s("h2"), s("http/1.1")]);
        sc.NextProtos = slice::__from_vec(alloc::vec![s("http/1.1")]);
        run("alpn-overlap", cc, sc);
    }
    {
        let (mut cc, sc) = base(&ca, &leafChain);
        cc.ServerName = s("example.test");
        run("sni-alt-name", cc, sc);
    }
    {
        let (mut cc, mut sc) = base(&ca, &leafChain);
        cc.MinVersion = tls::VersionTLS12;
        cc.MaxVersion = tls::VersionTLS12;
        sc.MinVersion = tls::VersionTLS12;
        sc.MaxVersion = tls::VersionTLS12;
        run("tls12-both", cc, sc);
    }
    {
        let (mut cc, mut sc) = base(&ca, &leafChain);
        cc.MinVersion = tls::VersionTLS13;
        cc.MaxVersion = tls::VersionTLS13;
        sc.MinVersion = tls::VersionTLS13;
        sc.MaxVersion = tls::VersionTLS13;
        run("tls13-both", cc, sc);
    }
    {
        let (mut cc, sc) = base(&ca, &leafChain);
        cc.InsecureSkipVerify = true;
        cc.RootCAs = None;
        run("insecure-skip-verify", cc, sc);
    }
    {
        let (mut cc, mut sc) = base(&ca, &leafChain);
        cc.MinVersion = tls::VersionTLS12;
        cc.MaxVersion = tls::VersionTLS12;
        sc.MinVersion = tls::VersionTLS12;
        sc.MaxVersion = tls::VersionTLS12;
        cc.CipherSuites =
            slice::__from_vec(alloc::vec![tls::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256]);
        run("tls12-one-suite", cc, sc);
    }
    {
        let (mut cc, mut sc) = base(&ca, &leafChain);
        cc.MinVersion = tls::VersionTLS12;
        cc.MaxVersion = tls::VersionTLS12;
        sc.MinVersion = tls::VersionTLS12;
        sc.MaxVersion = tls::VersionTLS12;
        cc.CipherSuites = slice::__from_vec(alloc::vec![
            tls::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        ]);
        run("tls12-one-suite-chacha", cc, sc);
    }
    {
        let (mut cc, mut sc) = base(&ca, &leafChain);
        cc.MinVersion = tls::VersionTLS12;
        cc.MaxVersion = tls::VersionTLS12;
        sc.MinVersion = tls::VersionTLS12;
        sc.MaxVersion = tls::VersionTLS12;
        cc.CipherSuites = slice::__from_vec(alloc::vec![tls::TLS_RSA_WITH_RC4_128_SHA]);
        run("tls12-rc4-only", cc, sc);
    }
    {
        let (mut cc, sc) = base(&ca, &leafChain);
        cc.RootCAs = Some(x509::NewCertPool());
        run("unknown-authority", cc, sc);
    }
    {
        let (mut cc, sc) = base(&ca, &leafChain);
        cc.ServerName = s("wrong.test");
        run("wrong-hostname", cc, sc);
    }
    {
        let (cc, mut sc) = base(&ca, &leafChain);
        sc.Certificates = slice::__from_vec(alloc::vec![expiredChain.clone()]);
        run("expired-cert", cc, sc);
    }
    {
        let (cc, mut sc) = base(&ca, &leafChain);
        sc.Certificates = slice::__from_vec(alloc::vec![otherChain.clone()]);
        run("wrong-ca", cc, sc);
    }
    {
        let (mut cc, mut sc) = base(&ca, &leafChain);
        cc.MinVersion = tls::VersionTLS13;
        cc.MaxVersion = tls::VersionTLS13;
        sc.MinVersion = tls::VersionTLS12;
        sc.MaxVersion = tls::VersionTLS12;
        run("version-mismatch", cc, sc);
    }
    {
        let (mut cc, mut sc) = base(&ca, &leafChain);
        cc.NextProtos = slice::__from_vec(alloc::vec![s("h2")]);
        sc.NextProtos = slice::__from_vec(alloc::vec![s("spdy/3")]);
        run("alpn-mismatch", cc, sc);
    }
    {
        let (cc, mut sc) = base(&ca, &leafChain);
        sc.Certificates = slice::new();
        run("server-no-cert", cc, sc);
    }
    {
        let (mut cc, mut sc) = base(&ca, &leafChain);
        cc.MinVersion = tls::VersionTLS12;
        cc.MaxVersion = tls::VersionTLS12;
        cc.CipherSuites =
            slice::__from_vec(alloc::vec![tls::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256]);
        sc.MinVersion = tls::VersionTLS12;
        sc.MaxVersion = tls::VersionTLS12;
        sc.CipherSuites =
            slice::__from_vec(alloc::vec![tls::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256]);
        run("suite-mismatch", cc, sc);
    }
    {
        let (cc, mut sc) = base(&ca, &leafChain);
        sc.ClientAuth = tls::RequireAndVerifyClientCert;
        sc.ClientCAs = Some(pool(&[&ca]));
        run("client-auth-missing", cc, sc);
    }
    {
        let (mut cc, mut sc) = base(&ca, &leafChain);
        cc.Certificates = slice::__from_vec(alloc::vec![leafChain.clone()]);
        sc.ClientAuth = tls::RequireAndVerifyClientCert;
        sc.ClientCAs = Some(pool(&[&ca]));
        run("client-auth-ok", cc, sc);
    }
    {
        let (mut cc, mut sc) = base(&ca, &leafChain);
        cc.Certificates = slice::__from_vec(alloc::vec![otherChain.clone()]);
        sc.ClientAuth = tls::RequireAndVerifyClientCert;
        sc.ClientCAs = Some(pool(&[&ca]));
        run("client-auth-wrong-ca", cc, sc);
    }
    let _ = otherCA;
    let suites = tls::CipherSuites();
    for i in 0..suites.Len() {
        let cs = suites[i].clone();
        let mut vs = string::from("[");
        for j in 0..cs.SupportedVersions.Len() {
            if j > 0 {
                vs = vs + " ";
            }
            vs = vs + fmt::Sprintf!("%d", cs.SupportedVersions[j]);
        }
        vs = vs + "]";
        chk(fmt::Sprintf!(
            "suite %-46s id=0x%04x insecure=%v vers=%s",
            cs.Name.clone(),
            cs.ID,
            cs.Insecure,
            vs
        ));
    }
    let ins = tls::InsecureCipherSuites();
    for i in 0..ins.Len() {
        let cs = ins[i].clone();
        chk(fmt::Sprintf!(
            "insecure %-43s id=0x%04x insecure=%v",
            cs.Name.clone(),
            cs.ID,
            cs.Insecure
        ));
    }
    for id in [
        0x0000u16, 0x1301, 0x1302, 0x1303, 0xc02f, 0xc02b, 0x002f, 0xffff,
    ] {
        chk(fmt::Sprintf!(
            "name 0x%04x -> %q",
            id,
            tls::CipherSuiteName(id)
        ));
    }
    let ln = *LN.Lock();
    let mut failed = *FAILED.Lock();
    if ln != GO.len() as int {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln, GO.len() as int);
        failed += 1;
    }
    if failed == 0 {
        fmt::Printf!("ok %d/%d\n", ln, ln);
        return;
    }
    fmt::Printf!("FAILED %d of %d\n", failed, ln);
    goish::syscall::Exit(1);
}
