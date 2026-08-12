// crypto/tls — Go's `crypto/tls` package.
//
// Goish v1.1 ships:
//   * `Config` struct with common fields (InsecureSkipVerify, ServerName, etc.)
//   * TLS 1.2 client-side handshake for TLS_RSA_WITH_AES_128_CBC_SHA (0x002F)
//   * `Conn` type wrapping an `io::Reader + io::Writer` with record-layer I/O
//   * `Dial(network, addr, cfg)` — connect + handshake
//   * `Client(conn, cfg)` — wrap an existing connection
//
// Reference: Go 1.25 `src/crypto/tls/`.

#![allow(non_snake_case, non_upper_case_globals)]

pub mod alert;
pub mod auth;
mod defaults_fips140;
pub mod conn;
pub(crate) mod cache;
pub mod ticket;
pub mod handshake_server;

// go: none — goish-only: auth.go's functions are unexported in Go,
// where tests are in-package. See the `defaults_*` shims below.
#[doc(hidden)]
pub fn auth_typeAndHashFromSignatureScheme(
    s: common::SignatureScheme,
) -> (crate::types::uint8, crate::crypto::Hash, crate::error) {
    return auth::typeAndHashFromSignatureScheme(s);
}

// go: none — goish-only: see `auth_typeAndHashFromSignatureScheme`.
#[doc(hidden)]
pub fn auth_signatureSchemesForPublicKey(
    version: crate::types::uint16,
    pub_: &crate::goany::Any,
) -> crate::goslice::slice<common::SignatureScheme> {
    return auth::signatureSchemesForPublicKey(version, pub_);
}

// go: none — goish-only: see `auth_typeAndHashFromSignatureScheme`.
#[doc(hidden)]
pub fn auth_legacyTypeAndHashFromPublicKey(
    pub_: &crate::goany::Any,
) -> (crate::types::uint8, crate::crypto::Hash, crate::error) {
    return auth::legacyTypeAndHashFromPublicKey(pub_);
}
pub mod cipher_suites;
pub use cipher_suites::{CipherSuite, CipherSuiteName, CipherSuites, InsecureCipherSuites};
pub use cipher_suites::{
    TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_RC4_128_SHA, TLS_FALLBACK_SCSV, TLS_RSA_WITH_3DES_EDE_CBC_SHA,
    TLS_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_128_CBC_SHA256,
    TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_256_CBC_SHA,
    TLS_RSA_WITH_AES_256_GCM_SHA384, TLS_RSA_WITH_RC4_128_SHA,
};
pub mod common;
pub mod common_string;
pub mod defaults;
pub mod ech;
pub mod prf;
pub mod quic;
pub use quic::{QUICEncryptionLevel, QUICEncryptionLevelApplication, QUICEncryptionLevelEarly, QUICEncryptionLevelHandshake, QUICEncryptionLevelInitial};
pub mod tls;
pub use tls::timeoutError;

// go: none — goish-only: prf.go's functions are all unexported in Go,
// where the tests are in-package. See the `defaults_*` shims above.
#[doc(hidden)]
pub fn prf_prf10(
    secret: crate::goslice::slice<crate::types::byte>,
    label: crate::gostring::string,
    seed: crate::goslice::slice<crate::types::byte>,
    keyLen: crate::types::int,
) -> crate::goslice::slice<crate::types::byte> {
    return prf::prf10(secret, label, seed, keyLen);
}

// go: none — goish-only: see `prf_prf10`.
#[doc(hidden)]
pub fn prf_prf12_sha256(
    secret: crate::goslice::slice<crate::types::byte>,
    label: crate::gostring::string,
    seed: crate::goslice::slice<crate::types::byte>,
    keyLen: crate::types::int,
) -> crate::goslice::slice<crate::types::byte> {
    return prf::prf12(
        crate::crypto::sha256::NewHash
            as fn() -> alloc::boxed::Box<dyn crate::hash::Hash + Send + Sync>,
        secret,
        label,
        seed,
        keyLen,
    );
}

// go: none — goish-only: see `prf_prf10`.
#[doc(hidden)]
pub fn prf_splitPreMasterSecret(
    secret: crate::goslice::slice<crate::types::byte>,
) -> (
    crate::goslice::slice<crate::types::byte>,
    crate::goslice::slice<crate::types::byte>,
) {
    return prf::splitPreMasterSecret(secret);
}

// go: none — goish-only: Go's tests live inside package tls and call its
// unexported functions directly. A goish example is an external crate,
// so the four `defaults.go` functions — all unexported in Go, and kept
// that way — need a visible shim to be testable. Named `defaults_<fn>`
// so it is obvious these are not Go's spelling.
// go: none — goish-only: see the banner above.
#[doc(hidden)]
pub fn defaults_defaultCurvePreferences() -> crate::goslice::slice<common::CurveID> {
    return defaults::defaultCurvePreferences();
}
// go: none — goish-only: see the banner above.
#[doc(hidden)]
pub fn defaults_defaultSupportedSignatureAlgorithms(
) -> crate::goslice::slice<common::SignatureScheme> {
    return defaults::defaultSupportedSignatureAlgorithms();
}
// go: none — goish-only: see the banner above.
#[doc(hidden)]
pub fn defaults_supportedCipherSuites(
    aesGCMPreferred: bool,
) -> crate::goslice::slice<crate::types::uint16> {
    return defaults::supportedCipherSuites(aesGCMPreferred);
}
// go: none — goish-only: see the banner above.
#[doc(hidden)]
pub fn defaults_defaultCipherSuites(
    aesGCMPreferred: bool,
) -> crate::goslice::slice<crate::types::uint16> {
    return defaults::defaultCipherSuites(aesGCMPreferred);
}

// Re-export common.go's protocol enumerations at the package root, the
// way Go has them in package tls.
pub use common::{
    ClientAuthType, CurveID,
    SignatureScheme, VersionName, CurveP256, CurveP384, CurveP521, ECDSAWithP256AndSHA256,
    ECDSAWithP384AndSHA384, ECDSAWithP521AndSHA512, ECDSAWithSHA1, Ed25519, NoClientCert,
    PKCS1WithSHA1, PKCS1WithSHA256, PKCS1WithSHA384, PKCS1WithSHA512, PSSWithSHA256, PSSWithSHA384,
    PSSWithSHA512, RequireAndVerifyClientCert, RequireAnyClientCert, RequestClientCert,
    VerifyClientCertIfGiven, VersionSSL30, VersionTLS10, VersionTLS11, VersionTLS12, VersionTLS13,
    X25519, X25519MLKEM768,
};
pub mod internal;

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::errors::{self, error};
use crate::goslice::slice;
use crate::gostring::string;
use crate::sync::Mutex;
use crate::types::{byte, int};

pub mod legacy_p256;
pub mod record;
pub mod key_agreement;

// go: none — goish-only: key_agreement.go's hash helpers are unexported
// in Go, where the tests are in-package. See the `defaults_*` shims.
#[doc(hidden)]
pub fn ka_hashForServerKeyExchange(
    sigType: crate::types::uint8,
    hashFunc: crate::crypto::Hash,
    version: crate::types::uint16,
    slices: crate::goslice::slice<crate::goslice::slice<crate::types::byte>>,
) -> crate::goslice::slice<crate::types::byte> {
    let v: alloc::vec::Vec<crate::goslice::slice<crate::types::byte>> =
        slices.clone().__into_vec();
    return key_agreement::hashForServerKeyExchange(sigType, hashFunc, version, &v);
}

// go: none — goish-only: see `ka_hashForServerKeyExchange`.
#[doc(hidden)]
pub fn ka_sha1Hash(
    slices: crate::goslice::slice<crate::goslice::slice<crate::types::byte>>,
) -> crate::goslice::slice<crate::types::byte> {
    let v: alloc::vec::Vec<crate::goslice::slice<crate::types::byte>> =
        slices.clone().__into_vec();
    return key_agreement::sha1Hash(&v);
}

// go: none — goish-only: see `ka_hashForServerKeyExchange`.
#[doc(hidden)]
pub fn ka_md5SHA1Hash(
    slices: crate::goslice::slice<crate::goslice::slice<crate::types::byte>>,
) -> crate::goslice::slice<crate::types::byte> {
    let v: alloc::vec::Vec<crate::goslice::slice<crate::types::byte>> =
        slices.clone().__into_vec();
    return key_agreement::md5SHA1Hash(&v);
}
pub mod key_schedule;
pub mod handshake_client_tls13;
pub mod session;
mod handshake_client;
mod handshake_messages;

// go: none — goish-only: the handshake message types are unexported in
// Go, where the tests are in-package. See the `defaults_*` shims below.
#[doc(hidden)]
pub fn msg_keyUpdate_marshal(updateRequested: bool) -> crate::goslice::slice<crate::types::byte> {
    let m = handshake_messages::keyUpdateMsg { updateRequested };
    let (b, _) = m.marshal();
    return b;
}

// go: none — goish-only: see `msg_keyUpdate_marshal`.
#[doc(hidden)]
pub fn msg_keyUpdate_unmarshal(
    data: crate::goslice::slice<crate::types::byte>,
) -> (bool, bool) {
    let mut m = handshake_messages::keyUpdateMsg::default();
    let ok = m.unmarshal(data);
    return (ok, m.updateRequested);
}

// go: none — goish-only: marshal-then-unmarshal for the three simple
// byte-container messages; returns the wire bytes, the parse result and
// the recovered body so one shim covers both directions.
#[doc(hidden)]
pub fn msg_simple_roundtrip(
    which: crate::types::int,
    body: crate::goslice::slice<crate::types::byte>,
) -> (
    crate::goslice::slice<crate::types::byte>,
    bool,
    crate::goslice::slice<crate::types::byte>,
) {
    use crate::goslice::slice as S;
    if which == 0 {
        let m = handshake_messages::serverKeyExchangeMsg { key: body };
        let (b, _) = m.marshal();
        let mut back = handshake_messages::serverKeyExchangeMsg::default();
        let ok = back.unmarshal(b.clone());
        return (b, ok, back.key);
    } else if which == 1 {
        let m = handshake_messages::clientKeyExchangeMsg { ciphertext: body };
        let (b, _) = m.marshal();
        let mut back = handshake_messages::clientKeyExchangeMsg::default();
        let ok = back.unmarshal(b.clone());
        return (b, ok, back.ciphertext);
    }
    let m = handshake_messages::newSessionTicketMsg { ticket: body };
    let (b, _) = m.marshal();
    let mut back = handshake_messages::newSessionTicketMsg::default();
    let ok = back.unmarshal(b.clone());
    let _ = S::__from_vec(alloc::vec::Vec::<crate::types::byte>::new());
    return (b, ok, back.ticket);
}

// go: none — goish-only: parse a raw buffer, for the rejection cases.
#[doc(hidden)]
pub fn msg_simple_unmarshal(
    which: crate::types::int,
    data: crate::goslice::slice<crate::types::byte>,
) -> bool {
    if which == 0 {
        return handshake_messages::serverKeyExchangeMsg::default().unmarshal(data);
    } else if which == 1 {
        return handshake_messages::clientKeyExchangeMsg::default().unmarshal(data);
    }
    return handshake_messages::newSessionTicketMsg::default().unmarshal(data);
}

// go: none — goish-only: see `msg_keyUpdate_marshal`.
#[doc(hidden)]
pub fn msg_helloRequest_marshal() -> crate::goslice::slice<crate::types::byte> {
    let m = handshake_messages::helloRequestMsg {};
    let (b, _) = m.marshal();
    return b;
}

// go: none — goish-only: round-trips addUint64 through readUint64.
#[doc(hidden)]
pub fn msg_uint64_roundtrip(
    vs: crate::goslice::slice<crate::types::uint64>,
) -> (crate::goslice::slice<crate::types::byte>, bool) {
    let mut b = crate::crypto::cryptobyte::NewBuilder(crate::goslice::slice::__from_vec(
        alloc::vec::Vec::new(),
    ));
    for (_, v) in crate::range!(vs.clone()) {
        handshake_messages::addUint64(&mut b, *v);
    }
    let (out, _) = b.Bytes();
    let mut s = crate::crypto::cryptobyte::String::New(out.clone());
    let mut ok = true;
    for (_, want) in crate::range!(vs) {
        let mut got: crate::types::uint64 = 0;
        if !handshake_messages::readUint64(&mut s, &mut got) || got != *want {
            ok = false;
        }
    }
    return (out, ok && s.Empty());
}

// go: none — goish-only: see `msg_keyUpdate_marshal`.
#[doc(hidden)]
pub fn msg_endOfEarlyData_marshal() -> crate::goslice::slice<crate::types::byte> {
    let m = handshake_messages::endOfEarlyDataMsg {};
    let (b, _) = m.marshal();
    return b;
}

// go: none — goish-only: see `msg_keyUpdate_marshal`.
#[doc(hidden)]
pub fn msg_certificateStatus_marshal(
    response: crate::goslice::slice<crate::types::byte>,
) -> crate::goslice::slice<crate::types::byte> {
    let m = handshake_messages::certificateStatusMsg { response };
    let (b, _) = m.marshal();
    return b;
}

// go: none — goish-only: see `msg_keyUpdate_marshal`.
#[doc(hidden)]
pub fn msg_certificateStatus_unmarshal(
    data: crate::goslice::slice<crate::types::byte>,
) -> (bool, crate::goslice::slice<crate::types::byte>) {
    let mut m = handshake_messages::certificateStatusMsg::default();
    let ok = m.unmarshal(data);
    return (ok, m.response);
}
mod handshake_server_tls13;

/// Gate for the per-record debug prints in `Conn::Read`/`Conn::Write`.
/// The one-shot client-handshake prints stay unconditional (once per
/// connection); these fire on every record, which a TLS *server*
/// cannot afford on stdout. Flip to `true` when debugging the record
/// layer.
const DEBUG: bool = false;

macro_rules! tls_debug {
    ($($arg:tt)*) => {
        if DEBUG {
            crate::fmt::Printf!($($arg)*);
        }
    };
}

/// Helper: return the actual key length for TLS 1.3 based on suite ID.
fn tls13_key_len(km: &record::KeyMaterial) -> usize {
    match km.suite {
        0x1302 => 32, // AES-256-GCM
        0x1303 => 32, // ChaCha20-Poly1305
        _ => 16,      // AES-128-GCM default
    }
}

// ─── ConnReader adapter ───────────────────────────────────────────────
// Wraps a `Box<dyn net::Conn>` as an `io::Reader` so we can pass it to
// `record::read_record` which requires `&mut dyn io::Reader`.

struct ConnReaderAdapter<'a>(&'a mut Box<dyn crate::net::Conn>);

impl<'a> crate::io::Reader for ConnReaderAdapter<'a> {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        self.0.Read(p)
    }
}

pub use record::{
    KeyMaterial, DirectionKeys, AeadKeyMaterial, AeadDirectionKeys,
    decode_x509_rsa_pubkey,
    prf12, derive_master_secret, derive_key_material, derive_aead_key_material,
    encrypt_record, decrypt_record, encrypt_record_aead, decrypt_record_aead,
    encode_record, read_record,
    RECORD_APPLICATION, RECORD_CHANGE_CIPHER_SPEC, RECORD_HANDSHAKE,
};

pub use handshake_client::{
    build_client_hello_bytes,
    parse_server_hello_fragment,
    parse_server_key_exchange_x25519,
    do_client_handshake,
    do_client_handshake_chacha20_only,
};

// ─── Config ───────────────────────────────────────────────────────────

/// `tls.Config` (Go 1.25 src/crypto/tls/common.go) — TLS-protocol
/// settings.
#[derive(Clone, Default)]
pub struct Config {
    /// Server name to verify against the cert. Default: derived from
    /// the dial address.
    pub ServerName: string,
    /// Skip cert chain validation. Insecure; documented to be only
    /// for testing.
    pub InsecureSkipVerify: bool,
    /// Minimum TLS protocol version (numeric Go const, e.g.
    /// `tls.VersionTLS12 = 0x0303`). Zero = library default.
    pub MinVersion: u16,
    /// Maximum TLS protocol version. Zero = library default.
    pub MaxVersion: u16,
    /// RootCAs defines the set of root certificate authorities that clients
    /// use when verifying server certificates.
    pub RootCAs: Option<crate::crypto::x509::CertPool>,
    /// Go: "ClientSessionCache is a cache of ClientSessionState entries
    /// for TLS session resumption. It is only used by clients."
    /// Reference: common.go:684.
    pub ClientSessionCache:
        Option<alloc::sync::Arc<crate::sync::Mutex<alloc::boxed::Box<dyn common::ClientSessionCache>>>>,
    /// Go: "VerifyPeerCertificate, if not nil, is called after normal
    /// certificate verification by either a TLS client or server. It
    /// receives the raw ASN.1 certificates provided by the peer and also
    /// any verified chains that normal processing found. If it returns a
    /// non-nil error, the handshake is aborted and that error results."
    /// Reference: common.go:762.
    pub VerifyPeerCertificate: Option<
        alloc::sync::Arc<
            dyn Fn(
                    crate::goslice::slice<crate::goslice::slice<crate::types::byte>>,
                    crate::goslice::slice<crate::goslice::slice<crate::crypto::x509::Certificate>>,
                ) -> crate::error
                + Send
                + Sync,
        >,
    >,
    /// Go: "VerifyConnection, if not nil, is called after normal
    /// certificate verification and after VerifyPeerCertificate by
    /// either a TLS client or server. If it returns a non-nil error, the
    /// handshake is aborted and that error results." Reference:
    /// common.go:776.
    pub VerifyConnection:
        Option<alloc::sync::Arc<dyn Fn(common::ConnectionState) -> crate::error + Send + Sync>>,
    /// Go: "EncryptedClientHelloRejectionVerify, if not nil, is called
    /// when ECH is rejected, in order to verify the ECH provider
    /// certificate in the outer ClientHello. If it returns a non-nil
    /// error, the handshake is aborted and that error results."
    /// Reference: common.go:855.
    pub EncryptedClientHelloRejectionVerify:
        Option<alloc::sync::Arc<dyn Fn(common::ConnectionState) -> crate::error + Send + Sync>>,
    /// Certificates contains one or more certificate chains to present
    /// to the other side of the connection (server side). The first
    /// entry is used; SNI-based selection (`GetCertificate`) is not
    /// wired yet. Reference: common.go:570.
    pub Certificates: slice<Certificate>,
    /// NextProtos is a list of supported application level protocols,
    /// in order of preference (ALPN). Reference: common.go:604.
    pub NextProtos: slice<string>,
    /// CipherSuites is a list of enabled TLS 1.0-1.2 cipher suites. If
    /// empty (Go: nil), a safe default list is used. Reference:
    /// common.go:644.
    pub CipherSuites: slice<crate::types::uint16>,
    /// CurvePreferences contains the elliptic curves that will be used
    /// in an ECDHE handshake, in preference order. If empty (Go: nil),
    /// the default is used. Reference: common.go:735.
    pub CurvePreferences: slice<common::CurveID>,
    /// EncryptedClientHelloConfigList is a serialized ECHConfigList. If
    /// non-empty, the client will attempt Encrypted Client Hello, which
    /// requires TLS 1.3. Reference: common.go:781.
    pub EncryptedClientHelloConfigList: slice<byte>,
    /// NameToCertificate maps from a certificate name to an element of
    /// Certificates. Deprecated in Go — see Config.GetCertificate — but
    /// still the field BuildNameToCertificate fills. Reference:
    /// common.go:576.
    pub NameToCertificate: crate::gomap::map<string, Certificate>,
    /// SessionTicketsDisabled may be set to true to disable session
    /// ticket and PSK (resumption) support. Reference: common.go:686.
    pub SessionTicketsDisabled: bool,
    /// SessionTicketKey is used by TLS servers to provide session
    /// resumption. Deprecated in Go — see SetSessionTicketKeys — but
    /// still the field initLegacySessionTicketKeyRLocked reads.
    /// Reference: common.go:694.
    pub SessionTicketKey: [byte; 32],
    /// ClientAuth determines the server's policy for TLS Client
    /// Authentication. The default is NoClientCert. Reference:
    /// common.go:625.
    pub ClientAuth: common::ClientAuthType,
    /// Renegotiation controls what types of renegotiation are
    /// supported. The default, none, is correct for the vast majority
    /// of applications. Reference: common.go:752.
    pub Renegotiation: common::RenegotiationSupport,
    /// DynamicRecordSizingDisabled disables adaptive sizing of TLS
    /// records. Reference: common.go:745.
    pub DynamicRecordSizingDisabled: bool,
    /// Explicitly configured ticket keys, newest first.
    ///
    /// Unexported in Go. Rust's struct-update syntax
    /// (`Config { .., ..Default::default() }`) needs every field
    /// visible to the caller, so this is `pub` but `#[doc(hidden)]` —
    /// nothing outside the package should name it.
    #[doc(hidden)]
    pub sessionTicketKeys: slice<common::ticketKey>,
    /// Auto-rotated ticket keys, newest first. Unexported in Go; see
    /// `sessionTicketKeys`.
    #[doc(hidden)]
    pub autoSessionTicketKeys: slice<common::ticketKey>,
}

// The TLS protocol-version constants live in common[rs] now, ported
// from common.go together with VersionName and the rest of the
// enumerations, and are re-exported at the top of this file. They used
// to be hand-declared here as raw `u16`.

// Polymorphic-nil triple per priority #5.
impl From<crate::nilval::Nil> for Config {
    fn from(_: crate::nilval::Nil) -> Self {
        Config::default()
    }
}
impl PartialEq<crate::nilval::Nil> for Config {
    fn eq(&self, _: &crate::nilval::Nil) -> bool {
        self.ServerName == crate::gostring::string::from_static("")
            && !self.InsecureSkipVerify
            && self.MinVersion == 0
            && self.MaxVersion == 0
            && self.RootCAs.is_none()
            && self.Certificates.Len() == 0
            && self.NextProtos.Len() == 0
    }
}
impl PartialEq<Config> for crate::nilval::Nil {
    fn eq(&self, other: &Config) -> bool {
        other.eq(self)
    }
}

// ─── Conn ─────────────────────────────────────────────────────────────

/// Inner mutable state of a TLS connection.
struct ConnInner {
    /// Whether the TLS handshake has completed.
    handshake_complete: bool,
    /// Sequence numbers for each direction (post-handshake record layer).
    client_seq: u64,
    server_seq: u64,
    /// Negotiated key material (all zeroes until handshake completes).
    keys: KeyMaterial,
    /// Buffer of decrypted application data not yet consumed by Read.
    pending: Vec<byte>,
}

impl Default for ConnInner {
    fn default() -> Self {
        ConnInner {
            handshake_complete: false,
            client_seq: 0,
            server_seq: 0,
            keys: KeyMaterial::default(),
            pending: Vec::new(),
        }
    }
}

/// `tls.Conn` — a TLS connection. Wraps an underlying `net::Conn` and
/// provides record-layer encryption/decryption once the handshake is done.
pub struct Conn {
    /// Underlying TCP connection, protected by a mutex so Read/Write
    /// can share it without data races.
    inner_conn: Arc<Mutex<Box<dyn crate::net::Conn>>>,
    state: Arc<Mutex<ConnInner>>,
    config: Config,
    /// Handshake role — mirrors Go's `Conn.isClient` (conn.go:44).
    /// Selects which handshake driver runs and which traffic-key
    /// direction Read/Write use.
    is_client: bool,
}

// Send + Sync are sound because every mutable field is behind Arc<Mutex<>>.
unsafe impl Send for Conn {}
unsafe impl Sync for Conn {}

impl Conn {
    /// `(*tls.Conn).Handshake()` — drive the TLS handshake.
    pub fn Handshake(&mut self) -> error {
        {
            let st = self.state.Lock();
            if st.handshake_complete {
                return errors::nil;
            }
        }

        if !self.is_client {
            return self.server_handshake();
        }

        // We need to pass the conn to the handshake driver.
        // Because ConnInner's mutex is separate we can hold a lock on
        // the conn while running the handshake.
        let skip_verify = self.config.InsecureSkipVerify;
        let server_name: &str = self.config.ServerName.as_ref();

        // Build a temporary adapter that can call Read/Write on the inner conn.
        let (km, err) = {
            let mut conn_guard = self.inner_conn.Lock();
            handshake_client::do_client_handshake(
                conn_guard.as_mut(),
                server_name,
                skip_verify,
            )
        };

        if !err.IsNil() {
            return err;
        }

        let mut st = self.state.Lock();
        st.handshake_complete = true;
        st.keys = km;
        if st.keys.is_tls13 {
            // TLS 1.3: application data uses separate key material from handshake.
            // Application sequence numbers start at 0.
            st.client_seq = 0;
            st.server_seq = 0;
        } else {
            // TLS 1.2: the handshake used seq=0 for both client Finished and
            // server Finished. The first post-handshake application data records use seq=1.
            st.client_seq = 1;
            st.server_seq = 1;
        }
        errors::nil
    }

    /// `(*tls.Conn).Read(b)` — decrypt and return application data.
    pub fn Read(&mut self, b: &mut slice<byte>) -> (int, error) {
        {
            let st = self.state.Lock();
            if !st.handshake_complete {
                drop(st);
                let err = self.Handshake();
                if !err.IsNil() {
                    return (0, err);
                }
            }
        }

        // Drain pending buffer first
        {
            let mut st = self.state.Lock();
            if !st.pending.is_empty() {
                let buf: &mut [byte] = &mut *b;
                let n = core::cmp::min(buf.len(), st.pending.len());
                buf[..n].copy_from_slice(&st.pending[..n]);
                st.pending.drain(..n);
                return (n as int, errors::nil); // goishlint:ignore GOISH005
            }
        }

        // Read a new record
        let (rtype, frag_s, err) = {
            let mut conn_guard = self.inner_conn.Lock();
            let mut adapter = ConnReaderAdapter(&mut conn_guard);
            record::read_record(&mut adapter)
        };
        let frag = frag_s.__into_vec();
        if !err.IsNil() {
            return (0, err);
        }

        // Handle TLS 1.3: record type 23 (application) wraps encrypted inner content
        if rtype == record::RECORD_CHANGE_CIPHER_SPEC {
            // TLS 1.3 compatibility CCS — ignore and retry
            drop(frag);
            return Conn::Read(self, b);
        }

        // Handle unencrypted (plaintext) TLS alerts. In TLS 1.3 alerts are
        // supposed to be encrypted (RECORD_APPLICATION with inner_type=21),
        // but some servers send a plaintext close_notify or other alert when
        // terminating the connection or reporting errors. If we tried to
        // AEAD-decrypt a 2-byte alert we'd get "fragment too short for AEAD tag".
        // Treat close_notify (desc=0) as EOF and other alerts as errors.
        if rtype == record::RECORD_ALERT {
            let desc = if frag.len() >= 2 { frag[1] } else { 0 };
            tls_debug!("[tls-debug] plaintext TLS Alert: level=%d desc=%d\n",
                if frag.is_empty() { 0i64 } else { frag[0] as i64 }, desc as i64);
            if desc == 0 {
                return (0, crate::io::EOF.into());
            }
            return (0, crate::errors::New("tls: received alert from server"));
        }

        let is_client = self.is_client;
        let plaintext = {
            let mut st = self.state.Lock();
            // Inbound direction: a client decrypts server-write records,
            // a server decrypts client-write records. The seq counters
            // follow the *sender* role (client_seq counts records sealed
            // with the client-write keys), so both role and counter flip
            // together.
            let seq = if is_client {
                let s = st.server_seq;
                st.server_seq += 1;
                s
            } else {
                let s = st.client_seq;
                st.client_seq += 1;
                s
            };
            tls_debug!("[tls-debug] conn.Read: suite=0x%04x is_tls13=%v rtype=%d seq=%d frag_len=%d\n",
                st.keys.suite as u64, st.keys.is_tls13, rtype as i64, seq, frag.len() as i64);
            if st.keys.is_tls13 {
                // TLS 1.3: decrypt inner content
                use handshake_client_tls13::tls13_decrypt_record_suite;
                let tks = if is_client {
                    key_schedule::TrafficKeys {
                        key: st.keys.tls13_server_key[..tls13_key_len(&st.keys)].to_vec(),
                        iv: st.keys.tls13_server_iv.to_vec(),
                    }
                } else {
                    key_schedule::TrafficKeys {
                        key: st.keys.tls13_client_key[..tls13_key_len(&st.keys)].to_vec(),
                        iv: st.keys.tls13_client_iv.to_vec(),
                    }
                };
                let (inner, inner_type, derr) = tls13_decrypt_record_suite(&tks, seq, &frag, st.keys.suite);
                if !derr.IsNil() { return (0, derr); }
                // inner_type is the real content type:
                // 22 = RECORD_HANDSHAKE (post-handshake, e.g. NewSessionTicket) → skip
                // 21 = RECORD_ALERT (encrypted alert, e.g. close_notify) → return EOF
                // 23 = RECORD_APPLICATION → return data
                tls_debug!("[tls-debug] conn.Read: inner_type=%d inner_len=%d\n",
                    inner_type as i64, inner.len() as i64);
                if inner_type == record::RECORD_HANDSHAKE {
                    let msg_type = if inner.is_empty() { 0u8 } else { inner[0] };
                    tls_debug!("[tls-debug] conn.Read: post-handshake msg type=%d\n",
                        msg_type as i64);
                    if msg_type == 24 {
                        // KeyUpdate (RFC 8446 §4.6.3): update server application traffic keys.
                        // KeyUpdate body: type(1) + len(3) + request_update(1) = 5 bytes.
                        // Derive new server_app_secret via HKDF-Expand-Label(..., "traffic upd", ...).
                        let suite_id = st.keys.suite;
                        if let Some(cs) = key_schedule::cipher_suite_tls13(suite_id) {
                            // Rotate the *inbound* (peer-write) secret:
                            // server-write keys on a client Conn,
                            // client-write keys on a server Conn.
                            let old_secret = if is_client {
                                st.keys.tls13_server_app_secret.clone()
                            } else {
                                st.keys.tls13_client_app_secret.clone()
                            };
                            if !old_secret.is_empty() {
                                let new_secret = key_schedule::next_traffic_secret(cs.hash_fn, &old_secret);
                                let new_keys = key_schedule::traffic_keys(cs.hash_fn, &new_secret, cs.key_len);
                                let key_len = new_keys.key.len().min(32);
                                let iv_len = new_keys.iv.len().min(12);
                                if is_client {
                                    st.keys.tls13_server_key = [0u8; 32];
                                    st.keys.tls13_server_key[..key_len].copy_from_slice(&new_keys.key[..key_len]);
                                    st.keys.tls13_server_iv = [0u8; 12];
                                    st.keys.tls13_server_iv[..iv_len].copy_from_slice(&new_keys.iv[..iv_len]);
                                    st.keys.tls13_server_app_secret = new_secret;
                                    st.server_seq = 0;
                                } else {
                                    st.keys.tls13_client_key = [0u8; 32];
                                    st.keys.tls13_client_key[..key_len].copy_from_slice(&new_keys.key[..key_len]);
                                    st.keys.tls13_client_iv = [0u8; 12];
                                    st.keys.tls13_client_iv[..iv_len].copy_from_slice(&new_keys.iv[..iv_len]);
                                    st.keys.tls13_client_app_secret = new_secret;
                                    st.client_seq = 0;
                                }
                                tls_debug!("[tls-debug] KeyUpdate: rotated inbound app keys, seq reset to 0\n");
                            } else {
                                tls_debug!("[tls-debug] KeyUpdate: inbound app secret is empty, cannot rotate\n");
                            }
                        } else {
                            tls_debug!("[tls-debug] KeyUpdate: unknown suite 0x%04x, skipping key rotation\n",
                                suite_id as u64);
                        }
                        drop(st);
                        return Conn::Read(self, b);
                    }
                    if msg_type == 4 {
                        // NewSessionTicket (RFC 8446 §4.6.1):
                        //   struct {
                        //     uint32 ticket_lifetime;
                        //     uint32 ticket_age_add;
                        //     opaque ticket_nonce<0..255>;
                        //     opaque ticket<1..2^16-1>;
                        //     Extension extensions<0..2^16-2>;
                        //   } NewSessionTicket;
                        // Body starts at inner[4] (after handshake header type+len).
                        let parsed = parse_new_session_ticket(&inner);
                        match parsed {
                            Some(nst) => {
                                let rms = st.keys.tls13_resumption_master_secret.clone();
                                let suite_id = st.keys.suite;
                                let hash_size = st.keys.tls13_hash_size;
                                drop(st);
                                if !rms.is_empty() && hash_size > 0 {
                                    if let Some(cs) = key_schedule::cipher_suite_tls13(suite_id) {
                                        let psk = key_schedule::ExpandLabel(
                                            cs.hash_fn, &rms, "resumption",
                                            &nst.ticket_nonce, hash_size as usize,
                                        );
                                        let server_name = self.config.ServerName.clone();
                                        let state = session::cachedSession {
                                            ticket: nst.ticket,
                                            ticket_age_add: nst.ticket_age_add,
                                            ticket_lifetime: nst.ticket_lifetime,
                                            received_at_ms: session::now_ms(),
                                            resumption_psk: psk,
                                            suite_id,
                                            hash_size,
                                        };
                                        let sn_str: &str = server_name.as_ref();
                                        tls_debug!("[tls-debug] NewSessionTicket: stored for %s (lifetime=%ds, ticket_len=%d)\n",
                                            sn_str,
                                            nst.ticket_lifetime as i64,
                                            state.ticket.len() as i64);
                                        session::put(server_name, state);
                                    } else {
                                        tls_debug!("[tls-debug] NewSessionTicket: unknown suite 0x%04x, dropping\n",
                                            suite_id as u64);
                                    }
                                } else {
                                    tls_debug!("[tls-debug] NewSessionTicket: no resumption_master_secret, dropping\n");
                                }
                                return Conn::Read(self, b);
                            }
                            None => {
                                tls_debug!("[tls-debug] NewSessionTicket: parse failed (len=%d)\n",
                                    inner.len() as i64);
                                drop(st);
                                return Conn::Read(self, b);
                            }
                        }
                    }
                    // Other post-handshake messages — skip
                    drop(st);
                    return Conn::Read(self, b);
                }
                if inner_type == record::RECORD_ALERT {
                    let level = if inner.len() >= 1 { inner[0] } else { 0 };
                    let desc = if inner.len() >= 2 { inner[1] } else { 0 };
                    tls_debug!("[tls-debug] encrypted alert level=%d desc=%d\n",
                        level as i64, desc as i64);
                    if desc == 0 {
                        // close_notify
                        return (0, crate::io::EOF.into());
                    }
                    // Other alert: return error with desc number for diagnosis
                    return (0, crate::errors::New(
                        crate::fmt::Sprintf!("tls: received alert level=%d desc=%d", level as i64, desc as i64)
                    ));
                }
                inner
            } else if st.keys.suite == 0xC02Fu16 || st.keys.suite == 0xC02Bu16 {
                let (s, derr) = record::decrypt_record_aead(rtype, seq, &st.keys.aead_server, &frag);
                if !derr.IsNil() { return (0, derr); }
                s.__into_vec()
            } else {
                let (s, derr) = record::decrypt_record(rtype, seq, &st.keys.server, &frag);
                if !derr.IsNil() { return (0, derr); }
                s.__into_vec()
            }
        };

        let buf: &mut [byte] = &mut *b;
        let n = core::cmp::min(buf.len(), plaintext.len());
        buf[..n].copy_from_slice(&plaintext[..n]);

        if plaintext.len() > n {
            // Save the remainder
            let mut st = self.state.Lock();
            st.pending.extend_from_slice(&plaintext[n..]);
        }

        (n as int, errors::nil) // goishlint:ignore GOISH005
    }

    /// `(*tls.Conn).Write(b)` — encrypt and send application data.
    /// Writes larger than `maxPlaintext` (16384, RFC 8446 §5.1 /
    /// Go conn.go:64) are fragmented into multiple records — receivers
    /// MUST reject records with an oversized plaintext.
    /// Accepts `impl AsRef<[byte]>` so callers can pass `slice<byte>`,
    /// `&[u8]`, or byte-string literals without conversion ceremony.
    pub fn Write<B: AsRef<[byte]>>(&mut self, b: B) -> (int, error) {
        let b = b.as_ref();
        const maxPlaintext: usize = 16384;
        if b.len() > maxPlaintext {
            let mut written: int = 0;
            let mut off = 0usize;
            while off < b.len() {
                let end = core::cmp::min(off + maxPlaintext, b.len());
                let (n, err) = self.Write(&b[off..end]);
                written += n;
                if !err.IsNil() {
                    return (written, err);
                }
                off = end;
            }
            return (written, errors::nil);
        }
        {
            let st = self.state.Lock();
            if !st.handshake_complete {
                drop(st);
                let err = self.Handshake();
                if !err.IsNil() {
                    return (0, err);
                }
            }
        }

        let is_client = self.is_client;
        let wire = {
            let mut st = self.state.Lock();
            // Outbound direction: a client seals with the client-write
            // keys, a server with the server-write keys.
            let seq = if is_client {
                let s = st.client_seq;
                st.client_seq += 1;
                s
            } else {
                let s = st.server_seq;
                st.server_seq += 1;
                s
            };
            let wire_s = if st.keys.is_tls13 {
                use handshake_client_tls13::tls13_encrypt_record_suite;
                let tks = if is_client {
                    key_schedule::TrafficKeys {
                        key: st.keys.tls13_client_key[..tls13_key_len(&st.keys)].to_vec(),
                        iv: st.keys.tls13_client_iv.to_vec(),
                    }
                } else {
                    key_schedule::TrafficKeys {
                        key: st.keys.tls13_server_key[..tls13_key_len(&st.keys)].to_vec(),
                        iv: st.keys.tls13_server_iv.to_vec(),
                    }
                };
                let suite_id = st.keys.suite;
                let (s, enc_err) = tls13_encrypt_record_suite(&tks, seq, record::RECORD_APPLICATION, b, suite_id);
                if !enc_err.IsNil() { return (0, enc_err); }
                s
            } else if st.keys.suite == 0xC02Fu16 || st.keys.suite == 0xC02Bu16 {
                let (s, enc_err) = record::encrypt_record_aead(
                    record::RECORD_APPLICATION, seq, &st.keys.aead_client, b);
                if !enc_err.IsNil() { return (0, enc_err); }
                s
            } else {
                let (s, enc_err) = record::encrypt_record(
                    record::RECORD_APPLICATION, seq, &st.keys.client, b);
                if !enc_err.IsNil() { return (0, enc_err); }
                s
            };
            wire_s
        };

        let mut conn_guard = self.inner_conn.Lock();
        conn_guard.as_mut().Write(wire)
    }

    /// `(*tls.Conn).Close()` — close the underlying connection.
    pub fn Close(&mut self) -> error {
        let mut conn_guard = self.inner_conn.Lock();
        conn_guard.Close()
    }

    /// `(*tls.Conn).LocalAddr()` (conn.go:130) — local address of the
    /// underlying connection.
    pub fn LocalAddr(&self) -> crate::net::TCPAddr {
        let conn_guard = self.inner_conn.Lock();
        (**conn_guard).LocalAddr()
    }

    /// `(*tls.Conn).RemoteAddr()` (conn.go:136) — remote address of
    /// the underlying connection.
    pub fn RemoteAddr(&self) -> crate::net::TCPAddr {
        let conn_guard = self.inner_conn.Lock();
        (**conn_guard).RemoteAddr()
    }

    /// `(*tls.Conn).SetDeadline(t)` — forward deadline to the underlying TCP conn.
    /// This is NOT part of Go's tls.Conn public API (Go uses context cancellation
    /// instead) but we expose it as a Goish extension so the HTTP Transport can
    /// apply per-request timeouts to HTTPS connections.
    pub fn SetDeadline(&self, t: crate::time::Time) -> error {
        let conn_guard = self.inner_conn.Lock();
        (**conn_guard).SetDeadline(t)
    }

    /// `Conn.serverHandshake` (handshake_server.go:39) — accept-side
    /// TLS 1.3 handshake. Extracts the certificate chain + private key
    /// from `Config.Certificates[0]` and drives
    /// `do_server_handshake_tls13`.
    fn server_handshake(&mut self) -> error {
        use handshake_server_tls13::ServerPrivateKey;

        if self.config.Certificates.Len() == 0 {
            return errors::New(
                "tls: no certificates configured (set Config.Certificates via X509KeyPair)",
            );
        }
        let cert = &self.config.Certificates[0 as crate::types::int];
        let mut chain: Vec<Vec<byte>> = Vec::new();
        {
            let mut i: crate::types::int = 0;
            while i < cert.Certificate.Len() {
                chain.push(cert.Certificate[i].clone().__into_vec());
                i += 1;
            }
        }
        let private_key = if let Some(k) = cert
            .PrivateKey
            .downcast_ref::<crate::crypto::rsa::PrivateKey>()
        {
            ServerPrivateKey::Rsa(k.clone())
        } else if let Some(k) = cert
            .PrivateKey
            .downcast_ref::<crate::crypto::ed25519::PrivateKey>()
        {
            ServerPrivateKey::Ed25519(k.clone())
        } else {
            return errors::New(
                "tls: unsupported certificate private key type (RSA and Ed25519 supported)",
            );
        };
        let mut next_protos: Vec<alloc::string::String> = Vec::new();
        {
            let mut i: crate::types::int = 0;
            while i < self.config.NextProtos.Len() {
                let p: &str = self.config.NextProtos[i].as_ref();
                next_protos.push(alloc::string::String::from(p));
                i += 1;
            }
        }

        let (km, _info, err) = {
            let mut conn_guard = self.inner_conn.Lock();
            handshake_server_tls13::do_server_handshake_tls13(
                conn_guard.as_mut(),
                &chain,
                &private_key,
                &next_protos,
            )
        };
        if !err.IsNil() {
            return err;
        }

        let mut st = self.state.Lock();
        st.handshake_complete = true;
        st.keys = km;
        // TLS 1.3 application records restart both sequence counters.
        st.client_seq = 0;
        st.server_seq = 0;
        errors::nil
    }
}

impl crate::io::Reader for Conn {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        Conn::Read(self, p)
    }
}

impl crate::io::Writer for Conn {
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        let raw: &[byte] = &p;
        Conn::Write(self, raw)
    }
}

impl crate::io::Closer for Conn {
    fn Close(&mut self) -> error {
        Conn::Close(self)
    }
}

// ─── Client / Dial ────────────────────────────────────────────────────

/// `tls.Client(conn, cfg)` — wrap `conn` in a TLS client connection.
/// The handshake is NOT driven yet; call `.Handshake()` or `Read`/`Write`.
pub fn Client(conn: Box<dyn crate::net::Conn>, cfg: &Config) -> Conn {
    Conn {
        inner_conn: Arc::new(Mutex::new(conn)),
        state: Arc::new(Mutex::new(ConnInner::default())),
        config: cfg.clone(),
        is_client: true,
    }
}

/// `tls.Server(conn, cfg)` (tls.go:47) — returns a new TLS server side
/// connection using `conn` as the underlying transport. The
/// configuration must include at least one certificate in
/// `Config.Certificates`. The handshake is NOT driven yet; call
/// `.Handshake()` or the first `Read`/`Write` drives it.
pub fn Server(conn: Box<dyn crate::net::Conn>, cfg: &Config) -> Conn {
    Conn {
        inner_conn: Arc::new(Mutex::new(conn)),
        state: Arc::new(Mutex::new(ConnInner::default())),
        config: cfg.clone(),
        is_client: false,
    }
}

/// `tls.Dial(network, addr, cfg)` — dial + handshake.
///
/// Dials `addr` over `network` (must be `"tcp"` or `"tcp4"`), wraps the
/// connection in a TLS client, and drives the handshake. Returns the
/// ready-to-use `Conn` or an error.
pub fn Dial<N, A>(network: N, addr: A, cfg: &Config) -> (Conn, error)
where
    N: Into<string>,
    A: Into<string>,
{
    let network = network.into();
    let addr = addr.into();

    let (raw_conn, err) = crate::net::Dial(network, addr.clone());
    if !err.IsNil() {
        // Dead-connection placeholder so caller can pattern-match on error.
        // The returned Conn must not be used when error is non-nil.
        let dead = make_dead_conn(cfg);
        return (dead, err);
    }

    // Extract server_name from addr if not set in config
    let server_name = if cfg.ServerName.Len() > 0 {
        cfg.ServerName.clone()
    } else {
        // addr is "host:port"; strip the port
        let addr_str: &str = addr.as_ref();
        let host = if let Some(pos) = addr_str.rfind(':') {
            string::from_bytes(addr_str[..pos].as_bytes())
        } else {
            addr.clone()
        };
        host
    };

    let mut effective_cfg = cfg.clone();
    if effective_cfg.ServerName.Len() == 0 {
        effective_cfg.ServerName = server_name;
    }

    let box_conn: alloc::boxed::Box<dyn crate::net::Conn> = alloc::boxed::Box::new(raw_conn);
    let mut tls_conn = Client(box_conn, &effective_cfg);
    let herr = tls_conn.Handshake();
    if !herr.IsNil() {
        return (tls_conn, herr);
    }
    (tls_conn, errors::nil)
}

/// `tls.DialChaCha20Only(network, addr, cfg)` — dial + TLS 1.3 ChaCha20-Poly1305-only handshake.
///
/// Like `Dial` but sends a ClientHello advertising only TLS_CHACHA20_POLY1305_SHA256 (0x1303).
/// Useful for testing ChaCha20-Poly1305 negotiation.
pub fn DialChaCha20Only<N, A>(network: N, addr: A, cfg: &Config) -> (Conn, error)
where
    N: Into<string>,
    A: Into<string>,
{
    let network = network.into();
    let addr = addr.into();

    let (raw_conn, err) = crate::net::Dial(network, addr.clone());
    if !err.IsNil() {
        let dead = make_dead_conn(cfg);
        return (dead, err);
    }

    let server_name = if cfg.ServerName.Len() > 0 {
        cfg.ServerName.clone()
    } else {
        let addr_str: &str = addr.as_ref();
        let host = if let Some(pos) = addr_str.rfind(':') {
            string::from_bytes(addr_str[..pos].as_bytes())
        } else {
            addr.clone()
        };
        host
    };

    let mut effective_cfg = cfg.clone();
    if effective_cfg.ServerName.Len() == 0 {
        effective_cfg.ServerName = server_name.clone();
    }

    let skip_verify = effective_cfg.InsecureSkipVerify;
    let sn: &str = effective_cfg.ServerName.as_ref();
    let sn_owned = alloc::string::String::from(sn);

    let mut box_conn: alloc::boxed::Box<dyn crate::net::Conn> = alloc::boxed::Box::new(raw_conn);
    let (km, herr) = handshake_client::do_client_handshake_chacha20_only(
        box_conn.as_mut(),
        &sn_owned,
        skip_verify,
    );
    if !herr.IsNil() {
        let dead = make_dead_conn(&effective_cfg);
        return (dead, herr);
    }

    // Manually set the key material on a new Conn
    let tls_conn = Conn {
        inner_conn: Arc::new(Mutex::new(box_conn)),
        state: Arc::new(Mutex::new(ConnInner {
            handshake_complete: true,
            client_seq: 0,
            server_seq: 0,
            keys: km,
            pending: alloc::vec::Vec::new(),
        })),
        config: effective_cfg,
        is_client: true,
    };
    (tls_conn, errors::nil)
}

// ─── internal helpers ─────────────────────────────────────────────────

/// Create a Conn that wraps a dead stub — for error return paths where
/// `Dial` failed before connecting. The returned Conn MUST NOT be used
/// for I/O; callers must check the accompanying error first.
fn make_dead_conn(cfg: &Config) -> Conn {
    Conn {
        inner_conn: Arc::new(Mutex::new(alloc::boxed::Box::new(DeadConn))),
        state: Arc::new(Mutex::new(ConnInner::default())),
        config: cfg.clone(),
        is_client: true,
    }
}

/// A no-op connection that returns errors for every operation.
/// Used exclusively as a placeholder in `Dial`'s error path.
struct DeadConn;

impl crate::io::Reader for DeadConn {
    fn Read(&mut self, _p: &mut slice<byte>) -> (int, error) {
        (0, errors::New("tls: use of dead connection"))
    }
}

impl crate::io::Writer for DeadConn {
    fn Write(&mut self, _p: slice<byte>) -> (int, error) {
        (0, errors::New("tls: use of dead connection"))
    }
}

impl crate::io::Closer for DeadConn {
    fn Close(&mut self) -> error {
        errors::nil
    }
}

impl crate::net::Conn for DeadConn {
    fn Read(&mut self, p: &mut slice<byte>) -> (int, error) {
        <Self as crate::io::Reader>::Read(self, p)
    }
    fn Write(&mut self, p: slice<byte>) -> (int, error) {
        <Self as crate::io::Writer>::Write(self, p)
    }
    fn Close(&mut self) -> error {
        errors::nil
    }
    fn LocalAddr(&self) -> crate::net::TCPAddr {
        crate::net::TCPAddr::zero()
    }
    fn RemoteAddr(&self) -> crate::net::TCPAddr {
        crate::net::TCPAddr::zero()
    }
    fn SetDeadline(&self, _t: crate::time::Time) -> error {
        errors::nil
    }
    fn SetReadDeadline(&self, _t: crate::time::Time) -> error {
        errors::nil
    }
    fn SetWriteDeadline(&self, _t: crate::time::Time) -> error {
        errors::nil
    }
}

// ─── Certificate + key-pair loaders (tls.go:243) ──────────────────────

pub use common::Certificate;

/// `tls.X509KeyPair(certPEMBlock, keyPEMBlock)` (tls.go:263) — parse a
/// public/private key pair from PEM data. The certificate input may
/// contain intermediates after the leaf to form a chain.
///
/// Goish deviation: `Certificate.Leaf` is not populated (no full
/// X.509 parser), and the key/cert consistency check Go performs is
/// applied for RSA keys only.
pub fn X509KeyPair(
    certPEMBlock: impl AsRef<[byte]>,
    keyPEMBlock: impl AsRef<[byte]>,
) -> (Certificate, error) {
    use crate::encoding::pem;

    // Go: for { certDERBlock, certPEMBlock = pem.Decode(certPEMBlock); ... }
    let mut chain: Vec<slice<byte>> = Vec::new();
    let mut skipped_types: Vec<string> = Vec::new();
    let mut rest: Vec<byte> = certPEMBlock.as_ref().to_vec();
    loop {
        let (block_opt, new_rest) = pem::Decode(slice::<byte>::__from_vec(rest));
        match block_opt {
            None => break,
            Some(blk) => {
                let t: &str = blk.Type.as_ref();
                if t == "CERTIFICATE" {
                    chain.push(blk.Bytes);
                } else {
                    skipped_types.push(blk.Type.clone());
                }
                rest = new_rest.__into_vec();
                if rest.is_empty() {
                    break;
                }
            }
        }
    }

    if chain.is_empty() {
        if skipped_types.is_empty() {
            return (
                Certificate::default(),
                errors::New("tls: failed to find any PEM data in certificate input"),
            );
        }
        if skipped_types.len() == 1 {
            let t: &str = skipped_types[0].as_ref();
            if t.ends_with("PRIVATE KEY") {
                return (
                    Certificate::default(),
                    errors::New("tls: failed to find certificate PEM data in certificate input, but did find a private key; PEM inputs may have been switched"),
                );
            }
        }
        return (
            Certificate::default(),
            errors::New("tls: failed to find \"CERTIFICATE\" PEM block in certificate input"),
        );
    }

    // Key input: skip non-key blocks until one whose type is
    // "PRIVATE KEY" or ends in " PRIVATE KEY" (tls.go:299).
    let key_der: slice<byte>;
    let mut rest: Vec<byte> = keyPEMBlock.as_ref().to_vec();
    loop {
        let (block_opt, new_rest) = pem::Decode(slice::<byte>::__from_vec(rest));
        match block_opt {
            None => {
                return (
                    Certificate::default(),
                    errors::New("tls: failed to find PEM block with type ending in \"PRIVATE KEY\" in key input"),
                );
            }
            Some(blk) => {
                let t: &str = blk.Type.as_ref();
                if t == "PRIVATE KEY" || t.ends_with(" PRIVATE KEY") {
                    key_der = blk.Bytes;
                    break;
                }
                rest = new_rest.__into_vec();
                if rest.is_empty() {
                    return (
                        Certificate::default(),
                        errors::New("tls: failed to find PEM block with type ending in \"PRIVATE KEY\" in key input"),
                    );
                }
            }
        }
    }
    let (private_key, err) = parsePrivateKey(key_der);
    if !err.IsNil() {
        return (Certificate::default(), err);
    }

    // Go verifies the private key matches the leaf public key
    // (tls.go:320). Our X.509 parser extracts RSA public keys only, so
    // the check runs for RSA and is skipped for Ed25519.
    if let Some(rsa_key) = private_key.downcast_ref::<crate::crypto::rsa::PrivateKey>() {
        let leaf: &slice<byte> = &chain[0];
        let leaf_raw: &[byte] = leaf;
        let (leaf_pub, perr) = record::decode_x509_rsa_pubkey(leaf_raw);
        if perr.IsNil() {
            if leaf_pub.N.Cmp(&rsa_key.PublicKey.N) != 0 || leaf_pub.E != rsa_key.PublicKey.E {
                return (
                    Certificate::default(),
                    errors::New("tls: private key does not match public key"),
                );
            }
        }
    }

    (
        Certificate {
            Certificate: slice::<slice<byte>>::__from_vec(chain),
            PrivateKey: private_key,
            ..Default::default()
        },
        errors::nil,
    )
}

/// `tls.LoadX509KeyPair(certFile, keyFile)` (tls.go:243) — read and
/// parse a key pair from a pair of PEM files.
pub fn LoadX509KeyPair<C, K>(certFile: C, keyFile: K) -> (Certificate, error)
where
    C: Into<string>,
    K: Into<string>,
{
    let (cert_pem, err) = crate::os::ReadFile(certFile);
    if !err.IsNil() {
        return (Certificate::default(), err);
    }
    let (key_pem, err) = crate::os::ReadFile(keyFile);
    if !err.IsNil() {
        return (Certificate::default(), err);
    }
    let cert_raw: &[byte] = &cert_pem;
    let key_raw: &[byte] = &key_pem;
    X509KeyPair(cert_raw, key_raw)
}

/// `parsePrivateKey(der)` (tls.go:361) — attempt to parse the DER key
/// as PKCS#1 (RSA), then PKCS#8 (RSA or Ed25519). OpenSSL 3.x writes
/// PKCS#8 by default; OpenSSL 1.x with `-traditional` writes PKCS#1.
/// EC (SEC1/ECDSA) keys are rejected — no ECDSA signer yet.
fn parsePrivateKey(der: slice<byte>) -> (crate::crypto::PrivateKey, error) {
    // PKCS#1.
    let (k, err) = crate::crypto::x509::goishParsePKCS1RSAPrivateKey(der.clone());
    if err.IsNil() {
        return (Arc::new(k), errors::nil);
    }
    // PKCS#8, RSA algorithm OID.
    let (k, err) = crate::crypto::x509::goishParsePKCS8RSAPrivateKey(der.clone());
    if err.IsNil() {
        return (Arc::new(k), errors::nil);
    }
    // PKCS#8, Ed25519 (RFC 8410) — goish's goishParsePKCS8RSAPrivateKey
    // handles the rsaEncryption OID only, so the Ed25519 shape is
    // parsed here.
    if let Some(k) = parse_pkcs8_ed25519(&der) {
        return (Arc::new(k), errors::nil);
    }
    (
        Arc::new(()),
        errors::New("tls: failed to parse private key (PKCS#1/PKCS#8 RSA and PKCS#8 Ed25519 supported)"),
    )
}

/// Parse a PKCS#8 PrivateKeyInfo carrying an Ed25519 key (RFC 8410):
///   SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 },
///              OCTET STRING { OCTET STRING seed[32] } }
fn parse_pkcs8_ed25519(der: &slice<byte>) -> Option<crate::crypto::ed25519::PrivateKey> {
    use crate::encoding::asn1;
    const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];

    let (outer, _, err) = asn1::ParseRaw(der.clone());
    if !err.IsNil() || outer.Tag != asn1::TagSequence {
        return None;
    }
    // version INTEGER (0)
    let (ver, rest1, err) = asn1::ParseRaw(outer.Bytes.clone());
    if !err.IsNil() || ver.Tag != asn1::TagInteger {
        return None;
    }
    // AlgorithmIdentifier SEQUENCE { OID }
    let (alg, rest2, err) = asn1::ParseRaw(rest1.clone());
    if !err.IsNil() || alg.Tag != asn1::TagSequence {
        return None;
    }
    let (oid, _, err) = asn1::ParseRaw(alg.Bytes.clone());
    if !err.IsNil() || oid.Tag != asn1::TagOID {
        return None;
    }
    let oid_raw: &[byte] = &oid.Bytes;
    if oid_raw != OID_ED25519 {
        return None;
    }
    // privateKey OCTET STRING wrapping "04 20 <seed>"
    let (pk, _, err) = asn1::ParseRaw(rest2.clone());
    if !err.IsNil() || pk.Tag != asn1::TagOctetString {
        return None;
    }
    let (inner, _, err) = asn1::ParseRaw(pk.Bytes.clone());
    if !err.IsNil() || inner.Tag != asn1::TagOctetString || inner.Bytes.Len() != 32 {
        return None;
    }
    Some(crate::crypto::ed25519::NewKeyFromSeed(inner.Bytes.clone()))
}

// ─── listener / NewListener / Listen (tls.go:70) ──────────────────────

/// `tls.listener` (tls.go:70) — a network listener for TLS
/// connections, wrapping an inner `net::Listener`.
#[allow(non_camel_case_types)]
pub struct listener {
    inner: crate::net::Listener,
    config: Config,
}

impl listener {
    /// `(*listener).Accept()` (tls.go:77) — waits for and returns the
    /// next incoming TLS connection. The handshake has not run yet.
    pub fn Accept(&self) -> (Conn, error) {
        let (c, err) = self.inner.Accept();
        if !err.IsNil() {
            return (make_dead_conn(&self.config), err);
        }
        (Server(Box::new(c), &self.config), errors::nil)
    }

    pub fn Close(&self) -> error {
        self.inner.Close()
    }

    pub fn Addr(&self) -> crate::net::TCPAddr {
        self.inner.Addr()
    }
}

/// `tls.NewListener(inner, config)` (tls.go:87) — creates a Listener
/// which accepts connections from an inner Listener and wraps each
/// connection with [`Server`].
pub fn NewListener(inner: crate::net::Listener, config: &Config) -> listener {
    listener {
        inner,
        config: config.clone(),
    }
}

/// `tls.Listen(network, laddr, config)` (tls.go:98) — creates a TLS
/// listener on the given address. The configuration must include at
/// least one certificate. On error the returned listener is dead and
/// must not be used.
pub fn Listen<N, A>(network: N, laddr: A, config: &Config) -> (listener, error)
where
    N: Into<string>,
    A: Into<string>,
{
    if config.Certificates.Len() == 0 {
        return (
            NewListener(crate::net::dead_listener(), config),
            errors::New("tls: neither Certificates, GetCertificate, nor GetConfigForClient set in Config"),
        );
    }
    let (l, err) = crate::net::Listen(network, laddr);
    if !err.IsNil() {
        return (NewListener(l, config), err);
    }
    (NewListener(l, config), errors::nil)
}

// ─── NewSessionTicket parser ──────────────────────────────────────────
//
// RFC 8446 §4.6.1.  The argument is the full inner-handshake bytes,
// including the 4-byte handshake header (type=4 || 3-byte length).
//
//   struct {
//     uint32 ticket_lifetime;
//     uint32 ticket_age_add;
//     opaque ticket_nonce<0..255>;
//     opaque ticket<1..2^16-1>;
//     Extension extensions<0..2^16-2>;
//   } NewSessionTicket;

struct ParsedNewSessionTicket {
    ticket_lifetime: u32,
    ticket_age_add: u32,
    ticket_nonce: alloc::vec::Vec<byte>,
    ticket: alloc::vec::Vec<byte>,
}

fn parse_new_session_ticket(inner: &[byte]) -> Option<ParsedNewSessionTicket> {
    if inner.len() < 4 || inner[0] != 4 {
        return None;
    }
    // Skip the handshake header.
    let body = &inner[4..];
    if body.len() < 8 + 1 + 2 {
        return None;
    }
    let ticket_lifetime = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    let ticket_age_add  = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
    let mut p = 8usize;

    // ticket_nonce<0..255>
    let nonce_len = body[p] as usize;
    p += 1;
    if p + nonce_len > body.len() {
        return None;
    }
    let ticket_nonce = body[p..p + nonce_len].to_vec();
    p += nonce_len;

    // ticket<1..2^16-1>
    if p + 2 > body.len() {
        return None;
    }
    let ticket_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    if p + ticket_len > body.len() || ticket_len == 0 {
        return None;
    }
    let ticket = body[p..p + ticket_len].to_vec();
    // extensions follow but we don't need them for resumption itself.

    Some(ParsedNewSessionTicket {
        ticket_lifetime,
        ticket_age_add,
        ticket_nonce,
        ticket,
    })
}

// go: none — goish idiom: fill the `#[goish::interface]` downcast
// registries for the types this package declares. See AGENTS.md §9b.
/// Register `tls::Conn` / `DeadConn` into the `io` and `net` interface
/// registries. Idempotent; called from `goish::init()`.
pub fn register_tls_impls() {
    use crate::io::{
        __goish_register_Closer_impl, __goish_register_Reader_impl,
        __goish_register_Writer_impl,
    };
    __goish_register_Reader_impl::<Conn>();
    __goish_register_Writer_impl::<Conn>();
    __goish_register_Closer_impl::<Conn>();
    __goish_register_Reader_impl::<DeadConn>();
    __goish_register_Writer_impl::<DeadConn>();
    __goish_register_Closer_impl::<DeadConn>();
    crate::net::__goish_register_Conn_impl::<DeadConn>();
}

// go: none — goish-only: certificateMsg is unexported in Go, where the
// tests are in-package. See the `defaults_*` shims above.
#[doc(hidden)]
pub fn msg_certificate_roundtrip(
    certs: crate::goslice::slice<crate::goslice::slice<crate::types::byte>>,
) -> (
    crate::goslice::slice<crate::types::byte>,
    bool,
    crate::types::int,
) {
    let m = handshake_messages::certificateMsg { certificates: certs };
    let (b, _) = m.marshal();
    let mut back = handshake_messages::certificateMsg::default();
    let ok = back.unmarshal(b.clone());
    let n = back.certificates.Len();
    return (b, ok, n);
}

// go: none — goish-only: see `msg_certificate_roundtrip`.
#[doc(hidden)]
pub fn msg_certificate_unmarshal(data: crate::goslice::slice<crate::types::byte>) -> bool {
    return handshake_messages::certificateMsg::default().unmarshal(data);
}

// go: none — goish-only: newSessionTicketMsgTLS13 is unexported in Go,
// where the tests are in-package. See the `defaults_*` shims above.
#[doc(hidden)]
pub fn msg_nst13_roundtrip(
    lifetime: crate::types::uint32,
    ageAdd: crate::types::uint32,
    nonce: crate::goslice::slice<crate::types::byte>,
    label: crate::goslice::slice<crate::types::byte>,
    maxEarlyData: crate::types::uint32,
) -> (
    crate::goslice::slice<crate::types::byte>,
    bool,
    crate::types::uint32,
) {
    let m = handshake_messages::newSessionTicketMsgTLS13 {
        lifetime,
        ageAdd,
        nonce,
        label,
        maxEarlyData,
    };
    let (b, _) = m.marshal();
    let mut back = handshake_messages::newSessionTicketMsgTLS13::default();
    let ok = back.unmarshal(b.clone());
    return (b, ok, back.maxEarlyData);
}

// go: none — goish-only: see `msg_nst13_roundtrip`.
#[doc(hidden)]
pub fn msg_nst13_unmarshal(data: crate::goslice::slice<crate::types::byte>) -> bool {
    return handshake_messages::newSessionTicketMsgTLS13::default().unmarshal(data);
}

// go: none — goish-only: certificateRequestMsgTLS13 is unexported in Go,
// where the tests are in-package. See the `defaults_*` shims above.
#[doc(hidden)]
pub fn msg_crt13_roundtrip(
    ocspStapling: bool,
    scts: bool,
    sigAlgs: crate::goslice::slice<common::SignatureScheme>,
    sigAlgsCert: crate::goslice::slice<common::SignatureScheme>,
    cas: crate::goslice::slice<crate::goslice::slice<crate::types::byte>>,
) -> (
    crate::goslice::slice<crate::types::byte>,
    bool,
    crate::types::int,
    crate::types::int,
    crate::types::int,
) {
    let m = handshake_messages::certificateRequestMsgTLS13 {
        ocspStapling,
        scts,
        supportedSignatureAlgorithms: sigAlgs,
        supportedSignatureAlgorithmsCert: sigAlgsCert,
        certificateAuthorities: cas,
    };
    let (b, _) = m.marshal();
    let mut back = handshake_messages::certificateRequestMsgTLS13::default();
    let ok = back.unmarshal(b.clone());
    return (
        b,
        ok && back.ocspStapling == ocspStapling && back.scts == scts,
        back.supportedSignatureAlgorithms.Len(),
        back.supportedSignatureAlgorithmsCert.Len(),
        back.certificateAuthorities.Len(),
    );
}

// go: none — goish-only: certificateRequestMsg is unexported in Go,
// where the tests are in-package. See the `defaults_*` shims above.
#[doc(hidden)]
pub fn msg_crm_roundtrip(
    hasSignatureAlgorithm: bool,
    certificateTypes: crate::goslice::slice<crate::types::byte>,
    sigAlgs: crate::goslice::slice<common::SignatureScheme>,
    cas: crate::goslice::slice<crate::goslice::slice<crate::types::byte>>,
) -> (
    crate::goslice::slice<crate::types::byte>,
    bool,
    crate::types::int,
    crate::types::int,
    crate::types::int,
) {
    let m = handshake_messages::certificateRequestMsg {
        hasSignatureAlgorithm,
        certificateTypes,
        supportedSignatureAlgorithms: sigAlgs,
        certificateAuthorities: cas,
    };
    let (b, _) = m.marshal();
    let mut back = handshake_messages::certificateRequestMsg::default();
    back.hasSignatureAlgorithm = hasSignatureAlgorithm;
    let ok = back.unmarshal(b.clone());
    return (
        b,
        ok,
        back.certificateTypes.Len(),
        back.supportedSignatureAlgorithms.Len(),
        back.certificateAuthorities.Len(),
    );
}

// go: none — goish-only: parse with an explicit hasSignatureAlgorithm,
// so the version-flag mismatch can be exercised.
#[doc(hidden)]
pub fn msg_crm_unmarshal_as(
    hasSignatureAlgorithm: bool,
    data: crate::goslice::slice<crate::types::byte>,
) -> bool {
    let mut m = handshake_messages::certificateRequestMsg::default();
    m.hasSignatureAlgorithm = hasSignatureAlgorithm;
    return m.unmarshal(data);
}

// go: none — goish-only: finishedMsg / certificateVerifyMsg are
// unexported in Go, where the tests are in-package.
#[doc(hidden)]
pub fn msg_finished_roundtrip(
    verifyData: crate::goslice::slice<crate::types::byte>,
) -> (
    crate::goslice::slice<crate::types::byte>,
    bool,
    crate::goslice::slice<crate::types::byte>,
) {
    let m = handshake_messages::finishedMsg {
        verifyData: verifyData.__into_vec(),
    };
    let (b, _) = m.marshal();
    let mut back = handshake_messages::finishedMsg::default();
    let ok = back.unmarshal(b.clone());
    return (b, ok, crate::goslice::slice::__from_vec(back.verifyData));
}

// go: none — goish-only: see `msg_finished_roundtrip`.
#[doc(hidden)]
pub fn msg_certVerify_roundtrip(
    hasSignatureAlgorithm: bool,
    alg: crate::types::uint16,
    sig: crate::goslice::slice<crate::types::byte>,
) -> (
    crate::goslice::slice<crate::types::byte>,
    bool,
    crate::types::uint16,
) {
    let m = handshake_messages::certificateVerifyMsg {
        hasSignatureAlgorithm,
        signatureAlgorithm: alg,
        signature: sig.__into_vec(),
    };
    let (b, _) = m.marshal();
    let mut back = handshake_messages::certificateVerifyMsg::default();
    back.hasSignatureAlgorithm = hasSignatureAlgorithm;
    let ok = back.unmarshal(b.clone());
    return (b, ok, back.signatureAlgorithm);
}

// go: none — goish-only: parse with an explicit flag, for the mismatch.
#[doc(hidden)]
pub fn msg_certVerify_unmarshal_as(
    hasSignatureAlgorithm: bool,
    data: crate::goslice::slice<crate::types::byte>,
) -> bool {
    let mut m = handshake_messages::certificateVerifyMsg::default();
    m.hasSignatureAlgorithm = hasSignatureAlgorithm;
    return m.unmarshal(data);
}

// go: none — goish-only: encryptedExtensionsMsg is unexported in Go.
// Parses a caller-supplied buffer so Go's own wire bytes can be fed in
// directly — stronger than a self round-trip, since the hand-written
// `marshal` above does not emit every field Go's does.
#[doc(hidden)]
pub fn msg_ee_unmarshal(
    data: crate::goslice::slice<crate::types::byte>,
) -> (bool, crate::gostring::string, bool, bool) {
    let mut m = handshake_messages::encryptedExtensionsMsg::default();
    let ok = m.unmarshal(data);
    return (
        ok,
        crate::gostring::string::from_bytes(m.alpnProtocol.as_bytes()),
        m.earlyData,
        m.serverNameAck,
    );
}

// go: none — goish-only: unmarshalCertificate is unexported in Go,
// where the tests are in-package. Returns the chain length, the OCSP
// staple and the SCT count so one shim covers what Go's test reads.
#[doc(hidden)]
pub fn msg_unmarshalCertificate(
    data: crate::goslice::slice<crate::types::byte>,
) -> (
    bool,
    crate::types::int,
    crate::goslice::slice<crate::types::byte>,
    crate::types::int,
) {
    let mut s = crate::crypto::cryptobyte::String::New(data);
    let mut cert = Certificate::default();
    let ok = handshake_messages::unmarshalCertificate(&mut s, &mut cert);
    return (
        ok && s.Empty(),
        cert.Certificate.Len(),
        cert.OCSPStaple,
        cert.SignedCertificateTimestamps.Len(),
    );
}

// go: none — goish-only: ech.go's parser is unexported in Go, where the
// tests are in-package.
#[doc(hidden)]
pub fn ech_parseConfig(
    data: crate::goslice::slice<crate::types::byte>,
) -> (
    bool,
    bool,
    crate::types::int,
    crate::types::uint16,
    crate::goslice::slice<crate::types::byte>,
    crate::types::int,
    crate::gostring::string,
    crate::types::int,
) {
    let (skip, ec, err) = ech::parseECHConfig(data);
    return (
        skip,
        err == crate::errors::nil,
        crate::int(ec.ConfigID),
        ec.KemID,
        ec.PublicKey.clone(),
        crate::int(ec.MaxNameLength),
        crate::gostring::string::from_bytes(&ec.PublicName),
        ec.SymmetricCipherSuite.Len(),
    );
}

// go: none — goish-only: see `ech_parseConfig`.
#[doc(hidden)]
pub fn ech_parseConfigList(
    data: crate::goslice::slice<crate::types::byte>,
) -> (crate::types::int, bool) {
    let (cfgs, err) = ech::parseECHConfigList(data);
    return (cfgs.Len(), err == crate::errors::nil);
}

// go: none — goish-only: the error message for a truncated config.
#[doc(hidden)]
pub fn ech_parseConfigErr(
    data: crate::goslice::slice<crate::types::byte>,
) -> crate::gostring::string {
    let (_, _, err) = ech::parseECHConfig(data);
    if err == crate::errors::nil {
        return crate::gostring::string::from_static("");
    }
    return err.Error();
}

// go: none — goish-only: validDNSName is unexported in Go, where the
// tests are in-package.
#[doc(hidden)]
pub fn ech_validDNSName(name: crate::gostring::string) -> bool {
    return ech::validDNSName(name);
}

// go: none — goish-only: cipher_suites.go's AEAD, MAC and TLS 1.3 suite
// records are all unexported in Go, where the tests are in-package.
// Each shim seals or MACs once and hands back the bytes, so the example
// can pin them against a running Go.
#[doc(hidden)]
pub fn cipher_suites_aeadSeal(
    which: crate::gostring::string,
    key: crate::goslice::slice<crate::types::byte>,
    fixedNonce: crate::goslice::slice<crate::types::byte>,
    nonce: crate::goslice::slice<crate::types::byte>,
    plaintext: crate::goslice::slice<crate::types::byte>,
    additionalData: crate::goslice::slice<crate::types::byte>,
) -> (
    crate::goslice::slice<crate::types::byte>,
    crate::types::int,
    crate::types::int,
    crate::types::int,
) {
    let mut a = cipher_suites_aeadByName(which, key, fixedNonce);
    let ct = cipher_suites::mutAEAD::Seal(
        &mut *a,
        crate::goslice::slice::new(),
        nonce,
        plaintext,
        additionalData,
    );
    let ns = cipher_suites::mutAEAD::NonceSize(&*a);
    let oh = cipher_suites::mutAEAD::Overhead(&*a);
    let ex = a.explicitNonceLen();
    return (ct, ns, oh, ex);
}

// go: none — goish-only: see `cipher_suites_aeadSeal`.
#[doc(hidden)]
pub fn cipher_suites_aeadOpen(
    which: crate::gostring::string,
    key: crate::goslice::slice<crate::types::byte>,
    fixedNonce: crate::goslice::slice<crate::types::byte>,
    nonce: crate::goslice::slice<crate::types::byte>,
    ciphertext: crate::goslice::slice<crate::types::byte>,
    additionalData: crate::goslice::slice<crate::types::byte>,
) -> (crate::goslice::slice<crate::types::byte>, crate::error) {
    let mut a = cipher_suites_aeadByName(which, key, fixedNonce);
    return cipher_suites::mutAEAD::Open(
        &mut *a,
        crate::goslice::slice::new(),
        nonce,
        ciphertext,
        additionalData,
    );
}

// go: none — goish-only: names the three constructors so an example can
// pick one without reaching the unexported types.
fn cipher_suites_aeadByName(
    which: crate::gostring::string,
    key: crate::goslice::slice<crate::types::byte>,
    fixedNonce: crate::goslice::slice<crate::types::byte>,
) -> alloc::boxed::Box<dyn cipher_suites::aead + Send + Sync> {
    if which == crate::gostring::string::from_static("aesgcm12") {
        return cipher_suites::aeadAESGCM(key, fixedNonce);
    }
    if which == crate::gostring::string::from_static("aesgcm13") {
        return cipher_suites::aeadAESGCMTLS13(key, fixedNonce);
    }
    return cipher_suites::aeadChaCha20Poly1305(key, fixedNonce);
}

// go: none — goish-only: see `cipher_suites_aeadSeal`.
#[doc(hidden)]
pub fn cipher_suites_tls10MAC(
    which: crate::gostring::string,
    key: crate::goslice::slice<crate::types::byte>,
    out: crate::goslice::slice<crate::types::byte>,
    seq: crate::goslice::slice<crate::types::byte>,
    header: crate::goslice::slice<crate::types::byte>,
    data: crate::goslice::slice<crate::types::byte>,
    extra: crate::goslice::slice<crate::types::byte>,
) -> (
    crate::goslice::slice<crate::types::byte>,
    crate::types::int,
    crate::types::int,
) {
    let mut h = if which == crate::gostring::string::from_static("sha1") {
        cipher_suites::macSHA1(key)
    } else {
        cipher_suites::macSHA256(key)
    };
    let size = h.Size();
    let block = h.BlockSize();
    let mac = cipher_suites::tls10MAC(&mut *h, out, seq, header, data, extra);
    return (mac, size, block);
}

// go: none — goish-only: see `cipher_suites_aeadSeal`.
#[doc(hidden)]
pub fn cipher_suites_constantTimeSHA1(
    data: crate::goslice::slice<crate::types::byte>,
) -> (
    crate::goslice::slice<crate::types::byte>,
    crate::types::int,
    crate::types::int,
) {
    let f = cipher_suites::newConstantTimeHash(cipher_suites_newSHA1CTH);
    let mut h = f.Call();
    let _ = crate::io::Writer::Write(&mut *h, data);
    return (
        h.Sum(crate::goslice::slice::new()),
        h.Size(),
        h.BlockSize(),
    );
}

// go: none — goish-only: see `cipher_suites_aeadSeal`.
fn cipher_suites_newSHA1CTH(
) -> alloc::boxed::Box<dyn cipher_suites::constantTimeHash + Send + Sync> {
    return alloc::boxed::Box::new(crate::crypto::sha1::New());
}

// go: none — goish-only: see `cipher_suites_aeadSeal`. Reports
// `(found, keyLen, hash)` for a TLS 1.3 suite ID.
#[doc(hidden)]
pub fn cipher_suites_tls13ByID(
    id: crate::types::uint16,
) -> (bool, crate::types::int, crate::crypto::Hash) {
    let found = cipher_suites::cipherSuiteTLS13ByID(id);
    if found.is_none() {
        return (false, 0, crate::crypto::Hash(0));
    }
    let s = found.unwrap();
    return (true, s.keyLen, s.hash);
}

// go: none — goish-only: see `cipher_suites_aeadSeal`.
#[doc(hidden)]
pub fn cipher_suites_mutualTLS13(
    have: crate::goslice::slice<crate::types::uint16>,
    want: crate::types::uint16,
) -> bool {
    return cipher_suites::mutualCipherSuiteTLS13(have, want).is_some();
}

// go: none — goish-only: key_schedule.go's decls are all unexported in
// Go, where the tests are in-package. Each shim looks the suite up by
// ID so the example never names the unexported record.
#[doc(hidden)]
pub fn key_schedule_nextTrafficSecret(
    id: crate::types::uint16,
    trafficSecret: crate::goslice::slice<crate::types::byte>,
) -> crate::goslice::slice<crate::types::byte> {
    let c = cipher_suites::cipherSuiteTLS13ByID(id).unwrap();
    return c.nextTrafficSecret(trafficSecret);
}

// go: none — goish-only: see `key_schedule_nextTrafficSecret`.
#[doc(hidden)]
pub fn key_schedule_trafficKey(
    id: crate::types::uint16,
    trafficSecret: crate::goslice::slice<crate::types::byte>,
) -> (
    crate::goslice::slice<crate::types::byte>,
    crate::goslice::slice<crate::types::byte>,
) {
    let c = cipher_suites::cipherSuiteTLS13ByID(id).unwrap();
    return c.trafficKey(trafficSecret);
}

// go: none — goish-only: see `key_schedule_nextTrafficSecret`. The
// transcript is built here so the example need not name `hash::Hash`.
#[doc(hidden)]
pub fn key_schedule_finishedHash(
    id: crate::types::uint16,
    baseKey: crate::goslice::slice<crate::types::byte>,
    transcript: crate::goslice::slice<crate::types::byte>,
) -> crate::goslice::slice<crate::types::byte> {
    let c = cipher_suites::cipherSuiteTLS13ByID(id).unwrap();
    let mut h = c.hash.New();
    let _ = crate::io::Writer::Write(&mut *h, transcript);
    return c.finishedHash(baseKey, &*h);
}

// go: none — goish-only: see `key_schedule_nextTrafficSecret`. Runs the
// full early → handshake → master schedule so the exporter has a real
// MasterSecret to derive from.
#[doc(hidden)]
pub fn key_schedule_exportKeyingMaterial(
    id: crate::types::uint16,
    transcript: crate::goslice::slice<crate::types::byte>,
    label: crate::gostring::string,
    context: crate::goslice::slice<crate::types::byte>,
    length: crate::types::int,
) -> (crate::goslice::slice<crate::types::byte>, bool) {
    use crate::crypto::internal::fips140::tls13;
    let c = cipher_suites::cipherSuiteTLS13ByID(id).unwrap();
    let hf = crate::hash::HashFunc::New(move || crate::crypto::SHA256.New());
    let es = tls13::NewEarlySecret(hf, crate::goslice::slice::new());
    let hs = es.HandshakeSecret(crate::goslice::slice::__from_vec(alloc::vec![0u8; 32]));
    let ms = hs.MasterSecret();
    let mut h = c.hash.New();
    let _ = crate::io::Writer::Write(&mut *h, transcript);
    let ekm = c.exportKeyingMaterial(&ms, &*h);
    let (out, err) = ekm(label, context, length);
    return (out, err == crate::errors::nil);
}

// go: none — goish-only: see `key_schedule_nextTrafficSecret`.
#[doc(hidden)]
pub fn key_schedule_curveForCurveID(id: common::CurveID) -> bool {
    let (_, ok) = key_schedule::curveForCurveID(id);
    return ok;
}

// go: none — goish-only: see `key_schedule_nextTrafficSecret`. Reports
// `(private, public, errText)` so the example can pin the bytes.
#[doc(hidden)]
pub fn key_schedule_generateECDHEKey(
    rand: &mut (dyn crate::io::Reader + Send + Sync + 'static),
    curveID: common::CurveID,
) -> (
    crate::goslice::slice<crate::types::byte>,
    crate::goslice::slice<crate::types::byte>,
    crate::gostring::string,
) {
    let (key, err) = key_schedule::generateECDHEKey(rand, curveID);
    if err != crate::errors::nil {
        return (
            crate::goslice::slice::new(),
            crate::goslice::slice::new(),
            err.Error(),
        );
    }
    let k = key.unwrap();
    return (
        k.Bytes(),
        k.PublicKey().Bytes(),
        crate::gostring::string::from_static(""),
    );
}

// go: none — goish-only: handshake_messages.go's message types are all
// unexported in Go, where the tests are in-package. This builds the same
// fully-populated ClientHello the goref test does, so the example can
// pin its encoding byte-for-byte.
fn handshake_messages_fullClientHello() -> handshake_messages::clientHelloMsg {
    let mut m = handshake_messages::clientHelloMsg::default();
    m.vers = common::VersionTLS12;
    m.random = (0..32u16).map(|i| i as crate::types::byte).collect();
    m.sessionId = alloc::vec![1u8, 2, 3, 4];
    m.cipherSuites = alloc::vec![
        cipher_suites::TLS_AES_128_GCM_SHA256,
        cipher_suites::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    ];
    m.compressionMethods = alloc::vec![0u8];
    m.serverName = "example.com".into();
    m.ocspStapling = true;
    m.supportedCurves = alloc::vec![common::X25519.0, common::CurveP256.0];
    m.supportedPoints = alloc::vec![0u8];
    m.ticketSupported = true;
    m.sessionTicket = alloc::vec![9u8, 9];
    m.supportedSignatureAlgorithms =
        alloc::vec![common::PSSWithSHA256.0, common::ECDSAWithP256AndSHA256.0];
    m.supportedSignatureAlgorithmsCert = alloc::vec![common::PKCS1WithSHA256.0];
    m.secureRenegotiationSupported = true;
    m.secureRenegotiation = alloc::vec![];
    m.extendedMasterSecret = true;
    m.alpnProtocols = alloc::vec!["h2".into(), "http/1.1".into()];
    m.scts = true;
    m.supportedVersions = alloc::vec![common::VersionTLS13, common::VersionTLS12];
    m.cookie = alloc::vec![7u8, 7, 7];
    m.keyShares = alloc::vec![handshake_messages::keyShare {
        group: common::X25519.0,
        data: alloc::vec![5u8, 5, 5, 5],
    }];
    m.earlyData = true;
    m.pskModes = alloc::vec![1u8];
    m.pskIdentities = alloc::vec![handshake_messages::pskIdentity {
        label: alloc::vec![0xabu8, 0xcd],
        obfuscatedTicketAge: 0x11223344,
    }];
    m.pskBinders = alloc::vec![alloc::vec![1u8, 2, 3, 4]];
    m.quicTransportParameters = Some(alloc::vec![]);
    m.encryptedClientHello = alloc::vec![0xdeu8, 0xad];
    return m;
}

// go: none — goish-only: see `handshake_messages_fullClientHello`.
// Returns `(marshal, marshalMsg(echInner), marshalWithoutBinders)`.
#[doc(hidden)]
pub fn handshake_messages_clientHelloEncodings() -> (
    crate::goslice::slice<crate::types::byte>,
    crate::goslice::slice<crate::types::byte>,
    crate::goslice::slice<crate::types::byte>,
) {
    let m = handshake_messages_fullClientHello();
    let (outer, _) = m.marshal();
    let (inner, _) = m.marshalMsg(true);
    let (wb, _) = m.marshalWithoutBinders();
    return (outer, inner, wb);
}

// go: none — goish-only: see `handshake_messages_fullClientHello`.
// Round-trips the encoding and reports what survived: `(unmarshal ok,
// re-marshal identical, originalBytes identical, extension count,
// quicTransportParameters present, encryptedClientHello)`.
#[doc(hidden)]
pub fn handshake_messages_clientHelloRoundTrip() -> (
    bool,
    bool,
    bool,
    crate::types::int,
    bool,
    crate::goslice::slice<crate::types::byte>,
) {
    let m = handshake_messages_fullClientHello();
    let (outer, _) = m.marshal();
    let mut r = handshake_messages::clientHelloMsg::default();
    let ok = r.unmarshal(outer.clone());
    let (re, _) = r.marshal();
    let orig = r.originalBytes();
    return (
        ok,
        re == outer,
        orig == outer,
        r.extensions.len() as crate::types::int,
        r.quicTransportParameters.is_some(),
        crate::goslice::slice::__from_vec(r.encryptedClientHello.clone()),
    );
}

// go: none — goish-only: see `handshake_messages_fullClientHello`.
#[doc(hidden)]
pub fn handshake_messages_clientHelloCloneEqual() -> bool {
    let m = handshake_messages_fullClientHello();
    let (a, _) = m.marshal();
    let (b, _) = m.clone().marshal();
    return a == b;
}

// go: none — goish-only: see `handshake_messages_fullClientHello`.
// `which` picks the case: 0 = matching binders, 1 = wrong count,
// 2 = right count but wrong length. Returns `(errText, tail)`.
#[doc(hidden)]
pub fn handshake_messages_clientHelloUpdateBinders(
    which: crate::types::int,
) -> (
    crate::gostring::string,
    crate::goslice::slice<crate::types::byte>,
) {
    let mut m = handshake_messages_fullClientHello();
    let binders: crate::goslice::slice<crate::goslice::slice<crate::types::byte>> = if which == 0 {
        crate::goslice::slice::__from_vec(alloc::vec![crate::goslice::slice::__from_vec(
            alloc::vec![9u8, 9, 9, 9]
        )])
    } else if which == 1 {
        crate::goslice::slice::new()
    } else {
        crate::goslice::slice::__from_vec(alloc::vec![crate::goslice::slice::__from_vec(
            alloc::vec![1u8]
        )])
    };
    let err = m.updateBinders(binders);
    let (out, _) = m.marshal();
    let n = out.Len();
    return (
        if err == crate::errors::nil {
            crate::gostring::string::from_static("")
        } else {
            err.Error()
        },
        out.slice(n - 8, n),
    );
}

// go: none — goish-only: see `handshake_messages_fullClientHello`. A
// ClientHello with no extensions at all, and one whose random is the
// wrong length — the case addBytesWithLength exists to catch.
#[doc(hidden)]
pub fn handshake_messages_clientHelloMinimal(
    randomLen: crate::types::int,
) -> (
    crate::goslice::slice<crate::types::byte>,
    crate::gostring::string,
) {
    let mut m = handshake_messages::clientHelloMsg::default();
    m.vers = common::VersionTLS12;
    m.random = alloc::vec![0u8; randomLen as usize];
    m.cipherSuites = alloc::vec![cipher_suites::TLS_AES_128_GCM_SHA256];
    m.compressionMethods = alloc::vec![0u8];
    let (out, err) = m.marshal();
    if err != crate::errors::nil {
        return (crate::goslice::slice::new(), err.Error());
    }
    return (out, crate::gostring::string::from_static(""));
}

// go: none — goish-only: see `handshake_messages_fullClientHello`.
#[doc(hidden)]
pub fn handshake_messages_serverHelloDone() -> (
    crate::goslice::slice<crate::types::byte>,
    bool,
    bool,
) {
    let mut m = handshake_messages::serverHelloDoneMsg::default();
    let (out, _) = m.marshal();
    let ok4 = m.unmarshal(out.clone());
    let ok3 = m.unmarshal(out.slice(0, 3));
    return (out, ok4, ok3);
}

// go: none — goish-only: common.go's version and signature-algorithm
// helpers are unexported in Go, where the tests are in-package.
#[doc(hidden)]
pub fn common_supportedVersionsFromMax(
    maxVersion: crate::types::uint16,
) -> crate::goslice::slice<crate::types::uint16> {
    return common::supportedVersionsFromMax(maxVersion);
}

// go: none — goish-only: see `common_supportedVersionsFromMax`.
#[doc(hidden)]
pub fn common_supportedSignatureAlgorithms(
    minVers: crate::types::uint16,
) -> crate::goslice::slice<common::SignatureScheme> {
    return common::supportedSignatureAlgorithms(minVers);
}

// go: none — goish-only: see `common_supportedVersionsFromMax`.
#[doc(hidden)]
pub fn common_supportedSignatureAlgorithmsCert(
) -> crate::goslice::slice<common::SignatureScheme> {
    return common::supportedSignatureAlgorithmsCert();
}

// go: none — goish-only: see `common_supportedVersionsFromMax`.
#[doc(hidden)]
pub fn common_isDisabledSignatureAlgorithm(
    version: crate::types::uint16,
    s: common::SignatureScheme,
    isCert: bool,
) -> bool {
    return common::isDisabledSignatureAlgorithm(version, s, isCert);
}

// go: none — goish-only: see `common_supportedVersionsFromMax`.
#[doc(hidden)]
pub fn common_isSupportedSignatureAlgorithm(
    sigAlg: common::SignatureScheme,
    supported: crate::goslice::slice<common::SignatureScheme>,
) -> bool {
    return common::isSupportedSignatureAlgorithm(sigAlg, supported);
}

// go: none — goish-only: see `common_supportedVersionsFromMax`. Reports
// `(Error(), Unwrap().Error(), errors::Is against the wrapped error)`.
#[doc(hidden)]
pub fn common_certificateVerificationError() -> (
    crate::gostring::string,
    crate::gostring::string,
    bool,
) {
    let inner = crate::errors::New("boom");
    let e = common::CertificateVerificationError {
        UnverifiedCertificates: crate::goslice::slice::new(),
        Err: inner.clone(),
    };
    let boxed: crate::error = crate::errors::Wrap(e.clone());
    return (
        e.Error(),
        e.Unwrap().Error(),
        crate::errors::Is(boxed, inner),
    );
}

// go: none — goish-only: see `common_supportedVersionsFromMax`.
#[doc(hidden)]
pub fn common_unexpectedMessageError(
    wanted: crate::gostring::string,
    got: crate::gostring::string,
) -> crate::gostring::string {
    return common::unexpectedMessageError(wanted, got).Error();
}

// go: none — goish-only: defaults_fips140.go's decls are unexported in
// Go. `which` picks the key: 0 = RSA-2048, 1 = RSA-1024, 2 = P-256,
// 3 = P-224, 4 = no public key at all.
#[doc(hidden)]
pub fn defaults_fips140_isCertificateAllowedFIPS(which: crate::types::int) -> bool {
    let mut c = crate::crypto::x509::Certificate::default();
    if which == 0 || which == 1 {
        // A modulus of exactly 2048 or 1024 bits: top bit set, rest zero.
        let nbytes: usize = if which == 0 { 256 } else { 128 };
        let mut raw = alloc::vec![0u8; nbytes];
        raw[0] = 0x80;
        let mut n = crate::math::big::NewInt(0);
        n.SetBytes(crate::goslice::slice::__from_vec(raw));
        c.PublicKey = crate::goany::Any::new_fn(crate::crypto::rsa::PublicKey { N: n, E: 65537 });
    } else if which == 2 || which == 3 {
        let curve: &'static (dyn crate::crypto::elliptic::Curve + Send + Sync) = if which == 2 {
            crate::crypto::elliptic::P256()
        } else {
            crate::crypto::elliptic::P224()
        };
        c.PublicKey = crate::goany::Any::new_fn(crate::crypto::ecdsa::PublicKey {
            Curve: curve,
            X: crate::math::big::NewInt(1),
            Y: crate::math::big::NewInt(2),
        });
    }
    return defaults_fips140::isCertificateAllowedFIPS(&c);
}

// go: none — goish-only: see `defaults_fips140_isCertificateAllowedFIPS`.
// Reports the four FIPS filter tables' lengths and first entries.
#[doc(hidden)]
pub fn defaults_fips140_tableSizes() -> (
    crate::types::int,
    crate::types::int,
    crate::types::int,
    crate::types::int,
) {
    return (
        defaults_fips140::allowedSupportedVersionsFIPS.len() as crate::types::int,
        defaults_fips140::allowedCurvePreferencesFIPS.len() as crate::types::int,
        defaults_fips140::allowedSignatureAlgorithmsFIPS.len() as crate::types::int,
        defaults_fips140::allowedCipherSuitesFIPS.len() as crate::types::int,
    );
}

// go: none — goish-only: marshalCertificate and the TLS 1.3 Certificate
// message are unexported in Go, where the tests are in-package. Returns
// `(marshalCertificate, certificateMsgTLS13.marshal with both flags set,
// the same with both flags clear)`.
#[doc(hidden)]
pub fn handshake_messages_certificateEncodings() -> (
    crate::goslice::slice<crate::types::byte>,
    crate::goslice::slice<crate::types::byte>,
    crate::goslice::slice<crate::types::byte>,
) {
    let c = handshake_messages_sampleCertificate();
    let mut b = crate::crypto::cryptobyte::NewBuilder(crate::goslice::slice::new());
    handshake_messages::marshalCertificate(&mut b, &c);
    let (raw, _) = b.Bytes();
    let full = handshake_messages::certificateMsgTLS13 {
        certificate: c.clone(),
        ocspStapling: true,
        scts: true,
    };
    let (withExts, _) = full.marshal();
    let bare = handshake_messages::certificateMsgTLS13 {
        certificate: c,
        ocspStapling: false,
        scts: false,
    };
    let (withoutExts, _) = bare.marshal();
    return (raw, withExts, withoutExts);
}

// go: none — goish-only: see `handshake_messages_certificateEncodings`.
fn handshake_messages_sampleCertificate() -> common::Certificate {
    let mut c = common::Certificate::default();
    c.Certificate = crate::goslice::slice::__from_vec(alloc::vec![
        crate::goslice::slice::__from_vec(alloc::vec![0xaau8, 0xbb, 0xcc]),
        crate::goslice::slice::__from_vec(alloc::vec![0xddu8, 0xee]),
    ]);
    c.OCSPStaple = crate::goslice::slice::__from_vec(alloc::vec![1u8, 2, 3, 4]);
    c.SignedCertificateTimestamps = crate::goslice::slice::__from_vec(alloc::vec![
        crate::goslice::slice::__from_vec(alloc::vec![0x11u8, 0x22]),
        crate::goslice::slice::__from_vec(alloc::vec![0x33u8]),
    ]);
    return c;
}

// go: none — goish-only: see `handshake_messages_certificateEncodings`.
// Reports `(ok, ocspStapling, scts, chain length, staple, first SCT)`.
#[doc(hidden)]
pub fn handshake_messages_certificateRoundTrip() -> (
    bool,
    bool,
    bool,
    crate::types::int,
    crate::goslice::slice<crate::types::byte>,
    crate::goslice::slice<crate::types::byte>,
) {
    let (_, withExts, _) = handshake_messages_certificateEncodings();
    let mut r = handshake_messages::certificateMsgTLS13::default();
    let ok = r.unmarshal(withExts);
    let sct0 = if r.certificate.SignedCertificateTimestamps.Len() > 0 {
        r.certificate.SignedCertificateTimestamps[0].clone()
    } else {
        crate::goslice::slice::new()
    };
    return (
        ok,
        r.ocspStapling,
        r.scts,
        r.certificate.Certificate.Len(),
        r.certificate.OCSPStaple.clone(),
        sct0,
    );
}

// go: none — goish-only: auth.go's two Certificate-driven functions are
// unexported in Go. `which` picks the certificate: 0 = no private key,
// 1 = Ed25519, 2 = Ed25519 with a custom algorithm list.
#[doc(hidden)]
pub fn auth_unsupportedCertificateError(which: crate::types::int) -> crate::gostring::string {
    return auth::unsupportedCertificateError(&auth_sampleCertificate(which)).Error();
}

// go: none — goish-only: see `auth_unsupportedCertificateError`.
fn auth_sampleCertificate(which: crate::types::int) -> common::Certificate {
    let mut c = common::Certificate::default();
    if which == 0 {
        return c;
    }
    let seed = crate::goslice::slice::__from_vec(alloc::vec![7u8; 32]);
    c.PrivateKey = alloc::sync::Arc::new(crate::crypto::ed25519::NewKeyFromSeed(seed));
    if which == 2 {
        c.SupportedSignatureAlgorithms =
            crate::goslice::slice::__from_vec(alloc::vec![common::PSSWithSHA256]);
    }
    return c;
}

// go: none — goish-only: see `auth_unsupportedCertificateError`. Reports
// `(scheme, errText)`.
#[doc(hidden)]
pub fn auth_selectSignatureScheme(
    which: crate::types::int,
    vers: crate::types::uint16,
    peerAlgs: crate::goslice::slice<common::SignatureScheme>,
) -> (common::SignatureScheme, crate::gostring::string) {
    let c = auth_sampleCertificate(which);
    let (s, err) = auth::selectSignatureScheme(vers, &c, peerAlgs);
    if err != crate::errors::nil {
        return (s, err.Error());
    }
    return (s, crate::gostring::string::from_static(""));
}

// go: none — goish-only: common.go's Config negotiation methods are
// unexported in Go, where the tests are in-package. `which` picks the
// Config: 0 = zero, 1 = MinVersion TLS 1.0, 2 = MaxVersion TLS 1.2,
// 3 = the 1.1-1.2 band, 4 = ECH offered with MinVersion TLS 1.0,
// 5 = MinVersion above MaxVersion, 6 = CurvePreferences pinned to
// P-384 and X25519, 7 = CipherSuites pinned to two suites.
fn common_sampleConfig(which: crate::types::int) -> Config {
    let mut c = Config::default();
    if which == 1 {
        c.MinVersion = common::VersionTLS10;
    } else if which == 2 {
        c.MaxVersion = common::VersionTLS12;
    } else if which == 3 {
        c.MinVersion = common::VersionTLS11;
        c.MaxVersion = common::VersionTLS12;
    } else if which == 4 {
        c.MinVersion = common::VersionTLS10;
        c.EncryptedClientHelloConfigList = crate::goslice::slice::__from_vec(alloc::vec![1u8]);
    } else if which == 5 {
        c.MinVersion = common::VersionTLS13;
        c.MaxVersion = common::VersionTLS12;
    } else if which == 6 {
        c.CurvePreferences =
            crate::goslice::slice::__from_vec(alloc::vec![common::CurveP384, common::X25519]);
    } else if which == 7 {
        c.CipherSuites = crate::goslice::slice::__from_vec(alloc::vec![
            cipher_suites::TLS_RSA_WITH_AES_128_CBC_SHA,
            cipher_suites::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        ]);
    }
    return c;
}

// go: none — goish-only: see `common_sampleConfig`.
#[doc(hidden)]
pub fn common_configSupportedVersions(
    which: crate::types::int,
    isClient: bool,
) -> crate::goslice::slice<crate::types::uint16> {
    return common_sampleConfig(which).supportedVersions(isClient);
}

// go: none — goish-only: see `common_sampleConfig`.
#[doc(hidden)]
pub fn common_configMaxSupportedVersion(
    which: crate::types::int,
    isClient: bool,
) -> crate::types::uint16 {
    return common_sampleConfig(which).maxSupportedVersion(isClient);
}

// go: none — goish-only: see `common_sampleConfig`.
#[doc(hidden)]
pub fn common_configMutualVersion(
    which: crate::types::int,
    isClient: bool,
    peerVersions: crate::goslice::slice<crate::types::uint16>,
) -> (crate::types::uint16, bool) {
    return common_sampleConfig(which).mutualVersion(isClient, peerVersions);
}

// go: none — goish-only: see `common_sampleConfig`.
#[doc(hidden)]
pub fn common_configCurvePreferences(
    which: crate::types::int,
    version: crate::types::uint16,
) -> crate::goslice::slice<common::CurveID> {
    return common_sampleConfig(which).curvePreferences(version);
}

// go: none — goish-only: see `common_sampleConfig`.
#[doc(hidden)]
pub fn common_configSupportsCurve(
    which: crate::types::int,
    version: crate::types::uint16,
    curve: common::CurveID,
) -> bool {
    return common_sampleConfig(which).supportsCurve(version, curve);
}

// go: none — goish-only: see `common_sampleConfig`.
#[doc(hidden)]
pub fn common_configCipherSuites(
    which: crate::types::int,
    aesGCMPreferred: bool,
) -> crate::goslice::slice<crate::types::uint16> {
    return common_sampleConfig(which).cipherSuites(aesGCMPreferred);
}

// go: none — goish-only: see `common_sampleConfig`.
#[doc(hidden)]
pub fn common_configSupportedCipherSuites(
    which: crate::types::int,
) -> crate::goslice::slice<crate::types::uint16> {
    return common_sampleConfig(which).supportedCipherSuites();
}

// go: none — goish-only: key_agreement.go's interface and its two
// implementations are unexported in Go, where the tests are in-package.
// This runs the full TLS 1.2 ECDHE exchange with an Ed25519 certificate
// — server SKX, client processing, client CKX, server processing — and
// reports what both sides ended up with.
#[doc(hidden)]
pub fn key_agreement_ecdheRoundTrip() -> (
    crate::gostring::string,
    crate::types::int,
    crate::goslice::slice<crate::types::byte>,
    crate::types::int,
    crate::types::int,
    crate::types::int,
    bool,
) {
    use key_agreement::keyAgreement as _;
    let cfg = Config::default();
    let seed = crate::goslice::slice::__from_vec(alloc::vec![7u8; 32]);
    let dk = crate::crypto::ed25519::NewKeyFromSeed(seed);
    let pubk = dk.Public();
    let mut cert = common::Certificate::default();
    cert.PrivateKey = alloc::sync::Arc::new(dk);

    let mut ch = handshake_messages::clientHelloMsg::default();
    ch.vers = common::VersionTLS12;
    ch.random = alloc::vec![0u8; 32];
    ch.supportedCurves = alloc::vec![common::X25519.0, common::CurveP256.0];
    ch.supportedSignatureAlgorithms = alloc::vec![common::Ed25519.0];
    let mut sh = handshake_messages::serverHelloMsg::default();
    sh.vers = common::VersionTLS12;
    sh.random = alloc::vec![0u8; 32];

    let mut ka = key_agreement::ecdheKeyAgreement::default();
    ka.version = common::VersionTLS12;
    let (skx, err) = ka.generateServerKeyExchange(&cfg, &cert, &ch, &sh);
    if err != crate::errors::nil || skx.is_none() {
        return (
            err.Error(),
            0,
            crate::goslice::slice::new(),
            0,
            0,
            0,
            false,
        );
    }
    let skx = skx.unwrap();
    let publen = skx.key[3] as crate::types::int;
    let sigalg = skx.key.slice(4 + publen, 4 + publen + 2);
    let siglen = ((skx.key[(4 + publen + 2) as usize] as crate::types::int) << 8)
        | (skx.key[(4 + publen + 3) as usize] as crate::types::int);

    let mut x509cert = crate::crypto::x509::Certificate::default();
    x509cert.PublicKey = crate::goany::Any::new_fn(
        pubk.downcast_ref::<crate::crypto::ed25519::PublicKey>()
            .unwrap()
            .clone(),
    );

    let mut kc = key_agreement::ecdheKeyAgreement::default();
    kc.version = common::VersionTLS12;
    let perr = kc.processServerKeyExchange(&cfg, &ch, &sh, &x509cert, &skx);
    if perr != crate::errors::nil {
        return (perr.Error(), skx.key.Len(), sigalg, siglen, 0, 0, false);
    }
    let (pms, ckx, cerr) = kc.generateClientKeyExchange(&cfg, &ch, &x509cert);
    if cerr != crate::errors::nil || ckx.is_none() {
        return (cerr.Error(), skx.key.Len(), sigalg, siglen, 0, 0, false);
    }
    let ckx = ckx.unwrap();
    let (pms2, serr) = ka.processClientKeyExchange(&cfg, &cert, &ckx, common::VersionTLS12);
    if serr != crate::errors::nil {
        return (serr.Error(), skx.key.Len(), sigalg, siglen, 0, 0, false);
    }
    return (
        crate::gostring::string::from_static(""),
        skx.key.Len(),
        sigalg,
        siglen,
        pms.Len(),
        ckx.ciphertext.Len(),
        pms == pms2 && ka.curveID == common::X25519,
    );
}

// go: none — goish-only: see `key_agreement_ecdheRoundTrip`. `which`
// selects an error path; the return is that path's message.
#[doc(hidden)]
pub fn key_agreement_errorPath(which: crate::types::int) -> crate::gostring::string {
    use key_agreement::keyAgreement as _;
    let cfg = Config::default();
    let cert = common::Certificate::default();
    let ch = handshake_messages::clientHelloMsg::default();
    let sh = handshake_messages::serverHelloMsg::default();
    let x509cert = crate::crypto::x509::Certificate::default();
    let mut rka = key_agreement::rsaKeyAgreement::default();
    let mut eka = key_agreement::ecdheKeyAgreement::default();
    eka.version = common::VersionTLS12;

    let ckxOf = |v: alloc::vec::Vec<crate::types::byte>| {
        let mut m = handshake_messages::clientKeyExchangeMsg::default();
        m.ciphertext = crate::goslice::slice::__from_vec(v);
        return m;
    };
    let skxOf = |v: alloc::vec::Vec<crate::types::byte>| {
        let mut m = handshake_messages::serverKeyExchangeMsg::default();
        m.key = crate::goslice::slice::__from_vec(v);
        return m;
    };
    let e: crate::error = match which {
        0 => {
            let (skx, err) = rka.generateServerKeyExchange(&cfg, &cert, &ch, &sh);
            if skx.is_some() {
                return crate::gostring::string::from_static("unexpected ServerKeyExchange");
            }
            err
        }
        1 => rka.processServerKeyExchange(&cfg, &ch, &sh, &x509cert, &skxOf(alloc::vec![])),
        2 => rka.processClientKeyExchange(&cfg, &cert, &ckxOf(alloc::vec![]), 0x0303).1,
        3 => rka.processClientKeyExchange(&cfg, &cert, &ckxOf(alloc::vec![1u8]), 0x0303).1,
        4 => {
            rka.processClientKeyExchange(&cfg, &cert, &ckxOf(alloc::vec![0u8, 5, 1, 2]), 0x0303)
                .1
        }
        5 => {
            rka.processClientKeyExchange(&cfg, &cert, &ckxOf(alloc::vec![0u8, 2, 9, 9]), 0x0303)
                .1
        }
        6 => eka.generateServerKeyExchange(&cfg, &cert, &ch, &sh).1,
        7 => eka.generateClientKeyExchange(&cfg, &ch, &x509cert).2,
        8 => eka.processServerKeyExchange(&cfg, &ch, &sh, &x509cert, &skxOf(alloc::vec![1u8, 2])),
        9 => eka.processServerKeyExchange(
            &cfg,
            &ch,
            &sh,
            &x509cert,
            &skxOf(alloc::vec![4u8, 0, 0x1d, 0]),
        ),
        _ => eka.processServerKeyExchange(
            &cfg,
            &ch,
            &sh,
            &x509cert,
            &skxOf(alloc::vec![3u8, 0, 0x18, 0, 0, 0]),
        ),
    };
    if e == crate::errors::nil {
        return crate::gostring::string::from_static("");
    }
    return e.Error();
}

// go: none — goish-only: prf.go's key schedule is unexported in Go,
// where the tests are in-package. Runs the whole TLS 1.0-1.2 schedule
// for one (suite, version) pair and hands back what Go's prf_test would
// compare: master secret, extended master secret, the six connection
// keys, the Finished transcript hash and both verify_data values.
#[doc(hidden)]
pub fn prf_schedule(
    suiteID: crate::types::uint16,
    version: crate::types::uint16,
) -> (
    crate::types::int,
    crate::goslice::slice<crate::types::byte>,
    crate::goslice::slice<crate::types::byte>,
    crate::goslice::slice<crate::goslice::slice<crate::types::byte>>,
    crate::goslice::slice<crate::types::byte>,
    crate::goslice::slice<crate::types::byte>,
    crate::goslice::slice<crate::types::byte>,
) {
    let suite = cipher_suites::cipherSuiteByID(suiteID).unwrap();
    let pms = crate::goslice::slice::__from_vec(
        (0..48u16).map(|i| i as crate::types::byte).collect::<alloc::vec::Vec<_>>(),
    );
    let cr = crate::goslice::slice::__from_vec(
        (0..32u16).map(|i| (0x40 + i) as crate::types::byte).collect::<alloc::vec::Vec<_>>(),
    );
    let sr = crate::goslice::slice::__from_vec(
        (0..32u16).map(|i| (0x80 + i) as crate::types::byte).collect::<alloc::vec::Vec<_>>(),
    );

    let (_, hash) = prf::prfAndHashForVersion(version, suite);
    let ms = prf::masterFromPreMasterSecret(version, suite, pms.clone(), cr.clone(), sr.clone());
    let ems = prf::extMasterFromPreMasterSecret(version, suite, pms, cr.clone());
    let (cm, sm, ck, sk, civ, siv) = prf::keysFromMasterSecret(
        version, suite, ms.clone(), cr.clone(), sr.clone(), 20, 16, 16,
    );
    let mut fh = prf::newFinishedHash(version, suite);
    let _ = fh.Write(crate::goslice::slice::__from_vec(
        b"handshake transcript".to_vec(),
    ));
    return (
        hash.0 as crate::types::int,
        ms.clone(),
        ems,
        crate::goslice::slice::__from_vec(alloc::vec![cm, sm, ck, sk, civ, siv]),
        fh.Sum(),
        fh.clientSum(ms.clone()),
        fh.serverSum(ms),
    );
}

// go: none — goish-only: see `prf_schedule`. Reports
// `(hashForClientCertificate over ECDSA, over Ed25519 when the buffer is
// live, ekm, ekm with a nil context, the reserved-label error)`.
#[doc(hidden)]
pub fn prf_certHashAndEKM(
    suiteID: crate::types::uint16,
    version: crate::types::uint16,
) -> (
    crate::goslice::slice<crate::types::byte>,
    crate::goslice::slice<crate::types::byte>,
    crate::goslice::slice<crate::types::byte>,
    crate::goslice::slice<crate::types::byte>,
    crate::gostring::string,
) {
    let suite = cipher_suites::cipherSuiteByID(suiteID).unwrap();
    let pms = crate::goslice::slice::__from_vec(
        (0..48u16).map(|i| i as crate::types::byte).collect::<alloc::vec::Vec<_>>(),
    );
    let cr = crate::goslice::slice::__from_vec(
        (0..32u16).map(|i| (0x40 + i) as crate::types::byte).collect::<alloc::vec::Vec<_>>(),
    );
    let sr = crate::goslice::slice::__from_vec(
        (0..32u16).map(|i| (0x80 + i) as crate::types::byte).collect::<alloc::vec::Vec<_>>(),
    );
    let ms = prf::masterFromPreMasterSecret(version, suite, pms, cr.clone(), sr.clone());
    let mut fh = prf::newFinishedHash(version, suite);
    let _ = fh.Write(crate::goslice::slice::__from_vec(
        b"handshake transcript".to_vec(),
    ));
    let ecdsaHash = fh.hashForClientCertificate(common::signatureECDSA, crate::crypto::SHA256);
    let edHash = if version >= common::VersionTLS12 {
        fh.hashForClientCertificate(common::signatureEd25519, crate::crypto::Hash(0))
    } else {
        crate::goslice::slice::new()
    };
    let ekm = prf::ekmFromMasterSecret(version, suite, ms, cr, sr);
    let (out, _) = ekm(
        crate::gostring::string::from_static("EXPERIMENTAL label"),
        crate::goslice::slice::__from_vec(alloc::vec![1u8, 2, 3]),
        32,
    );
    let (out2, _) = ekm(
        crate::gostring::string::from_static("EXPERIMENTAL label"),
        crate::goslice::slice::new(),
        16,
    );
    let (_, errR) = ekm(
        crate::gostring::string::from_static("master secret"),
        crate::goslice::slice::new(),
        16,
    );
    return (ecdsaHash, edHash, out, out2, errR.Error());
}

// go: none — goish-only: see `prf_schedule`. `discardHandshakeBuffer`
// makes hashForClientCertificate panic, which an example cannot catch,
// so the shim reports the flag instead.
#[doc(hidden)]
pub fn prf_discardHandshakeBuffer() -> bool {
    let suite =
        cipher_suites::cipherSuiteByID(cipher_suites::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
            .unwrap();
    let mut fh = prf::newFinishedHash(common::VersionTLS12, suite);
    fh.discardHandshakeBuffer();
    return fh.buffer.is_none();
}

// go: none — goish-only: cipher_suites.go's TLS 1.0-1.2 record is
// unexported in Go. Reports `(found, keyLen, macLen, ivLen, flags)`.
#[doc(hidden)]
pub fn cipher_suites_byID(
    id: crate::types::uint16,
) -> (
    bool,
    crate::types::int,
    crate::types::int,
    crate::types::int,
    crate::types::int,
) {
    let s = cipher_suites::cipherSuiteByID(id);
    if s.is_none() {
        return (false, 0, 0, 0, 0);
    }
    let s = s.unwrap();
    return (true, s.keyLen, s.macLen, s.ivLen, s.flags);
}

// go: none — goish-only: see `cipher_suites_byID`.
#[doc(hidden)]
pub fn cipher_suites_mutual(
    have: crate::goslice::slice<crate::types::uint16>,
    want: crate::types::uint16,
) -> bool {
    return cipher_suites::mutualCipherSuite(have, want).is_some();
}

// go: none — goish-only: see `cipher_suites_byID`.
#[doc(hidden)]
pub fn cipher_suites_isAESGCMPreferred(
    ciphers: crate::goslice::slice<crate::types::uint16>,
) -> bool {
    return cipher_suites::isAESGCMPreferred(ciphers);
}

// go: none — goish-only: see `cipher_suites_byID`. Filters on suiteECDHE,
// the predicate Go's own callers pass.
#[doc(hidden)]
pub fn cipher_suites_selectECDHE(
    ids: crate::goslice::slice<crate::types::uint16>,
    supportedIDs: crate::goslice::slice<crate::types::uint16>,
) -> crate::types::uint16 {
    let sel = cipher_suites::selectCipherSuite(ids, supportedIDs, &|c| {
        c.flags & cipher_suites::suiteECDHE != 0
    });
    if sel.is_none() {
        return 0;
    }
    return sel.unwrap().id;
}

// go: none — goish-only: conn.go's halfConn and the record codec's free
// functions are unexported in Go, where the tests are in-package.
#[doc(hidden)]
pub fn conn_extractPadding(
    payload: crate::goslice::slice<crate::types::byte>,
) -> (crate::types::int, crate::types::byte) {
    return conn::extractPadding(payload);
}

// go: none — goish-only: see `conn_extractPadding`.
#[doc(hidden)]
pub fn conn_roundUp(a: crate::types::int, b: crate::types::int) -> crate::types::int {
    return conn::roundUp(a, b);
}

// go: none — goish-only: see `conn_extractPadding`. Reports
// `(head, len(tail))`.
#[doc(hidden)]
pub fn conn_sliceForAppend(
    in_: crate::goslice::slice<crate::types::byte>,
    n: crate::types::int,
) -> (crate::goslice::slice<crate::types::byte>, crate::types::int) {
    let (head, tail) = conn::sliceForAppend(in_, n);
    return (head, tail.Len());
}

// go: none — goish-only: see `conn_extractPadding`. Reports
// `(explicitNonceLen with no cipher, changeCipherSpec's alert with no
// next cipher, explicitNonceLen after setTrafficSecret, seq is zeroed,
// level)`.
#[doc(hidden)]
pub fn conn_halfConnTrafficSecret() -> (
    crate::types::int,
    crate::gostring::string,
    crate::types::int,
    bool,
    crate::gostring::string,
) {
    let mut hc = conn::halfConn::default();
    hc.version = common::VersionTLS12;
    let nonceNil = hc.explicitNonceLen();
    let ccsAlert = match hc.changeCipherSpec() {
        Some(a) => a.Error(),
        None => crate::gostring::string::from_static(""),
    };

    let mut hc13 = conn::halfConn::default();
    hc13.version = common::VersionTLS13;
    let suite =
        cipher_suites::cipherSuiteTLS13ByID(cipher_suites::TLS_AES_128_GCM_SHA256).unwrap();
    let secret = crate::goslice::slice::__from_vec(
        (0..32u16).map(|i| (0x10 + i) as crate::types::byte).collect::<alloc::vec::Vec<_>>(),
    );
    hc13.setTrafficSecret(suite, quic::QUICEncryptionLevelInitial, secret);
    return (
        nonceNil,
        ccsAlert,
        hc13.explicitNonceLen(),
        hc13.seq == [0u8; 8],
        hc13.level.String(),
    );
}

// go: none — goish-only: see `conn_extractPadding`. `which` picks the
// starting sequence number: 0 = zero, 1 = ..00ff, 2 = ..ffff.
#[doc(hidden)]
pub fn conn_incSeq(which: crate::types::int) -> crate::goslice::slice<crate::types::byte> {
    let mut hc = conn::halfConn::default();
    if which == 1 {
        hc.seq = [0, 0, 0, 0, 0, 0, 0, 0xff];
    } else if which == 2 {
        hc.seq = [0, 0, 0, 0, 0, 0, 0xff, 0xff];
    }
    hc.incSeq();
    return crate::goslice::slice::__from_vec(hc.seq.to_vec());
}

// go: none — goish-only: see `conn_extractPadding`.
#[doc(hidden)]
pub fn conn_recordHeaderError(msg: crate::gostring::string) -> crate::gostring::string {
    let mut e = conn::RecordHeaderError::default();
    e.Msg = msg;
    return e.Error();
}

// go: none — goish-only: see `conn_extractPadding`. Reports
// `(Error(), Unwrap().Error(), Timeout(), Temporary())`.
#[doc(hidden)]
pub fn conn_permanentError() -> (
    crate::gostring::string,
    crate::gostring::string,
    bool,
    bool,
) {
    let e = conn::permanentError {
        err: crate::errors::New("boom"),
    };
    return (e.Error(), e.Unwrap().Error(), e.Timeout(), e.Temporary());
}

// go: none — goish-only: SessionState's private fields are unexported in
// Go, where the tests are in-package. `which` picks the session:
// 0 = a server TLS 1.3 session with two Extra blocks, 1 = a server TLS
// 1.2 session with extMasterSecret, EarlyData, an ALPN protocol and a
// curveID tail, 2 = the same as 0 but with an empty secret.
#[doc(hidden)]
pub fn ticket_sessionStateBytes(
    which: crate::types::int,
) -> (crate::goslice::slice<crate::types::byte>, crate::gostring::string) {
    let s = ticket_sampleSession(which);
    let (b, err) = s.Bytes();
    if err != crate::errors::nil {
        return (crate::goslice::slice::new(), err.Error());
    }
    return (b, crate::gostring::string::from_static(""));
}

// go: none — goish-only: see `ticket_sessionStateBytes`.
fn ticket_sampleSession(which: crate::types::int) -> ticket::SessionState {
    let mut s = ticket::SessionState::default();
    if which == 1 {
        s.__setVersion(common::VersionTLS12);
        s.__setCipherSuite(cipher_suites::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
        s.__setCreatedAt(7);
        s.__setSecret(crate::goslice::slice::__from_vec(alloc::vec![9u8, 9]));
        s.__setExtMasterSecret(true);
        s.EarlyData = true;
        s.__setAlpnProtocol(crate::gostring::string::from_static("h2"));
        s.__setCurveID(common::X25519);
        return s;
    }
    s.__setVersion(common::VersionTLS13);
    s.__setCipherSuite(cipher_suites::TLS_AES_128_GCM_SHA256);
    s.__setCreatedAt(0x1122334455667788);
    if which != 2 {
        s.__setSecret(crate::goslice::slice::__from_vec(alloc::vec![
            1u8, 2, 3, 4, 5, 6, 7, 8
        ]));
        s.Extra = crate::goslice::slice::__from_vec(alloc::vec![
            crate::goslice::slice::__from_vec(alloc::vec![0xaau8]),
            crate::goslice::slice::__from_vec(alloc::vec![0xbbu8, 0xcc]),
        ]);
    }
    return s;
}

// go: none — goish-only: see `ticket_sessionStateBytes`. Round-trips a
// sample session and reports `(err, version, suite, createdAt, secret,
// len(Extra), extMasterSecret, EarlyData, alpn, curveID, re-encoding is
// identical)`.
#[doc(hidden)]
pub fn ticket_roundTrip(
    which: crate::types::int,
) -> (
    crate::gostring::string,
    crate::types::int,
    crate::types::int,
    crate::types::uint64,
    crate::goslice::slice<crate::types::byte>,
    crate::types::int,
    bool,
    bool,
    crate::gostring::string,
    crate::types::int,
    bool,
) {
    let (enc, err) = ticket_sessionStateBytes(which);
    if err != crate::gostring::string::from_static("") {
        return (
            err, 0, 0, 0, crate::goslice::slice::new(), 0, false, false,
            crate::gostring::string::from_static(""), 0, false,
        );
    }
    let (p, perr) = ticket::ParseSessionState(enc.clone());
    if perr != crate::errors::nil {
        return (
            perr.Error(), 0, 0, 0, crate::goslice::slice::new(), 0, false, false,
            crate::gostring::string::from_static(""), 0, false,
        );
    }
    let (re, _) = p.Bytes();
    return (
        crate::gostring::string::from_static(""),
        p.__version() as crate::types::int,
        p.__cipherSuite() as crate::types::int,
        p.__createdAt(),
        p.__secret(),
        p.Extra.Len(),
        p.__extMasterSecret(),
        p.EarlyData,
        p.__alpnProtocol(),
        p.__curveID().0 as crate::types::int,
        re == enc,
    );
}

// go: none — goish-only: see `ticket_sessionStateBytes`. `which` picks a
// malformed encoding: 0 = empty, 1 = a two-byte version only, 2 = a
// valid encoding with the type byte set to 9, 3 = an empty secret.
#[doc(hidden)]
pub fn ticket_parseError(which: crate::types::int) -> crate::gostring::string {
    let data = if which == 0 {
        crate::goslice::slice::new()
    } else if which == 1 {
        crate::goslice::slice::__from_vec(alloc::vec![0x03u8, 0x04])
    } else if which == 2 {
        let (mut b, _) = ticket_sessionStateBytes(0);
        b[2] = 9;
        b
    } else {
        let (b, _) = ticket_sessionStateBytes(2);
        b
    };
    let (_, err) = ticket::ParseSessionState(data);
    if err == crate::errors::nil {
        return crate::gostring::string::from_static("");
    }
    return err.Error();
}

// go: none — goish-only: ech.go's extension codec and config selection
// are unexported in Go, where the tests are in-package. Reports
// `(type, KDFID, AEADID, configID, encap, payload, err)`.
#[doc(hidden)]
pub fn ech_parseExt(
    ext: crate::goslice::slice<crate::types::byte>,
) -> (
    crate::types::int,
    crate::types::int,
    crate::types::int,
    crate::types::int,
    crate::goslice::slice<crate::types::byte>,
    crate::goslice::slice<crate::types::byte>,
    crate::gostring::string,
) {
    let (typ, cs, id, encap, payload, err) = ech::parseECHExt(ext);
    return (
        typ.0 as crate::types::int,
        cs.KDFID as crate::types::int,
        cs.AEADID as crate::types::int,
        id as crate::types::int,
        encap,
        payload,
        if err == crate::errors::nil {
            crate::gostring::string::from_static("")
        } else {
            err.Error()
        },
    );
}

// go: none — goish-only: see `ech_parseExt`.
#[doc(hidden)]
pub fn ech_generateOuterExt(
    id: crate::types::uint8,
    kdfID: crate::types::uint16,
    aeadID: crate::types::uint16,
    encodedKey: crate::goslice::slice<crate::types::byte>,
    payload: crate::goslice::slice<crate::types::byte>,
) -> crate::goslice::slice<crate::types::byte> {
    let (b, _) = ech::generateOuterECHExt(id, kdfID, aeadID, encodedKey, payload);
    return b;
}

// go: none — goish-only: see `ech_parseExt`. `which`: 0 = two configs,
// 1 = none.
#[doc(hidden)]
pub fn ech_marshalConfigList(
    which: crate::types::int,
) -> crate::goslice::slice<crate::types::byte> {
    let configs = if which == 0 {
        let mut a = common::EncryptedClientHelloKey::default();
        a.Config = crate::goslice::slice::__from_vec(alloc::vec![1u8, 2, 3]);
        let mut b = common::EncryptedClientHelloKey::default();
        b.Config = crate::goslice::slice::__from_vec(alloc::vec![4u8, 5]);
        crate::goslice::slice::__from_vec(alloc::vec![a, b])
    } else {
        crate::goslice::slice::new()
    };
    let (out, _) = ech::marshalEncryptedClientHelloConfigList(configs);
    return out;
}

// go: none — goish-only: see `ech_parseExt`. Reports
// `(KDFID, AEADID, errText)`.
#[doc(hidden)]
pub fn ech_pickCipherSuite(
    pairs: crate::goslice::slice<crate::types::uint16>,
) -> (
    crate::types::int,
    crate::types::int,
    crate::gostring::string,
) {
    let mut suites: alloc::vec::Vec<ech::echCipher> = alloc::vec::Vec::new();
    let mut i: crate::types::int = 0;
    while i + 1 < pairs.Len() {
        suites.push(ech::echCipher {
            KDFID: pairs[i as usize],
            AEADID: pairs[(i + 1) as usize],
        });
        i += 2;
    }
    let (cs, err) = ech::pickECHCipherSuite(crate::goslice::slice::__from_vec(suites));
    return (
        cs.KDFID as crate::types::int,
        cs.AEADID as crate::types::int,
        if err == crate::errors::nil {
            crate::gostring::string::from_static("")
        } else {
            err.Error()
        },
    );
}

// go: none — goish-only: see `ech_parseExt`. `which` picks the config
// list: 0 = empty, 1 = usable, 2 = unknown KEM, 3 = empty public name,
// 4 = no usable cipher suite, 5 = a mandatory extension, 6 = an optional
// extension, 7 = an unusable config followed by a usable one.
#[doc(hidden)]
pub fn ech_pickConfig(which: crate::types::int) -> bool {
    let good = || {
        let mut c = ech::echConfig::default();
        c.KemID = 0x0020;
        c.PublicName = crate::goslice::slice::__from_vec(b"example.com".to_vec());
        c.SymmetricCipherSuite = crate::goslice::slice::__from_vec(alloc::vec![ech::echCipher {
            KDFID: 0x0001,
            AEADID: 0x0001
        }]);
        return c;
    };
    let list = match which {
        0 => crate::goslice::slice::new(),
        1 => crate::goslice::slice::__from_vec(alloc::vec![good()]),
        2 => {
            let mut c = good();
            c.KemID = 0x9999;
            crate::goslice::slice::__from_vec(alloc::vec![c])
        }
        3 => {
            let mut c = good();
            c.PublicName = crate::goslice::slice::new();
            crate::goslice::slice::__from_vec(alloc::vec![c])
        }
        4 => {
            let mut c = good();
            c.SymmetricCipherSuite =
                crate::goslice::slice::__from_vec(alloc::vec![ech::echCipher {
                    KDFID: 0x9999,
                    AEADID: 0x9999
                }]);
            crate::goslice::slice::__from_vec(alloc::vec![c])
        }
        5 => {
            let mut c = good();
            c.Extensions = crate::goslice::slice::__from_vec(alloc::vec![ech::echExtension {
                Type: 0x8001,
                Data: crate::goslice::slice::new()
            }]);
            crate::goslice::slice::__from_vec(alloc::vec![c])
        }
        6 => {
            let mut c = good();
            c.Extensions = crate::goslice::slice::__from_vec(alloc::vec![ech::echExtension {
                Type: 0x0001,
                Data: crate::goslice::slice::new()
            }]);
            crate::goslice::slice::__from_vec(alloc::vec![c])
        }
        _ => {
            let mut c = good();
            c.KemID = 0x9999;
            crate::goslice::slice::__from_vec(alloc::vec![c, good()])
        }
    };
    return ech::pickECHConfig(list).is_some();
}

// go: none — goish-only: see `ech_parseExt`. Reports the encoded inner
// ClientHello's length; the padding rule makes it a fixed value.
#[doc(hidden)]
pub fn ech_encodeInner(serverName: crate::gostring::string) -> crate::types::int {
    let mut inner = handshake_messages::clientHelloMsg::default();
    inner.vers = common::VersionTLS12;
    inner.random = alloc::vec![0u8; 32];
    inner.cipherSuites = alloc::vec![cipher_suites::TLS_AES_128_GCM_SHA256];
    inner.compressionMethods = alloc::vec![0u8];
    if serverName.Len() != 0 {
        inner.serverName = alloc::string::String::from_utf8(serverName.as_bytes().to_vec())
            .unwrap_or_default();
    }
    let (e, _) = ech::encodeInnerClientHello(&inner, 32);
    return e.Len();
}

// go: none — goish-only: see `ech_parseExt`. Reports
// `(extension types in wire order, errText)`.
#[doc(hidden)]
pub fn ech_extractRawExtensions(
    valid: bool,
) -> (
    crate::goslice::slice<crate::types::uint16>,
    crate::gostring::string,
) {
    let mut hello = handshake_messages::clientHelloMsg::default();
    if valid {
        hello.vers = common::VersionTLS12;
        hello.random = alloc::vec![0u8; 32];
        hello.cipherSuites = alloc::vec![cipher_suites::TLS_AES_128_GCM_SHA256];
        hello.compressionMethods = alloc::vec![0u8];
        hello.serverName = "example.com".into();
        hello.scts = true;
        hello.earlyData = true;
        let (enc, _) = hello.marshal();
        hello.original = enc.__into_vec();
    } else {
        hello.original = alloc::vec![1u8, 2, 3];
    }
    let (exts, err) = ech::extractRawExtensions(&hello);
    if err != crate::errors::nil {
        return (crate::goslice::slice::new(), err.Error());
    }
    let mut types: alloc::vec::Vec<crate::types::uint16> = alloc::vec::Vec::new();
    for (_, e) in crate::range!(exts) {
        types.push(e.extType);
    }
    return (
        crate::goslice::slice::__from_vec(types),
        crate::gostring::string::from_static(""),
    );
}

// go: none — goish-only: see `ech_parseExt`.
#[doc(hidden)]
pub fn ech_rejectionError() -> crate::gostring::string {
    return ech::ECHRejectionError::default().Error();
}

// go: none — goish-only: common.go's ticket-key derivation and FIPS
// chain filter are unexported in Go, where the tests are in-package.
// Reports `(aesKey, hmacKey)` for a 32-byte external key.
#[doc(hidden)]
pub fn common_ticketKeyFromBytes(
    b: crate::goslice::slice<crate::types::byte>,
) -> (
    crate::goslice::slice<crate::types::byte>,
    crate::goslice::slice<crate::types::byte>,
) {
    let mut raw = [0u8; 32];
    let src: &[crate::types::byte] = &b;
    raw[..src.len().min(32)].copy_from_slice(&src[..src.len().min(32)]);
    let k = Config::default().ticketKeyFromBytes(raw);
    return (
        crate::goslice::slice::__from_vec(k.aesKey.to_vec()),
        crate::goslice::slice::__from_vec(k.hmacKey.to_vec()),
    );
}

// go: none — goish-only: see `common_ticketKeyFromBytes`. Reports
// `(len(out), errText)` for a chain list of `n` single-certificate
// chains.
#[doc(hidden)]
pub fn common_fipsAllowedChains(n: crate::types::int) -> (crate::types::int, crate::gostring::string) {
    let mut chains: alloc::vec::Vec<crate::goslice::slice<crate::crypto::x509::Certificate>> =
        alloc::vec::Vec::new();
    let mut i: crate::types::int = 0;
    while i < n {
        chains.push(crate::goslice::slice::__from_vec(alloc::vec![
            crate::crypto::x509::Certificate::default()
        ]));
        i += 1;
    }
    let (out, err) = common::fipsAllowedChains(crate::goslice::slice::__from_vec(chains));
    if err != crate::errors::nil {
        return (0, err.Error());
    }
    return (out.Len(), crate::gostring::string::from_static(""));
}

// go: none — goish-only: see `common_ticketKeyFromBytes`.
#[doc(hidden)]
pub fn common_fipsAllowChain(n: crate::types::int) -> bool {
    let mut chain: alloc::vec::Vec<crate::crypto::x509::Certificate> = alloc::vec::Vec::new();
    let mut i: crate::types::int = 0;
    while i < n {
        chain.push(crate::crypto::x509::Certificate::default());
        i += 1;
    }
    return common::fipsAllowChain(crate::goslice::slice::__from_vec(chain));
}

// go: none — goish-only: see `common_ticketKeyFromBytes`. A default
// Config, as Go's defaultConfig returns.
#[doc(hidden)]
pub fn common_defaultConfigIsZero() -> bool {
    let c = common::defaultConfig();
    return c.MinVersion == 0
        && c.MaxVersion == 0
        && c.CipherSuites.Len() == 0
        && c.CurvePreferences.Len() == 0
        && !c.InsecureSkipVerify;
}

// go: none — goish-only: Config's ticket-key machinery is unexported in
// Go, where the tests are in-package. Reports
// `(len, first aesKey, second aesKey)` after SetSessionTicketKeys.
#[doc(hidden)]
pub fn common_setSessionTicketKeys() -> (
    crate::types::int,
    crate::goslice::slice<crate::types::byte>,
    crate::goslice::slice<crate::types::byte>,
) {
    let mut c = Config::default();
    let mut k1 = [0u8; 32];
    let mut k2 = [0u8; 32];
    let mut i = 0usize;
    while i < 32 {
        k1[i] = i as crate::types::byte;
        k2[i] = (0x80 + i) as crate::types::byte;
        i += 1;
    }
    c.SetSessionTicketKeys(crate::goslice::slice::__from_vec(alloc::vec![k1, k2]));
    let ks = c.ticketKeys(None);
    return (
        ks.Len(),
        crate::goslice::slice::__from_vec(ks[0].aesKey.to_vec()),
        crate::goslice::slice::__from_vec(ks[1].aesKey.to_vec()),
    );
}

// go: none — goish-only: see `common_setSessionTicketKeys`. `which`:
// 0 = SessionTicketsDisabled, 1 = a fresh Config (auto-rotation),
// 2 = a user-set SessionTicketKey, 3 = a configForClient with explicit
// keys, 4 = a configForClient with tickets disabled.
#[doc(hidden)]
pub fn common_ticketKeys(
    which: crate::types::int,
) -> (
    crate::types::int,
    crate::goslice::slice<crate::types::byte>,
    bool,
    bool,
) {
    let mut k1 = [0u8; 32];
    let mut k2 = [0u8; 32];
    let mut i = 0usize;
    while i < 32 {
        k1[i] = i as crate::types::byte;
        k2[i] = (0x80 + i) as crate::types::byte;
        i += 1;
    }
    if which == 0 {
        let mut d = Config::default();
        d.SessionTicketsDisabled = true;
        let ks = d.ticketKeys(None);
        return (ks.Len(), crate::goslice::slice::new(), false, false);
    }
    if which == 1 {
        let mut a = Config::default();
        let first = a.ticketKeys(None);
        let second = a.ticketKeys(None);
        let stable = first.Len() == second.Len()
            && first.Len() > 0
            && first[0].aesKey == second[0].aesKey;
        let deprecated = &a.SessionTicketKey[..10] == b"DEPRECATED";
        return (
            first.Len(),
            crate::goslice::slice::new(),
            stable,
            deprecated,
        );
    }
    if which == 2 {
        let mut u = Config::default();
        u.SessionTicketKey = k1;
        let ks = u.ticketKeys(None);
        return (
            ks.Len(),
            crate::goslice::slice::__from_vec(ks[0].aesKey.to_vec()),
            false,
            false,
        );
    }
    let mut a = Config::default();
    let mut cfc = Config::default();
    if which == 3 {
        cfc.SetSessionTicketKeys(crate::goslice::slice::__from_vec(alloc::vec![k2]));
    } else {
        cfc.SessionTicketsDisabled = true;
    }
    let ks = a.ticketKeys(Some(&mut cfc));
    let first = if ks.Len() > 0 {
        crate::goslice::slice::__from_vec(ks[0].aesKey.to_vec())
    } else {
        crate::goslice::slice::new()
    };
    return (ks.Len(), first, false, false);
}

// go: none — goish-only: see `common_setSessionTicketKeys`.
#[doc(hidden)]
pub fn common_configClone() -> (crate::gostring::string, crate::types::int, bool) {
    let mut orig = Config::default();
    orig.ServerName = crate::gostring::string::from_static("example.com");
    orig.MinVersion = common::VersionTLS12;
    orig.SessionTicketsDisabled = true;
    let cl = orig.Clone();
    return (
        cl.ServerName.clone(),
        cl.MinVersion as crate::types::int,
        cl.SessionTicketsDisabled,
    );
}

// go: none — goish-only: ClientHelloInfo.SupportsCertificate's private
// `config` field is unexported in Go, where the tests are in-package.
// `which` picks the ClientHello: 0 = TLS 1.3, 1 = an unsupported
// version, 2 = TLS 1.3 with no scheme the certificate can use, 3 = TLS
// 1.2 with no curves offered, 4 = TLS 1.2 with X25519 and an ECDSA
// suite, 5 = TLS 1.2 with X25519 but only RSA suites, 6 = TLS 1.2 with
// an incompatible point format, 7 = TLS 1.2 with no signature schemes.
// `withKey` selects an Ed25519 certificate or one with no private key.
#[doc(hidden)]
pub fn common_supportsCertificate(
    which: crate::types::int,
    withKey: bool,
) -> crate::gostring::string {
    let mut cert = common::Certificate::default();
    if withKey {
        let seed = crate::goslice::slice::__from_vec(alloc::vec![7u8; 32]);
        cert.PrivateKey = alloc::sync::Arc::new(crate::crypto::ed25519::NewKeyFromSeed(seed));
    }
    let all = crate::goslice::slice::__from_vec(alloc::vec![
        common::Ed25519,
        common::PSSWithSHA256,
        common::ECDSAWithP256AndSHA256
    ]);
    let mut chi = common::ClientHelloInfo::default();
    chi.SignatureSchemes = all.clone();
    match which {
        0 | 2 | 3 => {
            chi.SupportedVersions =
                crate::goslice::slice::__from_vec(alloc::vec![common::VersionTLS13]);
            if which == 2 {
                chi.SignatureSchemes =
                    crate::goslice::slice::__from_vec(alloc::vec![common::PSSWithSHA256]);
            }
            if which == 3 {
                chi.SupportedVersions =
                    crate::goslice::slice::__from_vec(alloc::vec![common::VersionTLS12]);
            }
        }
        1 => {
            chi.SupportedVersions = crate::goslice::slice::__from_vec(alloc::vec![0x0300u16]);
        }
        _ => {
            chi.SupportedVersions =
                crate::goslice::slice::__from_vec(alloc::vec![common::VersionTLS12]);
            chi.SupportedCurves = crate::goslice::slice::__from_vec(alloc::vec![common::X25519]);
            if which == 4 {
                chi.CipherSuites = crate::goslice::slice::__from_vec(alloc::vec![
                    cipher_suites::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                ]);
            } else if which == 5 {
                chi.CipherSuites = crate::goslice::slice::__from_vec(alloc::vec![
                    cipher_suites::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                ]);
            } else if which == 6 {
                chi.SupportedPoints = crate::goslice::slice::__from_vec(alloc::vec![1u8]);
            } else {
                chi.SignatureSchemes = crate::goslice::slice::new();
                chi.CipherSuites = crate::goslice::slice::__from_vec(alloc::vec![
                    cipher_suites::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                ]);
            }
        }
    }
    let err = chi.SupportsCertificate(&cert);
    if err == crate::errors::nil {
        return crate::gostring::string::from_static("");
    }
    return err.Error();
}

// go: none — goish-only: see `common_supportsCertificate`. `which`:
// 0 = a usable certificate, 1 = no private key, 2 = AcceptableCAs set
// against an empty chain.
#[doc(hidden)]
pub fn common_criSupportsCertificate(which: crate::types::int) -> crate::gostring::string {
    let mut cert = common::Certificate::default();
    if which != 1 {
        let seed = crate::goslice::slice::__from_vec(alloc::vec![7u8; 32]);
        cert.PrivateKey = alloc::sync::Arc::new(crate::crypto::ed25519::NewKeyFromSeed(seed));
    }
    let mut cri = common::CertificateRequestInfo::default();
    cri.Version = common::VersionTLS13;
    cri.SignatureSchemes = crate::goslice::slice::__from_vec(alloc::vec![
        common::Ed25519,
        common::PSSWithSHA256,
        common::ECDSAWithP256AndSHA256
    ]);
    if which == 2 {
        cri.AcceptableCAs = crate::goslice::slice::__from_vec(alloc::vec![
            crate::goslice::slice::__from_vec(alloc::vec![1u8, 2, 3])
        ]);
    }
    let err = cri.SupportsCertificate(&cert);
    if err == crate::errors::nil {
        return crate::gostring::string::from_static("");
    }
    return err.Error();
}

// go: none — goish-only: see `common_supportsCertificate`. Reports
// `(supported, errText)`.
#[doc(hidden)]
pub fn handshake_server_supportsECDHE(
    curves: crate::goslice::slice<common::CurveID>,
    points: crate::goslice::slice<crate::types::uint8>,
) -> (bool, crate::gostring::string) {
    let c = Config::default();
    let (ok, err) = handshake_server::supportsECDHE(&c, common::VersionTLS12, curves, points);
    if err != crate::errors::nil {
        return (ok, err.Error());
    }
    return (ok, crate::gostring::string::from_static(""));
}

// go: none — goish-only: see `common_supportsCertificate`.
#[doc(hidden)]
pub fn common_infoContextsAreNil() -> bool {
    return common::ClientHelloInfo::default().Context().is_none()
        && common::CertificateRequestInfo::default().Context().is_none();
}

// go: none — goish-only: lruSessionCache and ClientSessionState's
// private field are unexported in Go, where the tests are in-package.
// Runs Go's own eviction sequence over a capacity-3 cache and reports
// `(ticket for "a", presence of a/b/c/d after inserting "d", presence of
// "a" after a nil Put, the replaced secret for "c")`.
#[doc(hidden)]
pub fn common_lruSessionCache() -> (
    crate::goslice::slice<crate::types::byte>,
    bool,
    bool,
    bool,
    bool,
    bool,
    crate::goslice::slice<crate::types::byte>,
) {
    use common::ClientSessionCache as _;
    let mk = |tag: crate::types::byte| {
        let mut ss = ticket::SessionState::default();
        ss.__setVersion(common::VersionTLS13);
        ss.__setCipherSuite(cipher_suites::TLS_AES_128_GCM_SHA256);
        ss.__setSecret(crate::goslice::slice::__from_vec(alloc::vec![tag]));
        let (cs, _) = ticket::NewResumptionState(
            crate::goslice::slice::__from_vec(alloc::vec![tag, tag]),
            ss,
        );
        return cs;
    };
    let mut c = common::NewLRUClientSessionCache(3);
    c.Put(crate::gostring::string::from_static("a"), Some(mk(1)));
    c.Put(crate::gostring::string::from_static("b"), Some(mk(2)));
    c.Put(crate::gostring::string::from_static("c"), Some(mk(3)));
    let (sa, _) = c.Get(crate::gostring::string::from_static("a"));
    let (ticketA, _, _) = sa.unwrap().ResumptionState();
    let _ = c.Get(crate::gostring::string::from_static("b"));
    let _ = c.Get(crate::gostring::string::from_static("c"));
    // "c" is now most-recently-used and "a" least, so "d" evicts "a".
    c.Put(crate::gostring::string::from_static("d"), Some(mk(4)));
    let (_, okA) = c.Get(crate::gostring::string::from_static("a"));
    let (_, okB) = c.Get(crate::gostring::string::from_static("b"));
    let (_, okC) = c.Get(crate::gostring::string::from_static("c"));
    let (_, okD) = c.Get(crate::gostring::string::from_static("d"));
    c.Put(crate::gostring::string::from_static("a"), None);
    let (_, okANil) = c.Get(crate::gostring::string::from_static("a"));
    c.Put(crate::gostring::string::from_static("c"), Some(mk(9)));
    let (sc, _) = c.Get(crate::gostring::string::from_static("c"));
    let (_, stc, _) = sc.unwrap().ResumptionState();
    return (
        ticketA,
        okA,
        okB,
        okC,
        okD,
        okANil,
        stc.unwrap().__secret(),
    );
}

// go: none — goish-only: see `common_lruSessionCache`. A capacity of
// zero takes Go's default of 64; reports `(k0, k1, k64)` presence after
// 65 puts.
#[doc(hidden)]
pub fn common_lruDefaultCapacity() -> (bool, bool, bool) {
    use common::ClientSessionCache as _;
    let mut d = common::NewLRUClientSessionCache(0);
    let mut i: crate::types::int = 0;
    while i < 65 {
        let mut ss = ticket::SessionState::default();
        ss.__setVersion(common::VersionTLS13);
        ss.__setSecret(crate::goslice::slice::__from_vec(alloc::vec![i as crate::types::byte]));
        let (cs, _) = ticket::NewResumptionState(crate::goslice::slice::new(), ss);
        d.Put(
            crate::gostring::string::from("k") + crate::strconv::Itoa(i),
            Some(cs),
        );
        i += 1;
    }
    let (_, ok0) = d.Get(crate::gostring::string::from_static("k0"));
    let (_, ok1) = d.Get(crate::gostring::string::from_static("k1"));
    let (_, ok64) = d.Get(crate::gostring::string::from_static("k64"));
    return (ok0, ok1, ok64);
}

// go: none — goish-only: see `common_lruSessionCache`. Reports
// `(zero-value ticket is empty, zero-value state is nil, round-tripped
// ticket, round-tripped secret)`.
#[doc(hidden)]
pub fn ticket_resumptionState() -> (
    bool,
    bool,
    crate::goslice::slice<crate::types::byte>,
    crate::goslice::slice<crate::types::byte>,
) {
    let zero = ticket::ClientSessionState::default();
    let (tk, st, _) = zero.ResumptionState();
    let mut ss = ticket::SessionState::default();
    ss.__setVersion(common::VersionTLS13);
    ss.__setCipherSuite(cipher_suites::TLS_AES_128_GCM_SHA256);
    ss.__setSecret(crate::goslice::slice::__from_vec(alloc::vec![7u8]));
    let (cs, _) = ticket::NewResumptionState(
        crate::goslice::slice::__from_vec(alloc::vec![0xaau8, 0xbb]),
        ss,
    );
    let (tk3, st3, _) = cs.ResumptionState();
    return (tk.Len() == 0, st.is_none(), tk3, st3.unwrap().__secret());
}

// go: none — goish-only: ConnectionState's ekm field and Config's
// getCertificate are unexported in Go, where the tests are in-package.
// `which` picks the ekm hook: 0 = noEKMBecauseNoEMS,
// 1 = noEKMBecauseRenegotiation.
#[doc(hidden)]
pub fn common_exportKeyingMaterial(which: crate::types::int) -> crate::gostring::string {
    let mut cs = common::ConnectionState::default();
    cs.__setEKM(which == 1);
    let (_, err) = cs.ExportKeyingMaterial(
        crate::gostring::string::from_static("label"),
        crate::goslice::slice::new(),
        32,
    );
    if err == crate::errors::nil {
        return crate::gostring::string::from_static("");
    }
    return err.Error();
}

// go: none — goish-only: see `common_exportKeyingMaterial`. `which`:
// 0 = no certificates, 1 = one certificate, 2 = two with no name map,
// 3 = an exact NameToCertificate hit under a mixed-case SNI, 4 = a
// wildcard hit. Reports `(errText, the chosen leaf DER)`.
#[doc(hidden)]
pub fn common_getCertificate(
    which: crate::types::int,
) -> (
    crate::gostring::string,
    crate::goslice::slice<crate::types::byte>,
) {
    let seed = crate::goslice::slice::__from_vec(alloc::vec![7u8; 32]);
    let key = crate::crypto::ed25519::NewKeyFromSeed(seed);
    let mk = |der: crate::types::byte| {
        let mut c = common::Certificate::default();
        c.PrivateKey = alloc::sync::Arc::new(key.clone());
        c.Certificate = crate::goslice::slice::__from_vec(alloc::vec![
            crate::goslice::slice::__from_vec(alloc::vec![der])
        ]);
        return c;
    };
    let one = mk(1);
    let two = mk(2);
    let mut cfg = Config::default();
    let mut chi = common::ClientHelloInfo::default();
    if which >= 1 {
        cfg.Certificates = crate::goslice::slice::__from_vec(alloc::vec![one.clone()]);
    }
    if which >= 2 {
        cfg.Certificates =
            crate::goslice::slice::__from_vec(alloc::vec![one.clone(), two.clone()]);
        chi.ServerName = crate::gostring::string::from_static("x.example.com");
    }
    if which == 3 {
        cfg.NameToCertificate
            .Set(crate::gostring::string::from_static("a.example.com"), two.clone());
        chi.ServerName = crate::gostring::string::from_static("A.Example.com");
    }
    if which == 4 {
        cfg.NameToCertificate
            .Set(crate::gostring::string::from_static("*.example.com"), two.clone());
        chi.ServerName = crate::gostring::string::from_static("b.example.com");
    }
    let (got, err) = cfg.getCertificate(&chi);
    if err != crate::errors::nil {
        return (err.Error(), crate::goslice::slice::new());
    }
    return (
        crate::gostring::string::from_static(""),
        got.Certificate[0].clone(),
    );
}

// go: none — goish-only: see `common_exportKeyingMaterial`.
#[doc(hidden)]
pub fn common_keyLogLine() -> crate::gostring::string {
    let line = common::keyLogLine(
        crate::gostring::string::from_static("CLIENT_RANDOM"),
        crate::goslice::slice::__from_vec(alloc::vec![1u8, 2]),
        crate::goslice::slice::__from_vec(alloc::vec![3u8, 4]),
    );
    return crate::gostring::string::from_bytes(&line);
}

// go: none — goish-only: see `common_exportKeyingMaterial`.
#[doc(hidden)]
pub fn common_writeKeyLogIsNil() -> bool {
    return Config::default().writeKeyLog(
        crate::gostring::string::from_static("CLIENT_RANDOM"),
        crate::goslice::slice::new(),
        crate::goslice::slice::new(),
    ) == crate::errors::nil;
}

// go: none — goish-only: halfConn's record codec is unexported in Go,
// where the tests are in-package. Seals one record, seals a second to
// advance the sequence number, opens both, opens a tampered copy, and
// opens a TLS 1.3 change_cipher_spec — the five paths Go's own record
// tests cover. Reports
// `(record 1, plaintext 1, record 2, plaintext 2, tampered alert,
//   CCS type, CCS payload)`.
#[doc(hidden)]
pub fn conn_recordRoundTrip() -> (
    crate::goslice::slice<crate::types::byte>,
    crate::gostring::string,
    crate::goslice::slice<crate::types::byte>,
    crate::gostring::string,
    crate::gostring::string,
    crate::types::int,
    crate::goslice::slice<crate::types::byte>,
) {
    let suite =
        cipher_suites::cipherSuiteTLS13ByID(cipher_suites::TLS_AES_128_GCM_SHA256).unwrap();
    let secret = crate::goslice::slice::__from_vec(
        (0..32u16).map(|i| (0x10 + i) as crate::types::byte).collect::<alloc::vec::Vec<_>>(),
    );
    let mk = || {
        let mut hc = conn::halfConn::default();
        hc.version = common::VersionTLS13;
        hc.setTrafficSecret(suite, quic::QUICEncryptionLevelInitial, secret.clone());
        return hc;
    };
    let mut out = mk();
    let mut in_ = mk();
    let payload = crate::goslice::slice::__from_vec(b"hello record layer".to_vec());
    let header = crate::goslice::slice::__from_vec(alloc::vec![
        common::recordTypeHandshake.0,
        3,
        3,
        0,
        0
    ]);
    let mut rand = crate::crypto::rand::Reader;
    let (rec1, _) = out.encrypt(header.clone(), payload.clone(), &mut rand);
    let mut r1 = rec1.clone();
    let (pt1, _, _) = in_.decrypt(&mut r1);
    let (rec2, _) = out.encrypt(header, payload, &mut rand);
    let mut r2 = rec2.clone();
    let (pt2, _, _) = in_.decrypt(&mut r2);

    let mut bad = rec1.clone();
    let n = bad.Len();
    bad[(n - 1) as usize] ^= 0xff;
    let mut in2 = mk();
    let (_, _, alertErr) = in2.decrypt(&mut bad);
    let alertText = match alertErr {
        Some(a) => a.Error(),
        None => crate::gostring::string::from_static(""),
    };

    let mut ccs = crate::goslice::slice::__from_vec(alloc::vec![
        common::recordTypeChangeCipherSpec.0,
        3,
        3,
        0,
        1,
        0x01
    ]);
    let mut in3 = mk();
    let (ccsPayload, ccsType, _) = in3.decrypt(&mut ccs);

    return (
        rec1,
        crate::gostring::string::from_bytes(&pt1),
        rec2,
        crate::gostring::string::from_bytes(&pt2),
        alertText,
        ccsType.0 as crate::types::int,
        ccsPayload,
    );
}

// go: none — goish-only: see `conn_recordRoundTrip`. With no cipher
// configured, encrypt appends and decrypt passes through.
#[doc(hidden)]
pub fn conn_recordPlaintext() -> (
    crate::goslice::slice<crate::types::byte>,
    crate::gostring::string,
    crate::types::int,
) {
    let payload = crate::goslice::slice::__from_vec(b"hello record layer".to_vec());
    let header = crate::goslice::slice::__from_vec(alloc::vec![
        common::recordTypeHandshake.0,
        3,
        3,
        0,
        0
    ]);
    let mut out = conn::halfConn::default();
    out.version = common::VersionTLS12;
    let mut rand = crate::crypto::rand::Reader;
    let (rec, _) = out.encrypt(header, payload, &mut rand);
    let mut in_ = conn::halfConn::default();
    in_.version = common::VersionTLS12;
    let mut r = rec.clone();
    let (pt, typ, _) = in_.decrypt(&mut r);
    return (
        rec,
        crate::gostring::string::from_bytes(&pt),
        typ.0 as crate::types::int,
    );
}

// go: none — goish-only: the ticket sealing path reads Config's
// unexported key set. Seals a session, opens it, then tries a tampered
// ticket, a short one, a wrong key set, and a rotated set that still
// contains the original key. Reports `(len, round-trip fields, and the
// four rejection outcomes)`.
#[doc(hidden)]
pub fn ticket_sealRoundTrip() -> (
    crate::types::int,
    crate::types::int,
    crate::types::int,
    crate::types::uint64,
    crate::goslice::slice<crate::types::byte>,
    bool,
    bool,
    bool,
    bool,
    crate::gostring::string,
) {
    let mut k1 = [0u8; 32];
    let mut k2 = [0u8; 32];
    let mut i = 0usize;
    while i < 32 {
        k1[i] = i as crate::types::byte;
        k2[i] = (0x80 + i) as crate::types::byte;
        i += 1;
    }
    let mut c = Config::default();
    c.SetSessionTicketKeys(crate::goslice::slice::__from_vec(alloc::vec![k1]));

    let mut ss = ticket::SessionState::default();
    ss.__setVersion(common::VersionTLS13);
    ss.__setCipherSuite(cipher_suites::TLS_AES_128_GCM_SHA256);
    ss.__setCreatedAt(7);
    ss.__setSecret(crate::goslice::slice::__from_vec(alloc::vec![1u8, 2, 3, 4]));

    let (tk, _) = c.EncryptTicket(common::ConnectionState::default(), &ss);
    let (got, _) = c.DecryptTicket(tk.clone(), common::ConnectionState::default());
    let g = got.unwrap();

    let mut bad = tk.clone();
    let n = bad.Len();
    bad[(n - 1) as usize] ^= 0xff;
    let (tampered, _) = c.DecryptTicket(bad, common::ConnectionState::default());
    let (short, _) = c.DecryptTicket(
        crate::goslice::slice::__from_vec(alloc::vec![1u8, 2, 3]),
        common::ConnectionState::default(),
    );

    let mut d = Config::default();
    d.SetSessionTicketKeys(crate::goslice::slice::__from_vec(alloc::vec![k2]));
    let (wrongKey, _) = d.DecryptTicket(tk.clone(), common::ConnectionState::default());

    let mut e = Config::default();
    e.SetSessionTicketKeys(crate::goslice::slice::__from_vec(alloc::vec![k2, k1]));
    let (rotated, _) = e.DecryptTicket(tk.clone(), common::ConnectionState::default());

    let f = Config::default();
    let (_, noKeysErr) = f.encryptTicket(
        crate::goslice::slice::new(),
        crate::goslice::slice::new(),
    );

    return (
        tk.Len(),
        g.__version() as crate::types::int,
        g.__cipherSuite() as crate::types::int,
        g.__createdAt(),
        g.__secret(),
        tampered.is_none(),
        short.is_none(),
        wrongKey.is_none(),
        rotated.is_some(),
        noKeysErr.Error(),
    );
}

// go: none — goish-only: ech.go's inner-hello reconstruction is
// unexported in Go, where the tests are in-package. Builds an outer
// hello, encodes an inner one against it, decodes it back, and reports
// `(encoded length, reconstructed SNI, session id, first curve, first
// version, short-input error, nonzero-padding error)`.
#[doc(hidden)]
pub fn ech_decodeInnerRoundTrip() -> (
    crate::types::int,
    crate::gostring::string,
    crate::goslice::slice<crate::types::byte>,
    crate::types::int,
    crate::types::int,
    crate::gostring::string,
    crate::gostring::string,
) {
    let mk = |sni: &str, withECH: bool, sid: alloc::vec::Vec<crate::types::byte>| {
        let mut m = handshake_messages::clientHelloMsg::default();
        m.vers = common::VersionTLS12;
        m.random = alloc::vec![0u8; 32];
        m.sessionId = sid;
        m.cipherSuites = alloc::vec![cipher_suites::TLS_AES_128_GCM_SHA256];
        m.compressionMethods = alloc::vec![0u8];
        m.supportedCurves = alloc::vec![common::X25519.0];
        m.supportedVersions = alloc::vec![common::VersionTLS13];
        m.serverName = sni.into();
        if withECH {
            m.encryptedClientHello = alloc::vec![1u8];
        }
        return m;
    };
    let mut outer = mk("outer.example", false, alloc::vec![9u8, 9, 9]);
    let (oenc, _) = outer.marshal();
    outer.original = oenc.__into_vec();

    let inner = mk("inner.example", true, alloc::vec![]);
    let (encoded, _) = ech::encodeInnerClientHello(&inner, 32);
    let (got, err) = ech::decodeInnerClientHello(&outer, encoded.clone());
    if err != crate::errors::nil {
        return (
            encoded.Len(),
            err.Error(),
            crate::goslice::slice::new(),
            0,
            0,
            crate::gostring::string::from_static(""),
            crate::gostring::string::from_static(""),
        );
    }
    let g = got.unwrap();

    let (_, e1) = ech::decodeInnerClientHello(
        &outer,
        crate::goslice::slice::__from_vec(alloc::vec![1u8, 2, 3]),
    );
    let mut padded = encoded.__into_vec();
    let paddedLen = padded.len();
    padded.push(1);
    let (_, e2) =
        ech::decodeInnerClientHello(&outer, crate::goslice::slice::__from_vec(padded));

    return (
        paddedLen as crate::types::int,
        crate::gostring::string::from_bytes(g.serverName.as_bytes()),
        crate::goslice::slice::__from_vec(g.sessionId.clone()),
        g.supportedCurves[0] as crate::types::int,
        g.supportedVersions[0] as crate::types::int,
        e1.Error(),
        e2.Error(),
    );
}

// go: none — goish-only: see `ech_decodeInnerRoundTrip`. `which`:
// 0 = no key flagged SendAsRetry, 1 = one of two flagged.
#[doc(hidden)]
pub fn ech_buildRetryConfigList(
    which: crate::types::int,
) -> crate::goslice::slice<crate::types::byte> {
    let mut a = common::EncryptedClientHelloKey::default();
    a.Config = crate::goslice::slice::__from_vec(alloc::vec![1u8, 2]);
    let keys = if which == 0 {
        crate::goslice::slice::__from_vec(alloc::vec![a])
    } else {
        let mut b = common::EncryptedClientHelloKey::default();
        b.Config = crate::goslice::slice::__from_vec(alloc::vec![3u8, 4, 5]);
        b.SendAsRetry = true;
        crate::goslice::slice::__from_vec(alloc::vec![a, b])
    };
    let (out, _) = ech::buildRetryConfigList(keys);
    return out;
}

// go: none — goish-only: Conn's fields are unexported in Go, where the
// tests are in-package. `which`: 0 = a server Conn, 1 = a client with no
// handshake, 2 = a client with a handshake but no verified chain.
#[doc(hidden)]
pub fn conn_verifyHostname(which: crate::types::int) -> crate::gostring::string {
    let mut c = conn::Conn::default();
    if which >= 1 {
        c.__setIsClient(true);
    }
    if which >= 2 {
        c.__setHandshakeComplete(true);
    }
    return c
        .VerifyHostname(crate::gostring::string::from_static("x"))
        .Error();
}

// go: none — goish-only: see `conn_verifyHostname`. `which`: 0 = a
// handshake record, 1 = dynamic sizing disabled, 2 = four successive
// application records with no cipher, 3 = three with a TLS 1.3 AEAD,
// 4 = past the boost threshold.
#[doc(hidden)]
pub fn conn_maxPayloadSizeForWrite(
    which: crate::types::int,
) -> crate::goslice::slice<crate::types::int> {
    let mut c = conn::Conn::default();
    let mut out: alloc::vec::Vec<crate::types::int> = alloc::vec::Vec::new();
    if which == 0 {
        out.push(c.maxPayloadSizeForWrite(common::recordTypeHandshake));
    } else if which == 1 {
        c.__setDynamicRecordSizingDisabled(true);
        out.push(c.maxPayloadSizeForWrite(common::recordTypeApplicationData));
    } else if which == 2 {
        let mut i = 0;
        while i < 4 {
            out.push(c.maxPayloadSizeForWrite(common::recordTypeApplicationData));
            i += 1;
        }
    } else if which == 3 {
        c.__setVers(common::VersionTLS13);
        let suite =
            cipher_suites::cipherSuiteTLS13ByID(cipher_suites::TLS_AES_128_GCM_SHA256).unwrap();
        c.__setOutTrafficSecret(suite, crate::goslice::slice::__from_vec(alloc::vec![0u8; 32]));
        let mut i = 0;
        while i < 3 {
            out.push(c.maxPayloadSizeForWrite(common::recordTypeApplicationData));
            i += 1;
        }
    } else {
        c.__setBytesSent(conn::recordSizeBoostThreshold);
        out.push(c.maxPayloadSizeForWrite(common::recordTypeApplicationData));
    }
    return crate::goslice::slice::__from_vec(out);
}

// go: none — goish-only: see `conn_verifyHostname`. Reports
// `(HandshakeComplete, Version, CipherSuite, ServerName,
// NegotiatedProtocol, NegotiatedProtocolIsMutual, CurveID, TLSUnique,
// the ekm error, TLSUnique is empty at TLS 1.3, the renegotiation ekm
// error)`.
#[doc(hidden)]
pub fn conn_connectionState() -> (
    bool,
    crate::types::int,
    crate::types::int,
    crate::gostring::string,
    crate::gostring::string,
    bool,
    crate::types::int,
    crate::goslice::slice<crate::types::byte>,
    crate::gostring::string,
    bool,
    crate::gostring::string,
) {
    let mut k = conn::Conn::default();
    k.__setVers(common::VersionTLS12);
    k.__setHandshakeComplete(true);
    k.__setStateFields(
        cipher_suites::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        crate::gostring::string::from_static("example.com"),
        crate::gostring::string::from_static("h2"),
        common::X25519,
    );
    let st = k.ConnectionState();
    let (_, ekmErr) = st.ExportKeyingMaterial(
        crate::gostring::string::from_static("l"),
        crate::goslice::slice::new(),
        8,
    );

    let mut k13 = conn::Conn::default();
    k13.__setVers(common::VersionTLS13);
    let st13 = k13.ConnectionState();

    let mut kr = conn::Conn::default();
    kr.__setVers(common::VersionTLS13);
    kr.__setRenegotiation(common::RenegotiateOnceAsClient);
    let (_, rErr) = kr.ConnectionState().ExportKeyingMaterial(
        crate::gostring::string::from_static("l"),
        crate::goslice::slice::new(),
        8,
    );

    return (
        st.HandshakeComplete,
        st.Version as crate::types::int,
        st.CipherSuite as crate::types::int,
        st.ServerName.clone(),
        st.NegotiatedProtocol.clone(),
        st.NegotiatedProtocolIsMutual,
        st.CurveID.0 as crate::types::int,
        st.TLSUnique.clone(),
        ekmErr.Error(),
        st13.TLSUnique.Len() == 0,
        rErr.Error(),
    );
}

// go: none — goish-only: see `conn_verifyHostname`.
#[doc(hidden)]
pub fn conn_newRecordHeaderError() -> (
    crate::gostring::string,
    crate::goslice::slice<crate::types::byte>,
) {
    let mut m = conn::Conn::default();
    m.__setRawInput(crate::goslice::slice::__from_vec(alloc::vec![
        0x16u8, 0x03, 0x01, 0x00, 0x05, 0xff
    ]));
    let e = m.newRecordHeaderError(crate::gostring::string::from_static("boom"));
    return (
        e.Error(),
        crate::goslice::slice::__from_vec(e.RecordHeader.to_vec()),
    );
}

// go: none — goish-only: Conn's write path is unexported in Go, where
// the tests are in-package. Writes one record to an in-memory net::Conn
// and hands back what went on the wire. `which`: 0 = version unset,
// 1 = TLS 1.3, 2 = TLS 1.2, 3 = buffered then flushed.
#[doc(hidden)]
pub fn conn_writeRecord(
    which: crate::types::int,
) -> (
    crate::goslice::slice<crate::types::byte>,
    crate::types::int,
    crate::types::int,
    bool,
) {
    let sink = alloc::sync::Arc::new(crate::sync::Mutex::new(
        crate::goslice::slice::<crate::types::byte>::new(),
    ));
    let mut c = conn::Conn::default();
    c.__setMemConn(sink.clone());
    let data = match which {
        0 => alloc::vec![1u8, 2, 3],
        1 => alloc::vec![4u8, 5],
        2 => alloc::vec![6u8],
        _ => alloc::vec![7u8],
    };
    if which == 1 {
        c.__setVers(common::VersionTLS13);
    } else if which == 2 {
        c.__setVers(common::VersionTLS12);
    } else if which == 3 {
        c.__setBuffering(true);
    }
    let (n, _) = c.writeRecordLocked(
        common::recordTypeHandshake,
        crate::goslice::slice::__from_vec(data),
    );
    let mut flushed: crate::types::int = 0;
    let mut beforeFlush: crate::types::int = 0;
    if which == 3 {
        beforeFlush = sink.Lock().Len();
        let (fnum, _) = c.flush();
        flushed = fnum;
    }
    let out = sink.Lock().clone();
    let _ = n;
    return (out, beforeFlush, flushed, c.__buffering());
}

// go: none — goish-only: see `conn_writeRecord`. `which`: 0 = close
// notify, 1 = bad record MAC, 2 = no renegotiation, 3 = a
// change_cipher_spec with no next cipher. Reports `(errText, wire)`.
#[doc(hidden)]
pub fn conn_sendAlert(
    which: crate::types::int,
) -> (
    crate::gostring::string,
    crate::goslice::slice<crate::types::byte>,
) {
    let sink = alloc::sync::Arc::new(crate::sync::Mutex::new(
        crate::goslice::slice::<crate::types::byte>::new(),
    ));
    let mut c = conn::Conn::default();
    c.__setMemConn(sink.clone());
    c.__setVers(common::VersionTLS12);
    let err = if which == 0 {
        c.sendAlert(alert::alertCloseNotify)
    } else if which == 1 {
        c.sendAlert(alert::alertBadRecordMAC)
    } else if which == 2 {
        c.sendAlert(alert::alertNoRenegotiation)
    } else {
        c.writeChangeCipherRecord()
    };
    let text = if err == crate::errors::nil {
        crate::gostring::string::from_static("")
    } else {
        err.Error()
    };
    return (text, sink.Lock().clone());
}

// go: none — goish-only: Conn's read path is unexported in Go, where
// the tests are in-package. Feeds one record from an in-memory
// net::Conn and reports `(errText, c.hand)`. `which` selects the record;
// see the assertions for what each is.
#[doc(hidden)]
pub fn conn_readRecord(
    which: crate::types::int,
) -> (
    crate::gostring::string,
    crate::goslice::slice<crate::types::byte>,
    crate::types::int,
) {
    let feed: alloc::vec::Vec<crate::types::byte> = match which {
        0 => alloc::vec![0x16u8, 0x03, 0x01, 0x00, 0x03, 1, 2, 3],
        1 => alloc::vec![0x80u8, 0x03, 0x01, 0x00, 0x03, 1, 2, 3],
        2 => alloc::vec![0x17u8, 0x03, 0x01, 0x00, 0x01, 1],
        3 => alloc::vec![0x16u8, 0x10, 0x00, 0x00, 0x01, 1],
        4 => alloc::vec![0x16u8, 0x03, 0x01, 0x00, 0x01, 1],
        5 => alloc::vec![0x16u8, 0x03, 0x01, 0xff, 0xff],
        6 => alloc::vec![0x15u8, 0x03, 0x01, 0x00, 0x02, 0x01, 0x00],
        7 => alloc::vec![0x15u8, 0x03, 0x01, 0x00, 0x02, 0x02, 0x28],
        8 => alloc::vec![0x15u8, 0x03, 0x01, 0x00, 0x02, 0x01, 0x2e],
        9 | 10 => alloc::vec![0x14u8, 0x03, 0x01, 0x00, 0x01, 0x01],
        11 => alloc::vec![0x17u8, 0x03, 0x01, 0x00, 0x01, 1],
        _ => alloc::vec![],
    };
    let mut c = conn::Conn::default();
    c.__setFeedConn(crate::goslice::slice::__from_vec(feed));
    if which == 4 || (which >= 9 && which <= 11) {
        c.__setHaveVers(true);
        c.__setVers(common::VersionTLS12);
    }
    if which == 5 {
        c.__setHaveVers(true);
        c.__setVers(common::VersionTLS10);
    }
    let err = if which == 10 {
        c.readChangeCipherSpec()
    } else {
        c.readRecord()
    };
    let text = if err == crate::errors::nil {
        crate::gostring::string::from_static("")
    } else {
        err.Error()
    };
    return (text, c.__hand(), c.__retryCount());
}

// go: none — goish-only: Conn's close and handshake-read helpers are
// unexported in Go, where the tests are in-package. Reports
// `(CloseWrite before the handshake, CloseWrite after it, the wire, the
// second CloseWrite grew the wire, readHandshakeBytes(3) error, the
// handshake buffer, the short-feed error, its buffer)`.
#[doc(hidden)]
pub fn conn_closeAndHandshakeBytes() -> (
    crate::gostring::string,
    crate::gostring::string,
    crate::goslice::slice<crate::types::byte>,
    bool,
    crate::gostring::string,
    crate::goslice::slice<crate::types::byte>,
    crate::gostring::string,
    crate::goslice::slice<crate::types::byte>,
) {
    let mut early = conn::Conn::default();
    early.__setMemConn(alloc::sync::Arc::new(crate::sync::Mutex::new(
        crate::goslice::slice::<crate::types::byte>::new(),
    )));
    let earlyErr = early.CloseWrite().Error();

    let sink = alloc::sync::Arc::new(crate::sync::Mutex::new(
        crate::goslice::slice::<crate::types::byte>::new(),
    ));
    let mut c = conn::Conn::default();
    c.__setMemConn(sink.clone());
    c.__setVers(common::VersionTLS12);
    c.__setHandshakeComplete(true);
    let err1 = c.CloseWrite();
    let wire = sink.Lock().clone();
    let before = wire.Len();
    let _ = c.CloseWrite();
    let grew = sink.Lock().Len() != before;

    let feed = alloc::vec![
        0x16u8, 0x03, 0x01, 0x00, 0x02, 1, 2, 0x16, 0x03, 0x01, 0x00, 0x02, 3, 4
    ];
    let mut c3 = conn::Conn::default();
    c3.__setFeedConn(crate::goslice::slice::__from_vec(feed.clone()));
    let e3 = c3.readHandshakeBytes(3);
    let mut c4 = conn::Conn::default();
    c4.__setFeedConn(crate::goslice::slice::__from_vec(feed[..7].to_vec()));
    let e4 = c4.readHandshakeBytes(3);

    let txt = |e: crate::error| {
        if e == crate::errors::nil {
            return crate::gostring::string::from_static("");
        }
        return e.Error();
    };
    return (
        earlyErr,
        txt(err1),
        wire,
        grew,
        txt(e3),
        c3.__hand(),
        txt(e4),
        c4.__hand(),
    );
}

// go: none — goish-only: see `conn_closeAndHandshakeBytes`. Reports
// `(the default dialer's timeout, an explicit dialer's timeout)`.
#[doc(hidden)]
pub fn tls_dialerNetDialer() -> (crate::types::int64, crate::types::int64) {
    let d = tls::Dialer::default();
    let mut nd = crate::net::Dialer::default();
    nd.Timeout = crate::time::Second * 5;
    let mut d2 = tls::Dialer::default();
    d2.NetDialer = Some(nd);
    return (d.netDialer().Timeout.0, d2.netDialer().Timeout.0);
}

// go: none — goish-only: handshake_client.go's and handshake_server.go's
// free functions are unexported in Go, where the tests are in-package.
#[doc(hidden)]
pub fn handshake_client_hostnameInSNI(
    name: crate::gostring::string,
) -> crate::gostring::string {
    return handshake_client::hostnameInSNI(name);
}

// go: none — goish-only: see `handshake_client_hostnameInSNI`.
#[doc(hidden)]
pub fn handshake_client_checkKeySize(
    n: crate::types::int,
) -> (crate::types::int, bool) {
    return handshake_client::checkKeySize(n);
}

// go: none — goish-only: see `handshake_client_hostnameInSNI`.
#[doc(hidden)]
pub fn handshake_client_checkALPN(
    clientProtos: crate::goslice::slice<crate::gostring::string>,
    serverProto: crate::gostring::string,
    quic: bool,
) -> crate::gostring::string {
    let e = handshake_client::checkALPN(clientProtos, serverProto, quic);
    if e == crate::errors::nil {
        return crate::gostring::string::from_static("");
    }
    return e.Error();
}

// go: none — goish-only: see `handshake_client_hostnameInSNI`.
#[doc(hidden)]
pub fn handshake_server_negotiateALPN(
    serverProtos: crate::goslice::slice<crate::gostring::string>,
    clientProtos: crate::goslice::slice<crate::gostring::string>,
    quic: bool,
) -> (crate::gostring::string, crate::gostring::string) {
    let (p, e) = handshake_server::negotiateALPN(serverProtos, clientProtos, quic);
    if e == crate::errors::nil {
        return (p, crate::gostring::string::from_static(""));
    }
    return (p, e.Error());
}

// go: none — goish-only: certificateRequestInfoFromMsg is unexported in
// Go, where the tests are in-package. `which`: 0 = no signature
// algorithms and no certificate types, 1 = RSA only, 2 = ECDSA only,
// 3 = both, 4..6 = the same three with hasSignatureAlgorithm set and a
// mixed scheme list (including one unknown scheme). Reports
// `(Version, len(AcceptableCAs), the selected schemes)`.
#[doc(hidden)]
pub fn handshake_client_certificateRequestInfo(
    which: crate::types::int,
) -> (
    crate::types::int,
    crate::types::int,
    crate::goslice::slice<common::SignatureScheme>,
) {
    let mut m = handshake_messages::certificateRequestMsg::default();
    let types: alloc::vec::Vec<crate::types::byte> = match which % 4 {
        0 => alloc::vec![],
        1 => alloc::vec![1u8],
        2 => alloc::vec![64u8],
        _ => alloc::vec![1u8, 64],
    };
    m.certificateTypes = crate::goslice::slice::__from_vec(types);
    if which >= 4 {
        m.hasSignatureAlgorithm = true;
        m.supportedSignatureAlgorithms = crate::goslice::slice::__from_vec(alloc::vec![
            common::PSSWithSHA256,
            common::ECDSAWithP256AndSHA256,
            common::Ed25519,
            common::PKCS1WithSHA1,
            common::SignatureScheme(0x9999),
        ]);
    }
    if which == 7 {
        m.certificateAuthorities = crate::goslice::slice::__from_vec(alloc::vec![
            crate::goslice::slice::__from_vec(alloc::vec![1u8, 2])
        ]);
    }
    let cri = handshake_client::certificateRequestInfoFromMsg(common::VersionTLS12, &m);
    return (
        cri.Version as crate::types::int,
        cri.AcceptableCAs.Len(),
        cri.SignatureSchemes.clone(),
    );
}

// go: none — goish-only: illegalClientHelloChange and the TLS 1.3
// server state are unexported in Go, where the tests are in-package.
// `which` picks what the second ClientHello changed: 0 = nothing,
// 1 = keyShares, 2 = earlyData, 3 = pskIdentities, 4 = serverName,
// 5 = cipherSuites (replaced), 6 = cipherSuites (grew), 7 = random,
// 8 = cookie, 9 = alpnProtocols.
#[doc(hidden)]
pub fn handshake_server_tls13_illegalChange(which: crate::types::int) -> bool {
    let base = || {
        let mut m = handshake_messages::clientHelloMsg::default();
        m.vers = common::VersionTLS12;
        m.random = alloc::vec![0u8; 32];
        m.sessionId = alloc::vec![1u8];
        m.cipherSuites = alloc::vec![0x1301u16];
        m.compressionMethods = alloc::vec![0u8];
        m.supportedCurves = alloc::vec![common::X25519.0];
        m.supportedVersions = alloc::vec![common::VersionTLS13];
        m.supportedSignatureAlgorithms = alloc::vec![common::Ed25519.0];
        m.alpnProtocols = alloc::vec!["h2".into()];
        m.serverName = "a.example".into();
        m.pskModes = alloc::vec![1u8];
        return m;
    };
    let a = base();
    let mut b = base();
    match which {
        1 => {
            b.keyShares = alloc::vec![handshake_messages::keyShare {
                group: common::X25519.0,
                data: alloc::vec![1u8],
            }]
        }
        2 => b.earlyData = true,
        3 => {
            b.pskIdentities = alloc::vec![handshake_messages::pskIdentity {
                label: alloc::vec![1u8],
                obfuscatedTicketAge: 0,
            }]
        }
        4 => b.serverName = "b.example".into(),
        5 => b.cipherSuites = alloc::vec![0x1302u16],
        6 => b.cipherSuites = alloc::vec![0x1301u16, 0x1302],
        7 => b.random[0] = 9,
        8 => b.cookie = alloc::vec![1u8],
        9 => b.alpnProtocols = alloc::vec!["http/1.1".into()],
        _ => {}
    }
    return handshake_server_tls13::illegalClientHelloChange(&a, &b);
}

// go: none — goish-only: see `handshake_server_tls13_illegalChange`.
// Reports `(shouldSendSessionTickets by default, with tickets disabled,
// with no pskModes, requestClientCert by default, with
// RequestClientCert, with RequestClientCert and a PSK)`.
#[doc(hidden)]
pub fn handshake_server_tls13_stateFlags() -> (bool, bool, bool, bool, bool, bool) {
    let ch = || {
        let mut m = handshake_messages::clientHelloMsg::default();
        m.pskModes = alloc::vec![1u8];
        return m;
    };
    let mk = |cfg: Config, hello: handshake_messages::clientHelloMsg, psk: bool| {
        let mut c = conn::Conn::default();
        c.__setConfig(cfg);
        return handshake_server_tls13::serverHandshakeStateTLS13 {
            c,
            clientHello: hello,
            sentDummyCCS: false,
            usingPSK: psk,
            sigAlg: common::SignatureScheme(0),
            cert: None,
        };
    };
    let mut disabled = Config::default();
    disabled.SessionTicketsDisabled = true;
    let mut requested = Config::default();
    requested.ClientAuth = common::RequestClientCert;
    let noPSK = handshake_messages::clientHelloMsg::default();
    return (
        mk(Config::default(), ch(), false).shouldSendSessionTickets(),
        mk(disabled, ch(), false).shouldSendSessionTickets(),
        mk(Config::default(), noPSK, false).shouldSendSessionTickets(),
        mk(Config::default(), ch(), false).requestClientCert(),
        mk(requested.clone(), ch(), false).requestClientCert(),
        mk(requested, ch(), true).requestClientCert(),
    );
}

// go: none — goish-only: cloneHash is unexported in Go, where the tests
// are in-package. Forks a SHA-256 transcript, feeds each half a
// different byte, and reports `(clone succeeded, original digest, clone
// digest, a cross-hash clone was refused)`.
#[doc(hidden)]
pub fn handshake_server_tls13_cloneHash() -> (
    bool,
    crate::goslice::slice<crate::types::byte>,
    crate::goslice::slice<crate::types::byte>,
    bool,
) {
    let mut h = crate::crypto::sha256::NewHash();
    let _ = crate::io::Writer::Write(
        &mut *h,
        crate::goslice::slice::__from_vec(b"first half".to_vec()),
    );
    let c = handshake_server_tls13::cloneHash(&*h, crate::crypto::SHA256);
    if c.is_none() {
        return (
            false,
            crate::goslice::slice::new(),
            crate::goslice::slice::new(),
            false,
        );
    }
    let mut c = c.unwrap();
    let _ = crate::io::Writer::Write(
        &mut *h,
        crate::goslice::slice::__from_vec(alloc::vec![b'A']),
    );
    let _ = crate::io::Writer::Write(
        &mut *c,
        crate::goslice::slice::__from_vec(alloc::vec![b'B']),
    );
    let orig = h.Sum(crate::goslice::slice::new());
    let clone = c.Sum(crate::goslice::slice::new());
    let cross = handshake_server_tls13::cloneHash(
        &*crate::crypto::sha256::NewHash(),
        crate::crypto::SHA384,
    );
    return (true, orig, clone, cross.is_none());
}

// go: none — goish-only: serverHelloMsg is unexported in Go, where the
// tests are in-package. Marshals a TLS 1.3 ServerHello, parses it back,
// and reports `(encoding, unmarshal ok, vers, suite, sessionId,
// supportedVersion, key-share group, key-share data, originalBytes
// matches, a truncated input is rejected)`.
#[doc(hidden)]
pub fn handshake_messages_serverHelloRoundTrip() -> (
    crate::goslice::slice<crate::types::byte>,
    bool,
    crate::types::int,
    crate::types::int,
    crate::goslice::slice<crate::types::byte>,
    crate::types::int,
    crate::types::int,
    crate::goslice::slice<crate::types::byte>,
    bool,
    bool,
) {
    let mut sh = handshake_messages::serverHelloMsg::default();
    sh.vers = common::VersionTLS12;
    sh.random = alloc::vec![0u8; 32];
    sh.sessionId = alloc::vec![1u8, 2];
    sh.cipherSuite = cipher_suites::TLS_AES_128_GCM_SHA256;
    sh.supportedVersion = common::VersionTLS13;
    sh.serverShare = handshake_messages::keyShare {
        group: common::X25519.0,
        data: alloc::vec![9u8, 9, 9, 9],
    };
    let (enc, _) = sh.marshal();
    let mut r = handshake_messages::serverHelloMsg::default();
    let ok = r.unmarshal(enc.clone());
    let mut tr = handshake_messages::serverHelloMsg::default();
    let bad = !tr.unmarshal(enc.slice(0, 10));
    return (
        enc.clone(),
        ok,
        r.vers as crate::types::int,
        r.cipherSuite as crate::types::int,
        crate::goslice::slice::__from_vec(r.sessionId.clone()),
        r.supportedVersion as crate::types::int,
        r.serverShare.group as crate::types::int,
        crate::goslice::slice::__from_vec(r.serverShare.data.clone()),
        r.originalBytes() == enc,
        bad,
    );
}

// go: none — goish-only: serverHandshakeState is unexported in Go,
// where the tests are in-package. `which` picks the state's four
// capability flags and the version; the suite is named by `suiteID`.
#[doc(hidden)]
pub fn handshake_server_cipherSuiteOk(
    which: crate::types::int,
    suiteID: crate::types::uint16,
) -> bool {
    let mut c = conn::Conn::default();
    c.__setVers(if which == 5 {
        common::VersionTLS10
    } else {
        common::VersionTLS12
    });
    let hs = handshake_server::serverHandshakeState {
        c,
        clientHello: handshake_messages::clientHelloMsg::default(),
        hello: handshake_messages::serverHelloMsg::default(),
        suite: None,
        finishedHash: __neutralFinishedHash(),
        masterSecret: crate::goslice::slice::new(),
        sessionState: None,
        ecdheOk: which != 1,
        ecSignOk: which != 2,
        rsaDecryptOk: which != 4,
        rsaSignOk: which != 3,
    };
    let suite = cipher_suites::cipherSuiteByID(suiteID).unwrap();
    return hs.cipherSuiteOk(suite);
}

// go: none — goish-only: see `handshake_server_cipherSuiteOk`. `full`
// selects a populated ClientHello or one carrying only a version.
// Reports `(ServerName, cipher suites, curves, points, schemes, protos,
// extensions, supported versions)`.
#[doc(hidden)]
pub fn handshake_server_clientHelloInfo(
    full: bool,
) -> (
    crate::gostring::string,
    crate::types::int,
    crate::types::int,
    crate::types::int,
    crate::types::int,
    crate::types::int,
    crate::types::int,
    crate::goslice::slice<crate::types::uint16>,
) {
    let mut ch = handshake_messages::clientHelloMsg::default();
    ch.vers = common::VersionTLS12;
    if full {
        ch.cipherSuites = alloc::vec![cipher_suites::TLS_AES_128_GCM_SHA256];
        ch.serverName = "a.example".into();
        ch.supportedCurves = alloc::vec![common::X25519.0];
        ch.supportedPoints = alloc::vec![0u8];
        ch.supportedSignatureAlgorithms = alloc::vec![common::Ed25519.0];
        ch.alpnProtocols = alloc::vec!["h2".into()];
        ch.extensions = alloc::vec![0u16, 43];
    }
    let c = conn::Conn::default();
    let chi = handshake_server::clientHelloInfo(&c, &ch);
    return (
        chi.ServerName.clone(),
        chi.CipherSuites.Len(),
        chi.SupportedCurves.Len(),
        chi.SupportedPoints.Len(),
        chi.SignatureSchemes.Len(),
        chi.SupportedProtos.Len(),
        chi.Extensions.Len(),
        chi.SupportedVersions.clone(),
    );
}

// go: none — goish-only: pickTLSVersion and both pickCipherSuite
// methods are unexported in Go, where the tests are in-package.
// `which`: 0 = legacy 1.2 only, 1 = 1.2 with supported_versions 1.3,
// 2 = legacy 1.0, 3 = supported_versions 0x0305. Reports
// `(errText, c.vers, c.in.version)`.
#[doc(hidden)]
pub fn handshake_client_pickTLSVersion(
    which: crate::types::int,
) -> (
    crate::gostring::string,
    crate::types::int,
    crate::types::int,
) {
    let mut sh = handshake_messages::serverHelloMsg::default();
    sh.vers = match which {
        2 => common::VersionTLS10,
        _ => common::VersionTLS12,
    };
    if which == 1 {
        sh.supportedVersion = common::VersionTLS13;
    } else if which == 3 {
        sh.supportedVersion = 0x0305;
    }
    let mut c = conn::Conn::default();
    c.__setMemConn(alloc::sync::Arc::new(crate::sync::Mutex::new(
        crate::goslice::slice::<crate::types::byte>::new(),
    )));
    let err = c.pickTLSVersion(&sh);
    let text = if err == crate::errors::nil {
        crate::gostring::string::from_static("")
    } else {
        err.Error()
    };
    return (
        text,
        c.__vers() as crate::types::int,
        c.__inVersion() as crate::types::int,
    );
}

// go: none — goish-only: see `handshake_client_pickTLSVersion`.
// Reports `(errText, selected suite, the Conn's recorded suite)`.
#[doc(hidden)]
pub fn handshake_client_pickCipherSuite(
    offered: crate::goslice::slice<crate::types::uint16>,
    chosen: crate::types::uint16,
) -> (
    crate::gostring::string,
    crate::types::int,
    crate::types::int,
) {
    let mut c = conn::Conn::default();
    c.__setMemConn(alloc::sync::Arc::new(crate::sync::Mutex::new(
        crate::goslice::slice::<crate::types::byte>::new(),
    )));
    c.__setVers(common::VersionTLS12);
    let mut hello = handshake_messages::clientHelloMsg::default();
    hello.cipherSuites = offered.__into_vec();
    let mut serverHello = handshake_messages::serverHelloMsg::default();
    serverHello.cipherSuite = chosen;
    let mut hs = handshake_client::clientHandshakeState {
        c,
        serverHello,
        hello,
        suite: None,
        finishedHash: __neutralFinishedHash(),
        masterSecret: crate::goslice::slice::new(),
        session: None,
        ticket: crate::goslice::slice::new(),
    };
    let err = hs.pickCipherSuite();
    if err != crate::errors::nil {
        return (err.Error(), 0, 0);
    }
    return (
        crate::gostring::string::from_static(""),
        hs.suite.unwrap().id as crate::types::int,
        hs.c.__cipherSuite() as crate::types::int,
    );
}

// go: none — goish-only: see `handshake_client_pickTLSVersion`.
// `noECDHE` clears the ECDHE capability. Reports `(errText, suite)`.
#[doc(hidden)]
pub fn handshake_server_pickCipherSuite(
    offered: crate::goslice::slice<crate::types::uint16>,
    noECDHE: bool,
) -> (crate::gostring::string, crate::types::int) {
    let mut c = conn::Conn::default();
    c.__setMemConn(alloc::sync::Arc::new(crate::sync::Mutex::new(
        crate::goslice::slice::<crate::types::byte>::new(),
    )));
    c.__setVers(common::VersionTLS12);
    let mut clientHello = handshake_messages::clientHelloMsg::default();
    clientHello.vers = common::VersionTLS12;
    clientHello.cipherSuites = offered.__into_vec();
    let mut hs = handshake_server::serverHandshakeState {
        c,
        clientHello,
        hello: handshake_messages::serverHelloMsg::default(),
        suite: None,
        finishedHash: __neutralFinishedHash(),
        masterSecret: crate::goslice::slice::new(),
        sessionState: None,
        ecdheOk: !noECDHE,
        ecSignOk: true,
        rsaDecryptOk: true,
        rsaSignOk: true,
    };
    let err = hs.pickCipherSuite();
    if err != crate::errors::nil {
        return (err.Error(), 0);
    }
    return (
        crate::gostring::string::from_static(""),
        hs.suite.unwrap().id as crate::types::int,
    );
}

// go: none — goish-only: serverHandshakeState.establishKeys is
// unexported in Go, where the tests are in-package. Derives the keys for
// one suite and reports `(errText, explicitNonceLen before the
// ChangeCipherSpec, after it, whether a MAC was staged, clientKey,
// serverKey, clientIV, serverIV)`.
#[doc(hidden)]
pub fn handshake_server_establishKeys(
    suiteID: crate::types::uint16,
) -> (
    crate::gostring::string,
    crate::types::int,
    crate::types::int,
    bool,
    crate::goslice::slice<crate::types::byte>,
    crate::goslice::slice<crate::types::byte>,
    crate::goslice::slice<crate::types::byte>,
    crate::goslice::slice<crate::types::byte>,
) {
    let mut c = conn::Conn::default();
    c.__setMemConn(alloc::sync::Arc::new(crate::sync::Mutex::new(
        crate::goslice::slice::<crate::types::byte>::new(),
    )));
    c.__setVers(common::VersionTLS12);
    let suite = cipher_suites::cipherSuiteByID(suiteID).unwrap();
    let ms = crate::goslice::slice::__from_vec(
        (0..48u16).map(|i| (0x10 + i) as crate::types::byte).collect::<alloc::vec::Vec<_>>(),
    );
    let cr: alloc::vec::Vec<crate::types::byte> =
        (0..32u16).map(|i| (0x40 + i) as crate::types::byte).collect();
    let sr: alloc::vec::Vec<crate::types::byte> =
        (0..32u16).map(|i| (0x80 + i) as crate::types::byte).collect();
    let mut clientHello = handshake_messages::clientHelloMsg::default();
    clientHello.random = cr.clone();
    let mut hello = handshake_messages::serverHelloMsg::default();
    hello.random = sr.clone();
    let mut hs = handshake_server::serverHandshakeState {
        c,
        clientHello,
        hello,
        suite: Some(suite),
        finishedHash: __neutralFinishedHash(),
        masterSecret: ms.clone(),
        sessionState: None,
        ecdheOk: true,
        ecSignOk: true,
        rsaDecryptOk: true,
        rsaSignOk: true,
    };
    let err = hs.establishKeys();
    let before = hs.c.__inExplicitNonceLen();
    let staged = hs.c.__changeCipherSpecs();
    let after = hs.c.__inExplicitNonceLen();
    let (_, _, ck, sk, civ, siv) = prf::keysFromMasterSecret(
        common::VersionTLS12,
        suite,
        ms,
        crate::goslice::slice::__from_vec(cr),
        crate::goslice::slice::__from_vec(sr),
        suite.macLen,
        suite.keyLen,
        suite.ivLen,
    );
    let text = if err == crate::errors::nil {
        crate::gostring::string::from_static("")
    } else {
        err.Error()
    };
    return (text, before, after, staged, ck, sk, civ, siv);
}

// go: none — goish-only: checkForResumption reads Config's unexported
// ticket keys and SessionState's unexported fields. `which` mutates the
// scenario: 0 = a resumable session, 1 = tickets disabled, 2 = a session
// from a different TLS version, 3 = a suite the client no longer offers,
// 4 = a ticket older than maxSessionTicketLifetime, 5 = the session used
// extended_master_secret and the client does not, 6 = the reverse.
// Reports `(errText, didResume, a suite was selected)`.
#[doc(hidden)]
pub fn handshake_server_checkForResumption(
    which: crate::types::int,
) -> (crate::gostring::string, bool, bool) {
    let mut k = [0u8; 32];
    let mut i = 0usize;
    while i < 32 {
        k[i] = i as crate::types::byte;
        i += 1;
    }
    let mut cfg = Config::default();
    cfg.SetSessionTicketKeys(crate::goslice::slice::__from_vec(alloc::vec![k]));
    if which == 1 {
        cfg.SessionTicketsDisabled = true;
    }

    let mut ss = ticket::SessionState::default();
    ss.__setVersion(if which == 2 {
        common::VersionTLS13
    } else {
        common::VersionTLS12
    });
    ss.__setCipherSuite(cipher_suites::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
    let nowSec = crate::time::Now().Unix();
    ss.__setCreatedAt(if which == 4 {
        (nowSec - 8 * 24 * 3600) as crate::types::uint64
    } else {
        nowSec as crate::types::uint64
    });
    ss.__setSecret(crate::goslice::slice::__from_vec(alloc::vec![1u8, 2, 3, 4]));
    if which == 5 {
        ss.__setExtMasterSecret(true);
    }

    let mut ch = handshake_messages::clientHelloMsg::default();
    ch.cipherSuites = if which == 3 {
        alloc::vec![cipher_suites::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384]
    } else {
        alloc::vec![cipher_suites::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256]
    };
    if which == 6 {
        ch.extendedMasterSecret = true;
    }

    let (tk, _) = cfg.EncryptTicket(common::ConnectionState::default(), &ss);
    ch.sessionTicket = tk.__into_vec();

    let mut c = conn::Conn::default();
    c.__setMemConn(alloc::sync::Arc::new(crate::sync::Mutex::new(
        crate::goslice::slice::<crate::types::byte>::new(),
    )));
    c.__setVers(common::VersionTLS12);
    c.__setTicketKeys(cfg.ticketKeys(None));
    c.__setConfig(cfg);
    let mut hs = handshake_server::serverHandshakeState {
        c,
        clientHello: ch,
        hello: handshake_messages::serverHelloMsg::default(),
        suite: None,
        finishedHash: __neutralFinishedHash(),
        masterSecret: crate::goslice::slice::new(),
        sessionState: None,
        ecdheOk: true,
        ecSignOk: true,
        rsaDecryptOk: true,
        rsaSignOk: true,
    };
    let err = hs.checkForResumption();
    let text = if err == crate::errors::nil {
        crate::gostring::string::from_static("")
    } else {
        err.Error()
    };
    return (text, hs.c.__didResume(), hs.suite.is_some());
}

// go: none — goish-only: clientHandshakeState is unexported in Go,
// where the tests are in-package. Runs the client's establishKeys and
// reports `(errText, staged ok, read-half explicit nonce after the CCS)`.
#[doc(hidden)]
pub fn handshake_client_establishKeys() -> (
    crate::gostring::string,
    bool,
    crate::types::int,
) {
    let mut c = conn::Conn::default();
    c.__setMemConn(alloc::sync::Arc::new(crate::sync::Mutex::new(
        crate::goslice::slice::<crate::types::byte>::new(),
    )));
    c.__setVers(common::VersionTLS12);
    let suite =
        cipher_suites::cipherSuiteByID(cipher_suites::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
            .unwrap();
    let ms = crate::goslice::slice::__from_vec(
        (0..48u16).map(|i| (0x10 + i) as crate::types::byte).collect::<alloc::vec::Vec<_>>(),
    );
    let mut hello = handshake_messages::clientHelloMsg::default();
    hello.random = (0..32u16).map(|i| (0x40 + i) as crate::types::byte).collect();
    let mut serverHello = handshake_messages::serverHelloMsg::default();
    serverHello.random = (0..32u16).map(|i| (0x80 + i) as crate::types::byte).collect();
    let mut hs = handshake_client::clientHandshakeState {
        c,
        serverHello,
        hello,
        suite: Some(suite),
        finishedHash: __neutralFinishedHash(),
        masterSecret: ms,
        session: None,
        ticket: crate::goslice::slice::new(),
    };
    let err = hs.establishKeys();
    let staged = hs.c.__changeCipherSpecs();
    let text = if err == crate::errors::nil {
        crate::gostring::string::from_static("")
    } else {
        err.Error()
    };
    return (text, staged, hs.c.__inExplicitNonceLen());
}

// go: none — goish-only: see `handshake_client_establishKeys`.
// `which`: 0 = a session and matching ids, 1 = ids differ, 2 = no
// session, 3 = the client sent no session id.
#[doc(hidden)]
pub fn handshake_client_serverResumedSession(which: crate::types::int) -> bool {
    let mut hello = handshake_messages::clientHelloMsg::default();
    let mut serverHello = handshake_messages::serverHelloMsg::default();
    if which != 3 {
        hello.sessionId = alloc::vec![1u8, 2];
        serverHello.sessionId = if which == 1 {
            alloc::vec![3u8]
        } else {
            alloc::vec![1u8, 2]
        };
    }
    let hs = handshake_client::clientHandshakeState {
        c: conn::Conn::default(),
        serverHello,
        hello,
        suite: None,
        finishedHash: __neutralFinishedHash(),
        masterSecret: crate::goslice::slice::new(),
        session: if which == 2 {
            None
        } else {
            Some(ticket::SessionState::default())
        },
        ticket: crate::goslice::slice::new(),
    };
    return hs.serverResumedSession();
}

// go: none — goish-only: processServerHello reads clientHandshakeState's
// unexported fields. `which`: 0 = a plain ServerHello, 1 = an unsupported
// compression method, 2 = an incompatible point format, 3 = an
// unrequested ALPN protocol, 4 = a matching ALPN protocol, 5 = a
// non-empty renegotiation extension on the first handshake, 6 = a valid
// resumption, 7 = a session from another version, 8 = another suite,
// 9 = an EMS mismatch. Reports `(resumed, errText, masterSecret,
// negotiated protocol, didResume)`.
#[doc(hidden)]
pub fn handshake_client_processServerHello(
    which: crate::types::int,
) -> (
    bool,
    crate::gostring::string,
    crate::goslice::slice<crate::types::byte>,
    crate::gostring::string,
    bool,
) {
    let suiteID = cipher_suites::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
    let mut ch = handshake_messages::clientHelloMsg::default();
    ch.cipherSuites = alloc::vec![suiteID];
    let mut sh = handshake_messages::serverHelloMsg::default();
    sh.cipherSuite = suiteID;
    let mut sess: Option<ticket::SessionState> = None;
    match which {
        1 => sh.compressionMethod = 1,
        2 => sh.supportedPoints = alloc::vec![1u8],
        3 => sh.alpnProtocol = "h2".into(),
        4 => {
            ch.alpnProtocols = alloc::vec!["h2".into()];
            sh.alpnProtocol = "h2".into();
        }
        5 => {
            sh.secureRenegotiationSupported = true;
            sh.secureRenegotiation = alloc::vec![1u8];
        }
        6 | 7 | 8 | 9 => {
            ch.sessionId = alloc::vec![7u8];
            sh.sessionId = alloc::vec![7u8];
            let mut ss = ticket::SessionState::default();
            ss.__setVersion(if which == 7 {
                common::VersionTLS13
            } else {
                common::VersionTLS12
            });
            ss.__setCipherSuite(if which == 8 {
                cipher_suites::TLS_AES_128_GCM_SHA256
            } else {
                suiteID
            });
            ss.__setSecret(crate::goslice::slice::__from_vec(alloc::vec![9u8, 9]));
            if which == 9 {
                ss.__setExtMasterSecret(true);
            }
            sess = Some(ss);
        }
        _ => {}
    }
    let mut c = conn::Conn::default();
    c.__setMemConn(alloc::sync::Arc::new(crate::sync::Mutex::new(
        crate::goslice::slice::<crate::types::byte>::new(),
    )));
    c.__setVers(common::VersionTLS12);
    let mut hs = handshake_client::clientHandshakeState {
        c,
        serverHello: sh,
        hello: ch,
        suite: None,
        finishedHash: __neutralFinishedHash(),
        masterSecret: crate::goslice::slice::new(),
        session: sess,
        ticket: crate::goslice::slice::new(),
    };
    let (resumed, err) = hs.processServerHello();
    let text = if err == crate::errors::nil {
        crate::gostring::string::from_static("")
    } else {
        err.Error()
    };
    return (
        resumed,
        text,
        hs.masterSecret.clone(),
        hs.c.__clientProtocol(),
        hs.c.__didResume(),
    );
}

// go: none — goish-only: pickCertificate and getClientCertificate read
// unexported state. `which`: 0 = a usable Ed25519 certificate,
// 1 = no signature_algorithms, 2 = no certificates configured,
// 3 = usingPSK, 4 = a signature algorithm the certificate cannot use.
// Reports `(errText, sigAlg, a certificate was chosen)`.
#[doc(hidden)]
pub fn handshake_server_tls13_pickCertificate(
    which: crate::types::int,
) -> (crate::gostring::string, crate::gostring::string, bool) {
    let seed = crate::goslice::slice::__from_vec(alloc::vec![7u8; 32]);
    let mut cert = common::Certificate::default();
    cert.PrivateKey = alloc::sync::Arc::new(crate::crypto::ed25519::NewKeyFromSeed(seed));
    cert.Certificate = crate::goslice::slice::__from_vec(alloc::vec![
        crate::goslice::slice::__from_vec(alloc::vec![1u8])
    ]);
    let mut cfg = Config::default();
    if which != 2 && which != 3 {
        cfg.Certificates = crate::goslice::slice::__from_vec(alloc::vec![cert]);
    }
    let mut c = conn::Conn::default();
    c.__setMemConn(alloc::sync::Arc::new(crate::sync::Mutex::new(
        crate::goslice::slice::<crate::types::byte>::new(),
    )));
    c.__setVers(common::VersionTLS13);
    c.__setConfig(cfg);
    let mut ch = handshake_messages::clientHelloMsg::default();
    ch.supportedSignatureAlgorithms = match which {
        1 => alloc::vec![],
        4 => alloc::vec![common::PSSWithSHA256.0],
        _ => alloc::vec![common::Ed25519.0, common::PSSWithSHA256.0],
    };
    let mut hs = handshake_server_tls13::serverHandshakeStateTLS13 {
        c,
        clientHello: ch,
        sentDummyCCS: false,
        usingPSK: which == 3,
        sigAlg: common::SignatureScheme(0),
        cert: None,
    };
    let err = hs.pickCertificate();
    let text = if err == crate::errors::nil {
        crate::gostring::string::from_static("")
    } else {
        err.Error()
    };
    return (text, hs.sigAlg.String(), hs.cert.is_some());
}

// go: none — goish-only: see `handshake_server_tls13_pickCertificate`.
// `which`: 0 = a certificate the CertificateRequestInfo accepts,
// 1 = one it does not, 2 = no certificates configured. Reports
// `(errText, the chosen leaf DER)`.
#[doc(hidden)]
pub fn handshake_client_getClientCertificate(
    which: crate::types::int,
) -> (
    crate::gostring::string,
    crate::goslice::slice<crate::types::byte>,
) {
    let seed = crate::goslice::slice::__from_vec(alloc::vec![7u8; 32]);
    let mut cert = common::Certificate::default();
    cert.PrivateKey = alloc::sync::Arc::new(crate::crypto::ed25519::NewKeyFromSeed(seed));
    cert.Certificate = crate::goslice::slice::__from_vec(alloc::vec![
        crate::goslice::slice::__from_vec(alloc::vec![1u8])
    ]);
    let mut cfg = Config::default();
    if which != 2 {
        cfg.Certificates = crate::goslice::slice::__from_vec(alloc::vec![cert]);
    }
    let mut c = conn::Conn::default();
    c.__setConfig(cfg);
    c.__setVers(common::VersionTLS13);
    let mut cri = common::CertificateRequestInfo::default();
    cri.Version = common::VersionTLS13;
    cri.SignatureSchemes = crate::goslice::slice::__from_vec(if which == 1 {
        alloc::vec![common::PSSWithSHA256]
    } else {
        alloc::vec![common::Ed25519, common::PSSWithSHA256]
    });
    let (got, err) = c.getClientCertificate(&cri);
    let text = if err == crate::errors::nil {
        crate::gostring::string::from_static("")
    } else {
        err.Error()
    };
    let der = if got.Certificate.Len() > 0 {
        got.Certificate[0].clone()
    } else {
        crate::goslice::slice::new()
    };
    return (text, der);
}

// go: none — goish-only: `Conn.readHandshake` and
// `Conn.unmarshalHandshakeMessage` are unexported in Go, where the
// tests are in-package. Feeds one handshake record from an in-memory
// net::Conn and reports `(errText, the concrete message's name, the
// message re-marshalled, the SHA-256 of what the transcript hash was
// fed)`. `which` selects the record; see the assertions.
#[doc(hidden)]
pub fn conn_readHandshake(
    which: crate::types::int,
) -> (
    crate::gostring::string,
    crate::gostring::string,
    crate::goslice::slice<crate::types::byte>,
    crate::goslice::slice<crate::types::byte>,
) {
    use crate::crypto::tls::handshake_messages as hm;
    // A TLS 1.2 handshake record wrapping `body`.
    fn rec(body: &[crate::types::byte]) -> alloc::vec::Vec<crate::types::byte> {
        let n = body.len();
        let mut v: alloc::vec::Vec<crate::types::byte> = alloc::vec![
            0x16u8,
            0x03,
            0x03,
            crate::byte(crate::int(n) >> 8),
            crate::byte(crate::int(n) & 0xff)
        ];
        v.extend_from_slice(body);
        return v;
    }
    let (feed, vers) = match which {
        // serverHelloDoneMsg — four bytes, no body.
        0 => (rec(&[0x0eu8, 0x00, 0x00, 0x00]), common::VersionTLS12),
        // helloRequestMsg.
        1 => (rec(&[0x00u8, 0x00, 0x00, 0x00]), common::VersionTLS12),
        // finishedMsg with a 12-byte verify_data.
        2 => (
            rec(&[
                0x14u8, 0x00, 0x00, 0x0c, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
            ]),
            common::VersionTLS12,
        ),
        // keyUpdateMsg, update_not_requested.
        3 => (rec(&[0x18u8, 0x00, 0x00, 0x01, 0x00]), common::VersionTLS13),
        // typeNewSessionTicket picks by version: TLS 1.2 shape.
        4 => (
            rec(&[0x04u8, 0x00, 0x00, 0x06, 0, 0, 0, 0, 0x00, 0x00]),
            common::VersionTLS12,
        ),
        // Same byte, TLS 1.3 shape.
        5 => (
            rec(&[
                0x04u8, 0x00, 0x00, 0x0d, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]),
            common::VersionTLS13,
        ),
        // An unrecognised handshake type.
        6 => (rec(&[0x63u8, 0x00, 0x00, 0x00]), common::VersionTLS12),
        // A declared length of 65537, one over maxHandshake.
        7 => (rec(&[0x0eu8, 0x01, 0x00, 0x01]), common::VersionTLS12),
        // Well-formed header, body that does not parse: keyUpdate
        // requires a one-byte request_update, and this has none.
        8 => (rec(&[0x18u8, 0x00, 0x00, 0x00]), common::VersionTLS13),
        _ => (alloc::vec![], common::VersionTLS12),
    };

    let mut c = conn::Conn::default();
    c.__setFeedConn(crate::goslice::slice::__from_vec(feed));
    c.__setHaveVers(true);
    c.__setVers(vers);

    let mut h = crate::crypto::sha256::New();
    let (m, err) = c.readHandshake(Some(&mut h));
    let text = if err == crate::errors::nil {
        crate::gostring::string::from_static("")
    } else {
        err.Error()
    };
    let mut name = crate::gostring::string::from_static("");
    let mut remarshalled: crate::goslice::slice<crate::types::byte> =
        crate::goslice::slice::__from_vec(alloc::vec![]);
    if let Some(msg) = m.as_ref() {
        let a = msg.asAny();
        name = if a.is::<hm::serverHelloDoneMsg>() {
            crate::gostring::string::from_static("serverHelloDoneMsg")
        } else if a.is::<hm::helloRequestMsg>() {
            crate::gostring::string::from_static("helloRequestMsg")
        } else if a.is::<hm::finishedMsg>() {
            crate::gostring::string::from_static("finishedMsg")
        } else if a.is::<hm::keyUpdateMsg>() {
            crate::gostring::string::from_static("keyUpdateMsg")
        } else if a.is::<hm::newSessionTicketMsg>() {
            crate::gostring::string::from_static("newSessionTicketMsg")
        } else if a.is::<hm::newSessionTicketMsgTLS13>() {
            crate::gostring::string::from_static("newSessionTicketMsgTLS13")
        } else {
            crate::gostring::string::from_static("?")
        };
        let (b, _) = msg.marshal();
        remarshalled = b;
    }
    let digest = h.Sum(crate::goslice::slice::__from_vec(alloc::vec![]));
    return (text, name, remarshalled, digest);
}

// go: none — goish-only: `transcriptMsg` is unexported in Go, where the
// tests are in-package. Reports `(SHA-256 fed by a clientHelloMsg that
// came off the wire, SHA-256 fed by one that did not)`. The first must
// hash the ORIGINAL bytes, the second the re-marshalled ones.
#[doc(hidden)]
pub fn handshake_messages_transcriptMsg() -> (
    crate::goslice::slice<crate::types::byte>,
    crate::goslice::slice<crate::types::byte>,
    crate::goslice::slice<crate::types::byte>,
) {
    let m = handshake_messages_fullClientHello();
    let (wire, _) = m.marshal();

    // Parsed from the wire: originalBytes() is non-nil, so that is what
    // transcriptMsg hashes.
    let mut parsed = handshake_messages::clientHelloMsg::default();
    parsed.unmarshal(wire.clone());
    let mut h1 = crate::crypto::sha256::New();
    handshake_messages::transcriptMsg(&parsed, &mut h1);
    let d1 = h1.Sum(crate::goslice::slice::__from_vec(alloc::vec![]));

    // Built in memory: originalBytes() is nil, so marshal() is hashed.
    let mut h2 = crate::crypto::sha256::New();
    handshake_messages::transcriptMsg(&m, &mut h2);
    let d2 = h2.Sum(crate::goslice::slice::__from_vec(alloc::vec![]));

    // The reference: SHA-256 over the wire bytes themselves.
    let mut h3 = crate::crypto::sha256::New();
    crate::io::Writer::Write(&mut h3, wire.clone());
    let d3 = h3.Sum(crate::goslice::slice::__from_vec(alloc::vec![]));

    return (d1, d2, d3);
}

// go: none — goish-only: `Conn.writeHandshakeRecord`,
// `Conn.handleKeyUpdate` and `Conn.sessionState` are unexported in Go,
// where the tests are in-package. Reports
// `(writeHandshakeRecord's n, its wire, the transcript digest it fed,
// handleKeyUpdate's errText, the rotated read secret, the rotated write
// secret, the KeyUpdate it wrote)`. `req` is `keyUpdate.updateRequested`.
#[doc(hidden)]
pub fn conn_handshakeRecordAndKeyUpdate(
    req: bool,
) -> (
    crate::types::int,
    crate::goslice::slice<crate::types::byte>,
    crate::goslice::slice<crate::types::byte>,
    crate::gostring::string,
    crate::goslice::slice<crate::types::byte>,
    crate::goslice::slice<crate::types::byte>,
    crate::goslice::slice<crate::types::byte>,
) {
    let sink = alloc::sync::Arc::new(crate::sync::Mutex::new(
        crate::goslice::slice::<crate::types::byte>::new(),
    ));
    let mut c = conn::Conn::default();
    c.__setMemConn(sink.clone());
    c.__setHaveVers(true);
    c.__setVers(common::VersionTLS12);
    let fin = handshake_messages::finishedMsg {
        verifyData: alloc::vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
    };
    let mut h = crate::crypto::sha256::New();
    let (n, _) = c.writeHandshakeRecord(&fin, Some(&mut h));
    let whrWire = sink.Lock().clone();
    let digest = h.Sum(crate::goslice::slice::__from_vec(alloc::vec![]));

    let sink2 = alloc::sync::Arc::new(crate::sync::Mutex::new(
        crate::goslice::slice::<crate::types::byte>::new(),
    ));
    let mut c2 = conn::Conn::default();
    c2.__setMemConn(sink2.clone());
    c2.__setHaveVers(true);
    c2.__setVers(common::VersionTLS13);
    c2.__setCipherSuite(cipher_suites::TLS_AES_128_GCM_SHA256);
    c2.__setTrafficSecrets(
        crate::goslice::slice::__from_vec(alloc::vec![1u8, 2, 3, 4]),
        crate::goslice::slice::__from_vec(alloc::vec![5u8, 6, 7, 8]),
    );
    let ku = handshake_messages::keyUpdateMsg {
        updateRequested: req,
    };
    let err = c2.handleKeyUpdate(&ku);
    let text = if err == crate::errors::nil {
        crate::gostring::string::from_static("")
    } else {
        err.Error()
    };
    let (inSec, outSec) = c2.__trafficSecrets();
    return (n, whrWire, digest, text, inSec, outSec, sink2.Lock().clone());
}

// go: none — goish-only: `Conn.sessionState` is unexported in Go, where
// the tests are in-package. Reports the snapshot's fields.
#[doc(hidden)]
pub fn conn_sessionState() -> (
    crate::types::int,
    crate::types::int,
    crate::gostring::string,
    crate::goslice::slice<crate::types::byte>,
    crate::types::int,
    bool,
    bool,
    crate::types::int,
    bool,
) {
    let mut c = conn::Conn::default();
    c.__setVers(common::VersionTLS13);
    c.__setCipherSuite(cipher_suites::TLS_AES_128_GCM_SHA256);
    c.__setIsClient(true);
    c.__setClientProtocol(crate::gostring::string::from_static("h2"));
    c.__setSessionIdentity(
        crate::gostring::string::from_static("h2"),
        crate::goslice::slice::__from_vec(alloc::vec![9u8, 9]),
        crate::goslice::slice::__from_vec(alloc::vec![
            crate::goslice::slice::__from_vec(alloc::vec![7u8]),
            crate::goslice::slice::__from_vec(alloc::vec![8u8, 8]),
        ]),
        true,
        common::X25519,
    );
    let ss = c.sessionState();
    let now = crate::uint64(crate::time::Now().Unix());
    return (
        crate::int(ss.__version()),
        crate::int(ss.__cipherSuite()),
        ss.__alpnProtocol(),
        ss.__ocspResponse(),
        ss.__scts().Len(),
        ss.__isClientFlag(),
        ss.__extMasterSecret(),
        crate::int(ss.__curveID().0),
        ss.__createdAt() + 2 >= now && ss.__createdAt() <= now + 2,
    );
}

// go: none — goish-only: the shims below build a `clientHandshakeState`
// field by field, the way Go's composite literals do, but goish's
// `finishedHash` holds `Box<dyn Hash>` and so has no zero value. This
// is the neutral stand-in for shims that never touch the transcript.
#[doc(hidden)]
fn __neutralFinishedHash() -> prf::finishedHash {
    return prf::newFinishedHash(
        common::VersionTLS12,
        cipher_suites::cipherSuiteByID(cipher_suites::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
            .unwrap(),
    );
}

// go: none — goish-only: the TLS 1.2 Finished exchange is unexported in
// Go, where the tests are in-package. Drives the four ported methods
// against each other over an in-memory net::Conn with a fixed AES-GCM
// key: the server's `sendFinished` writes the record the client's
// `readFinished` then reads, and vice versa. Reports
// `(server sendFinished errText, its verify_data, its wire,
//   client readFinished errText, its verify_data,
//   client sendFinished errText, its verify_data,
//   server readFinished errText, its verify_data,
//   server readFinished over a corrupted record errText)`.
#[doc(hidden)]
pub fn handshake_finishedExchange() -> (
    crate::gostring::string,
    crate::goslice::slice<crate::types::byte>,
    crate::goslice::slice<crate::types::byte>,
    crate::gostring::string,
    crate::goslice::slice<crate::types::byte>,
    crate::gostring::string,
    crate::goslice::slice<crate::types::byte>,
    crate::gostring::string,
    crate::goslice::slice<crate::types::byte>,
    crate::gostring::string,
) {
    use crate::goslice::slice;
    let master: slice<crate::types::byte> = {
        let mut v: alloc::vec::Vec<crate::types::byte> = alloc::vec::Vec::new();
        let mut i: crate::types::int = 0;
        while i < 48 {
            v.push(crate::byte(i + 1));
            i += 1;
        }
        slice::__from_vec(v)
    };
    let suite = cipher_suites::cipherSuiteByID(cipher_suites::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
        .unwrap();
    let key = || slice::__from_vec(alloc::vec![0u8; 16]);
    let iv = || slice::__from_vec(alloc::vec![0u8; 4]);
    let errText = |e: crate::error| {
        if e == crate::errors::nil {
            crate::gostring::string::from_static("")
        } else {
            e.Error()
        }
    };
    // A Conn whose write half is ready, feeding `feed` on the read side.
    let mkConn = |feed: slice<crate::types::byte>,
                  sink: alloc::sync::Arc<crate::sync::Mutex<slice<crate::types::byte>>>,
                  read: bool| {
        let mut c = conn::Conn::default();
        c.__setMemConn(sink);
        if feed.Len() > 0 {
            c.__setFeedConn(feed);
        }
        c.__setHaveVers(true);
        c.__setVers(common::VersionTLS12);
        c.__setCipherSuite(cipher_suites::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
        let ci = if read {
            conn::halfConnCipher::AEAD((suite.aead.unwrap())(key(), iv()))
        } else {
            conn::halfConnCipher::None
        };
        let co = if read {
            conn::halfConnCipher::None
        } else {
            conn::halfConnCipher::AEAD((suite.aead.unwrap())(key(), iv()))
        };
        c.__prepareCipherSpecs(common::VersionTLS12, ci, None, co, None);
        return c;
    };
    let mkFH = || {
        let mut fh = prf::newFinishedHash(common::VersionTLS12, suite);
        fh.Write(slice::__from_vec(alloc::vec![0x01u8, 0x00, 0x00, 0x00]));
        return fh;
    };
    let newSink = || {
        alloc::sync::Arc::new(crate::sync::Mutex::new(
            slice::<crate::types::byte>::new(),
        ))
    };

    // Server sendFinished.
    let sSink = newSink();
    let mut shs = handshake_server::serverHandshakeState {
        c: mkConn(slice::new(), sSink.clone(), false),
        clientHello: handshake_messages::clientHelloMsg::default(),
        hello: handshake_messages::serverHelloMsg::default(),
        suite: Some(suite),
        finishedHash: mkFH(),
        masterSecret: master.clone(),
        sessionState: None,
        ecdheOk: false,
        ecSignOk: false,
        rsaDecryptOk: false,
        rsaSignOk: false,
    };
    let mut sOut: slice<crate::types::byte> = slice::__from_vec(alloc::vec![0u8; 12]);
    let sErr = errText(shs.sendFinished(&mut sOut));
    let sWire = sSink.Lock().clone();

    // Client readFinished, over exactly those bytes.
    let mut chs = handshake_client::clientHandshakeState {
        c: mkConn(sWire.clone(), newSink(), true),
        serverHello: handshake_messages::serverHelloMsg::default(),
        hello: handshake_messages::clientHelloMsg::default(),
        suite: Some(suite),
        finishedHash: mkFH(),
        masterSecret: master.clone(),
        session: None,
        ticket: slice::new(),
    };
    let mut cRead: slice<crate::types::byte> = slice::__from_vec(alloc::vec![0u8; 12]);
    let cReadErr = errText(chs.readFinished(&mut cRead));

    // Client sendFinished.
    let cSink = newSink();
    let mut chs2 = handshake_client::clientHandshakeState {
        c: mkConn(slice::new(), cSink.clone(), false),
        serverHello: handshake_messages::serverHelloMsg::default(),
        hello: handshake_messages::clientHelloMsg::default(),
        suite: Some(suite),
        finishedHash: mkFH(),
        masterSecret: master.clone(),
        session: None,
        ticket: slice::new(),
    };
    let mut cOut: slice<crate::types::byte> = slice::__from_vec(alloc::vec![0u8; 12]);
    let cErr = errText(chs2.sendFinished(&mut cOut));
    let cWire = cSink.Lock().clone();

    // Server readFinished, over exactly those bytes.
    let mut shs2 = handshake_server::serverHandshakeState {
        c: mkConn(cWire.clone(), newSink(), true),
        clientHello: handshake_messages::clientHelloMsg::default(),
        hello: handshake_messages::serverHelloMsg::default(),
        suite: Some(suite),
        finishedHash: mkFH(),
        masterSecret: master.clone(),
        sessionState: None,
        ecdheOk: false,
        ecSignOk: false,
        rsaDecryptOk: false,
        rsaSignOk: false,
    };
    let mut sRead: slice<crate::types::byte> = slice::__from_vec(alloc::vec![0u8; 12]);
    let sReadErr = errText(shs2.readFinished(&mut sRead));

    // The same record with its last byte flipped must be refused.
    let mut corrupt = cWire.__into_vec();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 0xff;
    let mut shs3 = handshake_server::serverHandshakeState {
        c: mkConn(slice::__from_vec(corrupt), newSink(), true),
        clientHello: handshake_messages::clientHelloMsg::default(),
        hello: handshake_messages::serverHelloMsg::default(),
        suite: Some(suite),
        finishedHash: mkFH(),
        masterSecret: master.clone(),
        sessionState: None,
        ecdheOk: false,
        ecSignOk: false,
        rsaDecryptOk: false,
        rsaSignOk: false,
    };
    let mut junk: slice<crate::types::byte> = slice::__from_vec(alloc::vec![0u8; 12]);
    let corruptErr = errText(shs3.readFinished(&mut junk));

    return (
        sErr, sOut, sWire, cReadErr, cRead, cErr, cOut, sReadErr, sRead, corruptErr,
    );
}

// go: none — goish-only: `clientHandshakeState.readSessionTicket` is
// unexported in Go, where the tests are in-package. `which`: 0 = a
// ticket we asked for, 1 = one we did not, 2 = none offered. Reports
// `(errText, hs.ticket)`.
#[doc(hidden)]
pub fn handshake_client_readSessionTicket(
    which: crate::types::int,
) -> (
    crate::gostring::string,
    crate::goslice::slice<crate::types::byte>,
) {
    use crate::goslice::slice;
    let suite = cipher_suites::cipherSuiteByID(cipher_suites::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
        .unwrap();
    let mut nst = handshake_messages::newSessionTicketMsg::default();
    nst.ticket = slice::__from_vec(alloc::vec![0xaau8, 0xbb, 0xcc]);
    let (body, _) = nst.marshal();
    let mut feed: alloc::vec::Vec<crate::types::byte> = alloc::vec![
        0x16u8,
        0x03,
        0x03,
        crate::byte(body.Len() >> 8),
        crate::byte(body.Len() & 0xff)
    ];
    feed.extend_from_slice(&body);

    let sink = alloc::sync::Arc::new(crate::sync::Mutex::new(
        slice::<crate::types::byte>::new(),
    ));
    let mut c = conn::Conn::default();
    c.__setMemConn(sink);
    c.__setFeedConn(slice::__from_vec(feed));
    c.__setHaveVers(true);
    c.__setVers(common::VersionTLS12);

    let mut serverHello = handshake_messages::serverHelloMsg::default();
    serverHello.ticketSupported = which != 2;
    let mut hello = handshake_messages::clientHelloMsg::default();
    hello.ticketSupported = which == 0;
    let mut hs = handshake_client::clientHandshakeState {
        c,
        serverHello,
        hello,
        suite: Some(suite),
        finishedHash: prf::newFinishedHash(common::VersionTLS12, suite),
        masterSecret: slice::new(),
        session: None,
        ticket: slice::new(),
    };
    let err = hs.readSessionTicket();
    let text = if err == crate::errors::nil {
        crate::gostring::string::from_static("")
    } else {
        err.Error()
    };
    return (text, hs.ticket.clone());
}

// go: none — goish-only: `Conn.verifyServerCertificate` is unexported
// in Go, where the tests are in-package. `which` selects the case; see
// the assertions. Reports `(errText, len(peerCertificates),
// len(verifiedChains))`. The certificate is the self-signed RSA-2048
// leaf `x509_parse_smoke` uses.
#[doc(hidden)]
pub fn handshake_client_verifyServerCertificate(
    which: crate::types::int,
) -> (crate::gostring::string, crate::types::int, crate::types::int) {
    use crate::goslice::slice;
    let der = crate::encoding::base64::StdEncoding.DecodeString(
        "MIIE4DCCA8igAwIBAgIFAQIDBAUwDQYJKoZIhvcNAQELBQAwbDELMAkGA1UEBhMCVEgxEDAOBgNVBAcTB0Jhbmdrb2sxFzAVBgNVBAoTDkdvaXNoIFRlc3QgT3JnMQ4wDAYDVQQLEwVQb3J0czETMBEGA1UEAxMKZ29pc2ggbGVhZjENMAsGA1UEBRMEU04tNzAeFw0yNDAzMDExMjAwMDBaFw0zMzA0MDIxMzE0MTVaMGwxCzAJBgNVBAYTAlRIMRAwDgYDVQQHEwdCYW5na29rMRcwFQYDVQQKEw5Hb2lzaCBUZXN0IE9yZzEOMAwGA1UECxMFUG9ydHMxEzARBgNVBAMTCmdvaXNoIGxlYWYxDTALBgNVBAUTBFNOLTcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDEE3zZMggLiQDVMKhbusFFqr5rE7BxpUMyaL9fCRhQHqKRaqwBHzo7fry6P9/SQmGQehkiS4ciMyhFI8YtYjHqdCT/K0o5Y0kk2gFBzmEWNKRN3J+dxZWYrA5gExmMpQCTdsYUSHG1683Z7a+S1rcLc+rHxhYDswT6HIioJfiF+Mko+27mtCirEJzHe/wA0NzHv6Wk+rQmjA8spQ4azr88duWqrxmh5l6Xcy6l1pnHaOvsIk78JtP7KTTeTvtLKCqdzrRrBKj+ISBj2gXopXJWROUBenJhcyNYROah0woJNrNw0Eq1ILBLBree7hx6rGog90dUn8lGkW7FWVnRgH8tAgMBAAGjggGHMIIBgzAOBgNVHQ8BAf8EBAMCAqQwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMBIGA1UdEwEB/wQIMAYBAf8CAQIwDgYDVR0OBAcEBQECAwQFMGEGCCsGAQUFBwEBBFUwUzAlBggrBgEFBQcwAYYZaHR0cDovL29jc3AuZ29pc2guZXhhbXBsZTAqBggrBgEFBQcwAoYeaHR0cDovL2NhLmdvaXNoLmV4YW1wbGUvY2EuY3J0MF8GA1UdEQRYMFaCDWdvaXNoLmV4YW1wbGWCEXd3dy5nb2lzaC5leGFtcGxlgRJwb3J0QGdvaXNoLmV4YW1wbGWHBMAAAgqGGGh0dHBzOi8vZ29pc2guZXhhbXBsZS9jYTA5BgNVHR4EMjAwoB0wD4INZ29pc2guZXhhbXBsZTAKhwgKAAAA/wAAAKEPMA2CC2JhZC5leGFtcGxlMC8GA1UdHwQoMCYwJKAioCCGHmh0dHA6Ly9jcmwuZ29pc2guZXhhbXBsZS94LmNybDANBgkqhkiG9w0BAQsFAAOCAQEAdIYb7TNaVRqsSMoVfCf+IcCmKjZaKJfIkxrOpupQZK205mzX+/w3szqUl/EUFhFrmqWCBAgntuZ7VZDNXF9KBrNjNwbCkV8EkP/uyNDzr0PYuutfhEY7V7GbJX4aUU+i+unHbTEcPbQjoVTWg6DVUUihnejtkee3b88GaRQFWhWy1GgwUPLe3xx2UEsok7bcBfFOzsOwyU8jcdl6YXQca37j974lL9Ej/C6lnO+ilk45+T08TVx3YQCmQGJWXYmmUQOL7WYZOPXEhreogZrVDGi8Uw80/fjU2zWB58JCMly/pK9s3yGcYqYSmDZfZZ3PR4appnTEXHCBV6AYRr1Nlw==",
    );
    let der = der.0;
    let (leaf, _) = crate::crypto::x509::ParseCertificate(der.clone());

    let sink = alloc::sync::Arc::new(crate::sync::Mutex::new(slice::<crate::types::byte>::new()));
    let mut c = conn::Conn::default();
    c.__setMemConn(sink);
    c.__setHaveVers(true);
    c.__setVers(common::VersionTLS12);
    c.__setIsClient(true);

    let mut cfg = Config::default();
    let mut pool = crate::crypto::x509::NewCertPool();
    pool.AddCert(leaf);
    match which {
        // Verification waived: the chain is adopted unverified.
        0 => cfg.InsecureSkipVerify = true,
        // Bytes that are not a certificate at all.
        1 => cfg.InsecureSkipVerify = true,
        // Verified against the empty default root set.
        2 => cfg.ServerName = crate::gostring::string::from_static("goish.example"),
        // Verified against the leaf itself, which is self-signed.
        3 => {
            cfg.ServerName = crate::gostring::string::from_static("goish.example");
            cfg.RootCAs = Some(pool);
        }
        // A name the certificate does not cover.
        4 => {
            cfg.ServerName = crate::gostring::string::from_static("nope.example");
            cfg.RootCAs = Some(pool);
        }
        // The two config callbacks, each refusing.
        5 => {
            cfg.InsecureSkipVerify = true;
            cfg.VerifyPeerCertificate = Some(alloc::sync::Arc::new(|_raw, _chains| {
                return crate::errors::New("tls: refused by VerifyPeerCertificate");
            }));
        }
        _ => {
            cfg.InsecureSkipVerify = true;
            cfg.VerifyConnection = Some(alloc::sync::Arc::new(|cs: common::ConnectionState| {
                return crate::fmt::Errorf!(
                    "tls: refused by VerifyConnection, version %04x",
                    cs.Version
                );
            }));
        }
    }
    c.__setConfig(cfg);

    let chain: slice<slice<crate::types::byte>> = if which == 1 {
        slice::__from_vec(alloc::vec![slice::__from_vec(alloc::vec![1u8, 2, 3])])
    } else {
        slice::__from_vec(alloc::vec![der])
    };
    let err = c.verifyServerCertificate(chain);
    let text = if err == crate::errors::nil {
        crate::gostring::string::from_static("")
    } else {
        err.Error()
    };
    return (text, c.__peerCertificateCount(), c.__verifiedChainCount());
}

// go: none — goish-only: a ClientSessionCache that records what was
// last Put into a handle the caller also holds, so the shim below can
// report it. Go's reference test uses an in-package struct for the same
// purpose; goish needs the shared handle because Config stores the
// cache behind `Box<dyn ClientSessionCache>`, which cannot be
// downcast back to a concrete type.
#[doc(hidden)]
#[derive(Default, Clone)]
pub struct __sessionCacheRecord {
    pub key: crate::gostring::string,
    pub cs: Option<ticket::ClientSessionState>,
    pub n: crate::types::int,
}

#[doc(hidden)]
pub struct __capturingSessionCache(
    pub alloc::sync::Arc<crate::sync::Mutex<__sessionCacheRecord>>,
);

impl common::ClientSessionCache for __capturingSessionCache {
    // go: none — goish-only: the recording cache never serves a hit.
    fn Get(
        &mut self,
        _sessionKey: crate::gostring::string,
    ) -> (Option<ticket::ClientSessionState>, bool) {
        return (None, false);
    }
    // go: none — goish-only: records what was Put for the shim to read.
    fn Put(
        &mut self,
        sessionKey: crate::gostring::string,
        cs: Option<ticket::ClientSessionState>,
    ) {
        let mut r = self.0.Lock();
        r.key = sessionKey;
        r.cs = cs;
        r.n += 1;
    }
}

// go: none — goish-only: `clientHandshakeState.saveSessionTicket` is
// unexported in Go, where the tests are in-package. `which`: 0 = a
// ticket and a cache key, 1 = no ticket, 2 = no cache key. Reports
// `(errText, Put count, key, cached secret, cached ticket, cached
// version)`.
#[doc(hidden)]
pub fn handshake_client_saveSessionTicket(
    which: crate::types::int,
) -> (
    crate::gostring::string,
    crate::types::int,
    crate::gostring::string,
    crate::goslice::slice<crate::types::byte>,
    crate::goslice::slice<crate::types::byte>,
    crate::types::int,
) {
    use crate::goslice::slice;
    let master: slice<crate::types::byte> = {
        let mut v: alloc::vec::Vec<crate::types::byte> = alloc::vec::Vec::new();
        let mut i: crate::types::int = 0;
        while i < 48 {
            v.push(crate::byte(i + 1));
            i += 1;
        }
        slice::__from_vec(v)
    };
    let record = alloc::sync::Arc::new(crate::sync::Mutex::new(__sessionCacheRecord::default()));
    let cache: alloc::sync::Arc<
        crate::sync::Mutex<alloc::boxed::Box<dyn common::ClientSessionCache>>,
    > = alloc::sync::Arc::new(crate::sync::Mutex::new(alloc::boxed::Box::new(
        __capturingSessionCache(record.clone()),
    )));

    let mut cfg = Config::default();
    cfg.ServerName = if which == 2 {
        crate::gostring::string::from_static("")
    } else {
        crate::gostring::string::from_static("goish.example")
    };
    cfg.ClientSessionCache = Some(cache);

    let mut c = conn::Conn::default();
    c.__setConfig(cfg);
    c.__setVers(common::VersionTLS12);
    c.__setCipherSuite(cipher_suites::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
    c.__setIsClient(true);

    let suite = cipher_suites::cipherSuiteByID(cipher_suites::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
        .unwrap();
    let mut hs = handshake_client::clientHandshakeState {
        c,
        serverHello: handshake_messages::serverHelloMsg::default(),
        hello: handshake_messages::clientHelloMsg::default(),
        suite: Some(suite),
        finishedHash: prf::newFinishedHash(common::VersionTLS12, suite),
        masterSecret: master,
        session: None,
        ticket: if which == 1 {
            slice::new()
        } else if which == 2 {
            slice::__from_vec(alloc::vec![0xaau8])
        } else {
            slice::__from_vec(alloc::vec![0xaau8, 0xbb, 0xcc])
        },
    };
    let err = hs.saveSessionTicket();
    let text = if err == crate::errors::nil {
        crate::gostring::string::from_static("")
    } else {
        err.Error()
    };

    let r = record.Lock().clone();
    let empty = slice::<crate::types::byte>::new();
    let (secret, tkt, vers) = match r.cs.as_ref().and_then(|s| s.__session()) {
        Some(s) => (s.__secret(), s.__ticket(), crate::int(s.__version())),
        None => (empty.clone(), empty, 0),
    };
    return (text, r.n, r.key.clone(), secret, tkt, vers);
}

// go: none — goish-only: `clientHandshakeStateTLS13`'s methods are
// unexported in Go, where the tests are in-package. Builds a valid
// TLS 1.3 ServerHello/ClientHello pair, applies the tweak `which`
// selects, and reports `(errText, hs.suite.id, c.cipherSuite)`. See the
// assertions for what each `which` is.
#[doc(hidden)]
pub fn handshake_client_tls13_checkServerHelloOrHRR(
    which: crate::types::int,
) -> (crate::gostring::string, crate::types::int, crate::types::int) {
    let mut hs = __chs13(which >= 100);
    match which {
        1 => hs.serverHello.supportedVersion = 0,
        2 => hs.serverHello.supportedVersion = common::VersionTLS12,
        3 => hs.serverHello.vers = common::VersionTLS13,
        4 => hs.serverHello.ticketSupported = true,
        5 => hs.serverHello.sessionId = alloc::vec![9u8, 9],
        6 => hs.serverHello.compressionMethod = 1,
        7 => {
            hs.suite = cipher_suites::cipherSuiteTLS13ByID(cipher_suites::TLS_AES_256_GCM_SHA384)
        }
        8 => hs.hello.cipherSuites = alloc::vec![cipher_suites::TLS_AES_256_GCM_SHA384],
        _ => {}
    }
    let err = hs.checkServerHelloOrHRR();
    let text = if err == crate::errors::nil {
        crate::gostring::string::from_static("")
    } else {
        err.Error()
    };
    let id = match hs.suite {
        Some(s) => crate::int(s.id),
        None => 0,
    };
    return (text, id, crate::int(hs.c.__cipherSuite()));
}

// go: none — goish-only: see `handshake_client_tls13_checkServerHelloOrHRR`.
// Reports `(first errText, second errText, wire after the first call,
// wire after the second, hs.sentDummyCCS)`.
#[doc(hidden)]
pub fn handshake_client_tls13_sendDummyChangeCipherSpec() -> (
    crate::gostring::string,
    crate::gostring::string,
    crate::goslice::slice<crate::types::byte>,
    crate::goslice::slice<crate::types::byte>,
    bool,
) {
    let sink = alloc::sync::Arc::new(crate::sync::Mutex::new(
        crate::goslice::slice::<crate::types::byte>::new(),
    ));
    let mut hs = __chs13(false);
    hs.c.__setMemConn(sink.clone());
    let e1 = hs.sendDummyChangeCipherSpec();
    let first = sink.Lock().clone();
    let e2 = hs.sendDummyChangeCipherSpec();
    let t = |e: crate::error| {
        if e == crate::errors::nil {
            crate::gostring::string::from_static("")
        } else {
            e.Error()
        }
    };
    return (t(e1), t(e2), first, sink.Lock().clone(), hs.sentDummyCCS);
}

// go: none — goish-only: see `handshake_client_tls13_checkServerHelloOrHRR`.
// Reports `(errText, hs.usingPSK, c.didResume, len(c.ocspResponse))`.
#[doc(hidden)]
pub fn handshake_client_tls13_processServerHello(
    which: crate::types::int,
) -> (crate::gostring::string, bool, bool, crate::types::int) {
    let mut hs = __chs13(false);
    hs.suite = cipher_suites::cipherSuiteTLS13ByID(cipher_suites::TLS_AES_128_GCM_SHA256);
    match which {
        1 => hs.serverHello.random = common::helloRetryRequestRandom.to_vec(),
        2 => hs.serverHello.cookie = alloc::vec![1u8],
        3 => hs.serverHello.selectedGroup = common::X25519.0,
        4 => hs.serverHello.serverShare = handshake_messages::keyShare::default(),
        5 => hs.serverHello.serverShare.group = common::CurveP256.0,
        6 => {
            hs.serverHello.selectedIdentityPresent = true;
            hs.serverHello.selectedIdentity = 3;
        }
        7 => {
            hs.serverHello.selectedIdentityPresent = true;
            hs.hello.pskIdentities = alloc::vec![handshake_messages::pskIdentity::default()];
            let mut ss = ticket::SessionState::default();
            ss.__setCipherSuite(cipher_suites::TLS_AES_128_GCM_SHA256);
            ss.__setOcspResponse(crate::goslice::slice::__from_vec(alloc::vec![7u8, 7]));
            hs.session = Some(ss);
        }
        8 => {
            hs.serverHello.selectedIdentityPresent = true;
            hs.hello.pskIdentities = alloc::vec![handshake_messages::pskIdentity::default()];
            let mut ss = ticket::SessionState::default();
            ss.__setCipherSuite(cipher_suites::TLS_AES_256_GCM_SHA384);
            hs.session = Some(ss);
        }
        _ => {}
    }
    let err = hs.processServerHello();
    let text = if err == crate::errors::nil {
        crate::gostring::string::from_static("")
    } else {
        err.Error()
    };
    return (
        text,
        hs.usingPSK,
        hs.c.__didResume(),
        hs.c.__ocspResponseLen(),
    );
}

// go: none — goish-only: the valid TLS 1.3 ServerHello/ClientHello pair
// the three shims above start from.
#[doc(hidden)]
fn __chs13(_unused: bool) -> handshake_client_tls13::clientHandshakeStateTLS13 {
    let sink = alloc::sync::Arc::new(crate::sync::Mutex::new(
        crate::goslice::slice::<crate::types::byte>::new(),
    ));
    let mut c = conn::Conn::default();
    c.__setMemConn(sink);
    c.__setHaveVers(true);
    c.__setVers(common::VersionTLS13);
    c.__setIsClient(true);

    let mut sh = handshake_messages::serverHelloMsg::default();
    sh.vers = common::VersionTLS12;
    sh.supportedVersion = common::VersionTLS13;
    sh.sessionId = alloc::vec![1u8, 2, 3];
    sh.cipherSuite = cipher_suites::TLS_AES_128_GCM_SHA256;
    sh.compressionMethod = common::compressionNone;
    sh.random = alloc::vec![0u8; 32];
    sh.serverShare = handshake_messages::keyShare {
        group: common::X25519.0,
        data: alloc::vec![9u8],
    };

    let mut ch = handshake_messages::clientHelloMsg::default();
    ch.sessionId = alloc::vec![1u8, 2, 3];
    ch.cipherSuites = alloc::vec![cipher_suites::TLS_AES_128_GCM_SHA256];
    ch.keyShares = alloc::vec![handshake_messages::keyShare {
        group: common::X25519.0,
        data: alloc::vec![8u8],
    }];

    return handshake_client_tls13::clientHandshakeStateTLS13 {
        c,
        serverHello: sh,
        hello: ch,
        session: None,
        usingPSK: false,
        sentDummyCCS: false,
        suite: None,
        transcript: None,
        masterSecret: None,
        trafficSecret: crate::goslice::slice::new(),
        echContext: None,
    };
}

// go: none — goish-only: `clientHandshakeStateTLS13.readServerFinished`
// and `.sendClientFinished` are unexported in Go, where the tests are
// in-package. Both are driven off the same fixed key schedule the
// reference test uses: an all-zero PSK, a 1..32 shared secret, and a
// transcript seeded with one four-byte message. `which`: 0 = the
// server's real Finished, 1 = a wrong one, 2 = sendClientFinished with
// no session cache, 3 = with one. Reports `(errText, the expected
// server MAC, hs.trafficSecret, c.in.trafficSecret, the wire,
// c.out.trafficSecret, c.resumptionSecret, c.ekm was set)`.
#[doc(hidden)]
pub fn handshake_client_tls13_finished(
    which: crate::types::int,
) -> (
    crate::gostring::string,
    crate::goslice::slice<crate::types::byte>,
    crate::goslice::slice<crate::types::byte>,
    crate::goslice::slice<crate::types::byte>,
    crate::goslice::slice<crate::types::byte>,
    crate::goslice::slice<crate::types::byte>,
    crate::goslice::slice<crate::types::byte>,
    bool,
) {
    use crate::crypto::internal::fips140::tls13;
    use crate::goslice::slice;
    let suite = cipher_suites::cipherSuiteTLS13ByID(cipher_suites::TLS_AES_128_GCM_SHA256).unwrap();
    let mkState = |feed: slice<crate::types::byte>,
                   sink: alloc::sync::Arc<crate::sync::Mutex<slice<crate::types::byte>>>| {
        let shared: slice<crate::types::byte> = {
            let mut v: alloc::vec::Vec<crate::types::byte> = alloc::vec::Vec::new();
            let mut i: crate::types::int = 0;
            while i < 32 {
                v.push(crate::byte(i + 1));
                i += 1;
            }
            slice::__from_vec(v)
        };
        let hf = crate::hash::HashFunc::New(move || crate::crypto::SHA256.New());
        let es = tls13::NewEarlySecret(hf, slice::new());
        let master = es.HandshakeSecret(shared).MasterSecret();

        let mut transcript = crate::crypto::sha256::New();
        crate::io::Writer::Write(
            &mut transcript,
            slice::__from_vec(alloc::vec![0x01u8, 0x00, 0x00, 0x00]),
        );

        let mut c = conn::Conn::default();
        c.__setMemConn(sink);
        if feed.Len() > 0 {
            c.__setFeedConn(feed);
        }
        c.__setHaveVers(true);
        c.__setVers(common::VersionTLS13);
        c.__setIsClient(true);
        c.__setCipherSuite(cipher_suites::TLS_AES_128_GCM_SHA256);
        c.__setTrafficSecrets(
            slice::__from_vec(alloc::vec![1u8, 2, 3, 4]),
            slice::__from_vec(alloc::vec![5u8, 6, 7, 8]),
        );

        let mut ch = handshake_messages::clientHelloMsg::default();
        ch.random = alloc::vec![0u8; 32];
        return handshake_client_tls13::clientHandshakeStateTLS13 {
            c,
            serverHello: handshake_messages::serverHelloMsg::default(),
            hello: ch,
            session: None,
            usingPSK: false,
            sentDummyCCS: false,
            suite: Some(suite),
            transcript: Some(handshake_messages::transcriptHasher(alloc::boxed::Box::new(
                transcript,
            ))),
            masterSecret: Some(master),
            trafficSecret: slice::new(),
            echContext: None,
        };
    };
    let newSink = || {
        alloc::sync::Arc::new(crate::sync::Mutex::new(
            slice::<crate::types::byte>::new(),
        ))
    };

    // The verify_data the client expects from the server.
    let probe = mkState(slice::new(), newSink());
    let expected = suite.finishedHash(
        probe.c.__inTrafficSecretOf(),
        &*probe.transcript.as_ref().unwrap().0,
    );

    let rec = |body: slice<crate::types::byte>| {
        let mut v: alloc::vec::Vec<crate::types::byte> = alloc::vec![
            0x16u8,
            0x03,
            0x03,
            crate::byte(body.Len() >> 8),
            crate::byte(body.Len() & 0xff)
        ];
        v.extend_from_slice(&body);
        return slice::__from_vec(v);
    };

    let empty = slice::<crate::types::byte>::new();
    if which <= 1 {
        let verifyData = if which == 0 {
            expected.clone().__into_vec()
        } else {
            alloc::vec![9u8; 32]
        };
        let fin = handshake_messages::finishedMsg { verifyData };
        let (body, _) = fin.marshal();
        let mut hs = mkState(rec(body), newSink());
        let err = hs.readServerFinished();
        let text = if err == crate::errors::nil {
            crate::gostring::string::from_static("")
        } else {
            err.Error()
        };
        let (inSec, _) = hs.c.__trafficSecrets();
        return (
            text,
            expected,
            hs.trafficSecret.clone(),
            inSec,
            empty.clone(),
            empty.clone(),
            empty,
            hs.c.__hasEkm(),
        );
    }

    let sink = newSink();
    let mut hs = mkState(slice::new(), sink.clone());
    hs.trafficSecret = slice::__from_vec(alloc::vec![0xaau8, 0xbb, 0xcc, 0xdd]);
    if which == 3 {
        let mut cfg = hs.c.__config();
        cfg.ClientSessionCache = Some(alloc::sync::Arc::new(crate::sync::Mutex::new(
            alloc::boxed::Box::new(common::NewLRUClientSessionCache(4)),
        )));
        hs.c.__setConfig(cfg);
    }
    let err = hs.sendClientFinished();
    let text = if err == crate::errors::nil {
        crate::gostring::string::from_static("")
    } else {
        err.Error()
    };
    let (_, outSec) = hs.c.__trafficSecrets();
    return (
        text,
        expected,
        empty.clone(),
        empty,
        sink.Lock().clone(),
        outSec,
        hs.c.__resumptionSecret(),
        hs.c.__hasEkm(),
    );
}

// go: none — goish-only: `clientHandshakeStateTLS13.readServerParameters`
// is unexported in Go, where the tests are in-package. Feeds one
// EncryptedExtensions record and reports `(errText, c.clientProtocol,
// hs.echContext.retryConfigs)`. `which` selects the case; see the
// assertions.
#[doc(hidden)]
pub fn handshake_client_tls13_readServerParameters(
    which: crate::types::int,
) -> (
    crate::gostring::string,
    crate::gostring::string,
    crate::goslice::slice<crate::types::byte>,
) {
    use crate::goslice::slice;
    let mut ee = handshake_messages::encryptedExtensionsMsg::default();
    match which {
        1 | 3 | 8 => ee.alpnProtocol = "h2".into(),
        2 => ee.alpnProtocol = "spdy".into(),
        4 => ee.quicTransportParameters = alloc::vec![1u8, 2],
        9 => ee.echRetryConfigs = alloc::vec![7u8, 7, 7],
        10 => ee.echRetryConfigs = alloc::vec![7u8],
        _ => {}
    }
    if which == 5 || which == 6 || which == 7 || which == 8 {
        ee.earlyData = true;
    }
    let (body, _) = ee.marshal();
    let mut feed: alloc::vec::Vec<crate::types::byte> = alloc::vec![
        0x16u8,
        0x03,
        0x03,
        crate::byte(body.Len() >> 8),
        crate::byte(body.Len() & 0xff)
    ];
    feed.extend_from_slice(&body);

    let mut c = conn::Conn::default();
    c.__setMemConn(alloc::sync::Arc::new(crate::sync::Mutex::new(
        slice::<crate::types::byte>::new(),
    )));
    c.__setFeedConn(slice::__from_vec(feed));
    c.__setHaveVers(true);
    c.__setVers(common::VersionTLS13);
    c.__setIsClient(true);
    c.__setCipherSuite(cipher_suites::TLS_AES_128_GCM_SHA256);

    let mut hello = handshake_messages::clientHelloMsg::default();
    match which {
        1 => {
            hello.alpnProtocols = alloc::vec![
                "h2".into(),
                "http/1.1".into()
            ]
        }
        2 => hello.alpnProtocols = alloc::vec!["h2".into()],
        8 => hello.alpnProtocols = alloc::vec!["h2".into()],
        _ => {}
    }
    if which == 6 || which == 7 || which == 8 {
        hello.earlyData = true;
    }

    let mut session: Option<ticket::SessionState> = None;
    if which == 6 || which == 7 || which == 8 {
        let mut ss = ticket::SessionState::default();
        ss.__setCipherSuite(if which == 7 {
            cipher_suites::TLS_AES_256_GCM_SHA384
        } else {
            cipher_suites::TLS_AES_128_GCM_SHA256
        });
        if which == 8 {
            ss.__setAlpnProtocol(crate::gostring::string::from_static("nope"));
        }
        session = Some(ss);
    }
    let echContext = match which {
        9 => Some(handshake_client::echClientContext {
            echRejected: true,
            retryConfigs: slice::new(),
        }),
        10 => Some(handshake_client::echClientContext::default()),
        _ => None,
    };

    let mut hs = handshake_client_tls13::clientHandshakeStateTLS13 {
        c,
        serverHello: handshake_messages::serverHelloMsg::default(),
        hello,
        session,
        usingPSK: false,
        sentDummyCCS: false,
        suite: cipher_suites::cipherSuiteTLS13ByID(cipher_suites::TLS_AES_128_GCM_SHA256),
        transcript: Some(handshake_messages::transcriptHasher(alloc::boxed::Box::new(
            crate::crypto::sha256::New(),
        ))),
        masterSecret: None,
        trafficSecret: slice::new(),
        echContext,
    };
    let err = hs.readServerParameters();
    let text = if err == crate::errors::nil {
        crate::gostring::string::from_static("")
    } else {
        err.Error()
    };
    let retry = match hs.echContext.as_ref() {
        Some(e) => e.retryConfigs.clone(),
        None => slice::new(),
    };
    return (text, hs.c.__clientProtocol(), retry);
}

// go: none — goish-only: `encryptedExtensionsMsg` is unexported in Go,
// where the tests are in-package. Marshals one with every field set and
// unmarshals it back. Reports `(wire, round-trip ok, alpn, quic
// transport parameters, earlyData, ech retry configs, serverNameAck)`.
#[doc(hidden)]
pub fn handshake_messages_encryptedExtensionsRoundTrip() -> (
    crate::goslice::slice<crate::types::byte>,
    bool,
    crate::gostring::string,
    crate::goslice::slice<crate::types::byte>,
    bool,
    crate::goslice::slice<crate::types::byte>,
    bool,
) {
    let mut ee = handshake_messages::encryptedExtensionsMsg::default();
    ee.alpnProtocol = "h2".into();
    ee.quicTransportParameters = alloc::vec![1u8, 2, 3];
    ee.earlyData = true;
    ee.echRetryConfigs = alloc::vec![7u8, 7, 7];
    ee.serverNameAck = true;
    let (wire, _) = ee.marshal();
    let mut r = handshake_messages::encryptedExtensionsMsg::default();
    let ok = r.unmarshal(wire.clone());
    return (
        wire,
        ok,
        crate::gostring::string::from_bytes(r.alpnProtocol.as_bytes()),
        crate::goslice::slice::__from_vec(r.quicTransportParameters.clone()),
        r.earlyData,
        crate::goslice::slice::__from_vec(r.echRetryConfigs.clone()),
        r.serverNameAck,
    );
}
