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
pub mod common;
pub mod common_string;
pub mod defaults;
pub mod prf;

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
    /// Certificates contains one or more certificate chains to present
    /// to the other side of the connection (server side). The first
    /// entry is used; SNI-based selection (`GetCertificate`) is not
    /// wired yet. Reference: common.go:570.
    pub Certificates: slice<Certificate>,
    /// NextProtos is a list of supported application level protocols,
    /// in order of preference (ALPN). Reference: common.go:604.
    pub NextProtos: slice<string>,
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
                                        let state = session::ClientSessionState {
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

/// `tls.Certificate` (common.go:1553) — a chain of one or more
/// certificates, leaf first, plus the leaf's private key.
#[derive(Clone)]
pub struct Certificate {
    /// Certificate contains a chain of one or more certificates,
    /// leaf first, in DER form.
    pub Certificate: slice<slice<byte>>,
    /// `crypto.PrivateKey` — the leaf certificate's private key.
    /// Supported concrete types: `rsa::PrivateKey`, `ed25519::PrivateKey`.
    pub PrivateKey: crate::crypto::PrivateKey,
}

impl Default for Certificate {
    fn default() -> Self {
        Certificate {
            Certificate: slice::<slice<byte>>::new(),
            // Unit sentinel — downcasts to no key type, so a
            // default-constructed Certificate fails the handshake with
            // a clean "unsupported private key type" error.
            PrivateKey: Arc::new(()),
        }
    }
}

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
