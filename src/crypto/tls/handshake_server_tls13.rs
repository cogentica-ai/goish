// crypto/tls/handshake_server_tls13.rs — TLS 1.3 server handshake.
//
// goishlint:ignore GOISH018 processClientHello — serverHandshakeStateTLS13's Conn-driven half; the live server below the divider implements the same protocol by hand. See ROADMAP.md.
//
// Port of Go 1.25.5 crypto/tls:
//   handshake_server.go       readClientHello (:134), negotiateALPN (:334)
//   handshake_server_tls13.go serverHandshakeStateTLS13.handshake (:66),
//     processClientHello (:105), pickCertificate (:502),
//     sendDummyChangeCipherSpec (:535), sendServerParameters (:735),
//     sendServerCertificate (:851), sendServerFinished (:906),
//     sendSessionTickets clientFinished precompute (:973),
//     readClientFinished (:1139)
//   auth.go                   signatureSchemesForPublicKey (:167),
//     selectSignatureScheme (:208), signedMessage via
//     tls13_signed_message (shared with the client verifier)
//
// Scope (documented deferrals, mirroring the M32 plan):
//   - TLS 1.3 only. A client whose supported_versions lacks 0x0304 is
//     rejected with a protocol_version alert (no TLS 1.2 server driver).
//   - X25519 ECDHE only; a client that advertises X25519 support but
//     sent no X25519 key_share would need a HelloRetryRequest, which
//     is not implemented — the handshake aborts instead. Every
//     mainstream client (Go, OpenSSL/curl, rustls, browsers) sends an
//     X25519 share in its first flight.
//   - No PSK resumption / session tickets (checkForResumption,
//     sendSessionTickets are omitted; clients do a full handshake
//     every time).
//   - No client certificates (ClientAuth == NoClientCert only).
//   - Certificates: RSA (PSS signatures) and Ed25519. ECDSA signing
//     needs ecdsa::SignASN1 which Goish does not have yet.
//
// The handshake flow (RFC 8446, Section 2):
//   Client → Server: ClientHello                        (plaintext)
//   Server → Client: ServerHello                        (plaintext)
//   Server → Client: [CCS] {EncryptedExtensions}
//                    {Certificate} {CertificateVerify}
//                    {Finished}          (server_handshake_traffic keys)
//   Client → Server: [CCS] {Finished}    (client_handshake_traffic keys)
//   Both sides switch to application_traffic keys.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use alloc::vec::Vec;

use crate::crypto::ecdh;
use crate::crypto::tls::handshake_client_tls13::{
    tls13_encrypt_record_suite, tls13_signed_message, Tls13HandshakeReader,
};
use crate::crypto::tls::handshake_messages::{
    certificateMsgTLS13, certificateVerifyMsg, clientHelloMsg, compressionNone,
    encryptedExtensionsMsg, finishedMsg, serverHelloMsg, keyShare, typeClientHello, typeFinished,
};
use crate::crypto::tls::key_schedule::{
    self, cipher_suite_tls13, finished_hash, traffic_keys, CipherSuiteTls13,
};
use crate::crypto::tls::record::{
    encode_record, read_record, KeyMaterial, RECORD_ALERT, RECORD_CHANGE_CIPHER_SPEC,
    RECORD_HANDSHAKE,
};
use crate::errors::{self, error};
use crate::goslice::slice;
use crate::types::byte;

// ─── TLS alerts (alert.go:23) ───────────────────────────────────────

const alertUnexpectedMessage: byte = 10;
const alertHandshakeFailure: byte = 40;
const alertIllegalParameter: byte = 47;
const alertDecodeError: byte = 50;
const alertDecryptError: byte = 51;
const alertProtocolVersion: byte = 70;
const alertInternalError: byte = 80;
const alertUnsupportedExtension: byte = 110;
const alertUnrecognizedName: byte = 112;
const alertNoApplicationProtocol: byte = 120;
const alertMissingExtension: byte = 109;

/// `c.sendAlert(desc)` — write a fatal alert record. Goish sends
/// alerts in plaintext even after the handshake keys are established
/// (Go encrypts them once possible); receivers treat any alert record
/// as fatal either way, so interop is unaffected.
fn send_alert(conn: &mut dyn crate::net::Conn, desc: byte) {
    // level=2 (fatal), description.
    let rec = encode_record(RECORD_ALERT, &[2u8, desc]);
    let _ = conn.Write(rec);
}

// ─── SignatureScheme values (common.go:1466, RFC 8446 §4.2.3) ───────

const PSSWithSHA256: u16 = 0x0804;
const PSSWithSHA384: u16 = 0x0805;
const PSSWithSHA512: u16 = 0x0806;
const Ed25519: u16 = 0x0807;

// CurveID values (common.go:186).
const X25519: u16 = 29;

// TLS 1.3 cipher suite server preference (cipher_suites.go
// defaultCipherSuitesTLS13).
const defaultCipherSuitesTLS13: [u16; 3] = [
    key_schedule::TLS_AES_128_GCM_SHA256,
    key_schedule::TLS_AES_256_GCM_SHA384,
    key_schedule::TLS_CHACHA20_POLY1305_SHA256,
];

// ─── Server private key ─────────────────────────────────────────────

/// The certificate private key, downcast from the `crypto.PrivateKey`
/// carried in `tls::Certificate`. Mirrors the `crypto.Signer`
/// dispatch in Go's sendServerCertificate.
pub(crate) enum ServerPrivateKey {
    Rsa(crate::crypto::rsa::PrivateKey),
    Ed25519(crate::crypto::ed25519::PrivateKey),
}

/// `signatureSchemesForPublicKey` (auth.go:167), restricted to the
/// key types the Goish server can sign with. RSA keys get the PSS
/// schemes only — TLS 1.3 forbids PKCS#1 v1.5 in CertificateVerify
/// (Go filters those via isDisabledSignatureAlgorithm).
fn signature_schemes_for_private_key(key: &ServerPrivateKey) -> &'static [u16] {
    match key {
        ServerPrivateKey::Rsa(_) => &[PSSWithSHA256, PSSWithSHA384, PSSWithSHA512],
        ServerPrivateKey::Ed25519(_) => &[Ed25519],
    }
}

/// `selectSignatureScheme` (auth.go:208) — pick from the peer's
/// preference list, as our preference order is not configurable.
fn select_signature_scheme(key: &ServerPrivateKey, peer_algs: &[u16]) -> Option<u16> {
    let supported = signature_schemes_for_private_key(key);
    for preferred in peer_algs.iter() {
        if supported.contains(preferred) {
            return Some(*preferred);
        }
    }
    None
}

/// `negotiateALPN(serverProtos, clientProtos, quic=false)` —
/// handshake_server.go:334.
pub(crate) fn negotiate_alpn(
    server_protos: &[alloc::string::String],
    client_protos: &[alloc::string::String],
) -> Result<alloc::string::String, error> {
    if server_protos.is_empty() || client_protos.is_empty() {
        return Ok(alloc::string::String::new());
    }
    let mut http11fallback = false;
    for s in server_protos.iter() {
        for c in client_protos.iter() {
            if s == c {
                return Ok(s.clone());
            }
            if s == "h2" && c == "http/1.1" {
                http11fallback = true;
            }
        }
    }
    // As a special case, let http/1.1 clients connect to h2 servers as
    // if they didn't support ALPN. See Go issue 46310.
    if http11fallback {
        return Ok(alloc::string::String::new());
    }
    Err(errors::New(
        "tls: client requested unsupported application protocols",
    ))
}

// ─── ClientHello reader ─────────────────────────────────────────────

/// Read the plaintext ClientHello handshake message from the wire.
/// TLS permits handshake messages to span records; buffer plaintext
/// handshake fragments until one complete message is available
/// (Go: c.readHandshake via the c.hand buffer).
fn read_client_hello_bytes(conn: &mut dyn crate::net::Conn) -> (Vec<byte>, error) {
    struct ConnReader<'a>(&'a mut dyn crate::net::Conn);
    impl<'a> crate::io::Reader for ConnReader<'a> {
        fn Read(&mut self, p: &mut slice<byte>) -> (crate::types::int, error) {
            self.0.Read(p)
        }
    }

    let mut buf: Vec<byte> = Vec::new();
    loop {
        if buf.len() >= 4 {
            let msg_len =
                ((buf[1] as usize) << 16) | ((buf[2] as usize) << 8) | (buf[3] as usize);
            if buf.len() >= 4 + msg_len {
                buf.truncate(4 + msg_len);
                return (buf, errors::nil);
            }
        }
        let (rtype, frag_s, err) = {
            let mut adapter = ConnReader(conn);
            read_record(&mut adapter)
        };
        if !err.IsNil() {
            return (Vec::new(), err);
        }
        if rtype != RECORD_HANDSHAKE {
            send_alert(conn, alertUnexpectedMessage);
            return (
                Vec::new(),
                errors::New("tls: first record from client is not a handshake message"),
            );
        }
        buf.extend_from_slice(&frag_s.__into_vec());
        if buf.is_empty() {
            return (Vec::new(), errors::New("tls: empty handshake record"));
        }
        if buf[0] != typeClientHello {
            send_alert(conn, alertUnexpectedMessage);
            return (
                Vec::new(),
                errors::New("tls: expected ClientHello as first handshake message"),
            );
        }
    }
}

// ─── The server handshake driver ────────────────────────────────────

/// Result of a completed server handshake, alongside the record-layer
/// key material: connection-level facts the caller may expose
/// (Go: fields set on `Conn` by the handshake).
// Go-shape Conn facts; unread until tls.ConnectionState is surfaced.
#[allow(dead_code)]
pub(crate) struct ServerHandshakeInfo {
    /// Negotiated ALPN protocol ("" if none).
    pub alpn_protocol: alloc::string::String,
    /// SNI value from the ClientHello ("" if absent).
    pub server_name: alloc::string::String,
}

/// `Conn.serverHandshake` + `serverHandshakeStateTLS13.handshake` —
/// drive the accept-side TLS 1.3 handshake over `conn`.
///
/// `certificates` is the parsed `Config.Certificates` list (the
/// first entry is used — `Config.getCertificate` without SNI-based
/// selection), `next_protos` the server's ALPN preference list.
pub(crate) fn do_server_handshake_tls13(
    conn: &mut dyn crate::net::Conn,
    cert_chain: &[Vec<byte>],
    private_key: &ServerPrivateKey,
    next_protos: &[alloc::string::String],
) -> (KeyMaterial, ServerHandshakeInfo, error) {
    let dummy_info = ServerHandshakeInfo {
        alpn_protocol: alloc::string::String::new(),
        server_name: alloc::string::String::new(),
    };
    macro_rules! fail {
        ($conn:expr, $alert:expr, $msg:expr) => {{
            send_alert($conn, $alert);
            return (KeyMaterial::default(), dummy_info, errors::New($msg));
        }};
    }

    // ── readClientHello (handshake_server.go:134) ────────────────────
    let (ch_bytes, err) = read_client_hello_bytes(conn);
    if !err.IsNil() {
        return (KeyMaterial::default(), dummy_info, err);
    }
    let mut client_hello = clientHelloMsg::default();
    if !client_hello.unmarshal(crate::goslice::slice::__from_vec(ch_bytes.clone())) {
        fail!(conn, alertDecodeError, "tls: could not decode ClientHello");
    }

    // Version negotiation: the Goish server is TLS 1.3-only. RFC 8446
    // §4.2.1 — a 1.3 client MUST list 0x0304 in supported_versions.
    if !client_hello.supportedVersions.contains(&0x0304) {
        fail!(
            conn,
            alertProtocolVersion,
            "tls: client does not support TLS 1.3 (Goish server is TLS 1.3-only)"
        );
    }

    // ── processClientHello (handshake_server_tls13.go:105) ───────────
    let mut hello = serverHelloMsg::default();
    // TLS 1.3 froze ServerHello.legacy_version; supported_versions
    // carries the real version. RFC 8446, Sections 4.1.3 and 4.2.1.
    hello.vers = 0x0303; // VersionTLS12
    hello.supportedVersion = 0x0304;

    if client_hello.compressionMethods.len() != 1
        || client_hello.compressionMethods[0] != compressionNone
    {
        fail!(
            conn,
            alertIllegalParameter,
            "tls: TLS 1.3 client supports illegal compression methods"
        );
    }

    // hello.random = 32 CSPRNG bytes.
    {
        let mut r = slice::<byte>::__from_vec(alloc::vec![0u8; 32]);
        let (n, rerr) = crate::crypto::rand::Read(&mut r);
        if !rerr.IsNil() || n != 32 {
            fail!(conn, alertInternalError, "tls: failed to read random bytes");
        }
        hello.random = r.__into_vec();
    }

    if !client_hello.secureRenegotiation.is_empty() {
        fail!(
            conn,
            alertHandshakeFailure,
            "tls: initial handshake had non-empty renegotiation extension"
        );
    }

    if client_hello.earlyData {
        // See RFC 8446, Section 4.2.10. We never issue session
        // tickets, so a client sending early data is misbehaving.
        fail!(
            conn,
            alertUnsupportedExtension,
            "tls: client sent unexpected early data"
        );
    }

    hello.sessionId = client_hello.sessionId.clone();
    hello.compressionMethod = compressionNone;

    // Cipher suite: server preference order over the client's list.
    let mut suite: Option<CipherSuiteTls13> = None;
    for suite_id in defaultCipherSuitesTLS13.iter() {
        if client_hello.cipherSuites.contains(suite_id) {
            suite = cipher_suite_tls13(*suite_id);
            break;
        }
    }
    let suite = match suite {
        Some(s) => s,
        None => fail!(
            conn,
            alertHandshakeFailure,
            "tls: no cipher suite supported by both client and server"
        ),
    };
    hello.cipherSuite = suite.id;
    let hash_fn = suite.hash_fn;
    let key_len = suite.key_len;

    // Key exchange: X25519 only. The client must have sent an X25519
    // key share in its first flight (no HelloRetryRequest support).
    if !client_hello.supportedCurves.contains(&X25519) {
        fail!(
            conn,
            alertHandshakeFailure,
            "tls: no key exchanges supported by both client and server (Goish server is X25519-only)"
        );
    }
    let client_key_share: Option<&keyShare> = client_hello
        .keyShares
        .iter()
        .find(|ks| ks.group == X25519);
    let client_key_share = match client_key_share {
        Some(ks) => ks,
        None => fail!(
            conn,
            alertHandshakeFailure,
            "tls: client sent no X25519 key share (HelloRetryRequest not supported)"
        ),
    };
    if client_key_share.data.len() != 32 {
        fail!(conn, alertIllegalParameter, "tls: invalid client key share");
    }

    let (server_priv, server_pub) = ecdh::x25519_generate();
    hello.serverShare = keyShare {
        group: X25519,
        data: server_pub.0.to_vec(),
    };
    let mut client_pub_arr = [0u8; 32];
    client_pub_arr.copy_from_slice(&client_key_share.data);
    let client_pub = ecdh::X25519PublicKey(client_pub_arr);
    let shared_key = ecdh::x25519_compute_shared(&server_priv, &client_pub);
    {
        // Reject low-order points (all-zero shared secret), matching
        // the ECDH error in Go.
        let mut is_zero = 0u8;
        for b in shared_key.iter() {
            is_zero |= *b;
        }
        if is_zero == 0 {
            fail!(conn, alertIllegalParameter, "tls: invalid client key share");
        }
    }

    // ALPN (handshake_server.go:334 via processClientHello).
    let selected_proto = match negotiate_alpn(next_protos, &client_hello.alpnProtocols) {
        Ok(p) => p,
        Err(e) => {
            send_alert(conn, alertNoApplicationProtocol);
            return (KeyMaterial::default(), dummy_info, e);
        }
    };

    // ── pickCertificate (handshake_server_tls13.go:502) ──────────────
    // signature_algorithms is required in TLS 1.3 (RFC 8446 §4.2.3).
    if client_hello.supportedSignatureAlgorithms.is_empty() {
        fail!(
            conn,
            alertMissingExtension,
            "tls: client did not send signature_algorithms"
        );
    }
    if cert_chain.is_empty() {
        fail!(
            conn,
            alertUnrecognizedName,
            "tls: no certificates configured"
        );
    }
    let sig_alg = match select_signature_scheme(
        private_key,
        &client_hello.supportedSignatureAlgorithms,
    ) {
        Some(a) => a,
        None => fail!(
            conn,
            alertHandshakeFailure,
            "tls: peer doesn't support any of the certificate's signature algorithms"
        ),
    };

    // ── sendServerParameters (handshake_server_tls13.go:735) ─────────
    // transcript = ClientHello || ServerHello (both full handshake
    // messages including the 4-byte header).
    let (hello_bytes_s, _) = hello.marshal();
    let hello_bytes: Vec<byte> = hello_bytes_s.__into_vec();
    let mut transcript: Vec<byte> = Vec::new();
    transcript.extend_from_slice(&ch_bytes);
    transcript.extend_from_slice(&hello_bytes);

    // ServerHello goes out in plaintext.
    let (_, werr) = conn.Write(encode_record(RECORD_HANDSHAKE, &hello_bytes));
    if !werr.IsNil() {
        return (KeyMaterial::default(), dummy_info, werr);
    }
    // sendDummyChangeCipherSpec (RFC 8446, Appendix D.4).
    let (_, werr) = conn.Write(encode_record(RECORD_CHANGE_CIPHER_SPEC, &[1u8]));
    if !werr.IsNil() {
        return (KeyMaterial::default(), dummy_info, werr);
    }

    // Key schedule: EarlySecret (no PSK) → HandshakeSecret.
    let early = key_schedule::EarlySecret::new(hash_fn, None);
    let hs = early.HandshakeSecret(&shared_key);
    let th = key_schedule::transcript_hash_fn(hash_fn, &transcript);
    let client_hs_secret = hs.ClientHandshakeTrafficSecret(&th);
    let server_hs_secret = hs.ServerHandshakeTrafficSecret(&th);
    let client_hs_keys = traffic_keys(hash_fn, &client_hs_secret, key_len);
    let server_hs_keys = traffic_keys(hash_fn, &server_hs_secret, key_len);
    let master = hs.MasterSecret();

    let mut server_hs_seq: u64 = 0;

    // EncryptedExtensions.
    let mut ee = encryptedExtensionsMsg::default();
    ee.alpnProtocol = selected_proto.clone();
    if !client_hello.serverName.is_empty() {
        ee.serverNameAck = true;
    }
    let (ee_bytes_s, _) = ee.marshal();
    let ee_bytes: alloc::vec::Vec<crate::types::byte> = ee_bytes_s.__into_vec();
    let (wire, eerr) = tls13_encrypt_record_suite(
        &server_hs_keys,
        server_hs_seq,
        RECORD_HANDSHAKE,
        &ee_bytes,
        suite.id,
    );
    if !eerr.IsNil() {
        return (KeyMaterial::default(), dummy_info, eerr);
    }
    server_hs_seq += 1;
    let (_, werr) = conn.Write(wire);
    if !werr.IsNil() {
        return (KeyMaterial::default(), dummy_info, werr);
    }
    transcript.extend_from_slice(&ee_bytes);

    // ── sendServerCertificate (handshake_server_tls13.go:851) ────────
    let mut cert_msg = certificateMsgTLS13::default();
    cert_msg.certificate.Certificate = crate::goslice::slice::__from_vec(
        cert_chain
            .iter()
            .map(|c| crate::goslice::slice::__from_vec(c.clone()))
            .collect(),
    );
    let (cert_bytes_s, _) = cert_msg.marshal();
    let cert_bytes: alloc::vec::Vec<crate::types::byte> = cert_bytes_s.__into_vec();
    let (wire, eerr) = tls13_encrypt_record_suite(
        &server_hs_keys,
        server_hs_seq,
        RECORD_HANDSHAKE,
        &cert_bytes,
        suite.id,
    );
    if !eerr.IsNil() {
        return (KeyMaterial::default(), dummy_info, eerr);
    }
    server_hs_seq += 1;
    let (_, werr) = conn.Write(wire);
    if !werr.IsNil() {
        return (KeyMaterial::default(), dummy_info, werr);
    }
    transcript.extend_from_slice(&cert_bytes);

    // CertificateVerify: sign 64×0x20 || "TLS 1.3, server
    // CertificateVerify" || 0x00 || transcript_hash (RFC 8446 §4.4.3).
    let cv_th = key_schedule::transcript_hash_fn(hash_fn, &transcript);
    let signed = tls13_signed_message(&cv_th);
    let signature: Vec<byte> = match sign_handshake(private_key, sig_alg, &signed) {
        Ok(s) => s,
        Err(e) => {
            send_alert(conn, alertInternalError);
            return (KeyMaterial::default(), dummy_info, e);
        }
    };
    let mut cv = certificateVerifyMsg::default();
    cv.hasSignatureAlgorithm = true;
    cv.signatureAlgorithm = sig_alg;
    cv.signature = signature;
    let (cv_bytes_s, _) = cv.marshal();
    let cv_bytes: alloc::vec::Vec<crate::types::byte> = cv_bytes_s.__into_vec();
    let (wire, eerr) = tls13_encrypt_record_suite(
        &server_hs_keys,
        server_hs_seq,
        RECORD_HANDSHAKE,
        &cv_bytes,
        suite.id,
    );
    if !eerr.IsNil() {
        return (KeyMaterial::default(), dummy_info, eerr);
    }
    server_hs_seq += 1;
    let (_, werr) = conn.Write(wire);
    if !werr.IsNil() {
        return (KeyMaterial::default(), dummy_info, werr);
    }
    transcript.extend_from_slice(&cv_bytes);

    // ── sendServerFinished (handshake_server_tls13.go:906) ───────────
    let fin_th = key_schedule::transcript_hash_fn(hash_fn, &transcript);
    let mut fin = finishedMsg::default();
    fin.verifyData = finished_hash(hash_fn, &server_hs_secret, &fin_th);
    let (fin_bytes_s, _) = fin.marshal();
    let fin_bytes: alloc::vec::Vec<crate::types::byte> = fin_bytes_s.__into_vec();
    let (wire, eerr) = tls13_encrypt_record_suite(
        &server_hs_keys,
        server_hs_seq,
        RECORD_HANDSHAKE,
        &fin_bytes,
        suite.id,
    );
    if !eerr.IsNil() {
        return (KeyMaterial::default(), dummy_info, eerr);
    }
    let (_, werr) = conn.Write(wire);
    if !werr.IsNil() {
        return (KeyMaterial::default(), dummy_info, werr);
    }
    transcript.extend_from_slice(&fin_bytes);

    // Derive secrets that take context through the server Finished.
    let app_th = key_schedule::transcript_hash_fn(hash_fn, &transcript);
    let client_app_secret = master.ClientApplicationTrafficSecret(&app_th);
    let server_app_secret = master.ServerApplicationTrafficSecret(&app_th);
    let client_app_keys = traffic_keys(hash_fn, &client_app_secret, key_len);
    let server_app_keys = traffic_keys(hash_fn, &server_app_secret, key_len);

    // Precompute the expected client Finished (sendSessionTickets,
    // handshake_server_tls13.go:975 — we don't request client certs,
    // so it covers the transcript through server Finished).
    let expected_client_vd = finished_hash(hash_fn, &client_hs_secret, &app_th);

    // resumption_master_secret needs the client Finished in the
    // transcript; derived below once it arrives (RFC 8446 §7.1).

    // ── readClientFinished (handshake_server_tls13.go:1139) ──────────
    let mut client_hs_seq: u64 = 0;
    let mut hs_reader = Tls13HandshakeReader::new();
    let (fin_plain, rerr) = hs_reader.next_msg(conn, &client_hs_keys, &mut client_hs_seq, suite.id);
    if !rerr.IsNil() {
        return (KeyMaterial::default(), dummy_info, rerr);
    }
    if fin_plain.is_empty() || fin_plain[0] != typeFinished {
        fail!(
            conn,
            alertUnexpectedMessage,
            "tls: expected client Finished message"
        );
    }
    if fin_plain.len() < 4 {
        fail!(conn, alertDecodeError, "tls: client Finished too short");
    }
    let vd_len = ((fin_plain[1] as usize) << 16)
        | ((fin_plain[2] as usize) << 8)
        | (fin_plain[3] as usize);
    if fin_plain.len() < 4 + vd_len || vd_len != expected_client_vd.len() {
        fail!(
            conn,
            alertDecryptError,
            "tls: invalid client finished hash"
        );
    }
    // hmac.Equal — constant-time comparison.
    let mut diff: byte = 0;
    for i in 0..vd_len {
        diff |= fin_plain[4 + i] ^ expected_client_vd[i];
    }
    if diff != 0 {
        fail!(
            conn,
            alertDecryptError,
            "tls: invalid client finished hash"
        );
    }

    // resumption_master_secret (RFC 8446 §7.1) — derived over the
    // transcript including the client Finished. Unused until session
    // tickets land, but cheap and keeps KeyMaterial complete.
    transcript.extend_from_slice(&fin_plain);
    let rms_th = key_schedule::transcript_hash_fn(hash_fn, &transcript);
    let resumption_master_secret =
        key_schedule::DeriveSecret(hash_fn, &master.secret, "res master", &rms_th);

    // ── build KeyMaterial ────────────────────────────────────────────
    let mut km = KeyMaterial::default();
    km.suite = suite.id;
    km.is_tls13 = true;
    let ckl = client_app_keys.key.len().min(32);
    km.tls13_client_key[..ckl].copy_from_slice(&client_app_keys.key[..ckl]);
    let civ = client_app_keys.iv.len().min(12);
    km.tls13_client_iv[..civ].copy_from_slice(&client_app_keys.iv[..civ]);
    let skl = server_app_keys.key.len().min(32);
    km.tls13_server_key[..skl].copy_from_slice(&server_app_keys.key[..skl]);
    let siv = server_app_keys.iv.len().min(12);
    km.tls13_server_iv[..siv].copy_from_slice(&server_app_keys.iv[..siv]);
    km.tls13_server_app_secret = server_app_secret;
    km.tls13_client_app_secret = client_app_secret;
    km.tls13_resumption_master_secret = resumption_master_secret;
    km.tls13_hash_size = suite.hash_size as u16; // goishlint:ignore GOISH005

    let info = ServerHandshakeInfo {
        alpn_protocol: selected_proto,
        server_name: client_hello.serverName.clone(),
    };
    (km, info, errors::nil)
}

/// Sign the CertificateVerify `signed` message with the certificate
/// key. Mirrors the `crypto.Signer` call in sendServerCertificate
/// (handshake_server_tls13.go:884): RSA keys sign RSA-PSS with
/// `PSSSaltLengthEqualsHash`; Ed25519 signs the raw message
/// (directSigning).
fn sign_handshake(
    key: &ServerPrivateKey,
    sig_alg: u16,
    signed: &[byte],
) -> Result<Vec<byte>, error> {
    use crate::crypto::rsa;
    match key {
        ServerPrivateKey::Ed25519(k) => {
            if sig_alg != Ed25519 {
                return Err(errors::New("tls: internal error: wrong sig scheme for Ed25519 key"));
            }
            let msg = slice::__from_vec(signed.to_vec());
            Ok(crate::crypto::ed25519::Sign(k, msg).__into_vec())
        }
        ServerPrivateKey::Rsa(k) => {
            let hash_id = match sig_alg {
                PSSWithSHA256 => crate::crypto::SHA256,
                PSSWithSHA384 => crate::crypto::SHA384,
                PSSWithSHA512 => crate::crypto::SHA512,
                _ => return Err(errors::New("tls: internal error: wrong sig scheme for RSA key")),
            };
            // digest = Hash(signed) — concrete hashers, same pattern
            // as the client-side verify_cert_verify.
            let s = slice::__from_vec(signed.to_vec());
            let empty = slice::<byte>::__from_vec(Vec::new());
            let digest: slice<byte> = match sig_alg {
                PSSWithSHA256 => {
                    let mut h = crate::crypto::sha256::New();
                    let _ = crate::io::Writer::Write(&mut h, s);
                    crate::hash::Hash::Sum(&h, empty)
                }
                PSSWithSHA384 => {
                    let mut h = crate::crypto::sha512::New384();
                    let _ = crate::io::Writer::Write(&mut h, s);
                    crate::hash::Hash::Sum(&h, empty)
                }
                _ => {
                    let mut h = crate::crypto::sha512::New();
                    let _ = crate::io::Writer::Write(&mut h, s);
                    crate::hash::Hash::Sum(&h, empty)
                }
            };

            let opts = rsa::PSSOptions {
                SaltLength: rsa::PSSSaltLengthEqualsHash,
                Hash: hash_id,
            };
            let mut rng = crate::crypto::rand::Reader;
            let (sig, serr) = rsa::SignPSS(&mut rng, k, hash_id, digest, Some(&opts));
            if !serr.IsNil() {
                return Err(serr);
            }
            Ok(sig.__into_vec())
        }
    }
}


// ─── crypto/tls/handshake_server_tls13.go, ported verbatim ────────────
//
// Everything above this divider is goish-only code that drives the live
// TLS 1.3 server. Below it is the state record Go declares and the
// methods that read it without driving the handshake.

// Go: handshake_server_tls13.go:40-64
//   type serverHandshakeStateTLS13 struct { c *Conn; ctx context.Context
//       clientHello *clientHelloMsg; hello *serverHelloMsg
//       sentDummyCCS bool; usingPSK bool; earlyData bool
//       suite *cipherSuiteTLS13; cert *Certificate
//       sigAlg SignatureScheme; earlySecret *tls13.EarlySecret
//       sharedKey []byte; handshakeSecret *tls13.HandshakeSecret
//       masterSecret *tls13.MasterSecret; trafficSecret []byte
//       transcript hash.Hash; clientFinished []byte
//       echContext *echServerContext }
/// Go: the TLS 1.3 server handshake state.
///
/// **Partial record.** Only the fields the ported methods read are
/// present; `ctx` lands with `handshake`, which drives the whole
/// exchange. `Default` is goish-only, standing in for Go's zero value
/// so test shims spell only the fields they set.
#[derive(Default)]
pub(crate) struct serverHandshakeStateTLS13 {
    pub c: super::conn::Conn,
    pub clientHello: super::handshake_messages::clientHelloMsg,
    pub hello: super::handshake_messages::serverHelloMsg,
    pub sentDummyCCS: bool,
    pub usingPSK: bool,
    pub earlyData: bool,
    pub sigAlg: super::common::SignatureScheme,
    pub cert: Option<super::common::Certificate>,
    pub suite: Option<&'static super::cipher_suites::cipherSuiteTLS13>,
    pub earlySecret: Option<crate::crypto::internal::fips140::tls13::EarlySecret>,
    pub sharedKey: crate::goslice::slice<crate::types::byte>,
    pub handshakeSecret: Option<crate::crypto::internal::fips140::tls13::HandshakeSecret>,
    pub masterSecret: Option<crate::crypto::internal::fips140::tls13::MasterSecret>,
    /// Go: the verify_data the server expects from the client, computed
    /// before the client's Finished is read.
    pub clientFinished: crate::goslice::slice<crate::types::byte>,
    /// Go: `client_application_traffic_secret_0`.
    pub trafficSecret: crate::goslice::slice<crate::types::byte>,
    pub transcript: Option<super::handshake_messages::transcriptHasher>,
    pub echContext: Option<echServerContext>,
}

// go: sdk 1.25.5 crypto/tls/handshake_server_tls13.go:33-43 echServerContext
/// Go: "inner indicates that the initial client_hello we recieved
/// contained an encrypted_client_hello extension that indicated it was
/// an 'inner' hello. We don't do any additional processing of the hello
/// in this case, so all fields above are unset."
#[derive(Default)]
pub(crate) struct echServerContext {
    pub hpkeContext: Option<crate::crypto::internal::hpke::Recipient>,
    pub configID: crate::types::uint8,
    pub ciphersuite: super::ech::echCipher,
    pub transcript: Option<super::handshake_messages::transcriptHasher>,
    pub inner: bool,
}

impl serverHandshakeStateTLS13 {
    // go: sdk 1.25.5 crypto/tls/handshake_server_tls13.go:535-545 serverHandshakeStateTLS13.sendDummyChangeCipherSpec
    /// Go: "sendDummyChangeCipherSpec sends a ChangeCipherSpec record for
    /// compatibility reasons. See RFC 8446, Appendix D.4."
    ///
    /// Deviation: the `c.quic != nil` branch is absent — goish ships no
    /// QUIC transport.
    pub(crate) fn sendDummyChangeCipherSpec(&mut self) -> crate::error {
        // Go: if hs.sentDummyCCS { return nil }
        //     hs.sentDummyCCS = true
        //     return hs.c.writeChangeCipherRecord()
        if self.sentDummyCCS {
            return crate::errors::nil;
        }
        self.sentDummyCCS = true;
        return self.c.writeChangeCipherRecord();
    }

    // go: sdk 1.25.5 crypto/tls/handshake_server_tls13.go:958-970 serverHandshakeStateTLS13.shouldSendSessionTickets
    ///
    /// Deviation: the QUIC check is absent — Go skips automatic tickets
    /// for QUIC because QUICConn.SendSessionTicket sends them instead,
    /// and goish ships no QUIC transport.
    pub(crate) fn shouldSendSessionTickets(&self) -> bool {
        // Go: if hs.c.config.SessionTicketsDisabled { return false }
        if self.c.__configSessionTicketsDisabled() {
            return false;
        }
        // Go: Don't send tickets the client wouldn't use. See RFC 8446,
        // Section 4.2.9.
        // Go: return slices.Contains(hs.clientHello.pskModes, pskModeDHE)
        return self
            .clientHello
            .pskModes
            .contains(&super::common::pskModeDHE);
    }

    // go: sdk 1.25.5 crypto/tls/handshake_server_tls13.go:834-836 serverHandshakeStateTLS13.requestClientCert
    pub(crate) fn requestClientCert(&self) -> bool {
        // Go: return hs.c.config.ClientAuth >= RequestClientCert && !hs.usingPSK
        return self.c.__configClientAuth().0 >= super::common::RequestClientCert.0
            && !self.usingPSK;
    }
}

// go: sdk 1.25.5 crypto/tls/handshake_server_tls13.go:675-728 illegalClientHelloChange
/// Go: "illegalClientHelloChange reports whether the second ClientHello
/// of a HelloRetryRequest exchange differs from the first in any way
/// other than the fields RFC 8446 Section 4.1.2 permits."
pub(crate) fn illegalClientHelloChange(
    ch: &super::handshake_messages::clientHelloMsg,
    ch1: &super::handshake_messages::clientHelloMsg,
) -> bool {
    // Go: if len(ch.supportedVersions) != len(ch1.supportedVersions) || … { return true }
    if ch.supportedVersions.len() != ch1.supportedVersions.len()
        || ch.cipherSuites.len() != ch1.cipherSuites.len()
        || ch.supportedCurves.len() != ch1.supportedCurves.len()
        || ch.supportedSignatureAlgorithms.len() != ch1.supportedSignatureAlgorithms.len()
        || ch.supportedSignatureAlgorithmsCert.len()
            != ch1.supportedSignatureAlgorithmsCert.len()
        || ch.alpnProtocols.len() != ch1.alpnProtocols.len()
    {
        return true;
    }
    // Go: for i := range ch.supportedVersions { … } — one loop per list.
    if ch.supportedVersions != ch1.supportedVersions
        || ch.cipherSuites != ch1.cipherSuites
        || ch.supportedCurves != ch1.supportedCurves
        || ch.supportedSignatureAlgorithms != ch1.supportedSignatureAlgorithms
        || ch.supportedSignatureAlgorithmsCert != ch1.supportedSignatureAlgorithmsCert
        || ch.alpnProtocols != ch1.alpnProtocols
    {
        return true;
    }
    // Go: return ch.vers != ch1.vers || !bytes.Equal(ch.random, ch1.random) || …
    //
    // Note what is NOT compared: keyShares, pskIdentities, pskBinders,
    // earlyData, cookie's presence — those are exactly the fields RFC
    // 8446 §4.1.2 lets the second ClientHello change.
    return ch.vers != ch1.vers
        || ch.random != ch1.random
        || ch.sessionId != ch1.sessionId
        || ch.compressionMethods != ch1.compressionMethods
        || ch.serverName != ch1.serverName
        || ch.ocspStapling != ch1.ocspStapling
        || ch.supportedPoints != ch1.supportedPoints
        || ch.ticketSupported != ch1.ticketSupported
        || ch.sessionTicket != ch1.sessionTicket
        || ch.secureRenegotiationSupported != ch1.secureRenegotiationSupported
        || ch.secureRenegotiation != ch1.secureRenegotiation
        || ch.scts != ch1.scts
        || ch.cookie != ch1.cookie
        || ch.pskModes != ch1.pskModes;
}


// go: sdk 1.25.5 crypto/tls/handshake_server_tls13.go:474-497 cloneHash
/// Go: "cloneHash clones the hash, or returns nil if the hash cannot be
/// cloned." Used to fork the handshake transcript for the
/// HelloRetryRequest synthetic message hash.
///
/// Deviation: Go recreates the `binaryMarshaler` interface inline "to
/// avoid importing encoding"; goish asserts against
/// `encoding::BinaryMarshaler` and `encoding::BinaryUnmarshaler`
/// directly, which are the same two methods and are already
/// `#[goish::interface]`.
pub(crate) fn cloneHash(
    in_: &(dyn crate::hash::Hash + Send + Sync + 'static),
    h: crate::crypto::Hash,
) -> Option<alloc::boxed::Box<dyn crate::hash::Hash + Send + Sync>> {
    // Go: marshaler, ok := in.(binaryMarshaler)
    //     if !ok { return nil }
    let marshaler =
        crate::goany::AsExt::As::<dyn crate::encoding::BinaryMarshaler + Send + Sync>(in_);
    if marshaler.is_none() {
        return None;
    }
    // Go: state, err := marshaler.MarshalBinary()
    //     if err != nil { return nil }
    let (state, err) = marshaler.unwrap().MarshalBinary();
    if err != crate::errors::nil {
        return None;
    }
    // Go: out := h.New()
    let mut out = h.New();
    // Go: unmarshaler, ok := out.(binaryMarshaler)
    //     if !ok { return nil }
    //     if err := unmarshaler.UnmarshalBinary(state); err != nil { return nil }
    //     return out
    {
        let unmarshaler = crate::goany::AsExtMut::AsMut::<
            dyn crate::encoding::BinaryUnmarshaler + Send + Sync,
        >(&mut *out);
        if unmarshaler.is_none() {
            return None;
        }
        if unmarshaler.unwrap().UnmarshalBinary(state) != crate::errors::nil {
            return None;
        }
    }
    return Some(out);
}


impl serverHandshakeStateTLS13 {
    // go: sdk 1.25.5 crypto/tls/handshake_server_tls13.go:499-531 serverHandshakeStateTLS13.pickCertificate
    /// Choose the server certificate and the scheme it will sign with.
    pub(crate) fn pickCertificate(&mut self) -> crate::error {
        // Go: Only one of PSK and certificates are used at a time.
        if self.usingPSK {
            return crate::errors::nil;
        }

        // Go: signature_algorithms is required in TLS 1.3. See RFC 8446,
        // Section 4.2.3.
        // Go: if len(hs.clientHello.supportedSignatureAlgorithms) == 0 {
        //         return c.sendAlert(alertMissingExtension) }
        if self.clientHello.supportedSignatureAlgorithms.len() == 0 {
            return self.c.sendAlert(super::alert::alertMissingExtension);
        }

        // Go: certificate, err := c.config.getCertificate(
        //         clientHelloInfo(hs.ctx, c, hs.clientHello))
        //     if err != nil {
        //         if err == errNoCertificates { c.sendAlert(alertUnrecognizedName) }
        //         else { c.sendAlert(alertInternalError) }
        //         return err }
        let chi = super::handshake_server::clientHelloInfo(&self.c, &self.clientHello);
        let (certificate, err) = self.c.__config().getCertificate(&chi);
        if err != crate::errors::nil {
            if crate::errors::Is(err.clone(), super::common::errNoCertificates) {
                self.c.sendAlert(super::alert::alertUnrecognizedName);
            } else {
                self.c.sendAlert(super::alert::alertInternalError);
            }
            return err;
        }
        // Go: hs.sigAlg, err = selectSignatureScheme(c.vers, certificate,
        //         hs.clientHello.supportedSignatureAlgorithms)
        //     if err != nil {
        //         // getCertificate returned a certificate that is unsupported or
        //         // incompatible with the client's signature algorithms.
        //         c.sendAlert(alertHandshakeFailure)
        //         return err }
        let peerAlgs: alloc::vec::Vec<super::common::SignatureScheme> = self
            .clientHello
            .supportedSignatureAlgorithms
            .iter()
            .map(|v| super::common::SignatureScheme(*v))
            .collect();
        let (sigAlg, err) = super::auth::selectSignatureScheme(
            self.c.__vers(),
            &certificate,
            crate::goslice::slice::__from_vec(peerAlgs),
        );
        if err != crate::errors::nil {
            self.c.sendAlert(super::alert::alertHandshakeFailure);
            return err;
        }
        self.sigAlg = sigAlg;
        // Go: hs.cert = certificate
        //     return nil
        self.cert = Some(certificate);
        return crate::errors::nil;
    }
}

impl serverHandshakeStateTLS13 {
    // go: sdk 1.25.5 crypto/tls/handshake_server_tls13.go:66-104 serverHandshakeStateTLS13.handshake
    /// Go: "For an overview of the TLS 1.3 handshake, see RFC 8446,
    /// Section 2." Sequences the whole server-side exchange.
    pub(crate) fn handshake(&mut self) -> crate::error {
        // Go: if err := hs.processClientHello(); err != nil { return err }
        let err = self.processClientHello();
        if err != crate::errors::nil {
            return err;
        }
        // Go: if err := hs.checkForResumption(); err != nil { return err }
        let err = self.checkForResumption();
        if err != crate::errors::nil {
            return err;
        }
        // Go: if err := hs.pickCertificate(); err != nil { return err }
        let err = self.pickCertificate();
        if err != crate::errors::nil {
            return err;
        }
        // Go: c.buffering = true
        self.c.__setBuffering(true);
        // Go: if err := hs.sendServerParameters(); err != nil { return err }
        let err = self.sendServerParameters();
        if err != crate::errors::nil {
            return err;
        }
        // Go: if err := hs.sendServerCertificate(); err != nil { return err }
        let err = self.sendServerCertificate();
        if err != crate::errors::nil {
            return err;
        }
        // Go: if err := hs.sendServerFinished(); err != nil { return err }
        let err = self.sendServerFinished();
        if err != crate::errors::nil {
            return err;
        }
        // Go: "Note that at this point we could start sending application
        //      data without waiting for the client's second flight, but the
        //      application might not expect the lack of replay protection of
        //      the ClientHello parameters."
        //     if _, err := c.flush(); err != nil { return err }
        let (_, err) = self.c.flush();
        if err != crate::errors::nil {
            return err;
        }
        // Go: if err := hs.readClientCertificate(); err != nil { return err }
        let err = self.readClientCertificate();
        if err != crate::errors::nil {
            return err;
        }
        // Go: if err := hs.readClientFinished(); err != nil { return err }
        let err = self.readClientFinished();
        if err != crate::errors::nil {
            return err;
        }
        // Go: c.isHandshakeComplete.Store(true)
        //     return nil
        self.c.__setHandshakeComplete(true);
        return crate::errors::nil;
    }

    // go: sdk 1.25.5 crypto/tls/handshake_server_tls13.go:1047-1137 serverHandshakeStateTLS13.readClientCertificate
    /// Go: if a client certificate was requested, read the Certificate
    /// (and, when non-empty, the CertificateVerify), verify the peer
    /// chain and the handshake signature, then send the session tickets
    /// deferred from sendServerFinished. Runs VerifyConnection in both the
    /// requested and not-requested paths.
    pub(crate) fn readClientCertificate(&mut self) -> crate::error {
        // Go: if !hs.requestClientCert() {
        //         if c.config.VerifyConnection != nil {
        //             if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
        //                 c.sendAlert(alertBadCertificate); return err } }
        //         return nil }
        if !self.requestClientCert() {
            if let Some(verify) = self.c.config.VerifyConnection.clone() {
                let err = verify(self.c.connectionStateLocked());
                if err != crate::errors::nil {
                    self.c.sendAlert(super::alert::alertBadCertificate);
                    return err;
                }
            }
            return crate::errors::nil;
        }

        // Go: msg, err := c.readHandshake(hs.transcript)
        //     if err != nil { return err }
        let (msg, err) = {
            let transcript = self.transcript.as_mut().unwrap();
            self.c.readHandshake(Some(transcript))
        };
        if err != crate::errors::nil {
            return err;
        }
        // Go: certMsg, ok := msg.(*certificateMsgTLS13)
        //     if !ok { c.sendAlert(alertUnexpectedMessage)
        //         return unexpectedMessageError(certMsg, msg) }
        let msg = match msg {
            Some(m) => m,
            None => return crate::errors::New("tls: internal error: no handshake message"),
        };
        let certMsg = match msg
            .asAny()
            .downcast_ref::<super::handshake_messages::certificateMsgTLS13>()
        {
            Some(m) => m.clone(),
            None => {
                self.c.sendAlert(super::alert::alertUnexpectedMessage);
                return super::common::unexpectedMessageError(
                    crate::gostring::string::from_static("*tls.certificateMsgTLS13"),
                    super::handshake_messages::handshakeMessageTypeName(&*msg),
                );
            }
        };

        // Go: if err := c.processCertsFromClient(certMsg.certificate); err != nil { return err }
        let err = self.c.processCertsFromClient(certMsg.certificate.clone());
        if err != crate::errors::nil {
            return err;
        }

        // Go: if c.config.VerifyConnection != nil {
        //         if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
        //             c.sendAlert(alertBadCertificate); return err } }
        if let Some(verify) = self.c.config.VerifyConnection.clone() {
            let err = verify(self.c.connectionStateLocked());
            if err != crate::errors::nil {
                self.c.sendAlert(super::alert::alertBadCertificate);
                return err;
            }
        }

        // Go: if len(certMsg.certificate.Certificate) != 0 {
        if certMsg.certificate.Certificate.Len() != 0 {
            // Go: msg, err = c.readHandshake(nil)
            //     if err != nil { return err }
            let (msg, err) = self.c.readHandshake(None);
            if err != crate::errors::nil {
                return err;
            }
            // Go: certVerify, ok := msg.(*certificateVerifyMsg)
            //     if !ok { c.sendAlert(alertUnexpectedMessage)
            //         return unexpectedMessageError(certVerify, msg) }
            let msg = match msg {
                Some(m) => m,
                None => {
                    return crate::errors::New("tls: internal error: no handshake message")
                }
            };
            let certVerify = match msg
                .asAny()
                .downcast_ref::<super::handshake_messages::certificateVerifyMsg>()
            {
                Some(m) => m.clone(),
                None => {
                    self.c.sendAlert(super::alert::alertUnexpectedMessage);
                    return super::common::unexpectedMessageError(
                        crate::gostring::string::from_static("*tls.certificateVerifyMsg"),
                        super::handshake_messages::handshakeMessageTypeName(&*msg),
                    );
                }
            };

            // Go: "See RFC 8446, Section 4.4.3."
            //     if !isSupportedSignatureAlgorithm(certVerify.signatureAlgorithm, supportedSignatureAlgorithms(c.vers)) ||
            //        !isSupportedSignatureAlgorithm(certVerify.signatureAlgorithm, signatureSchemesForPublicKey(c.vers, c.peerCertificates[0].PublicKey)) {
            //         c.sendAlert(alertIllegalParameter)
            //         return errors.New("tls: client certificate used with invalid signature algorithm") }
            let sigAlg = super::common::SignatureScheme(certVerify.signatureAlgorithm);
            if !super::common::isSupportedSignatureAlgorithm(
                sigAlg,
                super::common::supportedSignatureAlgorithms(self.c.__vers()),
            ) || !super::common::isSupportedSignatureAlgorithm(
                sigAlg,
                super::auth::signatureSchemesForPublicKey(
                    self.c.__vers(),
                    &self.c.peerCertificates[0].PublicKey,
                ),
            ) {
                self.c.sendAlert(super::alert::alertIllegalParameter);
                return crate::errors::New(
                    "tls: client certificate used with invalid signature algorithm",
                );
            }
            // Go: sigType, sigHash, err := typeAndHashFromSignatureScheme(certVerify.signatureAlgorithm)
            //     if err != nil { return c.sendAlert(alertInternalError) }
            let (sigType, sigHash, err) =
                super::auth::typeAndHashFromSignatureScheme(sigAlg);
            if err != crate::errors::nil {
                return self.c.sendAlert(super::alert::alertInternalError);
            }
            // Go: if sigType == signaturePKCS1v15 || sigHash == crypto.SHA1 {
            //         return c.sendAlert(alertInternalError) }
            if sigType == super::common::signaturePKCS1v15
                || sigHash == crate::crypto::SHA1
            {
                return self.c.sendAlert(super::alert::alertInternalError);
            }
            // Go: signed := signedMessage(sigHash, clientSignatureContext, hs.transcript)
            let signed = {
                let transcript = self.transcript.as_mut().unwrap();
                super::auth::signedMessage(
                    sigHash,
                    super::auth::clientSignatureContext,
                    &mut *transcript.0,
                )
            };
            // Go: if err := verifyHandshakeSignature(sigType, c.peerCertificates[0].PublicKey,
            //         sigHash, signed, certVerify.signature); err != nil {
            //         c.sendAlert(alertDecryptError)
            //         return errors.New("tls: invalid signature by the client certificate: " + err.Error()) }
            let err = super::auth::verifyHandshakeSignature(
                sigType,
                &self.c.peerCertificates[0].PublicKey,
                sigHash,
                signed,
                crate::goslice::slice::__from_vec(certVerify.signature.clone()),
            );
            if err != crate::errors::nil {
                self.c.sendAlert(super::alert::alertDecryptError);
                return crate::fmt::Errorf!(
                    "tls: invalid signature by the client certificate: %s",
                    err.Error()
                );
            }
            // Go: c.peerSigAlg = certVerify.signatureAlgorithm
            self.c.peerSigAlg = sigAlg;

            // Go: if err := transcriptMsg(certVerify, hs.transcript); err != nil { return err }
            let err = {
                let transcript = self.transcript.as_mut().unwrap();
                super::handshake_messages::transcriptMsg(&certVerify, transcript)
            };
            if err != crate::errors::nil {
                return err;
            }
        }

        // Go: "If we waited until the client certificates to send session
        //      tickets, we are ready to do it now."
        //     if err := hs.sendSessionTickets(); err != nil { return err }
        let err = self.sendSessionTickets();
        if err != crate::errors::nil {
            return err;
        }

        // Go: return nil
        return crate::errors::nil;
    }

    // go: sdk 1.25.5 crypto/tls/handshake_server_tls13.go:1139-1161 serverHandshakeStateTLS13.readClientFinished
    /// Go: read the client's Finished, check it against the verify_data
    /// computed earlier, and switch the read half to the client's
    /// application traffic secret.
    pub(crate) fn readClientFinished(&mut self) -> crate::error {
        // Go: "finishedMsg is not included in the transcript."
        let (msg, err) = self.c.readHandshake(None);
        if err != crate::errors::nil {
            return err;
        }
        // Go: finished, ok := msg.(*finishedMsg); if !ok { … }
        let msg = match msg {
            Some(m) => m,
            None => return crate::errors::New("tls: internal error: no handshake message"),
        };
        let finished = match msg
            .asAny()
            .downcast_ref::<super::handshake_messages::finishedMsg>()
        {
            Some(f) => f.clone(),
            None => {
                self.c.sendAlert(super::alert::alertUnexpectedMessage);
                return super::common::unexpectedMessageError(
                    crate::gostring::string::from_static("*tls.finishedMsg"),
                    super::handshake_messages::handshakeMessageTypeName(&*msg),
                );
            }
        };

        // Go: if !hmac.Equal(hs.clientFinished, finished.verifyData) {
        //         c.sendAlert(alertDecryptError)
        //         return errors.New("tls: invalid client finished hash") }
        if !crate::crypto::hmac::Equal(
            self.clientFinished.clone(),
            crate::goslice::slice::__from_vec(finished.verifyData.clone()),
        ) {
            self.c.sendAlert(super::alert::alertDecryptError);
            return crate::errors::New("tls: invalid client finished hash");
        }

        // Go: c.in.setTrafficSecret(hs.suite, QUICEncryptionLevelApplication, hs.trafficSecret)
        //     return nil
        self.c.in_.setTrafficSecret(
            self.suite.unwrap(),
            super::quic::QUICEncryptionLevelApplication,
            self.trafficSecret.clone(),
        );
        return crate::errors::nil;
    }
}

impl serverHandshakeStateTLS13 {
    // go: sdk 1.25.5 crypto/tls/handshake_server_tls13.go:838-904 serverHandshakeStateTLS13.sendServerCertificate
    /// Go: send the optional CertificateRequest, the server's
    /// Certificate, and the CertificateVerify that signs the transcript
    /// with the leaf's key.
    pub(crate) fn sendServerCertificate(&mut self) -> crate::error {
        // Go: "Only one of PSK and certificates are used at a time."
        if self.usingPSK {
            return crate::errors::nil;
        }

        // Go: if hs.requestClientCert() { … }
        if self.requestClientCert() {
            // Go: "Request a client certificate"
            let mut certReq = super::handshake_messages::certificateRequestMsgTLS13::default();
            certReq.ocspStapling = true;
            certReq.scts = true;
            certReq.supportedSignatureAlgorithms =
                super::common::supportedSignatureAlgorithms(self.c.__vers());
            certReq.supportedSignatureAlgorithmsCert =
                super::common::supportedSignatureAlgorithmsCert();
            // Go: if c.config.ClientCAs != nil {
            //         certReq.certificateAuthorities = c.config.ClientCAs.Subjects() }
            if let Some(pool) = self.c.config.ClientCAs.as_ref() {
                certReq.certificateAuthorities = pool.Subjects();
            }

            let (_, err) = {
                let transcript = self.transcript.as_mut().unwrap();
                self.c.writeHandshakeRecord(&certReq, Some(transcript))
            };
            if err != crate::errors::nil {
                return err;
            }
        }

        // Go: certMsg := new(certificateMsgTLS13)
        //     certMsg.certificate = *hs.cert
        //     certMsg.scts = hs.clientHello.scts && len(hs.cert.SignedCertificateTimestamps) > 0
        //     certMsg.ocspStapling = hs.clientHello.ocspStapling && len(hs.cert.OCSPStaple) > 0
        let cert = self.cert.clone().unwrap_or_default();
        let mut certMsg = super::handshake_messages::certificateMsgTLS13::default();
        certMsg.certificate = cert.clone();
        certMsg.scts =
            self.clientHello.scts && cert.SignedCertificateTimestamps.Len() > 0;
        certMsg.ocspStapling = self.clientHello.ocspStapling && cert.OCSPStaple.Len() > 0;

        let (_, err) = {
            let transcript = self.transcript.as_mut().unwrap();
            self.c.writeHandshakeRecord(&certMsg, Some(transcript))
        };
        if err != crate::errors::nil {
            return err;
        }

        // Go: certVerifyMsg := new(certificateVerifyMsg)
        //     certVerifyMsg.hasSignatureAlgorithm = true
        //     certVerifyMsg.signatureAlgorithm = hs.sigAlg
        let mut certVerifyMsg = super::handshake_messages::certificateVerifyMsg::default();
        certVerifyMsg.hasSignatureAlgorithm = true;
        certVerifyMsg.signatureAlgorithm = self.sigAlg.0;

        // Go: sigType, sigHash, err := typeAndHashFromSignatureScheme(hs.sigAlg)
        //     if err != nil { return c.sendAlert(alertInternalError) }
        let (sigType, sigHash, err) = super::auth::typeAndHashFromSignatureScheme(self.sigAlg);
        if err != crate::errors::nil {
            return self.c.sendAlert(super::alert::alertInternalError);
        }

        // Go: signed := signedMessage(sigHash, serverSignatureContext, hs.transcript)
        let signed = {
            let transcript = self.transcript.as_mut().unwrap();
            super::auth::signedMessage(
                sigHash,
                super::auth::serverSignatureContext,
                &mut *transcript.0,
            )
        };
        // Go: signOpts := crypto.SignerOpts(sigHash)
        //     if sigType == signatureRSAPSS {
        //         signOpts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: sigHash} }
        let opts: alloc::boxed::Box<dyn crate::crypto::SignerOpts + Send + Sync> =
            if sigType == super::common::signatureRSAPSS {
                alloc::boxed::Box::new(crate::crypto::rsa::PSSOptions {
                    SaltLength: crate::crypto::rsa::PSSSaltLengthEqualsHash,
                    Hash: sigHash,
                })
            } else {
                alloc::boxed::Box::new(sigHash)
            };
        // Go: sig, err := hs.cert.PrivateKey.(crypto.Signer).Sign(c.config.rand(), signed, signOpts)
        let signer = match super::auth::signerOf(&cert.PrivateKey) {
            Some(s) => s,
            None => {
                self.c.sendAlert(super::alert::alertInternalError);
                return crate::errors::New(
                    "tls: failed to sign handshake: certificate private key does not implement crypto.Signer",
                );
            }
        };
        let mut rng = self.c.config.rand();
        let (sig, err) = signer.Sign(&mut *rng, signed, &*opts);
        if err != crate::errors::nil {
            // Go: public := hs.cert.PrivateKey.(crypto.Signer).Public()
            //     if rsaKey, ok := public.(*rsa.PublicKey); ok && sigType == signatureRSAPSS &&
            //         rsaKey.N.BitLen()/8 < sigHash.Size()*2+2 { // key too small for RSA-PSS
            //         c.sendAlert(alertHandshakeFailure)
            //     } else { c.sendAlert(alertInternalError) }
            let pub_ = signer.Public();
            let tooSmallForPSS = match pub_.downcast_ref::<crate::crypto::rsa::PublicKey>() {
                Some(k) => {
                    sigType == super::common::signatureRSAPSS
                        && k.N.BitLen() / 8 < sigHash.Size() * 2 + 2
                }
                None => false,
            };
            if tooSmallForPSS {
                self.c.sendAlert(super::alert::alertHandshakeFailure);
            } else {
                self.c.sendAlert(super::alert::alertInternalError);
            }
            return crate::fmt::Errorf!("tls: failed to sign handshake: %s", err.Error());
        }
        // Go: certVerifyMsg.signature = sig
        certVerifyMsg.signature = sig.__into_vec();

        // Go: if _, err := hs.c.writeHandshakeRecord(certVerifyMsg, hs.transcript); err != nil { return err }
        let (_, err) = {
            let transcript = self.transcript.as_mut().unwrap();
            self.c.writeHandshakeRecord(&certVerifyMsg, Some(transcript))
        };
        if err != crate::errors::nil {
            return err;
        }

        // Go: return nil
        return crate::errors::nil;
    }

    // go: sdk 1.25.5 crypto/tls/handshake_server_tls13.go:107-329 serverHandshakeStateTLS13.processClientHello
    /// Go: vet the ClientHello, negotiate version/cipher/curve, run a
    /// HelloRetryRequest if no usable key share was offered, complete the
    /// (hybrid) ECDH, negotiate ALPN, and record the server name.
    ///
    /// Deviations: every `c.quic != nil` arm is absent — goish ships no
    /// QUIC transport — so the QUIC version floor, transport-parameters
    /// handling, and the early_data-with-QUIC branch collapse to Go's
    /// non-QUIC path.
    pub(crate) fn processClientHello(&mut self) -> crate::error {
        use crate::goslice::slice;

        // Go: hs.hello = new(serverHelloMsg)
        self.hello = super::handshake_messages::serverHelloMsg::default();

        // Go: "TLS 1.3 froze the ServerHello.legacy_version field ..."
        //     hs.hello.vers = VersionTLS12
        //     hs.hello.supportedVersion = c.vers
        self.hello.vers = super::common::VersionTLS12;
        self.hello.supportedVersion = self.c.__vers();

        // Go: if len(hs.clientHello.supportedVersions) == 0 {
        //         c.sendAlert(alertIllegalParameter)
        //         return errors.New("tls: client used the legacy version field to negotiate TLS 1.3") }
        if self.clientHello.supportedVersions.len() == 0 {
            self.c.sendAlert(super::alert::alertIllegalParameter);
            return crate::errors::New(
                "tls: client used the legacy version field to negotiate TLS 1.3",
            );
        }

        // Go: for _, id := range hs.clientHello.cipherSuites {
        //         if id == TLS_FALLBACK_SCSV {
        //             if c.vers < c.config.maxSupportedVersion(roleServer) {
        //                 c.sendAlert(alertInappropriateFallback)
        //                 return errors.New("tls: client using inappropriate protocol fallback") }
        //             break } }
        for id in self.clientHello.cipherSuites.iter() {
            if *id == super::cipher_suites::TLS_FALLBACK_SCSV {
                if self.c.__vers()
                    < self.c.config.maxSupportedVersion(super::common::roleServer)
                {
                    self.c.sendAlert(super::alert::alertInappropriateFallback);
                    return crate::errors::New(
                        "tls: client using inappropriate protocol fallback",
                    );
                }
                break;
            }
        }

        // Go: if len(hs.clientHello.compressionMethods) != 1 ||
        //        hs.clientHello.compressionMethods[0] != compressionNone {
        //         c.sendAlert(alertIllegalParameter)
        //         return errors.New("tls: TLS 1.3 client supports illegal compression methods") }
        if self.clientHello.compressionMethods.len() != 1
            || self.clientHello.compressionMethods[0] != super::common::compressionNone
        {
            self.c.sendAlert(super::alert::alertIllegalParameter);
            return crate::errors::New(
                "tls: TLS 1.3 client supports illegal compression methods",
            );
        }

        // Go: hs.hello.random = make([]byte, 32)
        //     if _, err := io.ReadFull(c.config.rand(), hs.hello.random); err != nil {
        //         c.sendAlert(alertInternalError); return err }
        self.hello.random = alloc::vec![0u8; 32];
        {
            let mut buf: slice<byte> = slice::__from_vec(self.hello.random.clone());
            let mut r = self.c.config.rand();
            let (_, err) = crate::io::ReadFull(&mut *r, &mut buf);
            if err != crate::errors::nil {
                self.c.sendAlert(super::alert::alertInternalError);
                return err;
            }
            self.hello.random = buf.__into_vec();
        }

        // Go: if len(hs.clientHello.secureRenegotiation) != 0 {
        //         c.sendAlert(alertHandshakeFailure)
        //         return errors.New("tls: initial handshake had non-empty renegotiation extension") }
        if self.clientHello.secureRenegotiation.len() != 0 {
            self.c.sendAlert(super::alert::alertHandshakeFailure);
            return crate::errors::New(
                "tls: initial handshake had non-empty renegotiation extension",
            );
        }

        // Go: (the `earlyData && c.quic != nil` arm cannot occur without
        //      QUIC) } else if hs.clientHello.earlyData {
        //         c.sendAlert(alertUnsupportedExtension)
        //         return errors.New("tls: client sent unexpected early data") }
        if self.clientHello.earlyData {
            self.c.sendAlert(super::alert::alertUnsupportedExtension);
            return crate::errors::New("tls: client sent unexpected early data");
        }

        // Go: hs.hello.sessionId = hs.clientHello.sessionId
        //     hs.hello.compressionMethod = compressionNone
        self.hello.sessionId = self.clientHello.sessionId.clone();
        self.hello.compressionMethod = super::common::compressionNone;

        // Go: preferenceList := defaultCipherSuitesTLS13
        //     if !hasAESGCMHardwareSupport || !isAESGCMPreferred(hs.clientHello.cipherSuites) {
        //         preferenceList = defaultCipherSuitesTLS13NoAES }
        //     if fips140tls.Required() { preferenceList = allowedCipherSuitesTLS13FIPS }
        let mut preferenceList: &[crate::types::uint16] = super::defaults::defaultCipherSuitesTLS13;
        if !super::cipher_suites::hasAESGCMHardwareSupport
            || !super::cipher_suites::isAESGCMPreferred(slice::__from_vec(
                self.clientHello.cipherSuites.clone(),
            ))
        {
            preferenceList = super::defaults::defaultCipherSuitesTLS13NoAES;
        }
        if super::internal::fips140tls::Required() {
            preferenceList = super::defaults_fips140::allowedCipherSuitesTLS13FIPS;
        }
        // Go: for _, suiteID := range preferenceList {
        //         hs.suite = mutualCipherSuiteTLS13(hs.clientHello.cipherSuites, suiteID)
        //         if hs.suite != nil { break } }
        for suiteID in preferenceList {
            self.suite = super::cipher_suites::mutualCipherSuiteTLS13(
                slice::__from_vec(self.clientHello.cipherSuites.clone()),
                *suiteID,
            );
            if self.suite.is_some() {
                break;
            }
        }
        // Go: if hs.suite == nil {
        //         c.sendAlert(alertHandshakeFailure)
        //         return fmt.Errorf("tls: no cipher suite supported by both client and server; client offered: %x", …) }
        if self.suite.is_none() {
            self.c.sendAlert(super::alert::alertHandshakeFailure);
            // Go formats `%x` on a []uint16 as "[13a1 1302 …]".
            // Go formats `%x` on a []uint16 as "[13a1 1302 …]".
            let mut offered: alloc::vec::Vec<byte> = alloc::vec![b'['];
            for (idx, id) in self.clientHello.cipherSuites.iter().enumerate() {
                if idx != 0 {
                    offered.push(b' ');
                }
                let h = crate::fmt::Sprintf!("%x", *id);
                offered.extend_from_slice(h.as_bytes());
            }
            offered.push(b']');
            return crate::fmt::Errorf!(
                "tls: no cipher suite supported by both client and server; client offered: %s",
                crate::gostring::string::from_bytes(&offered)
            );
        }
        let suite = self.suite.unwrap();
        // Go: c.cipherSuite = hs.suite.id
        //     hs.hello.cipherSuite = hs.suite.id
        //     hs.transcript = hs.suite.hash.New()
        self.c.__setCipherSuite(suite.id);
        self.hello.cipherSuite = suite.id;
        self.transcript = Some(super::handshake_messages::transcriptHasher(suite.hash.New()));

        // Go: preferredGroups := c.config.curvePreferences(c.vers)
        //     preferredGroups = slices.DeleteFunc(preferredGroups, func(group CurveID) bool {
        //         return !slices.Contains(hs.clientHello.supportedCurves, group) })
        let clientCurves: slice<super::common::CurveID> = slice::__from_vec(
            self.clientHello
                .supportedCurves
                .iter()
                .map(|v| super::common::CurveID(*v))
                .collect(),
        );
        let mut preferredGroups = crate::slices::DeleteFunc(
            self.c.config.curvePreferences(self.c.__vers()),
            |group: &super::common::CurveID| !crate::slices::Contains(&clientCurves, group),
        );
        // Go: if len(preferredGroups) == 0 {
        //         c.sendAlert(alertHandshakeFailure)
        //         return errors.New("tls: no key exchanges supported by both client and server") }
        if preferredGroups.Len() == 0 {
            self.c.sendAlert(super::alert::alertHandshakeFailure);
            return crate::errors::New(
                "tls: no key exchanges supported by both client and server",
            );
        }
        // Go: hasKeyShare := func(group CurveID) bool { … }
        let keyShares = self.clientHello.keyShares.clone();
        let hasKeyShare = move |group: super::common::CurveID| -> bool {
            for ks in keyShares.iter() {
                if ks.group == group.0 {
                    return true;
                }
            }
            return false;
        };
        // Go: sort.SliceStable(preferredGroups, func(i, j int) bool {
        //         return hasKeyShare(preferredGroups[i]) && !hasKeyShare(preferredGroups[j]) })
        {
            let pg = preferredGroups.clone();
            let hks = hasKeyShare.clone();
            crate::sort::SliceStable(&mut preferredGroups, |i: crate::types::int, j: crate::types::int| {
                hks(pg[i as usize]) && !hks(pg[j as usize])
            });
        }
        // Go: sort.SliceStable(preferredGroups, func(i, j int) bool {
        //         return isPQKeyExchange(preferredGroups[i]) && !isPQKeyExchange(preferredGroups[j]) })
        {
            let pg = preferredGroups.clone();
            crate::sort::SliceStable(&mut preferredGroups, |i: crate::types::int, j: crate::types::int| {
                super::common::isPQKeyExchange(pg[i as usize])
                    && !super::common::isPQKeyExchange(pg[j as usize])
            });
        }
        // Go: selectedGroup := preferredGroups[0]
        let selectedGroup = preferredGroups[0];

        // Go: var clientKeyShare *keyShare
        //     for _, ks := range hs.clientHello.keyShares {
        //         if ks.group == selectedGroup { clientKeyShare = &ks; break } }
        //     if clientKeyShare == nil {
        //         ks, err := hs.doHelloRetryRequest(selectedGroup)
        //         if err != nil { return err }
        //         clientKeyShare = ks }
        let mut clientKeyShare: Option<super::handshake_messages::keyShare> = None;
        for ks in self.clientHello.keyShares.iter() {
            if ks.group == selectedGroup.0 {
                clientKeyShare = Some(ks.clone());
                break;
            }
        }
        let clientKeyShare = match clientKeyShare {
            Some(ks) => ks,
            None => {
                let (ks, err) = self.doHelloRetryRequest(selectedGroup);
                if err != crate::errors::nil {
                    return err;
                }
                ks.unwrap()
            }
        };
        // Go: c.curveID = selectedGroup
        self.c.curveID = selectedGroup;

        // Go: ecdhGroup := selectedGroup; ecdhData := clientKeyShare.data
        //     if selectedGroup == X25519MLKEM768 {
        //         ecdhGroup = X25519
        //         if len(ecdhData) != mlkem.EncapsulationKeySize768+x25519PublicKeySize {
        //             c.sendAlert(alertIllegalParameter)
        //             return errors.New("tls: invalid X25519MLKEM768 client key share") }
        //         ecdhData = ecdhData[mlkem.EncapsulationKeySize768:] }
        let mut ecdhGroup = selectedGroup;
        let mut ecdhData = slice::__from_vec(clientKeyShare.data.clone());
        if selectedGroup == super::common::X25519MLKEM768 {
            ecdhGroup = super::common::X25519;
            if ecdhData.Len()
                != crate::crypto::internal::fips140::mlkem::EncapsulationKeySize768 as crate::types::int
                    + super::key_schedule::x25519PublicKeySize
            {
                self.c.sendAlert(super::alert::alertIllegalParameter);
                return crate::errors::New("tls: invalid X25519MLKEM768 client key share");
            }
            ecdhData = ecdhData.slice(
                crate::crypto::internal::fips140::mlkem::EncapsulationKeySize768 as crate::types::int,
                ecdhData.Len(),
            );
        }
        // Go: if _, ok := curveForCurveID(ecdhGroup); !ok {
        //         c.sendAlert(alertInternalError)
        //         return errors.New("tls: CurvePreferences includes unsupported curve") }
        let (_, ok) = super::key_schedule::curveForCurveID(ecdhGroup);
        if !ok {
            self.c.sendAlert(super::alert::alertInternalError);
            return crate::errors::New(
                "tls: CurvePreferences includes unsupported curve",
            );
        }
        // Go: key, err := generateECDHEKey(c.config.rand(), ecdhGroup)
        //     if err != nil { c.sendAlert(alertInternalError); return err }
        let (key, err) = {
            let mut r = self.c.config.rand();
            super::key_schedule::generateECDHEKey(&mut *r, ecdhGroup)
        };
        if err != crate::errors::nil {
            self.c.sendAlert(super::alert::alertInternalError);
            return err;
        }
        let key = key.unwrap();
        // Go: hs.hello.serverShare = keyShare{group: selectedGroup, data: key.PublicKey().Bytes()}
        self.hello.serverShare = super::handshake_messages::keyShare {
            group: selectedGroup.0,
            data: key.PublicKey().Bytes().__into_vec(),
        };
        // Go: peerKey, err := key.Curve().NewPublicKey(ecdhData)
        //     if err != nil { c.sendAlert(alertIllegalParameter)
        //         return errors.New("tls: invalid client key share") }
        let (peerKey, err) = key.Curve().NewPublicKey(&ecdhData);
        if err != crate::errors::nil {
            self.c.sendAlert(super::alert::alertIllegalParameter);
            return crate::errors::New("tls: invalid client key share");
        }
        // Go: hs.sharedKey, err = key.ECDH(peerKey)
        //     if err != nil { c.sendAlert(alertIllegalParameter)
        //         return errors.New("tls: invalid client key share") }
        let (sharedKey, err) = key.ECDH(&peerKey);
        if err != crate::errors::nil {
            self.c.sendAlert(super::alert::alertIllegalParameter);
            return crate::errors::New("tls: invalid client key share");
        }
        self.sharedKey = sharedKey;
        // Go: if selectedGroup == X25519MLKEM768 {
        //         k, err := mlkem.NewEncapsulationKey768(clientKeyShare.data[:mlkem.EncapsulationKeySize768])
        //         if err != nil { c.sendAlert(alertIllegalParameter)
        //             return errors.New("tls: invalid X25519MLKEM768 client key share") }
        //         mlkemSharedSecret, ciphertext := k.Encapsulate()
        //         hs.sharedKey = append(mlkemSharedSecret, hs.sharedKey...)
        //         hs.hello.serverShare.data = append(ciphertext, hs.hello.serverShare.data...) }
        if selectedGroup == super::common::X25519MLKEM768 {
            let ekBytes = slice::__from_vec(
                clientKeyShare.data
                    [..crate::crypto::internal::fips140::mlkem::EncapsulationKeySize768]
                    .to_vec(),
            );
            let (k, err) =
                crate::crypto::internal::fips140::mlkem::NewEncapsulationKey768(ekBytes);
            if err != crate::errors::nil {
                self.c.sendAlert(super::alert::alertIllegalParameter);
                return crate::errors::New("tls: invalid X25519MLKEM768 client key share");
            }
            let (mlkemSharedSecret, ciphertext) = k.Encapsulate();
            let mut newShared = mlkemSharedSecret.__into_vec();
            newShared.extend_from_slice({
                let raw: &[byte] = &self.sharedKey;
                raw
            });
            self.sharedKey = slice::__from_vec(newShared);
            let mut newData = ciphertext.__into_vec();
            newData.extend_from_slice(&self.hello.serverShare.data);
            self.hello.serverShare.data = newData;
        }

        // Go: selectedProto, err := negotiateALPN(c.config.NextProtos, hs.clientHello.alpnProtocols, c.quic != nil)
        //     if err != nil { c.sendAlert(alertNoApplicationProtocol); return err }
        //     c.clientProtocol = selectedProto
        let clientAlpn: slice<crate::gostring::string> = slice::__from_vec(
            self.clientHello
                .alpnProtocols
                .iter()
                .map(|p| crate::gostring::string::from_bytes(p.as_bytes()))
                .collect(),
        );
        let (selectedProto, err) = super::handshake_server::negotiateALPN(
            self.c.config.NextProtos.clone(),
            clientAlpn,
            false,
        );
        if err != crate::errors::nil {
            self.c.sendAlert(super::alert::alertNoApplicationProtocol);
            return err;
        }
        self.c.__setClientProtocol(selectedProto);

        // Go: (the `c.quic != nil` arm cannot occur) else {
        //         if hs.clientHello.quicTransportParameters != nil {
        //             c.sendAlert(alertUnsupportedExtension)
        //             return errors.New("tls: client sent an unexpected quic_transport_parameters extension") } }
        if self.clientHello.quicTransportParameters.is_some() {
            self.c.sendAlert(super::alert::alertUnsupportedExtension);
            return crate::errors::New(
                "tls: client sent an unexpected quic_transport_parameters extension",
            );
        }

        // Go: c.serverName = hs.clientHello.serverName
        //     return nil
        self.c.serverName =
            crate::gostring::string::from_bytes(self.clientHello.serverName.as_bytes());
        return crate::errors::nil;
    }

    // go: sdk 1.25.5 crypto/tls/handshake_server_tls13.go:730-833 serverHandshakeStateTLS13.sendServerParameters
    /// Go: write the ServerHello (computing the ECH acceptance
    /// confirmation into its random if ECH was accepted), switch both
    /// halves to the handshake traffic secrets, and send
    /// EncryptedExtensions.
    ///
    /// Deviations: the two `c.quic != nil` arms are absent — goish ships
    /// no QUIC transport — and `clientHelloInfo` takes no
    /// `context.Context`, per its own note.
    pub(crate) fn sendServerParameters(&mut self) -> crate::error {
        use crate::goslice::slice;
        let suite = self.suite.unwrap();

        // Go: if hs.echContext != nil {
        if self.echContext.is_some() {
            // Go: copy(hs.hello.random[32-8:], make([]byte, 8))
            let mut i: usize = 24;
            while i < 32 {
                self.hello.random[i] = 0;
                i += 1;
            }
            // Go: echTranscript := cloneHash(hs.transcript, hs.suite.hash)
            //     echTranscript.Write(hs.clientHello.original)
            //     if err := transcriptMsg(hs.hello, echTranscript); err != nil { return err }
            let mut echTranscript = super::handshake_messages::transcriptHasher(
                cloneHash(&*self.transcript.as_ref().unwrap().0, suite.hash).unwrap(),
            );
            crate::io::Writer::Write(
                &mut echTranscript,
                slice::__from_vec(self.clientHello.original.clone()),
            );
            let err =
                super::handshake_messages::transcriptMsg(&self.hello, &mut echTranscript);
            if err != crate::errors::nil {
                return err;
            }
            // Go: "compute the acceptance message"
            //     h := hs.suite.hash.New
            //     prk, err := hkdf.Extract(h, hs.clientHello.random, nil)
            let hash = suite.hash;
            let h = crate::hash::HashFunc::New(move || hash.New());
            let (prk, err) = crate::crypto::hkdf::Extract(
                h.clone(),
                slice::__from_vec(self.clientHello.random.clone()),
                slice::new(),
            );
            if err != crate::errors::nil {
                self.c.sendAlert(super::alert::alertInternalError);
                return err;
            }
            // Go: acceptConfirmation := tls13.ExpandLabel(h, prk,
            //         "ech accept confirmation", echTranscript.Sum(nil), 8)
            //     copy(hs.hello.random[32-8:], acceptConfirmation)
            let acceptConfirmation = crate::crypto::internal::fips140::tls13::ExpandLabel(
                h,
                prk,
                "ech accept confirmation",
                crate::hash::Hash::Sum(&*echTranscript.0, slice::new()),
                8,
            );
            let mut i: usize = 0;
            while i < 8 {
                self.hello.random[24 + i] = acceptConfirmation[i];
                i += 1;
            }
        }

        // Go: if err := transcriptMsg(hs.clientHello, hs.transcript); err != nil { return err }
        let err = {
            let transcript = self.transcript.as_mut().unwrap();
            super::handshake_messages::transcriptMsg(&self.clientHello, transcript)
        };
        if err != crate::errors::nil {
            return err;
        }

        // Go: if _, err := hs.c.writeHandshakeRecord(hs.hello, hs.transcript); err != nil { return err }
        let (_, err) = {
            let transcript = self.transcript.as_mut().unwrap();
            self.c.writeHandshakeRecord(&self.hello, Some(transcript))
        };
        if err != crate::errors::nil {
            return err;
        }

        // Go: if err := hs.sendDummyChangeCipherSpec(); err != nil { return err }
        let err = self.sendDummyChangeCipherSpec();
        if err != crate::errors::nil {
            return err;
        }

        // Go: earlySecret := hs.earlySecret
        //     if earlySecret == nil { earlySecret = tls13.NewEarlySecret(hs.suite.hash.New, nil) }
        //     hs.handshakeSecret = earlySecret.HandshakeSecret(hs.sharedKey)
        let hash = suite.hash;
        self.handshakeSecret = Some(match self.earlySecret.as_ref() {
            Some(earlySecret) => earlySecret.HandshakeSecret(self.sharedKey.clone()),
            None => crate::crypto::internal::fips140::tls13::NewEarlySecret(
                crate::hash::HashFunc::New(move || hash.New()),
                slice::new(),
            )
            .HandshakeSecret(self.sharedKey.clone()),
        });

        // Go: clientSecret := hs.handshakeSecret.ClientHandshakeTrafficSecret(hs.transcript)
        //     c.in.setTrafficSecret(hs.suite, QUICEncryptionLevelHandshake, clientSecret)
        //     serverSecret := hs.handshakeSecret.ServerHandshakeTrafficSecret(hs.transcript)
        //     c.out.setTrafficSecret(hs.suite, QUICEncryptionLevelHandshake, serverSecret)
        let (clientSecret, serverSecret) = {
            let transcript = self.transcript.as_ref().unwrap();
            let hsSecret = self.handshakeSecret.as_ref().unwrap();
            (
                hsSecret.ClientHandshakeTrafficSecret(&*transcript.0),
                hsSecret.ServerHandshakeTrafficSecret(&*transcript.0),
            )
        };
        self.c.in_.setTrafficSecret(
            suite,
            super::quic::QUICEncryptionLevelHandshake,
            clientSecret.clone(),
        );
        self.c.out.setTrafficSecret(
            suite,
            super::quic::QUICEncryptionLevelHandshake,
            serverSecret.clone(),
        );

        // Go: err := c.config.writeKeyLog(keyLogLabelClientHandshake, hs.clientHello.random, clientSecret)
        //     if err != nil { c.sendAlert(alertInternalError); return err }
        let clientHelloRandom = slice::__from_vec(self.clientHello.random.clone());
        let err = self.c.config.writeKeyLog(
            crate::gostring::string::from_static(super::common::keyLogLabelClientHandshake),
            clientHelloRandom.clone(),
            clientSecret,
        );
        if err != crate::errors::nil {
            self.c.sendAlert(super::alert::alertInternalError);
            return err;
        }
        // Go: err = c.config.writeKeyLog(keyLogLabelServerHandshake, hs.clientHello.random, serverSecret)
        //     if err != nil { c.sendAlert(alertInternalError); return err }
        let err = self.c.config.writeKeyLog(
            crate::gostring::string::from_static(super::common::keyLogLabelServerHandshake),
            clientHelloRandom,
            serverSecret,
        );
        if err != crate::errors::nil {
            self.c.sendAlert(super::alert::alertInternalError);
            return err;
        }

        // Go: encryptedExtensions := new(encryptedExtensionsMsg)
        //     encryptedExtensions.alpnProtocol = c.clientProtocol
        let mut encryptedExtensions =
            super::handshake_messages::encryptedExtensionsMsg::default();
        encryptedExtensions.alpnProtocol = match core::str::from_utf8(self.c.clientProtocol.as_bytes()) {
            Ok(p) => p.into(),
            Err(_) => Default::default(),
        };

        // Go: if !hs.c.didResume && hs.clientHello.serverName != "" {
        //         encryptedExtensions.serverNameAck = true }
        if !self.c.didResume && !self.clientHello.serverName.is_empty() {
            encryptedExtensions.serverNameAck = true;
        }

        // Go: "If client sent ECH extension, but we didn't accept it,
        //      send retry configs, if available."
        //     echKeys := hs.c.config.EncryptedClientHelloKeys
        //     if hs.c.config.GetEncryptedClientHelloKeys != nil {
        //         echKeys, err = hs.c.config.GetEncryptedClientHelloKeys(clientHelloInfo(hs.ctx, c, hs.clientHello)) }
        let mut echKeys = self.c.config.EncryptedClientHelloKeys.clone();
        if let Some(get) = self.c.config.GetEncryptedClientHelloKeys.clone() {
            let (keys, err) = get(super::handshake_server::clientHelloInfo(
                &self.c,
                &self.clientHello,
            ));
            if err != crate::errors::nil {
                self.c.sendAlert(super::alert::alertInternalError);
                return err;
            }
            echKeys = keys;
        }
        // Go: if len(echKeys) > 0 && len(hs.clientHello.encryptedClientHello) > 0 && hs.echContext == nil {
        //         encryptedExtensions.echRetryConfigs, err = buildRetryConfigList(echKeys) }
        if echKeys.Len() > 0
            && self.clientHello.encryptedClientHello.len() > 0
            && self.echContext.is_none()
        {
            let (retryConfigs, err) = super::ech::buildRetryConfigList(echKeys);
            if err != crate::errors::nil {
                self.c.sendAlert(super::alert::alertInternalError);
                return err;
            }
            encryptedExtensions.echRetryConfigs = retryConfigs.__into_vec();
        }

        // Go: if _, err := hs.c.writeHandshakeRecord(encryptedExtensions, hs.transcript); err != nil { return err }
        let (_, err) = {
            let transcript = self.transcript.as_mut().unwrap();
            self.c.writeHandshakeRecord(&encryptedExtensions, Some(transcript))
        };
        if err != crate::errors::nil {
            return err;
        }

        // Go: return nil
        return crate::errors::nil;
    }

    // go: sdk 1.25.5 crypto/tls/handshake_server_tls13.go:906-956 serverHandshakeStateTLS13.sendServerFinished
    /// Go: send Finished, advance the key schedule to the master secret,
    /// switch the write half to the application traffic secret, and — if
    /// no client certificate was requested — roll the transcript forward
    /// and send session tickets in the same first flight.
    ///
    /// Deviation: the `c.quic != nil` arm is absent — goish ships no
    /// QUIC transport.
    pub(crate) fn sendServerFinished(&mut self) -> crate::error {
        let suite = self.suite.unwrap();

        // Go: finished := &finishedMsg{
        //         verifyData: hs.suite.finishedHash(c.out.trafficSecret, hs.transcript) }
        let mut finished = super::handshake_messages::finishedMsg::default();
        finished.verifyData = suite
            .finishedHash(
                self.c.out.trafficSecret.clone(),
                &*self.transcript.as_ref().unwrap().0,
            )
            .__into_vec();

        // Go: if _, err := hs.c.writeHandshakeRecord(finished, hs.transcript); err != nil { return err }
        let (_, err) = {
            let transcript = self.transcript.as_mut().unwrap();
            self.c.writeHandshakeRecord(&finished, Some(transcript))
        };
        if err != crate::errors::nil {
            return err;
        }

        // Go: "Derive secrets that take context through the server Finished."
        //     hs.masterSecret = hs.handshakeSecret.MasterSecret()
        self.masterSecret = Some(self.handshakeSecret.as_ref().unwrap().MasterSecret());

        // Go: hs.trafficSecret = hs.masterSecret.ClientApplicationTrafficSecret(hs.transcript)
        //     serverSecret := hs.masterSecret.ServerApplicationTrafficSecret(hs.transcript)
        //     c.out.setTrafficSecret(hs.suite, QUICEncryptionLevelApplication, serverSecret)
        let serverSecret = {
            let transcript = self.transcript.as_ref().unwrap();
            let masterSecret = self.masterSecret.as_ref().unwrap();
            self.trafficSecret =
                masterSecret.ClientApplicationTrafficSecret(&*transcript.0);
            masterSecret.ServerApplicationTrafficSecret(&*transcript.0)
        };
        self.c.out.setTrafficSecret(
            suite,
            super::quic::QUICEncryptionLevelApplication,
            serverSecret.clone(),
        );

        // Go: err := c.config.writeKeyLog(keyLogLabelClientTraffic, hs.clientHello.random, hs.trafficSecret)
        //     if err != nil { c.sendAlert(alertInternalError); return err }
        let clientHelloRandom =
            crate::goslice::slice::__from_vec(self.clientHello.random.clone());
        let err = self.c.config.writeKeyLog(
            crate::gostring::string::from_static(super::common::keyLogLabelClientTraffic),
            clientHelloRandom.clone(),
            self.trafficSecret.clone(),
        );
        if err != crate::errors::nil {
            self.c.sendAlert(super::alert::alertInternalError);
            return err;
        }
        // Go: err = c.config.writeKeyLog(keyLogLabelServerTraffic, hs.clientHello.random, serverSecret)
        //     if err != nil { c.sendAlert(alertInternalError); return err }
        let err = self.c.config.writeKeyLog(
            crate::gostring::string::from_static(super::common::keyLogLabelServerTraffic),
            clientHelloRandom,
            serverSecret,
        );
        if err != crate::errors::nil {
            self.c.sendAlert(super::alert::alertInternalError);
            return err;
        }

        // Go: c.ekm = hs.suite.exportKeyingMaterial(hs.masterSecret, hs.transcript)
        self.c.ekm = Some(suite.exportKeyingMaterial(
            self.masterSecret.as_ref().unwrap(),
            &*self.transcript.as_ref().unwrap().0,
        ));

        // Go: "If we did not request client certificates, at this point we
        //      can precompute the client finished and roll the transcript
        //      forward to send session tickets in our first flight."
        //     if !hs.requestClientCert() {
        //         if err := hs.sendSessionTickets(); err != nil { return err } }
        if !self.requestClientCert() {
            let err = self.sendSessionTickets();
            if err != crate::errors::nil {
                return err;
            }
        }

        // Go: return nil
        return crate::errors::nil;
    }

    // go: sdk 1.25.5 crypto/tls/handshake_server_tls13.go:972-990 serverHandshakeStateTLS13.sendSessionTickets
    /// Go: precompute the client Finished, roll it into the transcript,
    /// derive the resumption secret, and send a ticket if the client
    /// would use one.
    pub(crate) fn sendSessionTickets(&mut self) -> crate::error {
        let suite = self.suite.unwrap();

        // Go: hs.clientFinished = hs.suite.finishedHash(c.in.trafficSecret, hs.transcript)
        //     finishedMsg := &finishedMsg{ verifyData: hs.clientFinished }
        self.clientFinished = suite.finishedHash(
            self.c.in_.trafficSecret.clone(),
            &*self.transcript.as_ref().unwrap().0,
        );
        let mut finishedMsg = super::handshake_messages::finishedMsg::default();
        finishedMsg.verifyData = self.clientFinished.clone().__into_vec();

        // Go: if err := transcriptMsg(finishedMsg, hs.transcript); err != nil { return err }
        let err = {
            let transcript = self.transcript.as_mut().unwrap();
            super::handshake_messages::transcriptMsg(&finishedMsg, transcript)
        };
        if err != crate::errors::nil {
            return err;
        }

        // Go: c.resumptionSecret = hs.masterSecret.ResumptionMasterSecret(hs.transcript)
        self.c.resumptionSecret = self
            .masterSecret
            .as_ref()
            .unwrap()
            .ResumptionMasterSecret(&*self.transcript.as_ref().unwrap().0);

        // Go: if !hs.shouldSendSessionTickets() { return nil }
        if !self.shouldSendSessionTickets() {
            return crate::errors::nil;
        }
        // Go: return c.sendSessionTicket(false, nil)
        return self
            .c
            .sendSessionTicket(false, crate::goslice::slice::new());
    }
}

use super::conn::Conn;

impl Conn {
    // go: sdk 1.25.5 crypto/tls/handshake_server_tls13.go:991-1045 Conn.sendSessionTicket
    /// Go: "ticket_nonce, which must be unique per connection, is always
    /// left at zero because we only ever send one ticket per connection."
    ///
    /// Go passes `extra [][]byte` with nil meaning none; goish spells
    /// that as an empty slice.
    pub(crate) fn sendSessionTicket(
        &mut self,
        earlyData: bool,
        extra: crate::goslice::slice<crate::goslice::slice<crate::types::byte>>,
    ) -> crate::error {
        use crate::goslice::slice;
        // Go: suite := cipherSuiteTLS13ByID(c.cipherSuite)
        //     if suite == nil { return errors.New("tls: internal error: unknown cipher suite") }
        let suite = match super::cipher_suites::cipherSuiteTLS13ByID(self.cipherSuite) {
            Some(s) => s,
            None => {
                return crate::errors::New("tls: internal error: unknown cipher suite")
            }
        };
        // Go: psk := tls13.ExpandLabel(suite.hash.New, c.resumptionSecret,
        //         "resumption", nil, suite.hash.Size())
        let hash = suite.hash;
        let psk = crate::crypto::internal::fips140::tls13::ExpandLabel(
            crate::hash::HashFunc::New(move || hash.New()),
            self.resumptionSecret.clone(),
            "resumption",
            slice::new(),
            suite.hash.Size(),
        );

        // Go: m := new(newSessionTicketMsgTLS13)
        let mut m = super::handshake_messages::newSessionTicketMsgTLS13::default();

        // Go: state := c.sessionState()
        //     state.secret = psk
        //     state.EarlyData = earlyData
        //     state.Extra = extra
        let mut state = self.sessionState();
        state.secret = psk;
        state.EarlyData = earlyData;
        state.Extra = extra;
        // Go: if c.config.WrapSession != nil {
        //         m.label, err = c.config.WrapSession(c.connectionStateLocked(), state)
        //         if err != nil { return err }
        //     } else {
        //         stateBytes, err := state.Bytes()
        //         if err != nil { c.sendAlert(alertInternalError); return err }
        //         m.label, err = c.config.encryptTicket(stateBytes, c.ticketKeys)
        //         if err != nil { return err }
        //     }
        if let Some(wrap) = self.config.WrapSession.clone() {
            let (label, err) = wrap(self.connectionStateLocked(), state);
            if err != crate::errors::nil {
                return err;
            }
            m.label = label;
        } else {
            let (stateBytes, err) = state.Bytes();
            if err != crate::errors::nil {
                self.sendAlert(super::alert::alertInternalError);
                return err;
            }
            let (label, err) = self
                .config
                .encryptTicket(stateBytes, self.ticketKeys.clone());
            if err != crate::errors::nil {
                return err;
            }
            m.label = label;
        }
        // Go: m.lifetime = uint32(maxSessionTicketLifetime / time.Second)
        m.lifetime = crate::uint32(
            (super::common::maxSessionTicketLifetime / crate::time::Second).0,
        );

        // Go: "ticket_age_add is a random 32-bit value. See RFC 8446,
        //      section 4.6.1. The value is not stored anywhere; we never
        //      need to check the ticket age because 0-RTT is not
        //      supported."
        //     ageAdd := make([]byte, 4)
        //     if _, err := c.config.rand().Read(ageAdd); err != nil { return err }
        //     m.ageAdd = byteorder.LEUint32(ageAdd)
        let mut ageAdd: slice<crate::types::byte> =
            slice::__from_vec(alloc::vec![0u8; 4]);
        let mut r = self.config.rand();
        let (_, err) = r.Read(&mut ageAdd);
        if err != crate::errors::nil {
            return err;
        }
        m.ageAdd = crate::internal::byteorder::LEUint32(ageAdd);

        // Go: if earlyData {
        //         // RFC 9001, Section 4.6.1
        //         m.maxEarlyData = 0xffffffff }
        if earlyData {
            m.maxEarlyData = 0xffffffff;
        }

        // Go: if _, err := c.writeHandshakeRecord(m, nil); err != nil { return err }
        let (_, err) = self.writeHandshakeRecord(&m, None);
        if err != crate::errors::nil {
            return err;
        }

        // Go: return nil
        return crate::errors::nil;
    }
}

// go: sdk 1.25.5 crypto/tls/handshake_server_tls13.go:28-31 maxClientPSKIdentities
/// Go: "maxClientPSKIdentities is the number of client PSK identities
/// the server will attempt to validate. It will ignore the rest not to
/// let cheap ClientHello messages cause too much work in session ticket
/// decryption attempts."
pub(crate) const maxClientPSKIdentities: crate::types::int = 5;

impl serverHandshakeStateTLS13 {
    // go: sdk 1.25.5 crypto/tls/handshake_server_tls13.go:331-471 serverHandshakeStateTLS13.checkForResumption
    /// Go: walk the client's PSK identities, decrypt or unwrap each
    /// ticket, vet the recovered session against the config, verify the
    /// PSK binder over the binder-less ClientHello, and adopt the first
    /// identity that survives.
    ///
    /// Deviation: the two `c.quic != nil` arms — session events and the
    /// 0-RTT early traffic secret — are absent; goish ships no QUIC
    /// transport.
    pub(crate) fn checkForResumption(&mut self) -> crate::error {
        use crate::goslice::slice;
        let suite = self.suite.unwrap();

        // Go: if c.config.SessionTicketsDisabled { return nil }
        if self.c.config.SessionTicketsDisabled {
            return crate::errors::nil;
        }

        // Go: modeOK := false
        //     for _, mode := range hs.clientHello.pskModes {
        //         if mode == pskModeDHE { modeOK = true; break } }
        //     if !modeOK { return nil }
        let mut modeOK = false;
        for mode in self.clientHello.pskModes.iter() {
            if *mode == super::common::pskModeDHE {
                modeOK = true;
                break;
            }
        }
        if !modeOK {
            return crate::errors::nil;
        }

        // Go: if len(hs.clientHello.pskIdentities) != len(hs.clientHello.pskBinders) {
        //         c.sendAlert(alertIllegalParameter)
        //         return errors.New("tls: invalid or missing PSK binders") }
        if self.clientHello.pskIdentities.len() != self.clientHello.pskBinders.len() {
            self.c.sendAlert(super::alert::alertIllegalParameter);
            return crate::errors::New("tls: invalid or missing PSK binders");
        }
        // Go: if len(hs.clientHello.pskIdentities) == 0 { return nil }
        if self.clientHello.pskIdentities.len() == 0 {
            return crate::errors::nil;
        }

        // Go: for i, identity := range hs.clientHello.pskIdentities {
        let mut i: usize = 0;
        while i < self.clientHello.pskIdentities.len() {
            // Go: if i >= maxClientPSKIdentities { break }
            if crate::int(i) >= maxClientPSKIdentities {
                break;
            }
            let identityLabel =
                slice::__from_vec(self.clientHello.pskIdentities[i].label.clone());

            // Go: var sessionState *SessionState
            //     if c.config.UnwrapSession != nil {
            //         sessionState, err = c.config.UnwrapSession(identity.label, c.connectionStateLocked())
            //         if err != nil { return err }
            //         if sessionState == nil { continue }
            //     } else {
            //         plaintext := c.config.decryptTicket(identity.label, c.ticketKeys)
            //         if plaintext == nil { continue }
            //         sessionState, err = ParseSessionState(plaintext)
            //         if err != nil { continue }
            //     }
            let sessionState;
            if let Some(unwrap) = self.c.config.UnwrapSession.clone() {
                let (ss, err) = unwrap(identityLabel, self.c.connectionStateLocked());
                if err != crate::errors::nil {
                    return err;
                }
                match ss {
                    None => {
                        i += 1;
                        continue;
                    }
                    Some(ss) => sessionState = ss,
                }
            } else {
                let plaintext = self
                    .c
                    .config
                    .decryptTicket(identityLabel, self.c.ticketKeys.clone());
                let plaintext = match plaintext {
                    None => {
                        i += 1;
                        continue;
                    }
                    Some(p) => p,
                };
                let (ss, err) = super::ticket::ParseSessionState(plaintext);
                if err != crate::errors::nil {
                    i += 1;
                    continue;
                }
                sessionState = ss;
            }

            // Go: if sessionState.version != VersionTLS13 { continue }
            if sessionState.version != super::common::VersionTLS13 {
                i += 1;
                continue;
            }

            // Go: createdAt := time.Unix(int64(sessionState.createdAt), 0)
            //     if c.config.time().Sub(createdAt) > maxSessionTicketLifetime { continue }
            let createdAt = crate::time::Unix(crate::int64(sessionState.createdAt), 0);
            if self.c.config.time().Sub(createdAt) > super::common::maxSessionTicketLifetime {
                i += 1;
                continue;
            }

            // Go: pskSuite := cipherSuiteTLS13ByID(sessionState.cipherSuite)
            //     if pskSuite == nil || pskSuite.hash != hs.suite.hash { continue }
            let pskSuite =
                super::cipher_suites::cipherSuiteTLS13ByID(sessionState.cipherSuite);
            match pskSuite {
                None => {
                    i += 1;
                    continue;
                }
                Some(ps) => {
                    if ps.hash != suite.hash {
                        i += 1;
                        continue;
                    }
                }
            }

            // Go: "PSK connections don't re-establish client certificates, but
            //      carry them over in the session ticket. Ensure the presence
            //      of client certs in the ticket is consistent with the
            //      configured requirements."
            let sessionHasClientCerts = sessionState.peerCertificates.Len() != 0;
            let needClientCerts =
                super::common::requiresClientCert(self.c.config.ClientAuth);
            if needClientCerts && !sessionHasClientCerts {
                i += 1;
                continue;
            }
            if sessionHasClientCerts
                && self.c.config.ClientAuth == super::common::NoClientCert
            {
                i += 1;
                continue;
            }
            if sessionHasClientCerts
                && self
                    .c
                    .config
                    .time()
                    .After(sessionState.peerCertificates[0].NotAfter)
            {
                i += 1;
                continue;
            }
            if sessionHasClientCerts
                && self.c.config.ClientAuth >= super::common::VerifyClientCertIfGiven
                && sessionState.verifiedChains.Len() == 0
            {
                i += 1;
                continue;
            }

            // Go: hs.earlySecret = tls13.NewEarlySecret(hs.suite.hash.New, sessionState.secret)
            //     binderKey := hs.earlySecret.ResumptionBinderKey()
            let hash = suite.hash;
            self.earlySecret = Some(crate::crypto::internal::fips140::tls13::NewEarlySecret(
                crate::hash::HashFunc::New(move || hash.New()),
                sessionState.secret.clone(),
            ));
            let binderKey = self.earlySecret.as_ref().unwrap().ResumptionBinderKey();
            // Go: "Clone the transcript in case a HelloRetryRequest was recorded."
            //     transcript := cloneHash(hs.transcript, hs.suite.hash)
            //     if transcript == nil { c.sendAlert(alertInternalError)
            //         return errors.New("tls: internal error: failed to clone hash") }
            let transcript =
                cloneHash(&*self.transcript.as_ref().unwrap().0, suite.hash);
            let mut transcript = match transcript {
                None => {
                    self.c.sendAlert(super::alert::alertInternalError);
                    return crate::errors::New(
                        "tls: internal error: failed to clone hash",
                    );
                }
                Some(t) => super::handshake_messages::transcriptHasher(t),
            };
            // Go: clientHelloBytes, err := hs.clientHello.marshalWithoutBinders()
            //     if err != nil { c.sendAlert(alertInternalError); return err }
            let (clientHelloBytes, err) = self.clientHello.marshalWithoutBinders();
            if err != crate::errors::nil {
                self.c.sendAlert(super::alert::alertInternalError);
                return err;
            }
            // Go: transcript.Write(clientHelloBytes)
            //     pskBinder := hs.suite.finishedHash(binderKey, transcript)
            //     if !hmac.Equal(hs.clientHello.pskBinders[i], pskBinder) {
            //         c.sendAlert(alertDecryptError)
            //         return errors.New("tls: invalid PSK binder") }
            crate::io::Writer::Write(&mut transcript, clientHelloBytes);
            let pskBinder = suite.finishedHash(binderKey, &*transcript.0);
            if !crate::crypto::hmac::Equal(
                slice::__from_vec(self.clientHello.pskBinders[i].clone()),
                pskBinder,
            ) {
                self.c.sendAlert(super::alert::alertDecryptError);
                return crate::errors::New("tls: invalid PSK binder");
            }

            // Go: c.didResume = true
            //     c.peerCertificates = sessionState.peerCertificates
            //     c.ocspResponse = sessionState.ocspResponse
            //     c.scts = sessionState.scts
            //     c.verifiedChains = sessionState.verifiedChains
            self.c.didResume = true;
            self.c.peerCertificates = sessionState.peerCertificates.clone();
            self.c.ocspResponse = sessionState.ocspResponse.clone();
            self.c.scts = sessionState.scts.clone();
            self.c.verifiedChains = sessionState.verifiedChains.clone();

            // Go: hs.hello.selectedIdentityPresent = true
            //     hs.hello.selectedIdentity = uint16(i)
            //     hs.usingPSK = true
            //     return nil
            self.hello.selectedIdentityPresent = true;
            self.hello.selectedIdentity = crate::uint16(crate::int(i));
            self.usingPSK = true;
            return crate::errors::nil;
        }

        // Go: return nil
        return crate::errors::nil;
    }

    // go: sdk 1.25.5 crypto/tls/handshake_server_tls13.go:547-673 serverHandshakeStateTLS13.doHelloRetryRequest
    /// Go: "The first ClientHello gets double-hashed into the transcript
    /// upon a HelloRetryRequest. See RFC 8446, Section 4.4.1." Sends the
    /// HRR, reads the second ClientHello, unwraps its ECH if one is in
    /// flight, and vets it against the first.
    pub(crate) fn doHelloRetryRequest(
        &mut self,
        selectedGroup: super::common::CurveID,
    ) -> (Option<super::handshake_messages::keyShare>, crate::error) {
        use crate::goslice::slice;
        let suite = self.suite.unwrap();

        // Go: if err := transcriptMsg(hs.clientHello, hs.transcript); err != nil { return nil, err }
        //     chHash := hs.transcript.Sum(nil)
        //     hs.transcript.Reset()
        //     hs.transcript.Write([]byte{typeMessageHash, 0, 0, uint8(len(chHash))})
        //     hs.transcript.Write(chHash)
        let err = {
            let transcript = self.transcript.as_mut().unwrap();
            super::handshake_messages::transcriptMsg(&self.clientHello, transcript)
        };
        if err != crate::errors::nil {
            return (None, err);
        }
        {
            let transcript = self.transcript.as_mut().unwrap();
            let chHash = crate::hash::Hash::Sum(&*transcript.0, slice::new());
            crate::hash::Hash::Reset(&mut *transcript.0);
            crate::io::Writer::Write(
                transcript,
                slice::__from_vec(alloc::vec![
                    super::handshake_messages::typeMessageHash,
                    0,
                    0,
                    crate::byte(chHash.Len()),
                ]),
            );
            crate::io::Writer::Write(transcript, chHash);
        }

        // Go: helloRetryRequest := &serverHelloMsg{ vers: hs.hello.vers,
        //         random: helloRetryRequestRandom, sessionId: hs.hello.sessionId,
        //         cipherSuite: hs.hello.cipherSuite,
        //         compressionMethod: hs.hello.compressionMethod,
        //         supportedVersion: hs.hello.supportedVersion,
        //         selectedGroup: selectedGroup }
        let mut helloRetryRequest = super::handshake_messages::serverHelloMsg::default();
        helloRetryRequest.vers = self.hello.vers;
        helloRetryRequest.random = super::common::helloRetryRequestRandom.to_vec();
        helloRetryRequest.sessionId = self.hello.sessionId.clone();
        helloRetryRequest.cipherSuite = self.hello.cipherSuite;
        helloRetryRequest.compressionMethod = self.hello.compressionMethod;
        helloRetryRequest.supportedVersion = self.hello.supportedVersion;
        helloRetryRequest.selectedGroup = selectedGroup.0;

        // Go: if hs.echContext != nil {
        if self.echContext.is_some() {
            // Go: "Compute the acceptance message."
            //     helloRetryRequest.encryptedClientHello = make([]byte, 8)
            //     confTranscript := cloneHash(hs.transcript, hs.suite.hash)
            //     if err := transcriptMsg(helloRetryRequest, confTranscript); err != nil { return nil, err }
            helloRetryRequest.encryptedClientHello = alloc::vec![0u8; 8];
            let mut confTranscript = super::handshake_messages::transcriptHasher(
                cloneHash(&*self.transcript.as_ref().unwrap().0, suite.hash).unwrap(),
            );
            let err = super::handshake_messages::transcriptMsg(
                &helloRetryRequest,
                &mut confTranscript,
            );
            if err != crate::errors::nil {
                return (None, err);
            }
            // Go: h := hs.suite.hash.New
            //     prf, err := hkdf.Extract(h, hs.clientHello.random, nil)
            //     if err != nil { c.sendAlert(alertInternalError); return nil, err }
            let hash = suite.hash;
            let h = crate::hash::HashFunc::New(move || hash.New());
            let (prf, err) = crate::crypto::hkdf::Extract(
                h.clone(),
                slice::__from_vec(self.clientHello.random.clone()),
                slice::new(),
            );
            if err != crate::errors::nil {
                self.c.sendAlert(super::alert::alertInternalError);
                return (None, err);
            }
            // Go: acceptConfirmation := tls13.ExpandLabel(h, prf,
            //         "hrr ech accept confirmation", confTranscript.Sum(nil), 8)
            //     helloRetryRequest.encryptedClientHello = acceptConfirmation
            let acceptConfirmation = crate::crypto::internal::fips140::tls13::ExpandLabel(
                h,
                prf,
                "hrr ech accept confirmation",
                crate::hash::Hash::Sum(&*confTranscript.0, slice::new()),
                8,
            );
            helloRetryRequest.encryptedClientHello = acceptConfirmation.__into_vec();
        }

        // Go: if _, err := hs.c.writeHandshakeRecord(helloRetryRequest, hs.transcript); err != nil { return nil, err }
        let (_, err) = {
            let transcript = self.transcript.as_mut().unwrap();
            self.c.writeHandshakeRecord(&helloRetryRequest, Some(transcript))
        };
        if err != crate::errors::nil {
            return (None, err);
        }

        // Go: if err := hs.sendDummyChangeCipherSpec(); err != nil { return nil, err }
        let err = self.sendDummyChangeCipherSpec();
        if err != crate::errors::nil {
            return (None, err);
        }

        // Go: "clientHelloMsg is not included in the transcript."
        //     msg, err := c.readHandshake(nil)
        //     if err != nil { return nil, err }
        let (msg, err) = self.c.readHandshake(None);
        if err != crate::errors::nil {
            return (None, err);
        }
        // Go: clientHello, ok := msg.(*clientHelloMsg)
        //     if !ok { c.sendAlert(alertUnexpectedMessage)
        //         return nil, unexpectedMessageError(clientHello, msg) }
        let msg = match msg {
            Some(m) => m,
            None => {
                return (
                    None,
                    crate::errors::New("tls: internal error: no handshake message"),
                )
            }
        };
        let mut clientHello = match msg
            .asAny()
            .downcast_ref::<super::handshake_messages::clientHelloMsg>()
        {
            Some(ch) => ch.clone(),
            None => {
                self.c.sendAlert(super::alert::alertUnexpectedMessage);
                return (
                    None,
                    super::common::unexpectedMessageError(
                        crate::gostring::string::from_static("*tls.clientHelloMsg"),
                        super::handshake_messages::handshakeMessageTypeName(&*msg),
                    ),
                );
            }
        };

        // Go: if hs.echContext != nil {
        if let Some(echContext) = self.echContext.as_mut() {
            // Go: if len(clientHello.encryptedClientHello) == 0 {
            //         c.sendAlert(alertMissingExtension)
            //         return nil, errors.New("tls: second client hello missing encrypted client hello extension") }
            if clientHello.encryptedClientHello.len() == 0 {
                self.c.sendAlert(super::alert::alertMissingExtension);
                return (
                    None,
                    crate::errors::New(
                        "tls: second client hello missing encrypted client hello extension",
                    ),
                );
            }

            // Go: echType, echCiphersuite, configID, encap, payload, err :=
            //         parseECHExt(clientHello.encryptedClientHello)
            //     if err != nil { c.sendAlert(alertDecodeError)
            //         return nil, errors.New("tls: client sent invalid encrypted client hello extension") }
            let (echType, echCiphersuite, configID, encap, payload, err) =
                super::ech::parseECHExt(slice::__from_vec(
                    clientHello.encryptedClientHello.clone(),
                ));
            if err != crate::errors::nil {
                self.c.sendAlert(super::alert::alertDecodeError);
                return (
                    None,
                    crate::errors::New(
                        "tls: client sent invalid encrypted client hello extension",
                    ),
                );
            }

            // Go: if echType == outerECHExt && hs.echContext.inner ||
            //        echType == innerECHExt && !hs.echContext.inner {
            //         c.sendAlert(alertDecodeError)
            //         return nil, errors.New("tls: unexpected switch in encrypted client hello extension type") }
            if echType == super::ech::outerECHExt && echContext.inner
                || echType == super::ech::innerECHExt && !echContext.inner
            {
                self.c.sendAlert(super::alert::alertDecodeError);
                return (
                    None,
                    crate::errors::New(
                        "tls: unexpected switch in encrypted client hello extension type",
                    ),
                );
            }

            // Go: if echType == outerECHExt {
            if echType == super::ech::outerECHExt {
                // Go: if echCiphersuite != hs.echContext.ciphersuite ||
                //        configID != hs.echContext.configID || len(encap) != 0 {
                //         c.sendAlert(alertIllegalParameter)
                //         return nil, errors.New("tls: second client hello encrypted client hello extension does not match") }
                if echCiphersuite != echContext.ciphersuite
                    || configID != echContext.configID
                    || encap.Len() != 0
                {
                    self.c.sendAlert(super::alert::alertIllegalParameter);
                    return (
                        None,
                        crate::errors::New(
                            "tls: second client hello encrypted client hello extension does not match",
                        ),
                    );
                }

                // Go: encodedInner, err := decryptECHPayload(hs.echContext.hpkeContext,
                //         clientHello.original, payload)
                //     if err != nil { c.sendAlert(alertDecryptError)
                //         return nil, errors.New("tls: failed to decrypt second client hello encrypted client hello extension payload") }
                let (encodedInner, err) = super::ech::decryptECHPayload(
                    echContext.hpkeContext.as_mut().unwrap(),
                    slice::__from_vec(clientHello.original.clone()),
                    payload,
                );
                if err != crate::errors::nil {
                    self.c.sendAlert(super::alert::alertDecryptError);
                    return (
                        None,
                        crate::errors::New(
                            "tls: failed to decrypt second client hello encrypted client hello extension payload",
                        ),
                    );
                }

                // Go: echInner, err := decodeInnerClientHello(clientHello, encodedInner)
                //     if err != nil { c.sendAlert(alertIllegalParameter)
                //         return nil, errors.New("tls: client sent invalid encrypted client hello extension") }
                let (echInner, err) =
                    super::ech::decodeInnerClientHello(&clientHello, encodedInner);
                if err != crate::errors::nil {
                    self.c.sendAlert(super::alert::alertIllegalParameter);
                    return (
                        None,
                        crate::errors::New(
                            "tls: client sent invalid encrypted client hello extension",
                        ),
                    );
                }

                // Go: clientHello = echInner
                clientHello = echInner.unwrap();
            }
        }

        // Go: if len(clientHello.keyShares) != 1 {
        //         c.sendAlert(alertIllegalParameter)
        //         return nil, errors.New("tls: client didn't send one key share in second ClientHello") }
        if clientHello.keyShares.len() != 1 {
            self.c.sendAlert(super::alert::alertIllegalParameter);
            return (
                None,
                crate::errors::New(
                    "tls: client didn't send one key share in second ClientHello",
                ),
            );
        }
        // Go: ks := &clientHello.keyShares[0]
        let ks = clientHello.keyShares[0].clone();

        // Go: if ks.group != selectedGroup {
        //         c.sendAlert(alertIllegalParameter)
        //         return nil, errors.New("tls: client sent unexpected key share in second ClientHello") }
        if ks.group != selectedGroup.0 {
            self.c.sendAlert(super::alert::alertIllegalParameter);
            return (
                None,
                crate::errors::New(
                    "tls: client sent unexpected key share in second ClientHello",
                ),
            );
        }

        // Go: if clientHello.earlyData {
        //         c.sendAlert(alertIllegalParameter)
        //         return nil, errors.New("tls: client indicated early data in second ClientHello") }
        if clientHello.earlyData {
            self.c.sendAlert(super::alert::alertIllegalParameter);
            return (
                None,
                crate::errors::New(
                    "tls: client indicated early data in second ClientHello",
                ),
            );
        }

        // Go: if illegalClientHelloChange(clientHello, hs.clientHello) {
        //         c.sendAlert(alertIllegalParameter)
        //         return nil, errors.New("tls: client illegally modified second ClientHello") }
        if illegalClientHelloChange(&clientHello, &self.clientHello) {
            self.c.sendAlert(super::alert::alertIllegalParameter);
            return (
                None,
                crate::errors::New("tls: client illegally modified second ClientHello"),
            );
        }

        // Go: c.didHRR = true
        //     hs.clientHello = clientHello
        //     return ks, nil
        self.c.didHRR = true;
        self.clientHello = clientHello;
        return (Some(ks), crate::errors::nil);
    }
}
