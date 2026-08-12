// crypto/tls/handshake_server_tls13.rs — TLS 1.3 server handshake.
//
// goishlint:ignore GOISH018 handshake, processClientHello, checkForResumption, doHelloRetryRequest, sendServerFinished, sendSessionTickets, sendSessionTicket, readClientCertificate — serverHandshakeStateTLS13's Conn-driven half; the live server below the divider implements the same protocol by hand. See ROADMAP.md.
// goishlint:ignore GOISH021 maxClientPSKIdentities — same.
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
/// present; `ctx` and `masterSecret` land with `handshake`, which
/// drives the whole exchange. `Default` is goish-only, standing in for
/// Go's zero value so test shims spell only the fields they set.
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
}
