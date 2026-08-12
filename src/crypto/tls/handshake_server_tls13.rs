// crypto/tls/handshake_server_tls13.rs — TLS 1.3 server handshake.
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
    if !client_hello.unmarshal(&ch_bytes) {
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
    let hello_bytes = hello.marshal();
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
    let ee_bytes = ee.marshal();
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
    let cv_bytes = cv.marshal();
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
    let fin_bytes = fin.marshal();
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
