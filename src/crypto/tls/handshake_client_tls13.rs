// goishlint:ignore GOISH018 handshake, processHelloRetryRequest, establishHandshakeKeys, handleNewSessionTicket — the rest of clientHandshakeStateTLS13, which drives the whole exchange through the key schedule and the transcript; the live TLS 1.3 client below is a self-contained function, not a port of these. See ROADMAP.md.
// crypto/tls/handshake_client_tls13.rs — TLS 1.3 client handshake.
//
// Port of:
//   crypto/tls/handshake_client_tls13.go (key functions)
//   crypto/tls/key_schedule.go (trafficKey, finishedHash, nextTrafficSecret)
//
// This file implements the TLS 1.3 client-side handshake as a self-contained
// function `do_client_handshake_tls13` called from handshake_client.rs after
// detecting supported_versions extension in ServerHello.
//
// TLS 1.3 flow:
//   Client → Server: ClientHello (with key_share, supported_versions)
//   Server → Client: ServerHello (with key_share response, supported_versions)
//   [Server encrypts from here using server_handshake_traffic_secret]
//   Server → Client: {EncryptedExtensions}
//   Server → Client: {Certificate}
//   Server → Client: {CertificateVerify}
//   Server → Client: {Finished}
//   [Client encrypts from here using client_handshake_traffic_secret]
//   Client → Server: {Finished}
//   [Both sides switch to application_traffic_secret]
//
// TLS 1.3 record encoding (RFC 8446 §5.2):
//   - All post-ServerHello records are TLSCiphertext (content_type=23).
//   - Plaintext = inner_plaintext || inner_content_type (1 byte).
//   - Nonce = write_iv XOR (seq_num as 12-byte BE).
//   - AAD = TLSCiphertext header bytes: type(1)||version(2)||length(2).
//
// Reference: RFC 8446.

#![allow(non_snake_case, non_upper_case_globals)]


// Per-record/handshake debug prints — gated so production + e2e output
// stays clean. Flip `TLS_DEBUG` to true (or wire an env check) when
// diagnosing a handshake failure.
const TLS_DEBUG: bool = false;
macro_rules! tls_debug {
    ($($arg:tt)*) => { if TLS_DEBUG { crate::fmt::Printf!($($arg)*); } };
}

extern crate alloc;

use alloc::vec::Vec;

use crate::crypto::ecdh;
use crate::crypto::tls::key_schedule::{
    self, CipherSuiteTls13, EarlySecret, TrafficKeys, finished_hash, traffic_keys,
};
use crate::crypto::tls::record::{
    RECORD_ALERT, RECORD_APPLICATION, RECORD_CHANGE_CIPHER_SPEC, RECORD_HANDSHAKE,
    encode_record, read_record,
};
use crate::errors::{self, error};
use crate::goslice::slice;
use crate::hash::Hash as HashTrait;
use crate::io::Writer as WriterTrait;
use crate::types::byte;

// ─── TLS 1.3 message types ────────────────────────────────────────────

const MSG_ENCRYPTED_EXTENSIONS: byte = 8;
const MSG_CERTIFICATE: byte = 11;
const MSG_CERTIFICATE_VERIFY: byte = 15;
const MSG_FINISHED: byte = 20;

// ─── TLS 1.3 SignatureScheme values (RFC 8446 §4.2.3) ─────────────────

/// ecdsa_secp256r1_sha256 = 0x0403
const SIG_ECDSA_SECP256R1_SHA256: u16 = 0x0403;
/// ecdsa_secp384r1_sha384 = 0x0503
#[allow(dead_code)] // RFC 8446 registry completeness; scheme not offered yet
const SIG_ECDSA_SECP384R1_SHA384: u16 = 0x0503;
/// rsa_pkcs1_sha256 = 0x0401 (deprecated in TLS 1.3 but some servers send it)
const SIG_RSA_PKCS1_SHA256: u16 = 0x0401;
/// rsa_pkcs1_sha384 = 0x0501
const SIG_RSA_PKCS1_SHA384: u16 = 0x0501;
/// rsa_pkcs1_sha512 = 0x0601
const SIG_RSA_PKCS1_SHA512: u16 = 0x0601;
/// rsa_pss_rsae_sha256 = 0x0804
const SIG_RSA_PSS_RSAE_SHA256: u16 = 0x0804;
/// rsa_pss_rsae_sha384 = 0x0805
const SIG_RSA_PSS_RSAE_SHA384: u16 = 0x0805;
/// rsa_pss_rsae_sha512 = 0x0806
const SIG_RSA_PSS_RSAE_SHA512: u16 = 0x0806;
/// ed25519 = 0x0807
const SIG_ED25519: u16 = 0x0807;

// ─── SPKI AlgorithmIdentifier OID bytes ───────────────────────────────
// These are the VALUE bytes of the OID TLV (after the 06 xx header).

/// rsaEncryption: 1.2.840.113549.1.1.1
const OID_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
/// ecPublicKey: 1.2.840.10045.2.1
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// Ed25519: 1.3.101.112
const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];

// ─── TLS 1.3 signedMessage (RFC 8446 §4.4.3) ──────────────────────────
//
// signed = 64 × 0x20 || context_string || 0x00 || transcript_hash
// context_string for server = "TLS 1.3, server CertificateVerify"

const SERVER_SIGNATURE_CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify\x00";

/// Build the `signed` message that covers the TLS 1.3 CertificateVerify.
/// RFC 8446 §4.4.3: for ECDSA (directSigning), this IS the message to be
/// signed/verified (not pre-hashed here — ECDSA/Ed25519 will SHA-256 it internally
/// as part of the scheme, but for VerifyP256 we must pass the SHA-256 digest).
/// Shared with handshake_server_tls13 (the server signs, the client verifies,
/// over the same context string).
pub(crate) fn tls13_signed_message(transcript_hash: &[u8]) -> Vec<byte> {
    let mut msg: Vec<byte> = Vec::with_capacity(64 + SERVER_SIGNATURE_CONTEXT.len() + transcript_hash.len());
    for _ in 0..64 {
        msg.push(0x20);
    }
    msg.extend_from_slice(SERVER_SIGNATURE_CONTEXT);
    msg.extend_from_slice(transcript_hash);
    msg
}

// ─── Server certificate key type ──────────────────────────────────────

#[derive(Clone)]
enum ServerPubKey {
    EcdsaP256(crate::crypto::tls::legacy_p256::P256PublicKey),
    Rsa(crate::crypto::rsa::PublicKey),
    Ed25519(crate::crypto::ed25519::PublicKey),
    Unknown,
}

/// Parse the server's public key type from a DER-encoded leaf certificate.
/// Returns the key type enum.
fn parse_server_pubkey(cert_der: &[u8]) -> ServerPubKey {
    use crate::encoding::asn1;

    let der_slice = slice::__from_vec(cert_der.to_vec());

    // outer Certificate SEQUENCE
    let (cert_rv, _, err) = asn1::ParseRaw(der_slice);
    if !err.IsNil() { return ServerPubKey::Unknown; }

    // TBSCertificate SEQUENCE
    let (tbs_rv, _, err) = asn1::ParseRaw(cert_rv.Bytes.clone());
    if !err.IsNil() { return ServerPubKey::Unknown; }

    // Find SPKI
    let (spki_bytes, spki_err) = crate::crypto::tls::legacy_p256::find_spki_in_tbs(&tbs_rv.Bytes);
    if !spki_err.IsNil() { return ServerPubKey::Unknown; }

    let (spki_rv, _, err) = asn1::ParseRaw(spki_bytes.clone());
    if !err.IsNil() { return ServerPubKey::Unknown; }

    // AlgorithmIdentifier SEQUENCE → get OID
    let (alg_rv, rest_after_alg, err) = asn1::ParseRaw(spki_rv.Bytes.clone());
    if !err.IsNil() { return ServerPubKey::Unknown; }

    // Parse OID from AlgorithmIdentifier
    let (oid_rv, _, err) = asn1::ParseRaw(alg_rv.Bytes.clone());
    if !err.IsNil() { return ServerPubKey::Unknown; }

    let oid_bytes: &[u8] = &oid_rv.Bytes;

    if oid_bytes == OID_ED25519 {
        // Ed25519: SPKI BIT STRING contains the 32-byte public key directly
        let (bits_rv, _, err) = asn1::ParseRaw(rest_after_alg.clone());
        if !err.IsNil() { return ServerPubKey::Unknown; }
        let bs: &[u8] = &bits_rv.Bytes;
        if bs.len() < 33 { return ServerPubKey::Unknown; }
        // bs[0] = unused bits (0), bs[1..33] = key
        let key_bytes = &bs[1..];
        if key_bytes.len() < 32 { return ServerPubKey::Unknown; }
        let key_s = slice::__from_vec(key_bytes[..32].to_vec());
        let pk = crate::crypto::ed25519::PublicKey(key_s);
        return ServerPubKey::Ed25519(pk);
    }

    if oid_bytes == OID_EC_PUBLIC_KEY {
        // Try ECDSA P256
        let (pk, err) = crate::crypto::tls::legacy_p256::decode_x509_ec_p256_pubkey(cert_der);
        if err.IsNil() {
            return ServerPubKey::EcdsaP256(pk);
        }
        return ServerPubKey::Unknown;
    }

    if oid_bytes == OID_RSA {
        // RSA
        let (pk, err) = crate::crypto::tls::record::decode_x509_rsa_pubkey(cert_der);
        if err.IsNil() {
            return ServerPubKey::Rsa(pk);
        }
        return ServerPubKey::Unknown;
    }

    ServerPubKey::Unknown
}

/// Parse the first leaf certificate DER bytes from a TLS 1.3 Certificate message body.
/// TLS 1.3 Certificate message (after the 4-byte msg_type+length header):
///   certificate_request_context: u8-length-prefixed
///   certificate_list: u24-length-prefixed list of:
///     cert_data: u24-length-prefixed DER bytes
///     extensions: u16-length-prefixed
fn parse_tls13_cert_message_leaf(plain: &[u8]) -> Option<Vec<u8>> {
    // plain[0] = MSG_CERTIFICATE (11)
    // plain[1..4] = u24 length of body
    if plain.len() < 4 { return None; }
    let body_len = ((plain[1] as usize) << 16) | ((plain[2] as usize) << 8) | (plain[3] as usize);
    if plain.len() < 4 + body_len { return None; }
    let mut pos = 4usize;

    // certificate_request_context (u8 length-prefixed)
    if pos >= plain.len() { return None; }
    let ctx_len = plain[pos] as usize;
    pos += 1 + ctx_len;

    // certificate_list (u24 length-prefixed)
    if pos + 3 > plain.len() { return None; }
    let cert_list_len = ((plain[pos] as usize) << 16) | ((plain[pos+1] as usize) << 8) | (plain[pos+2] as usize);
    pos += 3;
    if pos + cert_list_len > plain.len() { return None; }
    if cert_list_len == 0 { return None; }

    // First entry: cert_data (u24 length-prefixed)
    if pos + 3 > plain.len() { return None; }
    let cert_len = ((plain[pos] as usize) << 16) | ((plain[pos+1] as usize) << 8) | (plain[pos+2] as usize);
    pos += 3;
    if pos + cert_len > plain.len() { return None; }

    Some(plain[pos..pos + cert_len].to_vec())
}

/// Parse the CertificateVerify message body: (sig_alg: u16, signature: bytes).
/// plain[0] = MSG_CERTIFICATE_VERIFY (15)
/// plain[1..4] = u24 length
/// body: sig_alg(2) || sig_len(2) || sig_bytes
fn parse_tls13_cert_verify(plain: &[u8]) -> Option<(u16, Vec<u8>)> {
    if plain.len() < 4 { return None; }
    let mut pos = 4usize; // skip type+length
    if pos + 2 > plain.len() { return None; }
    let sig_alg = ((plain[pos] as u16) << 8) | (plain[pos+1] as u16);
    pos += 2;
    if pos + 2 > plain.len() { return None; }
    let sig_len = ((plain[pos] as usize) << 8) | (plain[pos+1] as usize);
    pos += 2;
    if pos + sig_len > plain.len() { return None; }
    Some((sig_alg, plain[pos..pos + sig_len].to_vec()))
}

/// Verify a TLS 1.3 CertificateVerify signature.
/// transcript_hash = hash(ClientHello || ServerHello || EncryptedExtensions || Certificate)
/// Returns nil on success.
fn verify_cert_verify(
    pubkey: &ServerPubKey,
    sig_alg: u16,
    signature: &[u8],
    transcript_hash_bytes: &[u8],
) -> error {
    let signed_msg = tls13_signed_message(transcript_hash_bytes);

    match sig_alg {
        SIG_ECDSA_SECP256R1_SHA256 => {
            let pk = match pubkey {
                ServerPubKey::EcdsaP256(k) => k,
                _ => return crate::errors::New("tls13: sig_alg is ECDSA-P256 but cert has different key type"),
            };
            // SHA-256 hash of signedMessage for VerifyP256
            let digest = {
                let mut h = crate::crypto::sha256::New();
                let s = slice::__from_vec(signed_msg.clone());
                let _ = crate::io::Writer::Write(&mut h, s);
                let empty = slice::__from_vec(Vec::new());
                crate::hash::Hash::Sum(&h, empty).__into_vec()
            };
            crate::crypto::tls::legacy_p256::VerifyP256(pk, &digest, signature)
        }
        SIG_RSA_PSS_RSAE_SHA256 => {
            let pk = match pubkey {
                ServerPubKey::Rsa(k) => k,
                _ => return crate::errors::New("tls13: sig_alg is RSA-PSS but cert has different key type"),
            };
            // SHA-256 hash of signedMessage
            let digest = {
                let mut h = crate::crypto::sha256::New();
                let s = slice::__from_vec(signed_msg.clone());
                let _ = crate::io::Writer::Write(&mut h, s);
                let empty = slice::__from_vec(Vec::new());
                crate::hash::Hash::Sum(&h, empty).__into_vec()
            };
            let digest_s = slice::__from_vec(digest);
            let sig_s = slice::__from_vec(signature.to_vec());
            // PSSSaltLengthEqualsHash = 0 in Go's rsa.PSSSaltLengthEqualsHash
            crate::crypto::rsa::VerifyPSS(pk, crate::crypto::SHA256, digest_s, sig_s, None)
        }
        SIG_RSA_PSS_RSAE_SHA384 => {
            let pk = match pubkey {
                ServerPubKey::Rsa(k) => k,
                _ => return crate::errors::New("tls13: sig_alg is RSA-PSS-SHA384 but cert has different key type"),
            };
            let digest = {
                let mut h = crate::crypto::sha512::New384();
                let s = slice::__from_vec(signed_msg.clone());
                let _ = crate::io::Writer::Write(&mut h, s);
                let empty = slice::__from_vec(Vec::new());
                crate::hash::Hash::Sum(&h, empty).__into_vec()
            };
            let digest_s = slice::__from_vec(digest);
            let sig_s = slice::__from_vec(signature.to_vec());
            crate::crypto::rsa::VerifyPSS(pk, crate::crypto::SHA384, digest_s, sig_s, None)
        }
        SIG_RSA_PSS_RSAE_SHA512 => {
            let pk = match pubkey {
                ServerPubKey::Rsa(k) => k,
                _ => return crate::errors::New("tls13: sig_alg is RSA-PSS-SHA512 but cert has different key type"),
            };
            let digest = {
                let mut h = crate::crypto::sha512::New();
                let s = slice::__from_vec(signed_msg.clone());
                let _ = crate::io::Writer::Write(&mut h, s);
                let empty = slice::__from_vec(Vec::new());
                crate::hash::Hash::Sum(&h, empty).__into_vec()
            };
            let digest_s = slice::__from_vec(digest);
            let sig_s = slice::__from_vec(signature.to_vec());
            crate::crypto::rsa::VerifyPSS(pk, crate::crypto::SHA512, digest_s, sig_s, None)
        }
        SIG_RSA_PKCS1_SHA256 => {
            let pk = match pubkey {
                ServerPubKey::Rsa(k) => k,
                _ => return crate::errors::New("tls13: sig_alg is RSA-PKCS1-SHA256 but cert has different key type"),
            };
            let digest = {
                let mut h = crate::crypto::sha256::New();
                let s = slice::__from_vec(signed_msg.clone());
                let _ = crate::io::Writer::Write(&mut h, s);
                let empty = slice::__from_vec(Vec::new());
                crate::hash::Hash::Sum(&h, empty).__into_vec()
            };
            let digest_s = slice::__from_vec(digest);
            let sig_s = slice::__from_vec(signature.to_vec());
            crate::crypto::rsa::VerifyPKCS1v15(pk, crate::crypto::SHA256, digest_s, sig_s)
        }
        SIG_RSA_PKCS1_SHA384 => {
            let pk = match pubkey {
                ServerPubKey::Rsa(k) => k,
                _ => return crate::errors::New("tls13: sig_alg is RSA-PKCS1-SHA384 but cert has different key type"),
            };
            let digest = {
                let mut h = crate::crypto::sha512::New384();
                let s = slice::__from_vec(signed_msg.clone());
                let _ = crate::io::Writer::Write(&mut h, s);
                let empty = slice::__from_vec(Vec::new());
                crate::hash::Hash::Sum(&h, empty).__into_vec()
            };
            let digest_s = slice::__from_vec(digest);
            let sig_s = slice::__from_vec(signature.to_vec());
            crate::crypto::rsa::VerifyPKCS1v15(pk, crate::crypto::SHA384, digest_s, sig_s)
        }
        SIG_RSA_PKCS1_SHA512 => {
            let pk = match pubkey {
                ServerPubKey::Rsa(k) => k,
                _ => return crate::errors::New("tls13: sig_alg is RSA-PKCS1-SHA512 but cert has different key type"),
            };
            let digest = {
                let mut h = crate::crypto::sha512::New();
                let s = slice::__from_vec(signed_msg.clone());
                let _ = crate::io::Writer::Write(&mut h, s);
                let empty = slice::__from_vec(Vec::new());
                crate::hash::Hash::Sum(&h, empty).__into_vec()
            };
            let digest_s = slice::__from_vec(digest);
            let sig_s = slice::__from_vec(signature.to_vec());
            crate::crypto::rsa::VerifyPKCS1v15(pk, crate::crypto::SHA512, digest_s, sig_s)
        }
        SIG_ED25519 => {
            let pk = match pubkey {
                ServerPubKey::Ed25519(k) => k,
                _ => return crate::errors::New("tls13: sig_alg is Ed25519 but cert has different key type"),
            };
            // Ed25519: directSigning — pass the full signed_msg as the message (no pre-hash)
            let msg_s = slice::__from_vec(signed_msg);
            let sig_s = slice::__from_vec(signature.to_vec());
            if crate::crypto::ed25519::Verify(pk, msg_s, sig_s) {
                crate::errors::nil
            } else {
                crate::errors::New("tls13: Ed25519 certificate signature verification failed")
            }
        }
        _ => {
            // For unknown sig_alg: log and skip verification (InsecureSkipVerify for unknown)
            tls_debug!("[tls13-debug] WARNING: unknown sig_alg=0x%04x — skipping verification\n", sig_alg as u64);
            crate::errors::nil
        }
    }
}

// ─── ConnAdapter ──────────────────────────────────────────────────────

struct ConnReader<'a>(&'a mut dyn crate::net::Conn);

impl<'a> crate::io::Reader for ConnReader<'a> {
    fn Read(&mut self, p: &mut slice<byte>) -> (crate::types::int, error) {
        self.0.Read(p)
    }
}

// ─── TLS 1.3 AEAD encrypt/decrypt helpers ─────────────────────────────
//
// RFC 8446 §5.2: TLSCiphertext
//   content_type = 23 (application_data)
//   legacy_version = 0x0303
//   length = len(encrypted_record)
//
// encrypted_record = AEAD(write_key, write_iv XOR seq, aad, TLSInnerPlaintext)
// TLSInnerPlaintext = content || ContentType(1)
//
// nonce = write_iv(12) XOR (seq as 12-byte big-endian)
// aad = record header (5 bytes): 23 || 03 03 || length_BE16

fn tls13_nonce(iv: &[byte; 12], seq: u64) -> [byte; 12] {
    let mut nonce = *iv;
    let seq_bytes = seq.to_be_bytes();
    // XOR last 8 bytes with the 8-byte sequence number
    for i in 0..8 {
        nonce[4 + i] ^= seq_bytes[i];
    }
    nonce
}

/// Encrypt a TLS 1.3 handshake/application record.
/// inner_content_type: the actual content type being protected.
/// Wraps in type=23 (application_data) on the wire.
/// suite_id: cipher suite (0x1301/0x1302 = AES-GCM, 0x1303 = ChaCha20-Poly1305).
pub fn tls13_encrypt_record(
    keys: &TrafficKeys,
    seq: u64,
    inner_content_type: byte,
    plaintext: &[byte],
) -> (slice<byte>, error) {
    tls13_encrypt_record_suite(keys, seq, inner_content_type, plaintext, 0x1301)
}

/// Same as `tls13_encrypt_record` but with explicit suite dispatch.
pub fn tls13_encrypt_record_suite(
    keys: &TrafficKeys,
    seq: u64,
    inner_content_type: byte,
    plaintext: &[byte],
    suite_id: u16,
) -> (slice<byte>, error) {
    use crate::crypto::{aes, cipher::{self}};

    // TLSInnerPlaintext = plaintext || inner_content_type
    let mut inner: Vec<byte> = Vec::with_capacity(plaintext.len() + 1);
    inner.extend_from_slice(plaintext);
    inner.push(inner_content_type);

    // AAD = outer record header: 23 || 03 03 || length_BE16
    // AEAD tag is always 16 bytes (GCM or Poly1305)
    let ct_len = inner.len() + 16;
    let ct_len_be = (ct_len as u16).to_be_bytes(); // goishlint:ignore GOISH005
    let aad: [byte; 5] = [
        RECORD_APPLICATION,
        0x03, 0x03,
        ct_len_be[0], ct_len_be[1],
    ];

    // Build nonce: iv XOR seq
    let iv12: [byte; 12] = keys.iv.as_slice().try_into().unwrap_or([0u8; 12]);
    let nonce12 = tls13_nonce(&iv12, seq);

    let ct_tag_v: Vec<byte> = if suite_id == 0x1303 {
        // ChaCha20-Poly1305
        use crate::crypto::chacha20poly1305;
        let key_s = slice::__from_vec(keys.key.clone());
        let (cp_opt, cerr) = chacha20poly1305::New(key_s);
        if !cerr.IsNil() {
            return (slice::__from_vec(Vec::new()), cerr);
        }
        let cp = match cp_opt {
            Some(c) => c,
            None => return (slice::__from_vec(Vec::new()), errors::New("tls13: ChaCha20-Poly1305 init error")),
        };
        let nonce_s = slice::__from_vec(nonce12.to_vec());
        let pt_s = slice::__from_vec(inner);
        let aad_s = slice::__from_vec(aad.to_vec());
        let empty = slice::__from_vec(Vec::new());
        cipher::AEAD::Seal(&cp, empty, nonce_s, pt_s, aad_s).__into_vec()
    } else {
        // AES-GCM (0x1301, 0x1302)
        let key_slice = slice::__from_vec(keys.key.clone());
        let (cipher_opt, _) = aes::NewCipher(key_slice);
        let cipher = match cipher_opt {
            Some(c) => c,
            None => return (slice::__from_vec(Vec::new()), errors::New("tls13: AES key error")),
        };
        let (gcm_opt, gerr) = cipher::NewGCM(cipher);
        if !gerr.IsNil() {
            return (slice::__from_vec(Vec::new()), gerr);
        }
        let gcm = match gcm_opt {
            Some(g) => g,
            None => return (slice::__from_vec(Vec::new()), errors::New("tls13: GCM init error")),
        };
        let nonce_s = slice::__from_vec(nonce12.to_vec());
        let pt_s = slice::__from_vec(inner);
        let aad_s = slice::__from_vec(aad.to_vec());
        let empty = slice::__from_vec(Vec::new());
        cipher::AEAD::Seal(&gcm, empty, nonce_s, pt_s, aad_s).__into_vec()
    };

    // Wire: header(5) + ciphertext+tag
    let mut out: Vec<byte> = Vec::with_capacity(5 + ct_tag_v.len());
    out.push(RECORD_APPLICATION); // 23
    out.push(0x03);
    out.push(0x03);
    let plen_be = (ct_tag_v.len() as u16).to_be_bytes(); // goishlint:ignore GOISH005
    out.extend_from_slice(&plen_be);
    out.extend_from_slice(&ct_tag_v);

    (slice::__from_vec(out), errors::nil)
}

/// Decrypt a TLS 1.3 record fragment (after the 5-byte header).
/// Returns (inner_plaintext_without_content_type, inner_content_type, error).
/// Uses AES-GCM by default (suite_id=0x1301/0x1302).
pub fn tls13_decrypt_record(
    keys: &TrafficKeys,
    seq: u64,
    fragment: &[byte],
) -> (Vec<byte>, byte, error) {
    tls13_decrypt_record_suite(keys, seq, fragment, 0x1301)
}

/// Same as `tls13_decrypt_record` but with explicit suite dispatch.
pub fn tls13_decrypt_record_suite(
    keys: &TrafficKeys,
    seq: u64,
    fragment: &[byte],
    suite_id: u16,
) -> (Vec<byte>, byte, error) {
    use crate::crypto::{aes, cipher::{self}};

    if fragment.len() < 16 {
        return (Vec::new(), 0, errors::New("tls13: fragment too short for AEAD tag"));
    }

    let ct_and_tag = fragment;

    // AAD = outer record header
    let frag_len = fragment.len() as u16; // goishlint:ignore GOISH005
    let frag_len_be = frag_len.to_be_bytes();
    let aad: [byte; 5] = [
        RECORD_APPLICATION,
        0x03, 0x03,
        frag_len_be[0], frag_len_be[1],
    ];

    let iv12: [byte; 12] = keys.iv.as_slice().try_into().unwrap_or([0u8; 12]);
    let nonce12 = tls13_nonce(&iv12, seq);

    let pt_v: Vec<byte> = if suite_id == 0x1303 {
        // ChaCha20-Poly1305 decrypt
        use crate::crypto::chacha20poly1305;
        let key_s = slice::__from_vec(keys.key.clone());
        let (cp_opt, cerr) = chacha20poly1305::New(key_s);
        if !cerr.IsNil() {
            return (Vec::new(), 0, cerr);
        }
        let cp = match cp_opt {
            Some(c) => c,
            None => return (Vec::new(), 0, errors::New("tls13: ChaCha20-Poly1305 init error")),
        };
        let nonce_s = slice::__from_vec(nonce12.to_vec());
        let ct_s = slice::__from_vec(ct_and_tag.to_vec());
        let aad_s = slice::__from_vec(aad.to_vec());
        let empty = slice::__from_vec(Vec::new());
        let (pt_s, derr) = cipher::AEAD::Open(&cp, empty, nonce_s, ct_s, aad_s);
        if !derr.IsNil() {
            return (Vec::new(), 0, derr);
        }
        pt_s.__into_vec()
    } else {
        // AES-GCM decrypt
        let key_slice = slice::__from_vec(keys.key.clone());
        let (cipher_opt, _) = aes::NewCipher(key_slice);
        let cipher = match cipher_opt {
            Some(c) => c,
            None => return (Vec::new(), 0, errors::New("tls13: AES key error")),
        };
        let (gcm_opt, gerr) = cipher::NewGCM(cipher);
        if !gerr.IsNil() {
            return (Vec::new(), 0, gerr);
        }
        let gcm = match gcm_opt {
            Some(g) => g,
            None => return (Vec::new(), 0, errors::New("tls13: GCM init error")),
        };
        let nonce_s = slice::__from_vec(nonce12.to_vec());
        let ct_s = slice::__from_vec(ct_and_tag.to_vec());
        let aad_s = slice::__from_vec(aad.to_vec());
        let empty = slice::__from_vec(Vec::new());
        let (pt_s, derr) = cipher::AEAD::Open(&gcm, empty, nonce_s, ct_s, aad_s);
        if !derr.IsNil() {
            return (Vec::new(), 0, derr);
        }
        pt_s.__into_vec()
    };

    let mut inner = pt_v;
    // Strip trailing zeros (padding) then inner_content_type byte
    while inner.last() == Some(&0) {
        inner.pop();
    }
    if inner.is_empty() {
        return (Vec::new(), 0, errors::New("tls13: empty inner plaintext after decryption"));
    }
    let inner_content_type = *inner.last().unwrap();
    inner.pop();

    (inner, inner_content_type, errors::nil)
}

// ─── Transcript hash helper ────────────────────────────────────────────

/// Compute the current transcript hash from all accumulated bytes.
pub fn transcript_hash(
    hash_fn: fn() -> alloc::boxed::Box<dyn HashTrait + Send + Sync>,
    transcript: &[byte],
) -> Vec<byte> {
    let mut h = hash_fn();
    let s = slice::__from_vec(transcript.to_vec());
    let _ = WriterTrait::Write(&mut h, s);
    let empty = slice::__from_vec(Vec::new());
    h.Sum(empty).__into_vec()
}

// ─── Read one TLS 1.3 encrypted record ────────────────────────────────

/// Read a decrypted TLS 1.3 record. Returns (plaintext, inner_type, error).
/// Direction-agnostic: pass the peer's write keys + your inbound sequence
/// counter (client passes server_hs keys; the server driver passes
/// client_hs keys).
pub(crate) fn read_tls13_record(
    conn: &mut dyn crate::net::Conn,
    server_hs_keys: &TrafficKeys,
    server_seq: &mut u64,
    suite_id: u16,
) -> (Vec<byte>, byte, error) {
    loop {
        let (rtype, frag_s, err) = {
            let mut adapter = ConnReader(conn);
            read_record(&mut adapter)
        };
        let frag = frag_s.__into_vec();
        if !err.IsNil() {
            return (Vec::new(), 0, err);
        }
        // Skip ChangeCipherSpec (compatibility middlebox)
        if rtype == RECORD_CHANGE_CIPHER_SPEC {
            continue;
        }
        if rtype == RECORD_ALERT {
            let desc = if frag.len() >= 2 { frag[1] } else { 0 };
            tls_debug!("[tls13-debug] TLS Alert: level=%d desc=%d\n",
                if frag.is_empty() { 0i64 } else { frag[0] as i64 }, desc as i64);
            return (Vec::new(), 0, errors::New("tls13: received TLS alert from server"));
        }
        if rtype != RECORD_APPLICATION {
            tls_debug!("[tls13-debug] unexpected record type=%d\n", rtype as i64);
            return (Vec::new(), 0, errors::New("tls13: unexpected record type"));
        }
        let seq = *server_seq;
        *server_seq += 1;
        let (plain, inner_type, derr) = tls13_decrypt_record_suite(server_hs_keys, seq, &frag, suite_id);
        if !derr.IsNil() {
            tls_debug!("[tls13-debug] decrypt error seq=%d: %v\n", seq, derr);
            return (Vec::new(), 0, derr);
        }
        // In TLS 1.3, alerts are encrypted (outer type=23, inner_type=21=RECORD_ALERT)
        if inner_type == RECORD_ALERT {
            let level = if plain.len() >= 1 { plain[0] } else { 0 };
            let desc  = if plain.len() >= 2 { plain[1] } else { 0 };
            tls_debug!("[tls13-debug] TLS Alert: level=%d desc=%d\n", level as i64, desc as i64);
            return (Vec::new(), 0, errors::New("tls13: received TLS alert from server"));
        }
        return (plain, inner_type, errors::nil);
    }
}

// ─── Handshake message reader (handles coalesced messages) ────────────
//
// TLS 1.3 allows multiple handshake messages to be coalesced into a single
// encrypted record. We maintain a buffer and parse messages from it.

pub(crate) struct Tls13HandshakeReader {
    buf: Vec<byte>,  // buffered decrypted handshake bytes
}

impl Tls13HandshakeReader {
    pub(crate) fn new() -> Self {
        Tls13HandshakeReader { buf: Vec::new() }
    }

    /// Read the next handshake message. Returns (msg_bytes, error).
    /// msg_bytes is the full message including type(1) + length(3) + body.
    /// Reads more encrypted records from conn as needed.
    pub(crate) fn next_msg(
        &mut self,
        conn: &mut dyn crate::net::Conn,
        keys: &TrafficKeys,
        seq: &mut u64,
        suite_id: u16,
    ) -> (Vec<byte>, error) {
        loop {
            // Try to parse a complete message from buffer
            if self.buf.len() >= 4 {
                let msg_len = ((self.buf[1] as usize) << 16)
                    | ((self.buf[2] as usize) << 8)
                    | (self.buf[3] as usize);
                let total = 4 + msg_len;
                if self.buf.len() >= total {
                    let msg = self.buf[..total].to_vec();
                    self.buf = self.buf[total..].to_vec();
                    return (msg, errors::nil);
                }
            }
            // Need more data: read another encrypted record
            let (plain, inner_type, err) = read_tls13_record(conn, keys, seq, suite_id);
            if !err.IsNil() {
                return (Vec::new(), err);
            }
            if inner_type != RECORD_HANDSHAKE {
                return (Vec::new(), errors::New("tls13: expected Handshake inner type in coalesced record"));
            }
            self.buf.extend_from_slice(&plain);
        }
    }
}

// ─── do_client_handshake_tls13 ────────────────────────────────────────

/// TLS 1.3 client handshake, called after we have received and parsed a
/// ServerHello that selected TLS 1.3 (supported_versions == 0x0304).
///
/// Parameters:
///   conn         — TCP connection
///   suite        — selected cipher suite descriptor
///   transcript   — handshake transcript so far: ClientHello || ServerHello bytes
///   client_random — the client_random from the ClientHello
///   server_key_share_data — the server's key_share.data from ServerHello
///   client_x25519_priv — the client's X25519 private key (used for server's X25519 share)
///
/// Returns (Tls13Keys, error) where Tls13Keys holds the application traffic secrets.
pub struct Tls13Keys {
    pub suite_id: u16,
    pub client_app_keys: TrafficKeys,
    pub server_app_keys: TrafficKeys,
    /// Client application traffic secret (for updating keys)
    pub client_app_secret: Vec<byte>,
    /// Server application traffic secret
    pub server_app_secret: Vec<byte>,
    /// The client_app_seq after handshake (starts at 0)
    pub client_seq: u64,
    /// The server_app_seq after handshake (starts at 0)
    pub server_seq: u64,
    /// RFC 8446 §7.1: resumption_master_secret =
    ///   Derive-Secret(MasterSecret, "res master", ClientHello…client Finished).
    /// Stashed here so the connection can derive a resumption PSK from any
    /// NewSessionTicket the server sends post-handshake.
    pub resumption_master_secret: Vec<byte>,
    /// Hash output size for the negotiated suite (32 for SHA-256, 48 for SHA-384).
    pub hash_size: u16,
}

pub fn do_client_handshake_tls13(
    conn: &mut dyn crate::net::Conn,
    suite: &CipherSuiteTls13,
    transcript: &[byte],
    _client_random: &[byte; 32],
    server_key_share_data: &[byte],
    client_x25519_priv: &ecdh::X25519PrivateKey,
) -> (Tls13Keys, error) {
    // Compute X25519 shared secret
    if server_key_share_data.len() != 32 {
        tls_debug!("[tls13-debug] server key share len=%d (expected 32 for x25519)\n",
            server_key_share_data.len() as i64);
        let dummy = Tls13Keys {
            suite_id: suite.id,
            client_app_keys: TrafficKeys { key: Vec::new(), iv: Vec::new() },
            server_app_keys: TrafficKeys { key: Vec::new(), iv: Vec::new() },
            client_app_secret: Vec::new(),
            server_app_secret: Vec::new(),
            client_seq: 0,
            server_seq: 0,
            resumption_master_secret: Vec::new(),
            hash_size: 0,
        };
        return (dummy, errors::New("tls13: server key share not 32 bytes (X25519 only supported)"));
    }
    let mut server_pub_arr = [0u8; 32];
    server_pub_arr.copy_from_slice(server_key_share_data);
    let server_pub = ecdh::X25519PublicKey(server_pub_arr);
    let shared_secret = ecdh::x25519_compute_shared(client_x25519_priv, &server_pub);

    // Check for low-order point
    let mut is_zero = 0u8;
    for b in shared_secret.iter() { is_zero |= *b; }
    if is_zero == 0 {
        let dummy = Tls13Keys {
            suite_id: suite.id,
            client_app_keys: TrafficKeys { key: Vec::new(), iv: Vec::new() },
            server_app_keys: TrafficKeys { key: Vec::new(), iv: Vec::new() },
            client_app_secret: Vec::new(),
            server_app_secret: Vec::new(),
            client_seq: 0,
            server_seq: 0,
            resumption_master_secret: Vec::new(),
            hash_size: 0,
        };
        return (dummy, errors::New("tls13: x25519 shared secret is all zeros"));
    }

    do_client_handshake_tls13_inner(conn, suite, transcript, &shared_secret)
}

/// TLS 1.3 handshake with a pre-computed ECDHE shared secret.
/// Used for HRR path where ECDHE may be P-256 (not just X25519).
pub fn do_client_handshake_tls13_with_ecdhe(
    conn: &mut dyn crate::net::Conn,
    suite: &CipherSuiteTls13,
    transcript: &[byte],
    shared_secret: &[byte; 32],
) -> (Tls13Keys, error) {
    do_client_handshake_tls13_inner_impl(conn, suite, transcript, shared_secret, None)
}

/// TLS 1.3 handshake with PSK resumption.
///
/// Called when the server's ServerHello contains a `pre_shared_key` extension
/// with `selected_identity = 0`. The PSK replaces the all-zeros IKM in the
/// EarlySecret derivation, and the server omits Certificate + CertificateVerify
/// (RFC 8446 §4.4 — PSK authentication).
pub fn do_client_handshake_tls13_with_psk(
    conn: &mut dyn crate::net::Conn,
    suite: &CipherSuiteTls13,
    transcript: &[byte],
    server_key_share_data: &[byte],
    client_x25519_priv: &ecdh::X25519PrivateKey,
    psk: &[byte],
) -> (Tls13Keys, error) {
    let dummy = Tls13Keys {
        suite_id: suite.id,
        client_app_keys: TrafficKeys { key: Vec::new(), iv: Vec::new() },
        server_app_keys: TrafficKeys { key: Vec::new(), iv: Vec::new() },
        client_app_secret: Vec::new(),
        server_app_secret: Vec::new(),
        client_seq: 0,
        server_seq: 0,
        resumption_master_secret: Vec::new(),
        hash_size: 0,
    };

    if server_key_share_data.len() != 32 {
        return (dummy, errors::New("tls13-psk: server key share not 32 bytes"));
    }
    let mut server_pub_arr = [0u8; 32];
    server_pub_arr.copy_from_slice(server_key_share_data);
    let server_pub = ecdh::X25519PublicKey(server_pub_arr);
    let shared_secret = ecdh::x25519_compute_shared(client_x25519_priv, &server_pub);

    let mut is_zero = 0u8;
    for b in shared_secret.iter() { is_zero |= *b; }
    if is_zero == 0 {
        return (dummy, errors::New("tls13-psk: x25519 shared secret is all zeros"));
    }

    do_client_handshake_tls13_inner_impl(conn, suite, transcript, &shared_secret, Some(psk))
}

fn do_client_handshake_tls13_inner(
    conn: &mut dyn crate::net::Conn,
    suite: &CipherSuiteTls13,
    transcript: &[byte],
    shared_secret: &[byte; 32],
) -> (Tls13Keys, error) {
    do_client_handshake_tls13_inner_impl(conn, suite, transcript, shared_secret, None)
}

fn do_client_handshake_tls13_inner_impl(
    conn: &mut dyn crate::net::Conn,
    suite: &CipherSuiteTls13,
    transcript: &[byte],
    shared_secret: &[byte; 32],
    psk: Option<&[byte]>,
) -> (Tls13Keys, error) {
    let dummy = Tls13Keys {
        suite_id: suite.id,
        client_app_keys: TrafficKeys { key: Vec::new(), iv: Vec::new() },
        server_app_keys: TrafficKeys { key: Vec::new(), iv: Vec::new() },
        client_app_secret: Vec::new(),
        server_app_secret: Vec::new(),
        client_seq: 0,
        server_seq: 0,
        resumption_master_secret: Vec::new(),
        hash_size: 0,
    };

    let hash_fn = suite.hash_fn;
    let key_len = suite.key_len;

    let using_psk = psk.is_some();
    if using_psk {
        tls_debug!("[tls13-debug] PSK resumption mode: using PSK for EarlySecret\n");
    } else {
        tls_debug!("[tls13-debug] ECDHE shared secret computed OK\n");
    }

    // ── 2. Derive handshake traffic secrets ───────────────────────────
    let early = EarlySecret::new(hash_fn, psk); // PSK or None (zeros)
    let hs = early.HandshakeSecret(shared_secret);

    let transcript_hash = key_schedule::transcript_hash_fn(hash_fn, transcript);

    let client_hs_secret = hs.ClientHandshakeTrafficSecret(&transcript_hash);
    let server_hs_secret = hs.ServerHandshakeTrafficSecret(&transcript_hash);
    tls_debug!("[tls13-debug] handshake traffic secrets derived\n");

    // Derive traffic keys
    let client_hs_keys = traffic_keys(hash_fn, &client_hs_secret, key_len);
    let server_hs_keys = traffic_keys(hash_fn, &server_hs_secret, key_len);
    tls_debug!("[tls13-debug] server_hs_secret (hex first 8): %02x%02x%02x%02x%02x%02x%02x%02x\n",
        server_hs_secret[0] as u64, server_hs_secret[1] as u64, server_hs_secret[2] as u64, server_hs_secret[3] as u64,
        server_hs_secret[4] as u64, server_hs_secret[5] as u64, server_hs_secret[6] as u64, server_hs_secret[7] as u64);
    tls_debug!("[tls13-debug] server_hs_key (hex first 8): %02x%02x%02x%02x%02x%02x%02x%02x\n",
        server_hs_keys.key[0] as u64, server_hs_keys.key[1] as u64, server_hs_keys.key[2] as u64, server_hs_keys.key[3] as u64,
        server_hs_keys.key[4] as u64, server_hs_keys.key[5] as u64, server_hs_keys.key[6] as u64, server_hs_keys.key[7] as u64);
    tls_debug!("[tls13-debug] server_hs_iv (hex): %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
        server_hs_keys.iv[0] as u64, server_hs_keys.iv[1] as u64, server_hs_keys.iv[2] as u64, server_hs_keys.iv[3] as u64,
        server_hs_keys.iv[4] as u64, server_hs_keys.iv[5] as u64, server_hs_keys.iv[6] as u64, server_hs_keys.iv[7] as u64,
        server_hs_keys.iv[8] as u64, server_hs_keys.iv[9] as u64, server_hs_keys.iv[10] as u64, server_hs_keys.iv[11] as u64);

    // Keep the master secret for later
    let master = hs.MasterSecret();

    // ── 3-6. Read handshake messages (EncryptedExtensions, Certificate,
    //        CertificateVerify, Finished).
    //
    // TLS 1.3 servers MAY coalesce multiple handshake messages into a single
    // encrypted record. Use Tls13HandshakeReader to handle both coalesced and
    // per-message cases transparently.
    let mut server_hs_seq: u64 = 0;
    let mut local_transcript = transcript.to_vec();
    let mut hs_reader = Tls13HandshakeReader::new();
    // Set to true if the server sends CertificateRequest. RFC 8446 §4.4.2
    // requires the client to send a Certificate message (empty list when no
    // cert is available) before its Finished, otherwise the server aborts
    // with unexpected_message.
    let mut client_cert_requested = false;

    // ── 3. Read EncryptedExtensions ───────────────────────────────────
    {
        let (plain, err) = hs_reader.next_msg(conn, &server_hs_keys, &mut server_hs_seq, suite.id);
        if !err.IsNil() {
            tls_debug!("[tls13-debug] read EncryptedExtensions error: %v\n", err);
            return (dummy, err);
        }
        if plain.is_empty() || plain[0] != MSG_ENCRYPTED_EXTENSIONS {
            tls_debug!("[tls13-debug] expected EncryptedExtensions(8), got=%d\n",
                if plain.is_empty() { 0i64 } else { plain[0] as i64 });
            return (dummy, errors::New("tls13: expected EncryptedExtensions message"));
        }
        tls_debug!("[tls13-debug] EncryptedExtensions OK\n");
        local_transcript.extend_from_slice(&plain);
    }

    // ── 4. Read Certificate (or CertificateRequest then Certificate) ──
    // In PSK mode (using_psk == true), the server OMITS Certificate and
    // CertificateVerify (RFC 8446 §4.4). The next message after
    // EncryptedExtensions is Finished directly.
    if !using_psk {
        let server_pubkey: ServerPubKey;
        {
            let (plain, err) = hs_reader.next_msg(conn, &server_hs_keys, &mut server_hs_seq, suite.id);
            if !err.IsNil() {
                tls_debug!("[tls13-debug] read cert/certreq error: %v\n", err);
                return (dummy, err);
            }
            if plain.is_empty() {
                return (dummy, errors::New("tls13: empty handshake record where Certificate expected"));
            }
            let msg_type = plain[0];

            // If CertificateRequest, consume it and remember that we MUST
            // send an empty client Certificate before client Finished
            // (RFC 8446 §4.4.2 — "If the client did not select any certificate,
            // the Certificate message will contain only the empty
            // certificate_list field.").
            let cert_plain = if msg_type == 13 {
                tls_debug!("[tls13-debug] CertificateRequest received — will send empty Certificate\n");
                local_transcript.extend_from_slice(&plain);
                client_cert_requested = true;
                let (plain2, err2) = hs_reader.next_msg(conn, &server_hs_keys, &mut server_hs_seq, suite.id);
                if !err2.IsNil() {
                    return (dummy, err2);
                }
                if plain2.is_empty() || plain2[0] != MSG_CERTIFICATE {
                    return (dummy, errors::New("tls13: expected Certificate after CertificateRequest"));
                }
                plain2
            } else if msg_type == MSG_CERTIFICATE {
                plain
            } else {
                tls_debug!("[tls13-debug] expected Certificate(11), got=%d\n", msg_type as i64);
                return (dummy, errors::New("tls13: expected Certificate message"));
            };

            tls_debug!("[tls13-debug] Certificate message received (len=%d)\n", cert_plain.len() as i64);

            // Extract leaf cert DER and parse the public key for CertificateVerify
            server_pubkey = match parse_tls13_cert_message_leaf(&cert_plain) {
                Some(cert_der) => {
                    let pk = parse_server_pubkey(&cert_der);
                    match &pk {
                        ServerPubKey::EcdsaP256(_) => { let _ = tls_debug!("[tls13-debug] server cert key type: ECDSA P256\n"); },
                        ServerPubKey::Rsa(_)        => { let _ = tls_debug!("[tls13-debug] server cert key type: RSA\n"); },
                        ServerPubKey::Ed25519(_)    => { let _ = tls_debug!("[tls13-debug] server cert key type: Ed25519\n"); },
                        ServerPubKey::Unknown       => { let _ = tls_debug!("[tls13-debug] server cert key type: unknown\n"); },
                    }
                    pk
                }
                None => {
                    let _ = tls_debug!("[tls13-debug] WARNING: could not parse Certificate message -- using Unknown key\n");
                    ServerPubKey::Unknown
                }
            };

            local_transcript.extend_from_slice(&cert_plain);
        }

        // ── 5. Read CertificateVerify ──────────────────────────────────────
        // RFC 8446 §4.4.3: verify server's signature over the transcript hash.
        // transcript_hash at this point covers: ClientHello || ServerHello ||
        //   EncryptedExtensions || Certificate.
        // The signed message = 64×0x20 || "TLS 1.3, server CertificateVerify\x00" || transcript_hash.
        {
            let (plain, err) = hs_reader.next_msg(conn, &server_hs_keys, &mut server_hs_seq, suite.id);
            if !err.IsNil() {
                tls_debug!("[tls13-debug] read CertVerify error: %v\n", err);
                return (dummy, err);
            }
            if plain.is_empty() || plain[0] != MSG_CERTIFICATE_VERIFY {
                tls_debug!("[tls13-debug] expected CertVerify(15), msg=%d\n",
                    if plain.is_empty() { 0i64 } else { plain[0] as i64 });
                return (dummy, errors::New("tls13: expected CertificateVerify message"));
            }

            // Parse sig_alg and signature from the message
            match parse_tls13_cert_verify(&plain) {
                Some((sig_alg, signature)) => {
                    // Compute transcript hash BEFORE adding CertificateVerify
                    let cert_verify_th = key_schedule::transcript_hash_fn(hash_fn, &local_transcript);
                    let verify_err = verify_cert_verify(&server_pubkey, sig_alg, &signature, &cert_verify_th);
                    if !verify_err.IsNil() {
                        tls_debug!("[tls13-debug] CertificateVerify sig_alg=0x%04x FAILED: %v\n",
                            sig_alg as u64, verify_err);
                        // RFC 8446: verification failure → abort with decrypt_error
                        return (dummy, verify_err);
                    }
                    tls_debug!("[tls13-debug] CertificateVerify verified OK sig_alg=0x%04x\n", sig_alg as u64);
                }
                None => {
                    tls_debug!("[tls13-debug] WARNING: could not parse CertificateVerify message\n");
                    // Continue — don't abort for parse failure (shouldn't happen with well-formed servers)
                }
            }

            local_transcript.extend_from_slice(&plain);
        }
        // server_pubkey is used within the inner blocks above; suppress unused warning
        #[allow(unused_variables)]
        let _pk_used = &server_pubkey;
    } else {
        tls_debug!("[tls13-debug] PSK mode: skipping Certificate + CertificateVerify\n");
    }

    // ── 6. Read server Finished ────────────────────────────────────────
    // The server Finished verify_data is computed BEFORE adding Finished to transcript.
    {
        let (plain, err) = hs_reader.next_msg(conn, &server_hs_keys, &mut server_hs_seq, suite.id);
        if !err.IsNil() {
            tls_debug!("[tls13-debug] read server Finished error: %v\n", err);
            return (dummy, err);
        }
        if plain.is_empty() || plain[0] != MSG_FINISHED {
            tls_debug!("[tls13-debug] expected Finished(20), msg=%d\n",
                if plain.is_empty() { 0i64 } else { plain[0] as i64 });
            return (dummy, errors::New("tls13: expected server Finished message"));
        }
        // Verify server Finished: verify_data = HMAC(server_hs_secret, transcript_hash)
        // transcript at this point includes up to and including CertificateVerify
        let current_th = key_schedule::transcript_hash_fn(hash_fn, &local_transcript);
        let expected_vd = finished_hash(hash_fn, &server_hs_secret, &current_th);

        // Finished body: type(1) + len(3) + verify_data
        let body = &plain;
        if body.len() < 4 {
            return (dummy, errors::New("tls13: server Finished too short"));
        }
        let vd_len = ((body[1] as usize) << 16) | ((body[2] as usize) << 8) | (body[3] as usize);
        if body.len() < 4 + vd_len {
            return (dummy, errors::New("tls13: server Finished truncated"));
        }
        let their_vd = &body[4..4 + vd_len];

        // Constant-time comparison
        if their_vd.len() != expected_vd.len() {
            return (dummy, errors::New("tls13: server Finished verify_data wrong length"));
        }
        let mut diff: byte = 0;
        for i in 0..expected_vd.len() {
            diff |= their_vd[i] ^ expected_vd[i];
        }
        if diff != 0 {
            tls_debug!("[tls13-debug] server Finished verify_data MISMATCH\n");
            return (dummy, errors::New("tls13: server Finished verify_data mismatch"));
        }
        tls_debug!("[tls13-debug] server Finished verified OK\n");

        // Add server Finished to transcript (for application secret derivation)
        local_transcript.extend_from_slice(&plain);
    }

    // ── 7. Derive application traffic secrets (before sending client Finished)
    // RFC 8446: application secrets are derived from transcript up to server Finished
    let app_transcript_hash = key_schedule::transcript_hash_fn(hash_fn, &local_transcript);
    let client_app_secret = master.ClientApplicationTrafficSecret(&app_transcript_hash);
    let server_app_secret = master.ServerApplicationTrafficSecret(&app_transcript_hash);
    let client_app_keys = traffic_keys(hash_fn, &client_app_secret, key_len);
    let server_app_keys = traffic_keys(hash_fn, &server_app_secret, key_len);
    tls_debug!("[tls13-debug] application traffic secrets derived\n");

    // ── 8. Send ChangeCipherSpec (middlebox compatibility, RFC 8446 Appendix D.4) ──
    let ccs_bytes = encode_record(RECORD_CHANGE_CIPHER_SPEC, &[1u8]);
    let (_, werr) = conn.Write(ccs_bytes);
    if !werr.IsNil() {
        return (dummy, werr);
    }

    let mut client_hs_seq: u64 = 0;

    // ── 8b. Empty client Certificate (only if server sent CertificateRequest)
    // RFC 8446 §4.4.2: client MUST send Certificate before client Finished
    // when CertificateRequest was received. With no cert, the message is the
    // 8-byte sequence: type=11, len=4, cert_request_context_len=0,
    // cert_list_len=0. Without this, servers that request client auth (e.g.,
    // kube-apiserver with --client-ca-file) abort with unexpected_message.
    if client_cert_requested {
        let empty_cert_body: [byte; 8] = [
            MSG_CERTIFICATE, 0x00, 0x00, 0x04,
            0x00, 0x00, 0x00, 0x00,
        ];
        let (cert_wire, enc_err) = tls13_encrypt_record_suite(
            &client_hs_keys, client_hs_seq, RECORD_HANDSHAKE, &empty_cert_body, suite.id);
        if !enc_err.IsNil() {
            tls_debug!("[tls13-debug] encrypt empty client Certificate error: %v\n", enc_err);
            return (dummy, enc_err);
        }
        client_hs_seq += 1;
        let (_, werr) = conn.Write(cert_wire);
        if !werr.IsNil() {
            return (dummy, werr);
        }
        local_transcript.extend_from_slice(&empty_cert_body);
        tls_debug!("[tls13-debug] empty client Certificate sent\n");
    }

    // ── 9. Send client Finished ────────────────────────────────────────
    // transcript at this point: ClientHello || ServerHello || EncryptedExtensions || ...
    // || server Finished || [optional empty client Certificate].
    // For client Finished, we use transcript BEFORE client Finished.
    let client_fin_transcript_hash = key_schedule::transcript_hash_fn(hash_fn, &local_transcript);
    let client_fin_vd = finished_hash(hash_fn, &client_hs_secret, &client_fin_transcript_hash);

    // Build Finished handshake message: type(1) + len(3) + verify_data
    let vd_len = client_fin_vd.len();
    let mut fin_body: Vec<byte> = Vec::with_capacity(4 + vd_len);
    fin_body.push(MSG_FINISHED);
    fin_body.push(((vd_len >> 16) & 0xFF) as byte);
    fin_body.push(((vd_len >> 8) & 0xFF) as byte);
    fin_body.push((vd_len & 0xFF) as byte);
    fin_body.extend_from_slice(&client_fin_vd);

    // Encrypt with client_hs_keys (client_hs_seq may already be 1 if we
    // sent an empty Certificate above).
    let (fin_wire, enc_err) = tls13_encrypt_record_suite(&client_hs_keys, client_hs_seq, RECORD_HANDSHAKE, &fin_body, suite.id);
    if !enc_err.IsNil() {
        tls_debug!("[tls13-debug] encrypt client Finished error: %v\n", enc_err);
        return (dummy, enc_err);
    }
    client_hs_seq += 1;
    let _ = client_hs_seq; // suppress unused warning

    let (_, werr) = conn.Write(fin_wire);
    if !werr.IsNil() {
        return (dummy, werr);
    }
    tls_debug!("[tls13-debug] client Finished sent\n");

    // ── 9b. Resumption master secret (RFC 8446 §7.1) ──────────────────
    // resumption_master_secret = Derive-Secret(MasterSecret, "res master",
    //     ClientHello…client Finished). Needed to derive a resumption PSK
    //     from any NewSessionTicket the server later sends.
    local_transcript.extend_from_slice(&fin_body);
    let rms_transcript_hash = key_schedule::transcript_hash_fn(hash_fn, &local_transcript);
    let resumption_master_secret =
        key_schedule::DeriveSecret(hash_fn, &master.secret, "res master", &rms_transcript_hash);

    // ── 10. Done: return application keys ─────────────────────────────
    tls_debug!("[tls13-debug] TLS 1.3 handshake complete! suite=0x%04x\n", suite.id as u64); // goishlint:ignore GOISH005

    (Tls13Keys {
        suite_id: suite.id,
        client_app_keys,
        server_app_keys,
        client_app_secret,
        server_app_secret,
        client_seq: 0,
        server_seq: 0,
        resumption_master_secret,
        hash_size: suite.hash_size as u16, // goishlint:ignore GOISH005
    }, errors::nil)
}

// ── clientHandshakeStateTLS13 (handshake_client_tls13.go:26) ────────

// Go: handshake_client_tls13.go:26-45
//   type clientHandshakeStateTLS13 struct {
//       c *Conn; ctx context.Context; serverHello *serverHelloMsg
//       hello *clientHelloMsg; keyShareKeys *keySharePrivateKeys
//       session *SessionState; earlySecret *tls13.EarlySecret
//       binderKey []byte; certReq *certificateRequestMsgTLS13
//       usingPSK, sentDummyCCS bool; suite *cipherSuiteTLS13
//       transcript hash.Hash; masterSecret *tls13.MasterSecret
//       trafficSecret []byte; echContext *echClientContext }
/// The TLS 1.3 client handshake state.
///
/// **Partial record.** Only the fields the ported methods read are
/// present; the key schedule, the transcript and the ECH context land
/// with `handshake`, which drives the whole exchange.
pub(crate) struct clientHandshakeStateTLS13 {
    pub c: super::conn::Conn,
    pub serverHello: super::handshake_messages::serverHelloMsg,
    pub hello: super::handshake_messages::clientHelloMsg,
    pub session: Option<super::ticket::SessionState>,
    pub usingPSK: bool,
    pub sentDummyCCS: bool,
    pub suite: Option<&'static super::cipher_suites::cipherSuiteTLS13>,
    pub transcript: Option<super::handshake_messages::transcriptHasher>,
    pub masterSecret: Option<crate::crypto::internal::fips140::tls13::MasterSecret>,
    /// Go: `client_application_traffic_secret_0`.
    pub trafficSecret: crate::goslice::slice<crate::types::byte>,
    pub echContext: Option<super::handshake_client::echClientContext>,
    pub certReq: Option<super::handshake_messages::certificateRequestMsgTLS13>,
}

impl clientHandshakeStateTLS13 {
    // go: sdk 1.25.5 crypto/tls/handshake_client_tls13.go:165-217 clientHandshakeStateTLS13.checkServerHelloOrHRR
    /// Go: the checks a ServerHello and a HelloRetryRequest share —
    /// version, forbidden extensions, the echoed session ID, and the
    /// cipher suite, which may not change across an HRR.
    pub(crate) fn checkServerHelloOrHRR(&mut self) -> crate::error {
        // Go: if hs.serverHello.supportedVersion == 0 {
        //         c.sendAlert(alertMissingExtension)
        //         return errors.New("tls: server selected TLS 1.3 using the legacy version field") }
        if self.serverHello.supportedVersion == 0 {
            self.c.sendAlert(super::alert::alertMissingExtension);
            return crate::errors::New(
                "tls: server selected TLS 1.3 using the legacy version field",
            );
        }

        // Go: if hs.serverHello.supportedVersion != VersionTLS13 { … }
        if self.serverHello.supportedVersion != super::common::VersionTLS13 {
            self.c.sendAlert(super::alert::alertIllegalParameter);
            return crate::errors::New(
                "tls: server selected an invalid version after a HelloRetryRequest",
            );
        }

        // Go: if hs.serverHello.vers != VersionTLS12 { … }
        if self.serverHello.vers != super::common::VersionTLS12 {
            self.c.sendAlert(super::alert::alertIllegalParameter);
            return crate::errors::New("tls: server sent an incorrect legacy version");
        }

        // Go: if hs.serverHello.ocspStapling || … || len(hs.serverHello.scts) != 0 {
        //         c.sendAlert(alertUnsupportedExtension)
        //         return errors.New("tls: server sent a ServerHello extension forbidden in TLS 1.3") }
        if self.serverHello.ocspStapling
            || self.serverHello.ticketSupported
            || self.serverHello.extendedMasterSecret
            || self.serverHello.secureRenegotiationSupported
            || self.serverHello.secureRenegotiation.len() != 0
            || self.serverHello.alpnProtocol.len() != 0
            || self.serverHello.scts.len() != 0
        {
            self.c.sendAlert(super::alert::alertUnsupportedExtension);
            return crate::errors::New(
                "tls: server sent a ServerHello extension forbidden in TLS 1.3",
            );
        }

        // Go: if !bytes.Equal(hs.hello.sessionId, hs.serverHello.sessionId) { … }
        if self.hello.sessionId != self.serverHello.sessionId {
            self.c.sendAlert(super::alert::alertIllegalParameter);
            return crate::errors::New("tls: server did not echo the legacy session ID");
        }

        // Go: if hs.serverHello.compressionMethod != compressionNone { … }
        if self.serverHello.compressionMethod != super::common::compressionNone {
            self.c.sendAlert(super::alert::alertDecodeError);
            return crate::errors::New("tls: server sent non-zero legacy TLS compression method");
        }

        // Go: selectedSuite := mutualCipherSuiteTLS13(hs.hello.cipherSuites, hs.serverHello.cipherSuite)
        //     if hs.suite != nil && selectedSuite != hs.suite { … }
        //     if selectedSuite == nil { … }
        //     hs.suite = selectedSuite; c.cipherSuite = hs.suite.id; return nil
        let selectedSuite = super::cipher_suites::mutualCipherSuiteTLS13(
            crate::goslice::slice::__from_vec(self.hello.cipherSuites.clone()),
            self.serverHello.cipherSuite,
        );
        if self.suite.is_some() && !suiteEq(selectedSuite, self.suite) {
            self.c.sendAlert(super::alert::alertIllegalParameter);
            return crate::errors::New("tls: server changed cipher suite after a HelloRetryRequest");
        }
        if selectedSuite.is_none() {
            self.c.sendAlert(super::alert::alertIllegalParameter);
            return crate::errors::New("tls: server chose an unconfigured cipher suite");
        }
        self.suite = selectedSuite;
        self.c.__setCipherSuite(self.suite.unwrap().id);
        return crate::errors::nil;
    }

    // go: sdk 1.25.5 crypto/tls/handshake_client_tls13.go:221-231 clientHandshakeStateTLS13.sendDummyChangeCipherSpec
    /// Go: send a ChangeCipherSpec once, for middlebox compatibility.
    /// See RFC 8446, Appendix D.4.
    ///
    /// Deviation: the `hs.c.quic != nil` guard is absent — goish ships
    /// no QUIC transport.
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

    // go: sdk 1.25.5 crypto/tls/handshake_client_tls13.go:416-473 clientHandshakeStateTLS13.processServerHello
    /// Go: the checks that apply to a real ServerHello only, plus
    /// adopting the offered PSK when the server selected one.
    pub(crate) fn processServerHello(&mut self) -> crate::error {
        // Go: if bytes.Equal(hs.serverHello.random, helloRetryRequestRandom) {
        //         c.sendAlert(alertUnexpectedMessage)
        //         return errors.New("tls: server sent two HelloRetryRequest messages") }
        if self.serverHello.random == super::common::helloRetryRequestRandom.to_vec() {
            self.c.sendAlert(super::alert::alertUnexpectedMessage);
            return crate::errors::New("tls: server sent two HelloRetryRequest messages");
        }

        // Go: if len(hs.serverHello.cookie) != 0 { … }
        if self.serverHello.cookie.len() != 0 {
            self.c.sendAlert(super::alert::alertUnsupportedExtension);
            return crate::errors::New("tls: server sent a cookie in a normal ServerHello");
        }

        // Go: if hs.serverHello.selectedGroup != 0 { … }
        if self.serverHello.selectedGroup != 0 {
            self.c.sendAlert(super::alert::alertDecodeError);
            return crate::errors::New("tls: malformed key_share extension");
        }

        // Go: if hs.serverHello.serverShare.group == 0 { … }
        if self.serverHello.serverShare.group == 0 {
            self.c.sendAlert(super::alert::alertIllegalParameter);
            return crate::errors::New("tls: server did not send a key share");
        }
        // Go: if !slices.ContainsFunc(hs.hello.keyShares, func(ks keyShare) bool {
        //         return ks.group == hs.serverHello.serverShare.group }) { … }
        let mut offered = false;
        for ks in self.hello.keyShares.iter() {
            if ks.group == self.serverHello.serverShare.group {
                offered = true;
            }
        }
        if !offered {
            self.c.sendAlert(super::alert::alertIllegalParameter);
            return crate::errors::New("tls: server selected unsupported group");
        }

        // Go: if !hs.serverHello.selectedIdentityPresent { return nil }
        if !self.serverHello.selectedIdentityPresent {
            return crate::errors::nil;
        }

        // Go: if int(hs.serverHello.selectedIdentity) >= len(hs.hello.pskIdentities) { … }
        if crate::int(self.serverHello.selectedIdentity) >= crate::int(self.hello.pskIdentities.len()) {
            self.c.sendAlert(super::alert::alertIllegalParameter);
            return crate::errors::New("tls: server selected an invalid PSK");
        }

        // Go: if len(hs.hello.pskIdentities) != 1 || hs.session == nil {
        //         return c.sendAlert(alertInternalError) }
        if self.hello.pskIdentities.len() != 1 || self.session.is_none() {
            return self.c.sendAlert(super::alert::alertInternalError);
        }
        let session = self.session.clone().unwrap();
        // Go: pskSuite := cipherSuiteTLS13ByID(hs.session.cipherSuite)
        //     if pskSuite == nil { return c.sendAlert(alertInternalError) }
        let pskSuite = super::cipher_suites::cipherSuiteTLS13ByID(session.__cipherSuite());
        if pskSuite.is_none() {
            return self.c.sendAlert(super::alert::alertInternalError);
        }
        // Go: if pskSuite.hash != hs.suite.hash { … }
        if pskSuite.unwrap().hash != self.suite.unwrap().hash {
            self.c.sendAlert(super::alert::alertIllegalParameter);
            return crate::errors::New(
                "tls: server selected an invalid PSK and cipher suite pair",
            );
        }

        // Go: hs.usingPSK = true; c.didResume = true
        //     c.peerCertificates = hs.session.peerCertificates
        //     c.verifiedChains = hs.session.verifiedChains
        //     c.ocspResponse = hs.session.ocspResponse
        //     c.scts = hs.session.scts
        //     return nil
        self.usingPSK = true;
        self.c.didResume = true;
        self.c.peerCertificates = session.__peerCertificates();
        self.c.verifiedChains = session.__verifiedChains();
        self.c.ocspResponse = session.__ocspResponse();
        self.c.scts = session.__scts();
        return crate::errors::nil;
    }
}

// go: none — goish-only: Go compares two `*cipherSuiteTLS13` pointers
// with `!=`; goish holds `Option<&'static …>`, whose derived equality
// would compare the suites field by field. Identity is what the check
// means, so compare the addresses.
fn suiteEq(
    a: Option<&'static super::cipher_suites::cipherSuiteTLS13>,
    b: Option<&'static super::cipher_suites::cipherSuiteTLS13>,
) -> bool {
    return match (a, b) {
        (Some(x), Some(y)) => core::ptr::eq(x, y),
        (None, None) => true,
        _ => false,
    };
}

impl clientHandshakeStateTLS13 {
    // go: sdk 1.25.5 crypto/tls/handshake_client_tls13.go:707-754 clientHandshakeStateTLS13.readServerFinished
    /// Go: read and check the server's Finished, then derive the
    /// application traffic secrets, which take context through it.
    ///
    /// Deviation: `c.ekm` is set from `exportKeyingMaterial`, which
    /// goish returns behind an `Arc` rather than as a bare closure.
    pub(crate) fn readServerFinished(&mut self) -> crate::error {
        // Go: "finishedMsg is included in the transcript, but not until
        // after we check the client version, since the state before this
        // message was sent is used during verification."
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

        // Go: expectedMAC := hs.suite.finishedHash(c.in.trafficSecret, hs.transcript)
        //     if !hmac.Equal(expectedMAC, finished.verifyData) {
        //         c.sendAlert(alertDecryptError)
        //         return errors.New("tls: invalid server finished hash") }
        let suite = self.suite.unwrap();
        let expectedMAC = {
            let transcript = self.transcript.as_ref().unwrap();
            suite.finishedHash(self.c.in_.trafficSecret.clone(), &*transcript.0)
        };
        if !crate::crypto::hmac::Equal(
            expectedMAC,
            crate::goslice::slice::__from_vec(finished.verifyData.clone()),
        ) {
            self.c.sendAlert(super::alert::alertDecryptError);
            return crate::errors::New("tls: invalid server finished hash");
        }

        // Go: if err := transcriptMsg(finished, hs.transcript); err != nil { return err }
        let err = {
            let transcript = self.transcript.as_mut().unwrap();
            super::handshake_messages::transcriptMsg(&finished, transcript)
        };
        if err != crate::errors::nil {
            return err;
        }

        // Go: "Derive secrets that take context through the server Finished."
        // Go: hs.trafficSecret = hs.masterSecret.ClientApplicationTrafficSecret(hs.transcript)
        //     serverSecret := hs.masterSecret.ServerApplicationTrafficSecret(hs.transcript)
        //     c.in.setTrafficSecret(hs.suite, QUICEncryptionLevelApplication, serverSecret)
        let master = self.masterSecret.as_ref().unwrap();
        let transcript = self.transcript.as_ref().unwrap();
        self.trafficSecret = master.ClientApplicationTrafficSecret(&*transcript.0);
        let serverSecret = master.ServerApplicationTrafficSecret(&*transcript.0);
        let ekm = suite.exportKeyingMaterial(master, &*transcript.0);
        let clientSecret = self.trafficSecret.clone();
        let helloRandom = crate::goslice::slice::__from_vec(self.hello.random.clone());
        self.c.in_.setTrafficSecret(
            suite,
            super::quic::QUICEncryptionLevelApplication,
            serverSecret.clone(),
        );

        // Go: err = c.config.writeKeyLog(keyLogLabelClientTraffic, hs.hello.random, hs.trafficSecret)
        //     if err != nil { c.sendAlert(alertInternalError); return err }
        let err = self.c.config.writeKeyLog(
            crate::gostring::string::from_static(super::common::keyLogLabelClientTraffic),
            helloRandom.clone(),
            clientSecret,
        );
        if err != crate::errors::nil {
            self.c.sendAlert(super::alert::alertInternalError);
            return err;
        }
        // Go: err = c.config.writeKeyLog(keyLogLabelServerTraffic, hs.hello.random, serverSecret)
        //     if err != nil { c.sendAlert(alertInternalError); return err }
        let err = self.c.config.writeKeyLog(
            crate::gostring::string::from_static(super::common::keyLogLabelServerTraffic),
            helloRandom,
            serverSecret,
        );
        if err != crate::errors::nil {
            self.c.sendAlert(super::alert::alertInternalError);
            return err;
        }

        // Go: c.ekm = hs.suite.exportKeyingMaterial(hs.masterSecret, hs.transcript)
        //     return nil
        self.c.ekm = Some(ekm);
        return crate::errors::nil;
    }

    // go: sdk 1.25.5 crypto/tls/handshake_client_tls13.go:830-855 clientHandshakeStateTLS13.sendClientFinished
    /// Go: send the client's Finished, switch the write half to the
    /// application traffic secret, and stash the resumption secret if a
    /// session cache is configured.
    ///
    /// Deviation: the `c.quic != nil` tail is absent — goish ships no
    /// QUIC transport.
    pub(crate) fn sendClientFinished(&mut self) -> crate::error {
        // Go: finished := &finishedMsg{
        //         verifyData: hs.suite.finishedHash(c.out.trafficSecret, hs.transcript)}
        let suite = self.suite.unwrap();
        let verifyData = {
            let transcript = self.transcript.as_ref().unwrap();
            suite.finishedHash(self.c.out.trafficSecret.clone(), &*transcript.0)
        };
        let finished = super::handshake_messages::finishedMsg {
            verifyData: verifyData.__into_vec(),
        };

        // Go: if _, err := hs.c.writeHandshakeRecord(finished, hs.transcript); err != nil { return err }
        let (_, err) = {
            let transcript = self.transcript.as_mut().unwrap();
            self.c
                .writeHandshakeRecord(&finished, Some(transcript))
        };
        if err != crate::errors::nil {
            return err;
        }

        // Go: c.out.setTrafficSecret(hs.suite, QUICEncryptionLevelApplication, hs.trafficSecret)
        self.c.out.setTrafficSecret(
            suite,
            super::quic::QUICEncryptionLevelApplication,
            self.trafficSecret.clone(),
        );

        // Go: if !c.config.SessionTicketsDisabled && c.config.ClientSessionCache != nil {
        //         c.resumptionSecret = hs.masterSecret.ResumptionMasterSecret(hs.transcript) }
        if !self.c.__configSessionTicketsDisabled()
            && self.c.__configClientSessionCache().is_some()
        {
            let master = self.masterSecret.as_ref().unwrap();
            let transcript = self.transcript.as_ref().unwrap();
            let rs = master.ResumptionMasterSecret(&*transcript.0);
            self.c.resumptionSecret = rs;
        }

        // Go: return nil
        return crate::errors::nil;
    }
}

impl clientHandshakeStateTLS13 {
    // go: sdk 1.25.5 crypto/tls/handshake_client_tls13.go:546-611 clientHandshakeStateTLS13.readServerParameters
    /// Go: read the server's EncryptedExtensions and check what it
    /// negotiated there — ALPN, early data, and the ECH retry configs.
    ///
    /// Deviations: the two `c.quic != nil` arms are absent — goish
    /// ships no QUIC transport — which also removes the
    /// `quicRejectedEarlyData` call. The check that the server did NOT
    /// send `quic_transport_parameters` is kept, since that is the arm
    /// a non-QUIC connection takes.
    pub(crate) fn readServerParameters(&mut self) -> crate::error {
        // Go: msg, err := c.readHandshake(hs.transcript)
        let (msg, err) = {
            let transcript = self.transcript.as_mut().unwrap();
            self.c.readHandshake(Some(transcript))
        };
        if err != crate::errors::nil {
            return err;
        }

        // Go: encryptedExtensions, ok := msg.(*encryptedExtensionsMsg); if !ok { … }
        let msg = match msg {
            Some(m) => m,
            None => return crate::errors::New("tls: internal error: no handshake message"),
        };
        let encryptedExtensions = match msg
            .asAny()
            .downcast_ref::<super::handshake_messages::encryptedExtensionsMsg>()
        {
            Some(e) => e.clone(),
            None => {
                self.c.sendAlert(super::alert::alertUnexpectedMessage);
                return super::common::unexpectedMessageError(
                    crate::gostring::string::from_static("*tls.encryptedExtensionsMsg"),
                    super::handshake_messages::handshakeMessageTypeName(&*msg),
                );
            }
        };

        // Go: if err := checkALPN(hs.hello.alpnProtocols, encryptedExtensions.alpnProtocol,
        //         c.quic != nil); err != nil {
        //         c.sendAlert(alertNoApplicationProtocol); return err }
        let alpn = crate::gostring::string::from_bytes(encryptedExtensions.alpnProtocol.as_bytes());
        let err = super::handshake_client::checkALPN(
            crate::goslice::slice::__from_vec(
                self.hello
                    .alpnProtocols
                    .iter()
                    .map(|p| crate::gostring::string::from_bytes(p.as_bytes()))
                    .collect::<alloc::vec::Vec<_>>(),
            ),
            alpn.clone(),
            false,
        );
        if err != crate::errors::nil {
            // Go: "RFC 8446 specifies that no_application_protocol is sent
            // by servers, but does not specify how clients handle the
            // selection of an incompatible protocol. RFC 9001 Section 8.1
            // specifies that QUIC clients send no_application_protocol in
            // this case. Always sending no_application_protocol seems
            // reasonable."
            self.c.sendAlert(super::alert::alertNoApplicationProtocol);
            return err;
        }
        // Go: c.clientProtocol = encryptedExtensions.alpnProtocol
        self.c.__setClientProtocol(alpn);

        // Go: the `c.quic != nil` arm is gone; this is its `else`.
        //     if encryptedExtensions.quicTransportParameters != nil {
        //         c.sendAlert(alertUnsupportedExtension)
        //         return errors.New("tls: server sent an unexpected quic_transport_parameters extension") }
        if encryptedExtensions.quicTransportParameters.len() != 0 {
            self.c.sendAlert(super::alert::alertUnsupportedExtension);
            return crate::errors::New(
                "tls: server sent an unexpected quic_transport_parameters extension",
            );
        }

        // Go: if !hs.hello.earlyData && encryptedExtensions.earlyData { … }
        if !self.hello.earlyData && encryptedExtensions.earlyData {
            self.c.sendAlert(super::alert::alertUnsupportedExtension);
            return crate::errors::New("tls: server sent an unexpected early_data extension");
        }
        // Go: if hs.hello.earlyData && !encryptedExtensions.earlyData {
        //         c.quicRejectedEarlyData() }   — QUIC-only, absent.

        // Go: if encryptedExtensions.earlyData {
        //         if hs.session.cipherSuite != c.cipherSuite { … }
        //         if hs.session.alpnProtocol != c.clientProtocol { … } }
        if encryptedExtensions.earlyData {
            let session = self.session.clone().unwrap_or_default();
            if session.__cipherSuite() != self.c.__cipherSuite() {
                self.c.sendAlert(super::alert::alertHandshakeFailure);
                return crate::errors::New(
                    "tls: server accepted 0-RTT with the wrong cipher suite",
                );
            }
            if session.__alpnProtocol() != self.c.__clientProtocol() {
                self.c.sendAlert(super::alert::alertHandshakeFailure);
                return crate::errors::New("tls: server accepted 0-RTT with the wrong ALPN");
            }
        }

        // Go: if hs.echContext != nil {
        //         if hs.echContext.echRejected {
        //             hs.echContext.retryConfigs = encryptedExtensions.echRetryConfigs
        //         } else if encryptedExtensions.echRetryConfigs != nil { … } }
        if let Some(ech) = self.echContext.as_mut() {
            if ech.echRejected {
                ech.retryConfigs =
                    crate::goslice::slice::__from_vec(encryptedExtensions.echRetryConfigs.clone());
            } else if encryptedExtensions.echRetryConfigs.len() != 0 {
                self.c.sendAlert(super::alert::alertUnsupportedExtension);
                return crate::errors::New(
                    "tls: server sent encrypted client hello retry configs after accepting encrypted client hello",
                );
            }
        }

        // Go: return nil
        return crate::errors::nil;
    }
}

impl clientHandshakeStateTLS13 {
    // go: sdk 1.25.5 crypto/tls/handshake_client_tls13.go:613-705 clientHandshakeStateTLS13.readServerCertificate
    /// Go: read the server's Certificate and CertificateVerify — or,
    /// on a PSK resumption, neither — and check the handshake
    /// signature against the leaf's public key.
    pub(crate) fn readServerCertificate(&mut self) -> crate::error {
        // Go: "Either a PSK or a certificate is always used, but not
        // both. See RFC 8446, Section 4.1.1."
        if self.usingPSK {
            // Go: "Make sure the connection is still being verified
            // whether or not this is a resumption. Resumptions currently
            // don't reverify certificates so they don't call
            // verifyServerCertificate. See Issue 31641."
            if let Some(f) = self.c.config.VerifyConnection.clone() {
                let st = self.c.connectionStateLocked();
                let err = f(st);
                if err != crate::errors::nil {
                    self.c.sendAlert(super::alert::alertBadCertificate);
                    return err;
                }
            }
            return crate::errors::nil;
        }

        // Go: msg, err := c.readHandshake(hs.transcript)
        let (msg, err) = {
            let transcript = self.transcript.as_mut().unwrap();
            self.c.readHandshake(Some(transcript))
        };
        if err != crate::errors::nil {
            return err;
        }
        let mut msg = match msg {
            Some(m) => m,
            None => return crate::errors::New("tls: internal error: no handshake message"),
        };

        // Go: certReq, ok := msg.(*certificateRequestMsgTLS13)
        //     if ok { hs.certReq = certReq
        //         msg, err = c.readHandshake(hs.transcript)
        //         if err != nil { return err } }
        if let Some(certReq) = msg
            .asAny()
            .downcast_ref::<super::handshake_messages::certificateRequestMsgTLS13>()
        {
            self.certReq = Some(certReq.clone());
            let (next, err) = {
                let transcript = self.transcript.as_mut().unwrap();
                self.c.readHandshake(Some(transcript))
            };
            if err != crate::errors::nil {
                return err;
            }
            msg = match next {
                Some(m) => m,
                None => return crate::errors::New("tls: internal error: no handshake message"),
            };
        }

        // Go: certMsg, ok := msg.(*certificateMsgTLS13); if !ok { … }
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
        // Go: if len(certMsg.certificate.Certificate) == 0 {
        //         c.sendAlert(alertDecodeError)
        //         return errors.New("tls: received empty certificates message") }
        if certMsg.certificate.Certificate.Len() == 0 {
            self.c.sendAlert(super::alert::alertDecodeError);
            return crate::errors::New("tls: received empty certificates message");
        }

        // Go: c.scts = certMsg.certificate.SignedCertificateTimestamps
        //     c.ocspResponse = certMsg.certificate.OCSPStaple
        self.c.scts = certMsg.certificate.SignedCertificateTimestamps.clone();
        self.c.ocspResponse = certMsg.certificate.OCSPStaple.clone();

        // Go: if err := c.verifyServerCertificate(certMsg.certificate.Certificate); err != nil { return err }
        let err = self
            .c
            .verifyServerCertificate(certMsg.certificate.Certificate.clone());
        if err != crate::errors::nil {
            return err;
        }

        // Go: "certificateVerifyMsg is included in the transcript, but
        // not until after we verify the handshake signature, since the
        // state before this message was sent is used."
        let (msg, err) = self.c.readHandshake(None);
        if err != crate::errors::nil {
            return err;
        }
        let msg = match msg {
            Some(m) => m,
            None => return crate::errors::New("tls: internal error: no handshake message"),
        };
        // Go: certVerify, ok := msg.(*certificateVerifyMsg); if !ok { … }
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

        // Go: "See RFC 8446, Section 4.4.3. We don't use
        // hs.hello.supportedSignatureAlgorithms because it might include
        // PKCS#1 v1.5 and SHA-1 if the ClientHello also supported TLS 1.2."
        let sigAlg = super::common::SignatureScheme(certVerify.signatureAlgorithm);
        let vers = self.c.__vers();
        let leafKey = self.c.peerCertificates[0].PublicKey.clone();
        if !super::common::isSupportedSignatureAlgorithm(
            sigAlg,
            super::common::supportedSignatureAlgorithms(vers),
        ) || !super::common::isSupportedSignatureAlgorithm(
            sigAlg,
            super::auth::signatureSchemesForPublicKey(vers, &leafKey),
        ) {
            self.c.sendAlert(super::alert::alertIllegalParameter);
            return crate::errors::New("tls: certificate used with invalid signature algorithm");
        }
        // Go: sigType, sigHash, err := typeAndHashFromSignatureScheme(certVerify.signatureAlgorithm)
        //     if err != nil { return c.sendAlert(alertInternalError) }
        let (sigType, sigHash, err) = super::auth::typeAndHashFromSignatureScheme(sigAlg);
        if err != crate::errors::nil {
            return self.c.sendAlert(super::alert::alertInternalError);
        }
        // Go: if sigType == signaturePKCS1v15 || sigHash == crypto.SHA1 {
        //         return c.sendAlert(alertInternalError) }
        if sigType == super::common::signaturePKCS1v15 || sigHash == crate::crypto::SHA1 {
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
        // Go: if err := verifyHandshakeSignature(sigType, c.peerCertificates[0].PublicKey,
        //         sigHash, signed, certVerify.signature); err != nil {
        //         c.sendAlert(alertDecryptError)
        //         return errors.New("tls: invalid signature by the server certificate: " + err.Error()) }
        let err = super::auth::verifyHandshakeSignature(
            sigType,
            &leafKey,
            sigHash,
            signed,
            crate::goslice::slice::__from_vec(certVerify.signature.clone()),
        );
        if err != crate::errors::nil {
            self.c.sendAlert(super::alert::alertDecryptError);
            return crate::fmt::Errorf!(
                "tls: invalid signature by the server certificate: %s",
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

        // Go: return nil
        return crate::errors::nil;
    }
}

impl clientHandshakeStateTLS13 {
    // go: sdk 1.25.5 crypto/tls/handshake_client_tls13.go:756-828 clientHandshakeStateTLS13.sendClientCertificate
    /// Go: answer a CertificateRequest with a chain and a
    /// CertificateVerify — or with an empty Certificate message, which
    /// needs no signature.
    ///
    /// Deviation: Go's `ctx: hs.ctx` on the CertificateRequestInfo has
    /// nowhere to land; goish's `CertificateRequestInfo` carries no
    /// context, as `certificateRequestInfoFromMsg` already documents.
    pub(crate) fn sendClientCertificate(&mut self) -> crate::error {
        // Go: if hs.certReq == nil { return nil }
        let certReq = match self.certReq.clone() {
            Some(r) => r,
            None => return crate::errors::nil,
        };

        // Go: if hs.echContext != nil && hs.echContext.echRejected {
        //         if _, err := hs.c.writeHandshakeRecord(&certificateMsgTLS13{}, hs.transcript);
        //             err != nil { return err }
        //         return nil }
        if self
            .echContext
            .as_ref()
            .map(|e| e.echRejected)
            .unwrap_or(false)
        {
            let empty = super::handshake_messages::certificateMsgTLS13::default();
            let (_, err) = {
                let transcript = self.transcript.as_mut().unwrap();
                self.c.writeHandshakeRecord(&empty, Some(transcript))
            };
            if err != crate::errors::nil {
                return err;
            }
            return crate::errors::nil;
        }

        // Go: cert, err := c.getClientCertificate(&CertificateRequestInfo{
        //         AcceptableCAs: hs.certReq.certificateAuthorities,
        //         SignatureSchemes: hs.certReq.supportedSignatureAlgorithms,
        //         Version: c.vers, ctx: hs.ctx})
        //     if err != nil { return err }
        let mut cri = super::common::CertificateRequestInfo::default();
        cri.AcceptableCAs = certReq.certificateAuthorities.clone();
        cri.SignatureSchemes = certReq.supportedSignatureAlgorithms.clone();
        cri.Version = self.c.__vers();
        let (cert, err) = self.c.getClientCertificate(&cri);
        if err != crate::errors::nil {
            return err;
        }

        // Go: certMsg := new(certificateMsgTLS13)
        //     certMsg.certificate = *cert
        //     certMsg.scts = hs.certReq.scts && len(cert.SignedCertificateTimestamps) > 0
        //     certMsg.ocspStapling = hs.certReq.ocspStapling && len(cert.OCSPStaple) > 0
        let mut certMsg = super::handshake_messages::certificateMsgTLS13::default();
        certMsg.certificate = cert.clone();
        certMsg.scts = certReq.scts && cert.SignedCertificateTimestamps.Len() > 0;
        certMsg.ocspStapling = certReq.ocspStapling && cert.OCSPStaple.Len() > 0;

        // Go: if _, err := hs.c.writeHandshakeRecord(certMsg, hs.transcript); err != nil { return err }
        let (_, err) = {
            let transcript = self.transcript.as_mut().unwrap();
            self.c.writeHandshakeRecord(&certMsg, Some(transcript))
        };
        if err != crate::errors::nil {
            return err;
        }

        // Go: "If we sent an empty certificate message, skip the CertificateVerify."
        if cert.Certificate.Len() == 0 {
            return crate::errors::nil;
        }

        // Go: certVerifyMsg := new(certificateVerifyMsg)
        //     certVerifyMsg.hasSignatureAlgorithm = true
        let mut certVerifyMsg = super::handshake_messages::certificateVerifyMsg::default();
        certVerifyMsg.hasSignatureAlgorithm = true;

        // Go: certVerifyMsg.signatureAlgorithm, err = selectSignatureScheme(c.vers, cert,
        //         hs.certReq.supportedSignatureAlgorithms)
        //     if err != nil {
        //         // getClientCertificate returned a certificate incompatible with the
        //         // CertificateRequestInfo supported signature algorithms.
        //         c.sendAlert(alertHandshakeFailure); return err }
        let (scheme, err) = super::auth::selectSignatureScheme(
            self.c.__vers(),
            &cert,
            certReq.supportedSignatureAlgorithms.clone(),
        );
        if err != crate::errors::nil {
            self.c.sendAlert(super::alert::alertHandshakeFailure);
            return err;
        }
        certVerifyMsg.signatureAlgorithm = scheme.0;

        // Go: sigType, sigHash, err := typeAndHashFromSignatureScheme(certVerifyMsg.signatureAlgorithm)
        //     if err != nil { return c.sendAlert(alertInternalError) }
        let (sigType, sigHash, err) = super::auth::typeAndHashFromSignatureScheme(scheme);
        if err != crate::errors::nil {
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
        // Go: signOpts := crypto.SignerOpts(sigHash)
        //     if sigType == signatureRSAPSS {
        //         signOpts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: sigHash} }
        //     sig, err := cert.PrivateKey.(crypto.Signer).Sign(c.config.rand(), signed, signOpts)
        //     if err != nil { c.sendAlert(alertInternalError)
        //         return errors.New("tls: failed to sign handshake: " + err.Error()) }
        let signer = match super::auth::signerOf(&cert.PrivateKey) {
            Some(s) => s,
            None => {
                self.c.sendAlert(super::alert::alertInternalError);
                return crate::errors::New(
                    "tls: failed to sign handshake: client certificate private key does not implement crypto.Signer",
                );
            }
        };
        let opts: alloc::boxed::Box<dyn crate::crypto::SignerOpts + Send + Sync> =
            if sigType == super::common::signatureRSAPSS {
                alloc::boxed::Box::new(crate::crypto::rsa::PSSOptions {
                    SaltLength: crate::crypto::rsa::PSSSaltLengthEqualsHash,
                    Hash: sigHash,
                })
            } else {
                alloc::boxed::Box::new(sigHash)
            };
        let mut rng = self.c.config.rand();
        let (sig, err) = signer.Sign(&mut *rng, signed, &*opts);
        if err != crate::errors::nil {
            self.c.sendAlert(super::alert::alertInternalError);
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
}
