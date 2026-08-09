// crypto/tls/key_schedule.rs — TLS 1.3 key schedule.
//
// Port of:
//   crypto/internal/fips140/tls13/tls13.go  (ExpandLabel, DeriveSecret,
//     EarlySecret, HandshakeSecret, MasterSecret)
//   crypto/tls/key_schedule.go               (nextTrafficSecret, trafficKey,
//     finishedHash, generateECDHEKey)
//
// Reference: RFC 8446, Section 7.
//
// The hash factory convention: `fn() -> Box<dyn Hash + Send + Sync>`.
// This matches goish's existing hmac::New / hkdf::Extract / hkdf::Expand APIs.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::crypto::{hkdf, hmac};
use crate::goslice::slice;
use crate::hash::Hash as HashTrait;
use crate::io::Writer as WriterTrait;
use crate::types::{byte, int};

// ─── Cipher suite descriptor ───────────────────────────────────────────

/// TLS 1.3 cipher suite descriptor.
/// Contains the hash factory + key/IV lengths for AEAD.
#[derive(Clone)]
pub struct CipherSuiteTls13 {
    /// Cipher suite ID (e.g. 0x1301).
    pub id: u16,
    /// AEAD key length in bytes.
    pub key_len: usize,
    /// Hash factory.
    pub hash_fn: fn() -> Box<dyn HashTrait + Send + Sync>,
    /// Hash output size (bytes). Equal to hash_fn().Size().
    pub hash_size: usize,
}

// TLS 1.3 cipher suites.
pub const TLS_AES_128_GCM_SHA256:      u16 = 0x1301;
pub const TLS_AES_256_GCM_SHA384:      u16 = 0x1302;
pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

/// Build the cipher suite descriptor for a given ID, or None if unsupported.
pub fn cipher_suite_tls13(id: u16) -> Option<CipherSuiteTls13> {
    match id {
        TLS_AES_128_GCM_SHA256 => Some(CipherSuiteTls13 {
            id,
            key_len: 16,
            hash_fn: crate::crypto::sha256::NewHash,
            hash_size: 32,
        }),
        TLS_AES_256_GCM_SHA384 => Some(CipherSuiteTls13 {
            id,
            key_len: 32,
            hash_fn: crate::crypto::sha512::NewHash384,
            hash_size: 48,
        }),
        TLS_CHACHA20_POLY1305_SHA256 => Some(CipherSuiteTls13 {
            id,
            key_len: 32, // ChaCha20-Poly1305 uses a 32-byte key
            hash_fn: crate::crypto::sha256::NewHash,
            hash_size: 32,
        }),
        _ => None,
    }
}

// ─── ExpandLabel (RFC 8446, Section 7.1) ──────────────────────────────
//
// HKDF-Expand-Label(Secret, Label, Context, Length) =
//     HKDF-Expand(Secret, HkdfLabel, Length)
//
// HkdfLabel = uint16(length) || (len("tls13 " + Label) as u8)
//             || "tls13 " || Label || (len(Context) as u8) || Context

pub fn ExpandLabel(
    hash_fn: fn() -> Box<dyn HashTrait + Send + Sync>,
    secret: &[byte],
    label: &str,
    context: &[byte],
    length: usize,
) -> Vec<byte> {
    // Build hkdfLabel: length(2) || label_length(1) || "tls13 " || label || context_length(1) || context
    const PREFIX: &[u8] = b"tls13 ";
    let label_bytes = label.as_bytes();
    let full_label_len = PREFIX.len() + label_bytes.len();

    let mut hkdf_label: Vec<byte> = Vec::new();
    let len_u16 = length as u16;
    hkdf_label.push((len_u16 >> 8) as byte);
    hkdf_label.push((len_u16 & 0xFF) as byte);
    hkdf_label.push(full_label_len as byte);
    hkdf_label.extend_from_slice(PREFIX);
    hkdf_label.extend_from_slice(label_bytes);
    hkdf_label.push(context.len() as byte);
    hkdf_label.extend_from_slice(context);

    // HKDF-Expand
    let secret_s = slice::__from_vec(secret.to_vec());
    // info must be a goish string for hkdf::Expand
    use crate::gostring::string as gostring;
    let info = gostring::from_bytes(&hkdf_label);
    let (out, _) = hkdf::Expand(hash_fn, secret_s, info, length as int);
    out.__into_vec()
}

// ─── DeriveSecret (RFC 8446, Section 7.1) ─────────────────────────────
//
// Derive-Secret(Secret, Label, Messages) =
//     HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)

pub fn DeriveSecret(
    hash_fn: fn() -> Box<dyn HashTrait + Send + Sync>,
    secret: &[byte],
    label: &str,
    transcript_hash: &[byte],
) -> Vec<byte> {
    let hash_size = hash_fn().Size() as usize;
    ExpandLabel(hash_fn, secret, label, transcript_hash, hash_size)
}

// ─── Extract (HKDF-Extract) ────────────────────────────────────────────

fn extract_key(
    hash_fn: fn() -> Box<dyn HashTrait + Send + Sync>,
    new_secret: &[byte],
    current_secret: &[byte],
) -> Vec<byte> {
    // RFC 8446: salt = current_secret, IKM = new_secret
    let ikm = slice::__from_vec(new_secret.to_vec());
    let salt = slice::__from_vec(current_secret.to_vec());
    let (prk, _) = hkdf::Extract(hash_fn, ikm, salt);
    prk.__into_vec()
}

// ─── EarlySecret ──────────────────────────────────────────────────────

pub struct EarlySecret {
    pub secret: Vec<byte>,
    pub hash_fn: fn() -> Box<dyn HashTrait + Send + Sync>,
}

impl EarlySecret {
    /// NewEarlySecret: extract(hash, psk_or_zeros, zeros_salt)
    /// RFC 8446 §7.1: When no PSK, IKM = zeros(hash_size), salt = zeros(hash_size)
    pub fn new(
        hash_fn: fn() -> Box<dyn HashTrait + Send + Sync>,
        psk: Option<&[byte]>,
    ) -> Self {
        let hash_size = hash_fn().Size() as usize;
        let zeros: Vec<byte> = alloc::vec![0u8; hash_size];
        // When psk is None, Go uses zeros of hash_size as the IKM
        let ikm = match psk {
            Some(k) => k.to_vec(),
            None => zeros.clone(),
        };
        let secret = extract_key(hash_fn, &ikm, &zeros);
        EarlySecret { secret, hash_fn }
    }

    /// ResumptionBinderKey: DeriveSecret(earlySecret, "res binder", H(""))
    /// RFC 8446 §4.2.11.2: used to compute the PSK binder in the ClientHello.
    pub fn ResumptionBinderKey(&self) -> Vec<byte> { // goishlint:ignore GOISH008
        let hash_fn = self.hash_fn;
        // H("") = hash of empty string
        let empty_hash = {
            let h = hash_fn();
            let empty = slice::__from_vec(Vec::new());
            h.Sum(empty).__into_vec()
        };
        DeriveSecret(hash_fn, &self.secret, "res binder", &empty_hash)
    }

    /// HandshakeSecret: derive then extract(hash, shared_secret, derived)
    pub fn HandshakeSecret(self, shared_secret: &[byte]) -> HandshakeSecret {
        let hash_fn = self.hash_fn;
        // derived = DeriveSecret(earlySecret, "derived", hash_of_empty)
        let empty_hash = {
            let h = hash_fn();
            let empty_slice = slice::__from_vec(Vec::new());
            h.Sum(empty_slice).__into_vec()
        };
        let derived = DeriveSecret(hash_fn, &self.secret, "derived", &empty_hash);
        let secret = extract_key(hash_fn, shared_secret, &derived);
        HandshakeSecret { secret, hash_fn }
    }
}

// ─── HandshakeSecret ──────────────────────────────────────────────────

pub struct HandshakeSecret {
    pub secret: Vec<byte>,
    pub hash_fn: fn() -> Box<dyn HashTrait + Send + Sync>,
}

impl HandshakeSecret {
    /// ClientHandshakeTrafficSecret: DeriveSecret(hs, "c hs traffic", transcript)
    pub fn ClientHandshakeTrafficSecret(&self, transcript_hash: &[byte]) -> Vec<byte> {
        DeriveSecret(self.hash_fn, &self.secret, "c hs traffic", transcript_hash)
    }

    /// ServerHandshakeTrafficSecret: DeriveSecret(hs, "s hs traffic", transcript)
    pub fn ServerHandshakeTrafficSecret(&self, transcript_hash: &[byte]) -> Vec<byte> {
        DeriveSecret(self.hash_fn, &self.secret, "s hs traffic", transcript_hash)
    }

    /// MasterSecret: derive then extract(hash, zeros, derived)
    pub fn MasterSecret(self) -> MasterSecret {
        let hash_fn = self.hash_fn;
        let empty_hash = {
            let h = hash_fn();
            let empty_slice = slice::__from_vec(Vec::new());
            h.Sum(empty_slice).__into_vec()
        };
        let derived = DeriveSecret(hash_fn, &self.secret, "derived", &empty_hash);
        let hash_size = hash_fn().Size() as usize;
        let zeros: Vec<byte> = alloc::vec![0u8; hash_size];
        let secret = extract_key(hash_fn, &zeros, &derived);
        MasterSecret { secret, hash_fn }
    }
}

// ─── MasterSecret ─────────────────────────────────────────────────────

pub struct MasterSecret {
    pub secret: Vec<byte>,
    pub hash_fn: fn() -> Box<dyn HashTrait + Send + Sync>,
}

impl MasterSecret {
    /// ClientApplicationTrafficSecret: DeriveSecret(ms, "c ap traffic", transcript)
    pub fn ClientApplicationTrafficSecret(&self, transcript_hash: &[byte]) -> Vec<byte> {
        DeriveSecret(self.hash_fn, &self.secret, "c ap traffic", transcript_hash)
    }

    /// ServerApplicationTrafficSecret: DeriveSecret(ms, "s ap traffic", transcript)
    pub fn ServerApplicationTrafficSecret(&self, transcript_hash: &[byte]) -> Vec<byte> {
        DeriveSecret(self.hash_fn, &self.secret, "s ap traffic", transcript_hash)
    }
}

// ─── Traffic key derivation (RFC 8446, Section 7.3) ───────────────────
//
// [sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
// [sender]_write_iv  = HKDF-Expand-Label(Secret, "iv",  "", iv_length)

pub const TLS13_IV_LENGTH: usize = 12;

pub struct TrafficKeys {
    pub key: Vec<byte>,
    pub iv: Vec<byte>,
}

/// Derive traffic key+iv from a traffic secret.
pub fn traffic_keys(
    hash_fn: fn() -> Box<dyn HashTrait + Send + Sync>,
    traffic_secret: &[byte],
    key_len: usize,
) -> TrafficKeys {
    let key = ExpandLabel(hash_fn, traffic_secret, "key", &[], key_len);
    let iv  = ExpandLabel(hash_fn, traffic_secret, "iv",  &[], TLS13_IV_LENGTH);
    TrafficKeys { key, iv }
}

// ─── Finished verify_data (RFC 8446, Section 4.4.4) ───────────────────
//
// finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
// verify_data  = HMAC(finished_key, Transcript-Hash(Messages))

pub fn finished_hash(
    hash_fn: fn() -> Box<dyn HashTrait + Send + Sync>,
    base_key: &[byte],
    transcript_hash: &[byte],
) -> Vec<byte> {
    let hash_size = hash_fn().Size() as usize;
    let finished_key = ExpandLabel(hash_fn, base_key, "finished", &[], hash_size);
    let finished_key_s = slice::__from_vec(finished_key);
    let mut mac = hmac::New(hash_fn, finished_key_s);
    let data_s = slice::__from_vec(transcript_hash.to_vec());
    let _ = WriterTrait::Write(&mut mac, data_s);
    let empty = slice::__from_vec(Vec::new());
    mac.Sum(empty).__into_vec()
}

// ─── Public transcript hash helper ────────────────────────────────────

/// Compute the hash of a transcript buffer.
/// Used by handshake_client_tls13 to compute DeriveSecret inputs.
pub fn transcript_hash_fn(
    hash_fn: fn() -> Box<dyn HashTrait + Send + Sync>,
    transcript: &[byte],
) -> Vec<byte> {
    let mut h = hash_fn();
    let s = slice::__from_vec(transcript.to_vec());
    let _ = WriterTrait::Write(&mut h, s);
    let empty = slice::__from_vec(Vec::new());
    h.Sum(empty).__into_vec()
}

// ─── NextTrafficSecret (RFC 8446, Section 7.2) ────────────────────────
//
// Used for key update: Application-Traffic-Secret_N+1 =
//     HKDF-Expand-Label(Application-Traffic-Secret_N, "traffic upd", "", Hash.length)

pub fn next_traffic_secret(
    hash_fn: fn() -> Box<dyn HashTrait + Send + Sync>,
    traffic_secret: &[byte],
) -> Vec<byte> {
    let hash_size = hash_fn().Size() as usize;
    ExpandLabel(hash_fn, traffic_secret, "traffic upd", &[], hash_size)
}
