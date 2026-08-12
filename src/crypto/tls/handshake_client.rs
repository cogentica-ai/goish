// crypto/tls/handshake_client.rs — TLS 1.2 client handshake.
//
// goishlint:ignore GOISH018 clientHandshake, handshake, doFullHandshake — clientHandshakeState and the Conn-driven half of the TLS 1.2 client; the live client below the divider implements the same protocol by hand. See ROADMAP.md.
// goishlint:ignore GOISH019 echClientContext — same.
// goishlint:ignore GOISH021 echClientContext, tlsmaxrsasize — same; tlsmaxrsasize is an internal/godebug var and godebug is not ported.
//
// Implements the CLIENT side of a TLS 1.2 handshake for:
//   * TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F)  ← preferred
//   * TLS_RSA_WITH_AES_128_CBC_SHA (0x002F)             ← fallback
//
// ClientHello now offers [0xC02F, 0x002F]. ServerHello selects one.
// ECDHE path: ServerKeyExchange follows Certificate; ClientKeyExchange
//   contains the client's ephemeral X25519 public key.
// RSA path: unchanged (no ServerKeyExchange).
//
// Reference: RFC 5246, RFC 4492.

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
use crate::crypto::tls::legacy_p256::{decode_x509_ec_p256_pubkey, P256PublicKey, VerifyP256};
use crate::crypto::rand;
use crate::crypto::rsa;
use crate::crypto::sha256;
use crate::crypto::tls::record::{
    RECORD_ALERT, RECORD_CHANGE_CIPHER_SPEC, RECORD_HANDSHAKE,
    decode_x509_rsa_pubkey, decrypt_record, decrypt_record_aead,
    derive_key_material, derive_aead_key_material,
    derive_master_secret, encrypt_record, encrypt_record_aead, prf12,
    KeyMaterial, TLS_VERSION_MAJOR, TLS_VERSION_MINOR,
};
use crate::errors::{self, error};
use crate::goslice::slice;
use crate::types::byte;

/// Holds either an RSA or EC (P-256) server public key extracted from the
/// server's Certificate message.
enum ServerPublicKey {
    Rsa(rsa::PublicKey),
    Ec(P256PublicKey),
}

// ─── record type constants ────────────────────────────────────────────
const MSG_CLIENT_HELLO: byte = 1;
const MSG_SERVER_HELLO: byte = 2;
const MSG_CERTIFICATE: byte = 11;
const MSG_SERVER_KEY_EXCHANGE: byte = 12;
const MSG_CERTIFICATE_REQUEST: byte = 13;
const MSG_SERVER_HELLO_DONE: byte = 14;
const MSG_CLIENT_KEY_EXCHANGE: byte = 16;
const MSG_FINISHED: byte = 20;

const CIPHER_SUITE_RSA_AES128_CBC_SHA: u16 = 0x002F;
const CIPHER_SUITE_ECDHE_RSA_AES128_GCM_SHA256: u16 = 0xC02F;
const CIPHER_SUITE_ECDHE_ECDSA_AES128_GCM_SHA256: u16 = 0xC02B;

// TLS named curve IDs (RFC 4492).
const NAMED_CURVE_X25519: u16 = 29;
const NAMED_CURVE_SECP256R1: u16 = 23;

// ServerKeyExchange curve type
const CURVE_TYPE_NAMED: u8 = 3;

// TLS extension types
const EXT_SUPPORTED_GROUPS: u16 = 10;
const EXT_EC_POINT_FORMATS: u16 = 11;
const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002B;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_SIG_ALGS_CERT: u16 = 0x0032;

// TLS 1.3 cipher suites
const CIPHER_TLS13_AES128_GCM_SHA256: u16 = 0x1301;
const CIPHER_TLS13_AES256_GCM_SHA384: u16 = 0x1302;
const CIPHER_TLS13_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

// TLS version bytes
const TLS_VERSION_TLS13: u16 = 0x0304;

// ─── ConnAdapter ─────────────────────────────────────────────────────
//
// We need to pass `conn: &mut dyn net::Conn` to `record::read_record`
// which expects `&mut dyn io::Reader`. `dyn net::Conn` doesn't impl
// `io::Reader` as a trait-object (the impl is on the concrete types).
//
// Workaround: define a local adapter that delegates Read/Write.

struct ConnReader<'a>(&'a mut dyn crate::net::Conn);

impl<'a> crate::io::Reader for ConnReader<'a> {
    fn Read(&mut self, p: &mut slice<byte>) -> (crate::types::int, error) {
        self.0.Read(p)
    }
}

// ─── do_client_handshake ─────────────────────────────────────────────

/// Drive a full TLS 1.2 or TLS 1.3 client-side handshake over `conn`.
/// On success returns derived `KeyMaterial`. On failure returns error.
pub fn do_client_handshake(
    conn: &mut dyn crate::net::Conn,
    _server_name: &str,
    _skip_verify: bool,
) -> (KeyMaterial, error) {
    tls_debug!("[tls-debug] do_client_handshake: start server_name=%s\n", _server_name);
    // ── 1. Generate client_random ──────────────────────────────────
    let mut client_random = [0u8; 32];
    {
        let mut buf = slice::<byte>::__from_vec(alloc::vec![0u8; 32]);
        let (_, err) = rand::Read(&mut buf);
        if !err.IsNil() {
            tls_debug!("[tls-debug] rand::Read error: %v\n", err);
            return (KeyMaterial::default(), err);
        }
        client_random.copy_from_slice(&buf.__into_vec()[..32]);
    }
    tls_debug!("[tls-debug] rand::Read OK for server_name=%s\n", _server_name);

    // ── 1b. Generate X25519 keypair for TLS 1.3 key_share ─────────
    let (client_x25519_priv, client_x25519_pub) = ecdh::x25519_generate();

    // ── 1c. Try to load a cached PSK session ──────────────────────
    // RFC 8446 §4.2.11: if a ticket is cached for this server, include
    // the pre_shared_key extension as the LAST extension in ClientHello.
    // We only resume with SHA-256 suites (suite_id 0x1301 or 0x1303)
    // for simplicity — the session hash_size check ensures correctness.
    let psk_session: Option<crate::crypto::tls::session::cachedSession> =
        crate::crypto::tls::session::take(_server_name);

    // ── 2. Build & send ClientHello ────────────────────────────────
    let (client_hello_body, offered_psk_session) = if let Some(sess) = psk_session {
        // Only offer PSK if the suite's hash matches one we support
        let suite_ok = matches!(sess.suite_id,
            0x1301 | 0x1302 | 0x1303
        );
        if suite_ok && sess.hash_size > 0 && !sess.resumption_psk.is_empty() && !sess.ticket.is_empty() {
            // Compute obfuscated_ticket_age
            let now = crate::crypto::tls::session::now_ms();
            let age_ms = now.wrapping_sub(sess.received_at_ms);
            let obf_age = (age_ms as u32).wrapping_add(sess.ticket_age_add); // goishlint:ignore GOISH005

            // Find the hash_fn for this suite
            let hash_fn_opt = crate::crypto::tls::key_schedule::cipher_suite_tls13(sess.suite_id)
                .map(|cs| cs.hash_fn);

            if let Some(hash_fn) = hash_fn_opt {
                tls_debug!("[tls-debug] PSK: offering ticket for %s (suite=0x%04x hash_size=%d ticket_len=%d)\n",
                    _server_name, sess.suite_id as u64, sess.hash_size as i64, sess.ticket.len() as i64); // goishlint:ignore GOISH005
                let (mut ch, binders_len) = build_client_hello_with_psk(
                    &client_random,
                    _server_name,
                    &client_x25519_pub,
                    &sess.ticket,
                    obf_age,
                    sess.hash_size as usize,
                );
                // Compute and patch the binder
                patch_psk_binder(&mut ch, &sess.resumption_psk, hash_fn, binders_len);
                tls_debug!("[tls-debug] PSK: ClientHello with pre_shared_key built, len=%d\n", ch.len() as i64); // goishlint:ignore GOISH005
                (ch, Some(sess))
            } else {
                tls_debug!("[tls-debug] PSK: unknown suite 0x%04x, falling back to full handshake\n", sess.suite_id as u64); // goishlint:ignore GOISH005
                (build_client_hello(&client_random, _server_name, &client_x25519_pub), None)
            }
        } else {
            tls_debug!("[tls-debug] PSK: session unsuitable (suite_ok=%v hash_size=%d), falling back\n",
                suite_ok, sess.hash_size as i64); // goishlint:ignore GOISH005
            (build_client_hello(&client_random, _server_name, &client_x25519_pub), None)
        }
    } else {
        (build_client_hello(&client_random, _server_name, &client_x25519_pub), None)
    };

    tls_debug!("[tls-debug] ClientHello built, len=%d psk_offered=%v\n",
        client_hello_body.len() as i64, offered_psk_session.is_some()); // goishlint:ignore GOISH005

    // Transcript accumulates all handshake messages
    let mut transcript: Vec<byte> = Vec::new();
    transcript.extend_from_slice(&client_hello_body);

    let record_slice = crate::crypto::tls::record::encode_record(
        RECORD_HANDSHAKE,
        &client_hello_body,
    );
    let (_, werr) = conn.Write(record_slice);
    if !werr.IsNil() {
        tls_debug!("[tls-debug] Write ClientHello error: %v\n", werr);
        return (KeyMaterial::default(), werr);
    }
    tls_debug!("[tls-debug] ClientHello sent, waiting for ServerHello\n");

    // ── 3. Receive ServerHello ─────────────────────────────────────
    let server_random;
    let negotiated_suite;
    // TLS 1.3 detection: if supported_versions extension present and == 0x0304
    let mut tls13_suite_id: u16 = 0;
    let mut tls13_server_key_share: Vec<byte> = Vec::new();
    // HRR cookie (EXT type=44=0x002C): if server sends cookie in HRR, echo it in 2nd ClientHello
    let mut hrr_cookie: Option<Vec<byte>> = None;
    // HRR selected_group: the group the server wants us to use in CH2
    let mut hrr_selected_group: u16 = 0;
    // PSK: server may echo selected_identity (0x0029) if it accepted PSK
    let mut sh_selected_psk_identity: Option<u16> = None;
    {
        let (rtype, frag_s, err) = {
            let mut adapter = ConnReader(conn);
            crate::crypto::tls::record::read_record(&mut adapter)
        };
        let frag = frag_s.__into_vec();
        tls_debug!("[tls-debug] read_record: rtype=%d frag_len=%d err=%v\n", rtype as i64, frag.len() as i64, err);
        if !err.IsNil() {
            return (KeyMaterial::default(), err);
        }
        if rtype == RECORD_ALERT {
            let alert_desc = if frag.len() >= 2 { frag[1] } else { 0 };
            tls_debug!("[tls-debug] TLS Alert received: level=%d desc=%d\n", if frag.len() >= 1 { frag[0] as i64 } else { 0 }, alert_desc as i64);
            return (
                KeyMaterial::default(),
                errors::New("tls: received TLS alert from server"),
            );
        }
        if rtype != RECORD_HANDSHAKE {
            tls_debug!("[tls-debug] unexpected record type=%d expected=%d (Handshake)\n", rtype as i64, RECORD_HANDSHAKE as i64);
            return (
                KeyMaterial::default(),
                errors::New("tls: expected Handshake record for ServerHello"),
            );
        }
        if frag.len() < 4 || frag[0] != MSG_SERVER_HELLO {
            tls_debug!("[tls-debug] not ServerHello: frag[0]=%d\n", if frag.is_empty() { 0i64 } else { frag[0] as i64 });
            return (KeyMaterial::default(), errors::New("tls: expected ServerHello message"));
        }
        transcript.extend_from_slice(&frag);

        // Parse ServerHello body (skip 4-byte type+length)
        let body = &frag[4..];
        if body.len() < 35 {
            return (KeyMaterial::default(), errors::New("tls: ServerHello body too short"));
        }
        let maj = body[0];
        let min = body[1];
        tls_debug!("[tls-debug] ServerHello version=%d.%d\n", maj as i64, min as i64);
        // TLS 1.3 ServerHello uses legacy_version = 0x0303 but sets supported_versions = 0x0304
        if maj != TLS_VERSION_MAJOR || min != TLS_VERSION_MINOR {
            tls_debug!("[tls-debug] server not TLS 1.2 or 1.3: got %d.%d\n", maj as i64, min as i64);
            return (KeyMaterial::default(), errors::New("tls: server version not 1.2 or 1.3"));
        }
        let mut sr = [0u8; 32];
        sr.copy_from_slice(&body[2..34]);
        server_random = sr;
        tls_debug!("[tls-debug] server_random first8: %02x%02x%02x%02x%02x%02x%02x%02x\n",
            sr[0] as u64, sr[1] as u64, sr[2] as u64, sr[3] as u64,
            sr[4] as u64, sr[5] as u64, sr[6] as u64, sr[7] as u64);

        let sid_len = body[34] as usize;
        let sid_end = 35 + sid_len;
        if body.len() < sid_end + 2 {
            return (KeyMaterial::default(), errors::New("tls: ServerHello truncated at cipher suite"));
        }
        let cs = u16::from_be_bytes([body[sid_end], body[sid_end + 1]]);
        tls_debug!("[tls-debug] ServerHello cipher_suite=0x%04x\n", cs as u64);

        // Check if extensions present (skip compression method byte)
        if body.len() > sid_end + 3 {
            let comp_method_offset = sid_end + 2;
            if body.len() > comp_method_offset + 2 {
                let ext_total_len = u16::from_be_bytes([body[comp_method_offset + 1], body[comp_method_offset + 2]]) as usize;
                let ext_start = comp_method_offset + 3;
                if ext_start + ext_total_len <= body.len() {
                    let exts = &body[ext_start..ext_start + ext_total_len];
                    // Parse extensions: type(2) + len(2) + data
                    let mut pos = 0usize;
                    while pos + 4 <= exts.len() {
                        let ext_type = u16::from_be_bytes([exts[pos], exts[pos + 1]]);
                        let ext_len = u16::from_be_bytes([exts[pos + 2], exts[pos + 3]]) as usize;
                        pos += 4;
                        if pos + ext_len > exts.len() { break; }
                        let ext_data = &exts[pos..pos + ext_len];
                        match ext_type {
                            EXT_SUPPORTED_VERSIONS => {
                                // Should be exactly 2 bytes: selected version
                                if ext_len >= 2 {
                                    let selected = u16::from_be_bytes([ext_data[0], ext_data[1]]);
                                    tls_debug!("[tls-debug] ServerHello supported_versions=0x%04x\n", selected as u64);
                                    if selected == TLS_VERSION_TLS13 {
                                        // TLS 1.3 selected: check suite
                                        if cs != CIPHER_TLS13_AES128_GCM_SHA256
                                            && cs != CIPHER_TLS13_AES256_GCM_SHA384
                                            && cs != CIPHER_TLS13_CHACHA20_POLY1305_SHA256
                                        {
                                            tls_debug!("[tls-debug] TLS 1.3 but unsupported suite 0x%04x\n", cs as u64);
                                            return (KeyMaterial::default(), errors::New("tls: TLS 1.3 server chose unsupported cipher suite"));
                                        }
                                        tls13_suite_id = cs;
                                    }
                                }
                            }
                            EXT_KEY_SHARE => {
                                // key_share extension: group(2) + key_exchange_len(2) + key_exchange
                                // In HRR, key_share has only group(2) (no key exchange data)
                                if ext_len >= 2 {
                                    let group = u16::from_be_bytes([ext_data[0], ext_data[1]]);
                                    if ext_len >= 4 {
                                        let ke_len = u16::from_be_bytes([ext_data[2], ext_data[3]]) as usize;
                                        tls_debug!("[tls-debug] ServerHello key_share group=0x%04x ke_len=%d\n", group as u64, ke_len as i64);
                                        if group == 29 && ext_len >= 4 + ke_len { // X25519
                                            tls13_server_key_share = ext_data[4..4 + ke_len].to_vec();
                                        }
                                    } else {
                                        // HRR: only group (no key exchange) — save the requested group
                                        hrr_selected_group = group;
                                        tls_debug!("[tls-debug] HRR key_share selected_group=0x%04x\n", group as u64);
                                    }
                                }
                            }
                            0x002C => {
                                // Cookie extension (RFC 8446 §4.2.2): u16-length-prefixed opaque data
                                if ext_len >= 2 {
                                    let cookie_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                                    if 2 + cookie_len <= ext_len {
                                        hrr_cookie = Some(ext_data[2..2 + cookie_len].to_vec());
                                        tls_debug!("[tls-debug] HRR cookie received (len=%d)\n", cookie_len as i64);
                                    }
                                }
                            }
                            0x0029 => {
                                // pre_shared_key — ServerHello body is uint16 selected_identity
                                if ext_len >= 2 {
                                    let sel_id = u16::from_be_bytes([ext_data[0], ext_data[1]]);
                                    tls_debug!("[tls-debug] PSK selected: selected_identity=%d\n", sel_id as i64); // goishlint:ignore GOISH005
                                    sh_selected_psk_identity = Some(sel_id);
                                }
                            }
                            _ => {}
                        }
                        pos += ext_len;
                    }
                }
            }
        }

        if tls13_suite_id != 0 {
            // TLS 1.3 path — cipher_suite and server key share already captured
            negotiated_suite = cs;
        } else {
            // TLS 1.2 path
            if cs != CIPHER_SUITE_RSA_AES128_CBC_SHA
                && cs != CIPHER_SUITE_ECDHE_RSA_AES128_GCM_SHA256
                && cs != CIPHER_SUITE_ECDHE_ECDSA_AES128_GCM_SHA256
            {
                tls_debug!("[tls-debug] unsupported cipher suite 0x%04x\n", cs as u64);
                return (KeyMaterial::default(), errors::New("tls: server chose unsupported cipher suite"));
            }
            negotiated_suite = cs;
        }
        tls_debug!("[tls-debug] negotiated suite=0x%04x tls13=%v\n", negotiated_suite as u64, tls13_suite_id != 0);
    }

    // ── 3b. HRR detection and retry ───────────────────────────────
    // RFC 8446 §4.1.4: If the server's ServerHello random == helloRetryRequestRandom,
    // we must:
    //   1. Replace transcript with message_hash form
    //   2. Re-send a new ClientHello with the requested key group
    //   3. Read the real ServerHello
    const HRR_RANDOM: [u8; 32] = [
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
        0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
        0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
        0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
    ];
    if tls13_suite_id != 0 && server_random == HRR_RANDOM {
        tls_debug!("[tls-debug] HelloRetryRequest detected (suite=0x%04x group=0x%04x) — retrying\n",
            tls13_suite_id as u64, hrr_selected_group as u64);

        // Get the hash function for the negotiated suite
        let hrr_suite = match crate::crypto::tls::key_schedule::cipher_suite_tls13(tls13_suite_id) {
            Some(s) => s,
            None => return (KeyMaterial::default(), errors::New("tls13: unsupported cipher suite in HRR")),
        };
        let hash_fn = hrr_suite.hash_fn;

        // Step 1: Replace transcript with message_hash form.
        // Per RFC 8446 §4.4.1:
        //   chHash = H(ClientHello1)
        //   new_transcript = {typeMessageHash(254), 0, 0, len(chHash), chHash...}
        //                    || ServerHello_HRR || ClientHello2 || ServerHello2
        let hrr_server_hello = transcript[client_hello_body.len()..].to_vec();
        let ch_hash = crate::crypto::tls::key_schedule::transcript_hash_fn(hash_fn, &client_hello_body);
        let hash_len = ch_hash.len() as byte;
        let mut new_transcript: Vec<byte> = Vec::new();
        new_transcript.push(0xFEu8); // typeMessageHash = 254
        new_transcript.push(0x00u8);
        new_transcript.push(0x00u8);
        new_transcript.push(hash_len);
        new_transcript.extend_from_slice(&ch_hash);
        new_transcript.extend_from_slice(&hrr_server_hello);
        transcript = new_transcript;

        // Step 3: Generate keypair for the group the server requested.
        // If the server asked for P-256 (group 23 = 0x0017), use P-256 ECDH.
        // Otherwise fall back to X25519.
        // Returns: (ch2_group, ch2_key_share_bytes, hrr_priv_x25519, hrr_priv_p256_scalar)
        const GROUP_X25519: u16 = 29;
        const GROUP_P256: u16 = 23;
        let use_group = if hrr_selected_group == GROUP_P256 {
            GROUP_P256
        } else {
            // Default to X25519 for group 29 or unknown groups
            GROUP_X25519
        };

        // Extract session_id from CH1 so we can reuse it in CH2.
        // RFC 8446: CH2 MUST use the same session_id as CH1.
        // client_hello_body layout: type(1)+len(3)+version(2)+random(32)+sid_len(1)+sid(32)+...
        // => session_id is at offset 4+2+32+1 = 39, length 32.
        let ch1_session_id: [u8; 32] = if client_hello_body.len() >= 71 {
            let mut sid = [0u8; 32];
            sid.copy_from_slice(&client_hello_body[39..71]);
            sid
        } else {
            [0u8; 32] // shouldn't happen
        };

        // P-256 private scalar (32 bytes) and full uncompressed public key (65 bytes)
        let mut hrr_p256_scalar = [0u8; 32];
        // X25519 private key and public key (32 bytes)
        let (client_x25519_priv_hrr, client_x25519_pub_hrr) = ecdh::x25519_generate();

        let ch2_key_share_bytes: Vec<byte>;
        if use_group == GROUP_P256 {
            let (scalar, pub65) = crate::crypto::tls::legacy_p256::p256_keypair_generate();
            hrr_p256_scalar = scalar;
            ch2_key_share_bytes = pub65.to_vec(); // 65 bytes
        } else {
            ch2_key_share_bytes = client_x25519_pub_hrr.0.to_vec(); // 32 bytes
        };

        // Step 4: Build CH2 with the new key share, correct group, and SAME session_id as CH1
        let client_hello_body2 = build_client_hello_hrr_group(
            &client_random, _server_name, use_group, &ch2_key_share_bytes,
            hrr_cookie.as_deref(), &ch1_session_id
        );
        transcript.extend_from_slice(&client_hello_body2);

        // Send CCS for middlebox compat before 2nd ClientHello (RFC 8446 D.4)
        let ccs_rec = crate::crypto::tls::record::encode_record(
            crate::crypto::tls::record::RECORD_CHANGE_CIPHER_SPEC,
            &[1u8],
        );
        let (_, werr) = conn.Write(ccs_rec);
        if !werr.IsNil() {
            return (KeyMaterial::default(), werr);
        }

        let record_slice2 = crate::crypto::tls::record::encode_record(
            RECORD_HANDSHAKE,
            &client_hello_body2,
        );
        let (_, werr2) = conn.Write(record_slice2);
        if !werr2.IsNil() {
            return (KeyMaterial::default(), werr2);
        }
        tls_debug!("[tls-debug] HRR: sent new ClientHello (group=0x%04x)\n", use_group as u64);

        // Step 5: Read the real ServerHello
        // hrr_server2_group: the group from the 2nd ServerHello key_share
        let mut hrr_server2_group: u16 = 0;
        let mut hrr_server2_key_data: Vec<byte> = Vec::new();
        tls13_suite_id = 0;
        {
            // Skip ChangeCipherSpec if server sends one
            loop {
                let (rtype2, frag2_s, err2) = {
                    let mut adapter = ConnReader(conn);
                    crate::crypto::tls::record::read_record(&mut adapter)
                };
                let frag2 = frag2_s.__into_vec();
                if !err2.IsNil() {
                    return (KeyMaterial::default(), err2);
                }
                if rtype2 == crate::crypto::tls::record::RECORD_CHANGE_CIPHER_SPEC {
                    tls_debug!("[tls-debug] HRR: skipping server CCS\n");
                    continue;
                }
                if rtype2 != RECORD_HANDSHAKE {
                    tls_debug!("[tls-debug] HRR: 2nd ServerHello read got rtype=%d frag_len=%d\n", rtype2 as i64, frag2.len() as i64);
                    if rtype2 == RECORD_ALERT && frag2.len() >= 2 {
                        tls_debug!("[tls-debug] HRR: Alert level=%d desc=%d\n", frag2[0] as i64, frag2[1] as i64);
                    }
                    return (KeyMaterial::default(), errors::New("tls13: HRR: expected Handshake record for 2nd ServerHello"));
                }
                if frag2.len() < 4 || frag2[0] != MSG_SERVER_HELLO {
                    return (KeyMaterial::default(), errors::New("tls13: HRR: expected 2nd ServerHello"));
                }
                transcript.extend_from_slice(&frag2);

                let body2 = &frag2[4..];
                if body2.len() < 35 {
                    return (KeyMaterial::default(), errors::New("tls13: HRR: 2nd ServerHello too short"));
                }
                // server random check: must NOT be HRR again
                let mut sr2 = [0u8; 32];
                sr2.copy_from_slice(&body2[2..34]);
                if sr2 == HRR_RANDOM {
                    return (KeyMaterial::default(), errors::New("tls13: server sent two HelloRetryRequests"));
                }

                let sid_len2 = body2[34] as usize;
                let sid_end2 = 35 + sid_len2;
                if body2.len() < sid_end2 + 3 {
                    return (KeyMaterial::default(), errors::New("tls13: HRR: 2nd ServerHello truncated"));
                }
                let cs2 = u16::from_be_bytes([body2[sid_end2], body2[sid_end2 + 1]]);
                tls_debug!("[tls-debug] HRR: 2nd ServerHello cipher_suite=0x%04x\n", cs2 as u64);

                // Parse extensions
                if body2.len() > sid_end2 + 3 {
                    let comp_off2 = sid_end2 + 2;
                    if body2.len() > comp_off2 + 2 {
                        let ext_total2 = u16::from_be_bytes([body2[comp_off2 + 1], body2[comp_off2 + 2]]) as usize;
                        let ext_start2 = comp_off2 + 3;
                        if ext_start2 + ext_total2 <= body2.len() {
                            let exts2 = &body2[ext_start2..ext_start2 + ext_total2];
                            let mut epos = 0usize;
                            while epos + 4 <= exts2.len() {
                                let etype = u16::from_be_bytes([exts2[epos], exts2[epos+1]]);
                                let elen = u16::from_be_bytes([exts2[epos+2], exts2[epos+3]]) as usize;
                                epos += 4;
                                if epos + elen > exts2.len() { break; }
                                let edata = &exts2[epos..epos+elen];
                                match etype {
                                    EXT_SUPPORTED_VERSIONS => {
                                        if elen >= 2 {
                                            let sv2 = u16::from_be_bytes([edata[0], edata[1]]);
                                            if sv2 == TLS_VERSION_TLS13 {
                                                if cs2 == CIPHER_TLS13_AES128_GCM_SHA256
                                                    || cs2 == CIPHER_TLS13_AES256_GCM_SHA384
                                                    || cs2 == CIPHER_TLS13_CHACHA20_POLY1305_SHA256
                                                {
                                                    tls13_suite_id = cs2;
                                                }
                                            }
                                        }
                                    }
                                    EXT_KEY_SHARE => {
                                        if elen >= 4 {
                                            let group2 = u16::from_be_bytes([edata[0], edata[1]]);
                                            let ke_len2 = u16::from_be_bytes([edata[2], edata[3]]) as usize;
                                            if elen >= 4 + ke_len2 {
                                                hrr_server2_group = group2;
                                                hrr_server2_key_data = edata[4..4 + ke_len2].to_vec();
                                                tls_debug!("[tls-debug] HRR: 2nd ServerHello key_share group=0x%04x ke_len=%d\n",
                                                    group2 as u64, ke_len2 as i64);
                                            }
                                        }
                                    }
                                    _ => {}
                                }
                                epos += elen;
                            }
                        }
                    }
                }
                break;
            }
        }

        if tls13_suite_id == 0 {
            return (KeyMaterial::default(), errors::New("tls13: HRR: 2nd ServerHello did not select TLS 1.3"));
        }
        if hrr_server2_key_data.is_empty() {
            return (KeyMaterial::default(), errors::New("tls13: HRR: no key_share in 2nd ServerHello"));
        }
        tls_debug!("[tls-debug] HRR: retry succeeded, suite=0x%04x server_group=0x%04x\n",
            tls13_suite_id as u64, hrr_server2_group as u64);

        // Compute ECDHE shared secret using the appropriate key type
        let hrr_shared_secret: [u8; 32];
        if hrr_server2_group == GROUP_P256 && hrr_server2_key_data.len() == 65 {
            // Server responded with P-256 key share
            hrr_shared_secret = crate::crypto::tls::legacy_p256::p256_ecdh_compute(
                &hrr_p256_scalar,
                &hrr_server2_key_data,
            );
            let mut is_zero = 0u8;
            for b in hrr_shared_secret.iter() { is_zero |= *b; }
            if is_zero == 0 {
                return (KeyMaterial::default(), errors::New("tls13: HRR: P-256 shared secret is all zeros"));
            }
            tls_debug!("[tls-debug] HRR: P-256 ECDHE shared secret computed OK\n");
        } else if hrr_server2_group == GROUP_X25519 && hrr_server2_key_data.len() == 32 {
            // Server responded with X25519 key share
            let mut srv_pub = [0u8; 32];
            srv_pub.copy_from_slice(&hrr_server2_key_data);
            let srv_x25519_pub = ecdh::X25519PublicKey(srv_pub);
            let ss = ecdh::x25519_compute_shared(&client_x25519_priv_hrr, &srv_x25519_pub);
            let mut is_zero = 0u8;
            for b in ss.iter() { is_zero |= *b; }
            if is_zero == 0 {
                return (KeyMaterial::default(), errors::New("tls13: HRR: X25519 shared secret is all zeros"));
            }
            hrr_shared_secret = ss;
            tls_debug!("[tls-debug] HRR: X25519 ECDHE shared secret computed OK\n");
        } else {
            tls_debug!("[tls-debug] HRR: unsupported server key share group=0x%04x len=%d\n",
                hrr_server2_group as u64, hrr_server2_key_data.len() as i64);
            return (KeyMaterial::default(), errors::New("tls13: HRR: unsupported server key group"));
        }

        // Complete the TLS 1.3 handshake with the pre-computed shared secret
        let suite_hrr = match crate::crypto::tls::key_schedule::cipher_suite_tls13(tls13_suite_id) {
            Some(s) => s,
            None => return (KeyMaterial::default(), errors::New("tls13: unsupported cipher suite after HRR")),
        };
        let (tls13_keys, err) = crate::crypto::tls::handshake_client_tls13::do_client_handshake_tls13_with_ecdhe(
            conn,
            &suite_hrr,
            &transcript,
            &hrr_shared_secret,
        );
        if !err.IsNil() {
            tls_debug!("[tls-debug] HRR TLS 1.3 handshake error: %v\n", err);
            return (KeyMaterial::default(), err);
        }
        let mut km = KeyMaterial::default();
        km.suite = tls13_suite_id;
        km.is_tls13 = true;
        let ck = &tls13_keys.client_app_keys;
        let sk = &tls13_keys.server_app_keys;
        let ck_len = ck.key.len().min(32);
        let sk_len = sk.key.len().min(32);
        km.tls13_client_key[..ck_len].copy_from_slice(&ck.key[..ck_len]);
        km.tls13_server_key[..sk_len].copy_from_slice(&sk.key[..sk_len]);
        let civ_len = ck.iv.len().min(12);
        let siv_len = sk.iv.len().min(12);
        km.tls13_client_iv[..civ_len].copy_from_slice(&ck.iv[..civ_len]);
        km.tls13_server_iv[..siv_len].copy_from_slice(&sk.iv[..siv_len]);
        km.tls13_server_app_secret = tls13_keys.server_app_secret.clone();
        km.tls13_resumption_master_secret = tls13_keys.resumption_master_secret.clone();
        km.tls13_hash_size = tls13_keys.hash_size;
        return (km, errors::nil);
    }

    // ── 3b. TLS 1.3 dispatch ──────────────────────────────────────
    if tls13_suite_id != 0 {
        tls_debug!("[tls-debug] TLS 1.3 dispatch: suite=0x%04x\n", tls13_suite_id as u64); // goishlint:ignore GOISH005
        if tls13_server_key_share.is_empty() {
            return (KeyMaterial::default(), errors::New("tls13: no key_share in ServerHello"));
        }
        let suite = match crate::crypto::tls::key_schedule::cipher_suite_tls13(tls13_suite_id) {
            Some(s) => s,
            None => return (KeyMaterial::default(), errors::New("tls13: unsupported cipher suite")),
        };

        // Determine if PSK was accepted by the server
        let accepted_psk: Option<Vec<byte>> = if sh_selected_psk_identity == Some(0) {
            // Server selected identity index 0 — use the PSK we offered
            if let Some(ref sess) = offered_psk_session {
                tls_debug!("[tls-debug] PSK accepted by server — using PSK for handshake\n");
                Some(sess.resumption_psk.clone())
            } else {
                None
            }
        } else {
            if sh_selected_psk_identity.is_some() {
                tls_debug!("[tls-debug] PSK: server selected unknown identity %d, ignoring\n",
                    sh_selected_psk_identity.unwrap() as i64); // goishlint:ignore GOISH005
            }
            None
        };

        let (tls13_keys, err) = if let Some(psk) = accepted_psk {
            crate::crypto::tls::handshake_client_tls13::do_client_handshake_tls13_with_psk(
                conn,
                &suite,
                &transcript,
                &tls13_server_key_share,
                &client_x25519_priv,
                &psk,
            )
        } else {
            crate::crypto::tls::handshake_client_tls13::do_client_handshake_tls13(
                conn,
                &suite,
                &transcript,
                &client_random,
                &tls13_server_key_share,
                &client_x25519_priv,
            )
        };
        if !err.IsNil() {
            tls_debug!("[tls-debug] TLS 1.3 handshake error: %v\n", err);
            return (KeyMaterial::default(), err);
        }

        // Package TLS 1.3 keys into KeyMaterial
        let mut km = KeyMaterial::default();
        km.suite = tls13_suite_id;
        km.is_tls13 = true;
        // Copy keys (support up to 32-byte keys — AES-256)
        let ck = &tls13_keys.client_app_keys;
        let sk = &tls13_keys.server_app_keys;
        let ck_len = ck.key.len().min(32);
        let sk_len = sk.key.len().min(32);
        km.tls13_client_key[..ck_len].copy_from_slice(&ck.key[..ck_len]);
        km.tls13_server_key[..sk_len].copy_from_slice(&sk.key[..sk_len]);
        let civ_len = ck.iv.len().min(12);
        let siv_len = sk.iv.len().min(12);
        km.tls13_client_iv[..civ_len].copy_from_slice(&ck.iv[..civ_len]);
        km.tls13_server_iv[..siv_len].copy_from_slice(&sk.iv[..siv_len]);
        km.tls13_server_app_secret = tls13_keys.server_app_secret.clone();
        km.tls13_resumption_master_secret = tls13_keys.resumption_master_secret.clone();
        km.tls13_hash_size = tls13_keys.hash_size;
        return (km, errors::nil);
    }

    // ── 4. Receive Certificate ─────────────────────────────────────
    let server_pub_key: ServerPublicKey;
    {
        let (rtype, frag_s, err) = {
            let mut adapter = ConnReader(conn);
            crate::crypto::tls::record::read_record(&mut adapter)
        };
        let frag = frag_s.__into_vec();
        tls_debug!("[tls-debug] cert record: rtype=%d len=%d err=%v\n", rtype as i64, frag.len() as i64, err);
        if !err.IsNil() {
            return (KeyMaterial::default(), err);
        }
        if rtype != RECORD_HANDSHAKE || frag.is_empty() || frag[0] != MSG_CERTIFICATE {
            tls_debug!("[tls-debug] expected Certificate (11) got rtype=%d msg=%d\n", rtype as i64, if frag.is_empty() { 0i64 } else { frag[0] as i64 });
            return (KeyMaterial::default(), errors::New("tls: expected Certificate message"));
        }
        transcript.extend_from_slice(&frag);

        // Certificate payload starts at frag[4] (after type+length)
        // Format: 3-byte total_list_len + [ 3-byte cert_len + DER ... ]
        let body = &frag[4..];
        if body.len() < 6 {
            return (KeyMaterial::default(), errors::New("tls: Certificate message too short"));
        }
        let cert_len = u24_to_usize([body[3], body[4], body[5]]);
        if cert_len > body.len().saturating_sub(6) {
            return (KeyMaterial::default(), errors::New("tls: Certificate DER truncated"));
        }
        let cert_der = &body[6..6 + cert_len];

        // Dispatch on cipher suite: ECDSA suites use EC pubkey, RSA suites use RSA pubkey.
        if negotiated_suite == CIPHER_SUITE_ECDHE_ECDSA_AES128_GCM_SHA256 {
            let (ec_pk, pk_err) = decode_x509_ec_p256_pubkey(cert_der);
            if !pk_err.IsNil() {
                tls_debug!("[tls-debug] decode_x509_ec_p256_pubkey error: %v\n", pk_err);
                return (KeyMaterial::default(), pk_err);
            }
            tls_debug!("[tls-debug] Certificate decoded OK (ECDSA P-256)\n");
            server_pub_key = ServerPublicKey::Ec(ec_pk);
        } else {
            let (pk, pk_err) = decode_x509_rsa_pubkey(cert_der);
            if !pk_err.IsNil() {
                tls_debug!("[tls-debug] decode_x509_rsa_pubkey error: %v\n", pk_err);
                return (KeyMaterial::default(), pk_err);
            }
            tls_debug!("[tls-debug] Certificate decoded OK (RSA)\n");
            server_pub_key = ServerPublicKey::Rsa(pk);
        }
    }

    // ── 5. ECDHE: Receive ServerKeyExchange (only for 0xC02F or 0xC02B) ────
    // For RSA path, skip directly to ServerHelloDone.
    let ecdhe_premaster: Option<[u8; 32]>;
    // client_pub is variable length: 32 bytes for X25519, 65 bytes for P-256
    let ecdhe_client_pub: Option<Vec<byte>>;
    let is_ecdhe = negotiated_suite == CIPHER_SUITE_ECDHE_RSA_AES128_GCM_SHA256
        || negotiated_suite == CIPHER_SUITE_ECDHE_ECDSA_AES128_GCM_SHA256;
    tls_debug!("[tls-debug] suite=0x%04x expecting SKE=%v\n", negotiated_suite as u64, is_ecdhe);
    if is_ecdhe {
        let (rtype, frag_s, err) = {
            let mut adapter = ConnReader(conn);
            crate::crypto::tls::record::read_record(&mut adapter)
        };
        let frag = frag_s.__into_vec();
        tls_debug!("[tls-debug] SKE record: rtype=%d len=%d err=%v\n", rtype as i64, frag.len() as i64, err);
        if !err.IsNil() {
            return (KeyMaterial::default(), err);
        }
        if rtype != RECORD_HANDSHAKE || frag.is_empty() || frag[0] != MSG_SERVER_KEY_EXCHANGE {
            tls_debug!("[tls-debug] expected SKE(12) got rtype=%d msg=%d\n", rtype as i64, if frag.is_empty() { 0i64 } else { frag[0] as i64 });
            return (KeyMaterial::default(), errors::New("tls: expected ServerKeyExchange for ECDHE"));
        }
        transcript.extend_from_slice(&frag);

        // Parse ServerKeyExchange body (skip 4-byte HS header)
        let body = &frag[4..];
        let (pm, client_pub_vec, ske_err) = match &server_pub_key {
            ServerPublicKey::Rsa(rsa_pk) => {
                let (pm, pub32, e) = parse_server_key_exchange(
                    body,
                    &client_random,
                    &server_random,
                    rsa_pk,
                );
                (pm, pub32.to_vec(), e)
            }
            ServerPublicKey::Ec(ec_pk) => {
                parse_server_key_exchange_ecdsa(
                    body,
                    &client_random,
                    &server_random,
                    ec_pk,
                )
            }
        };
        if !ske_err.IsNil() {
            return (KeyMaterial::default(), ske_err);
        }
        ecdhe_premaster = Some(pm);
        ecdhe_client_pub = Some(client_pub_vec);
    } else {
        ecdhe_premaster = None;
        ecdhe_client_pub = None;
    }

    // ── 6. Receive optional CertificateRequest, then ServerHelloDone ─
    // Servers that advertise client cert support (e.g. Kubernetes apiservers
    // with --client-ca-file) send CertificateRequest between SKE and SHD.
    // We treat it as "polite request, declined" — we don't have a client
    // cert, so we'll later send an empty Certificate message before CKE.
    let mut server_requested_client_cert = false;
    loop {
        let (rtype, frag_s, err) = {
            let mut adapter = ConnReader(conn);
            crate::crypto::tls::record::read_record(&mut adapter)
        };
        let frag = frag_s.__into_vec();
        if !err.IsNil() {
            return (KeyMaterial::default(), err);
        }
        if rtype != RECORD_HANDSHAKE || frag.is_empty() {
            return (KeyMaterial::default(), errors::New("tls: expected ServerHelloDone"));
        }
        let msg_type = frag[0];
        transcript.extend_from_slice(&frag);
        if msg_type == MSG_CERTIFICATE_REQUEST {
            server_requested_client_cert = true;
            continue; // loop and read the next handshake message
        }
        if msg_type == MSG_SERVER_HELLO_DONE {
            break;
        }
        return (KeyMaterial::default(), errors::New("tls: expected ServerHelloDone"));
    }

    // ── 7. If the server requested a client cert, send empty Certificate ──
    // RFC 5246 §7.4.6: if we received CertificateRequest, we must send a
    // Certificate message before ClientKeyExchange. Empty cert list (3-byte
    // length = 0) is legitimate and means "I have no client cert".
    if server_requested_client_cert {
        let empty_cert_body: [byte; 3] = [0, 0, 0];
        let cert_msg = build_handshake_msg(MSG_CERTIFICATE, &empty_cert_body);
        transcript.extend_from_slice(&cert_msg);
        let cert_record = crate::crypto::tls::record::encode_record(RECORD_HANDSHAKE, &cert_msg);
        let (_, werr) = conn.Write(cert_record);
        if !werr.IsNil() {
            return (KeyMaterial::default(), werr);
        }
    }

    // ── 8. Build & send ClientKeyExchange ─────────────────────────
    let premaster_48: [u8; 48];
    let cke_body;

    if negotiated_suite == CIPHER_SUITE_ECDHE_RSA_AES128_GCM_SHA256
        || negotiated_suite == CIPHER_SUITE_ECDHE_ECDSA_AES128_GCM_SHA256
    {
        // ECDHE: CKE body = pubkey_len_byte(1) || client_pub (variable length)
        // X25519: pubkey_len=32, P-256: pubkey_len=65
        let client_pub = ecdhe_client_pub.unwrap();
        let pub_len = client_pub.len();
        let mut b: Vec<byte> = Vec::with_capacity(1 + pub_len);
        b.push(pub_len as byte); // goishlint:ignore GOISH005
        b.extend_from_slice(&client_pub);
        cke_body = build_handshake_msg(MSG_CLIENT_KEY_EXCHANGE, &b);

        // premaster = ECDHE shared secret (32 bytes), padded to 48 for derive_master_secret
        let pm32 = ecdhe_premaster.unwrap();
        let mut pm48 = [0u8; 48];
        pm48[..32].copy_from_slice(&pm32);
        premaster_48 = pm48;
    } else {
        // RSA: premaster secret is 48-byte random, encrypted with server's public key
        let mut pm = [0u8; 48];
        pm[0] = TLS_VERSION_MAJOR;
        pm[1] = TLS_VERSION_MINOR;
        {
            let mut buf = slice::<byte>::__from_vec(alloc::vec![0u8; 46]);
            let _ = rand::Read(&mut buf);
            let v = buf.__into_vec();
            pm[2..48].copy_from_slice(&v[..46]);
        }
        let encrypted_pm = {
            let pm_slice = slice::<byte>::__from_vec(pm.to_vec());
            let mut rng = rand::RandReader;
            let rsa_pk = match &server_pub_key {
                ServerPublicKey::Rsa(pk) => pk,
                ServerPublicKey::Ec(_) => {
                    return (KeyMaterial::default(), errors::New("tls: RSA CKE but server has EC key"));
                }
            };
            let (enc, err) = rsa::EncryptPKCS1v15(&mut rng, rsa_pk, pm_slice);
            if !err.IsNil() {
                return (KeyMaterial::default(), err);
            }
            enc.__into_vec()
        };
        let enc_len = encrypted_pm.len();
        let mut b: Vec<byte> = Vec::with_capacity(2 + enc_len);
        b.push(((enc_len >> 8) & 0xFF) as byte); // goishlint:ignore GOISH005
        b.push((enc_len & 0xFF) as byte); // goishlint:ignore GOISH005
        b.extend_from_slice(&encrypted_pm);
        cke_body = build_handshake_msg(MSG_CLIENT_KEY_EXCHANGE, &b);
        premaster_48 = pm;
    }

    transcript.extend_from_slice(&cke_body);
    let cke_slice = crate::crypto::tls::record::encode_record(RECORD_HANDSHAKE, &cke_body);
    let (_, werr) = conn.Write(cke_slice);
    if !werr.IsNil() {
        return (KeyMaterial::default(), werr);
    }

    // ── 8. Derive key material ────────────────────────────────────
    // For ECDHE, premaster = first 32 bytes of the shared secret (zero-padded to 48).
    // RFC 5246 §8.1.2: for ECDHE the premaster IS the 32-byte x-coordinate.
    // So we use only the first 32 bytes.
    let is_aead = negotiated_suite == CIPHER_SUITE_ECDHE_RSA_AES128_GCM_SHA256
        || negotiated_suite == CIPHER_SUITE_ECDHE_ECDSA_AES128_GCM_SHA256;
    let actual_premaster: &[byte] = if is_aead {
        &premaster_48[..32]
    } else {
        &premaster_48[..]
    };

    let master = derive_master_secret(actual_premaster, &client_random, &server_random);

    let km = if is_aead {
        let aead_km = derive_aead_key_material(&master, &client_random, &server_random);
        let mut k = KeyMaterial::default();
        k.suite = negotiated_suite;
        k.aead_client = aead_km.client;
        k.aead_server = aead_km.server;
        k
    } else {
        let mut k = derive_key_material(&master, &client_random, &server_random);
        k.suite = CIPHER_SUITE_RSA_AES128_CBC_SHA;
        k
    };

    // ── 9. Send ChangeCipherSpec ──────────────────────────────────
    let ccs_slice = crate::crypto::tls::record::encode_record(
        RECORD_CHANGE_CIPHER_SPEC,
        &[1u8],
    );
    let (_, werr) = conn.Write(ccs_slice);
    if !werr.IsNil() {
        return (KeyMaterial::default(), werr);
    }

    // ── 10. Send Finished ─────────────────────────────────────────
    let client_finished_body = {
        let vd = compute_finished_verify_data(&master, &transcript, true);
        build_handshake_msg(MSG_FINISHED, &vd)
    };

    let fin_wire = if km.suite == CIPHER_SUITE_ECDHE_RSA_AES128_GCM_SHA256
        || km.suite == CIPHER_SUITE_ECDHE_ECDSA_AES128_GCM_SHA256
    {
        let (s, e) = encrypt_record_aead(
            RECORD_HANDSHAKE,
            0,
            &km.aead_client,
            &client_finished_body,
        );
        if !e.IsNil() { return (KeyMaterial::default(), e); }
        s
    } else {
        let (s, e) = encrypt_record(RECORD_HANDSHAKE, 0, &km.client, &client_finished_body);
        if !e.IsNil() { return (KeyMaterial::default(), e); }
        s
    };
    let (_, werr) = conn.Write(fin_wire);
    if !werr.IsNil() {
        return (KeyMaterial::default(), werr);
    }

    // Add client Finished to transcript
    transcript.extend_from_slice(&client_finished_body);

    // ── 11. Receive server ChangeCipherSpec ───────────────────────
    // The server may send NewSessionTicket (type 22) BEFORE its CCS (RFC 5077, Go TLS
    // sends it as a plaintext handshake message before CCS; Kubernetes apiserver follows
    // this pattern). We skip any unexpected Handshake records until we see CCS.
    {
        loop {
            let (rtype, _frag_11, err) = {
                let mut adapter = ConnReader(conn);
                crate::crypto::tls::record::read_record(&mut adapter)
            };
            if !err.IsNil() {
                return (KeyMaterial::default(), err);
            }
            if rtype == RECORD_CHANGE_CIPHER_SPEC {
                break;
            }
            if rtype == RECORD_HANDSHAKE {
                // NewSessionTicket or other handshake message — skip
                continue;
            }
            return (KeyMaterial::default(), errors::New("tls: unexpected record type before server CCS"));
        }
    }

    // ── 12. Receive server Finished ───────────────────────────────
    {
        let (rtype, frag_s, err) = {
            let mut adapter = ConnReader(conn);
            crate::crypto::tls::record::read_record(&mut adapter)
        };
        let frag = frag_s.__into_vec();
        if !err.IsNil() {
            return (KeyMaterial::default(), err);
        }
        if rtype != RECORD_HANDSHAKE {
            return (KeyMaterial::default(), errors::New("tls: expected server Finished record"));
        }
        // Decrypt server Finished (server seq = 0 after CCS)
        let plaintext = if km.suite == CIPHER_SUITE_ECDHE_RSA_AES128_GCM_SHA256
            || km.suite == CIPHER_SUITE_ECDHE_ECDSA_AES128_GCM_SHA256
        {
            let (ps, derr) = decrypt_record_aead(rtype, 0, &km.aead_server, &frag);
            if !derr.IsNil() { return (KeyMaterial::default(), derr); }
            ps.__into_vec()
        } else {
            let (ps, derr) = decrypt_record(rtype, 0, &km.server, &frag);
            if !derr.IsNil() { return (KeyMaterial::default(), derr); }
            ps.__into_vec()
        };
        if plaintext.is_empty() || plaintext[0] != MSG_FINISHED {
            return (KeyMaterial::default(), errors::New("tls: server Finished wrong msg type"));
        }
        // Verify verify_data (transcript does NOT include server's Finished)
        let expected_vd = compute_finished_verify_data(&master, &transcript, false);
        if plaintext.len() < 4 {
            return (KeyMaterial::default(), errors::New("tls: server Finished too short"));
        }
        let their_vd = &plaintext[4..]; // skip type(1) + length(3)
        if their_vd.len() != expected_vd.len() {
            return (
                KeyMaterial::default(),
                errors::New("tls: server verify_data length mismatch"),
            );
        }
        let mut diff: byte = 0;
        for i in 0..expected_vd.len() {
            diff |= their_vd[i] ^ expected_vd[i];
        }
        if diff != 0 {
            return (KeyMaterial::default(), errors::New("tls: server Finished verify_data mismatch"));
        }
    }

    (km, errors::nil)
}

// ─── helpers ──────────────────────────────────────────────────────────

/// Public test helper: build a ClientHello byte buffer (with 4-byte handshake header).
/// Returns the raw handshake message bytes (not wrapped in a TLS record).
///
/// `server_name` is included in the SNI extension when non-empty, mirroring
/// Go's `crypto/tls` behaviour where the server name is always sent in a real
/// handshake.
pub fn build_client_hello_bytes(client_random: &[u8; 32], server_name: &str) -> Vec<byte> {
    let (_, dummy_pub) = ecdh::x25519_generate();
    build_client_hello(client_random, server_name, &dummy_pub)
}

/// Public test helper: parse a ServerHello handshake fragment (the raw bytes after the
/// 5-byte TLS record header). Returns `(server_random, cipher_suite, error)`.
pub fn parse_server_hello_fragment(fragment: &[byte]) -> ([byte; 32], u16, error) {
    let zero_random = [0u8; 32];
    if fragment.len() < 4 || fragment[0] != MSG_SERVER_HELLO {
        return (zero_random, 0, errors::New("tls: not a ServerHello fragment"));
    }
    let body = &fragment[4..];
    if body.len() < 35 {
        return (zero_random, 0, errors::New("tls: ServerHello body too short"));
    }
    let maj = body[0];
    let min = body[1];
    if maj != TLS_VERSION_MAJOR || min != TLS_VERSION_MINOR {
        return (zero_random, 0, errors::New("tls: server not TLS 1.2"));
    }
    let mut sr = [0u8; 32];
    sr.copy_from_slice(&body[2..34]);
    let sid_len = body[34] as usize;
    let sid_end = 35 + sid_len;
    if body.len() < sid_end + 2 {
        return (zero_random, 0, errors::New("tls: ServerHello truncated at cipher suite"));
    }
    let cs = u16::from_be_bytes([body[sid_end], body[sid_end + 1]]);
    (sr, cs, errors::nil)
}

/// Build a second ClientHello for HelloRetryRequest response with a specific key group.
/// group: 29 (X25519) or 23 (P-256).
/// key_bytes: the raw key share bytes (32 bytes for X25519, 65 bytes for P-256).
/// cookie: if Some, includes the cookie extension.
/// session_id: MUST be the same session_id as CH1 (RFC 8446 §4.1.2).
fn build_client_hello_hrr_group(
    client_random: &[byte; 32],
    server_name: &str,
    group: u16,
    key_bytes: &[byte],
    cookie: Option<&[byte]>,
    session_id: &[byte; 32],
) -> Vec<byte> {
    let mut body: Vec<byte> = Vec::new();
    body.push(TLS_VERSION_MAJOR);
    body.push(TLS_VERSION_MINOR);
    body.extend_from_slice(client_random);
    // RFC 8446 §4.1.2: CH2 MUST use the same session_id as CH1
    body.push(32u8);
    body.extend_from_slice(session_id);
    // cipher_suites: TLS 1.3 + TLS 1.2
    body.push(0);
    body.push(12);
    body.extend_from_slice(&CIPHER_TLS13_AES128_GCM_SHA256.to_be_bytes());
    body.extend_from_slice(&CIPHER_TLS13_AES256_GCM_SHA384.to_be_bytes());
    body.extend_from_slice(&CIPHER_TLS13_CHACHA20_POLY1305_SHA256.to_be_bytes());
    body.extend_from_slice(&CIPHER_SUITE_ECDHE_ECDSA_AES128_GCM_SHA256.to_be_bytes());
    body.extend_from_slice(&CIPHER_SUITE_ECDHE_RSA_AES128_GCM_SHA256.to_be_bytes());
    body.extend_from_slice(&CIPHER_SUITE_RSA_AES128_CBC_SHA.to_be_bytes());
    body.push(1);
    body.push(0); // compression methods
    let mut exts: Vec<byte> = Vec::new();
    // server_name extension
    if !server_name.is_empty() {
        let host = server_name.as_bytes();
        let host_len = host.len() as u16; // goishlint:ignore GOISH005
        let server_name_list_len = (1u16 + 2u16 + host_len) as u16;
        let ext_data_len = (2u16 + server_name_list_len) as u16;
        exts.extend_from_slice(&[0x00u8, 0x00u8]);
        exts.extend_from_slice(&ext_data_len.to_be_bytes());
        exts.extend_from_slice(&server_name_list_len.to_be_bytes());
        exts.push(0x00u8);
        exts.extend_from_slice(&host_len.to_be_bytes());
        exts.extend_from_slice(host);
    }
    // supported_versions extension
    {
        let versions: &[u8] = &[0x03u8, 0x04u8, 0x03u8, 0x03u8];
        let list_len = versions.len() as u8; // goishlint:ignore GOISH005
        let ext_data_len = (1u16 + versions.len() as u16) as u16; // goishlint:ignore GOISH005
        exts.extend_from_slice(&EXT_SUPPORTED_VERSIONS.to_be_bytes());
        exts.extend_from_slice(&ext_data_len.to_be_bytes());
        exts.push(list_len);
        exts.extend_from_slice(versions);
    }
    // supported_groups extension: X25519=29, P-256=23 only (no P-384)
    {
        let groups: &[u8] = &[0x00u8, 0x1du8, 0x00u8, 0x17u8]; // X25519=29, P-256=23
        let groups_inner_len = groups.len() as u16; // goishlint:ignore GOISH005
        let groups_ext_len = 2 + groups_inner_len;
        exts.extend_from_slice(&EXT_SUPPORTED_GROUPS.to_be_bytes());
        exts.extend_from_slice(&groups_ext_len.to_be_bytes());
        exts.extend_from_slice(&groups_inner_len.to_be_bytes());
        exts.extend_from_slice(groups);
    }
    // key_share extension with the specified group
    {
        let ke_len = key_bytes.len() as u16; // goishlint:ignore GOISH005
        let entry_len: u16 = 2 + 2 + ke_len;
        let list_len: u16 = entry_len;
        let ext_data_len: u16 = 2 + list_len;
        exts.extend_from_slice(&EXT_KEY_SHARE.to_be_bytes());
        exts.extend_from_slice(&ext_data_len.to_be_bytes());
        exts.extend_from_slice(&list_len.to_be_bytes());
        exts.extend_from_slice(&group.to_be_bytes());
        exts.extend_from_slice(&ke_len.to_be_bytes());
        exts.extend_from_slice(key_bytes);
    }
    // ec_point_formats extension
    {
        let formats: &[u8] = &[0x00u8];
        let fmt_inner_len = formats.len() as u16; // goishlint:ignore GOISH005
        let fmt_ext_len = 1 + fmt_inner_len;
        exts.extend_from_slice(&EXT_EC_POINT_FORMATS.to_be_bytes());
        exts.extend_from_slice(&fmt_ext_len.to_be_bytes());
        exts.push(fmt_inner_len as byte); // goishlint:ignore GOISH005
        exts.extend_from_slice(formats);
    }
    // signature_algorithms extension
    {
        let algs: &[u8] = &[
            0x04u8, 0x03u8, // ecdsa_secp256r1_sha256
            0x05u8, 0x03u8, // ecdsa_secp384r1_sha384
            0x08u8, 0x04u8, // rsa_pss_rsae_sha256
            0x08u8, 0x05u8, // rsa_pss_rsae_sha384
            0x04u8, 0x01u8, // rsa_pkcs1_sha256
            0x05u8, 0x01u8, // rsa_pkcs1_sha384
        ];
        let algs_inner_len = algs.len() as u16; // goishlint:ignore GOISH005
        let algs_ext_len = 2 + algs_inner_len;
        exts.extend_from_slice(&EXT_SIGNATURE_ALGORITHMS.to_be_bytes());
        exts.extend_from_slice(&algs_ext_len.to_be_bytes());
        exts.extend_from_slice(&algs_inner_len.to_be_bytes());
        exts.extend_from_slice(algs);
    }
    // signature_algorithms_cert extension
    {
        let algs: &[u8] = &[
            0x04u8, 0x03u8, // ecdsa_secp256r1_sha256
            0x05u8, 0x03u8, // ecdsa_secp384r1_sha384
            0x08u8, 0x04u8, // rsa_pss_rsae_sha256
            0x08u8, 0x05u8, // rsa_pss_rsae_sha384
            0x04u8, 0x01u8, // rsa_pkcs1_sha256
            0x05u8, 0x01u8, // rsa_pkcs1_sha384
        ];
        let algs_inner_len = algs.len() as u16; // goishlint:ignore GOISH005
        let algs_ext_len = 2 + algs_inner_len;
        exts.extend_from_slice(&EXT_SIG_ALGS_CERT.to_be_bytes());
        exts.extend_from_slice(&algs_ext_len.to_be_bytes());
        exts.extend_from_slice(&algs_inner_len.to_be_bytes());
        exts.extend_from_slice(algs);
    }
    // ALPN extension
    {
        let proto = b"http/1.1";
        let proto_entry_len = 1 + proto.len();
        let proto_list_len = proto_entry_len as u16; // goishlint:ignore GOISH005
        let ext_data_len = (2 + proto_list_len) as u16;
        exts.extend_from_slice(&0x0010u16.to_be_bytes());
        exts.extend_from_slice(&ext_data_len.to_be_bytes());
        exts.extend_from_slice(&proto_list_len.to_be_bytes());
        exts.push(proto.len() as byte); // goishlint:ignore GOISH005
        exts.extend_from_slice(proto);
    }
    // psk_key_exchange_modes extension (type=0x002D): RFC 8446 §4.2.9
    {
        let modes: &[u8] = &[0x01u8]; // psk_dhe_ke
        let modes_len = modes.len() as u8; // goishlint:ignore GOISH005
        let ext_data_len: u16 = 1 + modes.len() as u16; // goishlint:ignore GOISH005
        exts.extend_from_slice(&0x002Du16.to_be_bytes());
        exts.extend_from_slice(&ext_data_len.to_be_bytes());
        exts.push(modes_len);
        exts.extend_from_slice(modes);
    }
    // Cookie extension if provided
    if let Some(c) = cookie {
        let cookie_len = c.len() as u16; // goishlint:ignore GOISH005
        let ext_data_len = 2 + cookie_len;
        exts.extend_from_slice(&0x002Cu16.to_be_bytes());
        exts.extend_from_slice(&ext_data_len.to_be_bytes());
        exts.extend_from_slice(&cookie_len.to_be_bytes());
        exts.extend_from_slice(c);
    }
    let exts_total_len = exts.len() as u16; // goishlint:ignore GOISH005
    body.extend_from_slice(&exts_total_len.to_be_bytes());
    body.extend_from_slice(&exts);
    build_handshake_msg(MSG_CLIENT_HELLO, &body)
}

/// Build a second ClientHello for HelloRetryRequest response.
fn build_client_hello(client_random: &[byte; 32], server_name: &str, x25519_pub: &ecdh::X25519PublicKey) -> Vec<byte> {
    build_client_hello_inner(client_random, server_name, x25519_pub, None)
}

fn build_client_hello_inner(client_random: &[byte; 32], server_name: &str, x25519_pub: &ecdh::X25519PublicKey, cookie: Option<&[byte]>) -> Vec<byte> {
    let mut body: Vec<byte> = Vec::new();
    body.push(TLS_VERSION_MAJOR);
    body.push(TLS_VERSION_MINOR);
    body.extend_from_slice(client_random);
    // TLS 1.3 requires a non-empty session_id for middlebox compat (RFC 8446 D.4)
    // Generate 32-byte random session ID
    let mut session_id = [0u8; 32];
    {
        let mut buf = slice::<byte>::__from_vec(alloc::vec![0u8; 32]);
        let _ = rand::Read(&mut buf);
        let v = buf.__into_vec();
        session_id.copy_from_slice(&v[..32]);
    }
    body.push(32u8); // session_id length
    body.extend_from_slice(&session_id);
    // cipher_suites: 6 suites (TLS 1.3 first, then TLS 1.2)
    // 0x1301 TLS_AES_128_GCM_SHA256
    // 0x1302 TLS_AES_256_GCM_SHA384
    // 0x1303 TLS_CHACHA20_POLY1305_SHA256
    // 0xC02B ECDHE_ECDSA_AES128_GCM_SHA256
    // 0xC02F ECDHE_RSA_AES128_GCM_SHA256
    // 0x002F RSA_AES128_CBC_SHA
    body.push(0);
    body.push(12); // 6 suites * 2 bytes
    body.extend_from_slice(&CIPHER_TLS13_AES128_GCM_SHA256.to_be_bytes());
    body.extend_from_slice(&CIPHER_TLS13_AES256_GCM_SHA384.to_be_bytes());
    body.extend_from_slice(&CIPHER_TLS13_CHACHA20_POLY1305_SHA256.to_be_bytes());
    body.extend_from_slice(&CIPHER_SUITE_ECDHE_ECDSA_AES128_GCM_SHA256.to_be_bytes());
    body.extend_from_slice(&CIPHER_SUITE_ECDHE_RSA_AES128_GCM_SHA256.to_be_bytes());
    body.extend_from_slice(&CIPHER_SUITE_RSA_AES128_CBC_SHA.to_be_bytes());
    // compression_methods: length(1) + null(1)
    body.push(1);
    body.push(0);
    // Extensions
    let mut exts: Vec<byte> = Vec::new();
    // server_name extension (type=0x0000), RFC 6066 §3
    if !server_name.is_empty() {
        let host = server_name.as_bytes();
        let host_len = host.len() as u16; // goishlint:ignore GOISH005
        let server_name_list_len = (1u16 + 2u16 + host_len) as u16;
        let ext_data_len = (2u16 + server_name_list_len) as u16;
        exts.extend_from_slice(&[0x00u8, 0x00u8]);
        exts.extend_from_slice(&ext_data_len.to_be_bytes());
        exts.extend_from_slice(&server_name_list_len.to_be_bytes());
        exts.push(0x00u8);
        exts.extend_from_slice(&host_len.to_be_bytes());
        exts.extend_from_slice(host);
    }
    // supported_versions extension (0x002B): advertise TLS 1.3 and TLS 1.2
    // RFC 8446 §4.2.1: list of versions client supports
    {
        // versions list: 2 versions * 2 bytes = 4 bytes
        let versions: &[u8] = &[0x03u8, 0x04u8, 0x03u8, 0x03u8]; // TLS 1.3, TLS 1.2
        let list_len = versions.len() as u8; // goishlint:ignore GOISH005
        let ext_data_len = (1u16 + versions.len() as u16) as u16; // goishlint:ignore GOISH005
        exts.extend_from_slice(&EXT_SUPPORTED_VERSIONS.to_be_bytes());
        exts.extend_from_slice(&ext_data_len.to_be_bytes());
        exts.push(list_len);
        exts.extend_from_slice(versions);
    }
    // supported_groups extension (type=10): x25519=29, secp256r1=23
    // NOTE: We deliberately omit secp384r1 (24) because we can't compute P-384 ECDH.
    // If a server requests P-384 in HRR and we send X25519 instead, it would be
    // non-compliant. So we only advertise groups we can actually use.
    {
        let groups: &[u8] = &[0x00u8, 0x1du8, 0x00u8, 0x17u8]; // X25519=29, P-256=23
        let groups_inner_len = groups.len() as u16; // goishlint:ignore GOISH005
        let groups_ext_len = 2 + groups_inner_len;
        exts.extend_from_slice(&EXT_SUPPORTED_GROUPS.to_be_bytes());
        exts.extend_from_slice(&groups_ext_len.to_be_bytes());
        exts.extend_from_slice(&groups_inner_len.to_be_bytes());
        exts.extend_from_slice(groups);
    }
    // key_share extension (0x0033): advertise X25519 key share
    // RFC 8446 §4.2.8
    {
        let pub_bytes = &x25519_pub.0;
        // key_share_entry: group(2) + key_exchange_len(2) + key_exchange(32)
        let entry_len: u16 = 2 + 2 + 32;
        let list_len: u16 = entry_len;
        let ext_data_len: u16 = 2 + list_len;
        exts.extend_from_slice(&EXT_KEY_SHARE.to_be_bytes());
        exts.extend_from_slice(&ext_data_len.to_be_bytes());
        exts.extend_from_slice(&list_len.to_be_bytes());
        exts.extend_from_slice(&29u16.to_be_bytes()); // X25519 = 29
        exts.extend_from_slice(&32u16.to_be_bytes()); // key length = 32
        exts.extend_from_slice(pub_bytes);
    }
    // ec_point_formats extension (type=11): uncompressed only
    {
        let formats: &[u8] = &[0x00u8];
        let fmt_inner_len = formats.len() as u16; // goishlint:ignore GOISH005
        let fmt_ext_len = 1 + fmt_inner_len;
        exts.extend_from_slice(&EXT_EC_POINT_FORMATS.to_be_bytes());
        exts.extend_from_slice(&fmt_ext_len.to_be_bytes());
        exts.push(fmt_inner_len as byte); // goishlint:ignore GOISH005
        exts.extend_from_slice(formats);
    }
    // signature_algorithms extension (type=13):
    // ecdsa_secp256r1_sha256 (0x0403), ecdsa_secp384r1_sha384 (0x0503),
    // rsa_pss_rsae_sha256 (0x0804), rsa_pss_rsae_sha384 (0x0805),
    // rsa_pkcs1_sha256 (0x0401), rsa_pkcs1_sha384 (0x0501)
    {
        let algs: &[u8] = &[
            0x04u8, 0x03u8, // ecdsa_secp256r1_sha256
            0x05u8, 0x03u8, // ecdsa_secp384r1_sha384
            0x08u8, 0x04u8, // rsa_pss_rsae_sha256
            0x08u8, 0x05u8, // rsa_pss_rsae_sha384
            0x04u8, 0x01u8, // rsa_pkcs1_sha256
            0x05u8, 0x01u8, // rsa_pkcs1_sha384
        ];
        let algs_inner_len = algs.len() as u16; // goishlint:ignore GOISH005
        let algs_ext_len = 2 + algs_inner_len;
        exts.extend_from_slice(&EXT_SIGNATURE_ALGORITHMS.to_be_bytes());
        exts.extend_from_slice(&algs_ext_len.to_be_bytes());
        exts.extend_from_slice(&algs_inner_len.to_be_bytes());
        exts.extend_from_slice(algs);
    }
    // signature_algorithms_cert extension (0x0032):
    // Same list as signature_algorithms
    {
        let algs: &[u8] = &[
            0x04u8, 0x03u8, // ecdsa_secp256r1_sha256
            0x05u8, 0x03u8, // ecdsa_secp384r1_sha384
            0x08u8, 0x04u8, // rsa_pss_rsae_sha256
            0x08u8, 0x05u8, // rsa_pss_rsae_sha384
            0x04u8, 0x01u8, // rsa_pkcs1_sha256
            0x05u8, 0x01u8, // rsa_pkcs1_sha384
        ];
        let algs_inner_len = algs.len() as u16; // goishlint:ignore GOISH005
        let algs_ext_len = 2 + algs_inner_len;
        exts.extend_from_slice(&EXT_SIG_ALGS_CERT.to_be_bytes());
        exts.extend_from_slice(&algs_ext_len.to_be_bytes());
        exts.extend_from_slice(&algs_inner_len.to_be_bytes());
        exts.extend_from_slice(algs);
    }
    // ALPN extension (0x0010): "http/1.1"
    // RFC 7301: protocol_name_list = len(2) + [ len(1) + name ]
    {
        let proto = b"http/1.1";
        let proto_entry_len = 1 + proto.len(); // len(1) + name
        let proto_list_len = proto_entry_len as u16; // goishlint:ignore GOISH005
        let ext_data_len = (2 + proto_list_len) as u16;
        exts.extend_from_slice(&0x0010u16.to_be_bytes()); // ALPN type
        exts.extend_from_slice(&ext_data_len.to_be_bytes());
        exts.extend_from_slice(&proto_list_len.to_be_bytes());
        exts.push(proto.len() as byte); // goishlint:ignore GOISH005
        exts.extend_from_slice(proto);
    }
    // psk_key_exchange_modes extension (type=0x002D): RFC 8446 §4.2.9
    // Always include for TLS 1.3 compliance (Go does this even without PSK).
    // Value: psk_dhe_ke (1) — PSK with (EC)DHE key establishment.
    {
        // ext_data = modes_len(1) + modes([0x01])
        let modes: &[u8] = &[0x01u8]; // psk_dhe_ke
        let modes_len = modes.len() as u8; // goishlint:ignore GOISH005
        let ext_data_len: u16 = 1 + modes.len() as u16; // goishlint:ignore GOISH005
        exts.extend_from_slice(&0x002Du16.to_be_bytes()); // psk_key_exchange_modes type
        exts.extend_from_slice(&ext_data_len.to_be_bytes());
        exts.push(modes_len);
        exts.extend_from_slice(modes);
    }
    // Cookie extension (type=0x002C): if provided by HRR, echo it back (RFC 8446 §4.2.2)
    if let Some(c) = cookie {
        let cookie_len = c.len() as u16; // goishlint:ignore GOISH005
        let ext_data_len = 2 + cookie_len; // u16-length-prefixed cookie value
        exts.extend_from_slice(&0x002Cu16.to_be_bytes()); // cookie type
        exts.extend_from_slice(&ext_data_len.to_be_bytes());
        exts.extend_from_slice(&cookie_len.to_be_bytes());
        exts.extend_from_slice(c);
    }
    let exts_total_len = exts.len() as u16; // goishlint:ignore GOISH005
    body.extend_from_slice(&exts_total_len.to_be_bytes());
    body.extend_from_slice(&exts);
    build_handshake_msg(MSG_CLIENT_HELLO, &body)
}

fn build_handshake_msg(msg_type: byte, body: &[byte]) -> Vec<byte> {
    // type(1) + length(3 bytes big-endian) + body
    let len = body.len();
    let mut out: Vec<byte> = Vec::with_capacity(4 + len);
    out.push(msg_type);
    out.push(((len >> 16) & 0xFF) as byte); // goishlint:ignore GOISH005
    out.push(((len >> 8) & 0xFF) as byte); // goishlint:ignore GOISH005
    out.push((len & 0xFF) as byte); // goishlint:ignore GOISH005
    out.extend_from_slice(body);
    out
}

// ─── PSK extension (pre_shared_key, type=0x0029) ──────────────────────
//
// RFC 8446 §4.2.11. The extension MUST be the LAST extension in ClientHello.
//
// Wire format:
//   uint16 identities_len
//     uint16 identity_len
//     uint8  identity[identity_len]
//     uint32 obfuscated_ticket_age
//   uint16 binders_len
//     uint8 binder_len
//     uint8 binder[binder_len]
//
// The binder is initially zero-filled at hash_size bytes; the caller
// replaces it after computing the PSK binder HMAC.

/// Build the raw ext_data bytes (identities + binders placeholder) for one PSK.
/// Returns (ext_data, binders_list_len) where binders_list_len is the total byte
/// count of the binders list INCLUDING the u16 outer length prefix.
fn build_psk_extension_data(
    ticket: &[byte],
    obfuscated_ticket_age: u32,
    hash_size: usize,
) -> (Vec<byte>, usize) {
    let mut data: Vec<byte> = Vec::new();

    // identities list
    let identity_len = ticket.len() as u16; // goishlint:ignore GOISH005
    // one entry: u16 identity_len + identity + u32 obf_age
    let one_entry_len = 2 + identity_len + 4;
    let identities_list_len: u16 = one_entry_len;
    data.extend_from_slice(&identities_list_len.to_be_bytes());
    data.extend_from_slice(&identity_len.to_be_bytes());
    data.extend_from_slice(ticket);
    data.extend_from_slice(&obfuscated_ticket_age.to_be_bytes());

    // binders list: u16 outer len + u8 per-binder len + binder bytes
    let per_binder_total = 1 + hash_size; // u8 length byte + hash_size zeros
    let binders_list_total = 2 + per_binder_total; // u16 outer + per_binder_total
    let binders_list_len = per_binder_total as u16; // goishlint:ignore GOISH005
    data.extend_from_slice(&binders_list_len.to_be_bytes());
    data.push(hash_size as byte); // goishlint:ignore GOISH005
    // zero-filled binder placeholder
    for _ in 0..hash_size {
        data.push(0u8);
    }

    (data, binders_list_total)
}

/// Build a ClientHello with a PSK extension as the LAST extension.
///
/// Returns (ch_bytes, binders_len) where `binders_len` is the size of the
/// binders list (2-byte outer length + each binder entry including their
/// 1-byte length prefix).  The caller must:
///
///   1. Hash `ch_bytes[..ch_bytes.len() - binders_len]` with the suite hash.
///   2. Compute `binder = HMAC(finished_key, that_hash)`.
///   3. Patch `ch_bytes[ch_bytes.len() - binders_len + 2..]` (skip the u16 outer
///      length prefix, then skip the u8 per-binder length) with the binder.
///
/// Actually, the patch offset is `ch_bytes.len() - hash_size` because the
/// last `hash_size` bytes are the binder body itself.
fn build_client_hello_with_psk(
    client_random: &[byte; 32],
    server_name: &str,
    x25519_pub: &crate::crypto::ecdh::X25519PublicKey,
    ticket: &[byte],
    obfuscated_ticket_age: u32,
    hash_size: usize,
) -> (Vec<byte>, usize) {
    // Build the base extensions (everything except pre_shared_key)
    let mut body: Vec<byte> = Vec::new();
    body.push(TLS_VERSION_MAJOR);
    body.push(TLS_VERSION_MINOR);
    body.extend_from_slice(client_random);
    // session_id: 32-byte random for middlebox compat
    let mut session_id = [0u8; 32];
    {
        let mut buf = slice::<byte>::__from_vec(alloc::vec![0u8; 32]);
        let _ = rand::Read(&mut buf);
        let v = buf.__into_vec();
        session_id.copy_from_slice(&v[..32]);
    }
    body.push(32u8);
    body.extend_from_slice(&session_id);
    // cipher_suites: same as normal ClientHello
    body.push(0);
    body.push(12);
    body.extend_from_slice(&CIPHER_TLS13_AES128_GCM_SHA256.to_be_bytes());
    body.extend_from_slice(&CIPHER_TLS13_AES256_GCM_SHA384.to_be_bytes());
    body.extend_from_slice(&CIPHER_TLS13_CHACHA20_POLY1305_SHA256.to_be_bytes());
    body.extend_from_slice(&CIPHER_SUITE_ECDHE_ECDSA_AES128_GCM_SHA256.to_be_bytes());
    body.extend_from_slice(&CIPHER_SUITE_ECDHE_RSA_AES128_GCM_SHA256.to_be_bytes());
    body.extend_from_slice(&CIPHER_SUITE_RSA_AES128_CBC_SHA.to_be_bytes());
    body.push(1);
    body.push(0); // compression_methods

    let mut exts: Vec<byte> = Vec::new();

    // server_name
    if !server_name.is_empty() {
        let host = server_name.as_bytes();
        let host_len = host.len() as u16; // goishlint:ignore GOISH005
        let snl = (1u16 + 2u16 + host_len) as u16;
        let edl = (2u16 + snl) as u16;
        exts.extend_from_slice(&[0x00u8, 0x00u8]);
        exts.extend_from_slice(&edl.to_be_bytes());
        exts.extend_from_slice(&snl.to_be_bytes());
        exts.push(0x00u8);
        exts.extend_from_slice(&host_len.to_be_bytes());
        exts.extend_from_slice(host);
    }
    // supported_versions
    {
        let versions: &[u8] = &[0x03u8, 0x04u8, 0x03u8, 0x03u8];
        let list_len = versions.len() as u8; // goishlint:ignore GOISH005
        let ext_data_len = (1u16 + versions.len() as u16) as u16; // goishlint:ignore GOISH005
        exts.extend_from_slice(&EXT_SUPPORTED_VERSIONS.to_be_bytes());
        exts.extend_from_slice(&ext_data_len.to_be_bytes());
        exts.push(list_len);
        exts.extend_from_slice(versions);
    }
    // supported_groups
    {
        let groups: &[u8] = &[0x00u8, 0x1du8, 0x00u8, 0x17u8];
        let groups_inner_len = groups.len() as u16; // goishlint:ignore GOISH005
        let groups_ext_len = 2 + groups_inner_len;
        exts.extend_from_slice(&EXT_SUPPORTED_GROUPS.to_be_bytes());
        exts.extend_from_slice(&groups_ext_len.to_be_bytes());
        exts.extend_from_slice(&groups_inner_len.to_be_bytes());
        exts.extend_from_slice(groups);
    }
    // key_share
    {
        let pub_bytes = &x25519_pub.0;
        let entry_len: u16 = 2 + 2 + 32;
        let list_len: u16 = entry_len;
        let ext_data_len: u16 = 2 + list_len;
        exts.extend_from_slice(&EXT_KEY_SHARE.to_be_bytes());
        exts.extend_from_slice(&ext_data_len.to_be_bytes());
        exts.extend_from_slice(&list_len.to_be_bytes());
        exts.extend_from_slice(&29u16.to_be_bytes());
        exts.extend_from_slice(&32u16.to_be_bytes());
        exts.extend_from_slice(pub_bytes);
    }
    // ec_point_formats
    {
        let formats: &[u8] = &[0x00u8];
        let fmt_inner_len = formats.len() as u16; // goishlint:ignore GOISH005
        let fmt_ext_len = 1 + fmt_inner_len;
        exts.extend_from_slice(&EXT_EC_POINT_FORMATS.to_be_bytes());
        exts.extend_from_slice(&fmt_ext_len.to_be_bytes());
        exts.push(fmt_inner_len as byte); // goishlint:ignore GOISH005
        exts.extend_from_slice(formats);
    }
    // signature_algorithms
    {
        let algs: &[u8] = &[
            0x04u8, 0x03u8,
            0x05u8, 0x03u8,
            0x08u8, 0x04u8,
            0x08u8, 0x05u8,
            0x04u8, 0x01u8,
            0x05u8, 0x01u8,
        ];
        let algs_inner_len = algs.len() as u16; // goishlint:ignore GOISH005
        let algs_ext_len = 2 + algs_inner_len;
        exts.extend_from_slice(&EXT_SIGNATURE_ALGORITHMS.to_be_bytes());
        exts.extend_from_slice(&algs_ext_len.to_be_bytes());
        exts.extend_from_slice(&algs_inner_len.to_be_bytes());
        exts.extend_from_slice(algs);
    }
    // signature_algorithms_cert
    {
        let algs: &[u8] = &[
            0x04u8, 0x03u8,
            0x05u8, 0x03u8,
            0x08u8, 0x04u8,
            0x08u8, 0x05u8,
            0x04u8, 0x01u8,
            0x05u8, 0x01u8,
        ];
        let algs_inner_len = algs.len() as u16; // goishlint:ignore GOISH005
        let algs_ext_len = 2 + algs_inner_len;
        exts.extend_from_slice(&EXT_SIG_ALGS_CERT.to_be_bytes());
        exts.extend_from_slice(&algs_ext_len.to_be_bytes());
        exts.extend_from_slice(&algs_inner_len.to_be_bytes());
        exts.extend_from_slice(algs);
    }
    // ALPN
    {
        let proto = b"http/1.1";
        let proto_entry_len = 1 + proto.len();
        let proto_list_len = proto_entry_len as u16; // goishlint:ignore GOISH005
        let ext_data_len = (2 + proto_list_len) as u16; // goishlint:ignore GOISH005
        exts.extend_from_slice(&0x0010u16.to_be_bytes());
        exts.extend_from_slice(&ext_data_len.to_be_bytes());
        exts.extend_from_slice(&proto_list_len.to_be_bytes());
        exts.push(proto.len() as byte); // goishlint:ignore GOISH005
        exts.extend_from_slice(proto);
    }
    // psk_key_exchange_modes — MUST come before pre_shared_key
    {
        let modes: &[u8] = &[0x01u8];
        let modes_len = modes.len() as u8; // goishlint:ignore GOISH005
        let ext_data_len: u16 = 1 + modes.len() as u16; // goishlint:ignore GOISH005
        exts.extend_from_slice(&0x002Du16.to_be_bytes());
        exts.extend_from_slice(&ext_data_len.to_be_bytes());
        exts.push(modes_len);
        exts.extend_from_slice(modes);
    }

    // pre_shared_key — MUST be LAST (RFC 8446 §4.2.11)
    let (psk_ext_data, binders_list_len) = build_psk_extension_data(ticket, obfuscated_ticket_age, hash_size);
    {
        let psk_ext_data_len = psk_ext_data.len() as u16; // goishlint:ignore GOISH005
        exts.extend_from_slice(&0x0029u16.to_be_bytes()); // pre_shared_key type
        exts.extend_from_slice(&psk_ext_data_len.to_be_bytes());
        exts.extend_from_slice(&psk_ext_data);
    }

    let exts_total_len = exts.len() as u16; // goishlint:ignore GOISH005
    body.extend_from_slice(&exts_total_len.to_be_bytes());
    body.extend_from_slice(&exts);
    let ch = build_handshake_msg(MSG_CLIENT_HELLO, &body);
    (ch, binders_list_len)
}

/// Compute and patch the PSK binder into the ClientHello bytes.
///
/// `ch_bytes` — the complete ClientHello (with zero binder placeholder).
/// `psk` — the resumption PSK derived from NewSessionTicket.
/// `hash_fn` — hash function for the suite.
/// `binders_len` — byte count of the binders list (2-byte outer length + per-binder entries).
///
/// After this call, `ch_bytes` contains the correct binder in place of zeros.
fn patch_psk_binder(
    ch_bytes: &mut Vec<byte>,
    psk: &[byte],
    hash_fn: fn() -> alloc::boxed::Box<dyn crate::hash::Hash + Send + Sync>,
    binders_len: usize,
) {
    use crate::crypto::tls::key_schedule::{EarlySecret, finished_hash};
    use crate::io::Writer as WriterTrait;

    let hash_size = hash_fn().Size() as usize;

    // early_secret = HKDF-Extract(zeros, psk)
    let early = EarlySecret::new(hash_fn, Some(psk));
    // binder_key = DeriveSecret(early_secret, "res binder", H(""))
    let binder_key = early.ResumptionBinderKey();

    // Truncate: hash everything BEFORE the binders list.
    // binders_list_len = 2 (outer u16) + 1 (u8 per-binder length) + hash_size
    // transcript_prefix = ch_bytes[..ch_bytes.len() - binders_len]
    let truncate_at = ch_bytes.len() - binders_len;
    let ch_prefix = &ch_bytes[..truncate_at];

    // Transcript hash of the prefix
    let prefix_hash = {
        let mut h = hash_fn();
        let s = slice::<byte>::__from_vec(ch_prefix.to_vec());
        let _ = WriterTrait::Write(&mut h, s);
        let empty = slice::<byte>::__from_vec(alloc::vec![]);
        h.Sum(empty).__into_vec()
    };

    // binder = finished_hash(binder_key, prefix_hash)
    // = HMAC(HKDF-Expand-Label(binder_key, "finished", "", hash_size), prefix_hash)
    let binder = finished_hash(hash_fn, &binder_key, &prefix_hash);

    // Patch: the binder body occupies the last `hash_size` bytes of ch_bytes.
    let binder_start = ch_bytes.len() - hash_size;
    let binder_len = binder.len().min(hash_size);
    ch_bytes[binder_start..binder_start + binder_len].copy_from_slice(&binder[..binder_len]);
}

fn u24_to_usize(b: [u8; 3]) -> usize {
    ((b[0] as usize) << 16) | ((b[1] as usize) << 8) | (b[2] as usize)
}

/// Parse a ServerKeyExchange body for the ECDHE_RSA key agreement.
///
/// Wire format (RFC 4492 §5.4):
///   curve_type    (1) — must be 3 (named_curve)
///   named_curve   (2) — 29 = x25519
///   pubkey_len    (1) — 32 for x25519
///   pubkey        (pubkey_len bytes)
///   sig_len       (2)
///   signature     (sig_len bytes) — RSA-PKCS1v1.5 over SHA-256 of the signed params
///
/// signed_params = client_random(32) || server_random(32) || curve_type(1) || named_curve(2) || pubkey_len(1) || pubkey
///
/// Returns (premaster_secret[32], client_pub[32], error).
pub fn parse_server_key_exchange(
    body: &[byte],
    client_random: &[byte; 32],
    server_random: &[byte; 32],
    server_rsa_pubkey: &rsa::PublicKey,
) -> ([byte; 32], [byte; 32], error) {
    let zero = [0u8; 32];

    if body.len() < 4 {
        return (zero, zero, errors::New("tls: ServerKeyExchange too short"));
    }
    // curve_type must be 3 = named_curve
    let curve_type = body[0];
    if curve_type != CURVE_TYPE_NAMED {
        return (zero, zero, errors::New("tls: ServerKeyExchange: expected named_curve"));
    }
    // named_curve
    let named_curve = u16::from_be_bytes([body[1], body[2]]);
    if named_curve != NAMED_CURVE_X25519 {
        // Could add P-256 support later; for now only x25519.
        return (zero, zero, errors::New("tls: ServerKeyExchange: only x25519 (29) supported"));
    }
    let pubkey_len = body[3] as usize;
    if pubkey_len != 32 {
        return (zero, zero, errors::New("tls: ServerKeyExchange: x25519 pubkey must be 32 bytes"));
    }
    // TLS 1.2: after the public key, the server sends a 2-byte
    // SignatureAndHashAlgorithm { hash_algorithm: u8, signature_algorithm: u8 }
    // BEFORE the 2-byte signature length. RFC 5246 §7.4.1.4.1 + §7.4.3.
    if body.len() < 4 + pubkey_len + 4 {
        return (zero, zero, errors::New("tls: ServerKeyExchange: truncated after pubkey"));
    }
    let server_pub_raw = &body[4..4 + pubkey_len];
    let hash_alg = body[4 + pubkey_len];
    let sig_alg = body[4 + pubkey_len + 1];
    // We only support SHA256+RSA (4, 1). SHA384+RSA (5, 1) and SHA512+RSA (6, 1)
    // would also be common; extend here if needed.
    if hash_alg != 4 || sig_alg != 1 {
        return (zero, zero, errors::New("tls: ServerKeyExchange: unsupported SignatureAndHashAlgorithm (only SHA256+RSA supported)"));
    }
    let sig_len = u16::from_be_bytes([body[4 + pubkey_len + 2], body[4 + pubkey_len + 3]]) as usize;
    if body.len() < 4 + pubkey_len + 4 + sig_len {
        return (zero, zero, errors::New("tls: ServerKeyExchange: truncated signature"));
    }
    let signature = &body[4 + pubkey_len + 4..4 + pubkey_len + 4 + sig_len];

    // Verify the signature:
    // sig_input = client_random || server_random || curve_type(1) || named_curve(2) || pubkey_len(1) || pubkey
    let mut sig_input: Vec<byte> = Vec::with_capacity(32 + 32 + 4 + pubkey_len);
    sig_input.extend_from_slice(client_random);
    sig_input.extend_from_slice(server_random);
    sig_input.push(curve_type);
    sig_input.push(((named_curve >> 8) & 0xFF) as byte); // goishlint:ignore GOISH005
    sig_input.push((named_curve & 0xFF) as byte); // goishlint:ignore GOISH005
    sig_input.push(pubkey_len as byte); // goishlint:ignore GOISH005
    sig_input.extend_from_slice(server_pub_raw);

    // SHA-256 digest of sig_input
    let digest = {
        use crate::hash::Hash as HashTrait;
        use crate::io::Writer as WriterTrait;
        let mut h = sha256::New();
        let si_s = slice::<byte>::__from_vec(sig_input);
        let _ = WriterTrait::Write(&mut h, si_s);
        let sum = HashTrait::Sum(&h, slice::<byte>::__from_vec(alloc::vec![]));
        sum.__into_vec()
    };

    // Verify RSA-PKCS1v1.5 signature (SHA-256)
    {
        let digest_s = slice::<byte>::__from_vec(digest.clone());
        let sig_s = slice::<byte>::__from_vec(signature.to_vec());
        let verr = rsa::VerifyPKCS1v15(
            server_rsa_pubkey,
            crate::crypto::SHA256,
            digest_s,
            sig_s,
        );
        if !verr.IsNil() {
            return (zero, zero, verr);
        }
    }

    // Generate our ephemeral X25519 keypair and compute shared secret
    let (client_priv, client_pub_key) = ecdh::x25519_generate();
    let mut server_pub_arr = [0u8; 32];
    server_pub_arr.copy_from_slice(server_pub_raw);
    let server_pub_key = ecdh::X25519PublicKey(server_pub_arr);

    let shared = ecdh::x25519_compute_shared(&client_priv, &server_pub_key);

    // Check for low-order point attack (all-zeros shared secret)
    let mut is_zero = 0u8;
    for b in shared.iter() { is_zero |= *b; }
    if is_zero == 0 {
        return (zero, zero, errors::New("tls: x25519 shared secret is all zeros"));
    }

    (shared, client_pub_key.0, errors::nil)
}

/// Parse a ServerKeyExchange body for the ECDHE_ECDSA key agreement.
///
/// Wire format (RFC 4492 §5.4):
///   curve_type    (1) — must be 3 (named_curve)
///   named_curve   (2) — 29 = x25519, 23 = secp256r1
///   pubkey_len    (1) — 32 for x25519, 65 for uncompressed P-256
///   pubkey        (pubkey_len bytes)
///   hash_alg      (1) — 4 = SHA-256
///   sig_alg       (1) — 3 = ECDSA
///   sig_len       (2)
///   signature     (sig_len bytes) — DER-encoded ECDSA signature
///
/// Returns (premaster_secret[32], client_pub_bytes: Vec<byte>, error).
/// client_pub_bytes is 32 bytes for X25519 or 65 bytes for uncompressed P-256.
fn parse_server_key_exchange_ecdsa(
    body: &[byte],
    client_random: &[byte; 32],
    server_random: &[byte; 32],
    server_ec_pubkey: &P256PublicKey,
) -> ([byte; 32], Vec<byte>, error) {
    let zero32 = [0u8; 32];
    let empty_vec: Vec<byte> = Vec::new();

    if body.len() < 4 {
        return (zero32, empty_vec, errors::New("tls: ServerKeyExchange too short"));
    }
    // curve_type must be 3 = named_curve
    let curve_type = body[0];
    if curve_type != CURVE_TYPE_NAMED {
        return (zero32, empty_vec, errors::New("tls: ServerKeyExchange: expected named_curve"));
    }
    // named_curve
    let named_curve = u16::from_be_bytes([body[1], body[2]]);
    let pubkey_len = body[3] as usize;

    // Validate named_curve and pubkey_len
    match named_curve {
        NAMED_CURVE_X25519 => {
            if pubkey_len != 32 {
                return (zero32, empty_vec, errors::New("tls: ServerKeyExchange: x25519 pubkey must be 32 bytes"));
            }
        }
        NAMED_CURVE_SECP256R1 => {
            // Uncompressed P-256: 0x04 || x(32) || y(32) = 65 bytes
            if pubkey_len != 65 {
                return (zero32, empty_vec, errors::New("tls: ServerKeyExchange: P-256 pubkey must be 65 bytes"));
            }
        }
        _ => {
            tls_debug!("[tls-debug] SKE-ECDSA: unsupported named_curve=0x%04x\n", named_curve as u64);
            return (zero32, empty_vec, errors::New("tls: ServerKeyExchange: unsupported named_curve for ECDSA"));
        }
    }

    if body.len() < 4 + pubkey_len + 4 {
        return (zero32, empty_vec, errors::New("tls: ServerKeyExchange: truncated after pubkey"));
    }
    let server_pub_raw = &body[4..4 + pubkey_len];
    let hash_alg = body[4 + pubkey_len];
    let sig_alg = body[4 + pubkey_len + 1];
    // Only support SHA-256 + ECDSA (4, 3)
    if hash_alg != 4 || sig_alg != 3 {
        tls_debug!("[tls-debug] SKE-ECDSA: unsupported hash_alg=%d sig_alg=%d\n", hash_alg as i64, sig_alg as i64);
        return (zero32, empty_vec, errors::New("tls: ServerKeyExchange: unsupported SignatureAndHashAlgorithm (only SHA256+ECDSA supported)"));
    }
    let sig_len = u16::from_be_bytes([body[4 + pubkey_len + 2], body[4 + pubkey_len + 3]]) as usize;
    if body.len() < 4 + pubkey_len + 4 + sig_len {
        return (zero32, empty_vec, errors::New("tls: ServerKeyExchange: truncated ECDSA signature"));
    }
    let signature = &body[4 + pubkey_len + 4..4 + pubkey_len + 4 + sig_len];

    // Verify the ECDSA signature:
    // sig_input = client_random || server_random || curve_type(1) || named_curve(2) || pubkey_len(1) || pubkey
    let mut sig_input: Vec<byte> = Vec::with_capacity(32 + 32 + 4 + pubkey_len);
    sig_input.extend_from_slice(client_random);
    sig_input.extend_from_slice(server_random);
    sig_input.push(curve_type);
    sig_input.push(((named_curve >> 8) & 0xFF) as byte); // goishlint:ignore GOISH005
    sig_input.push((named_curve & 0xFF) as byte); // goishlint:ignore GOISH005
    sig_input.push(pubkey_len as byte); // goishlint:ignore GOISH005
    sig_input.extend_from_slice(server_pub_raw);

    // SHA-256 digest of sig_input
    let digest = {
        use crate::hash::Hash as HashTrait;
        use crate::io::Writer as WriterTrait;
        let mut h = sha256::New();
        let si_s = slice::<byte>::__from_vec(sig_input);
        let _ = WriterTrait::Write(&mut h, si_s);
        let sum = HashTrait::Sum(&h, slice::<byte>::__from_vec(alloc::vec![]));
        sum.__into_vec()
    };

    // Verify ECDSA-P256 signature
    {
        let verr = VerifyP256(server_ec_pubkey, &digest, signature);
        if !verr.IsNil() {
            tls_debug!("[tls-debug] ECDSA signature verify error: %v\n", verr);
            return (zero32, empty_vec, verr);
        }
    }
    tls_debug!("[tls-debug] ECDSA signature verified OK\n");

    // Generate our ephemeral keypair and compute shared secret.
    // The ECDH key exchange uses the same curve as the server's ECDH key.
    match named_curve {
        NAMED_CURVE_X25519 => {
            // Generate X25519 keypair
            let (client_priv, client_pub_key) = ecdh::x25519_generate();
            let mut server_pub_arr = [0u8; 32];
            server_pub_arr.copy_from_slice(server_pub_raw);
            let server_pub_key_x = ecdh::X25519PublicKey(server_pub_arr);
            let shared = ecdh::x25519_compute_shared(&client_priv, &server_pub_key_x);

            // Check for low-order point attack
            let mut is_zero = 0u8;
            for b in shared.iter() { is_zero |= *b; }
            if is_zero == 0 {
                return (zero32, empty_vec, errors::New("tls: x25519 shared secret is all zeros"));
            }
            (shared, client_pub_key.0.to_vec(), errors::nil)
        }
        NAMED_CURVE_SECP256R1 => {
            // P-256 ECDH key exchange
            // server_pub_raw is 65 bytes: 0x04 || server_x(32) || server_y(32)
            if server_pub_raw[0] != 0x04 {
                return (zero32, empty_vec, errors::New("tls: ECDHE P-256 server pubkey not uncompressed"));
            }
            // Generate P-256 ECDH keypair and compute shared secret.
            // Returns (priv[32], client_pub_65[65], shared[32]).
            let (client_priv_bytes, client_pub_65, shared) =
                crate::crypto::tls::legacy_p256::p256_ecdh_generate_and_compute_full(server_pub_raw);
            if client_priv_bytes.iter().all(|&b| b == 0) {
                return (zero32, empty_vec, errors::New("tls: P-256 ECDH failed"));
            }
            // Return the full 65-byte uncompressed client public key.
            // The caller will use this directly in the CKE message.
            (shared, client_pub_65.to_vec(), errors::nil)
        }
        _ => {
            return (zero32, empty_vec, errors::New("tls: unsupported named_curve in ECDSA SKE"));
        }
    }
}

/// Public test helper: parse ServerKeyExchange for ECDHE path.
pub fn parse_server_key_exchange_x25519(
    body: &[byte],
    client_random: &[byte; 32],
    server_random: &[byte; 32],
    server_rsa_pubkey: &rsa::PublicKey,
) -> ([byte; 32], [byte; 32], error) {
    parse_server_key_exchange(body, client_random, server_random, server_rsa_pubkey)
}

fn compute_finished_verify_data(
    master: &[byte; 48],
    transcript: &[byte],
    is_client: bool,
) -> Vec<byte> {
    use crate::crypto::sha256;
    use crate::hash::Hash as HashTrait;
    use crate::io::Writer as WriterTrait;

    // SHA256(all handshake messages)
    let mut h = sha256::New();
    let t_slice = slice::<byte>::__from_vec(transcript.to_vec());
    let _ = WriterTrait::Write(&mut h, t_slice);
    let digest = HashTrait::Sum(&h, slice::<byte>::__from_vec(alloc::vec![]));
    let digest_vec = digest.__into_vec();

    let label: &[byte] = if is_client { b"client finished" } else { b"server finished" };

    let mut vd = [0u8; 12];
    prf12(&mut vd, master, label, &digest_vec);
    vd.to_vec()
}

// ─── ChaCha20-Poly1305 only handshake ────────────────────────────────

/// Build a ClientHello that advertises *only* TLS_CHACHA20_POLY1305_SHA256 (0x1303).
/// This forces a TLS 1.3 handshake using ChaCha20-Poly1305 or nothing.
fn build_client_hello_chacha20_only(
    client_random: &[byte; 32],
    server_name: &str,
    x25519_pub: &ecdh::X25519PublicKey,
) -> Vec<byte> {
    let mut body: Vec<byte> = Vec::new();
    body.push(TLS_VERSION_MAJOR);
    body.push(TLS_VERSION_MINOR);
    body.extend_from_slice(client_random);
    // session_id: 32-byte random for middlebox compat
    let mut session_id = [0u8; 32];
    {
        let mut buf = slice::<byte>::__from_vec(alloc::vec![0u8; 32]);
        let _ = rand::Read(&mut buf);
        let v = buf.__into_vec();
        session_id.copy_from_slice(&v[..32]);
    }
    body.push(32u8);
    body.extend_from_slice(&session_id);
    // cipher_suites: 1 suite only — TLS_CHACHA20_POLY1305_SHA256 (0x1303)
    body.push(0);
    body.push(2); // 1 suite * 2 bytes
    body.extend_from_slice(&CIPHER_TLS13_CHACHA20_POLY1305_SHA256.to_be_bytes());
    // compression_methods: null only
    body.push(1);
    body.push(0);
    // Extensions (same as build_client_hello_inner but without TLS 1.2 suites)
    let mut exts: Vec<byte> = Vec::new();
    // server_name
    if !server_name.is_empty() {
        let host = server_name.as_bytes();
        let host_len = host.len() as u16; // goishlint:ignore GOISH005
        let server_name_list_len = (1u16 + 2u16 + host_len) as u16;
        let ext_data_len = (2u16 + server_name_list_len) as u16;
        exts.extend_from_slice(&[0x00u8, 0x00u8]);
        exts.extend_from_slice(&ext_data_len.to_be_bytes());
        exts.extend_from_slice(&server_name_list_len.to_be_bytes());
        exts.push(0x00u8);
        exts.extend_from_slice(&host_len.to_be_bytes());
        exts.extend_from_slice(host);
    }
    // supported_versions: TLS 1.3 only
    {
        let versions: &[u8] = &[0x03u8, 0x04u8]; // TLS 1.3 only
        let list_len = versions.len() as u8; // goishlint:ignore GOISH005
        let ext_data_len = (1u16 + versions.len() as u16) as u16; // goishlint:ignore GOISH005
        exts.extend_from_slice(&EXT_SUPPORTED_VERSIONS.to_be_bytes());
        exts.extend_from_slice(&ext_data_len.to_be_bytes());
        exts.push(list_len);
        exts.extend_from_slice(versions);
    }
    // supported_groups: X25519, P-256
    {
        let groups: &[u8] = &[0x00u8, 0x1du8, 0x00u8, 0x17u8];
        let groups_inner_len = groups.len() as u16; // goishlint:ignore GOISH005
        let groups_ext_len = 2 + groups_inner_len;
        exts.extend_from_slice(&EXT_SUPPORTED_GROUPS.to_be_bytes());
        exts.extend_from_slice(&groups_ext_len.to_be_bytes());
        exts.extend_from_slice(&groups_inner_len.to_be_bytes());
        exts.extend_from_slice(groups);
    }
    // key_share: X25519
    {
        let pub_bytes = &x25519_pub.0;
        let entry_len: u16 = 2 + 2 + 32;
        let list_len: u16 = entry_len;
        let ext_data_len: u16 = 2 + list_len;
        exts.extend_from_slice(&EXT_KEY_SHARE.to_be_bytes());
        exts.extend_from_slice(&ext_data_len.to_be_bytes());
        exts.extend_from_slice(&list_len.to_be_bytes());
        exts.extend_from_slice(&29u16.to_be_bytes());
        exts.extend_from_slice(&32u16.to_be_bytes());
        exts.extend_from_slice(pub_bytes);
    }
    // ec_point_formats
    {
        let formats: &[u8] = &[0x00u8];
        let fmt_inner_len = formats.len() as u16; // goishlint:ignore GOISH005
        let fmt_ext_len = 1 + fmt_inner_len;
        exts.extend_from_slice(&EXT_EC_POINT_FORMATS.to_be_bytes());
        exts.extend_from_slice(&fmt_ext_len.to_be_bytes());
        exts.push(fmt_inner_len as byte); // goishlint:ignore GOISH005
        exts.extend_from_slice(formats);
    }
    // signature_algorithms
    {
        let algs: &[u8] = &[
            0x04u8, 0x03u8,
            0x05u8, 0x03u8,
            0x08u8, 0x04u8,
            0x08u8, 0x05u8,
            0x04u8, 0x01u8,
            0x05u8, 0x01u8,
        ];
        let algs_inner_len = algs.len() as u16; // goishlint:ignore GOISH005
        let algs_ext_len = 2 + algs_inner_len;
        exts.extend_from_slice(&EXT_SIGNATURE_ALGORITHMS.to_be_bytes());
        exts.extend_from_slice(&algs_ext_len.to_be_bytes());
        exts.extend_from_slice(&algs_inner_len.to_be_bytes());
        exts.extend_from_slice(algs);
    }
    // psk_key_exchange_modes
    {
        let modes: &[u8] = &[0x01u8];
        let modes_len = modes.len() as u8; // goishlint:ignore GOISH005
        let ext_data_len: u16 = 1 + modes.len() as u16; // goishlint:ignore GOISH005
        exts.extend_from_slice(&0x002Du16.to_be_bytes());
        exts.extend_from_slice(&ext_data_len.to_be_bytes());
        exts.push(modes_len);
        exts.extend_from_slice(modes);
    }
    let exts_total_len = exts.len() as u16; // goishlint:ignore GOISH005
    body.extend_from_slice(&exts_total_len.to_be_bytes());
    body.extend_from_slice(&exts);
    build_handshake_msg(MSG_CLIENT_HELLO, &body)
}

/// Drive a TLS 1.3 client-side handshake that forces ChaCha20-Poly1305 (0x1303).
/// Only advertises TLS_CHACHA20_POLY1305_SHA256 in the ClientHello cipher suites.
/// On success returns derived `KeyMaterial` with `suite == 0x1303`.
pub fn do_client_handshake_chacha20_only(
    conn: &mut dyn crate::net::Conn,
    _server_name: &str,
    _skip_verify: bool,
) -> (KeyMaterial, error) {
    tls_debug!("[tls-debug] do_client_handshake_chacha20_only: start server_name=%s\n", _server_name);
    // ── 1. Generate client_random ──────────────────────────────────
    let mut client_random = [0u8; 32];
    {
        let mut buf = slice::<byte>::__from_vec(alloc::vec![0u8; 32]);
        let (_, err) = rand::Read(&mut buf);
        if !err.IsNil() {
            return (KeyMaterial::default(), err);
        }
        client_random.copy_from_slice(&buf.__into_vec()[..32]);
    }

    // ── 1b. Generate X25519 keypair ────────────────────────────────
    let (client_x25519_priv, client_x25519_pub) = ecdh::x25519_generate();

    // ── 2. Build & send ClientHello (ChaCha20-only) ────────────────
    let client_hello_body = build_client_hello_chacha20_only(&client_random, _server_name, &client_x25519_pub);
    tls_debug!("[tls-debug] ChaCha20-only ClientHello built, len=%d\n", client_hello_body.len() as i64);

    let mut transcript: Vec<byte> = Vec::new();
    transcript.extend_from_slice(&client_hello_body);

    let record_slice = crate::crypto::tls::record::encode_record(
        RECORD_HANDSHAKE,
        &client_hello_body,
    );
    let (_, werr) = conn.Write(record_slice);
    if !werr.IsNil() {
        return (KeyMaterial::default(), werr);
    }

    // ── 3. Receive ServerHello ─────────────────────────────────────
    let server_random;
    let mut tls13_suite_id: u16 = 0;
    let mut tls13_server_key_share: Vec<byte> = Vec::new();
    let mut hrr_cookie: Option<Vec<byte>> = None;
    // HRR selected_group is parsed but unused here: this path has no
    // second-ClientHello support; an HRR fails later at the
    // no-key_share check.
    let mut _hrr_selected_group: u16 = 0;
    {
        let (rtype, frag_s, err) = {
            let mut adapter = ConnReader(conn);
            crate::crypto::tls::record::read_record(&mut adapter)
        };
        let frag = frag_s.__into_vec();
        if !err.IsNil() {
            return (KeyMaterial::default(), err);
        }
        if rtype == RECORD_ALERT {
            let alert_desc = if frag.len() >= 2 { frag[1] } else { 0 };
            tls_debug!("[tls-debug] TLS Alert level=%d desc=%d\n", if frag.len() >= 1 { frag[0] as i64 } else { 0 }, alert_desc as i64);
            return (KeyMaterial::default(), errors::New("tls: received TLS alert from server"));
        }
        if rtype != RECORD_HANDSHAKE || frag.len() < 4 || frag[0] != MSG_SERVER_HELLO {
            return (KeyMaterial::default(), errors::New("tls: expected ServerHello message"));
        }
        transcript.extend_from_slice(&frag);

        let body = &frag[4..];
        if body.len() < 35 {
            return (KeyMaterial::default(), errors::New("tls: ServerHello body too short"));
        }
        let maj = body[0];
        let min = body[1];
        if maj != TLS_VERSION_MAJOR || min != TLS_VERSION_MINOR {
            return (KeyMaterial::default(), errors::New("tls: server version not 1.2 or 1.3"));
        }
        let mut sr = [0u8; 32];
        sr.copy_from_slice(&body[2..34]);
        server_random = sr;

        let sid_len = body[34] as usize;
        let sid_end = 35 + sid_len;
        if body.len() < sid_end + 2 {
            return (KeyMaterial::default(), errors::New("tls: ServerHello truncated"));
        }
        let cs = u16::from_be_bytes([body[sid_end], body[sid_end + 1]]);
        tls_debug!("[tls-debug] ChaCha20-only ServerHello cipher_suite=0x%04x\n", cs as u64);

        if body.len() > sid_end + 3 {
            let comp_method_offset = sid_end + 2;
            if body.len() > comp_method_offset + 2 {
                let ext_total_len = u16::from_be_bytes([body[comp_method_offset + 1], body[comp_method_offset + 2]]) as usize;
                let ext_start = comp_method_offset + 3;
                if ext_start + ext_total_len <= body.len() {
                    let exts = &body[ext_start..ext_start + ext_total_len];
                    let mut pos = 0usize;
                    while pos + 4 <= exts.len() {
                        let ext_type = u16::from_be_bytes([exts[pos], exts[pos + 1]]);
                        let ext_len = u16::from_be_bytes([exts[pos + 2], exts[pos + 3]]) as usize;
                        pos += 4;
                        if pos + ext_len > exts.len() { break; }
                        let ext_data = &exts[pos..pos + ext_len];
                        match ext_type {
                            EXT_SUPPORTED_VERSIONS => {
                                if ext_len >= 2 {
                                    let selected = u16::from_be_bytes([ext_data[0], ext_data[1]]);
                                    tls_debug!("[tls-debug] ChaCha20-only supported_versions=0x%04x\n", selected as u64);
                                    if selected == TLS_VERSION_TLS13 {
                                        if cs != CIPHER_TLS13_CHACHA20_POLY1305_SHA256 {
                                            tls_debug!("[tls-debug] ChaCha20-only: server chose suite 0x%04x, expected 0x1303\n", cs as u64);
                                            return (KeyMaterial::default(), errors::New("tls: server did not choose ChaCha20-Poly1305"));
                                        }
                                        tls13_suite_id = cs;
                                    }
                                }
                            }
                            EXT_KEY_SHARE => {
                                if ext_len >= 2 {
                                    let group = u16::from_be_bytes([ext_data[0], ext_data[1]]);
                                    if ext_len >= 4 {
                                        let ke_len = u16::from_be_bytes([ext_data[2], ext_data[3]]) as usize;
                                        if group == 29 && ext_len >= 4 + ke_len {
                                            tls13_server_key_share = ext_data[4..4 + ke_len].to_vec();
                                        }
                                    } else {
                                        _hrr_selected_group = group;
                                    }
                                }
                            }
                            0x002C => {
                                if ext_len >= 2 {
                                    let cookie_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                                    if 2 + cookie_len <= ext_len {
                                        hrr_cookie = Some(ext_data[2..2 + cookie_len].to_vec());
                                    }
                                }
                            }
                            _ => {}
                        }
                        pos += ext_len;
                    }
                }
            }
        }

        if tls13_suite_id == 0 {
            return (KeyMaterial::default(), errors::New("tls: server did not negotiate TLS 1.3 with ChaCha20-Poly1305"));
        }
    }

    // ── 3b. HRR handling (same logic as do_client_handshake) ─────
    const HRR_RANDOM_CC: [u8; 32] = [
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
        0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
        0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
        0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
    ];
    let (client_x25519_priv, _client_x25519_pub) = if server_random == HRR_RANDOM_CC {
        tls_debug!("[tls-debug] ChaCha20-only HRR detected\n");
        let hrr_suite = match crate::crypto::tls::key_schedule::cipher_suite_tls13(tls13_suite_id) {
            Some(s) => s,
            None => return (KeyMaterial::default(), errors::New("tls13: unsupported cipher suite in HRR")),
        };
        let hash_fn = hrr_suite.hash_fn;
        let hrr_server_hello = transcript[client_hello_body.len()..].to_vec();
        let ch_hash = crate::crypto::tls::key_schedule::transcript_hash_fn(hash_fn, &client_hello_body);
        let hash_len = ch_hash.len() as byte;
        let mut new_transcript: Vec<byte> = Vec::new();
        new_transcript.push(0xFEu8);
        new_transcript.push(0x00u8);
        new_transcript.push(0x00u8);
        new_transcript.push(hash_len);
        new_transcript.extend_from_slice(&ch_hash);
        new_transcript.extend_from_slice(&hrr_server_hello);
        transcript = new_transcript;

        // ChaCha20-only only advertises X25519 — always use X25519 for HRR
        let (new_priv, new_pub) = crate::crypto::ecdh::x25519_generate();
        let ch2_pub_bytes = new_pub.0.to_vec();
        let ch2_group: u16 = 29u16; // X25519

        // Build CH2 with chacha20-only cipher, cookie if present
        let mut ch2_body: Vec<byte> = Vec::new();
        ch2_body.push(TLS_VERSION_MAJOR);
        ch2_body.push(TLS_VERSION_MINOR);
        ch2_body.extend_from_slice(&client_random);
        let mut session_id2 = [0u8; 32];
        {
            let mut buf = slice::<byte>::__from_vec(alloc::vec![0u8; 32]);
            let _ = rand::Read(&mut buf);
            let v = buf.__into_vec();
            session_id2.copy_from_slice(&v[..32]);
        }
        ch2_body.push(32u8);
        ch2_body.extend_from_slice(&session_id2);
        ch2_body.push(0); ch2_body.push(2);
        ch2_body.extend_from_slice(&CIPHER_TLS13_CHACHA20_POLY1305_SHA256.to_be_bytes());
        ch2_body.push(1); ch2_body.push(0);

        let mut exts2: Vec<byte> = Vec::new();
        // SNI
        if !_server_name.is_empty() {
            let host = _server_name.as_bytes();
            let host_len = host.len() as u16; // goishlint:ignore GOISH005
            let snl = (1u16 + 2u16 + host_len) as u16;
            let edl = (2u16 + snl) as u16;
            exts2.extend_from_slice(&[0x00u8, 0x00u8]);
            exts2.extend_from_slice(&edl.to_be_bytes());
            exts2.extend_from_slice(&snl.to_be_bytes());
            exts2.push(0x00u8);
            exts2.extend_from_slice(&host_len.to_be_bytes());
            exts2.extend_from_slice(host);
        }
        // supported_versions TLS 1.3 only
        exts2.extend_from_slice(&EXT_SUPPORTED_VERSIONS.to_be_bytes());
        exts2.extend_from_slice(&3u16.to_be_bytes());
        exts2.push(2u8);
        exts2.extend_from_slice(&[0x03u8, 0x04u8]);
        // supported_groups
        {
            let groups: &[u8] = &[0x00u8, 0x1du8, 0x00u8, 0x17u8];
            let gil = groups.len() as u16; // goishlint:ignore GOISH005
            exts2.extend_from_slice(&EXT_SUPPORTED_GROUPS.to_be_bytes());
            exts2.extend_from_slice(&(2 + gil).to_be_bytes());
            exts2.extend_from_slice(&gil.to_be_bytes());
            exts2.extend_from_slice(groups);
        }
        // key_share for the HRR-requested group
        {
            let ke_len = ch2_pub_bytes.len() as u16; // goishlint:ignore GOISH005
            let entry_len: u16 = 2 + 2 + ke_len;
            let ext_data_len: u16 = 2 + entry_len;
            exts2.extend_from_slice(&EXT_KEY_SHARE.to_be_bytes());
            exts2.extend_from_slice(&ext_data_len.to_be_bytes());
            exts2.extend_from_slice(&entry_len.to_be_bytes());
            exts2.extend_from_slice(&ch2_group.to_be_bytes());
            exts2.extend_from_slice(&ke_len.to_be_bytes());
            exts2.extend_from_slice(&ch2_pub_bytes);
        }
        // psk_key_exchange_modes
        exts2.extend_from_slice(&0x002Du16.to_be_bytes());
        exts2.extend_from_slice(&2u16.to_be_bytes());
        exts2.push(1u8);
        exts2.push(0x01u8);
        // cookie if provided
        if let Some(c) = &hrr_cookie {
            let cl = c.len() as u16; // goishlint:ignore GOISH005
            let edl = 2 + cl;
            exts2.extend_from_slice(&0x002Cu16.to_be_bytes());
            exts2.extend_from_slice(&edl.to_be_bytes());
            exts2.extend_from_slice(&cl.to_be_bytes());
            exts2.extend_from_slice(c);
        }
        let etl = exts2.len() as u16; // goishlint:ignore GOISH005
        ch2_body.extend_from_slice(&etl.to_be_bytes());
        ch2_body.extend_from_slice(&exts2);
        let ch2_msg = build_handshake_msg(MSG_CLIENT_HELLO, &ch2_body);
        transcript.extend_from_slice(&ch2_msg);
        let rec2 = crate::crypto::tls::record::encode_record(RECORD_HANDSHAKE, &ch2_msg);
        let (_, we2) = conn.Write(rec2);
        if !we2.IsNil() { return (KeyMaterial::default(), we2); }

        // Read real ServerHello
        let (rtype2, frag2_s, err2) = {
            let mut adapter = ConnReader(conn);
            crate::crypto::tls::record::read_record(&mut adapter)
        };
        let frag2 = frag2_s.__into_vec();
        if !err2.IsNil() { return (KeyMaterial::default(), err2); }
        if rtype2 != RECORD_HANDSHAKE || frag2.len() < 4 || frag2[0] != MSG_SERVER_HELLO {
            return (KeyMaterial::default(), errors::New("tls: expected ServerHello after HRR"));
        }
        transcript.extend_from_slice(&frag2);
        // Update server key share from real ServerHello
        let body2 = &frag2[4..];
        if body2.len() > 38 {
            let sid_len2 = body2[34] as usize;
            let sid_end2 = 35 + sid_len2;
            if body2.len() > sid_end2 + 3 {
                let cmo2 = sid_end2 + 2;
                if body2.len() > cmo2 + 2 {
                    let etl2 = u16::from_be_bytes([body2[cmo2 + 1], body2[cmo2 + 2]]) as usize;
                    let es2 = cmo2 + 3;
                    if es2 + etl2 <= body2.len() {
                        let exts2b = &body2[es2..es2 + etl2];
                        let mut pos2 = 0usize;
                        while pos2 + 4 <= exts2b.len() {
                            let et2 = u16::from_be_bytes([exts2b[pos2], exts2b[pos2 + 1]]);
                            let el2 = u16::from_be_bytes([exts2b[pos2 + 2], exts2b[pos2 + 3]]) as usize;
                            pos2 += 4;
                            if pos2 + el2 > exts2b.len() { break; }
                            let ed2 = &exts2b[pos2..pos2 + el2];
                            if et2 == EXT_KEY_SHARE && el2 >= 4 {
                                let grp2 = u16::from_be_bytes([ed2[0], ed2[1]]);
                                let kl2 = u16::from_be_bytes([ed2[2], ed2[3]]) as usize;
                                if grp2 == 29 && el2 >= 4 + kl2 {
                                    tls13_server_key_share = ed2[4..4 + kl2].to_vec();
                                }
                            }
                            pos2 += el2;
                        }
                    }
                }
            }
        }
        (new_priv, new_pub)
    } else {
        (client_x25519_priv, client_x25519_pub)
    };

    // ── 4. TLS 1.3 handshake (same flow as do_client_handshake) ───
    if tls13_server_key_share.is_empty() {
        return (KeyMaterial::default(), errors::New("tls13: no key_share in ServerHello"));
    }
    let suite = match crate::crypto::tls::key_schedule::cipher_suite_tls13(tls13_suite_id) {
        Some(s) => s,
        None => return (KeyMaterial::default(), errors::New("tls13: unsupported cipher suite")),
    };
    let (tls13_keys, err) = crate::crypto::tls::handshake_client_tls13::do_client_handshake_tls13(
        conn,
        &suite,
        &transcript,
        &client_random,
        &tls13_server_key_share,
        &client_x25519_priv,
    );
    if !err.IsNil() {
        tls_debug!("[tls-debug] ChaCha20-only TLS 1.3 handshake error: %v\n", err);
        return (KeyMaterial::default(), err);
    }
    let mut km = KeyMaterial::default();
    km.suite = tls13_suite_id;
    km.is_tls13 = true;
    let ck = &tls13_keys.client_app_keys;
    let sk = &tls13_keys.server_app_keys;
    let ck_len = ck.key.len().min(32);
    let sk_len = sk.key.len().min(32);
    km.tls13_client_key[..ck_len].copy_from_slice(&ck.key[..ck_len]);
    km.tls13_server_key[..sk_len].copy_from_slice(&sk.key[..sk_len]);
    let civ_len = ck.iv.len().min(12);
    let siv_len = sk.iv.len().min(12);
    km.tls13_client_iv[..civ_len].copy_from_slice(&ck.iv[..civ_len]);
    km.tls13_server_iv[..siv_len].copy_from_slice(&sk.iv[..siv_len]);
    km.tls13_server_app_secret = tls13_keys.server_app_secret.clone();
    km.tls13_resumption_master_secret = tls13_keys.resumption_master_secret.clone();
    km.tls13_hash_size = tls13_keys.hash_size;
    (km, errors::nil)
}


use super::conn::Conn;

// ─── crypto/tls/handshake_client.go, ported verbatim ──────────────────
//
// The three free functions of handshake_client.go. Everything above this
// divider is goish-only code that drives the live TLS 1.2 client.

// go: sdk 1.25.5 crypto/tls/handshake_client.go:1098-1108 checkKeySize
///
/// Deviation: Go consults the `tlsmaxrsasize` GODEBUG first;
/// `internal/godebug` is not ported, so an unset variable takes the
/// default branch — which is exactly what Go does when it is unset.
pub(crate) fn checkKeySize(n: crate::types::int) -> (crate::types::int, bool) {
    // Go: if v := tlsmaxrsasize.Value(); v != "" { … }
    //     return defaultMaxRSAKeySize, n <= defaultMaxRSAKeySize
    return (defaultMaxRSAKeySize, n <= defaultMaxRSAKeySize);
}

// Go: handshake_client.go:1092-1094
//   const defaultMaxRSAKeySize = 8192
/// Go: "defaultMaxRSAKeySize is the maximum RSA key size in bits that we
/// are willing to verify the signatures of during a TLS handshake."
pub(crate) const defaultMaxRSAKeySize: crate::types::int = 8192;

// go: sdk 1.25.5 crypto/tls/handshake_client.go:1308-1323 hostnameInSNI
/// Go: "hostnameInSNI converts name into an appropriate hostname for SNI.
/// Literal IP addresses and absolute FQDNs are not permitted as SNI
/// values. See RFC 6066, Section 3."
///
/// **Known gap, not a port deviation:** goish's `net::IP` is four bytes
/// and `net::ParseIP` only parses IPv4, so an IPv6 literal — bracketed,
/// zoned, or bare — is not recognised as an address and is returned as
/// a hostname. Go returns "" for all three. The bracket-stripping and
/// zone-stripping above are ported and do run; it is the final
/// `ParseIP` test that cannot see the result. This closes when
/// `net::ParseIP` grows IPv6.
pub(crate) fn hostnameInSNI(name: crate::gostring::string) -> crate::gostring::string {
    // Go: host := name
    //     if len(host) > 0 && host[0] == '[' && host[len(host)-1] == ']' {
    //         host = host[1 : len(host)-1] }
    let mut name = name;
    let mut host = name.clone();
    let hb = host.as_bytes();
    if hb.len() > 0 && hb[0] == b'[' && hb[hb.len() - 1] == b']' {
        host = host.slice(1, host.Len() - 1);
    }
    // Go: if i := strings.LastIndex(host, "%"); i > 0 { host = host[:i] }
    let i = crate::strings::LastIndex(host.clone(), "%");
    if i > 0 {
        host = host.slice(0, i);
    }
    // Go: if net.ParseIP(host) != nil { return "" }
    if !crate::net::ParseIP(host).IsNil() {
        return crate::gostring::string::from_static("");
    }
    // Go: for len(name) > 0 && name[len(name)-1] == '.' { name = name[:len(name)-1] }
    //     return name
    while name.Len() > 0 && name.as_bytes()[name.Len() as usize - 1] == b'.' {
        name = name.slice(0, name.Len() - 1);
    }
    return name;
}

// go: sdk 1.25.5 crypto/tls/handshake_client.go:977-994 checkALPN
/// Validate the server's ALPN choice against what the client offered.
pub(crate) fn checkALPN(
    clientProtos: crate::goslice::slice<crate::gostring::string>,
    serverProto: crate::gostring::string,
    quic: bool,
) -> crate::error {
    // Go: if serverProto == "" {
    //         if quic && len(clientProtos) > 0 {
    //             // RFC 9001, Section 8.1
    //             return errors.New("tls: server did not select an ALPN protocol") }
    //         return nil }
    if serverProto == crate::gostring::string::from_static("") {
        if quic && clientProtos.Len() > 0 {
            return crate::errors::New("tls: server did not select an ALPN protocol");
        }
        return crate::errors::nil;
    }
    // Go: if len(clientProtos) == 0 {
    //         return errors.New("tls: server advertised unrequested ALPN extension") }
    if clientProtos.Len() == 0 {
        return crate::errors::New("tls: server advertised unrequested ALPN extension");
    }
    // Go: for _, proto := range clientProtos { if proto == serverProto { return nil } }
    //     return errors.New("tls: server selected unadvertised ALPN protocol")
    for (_, proto) in crate::range!(clientProtos) {
        if *proto == serverProto {
            return crate::errors::nil;
        }
    }
    return crate::errors::New("tls: server selected unadvertised ALPN protocol");
}

impl Conn {
    // go: sdk 1.25.5 crypto/tls/handshake_client.go:1295-1303 Conn.clientSessionCacheKey
    /// The key a client session is cached under: the configured server
    /// name if there is one, otherwise the peer's address.
    pub(crate) fn clientSessionCacheKey(&self) -> crate::gostring::string {
        // Go: if len(c.config.ServerName) > 0 { return c.config.ServerName }
        if self.__configServerName().Len() > 0 {
            return self.__configServerName();
        }
        // Go: if c.conn != nil { return c.conn.RemoteAddr().String() }
        //     return ""
        if self.NetConn().is_some() {
            return self.RemoteAddr().String();
        }
        return crate::gostring::string::from_static("");
    }
}

// go: sdk 1.25.5 crypto/tls/handshake_client.go:1213-1275 certificateRequestInfoFromMsg
///
/// Deviation: Go's leading `ctx context.Context` parameter has nowhere
/// to go — `CertificateRequestInfo.ctx` is set by the handshake, which
/// is not ported.
/// goishlint:ignore GOISH020 certificateRequestInfoFromMsg — Go's context.Context parameter has no field to land in yet
pub(crate) fn certificateRequestInfoFromMsg(
    vers: crate::types::uint16,
    certReq: &super::handshake_messages::certificateRequestMsg,
) -> super::common::CertificateRequestInfo {
    // Go: cri := &CertificateRequestInfo{AcceptableCAs: certReq.certificateAuthorities,
    //         Version: vers, ctx: ctx}
    let mut cri = super::common::CertificateRequestInfo::default();
    cri.AcceptableCAs = certReq.certificateAuthorities.clone();
    cri.Version = vers;

    // Go: var rsaAvail, ecAvail bool
    //     for _, certType := range certReq.certificateTypes {
    //         switch certType {
    //         case certTypeRSASign: rsaAvail = true
    //         case certTypeECDSASign: ecAvail = true } }
    let mut rsaAvail = false;
    let mut ecAvail = false;
    for (_, certType) in crate::range!(certReq.certificateTypes.clone()) {
        if *certType == super::common::certTypeRSASign {
            rsaAvail = true;
        } else if *certType == super::common::certTypeECDSASign {
            ecAvail = true;
        }
    }

    // Go: if !certReq.hasSignatureAlgorithm {
    //         // Prior to TLS 1.2, signature schemes did not exist. In this case
    //         // we make up a list based on the acceptable certificate types, to
    //         // help GetClientCertificate and SupportsCertificate select the
    //         // right certificate. The hash part of the SignatureScheme is a lie
    //         // here, because TLS 1.0 and 1.1 always use MD5+SHA1 for RSA and
    //         // SHA1 for ECDSA.
    //         switch { case rsaAvail && ecAvail: … ; case rsaAvail: … ; case ecAvail: … }
    //         return cri }
    if !certReq.hasSignatureAlgorithm {
        if rsaAvail && ecAvail {
            cri.SignatureSchemes = crate::goslice::slice::__from_vec(alloc::vec![
                super::common::ECDSAWithP256AndSHA256,
                super::common::ECDSAWithP384AndSHA384,
                super::common::ECDSAWithP521AndSHA512,
                super::common::PKCS1WithSHA256,
                super::common::PKCS1WithSHA384,
                super::common::PKCS1WithSHA512,
                super::common::PKCS1WithSHA1,
            ]);
        } else if rsaAvail {
            cri.SignatureSchemes = crate::goslice::slice::__from_vec(alloc::vec![
                super::common::PKCS1WithSHA256,
                super::common::PKCS1WithSHA384,
                super::common::PKCS1WithSHA512,
                super::common::PKCS1WithSHA1,
            ]);
        } else if ecAvail {
            cri.SignatureSchemes = crate::goslice::slice::__from_vec(alloc::vec![
                super::common::ECDSAWithP256AndSHA256,
                super::common::ECDSAWithP384AndSHA384,
                super::common::ECDSAWithP521AndSHA512,
            ]);
        }
        return cri;
    }

    // Go: Filter the signature schemes based on the certificate types.
    // See RFC 5246, Section 7.4.4 (where it calls this "somewhat
    // complicated").
    let mut out: alloc::vec::Vec<super::common::SignatureScheme> =
        alloc::vec::Vec::with_capacity(certReq.supportedSignatureAlgorithms.Len() as usize);
    for (_, sigScheme) in crate::range!(certReq.supportedSignatureAlgorithms.clone()) {
        let (sigType, _, err) = super::auth::typeAndHashFromSignatureScheme(*sigScheme);
        if err != crate::errors::nil {
            continue;
        }
        if sigType == super::common::signatureECDSA
            || sigType == super::common::signatureEd25519
        {
            if ecAvail {
                out.push(*sigScheme);
            }
        } else if sigType == super::common::signatureRSAPSS
            || sigType == super::common::signaturePKCS1v15
        {
            if rsaAvail {
                out.push(*sigScheme);
            }
        }
    }
    cri.SignatureSchemes = crate::goslice::slice::__from_vec(out);

    // Go: return cri
    return cri;
}


// Go: handshake_client.go:39-49
//   type clientHandshakeState struct { c *Conn; ctx context.Context
//       serverHello *serverHelloMsg; hello *clientHelloMsg
//       suite *cipherSuite; finishedHash finishedHash
//       masterSecret []byte; session *SessionState; ticket []byte }
/// The TLS 1.0-1.2 client handshake state.
///
/// **Partial record.** Only the fields the ported methods read are
/// present; the key schedule and session fields land with `handshake`.
pub(crate) struct clientHandshakeState {
    pub c: Conn,
    pub serverHello: super::handshake_messages::serverHelloMsg,
    pub hello: super::handshake_messages::clientHelloMsg,
    pub suite: Option<&'static super::cipher_suites::cipherSuite>,
    pub finishedHash: super::prf::finishedHash,
    pub masterSecret: crate::goslice::slice<crate::types::byte>,
    pub session: Option<super::ticket::SessionState>,
    pub ticket: crate::goslice::slice<crate::types::byte>,
}

impl clientHandshakeState {
    // go: sdk 1.25.5 crypto/tls/handshake_client.go:545-640 clientHandshakeState.handshake
    /// Go: the TLS 1.0–1.2 client handshake driver — reject an echoed
    /// TLS 1.3 compatibility session ID, split on resumption, and
    /// sequence the key establishment, Finished exchange, and session
    /// ticket handling in the order the resumption decision dictates.
    pub(crate) fn handshake(&mut self) -> crate::error {
        // Go: "Since we're now handshaking for TLS 1.2, if the server
        // echoed the transmitted ID back to us, we know mischief is
        // afoot: the session ID was random and can't possibly be
        // recognized by the server."
        //     if hs.session == nil && hs.hello.sessionId != nil &&
        //         bytes.Equal(hs.hello.sessionId, hs.serverHello.sessionId) {
        //         c.sendAlert(alertIllegalParameter)
        //         return errors.New("tls: server echoed TLS 1.3 compatibility session ID in TLS 1.2") }
        if self.session.is_none()
            && self.hello.sessionId.len() != 0
            && crate::bytes::Equal(
                crate::goslice::slice::__from_vec(self.hello.sessionId.clone()),
                crate::goslice::slice::__from_vec(self.serverHello.sessionId.clone()),
            )
        {
            self.c.sendAlert(super::alert::alertIllegalParameter);
            return crate::errors::New(
                "tls: server echoed TLS 1.3 compatibility session ID in TLS 1.2",
            );
        }

        // Go: isResume, err := hs.processServerHello()
        //     if err != nil { return err }
        let (isResume, err) = self.processServerHello();
        if err != crate::errors::nil {
            return err;
        }

        // Go: hs.finishedHash = newFinishedHash(c.vers, hs.suite)
        self.finishedHash = super::prf::newFinishedHash(self.c.vers, self.suite.unwrap());

        // Go: "No signatures of the handshake are needed in a
        // resumption. Otherwise, in a full handshake, if we don't have
        // any certificates configured then we will never send a
        // CertificateVerify message and thus no signatures are needed in
        // that case either."
        //     if isResume || (len(c.config.Certificates) == 0 && c.config.GetClientCertificate == nil) {
        //         hs.finishedHash.discardHandshakeBuffer() }
        if isResume
            || (self.c.config.Certificates.Len() == 0
                && self.c.config.GetClientCertificate.is_none())
        {
            self.finishedHash.discardHandshakeBuffer();
        }

        // Go: if err := transcriptMsg(hs.hello, &hs.finishedHash); err != nil { return err }
        //     if err := transcriptMsg(hs.serverHello, &hs.finishedHash); err != nil { return err }
        let err =
            super::handshake_messages::transcriptMsg(&self.hello, &mut self.finishedHash);
        if err != crate::errors::nil {
            return err;
        }
        let err = super::handshake_messages::transcriptMsg(
            &self.serverHello,
            &mut self.finishedHash,
        );
        if err != crate::errors::nil {
            return err;
        }

        // Go: c.buffering = true
        //     c.didResume = isResume
        self.c.buffering = true;
        self.c.didResume = isResume;
        // Go: if isResume {
        if isResume {
            // Go: if err := hs.establishKeys(); err != nil { return err }
            //     if err := hs.readSessionTicket(); err != nil { return err }
            //     if err := hs.readFinished(c.serverFinished[:]); err != nil { return err }
            //     c.clientFinishedIsFirst = false
            let err = self.establishKeys();
            if err != crate::errors::nil {
                return err;
            }
            let err = self.readSessionTicket();
            if err != crate::errors::nil {
                return err;
            }
            let mut out =
                crate::goslice::slice::__from_vec(self.c.serverFinished.to_vec());
            let err = self.readFinished(&mut out);
            if err != crate::errors::nil {
                return err;
            }
            {
                let raw: &[crate::types::byte] = &out;
                self.c.serverFinished.copy_from_slice(raw);
            }
            self.c.clientFinishedIsFirst = false;
            // Go: "Make sure the connection is still being verified
            // whether or not this is a resumption. Resumptions currently
            // don't reverify certificates so they don't call
            // verifyServerCertificate. See Issue 31641."
            //     if c.config.VerifyConnection != nil {
            //         if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
            //             c.sendAlert(alertBadCertificate); return err } }
            if let Some(verify) = self.c.config.VerifyConnection.clone() {
                let err = verify(self.c.connectionStateLocked());
                if err != crate::errors::nil {
                    self.c.sendAlert(super::alert::alertBadCertificate);
                    return err;
                }
            }
            // Go: if err := hs.sendFinished(c.clientFinished[:]); err != nil { return err }
            //     if _, err := c.flush(); err != nil { return err }
            let mut out =
                crate::goslice::slice::__from_vec(self.c.clientFinished.to_vec());
            let err = self.sendFinished(&mut out);
            if err != crate::errors::nil {
                return err;
            }
            {
                let raw: &[crate::types::byte] = &out;
                self.c.clientFinished.copy_from_slice(raw);
            }
            let (_, err) = self.c.flush();
            if err != crate::errors::nil {
                return err;
            }
        } else {
            // Go: if err := hs.doFullHandshake(); err != nil { return err }
            //     if err := hs.establishKeys(); err != nil { return err }
            //     if err := hs.sendFinished(c.clientFinished[:]); err != nil { return err }
            //     if _, err := c.flush(); err != nil { return err }
            //     c.clientFinishedIsFirst = true
            //     if err := hs.readSessionTicket(); err != nil { return err }
            //     if err := hs.readFinished(c.serverFinished[:]); err != nil { return err }
            let err = self.doFullHandshake();
            if err != crate::errors::nil {
                return err;
            }
            let err = self.establishKeys();
            if err != crate::errors::nil {
                return err;
            }
            let mut out =
                crate::goslice::slice::__from_vec(self.c.clientFinished.to_vec());
            let err = self.sendFinished(&mut out);
            if err != crate::errors::nil {
                return err;
            }
            {
                let raw: &[crate::types::byte] = &out;
                self.c.clientFinished.copy_from_slice(raw);
            }
            let (_, err) = self.c.flush();
            if err != crate::errors::nil {
                return err;
            }
            self.c.clientFinishedIsFirst = true;
            let err = self.readSessionTicket();
            if err != crate::errors::nil {
                return err;
            }
            let mut out =
                crate::goslice::slice::__from_vec(self.c.serverFinished.to_vec());
            let err = self.readFinished(&mut out);
            if err != crate::errors::nil {
                return err;
            }
            {
                let raw: &[crate::types::byte] = &out;
                self.c.serverFinished.copy_from_slice(raw);
            }
        }
        // Go: if err := hs.saveSessionTicket(); err != nil { return err }
        let err = self.saveSessionTicket();
        if err != crate::errors::nil {
            return err;
        }

        // Go: c.ekm = ekmFromMasterSecret(c.vers, hs.suite, hs.masterSecret,
        //         hs.hello.random, hs.serverHello.random)
        //     c.isHandshakeComplete.Store(true)
        //     return nil
        self.c.ekm = Some(super::prf::ekmFromMasterSecret(
            self.c.vers,
            self.suite.unwrap(),
            self.masterSecret.clone(),
            crate::goslice::slice::__from_vec(self.hello.random.clone()),
            crate::goslice::slice::__from_vec(self.serverHello.random.clone()),
        ));
        self.c.isHandshakeComplete = true;
        return crate::errors::nil;
    }

    // go: sdk 1.25.5 crypto/tls/handshake_client.go:642-659 clientHandshakeState.pickCipherSuite
    ///
    /// Deviation: the two GODEBUG counter bumps (`tlsrsakex`, `tls3des`)
    /// are absent — `internal/godebug` is not ported, and the branches
    /// have no other effect.
    pub(crate) fn pickCipherSuite(&mut self) -> crate::error {
        // Go: if hs.suite = mutualCipherSuite(hs.hello.cipherSuites,
        //         hs.serverHello.cipherSuite); hs.suite == nil {
        //         hs.c.sendAlert(alertHandshakeFailure)
        //         return errors.New("tls: server chose an unconfigured cipher suite") }
        self.suite = super::cipher_suites::mutualCipherSuite(
            crate::goslice::slice::__from_vec(self.hello.cipherSuites.clone()),
            self.serverHello.cipherSuite,
        );
        if self.suite.is_none() {
            self.c.sendAlert(super::alert::alertHandshakeFailure);
            return crate::errors::New("tls: server chose an unconfigured cipher suite");
        }

        // Go: hs.c.cipherSuite = hs.suite.id
        //     return nil
        self.c.__setCipherSuite(self.suite.unwrap().id);
        return crate::errors::nil;
    }
}

impl Conn {
    // go: sdk 1.25.5 crypto/tls/handshake_client.go:523-541 Conn.pickTLSVersion
    /// Adopt the version the server selected, or refuse it.
    pub(crate) fn pickTLSVersion(
        &mut self,
        serverHello: &super::handshake_messages::serverHelloMsg,
    ) -> crate::error {
        // Go: peerVersion := serverHello.vers
        //     if serverHello.supportedVersion != 0 { peerVersion = serverHello.supportedVersion }
        let mut peerVersion = serverHello.vers;
        if serverHello.supportedVersion != 0 {
            peerVersion = serverHello.supportedVersion;
        }

        // Go: vers, ok := c.config.mutualVersion(roleClient, []uint16{peerVersion})
        //     if !ok {
        //         c.sendAlert(alertProtocolVersion)
        //         return fmt.Errorf("tls: server selected unsupported protocol version %x", peerVersion) }
        let (vers, ok) = self.__config().mutualVersion(
            super::common::roleClient,
            crate::goslice::slice::__from_vec(alloc::vec![peerVersion]),
        );
        if !ok {
            self.sendAlert(super::alert::alertProtocolVersion);
            return crate::fmt::Errorf!(
                "tls: server selected unsupported protocol version %x",
                peerVersion
            );
        }

        // Go: c.vers = vers; c.haveVers = true
        //     c.in.version = vers; c.out.version = vers
        //     return nil
        self.__adoptVersion(vers);
        return crate::errors::nil;
    }
}


impl clientHandshakeState {
    // go: sdk 1.25.5 crypto/tls/handshake_client.go:661-857 clientHandshakeState.doFullHandshake
    /// Go: the full (non-resumed) TLS 1.0–1.2 client handshake — read
    /// the server's Certificate, optional CertificateStatus,
    /// ServerKeyExchange, and optional CertificateRequest up to
    /// ServerHelloDone, then send the client's Certificate,
    /// ClientKeyExchange, and CertificateVerify, and derive the master
    /// secret.
    ///
    /// Deviation: the `tlssha1` GODEBUG counter bump when a SHA-1
    /// signature is selected is absent — goish ships no godebug.
    pub(crate) fn doFullHandshake(&mut self) -> crate::error {
        use crate::goslice::slice;

        // Go: msg, err := c.readHandshake(&hs.finishedHash)
        //     if err != nil { return err }
        //     certMsg, ok := msg.(*certificateMsg)
        //     if !ok || len(certMsg.certificates) == 0 {
        //         c.sendAlert(alertUnexpectedMessage)
        //         return unexpectedMessageError(certMsg, msg) }
        let (msg, err) = self.c.readHandshake(Some(&mut self.finishedHash));
        if err != crate::errors::nil {
            return err;
        }
        let msg = match msg {
            Some(m) => m,
            None => return crate::errors::New("tls: internal error: no handshake message"),
        };
        let certMsg = match msg
            .asAny()
            .downcast_ref::<super::handshake_messages::certificateMsg>()
        {
            Some(cm) if cm.certificates.Len() != 0 => cm.clone(),
            _ => {
                self.c.sendAlert(super::alert::alertUnexpectedMessage);
                return super::common::unexpectedMessageError(
                    crate::gostring::string::from_static("*tls.certificateMsg"),
                    super::handshake_messages::handshakeMessageTypeName(&*msg),
                );
            }
        };

        // Go: msg, err = c.readHandshake(&hs.finishedHash)
        //     if err != nil { return err }
        let (msg, err) = self.c.readHandshake(Some(&mut self.finishedHash));
        if err != crate::errors::nil {
            return err;
        }
        let mut msg = match msg {
            Some(m) => m,
            None => return crate::errors::New("tls: internal error: no handshake message"),
        };

        // Go: cs, ok := msg.(*certificateStatusMsg)
        //     if ok {
        if let Some(cs) = msg
            .asAny()
            .downcast_ref::<super::handshake_messages::certificateStatusMsg>()
        {
            // Go: "RFC4366 on Certificate Status Request: The server MAY
            // return a "certificate_status" message."
            //     if !hs.serverHello.ocspStapling {
            //         c.sendAlert(alertUnexpectedMessage)
            //         return errors.New("tls: received unexpected CertificateStatus message") }
            //     c.ocspResponse = cs.response
            if !self.serverHello.ocspStapling {
                self.c.sendAlert(super::alert::alertUnexpectedMessage);
                return crate::errors::New(
                    "tls: received unexpected CertificateStatus message",
                );
            }
            self.c.ocspResponse = cs.response.clone();

            // Go: msg, err = c.readHandshake(&hs.finishedHash)
            //     if err != nil { return err }
            let (nextMsg, err) = self.c.readHandshake(Some(&mut self.finishedHash));
            if err != crate::errors::nil {
                return err;
            }
            msg = match nextMsg {
                Some(m) => m,
                None => {
                    return crate::errors::New("tls: internal error: no handshake message")
                }
            };
        }

        // Go: if c.handshakes == 0 {
        //         if err := c.verifyServerCertificate(certMsg.certificates); err != nil { return err }
        //     } else {
        //         if !bytes.Equal(c.peerCertificates[0].Raw, certMsg.certificates[0]) {
        //             c.sendAlert(alertBadCertificate)
        //             return errors.New("tls: server's identity changed during renegotiation") } }
        if self.c.handshakes == 0 {
            let err = self.c.verifyServerCertificate(certMsg.certificates.clone());
            if err != crate::errors::nil {
                return err;
            }
        } else {
            if !crate::bytes::Equal(
                self.c.peerCertificates[0].Raw.clone(),
                certMsg.certificates[0].clone(),
            ) {
                self.c.sendAlert(super::alert::alertBadCertificate);
                return crate::errors::New(
                    "tls: server's identity changed during renegotiation",
                );
            }
        }

        // Go: keyAgreement := hs.suite.ka(c.vers)
        let mut keyAgreement = (self.suite.unwrap().ka)(self.c.vers);

        // Go: skx, ok := msg.(*serverKeyExchangeMsg)
        //     if ok {
        if let Some(skx) = msg
            .asAny()
            .downcast_ref::<super::handshake_messages::serverKeyExchangeMsg>()
        {
            // Go: err = keyAgreement.processServerKeyExchange(c.config,
            //         hs.hello, hs.serverHello, c.peerCertificates[0], skx)
            //     if err != nil { c.sendAlert(alertIllegalParameter); return err }
            let err = keyAgreement.processServerKeyExchange(
                &self.c.config,
                &self.hello,
                &self.serverHello,
                &self.c.peerCertificates[0],
                skx,
            );
            if err != crate::errors::nil {
                self.c.sendAlert(super::alert::alertIllegalParameter);
                return err;
            }
            // Go: if keyAgreement, ok := keyAgreement.(*ecdheKeyAgreement); ok {
            //         c.curveID = keyAgreement.curveID
            //         c.peerSigAlg = keyAgreement.signatureAlgorithm }
            if let Some(ecdhe) = keyAgreement
                .asAny()
                .downcast_ref::<super::key_agreement::ecdheKeyAgreement>()
            {
                self.c.curveID = ecdhe.curveID;
                self.c.peerSigAlg = ecdhe.signatureAlgorithm;
            }

            // Go: msg, err = c.readHandshake(&hs.finishedHash)
            //     if err != nil { return err }
            let (nextMsg, err) = self.c.readHandshake(Some(&mut self.finishedHash));
            if err != crate::errors::nil {
                return err;
            }
            msg = match nextMsg {
                Some(m) => m,
                None => {
                    return crate::errors::New("tls: internal error: no handshake message")
                }
            };
        }

        // Go: var chainToSend *Certificate
        //     var certRequested bool
        //     certReq, ok := msg.(*certificateRequestMsg)
        //     if ok {
        let mut chainToSend: Option<super::common::Certificate> = None;
        let mut certRequested = false;
        let mut certReq: Option<super::handshake_messages::certificateRequestMsg> = None;
        if let Some(cr) = msg
            .asAny()
            .downcast_ref::<super::handshake_messages::certificateRequestMsg>()
        {
            certRequested = true;
            certReq = Some(cr.clone());

            // Go: cri := certificateRequestInfoFromMsg(hs.ctx, c.vers, certReq)
            //     if chainToSend, err = c.getClientCertificate(cri); err != nil {
            //         c.sendAlert(alertInternalError); return err }
            let cri = super::handshake_client::certificateRequestInfoFromMsg(
                self.c.vers,
                certReq.as_ref().unwrap(),
            );
            let (chain, err) = self.c.getClientCertificate(&cri);
            if err != crate::errors::nil {
                self.c.sendAlert(super::alert::alertInternalError);
                return err;
            }
            chainToSend = Some(chain);

            // Go: msg, err = c.readHandshake(&hs.finishedHash)
            //     if err != nil { return err }
            let (nextMsg, err) = self.c.readHandshake(Some(&mut self.finishedHash));
            if err != crate::errors::nil {
                return err;
            }
            msg = match nextMsg {
                Some(m) => m,
                None => {
                    return crate::errors::New("tls: internal error: no handshake message")
                }
            };
        }

        // Go: shd, ok := msg.(*serverHelloDoneMsg)
        //     if !ok { c.sendAlert(alertUnexpectedMessage)
        //         return unexpectedMessageError(shd, msg) }
        if msg
            .asAny()
            .downcast_ref::<super::handshake_messages::serverHelloDoneMsg>()
            .is_none()
        {
            self.c.sendAlert(super::alert::alertUnexpectedMessage);
            return super::common::unexpectedMessageError(
                crate::gostring::string::from_static("*tls.serverHelloDoneMsg"),
                super::handshake_messages::handshakeMessageTypeName(&*msg),
            );
        }

        // Go: "If the server requested a certificate then we have to
        // send a Certificate message, even if it's empty because we
        // don't have a certificate to send."
        //     if certRequested {
        //         certMsg = new(certificateMsg)
        //         certMsg.certificates = chainToSend.Certificate
        //         if _, err := hs.c.writeHandshakeRecord(certMsg, &hs.finishedHash); err != nil {
        //             return err } }
        if certRequested {
            let mut certMsg = super::handshake_messages::certificateMsg::default();
            certMsg.certificates = chainToSend.as_ref().unwrap().Certificate.clone();
            let (_, err) = self
                .c
                .writeHandshakeRecord(&certMsg, Some(&mut self.finishedHash));
            if err != crate::errors::nil {
                return err;
            }
        }

        // Go: preMasterSecret, ckx, err := keyAgreement.generateClientKeyExchange(
        //         c.config, hs.hello, c.peerCertificates[0])
        //     if err != nil { c.sendAlert(alertInternalError); return err }
        let (preMasterSecret, ckx, err) = keyAgreement.generateClientKeyExchange(
            &self.c.config,
            &self.hello,
            &self.c.peerCertificates[0],
        );
        if err != crate::errors::nil {
            self.c.sendAlert(super::alert::alertInternalError);
            return err;
        }
        // Go: if ckx != nil {
        //         if _, err := hs.c.writeHandshakeRecord(ckx, &hs.finishedHash); err != nil {
        //             return err } }
        if let Some(ckx) = ckx.as_ref() {
            let (_, err) = self
                .c
                .writeHandshakeRecord(ckx, Some(&mut self.finishedHash));
            if err != crate::errors::nil {
                return err;
            }
        }

        // Go: if hs.serverHello.extendedMasterSecret {
        //         c.extMasterSecret = true
        //         hs.masterSecret = extMasterFromPreMasterSecret(c.vers, hs.suite,
        //             preMasterSecret, hs.finishedHash.Sum())
        //     } else {
        //         if fips140tls.Required() {
        //             c.sendAlert(alertHandshakeFailure)
        //             return errors.New("tls: FIPS 140-3 requires the use of Extended Master Secret") }
        //         hs.masterSecret = masterFromPreMasterSecret(c.vers, hs.suite,
        //             preMasterSecret, hs.hello.random, hs.serverHello.random) }
        if self.serverHello.extendedMasterSecret {
            self.c.extMasterSecret = true;
            let sum = self.finishedHash.Sum();
            self.masterSecret = super::prf::extMasterFromPreMasterSecret(
                self.c.vers,
                self.suite.unwrap(),
                preMasterSecret,
                sum,
            );
        } else {
            if super::internal::fips140tls::Required() {
                self.c.sendAlert(super::alert::alertHandshakeFailure);
                return crate::errors::New(
                    "tls: FIPS 140-3 requires the use of Extended Master Secret",
                );
            }
            self.masterSecret = super::prf::masterFromPreMasterSecret(
                self.c.vers,
                self.suite.unwrap(),
                preMasterSecret,
                slice::__from_vec(self.hello.random.clone()),
                slice::__from_vec(self.serverHello.random.clone()),
            );
        }
        // Go: if err := c.config.writeKeyLog(keyLogLabelTLS12, hs.hello.random, hs.masterSecret); err != nil {
        //         c.sendAlert(alertInternalError)
        //         return errors.New("tls: failed to write to key log: " + err.Error()) }
        let err = self.c.config.writeKeyLog(
            crate::gostring::string::from_static(super::common::keyLogLabelTLS12),
            slice::__from_vec(self.hello.random.clone()),
            self.masterSecret.clone(),
        );
        if err != crate::errors::nil {
            self.c.sendAlert(super::alert::alertInternalError);
            return crate::fmt::Errorf!("tls: failed to write to key log: %s", err.Error());
        }

        // Go: if chainToSend != nil && len(chainToSend.Certificate) > 0 {
        if chainToSend.is_some()
            && chainToSend.as_ref().unwrap().Certificate.Len() > 0
        {
            let cert = chainToSend.as_ref().unwrap();
            // Go: certVerify := &certificateVerifyMsg{}
            let mut certVerify = super::handshake_messages::certificateVerifyMsg::default();

            // Go: key, ok := chainToSend.PrivateKey.(crypto.Signer)
            //     if !ok { c.sendAlert(alertInternalError)
            //         return fmt.Errorf("tls: client certificate private key of type %T does not implement crypto.Signer", chainToSend.PrivateKey) }
            let key = match super::auth::signerOf(&cert.PrivateKey) {
                Some(s) => s,
                None => {
                    self.c.sendAlert(super::alert::alertInternalError);
                    return crate::errors::New(
                        "tls: client certificate private key of type unknown does not implement crypto.Signer",
                    );
                }
            };

            // Go: var sigType uint8
            //     var sigHash crypto.Hash
            //     if c.vers >= VersionTLS12 {
            //         signatureAlgorithm, err := selectSignatureScheme(c.vers, chainToSend, certReq.supportedSignatureAlgorithms)
            //         if err != nil { c.sendAlert(alertHandshakeFailure); return err }
            //         sigType, sigHash, err = typeAndHashFromSignatureScheme(signatureAlgorithm)
            //         if err != nil { return c.sendAlert(alertInternalError) }
            //         certVerify.hasSignatureAlgorithm = true
            //         certVerify.signatureAlgorithm = signatureAlgorithm
            //         if sigHash == crypto.SHA1 { tlssha1.Value(); tlssha1.IncNonDefault() }
            //     } else {
            //         sigType, sigHash, err = legacyTypeAndHashFromPublicKey(key.Public())
            //         if err != nil { c.sendAlert(alertIllegalParameter); return err } }
            let sigType: crate::types::uint8;
            let sigHash: crate::crypto::Hash;
            if self.c.vers >= super::common::VersionTLS12 {
                let (signatureAlgorithm, err) = super::auth::selectSignatureScheme(
                    self.c.vers,
                    cert,
                    certReq
                        .as_ref()
                        .unwrap()
                        .supportedSignatureAlgorithms
                        .clone(),
                );
                if err != crate::errors::nil {
                    self.c.sendAlert(super::alert::alertHandshakeFailure);
                    return err;
                }
                let (st, sh, err) =
                    super::auth::typeAndHashFromSignatureScheme(signatureAlgorithm);
                if err != crate::errors::nil {
                    return self.c.sendAlert(super::alert::alertInternalError);
                }
                sigType = st;
                sigHash = sh;
                certVerify.hasSignatureAlgorithm = true;
                certVerify.signatureAlgorithm = signatureAlgorithm.0;
            } else {
                let pubAny = super::auth::anyOfPublicKey(&key.Public());
                let (st, sh, err) =
                    super::auth::legacyTypeAndHashFromPublicKey(&pubAny);
                if err != crate::errors::nil {
                    self.c.sendAlert(super::alert::alertIllegalParameter);
                    return err;
                }
                sigType = st;
                sigHash = sh;
            }

            // Go: signed := hs.finishedHash.hashForClientCertificate(sigType, sigHash)
            //     signOpts := crypto.SignerOpts(sigHash)
            //     if sigType == signatureRSAPSS {
            //         signOpts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: sigHash} }
            //     certVerify.signature, err = key.Sign(c.config.rand(), signed, signOpts)
            //     if err != nil { c.sendAlert(alertInternalError); return err }
            let signed = self.finishedHash.hashForClientCertificate(sigType, sigHash);
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
            let (sig, err) = key.Sign(&mut *rng, signed, &*opts);
            if err != crate::errors::nil {
                self.c.sendAlert(super::alert::alertInternalError);
                return err;
            }
            certVerify.signature = sig.__into_vec();

            // Go: if _, err := hs.c.writeHandshakeRecord(certVerify, &hs.finishedHash); err != nil {
            //         return err }
            let (_, err) = self
                .c
                .writeHandshakeRecord(&certVerify, Some(&mut self.finishedHash));
            if err != crate::errors::nil {
                return err;
            }
        }

        // Go: hs.finishedHash.discardHandshakeBuffer()
        //     return nil
        self.finishedHash.discardHandshakeBuffer();
        return crate::errors::nil;
    }

    // go: sdk 1.25.5 crypto/tls/handshake_client.go:859-879 clientHandshakeState.establishKeys
    /// The client's mirror of the server's `establishKeys`: the same six
    /// keys, but the halves are crossed — the client writes with the
    /// client key and reads with the server's.
    pub(crate) fn establishKeys(&mut self) -> crate::error {
        let suite = self.suite.unwrap();
        // Go: clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
        //         keysFromMasterSecret(c.vers, hs.suite, hs.masterSecret,
        //             hs.hello.random, hs.serverHello.random,
        //             hs.suite.macLen, hs.suite.keyLen, hs.suite.ivLen)
        let (clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV) =
            super::prf::keysFromMasterSecret(
                self.c.__vers(),
                suite,
                self.masterSecret.clone(),
                crate::goslice::slice::__from_vec(self.hello.random.clone()),
                crate::goslice::slice::__from_vec(self.serverHello.random.clone()),
                suite.macLen,
                suite.keyLen,
                suite.ivLen,
            );
        // Go: if hs.suite.cipher != nil {
        //         clientCipher = hs.suite.cipher(clientKey, clientIV, false /* not for reading */)
        //         clientHash = hs.suite.mac(clientMAC)
        //         serverCipher = hs.suite.cipher(serverKey, serverIV, true /* for reading */)
        //         serverHash = hs.suite.mac(serverMAC)
        //     } else {
        //         clientCipher = hs.suite.aead(clientKey, clientIV)
        //         serverCipher = hs.suite.aead(serverKey, serverIV) }
        let clientCipher: super::conn::halfConnCipher;
        let serverCipher: super::conn::halfConnCipher;
        let mut clientHash: Option<alloc::boxed::Box<dyn crate::hash::Hash + Send + Sync>> = None;
        let mut serverHash: Option<alloc::boxed::Box<dyn crate::hash::Hash + Send + Sync>> = None;
        if suite.cipher.is_some() {
            let cipherFn = suite.cipher.unwrap();
            let macFn = suite.mac.unwrap();
            clientCipher = super::conn::halfConnCipherOf(cipherFn(clientKey, clientIV, false));
            clientHash = Some(macFn(clientMAC));
            serverCipher = super::conn::halfConnCipherOf(cipherFn(serverKey, serverIV, true));
            serverHash = Some(macFn(serverMAC));
        } else {
            let aeadFn = suite.aead.unwrap();
            clientCipher = super::conn::halfConnCipher::AEAD(aeadFn(clientKey, clientIV));
            serverCipher = super::conn::halfConnCipher::AEAD(aeadFn(serverKey, serverIV));
        }

        // Go: c.in.prepareCipherSpec(c.vers, serverCipher, serverHash)
        //     c.out.prepareCipherSpec(c.vers, clientCipher, clientHash)
        //     return nil
        //
        // Note the crossing: the client READS what the server wrote.
        let vers = self.c.__vers();
        self.c
            .__prepareCipherSpecs(vers, serverCipher, serverHash, clientCipher, clientHash);
        return crate::errors::nil;
    }

    // go: sdk 1.25.5 crypto/tls/handshake_client.go:881-886 clientHandshakeState.serverResumedSession
    pub(crate) fn serverResumedSession(&self) -> bool {
        // Go: If the server responded with the same sessionId then it
        // means the sessionTicket is being used to resume a TLS session.
        // Go: return hs.session != nil && hs.hello.sessionId != nil &&
        //         bytes.Equal(hs.serverHello.sessionId, hs.hello.sessionId)
        //
        // goish slices carry no nil/empty distinction, so `sessionId !=
        // nil` reads as a non-empty id — a client that sent none cannot
        // have its echo match anyway.
        return self.session.is_some()
            && self.hello.sessionId.len() != 0
            && self.serverHello.sessionId == self.hello.sessionId;
    }
}


impl clientHandshakeState {
    // go: sdk 1.25.5 crypto/tls/handshake_client.go:888-973 clientHandshakeState.processServerHello
    /// Validate the ServerHello and, if the server chose to resume,
    /// restore the session's secrets and peer state.
    ///
    /// Deviation: the renegotiation branch reads `c.handshakes`, which
    /// no ported code increments yet — the driver that would is
    /// `clientHandshake`. The branch is ported so it goes live with it.
    pub(crate) fn processServerHello(&mut self) -> (bool, crate::error) {
        // Go: if err := hs.pickCipherSuite(); err != nil { return false, err }
        let err = self.pickCipherSuite();
        if err != crate::errors::nil {
            return (false, err);
        }

        // Go: if hs.serverHello.compressionMethod != compressionNone {
        //         c.sendAlert(alertIllegalParameter)
        //         return false, errors.New("tls: server selected unsupported compression format") }
        if self.serverHello.compressionMethod != super::handshake_messages::compressionNone {
            self.c.sendAlert(super::alert::alertIllegalParameter);
            return (
                false,
                crate::errors::New("tls: server selected unsupported compression format"),
            );
        }

        // Go: supportsPointFormat := false; offeredNonCompressedFormat := false
        //     for _, format := range hs.serverHello.supportedPoints {
        //         if format == pointFormatUncompressed { supportsPointFormat = true }
        //         else { offeredNonCompressedFormat = true } }
        //     if !supportsPointFormat && offeredNonCompressedFormat {
        //         return false, errors.New("tls: server offered only incompatible point formats") }
        let mut supportsPointFormat = false;
        let mut offeredNonCompressedFormat = false;
        for format in self.serverHello.supportedPoints.iter() {
            if *format == super::common::pointFormatUncompressed {
                supportsPointFormat = true;
            } else {
                offeredNonCompressedFormat = true;
            }
        }
        if !supportsPointFormat && offeredNonCompressedFormat {
            return (
                false,
                crate::errors::New("tls: server offered only incompatible point formats"),
            );
        }

        // Go: if c.handshakes == 0 && hs.serverHello.secureRenegotiationSupported {
        //         c.secureRenegotiation = true
        //         if len(hs.serverHello.secureRenegotiation) != 0 {
        //             c.sendAlert(alertHandshakeFailure)
        //             return false, errors.New("tls: initial handshake had non-empty
        //                 renegotiation extension") } }
        if self.c.__handshakes() == 0 && self.serverHello.secureRenegotiationSupported {
            self.c.__setSecureRenegotiation(true);
            if self.serverHello.secureRenegotiation.len() != 0 {
                self.c.sendAlert(super::alert::alertHandshakeFailure);
                return (
                    false,
                    crate::errors::New(
                        "tls: initial handshake had non-empty renegotiation extension",
                    ),
                );
            }
        }

        // Go: if c.handshakes > 0 && c.secureRenegotiation {
        //         var expectedSecureRenegotiation [24]byte
        //         copy(expectedSecureRenegotiation[:], c.clientFinished[:])
        //         copy(expectedSecureRenegotiation[12:], c.serverFinished[:])
        //         if !bytes.Equal(hs.serverHello.secureRenegotiation,
        //             expectedSecureRenegotiation[:]) {
        //             c.sendAlert(alertHandshakeFailure)
        //             return false, errors.New("tls: incorrect renegotiation extension contents") } }
        if self.c.__handshakes() > 0 && self.c.__secureRenegotiation() {
            let expected = self.c.__expectedSecureRenegotiation();
            if slice::__from_vec(self.serverHello.secureRenegotiation.clone()) != expected {
                self.c.sendAlert(super::alert::alertHandshakeFailure);
                return (
                    false,
                    crate::errors::New("tls: incorrect renegotiation extension contents"),
                );
            }
        }

        // Go: if err := checkALPN(hs.hello.alpnProtocols,
        //         hs.serverHello.alpnProtocol, false); err != nil {
        //         c.sendAlert(alertUnsupportedExtension)
        //         return false, err }
        //     c.clientProtocol = hs.serverHello.alpnProtocol
        //     c.scts = hs.serverHello.scts
        let protos: alloc::vec::Vec<crate::gostring::string> = self
            .hello
            .alpnProtocols
            .iter()
            .map(|p| crate::gostring::string::from_bytes(p.as_bytes()))
            .collect();
        let chosen =
            crate::gostring::string::from_bytes(self.serverHello.alpnProtocol.as_bytes());
        let err = checkALPN(slice::__from_vec(protos), chosen.clone(), false);
        if err != crate::errors::nil {
            self.c.sendAlert(super::alert::alertUnsupportedExtension);
            return (false, err);
        }
        self.c.__setClientProtocol(chosen);
        self.c.__setSCTs(slice::__from_vec(
            self.serverHello
                .scts
                .iter()
                .map(|v| slice::__from_vec(v.clone()))
                .collect(),
        ));

        // Go: if !hs.serverResumedSession() { return false, nil }
        if !self.serverResumedSession() {
            return (false, crate::errors::nil);
        }
        let session = self.session.clone().unwrap();

        // Go: if hs.session.version != c.vers {
        //         c.sendAlert(alertHandshakeFailure)
        //         return false, errors.New("tls: server resumed a session with a
        //             different version") }
        if session.__version() != self.c.__vers() {
            self.c.sendAlert(super::alert::alertHandshakeFailure);
            return (
                false,
                crate::errors::New("tls: server resumed a session with a different version"),
            );
        }
        // Go: if hs.session.cipherSuite != hs.suite.id { … different cipher suite }
        if session.__cipherSuite() != self.suite.unwrap().id {
            self.c.sendAlert(super::alert::alertHandshakeFailure);
            return (
                false,
                crate::errors::New(
                    "tls: server resumed a session with a different cipher suite",
                ),
            );
        }
        // Go: RFC 7627, Section 5.3
        // Go: if hs.session.extMasterSecret != hs.serverHello.extendedMasterSecret {
        //         … different EMS extension }
        if session.__extMasterSecret() != self.serverHello.extendedMasterSecret {
            self.c.sendAlert(super::alert::alertHandshakeFailure);
            return (
                false,
                crate::errors::New("tls: server resumed a session with a different EMS extension"),
            );
        }

        // Go: Restore master secret and certificates from previous state
        // Go: hs.masterSecret = hs.session.secret … c.curveID = hs.session.curveID
        self.masterSecret = session.__secret();
        self.c.__restoreSession(&session);
        // Go: Let the ServerHello SCTs override the session SCTs from the
        // original connection, if any are provided.
        // Go: if len(c.scts) == 0 && len(hs.session.scts) != 0 { c.scts = hs.session.scts }
        //
        // __adoptSession assigns the session's SCTs unconditionally, so
        // the ServerHello's are put back when it had any.
        if self.serverHello.scts.len() != 0 {
            self.c.__setSCTs(slice::__from_vec(
                self.serverHello
                    .scts
                    .iter()
                    .map(|v| slice::__from_vec(v.clone()))
                    .collect(),
            ));
        }

        // Go: return true, nil
        return (true, crate::errors::nil);
    }
}


impl Conn {
    // go: sdk 1.25.5 crypto/tls/handshake_client.go:1277-1291 Conn.getClientCertificate
    /// The certificate to answer a CertificateRequest with, or an empty
    /// one meaning "none".
    pub(crate) fn getClientCertificate(
        &self,
        cri: &super::common::CertificateRequestInfo,
    ) -> (super::common::Certificate, crate::error) {
        // Go: if c.config.GetClientCertificate != nil {
        //         return c.config.GetClientCertificate(cri) }
        if let Some(get) = self.__config().GetClientCertificate.as_ref() {
            return get(cri);
        }

        // Go: for _, chain := range c.config.Certificates {
        //         if err := cri.SupportsCertificate(&chain); err != nil { continue }
        //         return &chain, nil }
        for (_, chain) in crate::range!(self.__config().Certificates) {
            if cri.SupportsCertificate(chain) != crate::errors::nil {
                continue;
            }
            return (chain.clone(), crate::errors::nil);
        }

        // Go: No acceptable certificate found. Don't send a certificate.
        // Go: return new(Certificate), nil
        return (super::common::Certificate::default(), crate::errors::nil);
    }
}

impl clientHandshakeState {
    // go: sdk 1.25.5 crypto/tls/handshake_client.go:1076-1089 clientHandshakeState.sendFinished
    /// Go: flush the pending records under a ChangeCipherSpec, then send
    /// the client's Finished and copy its verify_data into `out`.
    ///
    /// Deviation: `out` is `&mut slice<byte>` — goish slices do not share
    /// a backing array across handles, so Go's `copy(out, …)` would be
    /// invisible to the caller through a by-value parameter.
    pub(crate) fn sendFinished(&mut self, out: &mut crate::goslice::slice<crate::types::byte>) -> crate::error {
        // Go: c := hs.c
        // Go: if err := c.writeChangeCipherRecord(); err != nil { return err }
        let err = self.c.writeChangeCipherRecord();
        if err != crate::errors::nil {
            return err;
        }

        // Go: finished := new(finishedMsg)
        //     finished.verifyData = hs.finishedHash.clientSum(hs.masterSecret)
        let mut finished = super::handshake_messages::finishedMsg::default();
        finished.verifyData = self
            .finishedHash
            .clientSum(self.masterSecret.clone())
            .__into_vec();
        // Go: if _, err := hs.c.writeHandshakeRecord(finished, &hs.finishedHash); err != nil { return err }
        let (_, err) = self
            .c
            .writeHandshakeRecord(&finished, Some(&mut self.finishedHash));
        if err != crate::errors::nil {
            return err;
        }
        // Go: copy(out, finished.verifyData)
        copyInto(out, &finished.verifyData);
        return crate::errors::nil;
    }

    // go: sdk 1.25.5 crypto/tls/handshake_client.go:996-1029 clientHandshakeState.readFinished
    /// Go: read the server's ChangeCipherSpec and Finished, check the
    /// verify_data in constant time, and only then add the message to
    /// the transcript.
    ///
    /// Deviation: `out` is `&mut slice<byte>`; see `sendFinished`.
    pub(crate) fn readFinished(&mut self, out: &mut crate::goslice::slice<crate::types::byte>) -> crate::error {
        // Go: if err := c.readChangeCipherSpec(); err != nil { return err }
        let err = self.c.readChangeCipherSpec();
        if err != crate::errors::nil {
            return err;
        }

        // Go: "finishedMsg is included in the transcript, but not until
        // after we check the client version, since the state before this
        // message was sent is used during verification."
        let (msg, err) = self.c.readHandshake(None);
        if err != crate::errors::nil {
            return err;
        }
        // Go: serverFinished, ok := msg.(*finishedMsg); if !ok { … }
        let msg = match msg {
            Some(m) => m,
            None => return crate::errors::New("tls: internal error: no handshake message"),
        };
        let serverFinished = match msg
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

        // Go: verify := hs.finishedHash.serverSum(hs.masterSecret)
        //     if len(verify) != len(serverFinished.verifyData) ||
        //         subtle.ConstantTimeCompare(verify, serverFinished.verifyData) != 1 {
        //         c.sendAlert(alertHandshakeFailure)
        //         return errors.New("tls: server's Finished message was incorrect") }
        let verify = self.finishedHash.serverSum(self.masterSecret.clone());
        let got = crate::goslice::slice::__from_vec(serverFinished.verifyData.clone());
        if verify.Len() != got.Len()
            || crate::crypto::subtle::ConstantTimeCompare(&verify, &got) != 1
        {
            self.c.sendAlert(super::alert::alertHandshakeFailure);
            return crate::errors::New("tls: server's Finished message was incorrect");
        }

        // Go: if err := transcriptMsg(serverFinished, &hs.finishedHash); err != nil { return err }
        let err = super::handshake_messages::transcriptMsg(&serverFinished, &mut self.finishedHash);
        if err != crate::errors::nil {
            return err;
        }

        // Go: copy(out, verify)
        copyInto(out, &verify.__into_vec());
        return crate::errors::nil;
    }

    // go: sdk 1.25.5 crypto/tls/handshake_client.go:1031-1053 clientHandshakeState.readSessionTicket
    /// Go: read the server's NewSessionTicket, which is only legal if we
    /// offered the extension and the server echoed it.
    pub(crate) fn readSessionTicket(&mut self) -> crate::error {
        // Go: if !hs.serverHello.ticketSupported { return nil }
        if !self.serverHello.ticketSupported {
            return crate::errors::nil;
        }

        // Go: if !hs.hello.ticketSupported {
        //         c.sendAlert(alertIllegalParameter)
        //         return errors.New("tls: server sent unrequested session ticket") }
        if !self.hello.ticketSupported {
            self.c.sendAlert(super::alert::alertIllegalParameter);
            return crate::errors::New("tls: server sent unrequested session ticket");
        }

        // Go: msg, err := c.readHandshake(&hs.finishedHash)
        let (msg, err) = self.c.readHandshake(Some(&mut self.finishedHash));
        if err != crate::errors::nil {
            return err;
        }
        // Go: sessionTicketMsg, ok := msg.(*newSessionTicketMsg); if !ok { … }
        let msg = match msg {
            Some(m) => m,
            None => return crate::errors::New("tls: internal error: no handshake message"),
        };
        let sessionTicketMsg = match msg
            .asAny()
            .downcast_ref::<super::handshake_messages::newSessionTicketMsg>()
        {
            Some(t) => t.clone(),
            None => {
                self.c.sendAlert(super::alert::alertUnexpectedMessage);
                return super::common::unexpectedMessageError(
                    crate::gostring::string::from_static("*tls.newSessionTicketMsg"),
                    super::handshake_messages::handshakeMessageTypeName(&*msg),
                );
            }
        };

        // Go: hs.ticket = sessionTicketMsg.ticket
        //     return nil
        self.ticket = sessionTicketMsg.ticket.clone();
        return crate::errors::nil;
    }
}

// go: none — goish-only: stands in for Go's builtin `copy(dst, src)`.
// goish slices do not share a backing array across handles, so the
// destination is taken by `&mut` and written element by element.
pub(crate) fn copyInto(
    dst: &mut crate::goslice::slice<crate::types::byte>,
    src: &[crate::types::byte],
) {
    let mut i: usize = 0;
    while i < src.len() && crate::int(i) < dst.Len() {
        dst[i] = src[i];
        i += 1;
    }
}

impl clientHandshakeState {
    // go: sdk 1.25.5 crypto/tls/handshake_client.go:1055-1074 clientHandshakeState.saveSessionTicket
    /// Go: put the ticket the server sent, together with the master
    /// secret it resumes, into the client session cache.
    ///
    /// Deviation: Go calls `c.config.ClientSessionCache.Put` without a
    /// nil check, because `doFullHandshake` only reaches this when the
    /// cache is set. goish's field is an `Option`, so a `None` cache is
    /// a no-op rather than a panic.
    pub(crate) fn saveSessionTicket(&mut self) -> crate::error {
        // Go: if hs.ticket == nil { return nil }
        if self.ticket.Len() == 0 {
            return crate::errors::nil;
        }

        // Go: cacheKey := c.clientSessionCacheKey()
        //     if cacheKey == "" { return nil }
        let cacheKey = self.c.clientSessionCacheKey();
        if cacheKey.Len() == 0 {
            return crate::errors::nil;
        }

        // Go: session := c.sessionState()
        //     session.secret = hs.masterSecret
        //     session.ticket = hs.ticket
        let mut session = self.c.sessionState();
        session.__setSecret(self.masterSecret.clone());
        session.__setTicket(self.ticket.clone());

        // Go: cs := &ClientSessionState{session: session}
        //     c.config.ClientSessionCache.Put(cacheKey, cs)
        //     return nil
        let cs = super::ticket::ClientSessionState::__of(session);
        if let Some(cache) = self.c.__configClientSessionCache() {
            cache.Lock().Put(cacheKey, Some(cs));
        }
        return crate::errors::nil;
    }
}

impl Conn {
    // go: sdk 1.25.5 crypto/tls/handshake_client.go:1112-1209 Conn.verifyServerCertificate
    /// Go: parse the server's chain, verify it against the configured
    /// roots unless verification was waived, and run the two config
    /// callbacks.
    pub(crate) fn verifyServerCertificate(
        &mut self,
        certificates: crate::goslice::slice<crate::goslice::slice<crate::types::byte>>,
    ) -> crate::error {
        use crate::crypto::x509;
        // Go: certs := make([]*x509.Certificate, len(certificates))
        //     for i, asn1Data := range certificates { … }
        let mut certs: alloc::vec::Vec<x509::Certificate> = alloc::vec::Vec::new();
        for (_, asn1Data) in crate::range!(certificates) {
            // Go: cert, err := globalCertCache.newCert(asn1Data)
            //     if err != nil { c.sendAlert(alertDecodeError)
            //         return errors.New("tls: failed to parse certificate from server: " + err.Error()) }
            let (cert, err) = super::cache::globalCertCache.newCert(asn1Data.clone());
            if err != crate::errors::nil {
                self.sendAlert(super::alert::alertDecodeError);
                return crate::fmt::Errorf!(
                    "tls: failed to parse certificate from server: %s",
                    err.Error()
                );
            }
            let cert = cert.unwrap();
            // Go: if cert.PublicKeyAlgorithm == x509.RSA {
            //         n := cert.PublicKey.(*rsa.PublicKey).N.BitLen()
            //         if max, ok := checkKeySize(n); !ok {
            //             c.sendAlert(alertBadCertificate)
            //             return fmt.Errorf("tls: server sent certificate containing RSA key larger than %d bits", max) } }
            if cert.PublicKeyAlgorithm == x509::RSA {
                let n = rsaPublicKeyBitLen(&cert);
                let (max, ok) = checkKeySize(n);
                if !ok {
                    self.sendAlert(super::alert::alertBadCertificate);
                    return crate::fmt::Errorf!(
                        "tls: server sent certificate containing RSA key larger than %d bits",
                        max
                    );
                }
            }
            certs.push(cert);
        }
        let certs: crate::goslice::slice<x509::Certificate> =
            crate::goslice::slice::__from_vec(certs);

        // Go: echRejected := c.config.EncryptedClientHelloConfigList != nil && !c.echAccepted
        let echRejected =
            self.config.EncryptedClientHelloConfigList.Len() > 0 && !self.echAccepted;

        // Go: if echRejected { … } else if !c.config.InsecureSkipVerify { … }
        //
        // The two arms differ only in the DNSName they verify against
        // (c.serverName vs c.config.ServerName) and in the ECH arm's
        // chance to hand the whole job to the rejection callback.
        if echRejected {
            // Go: if c.config.EncryptedClientHelloRejectionVerify != nil { … }
            if let Some(f) = self.config.EncryptedClientHelloRejectionVerify.clone() {
                let st = self.connectionStateLocked();
                let err = f(st);
                if err != crate::errors::nil {
                    self.sendAlert(super::alert::alertBadCertificate);
                    return err;
                }
            } else {
                let err = self.verifyChainAgainstRoots(&certs, self.serverName.clone());
                if err != crate::errors::nil {
                    return err;
                }
            }
        } else if !self.config.InsecureSkipVerify {
            let err = self.verifyChainAgainstRoots(&certs, self.config.ServerName.clone());
            if err != crate::errors::nil {
                return err;
            }
        }

        // Go: switch certs[0].PublicKey.(type) {
        //     case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey: break
        //     default: c.sendAlert(alertUnsupportedCertificate)
        //         return fmt.Errorf("tls: server's certificate contains an unsupported type of public key: %T", …) }
        if !supportedPublicKey(&certs[0]) {
            self.sendAlert(super::alert::alertUnsupportedCertificate);
            return crate::fmt::Errorf!(
                "tls: server's certificate contains an unsupported type of public key: %s",
                publicKeyTypeName(&certs[0])
            );
        }

        // Go: c.peerCertificates = certs
        self.peerCertificates = certs;

        // Go: if c.config.VerifyPeerCertificate != nil && !echRejected {
        //         if err := c.config.VerifyPeerCertificate(certificates, c.verifiedChains); err != nil {
        //             c.sendAlert(alertBadCertificate); return err } }
        if !echRejected {
            if let Some(f) = self.config.VerifyPeerCertificate.clone() {
                let err = f(certificates.clone(), self.verifiedChains.clone());
                if err != crate::errors::nil {
                    self.sendAlert(super::alert::alertBadCertificate);
                    return err;
                }
            }
        }

        // Go: if c.config.VerifyConnection != nil && !echRejected {
        //         if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
        //             c.sendAlert(alertBadCertificate); return err } }
        if !echRejected {
            if let Some(f) = self.config.VerifyConnection.clone() {
                let st = self.connectionStateLocked();
                let err = f(st);
                if err != crate::errors::nil {
                    self.sendAlert(super::alert::alertBadCertificate);
                    return err;
                }
            }
        }

        // Go: return nil
        return crate::errors::nil;
    }

    // go: none — goish-only: Go spells this block out twice inside
    // `verifyServerCertificate`, once per arm of the ECH test, differing
    // only in the DNSName. Naming it once keeps both arms verbatim.
    fn verifyChainAgainstRoots(
        &mut self,
        certs: &crate::goslice::slice<crate::crypto::x509::Certificate>,
        dnsName: crate::gostring::string,
    ) -> crate::error {
        use crate::crypto::x509;
        // Go: opts := x509.VerifyOptions{Roots: c.config.RootCAs,
        //         CurrentTime: c.config.time(), DNSName: …,
        //         Intermediates: x509.NewCertPool()}
        //     for _, cert := range certs[1:] { opts.Intermediates.AddCert(cert) }
        let mut intermediates = x509::NewCertPool();
        let mut i: crate::types::int = 1;
        while i < certs.Len() {
            intermediates.AddCert(certs[i as usize].clone());
            i += 1;
        }
        let opts = x509::VerifyOptions {
            Roots: self.config.RootCAs.clone(),
            CurrentTime: self.config.time(),
            DNSName: dnsName,
            Intermediates: Some(intermediates),
            ..x509::VerifyOptions::default()
        };

        // Go: chains, err := certs[0].Verify(opts)
        //     if err != nil { c.sendAlert(alertBadCertificate)
        //         return &CertificateVerificationError{UnverifiedCertificates: certs, Err: err} }
        let (chains, err) = certs[0].Verify(opts);
        if err != crate::errors::nil {
            self.sendAlert(super::alert::alertBadCertificate);
            return super::common::CertificateVerificationError {
                UnverifiedCertificates: certs.clone(),
                Err: err,
            }
            .into();
        }

        // Go: c.verifiedChains, err = fipsAllowedChains(chains)
        //     if err != nil { c.sendAlert(alertBadCertificate)
        //         return &CertificateVerificationError{UnverifiedCertificates: certs, Err: err} }
        let (allowed, err) = super::common::fipsAllowedChains(chains);
        if err != crate::errors::nil {
            self.sendAlert(super::alert::alertBadCertificate);
            return super::common::CertificateVerificationError {
                UnverifiedCertificates: certs.clone(),
                Err: err,
            }
            .into();
        }
        self.verifiedChains = allowed;
        return crate::errors::nil;
    }
}

// go: none — goish-only: Go writes `cert.PublicKey.(*rsa.PublicKey).N.BitLen()`,
// a type assertion guarded by `PublicKeyAlgorithm == x509.RSA`.
fn rsaPublicKeyBitLen(cert: &crate::crypto::x509::Certificate) -> crate::types::int {
    match cert.PublicKey.As::<crate::crypto::rsa::PublicKey>() {
        Some(k) => return k.N.BitLen(),
        None => return 0,
    };
}

// go: none — goish-only: stands in for Go's type switch over
// `*rsa.PublicKey`, `*ecdsa.PublicKey` and `ed25519.PublicKey`.
fn supportedPublicKey(cert: &crate::crypto::x509::Certificate) -> bool {
    return cert.PublicKey.As::<crate::crypto::rsa::PublicKey>().is_some()
        || cert
            .PublicKey
            .As::<crate::crypto::ecdsa::PublicKey>()
            .is_some()
        || cert
            .PublicKey
            .As::<crate::crypto::ed25519::PublicKey>()
            .is_some();
}

// go: none — goish-only: stands in for Go's `%T` on the public key.
pub(crate) fn publicKeyTypeName(cert: &crate::crypto::x509::Certificate) -> crate::gostring::string {
    match cert.PublicKeyAlgorithm {
        crate::crypto::x509::RSA => return crate::gostring::string::from_static("*rsa.PublicKey"),
        crate::crypto::x509::ECDSA => {
            return crate::gostring::string::from_static("*ecdsa.PublicKey")
        }
        crate::crypto::x509::Ed25519 => {
            return crate::gostring::string::from_static("ed25519.PublicKey")
        }
        _ => return crate::gostring::string::from_static("<unknown>"),
    };
}

// Go: handshake_client.go:241-251
//   type echClientContext struct {
//       config *echConfig; hpkeContext *hpke.Sender
//       encapsulatedKey []byte; innerHello *clientHelloMsg
//       innerTranscript hash.Hash; kdfID, aeadID uint16
//       echRejected bool; retryConfigs []byte }
/// The client's Encrypted Client Hello state.
///
/// Deviation: `hpkeContext` and `innerTranscript` are not `Clone`
/// (an HPKE sender and a live hash are single-use), so this record is
/// not `Clone`; the methods that need it thread `&mut`.
#[derive(Default)]
pub(crate) struct echClientContext {
    pub config: Option<super::ech::echConfig>,
    pub hpkeContext: Option<crate::crypto::internal::hpke::Sender>,
    pub encapsulatedKey: crate::goslice::slice<crate::types::byte>,
    pub innerHello: Option<super::handshake_messages::clientHelloMsg>,
    pub innerTranscript:
        Option<alloc::boxed::Box<dyn crate::hash::Hash + Send + Sync>>,
    pub kdfID: crate::types::uint16,
    pub aeadID: crate::types::uint16,
    pub echRejected: bool,
    pub retryConfigs: crate::goslice::slice<crate::types::byte>,
}

// go: sdk 1.25.5 crypto/tls/handshake_client.go:1325-1333 computeAndUpdatePSK
/// Go: hash the hello up to (but not including) the PSK binders, derive
/// the binder from `binderKey` over that transcript, and write it back
/// into the message.
///
/// Deviation: Go's `finishedHash func([]byte, hash.Hash) []byte` is a
/// method value (`hs.suite.finishedHash`); goish passes the same thing
/// as a borrowed closure, since `cipherSuiteTLS13::finishedHash` takes
/// `&self` and cannot be detached from its suite.
pub(crate) fn computeAndUpdatePSK(
    m: &mut super::handshake_messages::clientHelloMsg,
    binderKey: crate::goslice::slice<crate::types::byte>,
    transcript: &mut super::handshake_messages::transcriptHasher,
    finishedHash: &dyn Fn(
        crate::goslice::slice<crate::types::byte>,
        &(dyn crate::hash::Hash + Send + Sync + 'static),
    ) -> crate::goslice::slice<crate::types::byte>,
) -> crate::error {
    // Go: helloBytes, err := m.marshalWithoutBinders()
    //     if err != nil { return err }
    let (helloBytes, err) = m.marshalWithoutBinders();
    if err != crate::errors::nil {
        return err;
    }
    // Go: transcript.Write(helloBytes)
    crate::io::Writer::Write(transcript, helloBytes);
    // Go: pskBinders := [][]byte{finishedHash(binderKey, transcript)}
    let pskBinders = crate::goslice::slice::__from_vec(alloc::vec![finishedHash(
        binderKey,
        &*transcript.0
    )]);
    // Go: return m.updateBinders(pskBinders)
    return m.updateBinders(pskBinders);
}

impl Conn {
    // go: sdk 1.25.5 crypto/tls/handshake_client.go:44-238 Conn.makeClientHello
    /// Go: build the initial ClientHello from the config — versions,
    /// cipher suites, curves, signature algorithms, the TLS 1.3 key
    /// shares (including the hybrid X25519MLKEM768), and, when a config
    /// list is set, the Encrypted Client Hello outer state.
    ///
    /// Deviation: the `c.quic != nil` arm is absent — goish ships no
    /// QUIC transport — so the session ID is always set and no transport
    /// parameters are attached.
    pub(crate) fn makeClientHello(
        &mut self,
    ) -> (
        Option<super::handshake_messages::clientHelloMsg>,
        Option<super::key_schedule::keySharePrivateKeys>,
        Option<super::handshake_client::echClientContext>,
        crate::error,
    ) {
        use crate::goslice::slice;
        let config = self.config.clone();
        // Go: if len(config.ServerName) == 0 && !config.InsecureSkipVerify {
        //         return nil, nil, nil, errors.New("tls: either ServerName or InsecureSkipVerify must be specified in the tls.Config") }
        if config.ServerName.Len() == 0 && !config.InsecureSkipVerify {
            return (
                None,
                None,
                None,
                crate::errors::New(
                    "tls: either ServerName or InsecureSkipVerify must be specified in the tls.Config",
                ),
            );
        }

        // Go: nextProtosLength := 0
        //     for _, proto := range config.NextProtos {
        //         if l := len(proto); l == 0 || l > 255 { return … "tls: invalid NextProtos value" }
        //         else { nextProtosLength += 1 + l } }
        //     if nextProtosLength > 0xffff { return … "tls: NextProtos values too large" }
        let mut nextProtosLength: crate::types::int = 0;
        for proto in config.NextProtos.iter() {
            let l = proto.Len();
            if l == 0 || l > 255 {
                return (None, None, None, crate::errors::New("tls: invalid NextProtos value"));
            }
            nextProtosLength += 1 + l;
        }
        if nextProtosLength > 0xffff {
            return (None, None, None, crate::errors::New("tls: NextProtos values too large"));
        }

        // Go: supportedVersions := config.supportedVersions(roleClient)
        //     if len(supportedVersions) == 0 { return … "tls: no supported versions satisfy MinVersion and MaxVersion" }
        let supportedVersions = config.supportedVersions(super::common::roleClient);
        if supportedVersions.Len() == 0 {
            return (
                None,
                None,
                None,
                crate::errors::New(
                    "tls: no supported versions satisfy MinVersion and MaxVersion",
                ),
            );
        }
        // Go: maxVersion := supportedVersions[0]
        //     minVersion := supportedVersions[len(supportedVersions)-1]
        let maxVersion = supportedVersions[0];
        let minVersion = supportedVersions[supportedVersions.Len() - 1];

        // Go: hello := &clientHelloMsg{ … }
        let mut hello = super::handshake_messages::clientHelloMsg::default();
        hello.vers = maxVersion;
        hello.compressionMethods = alloc::vec![super::common::compressionNone];
        hello.random = alloc::vec![0u8; 32];
        hello.extendedMasterSecret = true;
        hello.ocspStapling = true;
        hello.scts = true;
        hello.serverName = core::str::from_utf8(
            super::handshake_client::hostnameInSNI(config.ServerName.clone()).as_bytes(),
        )
        .map(|s| s.into())
        .unwrap_or_default();
        hello.supportedCurves = config
            .curvePreferences(maxVersion)
            .iter()
            .map(|c| c.0)
            .collect();
        hello.supportedPoints = alloc::vec![super::common::pointFormatUncompressed];
        hello.secureRenegotiationSupported = true;
        hello.alpnProtocols = config
            .NextProtos
            .iter()
            .map(|p| {
                core::str::from_utf8(p.as_bytes())
                    .map(|s| s.into())
                    .unwrap_or_default()
            })
            .collect();
        hello.supportedVersions = supportedVersions.iter().cloned().collect();

        // Go: if hello.vers > VersionTLS12 { hello.vers = VersionTLS12 }
        if hello.vers > super::common::VersionTLS12 {
            hello.vers = super::common::VersionTLS12;
        }

        // Go: if c.handshakes > 0 { hello.secureRenegotiation = c.clientFinished[:] }
        if self.handshakes > 0 {
            hello.secureRenegotiation = self.clientFinished.to_vec();
        }

        // Go: hello.cipherSuites = config.cipherSuites(hasAESGCMHardwareSupport)
        //     if maxVersion < VersionTLS12 {
        //         hello.cipherSuites = slices.DeleteFunc(hello.cipherSuites, func(id uint16) bool {
        //             return cipherSuiteByID(id).flags&suiteTLS12 != 0 }) }
        let mut cipherSuites =
            config.cipherSuites(super::cipher_suites::hasAESGCMHardwareSupport);
        if maxVersion < super::common::VersionTLS12 {
            cipherSuites = crate::slices::DeleteFunc(cipherSuites, |id: &crate::types::uint16| {
                match super::cipher_suites::cipherSuiteByID(*id) {
                    Some(cs) => cs.flags & super::cipher_suites::suiteTLS12 != 0,
                    None => false,
                }
            });
        }
        hello.cipherSuites = cipherSuites.iter().cloned().collect();

        // Go: _, err := io.ReadFull(config.rand(), hello.random)
        //     if err != nil { return … "tls: short read from Rand: " + err.Error() }
        {
            let mut buf: slice<byte> = slice::__from_vec(hello.random.clone());
            let mut r = config.rand();
            let (_, err) = crate::io::ReadFull(&mut *r, &mut buf);
            if err != crate::errors::nil {
                return (
                    None,
                    None,
                    None,
                    crate::fmt::Errorf!("tls: short read from Rand: %s", err.Error()),
                );
            }
            hello.random = buf.__into_vec();
        }

        // Go: (no QUIC) if c.quic == nil {
        //         hello.sessionId = make([]byte, 32)
        //         if _, err := io.ReadFull(config.rand(), hello.sessionId); err != nil {
        //             return … "tls: short read from Rand: " + err.Error() } }
        {
            let mut buf: slice<byte> = slice::__from_vec(alloc::vec![0u8; 32]);
            let mut r = config.rand();
            let (_, err) = crate::io::ReadFull(&mut *r, &mut buf);
            if err != crate::errors::nil {
                return (
                    None,
                    None,
                    None,
                    crate::fmt::Errorf!("tls: short read from Rand: %s", err.Error()),
                );
            }
            hello.sessionId = buf.__into_vec();
        }

        // Go: if maxVersion >= VersionTLS12 {
        //         hello.supportedSignatureAlgorithms = supportedSignatureAlgorithms(minVersion)
        //         hello.supportedSignatureAlgorithmsCert = supportedSignatureAlgorithmsCert() }
        if maxVersion >= super::common::VersionTLS12 {
            hello.supportedSignatureAlgorithms =
                super::common::supportedSignatureAlgorithms(minVersion)
                    .iter()
                    .map(|s| s.0)
                    .collect();
            hello.supportedSignatureAlgorithmsCert =
                super::common::supportedSignatureAlgorithmsCert()
                    .iter()
                    .map(|s| s.0)
                    .collect();
        }

        // Go: var keyShareKeys *keySharePrivateKeys
        //     if maxVersion >= VersionTLS13 { … }
        let mut keyShareKeys: Option<super::key_schedule::keySharePrivateKeys> = None;
        if maxVersion >= super::common::VersionTLS13 {
            // Go: if minVersion >= VersionTLS13 { hello.cipherSuites = nil }
            if minVersion >= super::common::VersionTLS13 {
                hello.cipherSuites = alloc::vec::Vec::new();
            }
            // Go: if fips140tls.Required() { …FIPS… }
            //     else if hasAESGCMHardwareSupport { …defaultCipherSuitesTLS13… }
            //     else { …NoAES… }
            if super::internal::fips140tls::Required() {
                hello
                    .cipherSuites
                    .extend_from_slice(super::defaults_fips140::allowedCipherSuitesTLS13FIPS);
            } else if super::cipher_suites::hasAESGCMHardwareSupport {
                hello
                    .cipherSuites
                    .extend_from_slice(super::defaults::defaultCipherSuitesTLS13);
            } else {
                hello
                    .cipherSuites
                    .extend_from_slice(super::defaults::defaultCipherSuitesTLS13NoAES);
            }

            // Go: if len(hello.supportedCurves) == 0 { return … "tls: no supported elliptic curves for ECDHE" }
            if hello.supportedCurves.is_empty() {
                return (
                    None,
                    None,
                    None,
                    crate::errors::New("tls: no supported elliptic curves for ECDHE"),
                );
            }
            // Go: curveID := hello.supportedCurves[0]
            //     keyShareKeys = &keySharePrivateKeys{curveID: curveID}
            let curveID = super::common::CurveID(hello.supportedCurves[0]);
            let mut ksk = super::key_schedule::keySharePrivateKeys {
                curveID,
                ecdhe: None,
                mlkem: None,
            };
            // Go: if curveID == X25519MLKEM768 { … } else { … }
            if curveID == super::common::X25519MLKEM768 {
                // Go: keyShareKeys.ecdhe, err = generateECDHEKey(config.rand(), X25519)
                let (ecdhe, err) = {
                    let mut r = config.rand();
                    super::key_schedule::generateECDHEKey(&mut *r, super::common::X25519)
                };
                if err != crate::errors::nil {
                    return (None, None, None, err);
                }
                ksk.ecdhe = ecdhe;
                // Go: seed := make([]byte, mlkem.SeedSize)
                //     if _, err := io.ReadFull(config.rand(), seed); err != nil { return … }
                let mut seed: slice<byte> = slice::__from_vec(alloc::vec![
                    0u8;
                    crate::crypto::internal::fips140::mlkem::SeedSize
                ]);
                {
                    let mut r = config.rand();
                    let (_, err) = crate::io::ReadFull(&mut *r, &mut seed);
                    if err != crate::errors::nil {
                        return (None, None, None, err);
                    }
                }
                // Go: keyShareKeys.mlkem, err = mlkem.NewDecapsulationKey768(seed)
                let (mlkemKey, err) =
                    crate::crypto::internal::fips140::mlkem::NewDecapsulationKey768(seed);
                if err != crate::errors::nil {
                    return (None, None, None, err);
                }
                let mlkemKey = *mlkemKey;
                // Go: mlkemEncapsulationKey := keyShareKeys.mlkem.EncapsulationKey().Bytes()
                //     x25519EphemeralKey := keyShareKeys.ecdhe.PublicKey().Bytes()
                let mlkemEncapsulationKey = mlkemKey.EncapsulationKey().Bytes();
                let x25519EphemeralKey =
                    ksk.ecdhe.as_ref().unwrap().PublicKey().Bytes();
                ksk.mlkem = Some(mlkemKey);
                // Go: hello.keyShares = []keyShare{{group: X25519MLKEM768, data: append(mlkemEncapsulationKey, x25519EphemeralKey...)}}
                let mut combined = mlkemEncapsulationKey.__into_vec();
                {
                    let raw: &[byte] = &x25519EphemeralKey;
                    combined.extend_from_slice(raw);
                }
                hello.keyShares = alloc::vec![super::handshake_messages::keyShare {
                    group: super::common::X25519MLKEM768.0,
                    data: combined,
                }];
                // Go: if slices.Contains(hello.supportedCurves, X25519) {
                //         hello.keyShares = append(hello.keyShares, keyShare{group: X25519, data: x25519EphemeralKey}) }
                if hello.supportedCurves.contains(&super::common::X25519.0) {
                    hello.keyShares.push(super::handshake_messages::keyShare {
                        group: super::common::X25519.0,
                        data: x25519EphemeralKey.__into_vec(),
                    });
                }
            } else {
                // Go: if _, ok := curveForCurveID(curveID); !ok { return … "tls: CurvePreferences includes unsupported curve" }
                let (_, ok) = super::key_schedule::curveForCurveID(curveID);
                if !ok {
                    return (
                        None,
                        None,
                        None,
                        crate::errors::New(
                            "tls: CurvePreferences includes unsupported curve",
                        ),
                    );
                }
                // Go: keyShareKeys.ecdhe, err = generateECDHEKey(config.rand(), curveID)
                let (ecdhe, err) = {
                    let mut r = config.rand();
                    super::key_schedule::generateECDHEKey(&mut *r, curveID)
                };
                if err != crate::errors::nil {
                    return (None, None, None, err);
                }
                ksk.ecdhe = ecdhe;
                // Go: hello.keyShares = []keyShare{{group: curveID, data: keyShareKeys.ecdhe.PublicKey().Bytes()}}
                hello.keyShares = alloc::vec![super::handshake_messages::keyShare {
                    group: curveID.0,
                    data: ksk.ecdhe.as_ref().unwrap().PublicKey().Bytes().__into_vec(),
                }];
            }
            keyShareKeys = Some(ksk);
        }

        // Go: var ech *echClientContext
        //     if c.config.EncryptedClientHelloConfigList != nil { … }
        let mut ech: Option<super::handshake_client::echClientContext> = None;
        if self.config.EncryptedClientHelloConfigList.Len() != 0 {
            // Go: if c.config.MinVersion != 0 && c.config.MinVersion < VersionTLS13 { return … }
            if self.config.MinVersion != 0
                && self.config.MinVersion < super::common::VersionTLS13
            {
                return (
                    None,
                    None,
                    None,
                    crate::errors::New(
                        "tls: MinVersion must be >= VersionTLS13 if EncryptedClientHelloConfigList is populated",
                    ),
                );
            }
            // Go: if c.config.MaxVersion != 0 && c.config.MaxVersion <= VersionTLS12 { return … }
            if self.config.MaxVersion != 0
                && self.config.MaxVersion <= super::common::VersionTLS12
            {
                return (
                    None,
                    None,
                    None,
                    crate::errors::New(
                        "tls: MaxVersion must be >= VersionTLS13 if EncryptedClientHelloConfigList is populated",
                    ),
                );
            }
            // Go: echConfigs, err := parseECHConfigList(c.config.EncryptedClientHelloConfigList)
            //     if err != nil { return … }
            let (echConfigs, err) = super::ech::parseECHConfigList(
                self.config.EncryptedClientHelloConfigList.clone(),
            );
            if err != crate::errors::nil {
                return (None, None, None, err);
            }
            // Go: echConfig := pickECHConfig(echConfigs)
            //     if echConfig == nil { return … "tls: EncryptedClientHelloConfigList contains no valid configs" }
            let echConfig = super::ech::pickECHConfig(echConfigs);
            let echConfig = match echConfig {
                None => {
                    return (
                        None,
                        None,
                        None,
                        crate::errors::New(
                            "tls: EncryptedClientHelloConfigList contains no valid configs",
                        ),
                    )
                }
                Some(cfg) => cfg,
            };
            // Go: ech = &echClientContext{config: echConfig}
            //     hello.encryptedClientHello = []byte{1}
            //     hello.supportedPoints = nil; hello.ticketSupported = false
            //     hello.secureRenegotiationSupported = false; hello.extendedMasterSecret = false
            let mut echCtx = super::handshake_client::echClientContext::default();
            hello.encryptedClientHello = alloc::vec![1u8];
            hello.supportedPoints = alloc::vec::Vec::new();
            hello.ticketSupported = false;
            hello.secureRenegotiationSupported = false;
            hello.extendedMasterSecret = false;
            // Go: echPK, err := hpke.ParseHPKEPublicKey(ech.config.KemID, ech.config.PublicKey)
            let (echPK, err) = crate::crypto::internal::hpke::ParseHPKEPublicKey(
                echConfig.KemID,
                &echConfig.PublicKey,
            );
            if err != crate::errors::nil {
                return (None, None, None, err);
            }
            // Go: suite, err := pickECHCipherSuite(ech.config.SymmetricCipherSuite)
            let (suite, err) =
                super::ech::pickECHCipherSuite(echConfig.SymmetricCipherSuite.clone());
            if err != crate::errors::nil {
                return (None, None, None, err);
            }
            // Go: ech.kdfID, ech.aeadID = suite.KDFID, suite.AEADID
            echCtx.kdfID = suite.KDFID;
            echCtx.aeadID = suite.AEADID;
            // Go: info := append([]byte("tls ech\x00"), ech.config.raw...)
            let info = {
                let mut v: alloc::vec::Vec<byte> = b"tls ech\x00".to_vec();
                let raw: &[byte] = &echConfig.raw;
                v.extend_from_slice(raw);
                slice::__from_vec(v)
            };
            // Go: ech.encapsulatedKey, ech.hpkeContext, err = hpke.SetupSender(ech.config.KemID, suite.KDFID, suite.AEADID, echPK, info)
            let (encapKey, hpkeCtx, err) = crate::crypto::internal::hpke::SetupSender(
                echConfig.KemID,
                suite.KDFID,
                suite.AEADID,
                &echPK,
                &info,
            );
            if err != crate::errors::nil {
                return (None, None, None, err);
            }
            echCtx.encapsulatedKey = encapKey;
            echCtx.hpkeContext = hpkeCtx;
            echCtx.config = Some(echConfig);
            ech = Some(echCtx);
        }

        // Go: return hello, keyShareKeys, ech, nil
        return (Some(hello), keyShareKeys, ech, crate::errors::nil);
    }
}

impl Conn {
    // go: sdk 1.25.5 crypto/tls/handshake_client.go:253-378 Conn.clientHandshake
    /// Go: the client handshake entry point — build and send the
    /// ClientHello (splitting it for ECH), read the ServerHello, check
    /// the downgrade canaries, and hand off to the TLS 1.3 or TLS 1.0–1.2
    /// driver. A failed resumption drops the session ticket (RFC 5077,
    /// Section 3.2).
    ///
    /// Deviations: Go's `ctx context.Context` parameter has no field to
    /// land in; the `hello.earlyData` block is absent — early data is
    /// only ever offered over QUIC, which goish does not ship.
    /// goishlint:ignore GOISH020 clientHandshake — Go's context.Context parameter has no field to land in
    pub(crate) fn clientHandshake(&mut self) -> crate::error {
        // Go: if c.config == nil { c.config = defaultConfig() }
        //
        // goish: Conn.config is a value, not a pointer, and Go's
        // defaultConfig() is the zero Config (`&emptyConfig`), so the
        // normalization is already the field's resting state.

        // Go: "This may be a renegotiation handshake, in which case some
        // fields need to be reset."
        //     c.didResume = false
        //     c.curveID = 0
        self.didResume = false;
        self.curveID = super::common::CurveID(0);

        // Go: hello, keyShareKeys, ech, err := c.makeClientHello()
        //     if err != nil { return err }
        let (hello, keyShareKeys, ech, err) = self.makeClientHello();
        if err != crate::errors::nil {
            return err;
        }
        let mut hello = hello.unwrap();
        let mut ech = ech;

        // Go: session, earlySecret, binderKey, err := c.loadSession(hello)
        //     if err != nil { return err }
        let (session, earlySecret, binderKey, err) = self.loadSession(&mut hello);
        if err != crate::errors::nil {
            return err;
        }

        // Go: if session != nil { defer func() { if err != nil {
        //         if cacheKey := c.clientSessionCacheKey(); cacheKey != "" {
        //             c.config.ClientSessionCache.Put(cacheKey, nil) } } }() }
        //
        // goish: the deferred drop runs after the immediately-invoked
        // tail below, which stands in for the rest of the Go function
        // body so every error return passes through it.
        let hadSession = session.is_some();
        let err = (|| -> crate::error {
            // Go: if ech != nil {
            if ech.is_some() {
                let echCtx = ech.as_mut().unwrap();
                // Go: "Split hello into inner and outer"
                //     ech.innerHello = hello.clone()
                echCtx.innerHello = Some(hello.clone());

                // Go: "Overwrite the server name in the outer hello with
                // the public facing name."
                //     hello.serverName = string(ech.config.PublicName)
                hello.serverName =
                    core::str::from_utf8(&echCtx.config.as_ref().unwrap().PublicName)
                        .map(|s| s.into())
                        .unwrap_or_default();
                // Go: "Generate a new random for the outer hello."
                //     hello.random = make([]byte, 32)
                //     _, err = io.ReadFull(c.config.rand(), hello.random)
                //     if err != nil { return errors.New("tls: short read from Rand: " + err.Error()) }
                hello.random = alloc::vec![0u8; 32];
                let err = {
                    let mut r = self.config.rand();
                    let mut buf =
                        crate::goslice::slice::__from_vec(hello.random.clone());
                    let (_, err) = crate::io::ReadFull(&mut *r, &mut buf);
                    let raw: &[crate::types::byte] = &buf;
                    hello.random.copy_from_slice(raw);
                    err
                };
                if err != crate::errors::nil {
                    return crate::fmt::Errorf!(
                        "tls: short read from Rand: %s",
                        err.Error()
                    );
                }

                // Go: "NOTE: we don't do PSK GREASE, in line with
                // boringssl […]"
                //     if err := computeAndUpdateOuterECHExtension(hello, ech.innerHello, ech, true); err != nil {
                //         return err }
                let inner = echCtx.innerHello.clone().unwrap();
                let err = super::ech::computeAndUpdateOuterECHExtension(
                    &mut hello,
                    &inner,
                    echCtx,
                    true,
                );
                if err != crate::errors::nil {
                    return err;
                }
            }

            // Go: c.serverName = hello.serverName
            self.serverName =
                crate::gostring::string::from_bytes(hello.serverName.as_bytes());

            // Go: if _, err := c.writeHandshakeRecord(hello, nil); err != nil { return err }
            let (_, err) = self.writeHandshakeRecord(&hello, None);
            if err != crate::errors::nil {
                return err;
            }

            // Go: the `if hello.earlyData` block is absent — early data
            // is only ever offered over QUIC, which goish does not ship.

            // Go: "serverHelloMsg is not included in the transcript"
            //     msg, err := c.readHandshake(nil)
            //     if err != nil { return err }
            let (msg, err) = self.readHandshake(None);
            if err != crate::errors::nil {
                return err;
            }
            let msg = match msg {
                Some(m) => m,
                None => {
                    return crate::errors::New("tls: internal error: no handshake message")
                }
            };

            // Go: serverHello, ok := msg.(*serverHelloMsg)
            //     if !ok { c.sendAlert(alertUnexpectedMessage)
            //         return unexpectedMessageError(serverHello, msg) }
            let serverHello = match msg
                .asAny()
                .downcast_ref::<super::handshake_messages::serverHelloMsg>()
            {
                Some(sh) => sh.clone(),
                None => {
                    self.sendAlert(super::alert::alertUnexpectedMessage);
                    return super::common::unexpectedMessageError(
                        crate::gostring::string::from_static("*tls.serverHelloMsg"),
                        super::handshake_messages::handshakeMessageTypeName(&*msg),
                    );
                }
            };

            // Go: if err := c.pickTLSVersion(serverHello); err != nil { return err }
            let err = self.pickTLSVersion(&serverHello);
            if err != crate::errors::nil {
                return err;
            }

            // Go: "If we are negotiating a protocol version that's lower
            // than what we support, check for the server downgrade
            // canaries. See RFC 8446, Section 4.1.3."
            //     maxVers := c.config.maxSupportedVersion(roleClient)
            //     tls12Downgrade := string(serverHello.random[24:]) == downgradeCanaryTLS12
            //     tls11Downgrade := string(serverHello.random[24:]) == downgradeCanaryTLS11
            //     if maxVers == VersionTLS13 && c.vers <= VersionTLS12 && (tls12Downgrade || tls11Downgrade) ||
            //         maxVers == VersionTLS12 && c.vers <= VersionTLS11 && tls11Downgrade {
            //         c.sendAlert(alertIllegalParameter)
            //         return errors.New("tls: downgrade attempt detected, possibly due to a MitM attack or a broken middlebox") }
            let maxVers = self.config.maxSupportedVersion(super::common::roleClient);
            let tls12Downgrade =
                &serverHello.random[24..] == super::common::downgradeCanaryTLS12;
            let tls11Downgrade =
                &serverHello.random[24..] == super::common::downgradeCanaryTLS11;
            if maxVers == super::common::VersionTLS13
                && self.vers <= super::common::VersionTLS12
                && (tls12Downgrade || tls11Downgrade)
                || maxVers == super::common::VersionTLS12
                    && self.vers <= super::common::VersionTLS11
                    && tls11Downgrade
            {
                self.sendAlert(super::alert::alertIllegalParameter);
                return crate::errors::New(
                    "tls: downgrade attempt detected, possibly due to a MitM attack or a broken middlebox",
                );
            }

            // Go: if c.vers == VersionTLS13 {
            //         hs := &clientHandshakeStateTLS13{ c: c, ctx: ctx,
            //             serverHello: serverHello, hello: hello,
            //             keyShareKeys: keyShareKeys, session: session,
            //             earlySecret: earlySecret, binderKey: binderKey,
            //             echContext: ech }
            //         return hs.handshake() }
            if self.vers == super::common::VersionTLS13 {
                let mut hs = super::handshake_client_tls13::clientHandshakeStateTLS13 {
                    c: core::mem::take(self),
                    serverHello,
                    hello,
                    keyShareKeys,
                    session,
                    earlySecret,
                    binderKey,
                    usingPSK: false,
                    sentDummyCCS: false,
                    suite: None,
                    transcript: None,
                    masterSecret: None,
                    trafficSecret: crate::goslice::slice::new(),
                    echContext: ech,
                    certReq: None,
                };
                let err = hs.handshake();
                *self = hs.c;
                return err;
            }

            // Go: hs := &clientHandshakeState{ c: c, ctx: ctx,
            //         serverHello: serverHello, hello: hello, session: session }
            //     return hs.handshake()
            let mut hs = super::handshake_client::clientHandshakeState {
                c: core::mem::take(self),
                serverHello,
                hello,
                suite: None,
                // goish: `finishedHash` has no zero value (it holds live
                // hashes); hs.handshake() replaces it via
                // newFinishedHash before first use.
                finishedHash: super::prf::newFinishedHash(
                    super::common::VersionTLS12,
                    super::cipher_suites::cipherSuiteByID(
                        super::cipher_suites::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    )
                    .unwrap(),
                ),
                masterSecret: crate::goslice::slice::new(),
                session,
                ticket: crate::goslice::slice::new(),
            };
            let err = hs.handshake();
            *self = hs.c;
            return err;
        })();

        // Go (the deferred func above): "If we got a handshake failure
        // when resuming a session, throw away the session ticket. […] we
        // need to delete tickets to recover from a corrupted PSK."
        if hadSession && err != crate::errors::nil {
            let cacheKey = self.clientSessionCacheKey();
            if cacheKey != crate::gostring::string::from_static("") {
                if let Some(cache) = self.config.ClientSessionCache.as_ref() {
                    cache.Lock().Put(cacheKey, None);
                }
            }
        }
        return err;
    }

    // go: sdk 1.25.5 crypto/tls/handshake_client.go:380-521 Conn.loadSession
    /// Go: if a client session cache is configured, look up a resumable
    /// session for this connection, validate it against the offered
    /// versions, the cached certificate, and the cipher/KDF, and — for
    /// TLS 1.3 — install the pre_shared_key identity and compute its
    /// binder over the ClientHello, returning the early secret and binder
    /// key for the handshake to finish.
    ///
    /// Deviation: the `c.quic != nil` arm (session events and 0-RTT
    /// early data) is absent — goish ships no QUIC transport.
    pub(crate) fn loadSession(
        &mut self,
        hello: &mut super::handshake_messages::clientHelloMsg,
    ) -> (
        Option<super::ticket::SessionState>,
        Option<crate::crypto::internal::fips140::tls13::EarlySecret>,
        crate::goslice::slice<crate::types::byte>,
        crate::error,
    ) {
        use crate::goslice::slice;
        // Go: if c.config.SessionTicketsDisabled || c.config.ClientSessionCache == nil {
        //         return nil, nil, nil, nil }
        if self.config.SessionTicketsDisabled || self.config.ClientSessionCache.is_none() {
            return (None, None, slice::new(), crate::errors::nil);
        }

        // Go: echInner := bytes.Equal(hello.encryptedClientHello, []byte{1})
        //     hello.ticketSupported = true && !echInner
        let echInner = {
            let ech: &[byte] = &hello.encryptedClientHello;
            ech == [1u8]
        };
        hello.ticketSupported = true && !echInner;

        // Go: if hello.supportedVersions[0] == VersionTLS13 {
        //         hello.pskModes = []uint8{pskModeDHE} }
        if hello.supportedVersions[0] == super::common::VersionTLS13 {
            hello.pskModes = alloc::vec![super::common::pskModeDHE];
        }

        // Go: if c.handshakes != 0 { return nil, nil, nil, nil }
        if self.handshakes != 0 {
            return (None, None, slice::new(), crate::errors::nil);
        }

        // Go: cacheKey := c.clientSessionCacheKey()
        //     if cacheKey == "" { return nil, nil, nil, nil }
        let cacheKey = self.clientSessionCacheKey();
        if cacheKey.Len() == 0 {
            return (None, None, slice::new(), crate::errors::nil);
        }
        // Go: cs, ok := c.config.ClientSessionCache.Get(cacheKey)
        //     if !ok || cs == nil { return nil, nil, nil, nil }
        //     session = cs.session
        let cache = self.config.ClientSessionCache.clone().unwrap();
        let (cs, ok) = cache.Lock().Get(cacheKey.clone());
        let cs = match cs {
            Some(cs) if ok => cs,
            _ => return (None, None, slice::new(), crate::errors::nil),
        };
        let session = match cs.session {
            Some(s) => s,
            None => return (None, None, slice::new(), crate::errors::nil),
        };

        // Go: versOk := false
        //     for _, v := range hello.supportedVersions { if v == session.version { versOk = true; break } }
        //     if !versOk { return nil, nil, nil, nil }
        let mut versOk = false;
        for v in hello.supportedVersions.iter() {
            if *v == session.version {
                versOk = true;
                break;
            }
        }
        if !versOk {
            return (None, None, slice::new(), crate::errors::nil);
        }

        // Go: if c.config.time().After(session.peerCertificates[0].NotAfter) {
        //         c.config.ClientSessionCache.Put(cacheKey, nil); return nil, nil, nil, nil }
        if self
            .config
            .time()
            .After(session.peerCertificates[0].NotAfter)
        {
            cache.Lock().Put(cacheKey.clone(), None);
            return (None, None, slice::new(), crate::errors::nil);
        }
        // Go: if !c.config.InsecureSkipVerify {
        //         if len(session.verifiedChains) == 0 { return nil, nil, nil, nil }
        //         if err := session.peerCertificates[0].VerifyHostname(c.config.ServerName); err != nil {
        //             return nil, nil, nil, nil } }
        if !self.config.InsecureSkipVerify {
            if session.verifiedChains.Len() == 0 {
                return (None, None, slice::new(), crate::errors::nil);
            }
            let err = session.peerCertificates[0]
                .VerifyHostname(self.config.ServerName.clone());
            if err != crate::errors::nil {
                return (None, None, slice::new(), crate::errors::nil);
            }
        }

        // Go: if session.version != VersionTLS13 {
        //         if mutualCipherSuite(hello.cipherSuites, session.cipherSuite) == nil { return nil, nil, nil, nil }
        //         if !session.extMasterSecret && fips140tls.Required() { return nil, nil, nil, nil }
        //         hello.sessionTicket = session.ticket
        //         return }
        if session.version != super::common::VersionTLS13 {
            if super::cipher_suites::mutualCipherSuite(
                slice::__from_vec(hello.cipherSuites.clone()),
                session.cipherSuite,
            )
            .is_none()
            {
                return (None, None, slice::new(), crate::errors::nil);
            }
            if !session.extMasterSecret && super::internal::fips140tls::Required() {
                return (None, None, slice::new(), crate::errors::nil);
            }
            hello.sessionTicket = session.ticket.clone().__into_vec();
            return (Some(session), None, slice::new(), crate::errors::nil);
        }

        // Go: if c.config.time().After(time.Unix(int64(session.useBy), 0)) {
        //         c.config.ClientSessionCache.Put(cacheKey, nil); return nil, nil, nil, nil }
        if self
            .config
            .time()
            .After(crate::time::Unix(crate::int64(session.useBy), 0))
        {
            cache.Lock().Put(cacheKey.clone(), None);
            return (None, None, slice::new(), crate::errors::nil);
        }

        // Go: cipherSuite := cipherSuiteTLS13ByID(session.cipherSuite)
        //     if cipherSuite == nil { return nil, nil, nil, nil }
        let cipherSuite =
            super::cipher_suites::cipherSuiteTLS13ByID(session.cipherSuite);
        let cipherSuite = match cipherSuite {
            Some(cs) => cs,
            None => return (None, None, slice::new(), crate::errors::nil),
        };
        // Go: cipherSuiteOk := false
        //     for _, offeredID := range hello.cipherSuites {
        //         offeredSuite := cipherSuiteTLS13ByID(offeredID)
        //         if offeredSuite != nil && offeredSuite.hash == cipherSuite.hash { cipherSuiteOk = true; break } }
        //     if !cipherSuiteOk { return nil, nil, nil, nil }
        let mut cipherSuiteOk = false;
        for offeredID in hello.cipherSuites.iter() {
            if let Some(offeredSuite) =
                super::cipher_suites::cipherSuiteTLS13ByID(*offeredID)
            {
                if offeredSuite.hash == cipherSuite.hash {
                    cipherSuiteOk = true;
                    break;
                }
            }
        }
        if !cipherSuiteOk {
            return (None, None, slice::new(), crate::errors::nil);
        }

        // Go: ticketAge := c.config.time().Sub(time.Unix(int64(session.createdAt), 0))
        //     identity := pskIdentity{ label: session.ticket,
        //         obfuscatedTicketAge: uint32(ticketAge/time.Millisecond) + session.ageAdd }
        //     hello.pskIdentities = []pskIdentity{identity}
        //     hello.pskBinders = [][]byte{make([]byte, cipherSuite.hash.Size())}
        let ticketAge = self
            .config
            .time()
            .Sub(crate::time::Unix(crate::int64(session.createdAt), 0));
        let identity = super::handshake_messages::pskIdentity {
            label: session.ticket.clone().__into_vec(),
            obfuscatedTicketAge: crate::uint32((ticketAge / crate::time::Millisecond).0)
                .wrapping_add(session.ageAdd),
        };
        hello.pskIdentities = alloc::vec![identity];
        hello.pskBinders =
            alloc::vec![alloc::vec![0u8; cipherSuite.hash.Size() as usize]];

        // Go: earlySecret = tls13.NewEarlySecret(cipherSuite.hash.New, session.secret)
        //     binderKey = earlySecret.ResumptionBinderKey()
        //     transcript := cipherSuite.hash.New()
        //     if err := computeAndUpdatePSK(hello, binderKey, transcript, cipherSuite.finishedHash); err != nil {
        //         return nil, nil, nil, err }
        //     return
        let hash = cipherSuite.hash;
        let earlySecret = crate::crypto::internal::fips140::tls13::NewEarlySecret(
            crate::hash::HashFunc::New(move || hash.New()),
            session.secret.clone(),
        );
        let binderKey = earlySecret.ResumptionBinderKey();
        let mut transcript = super::handshake_messages::transcriptHasher(hash.New());
        let err = super::handshake_client::computeAndUpdatePSK(
            hello,
            binderKey.clone(),
            &mut transcript,
            &|k, t| cipherSuite.finishedHash(k, t),
        );
        if err != crate::errors::nil {
            return (None, None, slice::new(), err);
        }
        return (Some(session), Some(earlySecret), binderKey, crate::errors::nil);
    }
}
