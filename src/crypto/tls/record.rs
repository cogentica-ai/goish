// crypto/tls/record.rs — TLS 1.2 record layer (encrypt / decrypt).
//
// goishlint:ignore GOISH015 — this file is INVENTED, not a port. It
//     predates `conn.rs`, which is Go's record layer with 55 anchors,
//     and ROADMAP.md §1 has retiring it as the last of the tls
//     demolition: `handshake_client.rs` still reaches
//     `record::read_record` nine times. The `conn.go` citation below is
//     the RULE this file now enforces, quoted so the two can be
//     compared — not a claim that record.rs ports conn.go. Renaming it
//     to conn.rs, which is what this rule asks for, would collide with
//     the real port.
//
// ─── What has been diffed against Go, 2026-09-04 ─────────────────────
//
// This file had never been compared to `conn.rs`, the anchored port it
// stands in for. Four defects came out of doing it, each in its own
// commit with a smoke:
//
//   * no bound on the record length — a u16 was read and that many
//     bytes allocated, where Go refuses anything over maxCiphertext.
//   * no bound on the DECRYPTED length, which the first does not
//     imply: maxCiphertext leaves ~2 KiB of slack over maxPlaintext.
//   * a padding oracle — three distinguishable errors for bad padding
//     versus bad MAC, and an early return on the first bad byte. Go's
//     constant-time `extractPadding` is now ported verbatim and the
//     two results are folded before either is acted on. The same check
//     also refused padding over 16 bytes, where TLS permits 255.
//
// A fourth was reported at the time and RETRACTED — a discarded
// `rand::Read` result said to leave the per-record IV as zeros. It
// does not: `crypto::rand::Read` matches Go's contract and calls
// `fatal` on a read failure, which diverges, so it can neither return
// a non-nil error nor short-read. The `let _ =` was correct. The
// correction has been in the code at the IV draw for some time and
// this header kept claiming four; it is three, and the retraction is
// stated here because the next reader reaches this list first.
//
// Rediscovered independently on 2026-09-06 by the same reasoning that
// produced it — five more `let _ = rand::Read(…)` in
// handshake_client.rs and one in x25519_generate, all of which look
// alarming (the x25519 one would fix the ECDHE private key to a
// constant) and none of which can fire. That is what a misleading
// header costs.
//
// Checked and found to MATCH Go, so the next reader need not redo it:
//
//   * the per-record explicit IV is freshly drawn, not reused.
//   * the AEAD path takes the 8-byte explicit nonce FROM THE WIRE and
//     prepends the 4-byte fixed IV, which is the TLS 1.2 GCM
//     construction.
//   * `compute_mac` covers seq || type || version || length ||
//     fragment, per RFC 5246 6.2.3.1.
//   * unencrypted application data cannot be injected mid-handshake:
//     `handshake_client.rs` rejects any record whose type is not the
//     one its state machine expects, which is what Go's "Application
//     Data messages are always protected" check buys.
//   * sequence-number wraparound is not reachable here — `seq` is a
//     u64 parameter the caller owns, and `conn.rs` carries Go's
//     `incSeq` panic.
//
// Not established, and worth stating: none of this makes the CBC path
// constant TIME. The padding scan is Go's, but the MAC is computed
// over a variable-length payload, which is the other half of Lucky13.
//
// Implements the TLS 1.2 record-layer codec for cipher suite
// TLS_RSA_WITH_AES_128_CBC_SHA (0x002F):
//
//   record wire format:
//     content_type  u8  (20=ChangeCipherSpec, 21=Alert, 22=Handshake, 23=Application)
//     version       [2] (0x03, 0x03 = TLS 1.2)
//     length        u16 (big-endian)
//     fragment      [length] bytes
//
//   encrypted fragment layout (post-handshake, TLS 1.2 explicit-IV):
//     iv         [16] bytes  — random per-record explicit IV (TLS >= 1.1)
//     ciphertext      bytes  — AES-128-CBC( plaintext || HMAC-SHA1 || padding )
//
//   MAC = HMAC-SHA1(mac_key, seqnum_BE64 || type || version[2] || length_BE16 || plaintext)
//
//   padding = PKCS7-style: each pad byte = pad_len-1; total padded length
//             is the next multiple of block_size after (plaintext + mac_size).
//
// Reference: RFC 5246 §6.2.3.2 (CBC block cipher).
//
// go: none — goish-only legacy: a hand-written record layer + PRF +
// SPKI parser predating the verbatim port. Go's equivalents live in
// conn.go (halfConn), prf.go, and crypto/x509 — prf.go is fully
// ported in prf.rs, so names here (prf12, p_sha256, read_record, …)
// are goish-invented shapes, NOT ports of the same-named Go
// declarations. The remaining client/server handshake declarations
// replace this file's call sites; it is slated for deletion when the
// dial path moves onto Conn's real read/write machinery.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use alloc::vec::Vec;

use crate::crypto::aes;
use crate::crypto::cipher::BlockMode;
use crate::crypto::cipher::{NewCBCDecrypter, NewCBCEncrypter};
use crate::crypto::hmac;
use crate::crypto::rand;
use crate::crypto::rsa;
use crate::crypto::sha1;
use crate::encoding::asn1;
use crate::errors::{self, error};
use crate::goslice::slice;
use crate::hash::Hash as HashTrait;
use crate::io::Writer as WriterTrait;
use crate::types::byte;

// ─── record-type constants ─────────────────────────────────────────────
pub const RECORD_CHANGE_CIPHER_SPEC: byte = 20;
pub const RECORD_ALERT: byte = 21;
pub const RECORD_HANDSHAKE: byte = 22;
pub const RECORD_APPLICATION: byte = 23;

// TLS 1.2 version bytes
pub const TLS_VERSION_MAJOR: byte = 3;
pub const TLS_VERSION_MINOR: byte = 3;

// AES-128 block + key size; SHA-1 mac size
const AES_BLOCK_SIZE: usize = 16;
const SHA1_SIZE: usize = 20;

// ─── KeyMaterial ──────────────────────────────────────────────────────

/// Session key material for one direction (client→server or server→client).
#[derive(Clone, Default)]
pub struct DirectionKeys {
    /// 20-byte HMAC-SHA1 MAC key.
    pub mac_key: [byte; 20],
    /// 16-byte AES-128 encryption key.
    pub enc_key: [byte; 16],
    /// 16-byte IV (TLS 1.0 implicit; TLS 1.2 uses per-record explicit IV).
    pub iv: [byte; 16],
}

/// All key material negotiated during the handshake.
#[derive(Clone, Default)]
pub struct KeyMaterial {
    pub client: DirectionKeys,
    pub server: DirectionKeys,
    /// Negotiated cipher suite. 0x002F = CBC, 0xC02F/0xC02B = GCM (TLS 1.2),
    /// 0x1301/0x1302 = TLS 1.3 AES-GCM.
    pub suite: u16,
    /// GCM-mode keys (populated when suite == 0xC02F or 0xC02B, TLS 1.2).
    pub aead_client: AeadDirectionKeys,
    pub aead_server: AeadDirectionKeys,
    /// TLS 1.3 flag. When true, use tls13_client/tls13_server instead.
    pub is_tls13: bool,
    /// TLS 1.3 traffic keys (client write).
    pub tls13_client_key: [byte; 32],
    pub tls13_client_iv: [byte; 12],
    /// TLS 1.3 traffic keys (server read).
    pub tls13_server_key: [byte; 32],
    pub tls13_server_iv: [byte; 12],
    /// TLS 1.3 server application traffic secret (stored for KeyUpdate).
    pub tls13_server_app_secret: Vec<byte>,
    /// TLS 1.3 client application traffic secret. Populated by the
    /// server-side handshake so a server Conn can rotate its inbound
    /// (client-write) keys on KeyUpdate; empty on client Conns.
    pub tls13_client_app_secret: Vec<byte>,
    /// TLS 1.3 resumption_master_secret. Used when a NewSessionTicket arrives
    /// post-handshake: PSK = HKDF-Expand-Label(rms, "resumption", ticket_nonce, hash_size).
    /// Empty when not TLS 1.3 or when the handshake hasn't completed yet.
    pub tls13_resumption_master_secret: Vec<byte>,
    /// Hash output size of the negotiated TLS 1.3 cipher suite (32 for SHA-256, 48 for SHA-384).
    /// Needed for resumption PSK derivation.
    pub tls13_hash_size: u16,
}

// ─── TLS 1.2 PRF ─────────────────────────────────────────────────────
//
// RFC 5246 §5:
//   PRF(secret, label, seed) = P_SHA256(secret, label + seed)
//
//   P_SHA256(secret, seed) = HMAC_SHA256(secret, A(1) + seed) +
//                             HMAC_SHA256(secret, A(2) + seed) + ...
//   where A(0) = seed,  A(i) = HMAC_SHA256(secret, A(i-1))

fn hmac_sha256(key: &[byte], data: &[byte]) -> [byte; 32] {
    let key_slice = slice::<byte>::__from_vec(key.to_vec());
    let mut h = hmac::New(crate::crypto::sha256::NewHash, key_slice);
    let data_slice = slice::<byte>::__from_vec(data.to_vec());
    let _ = WriterTrait::Write(&mut h, data_slice);
    let result = HashTrait::Sum(&h, slice::<byte>::__from_vec(Vec::new()));
    let v = result.__into_vec();
    let mut out = [0u8; 32];
    let n = core::cmp::min(v.len(), 32);
    out[..n].copy_from_slice(&v[..n]);
    out
}

fn hmac_sha1(key: &[byte], data: &[byte]) -> [byte; 20] {
    let key_slice = slice::<byte>::__from_vec(key.to_vec());
    let mut h = hmac::New(sha1::NewHash, key_slice);
    let data_slice = slice::<byte>::__from_vec(data.to_vec());
    let _ = WriterTrait::Write(&mut h, data_slice);
    let result = HashTrait::Sum(&h, slice::<byte>::__from_vec(Vec::new()));
    let v = result.__into_vec();
    let mut out = [0u8; 20];
    let n = core::cmp::min(v.len(), 20);
    out[..n].copy_from_slice(&v[..n]);
    out
}

/// P_SHA256(secret, seed) — fills `out` with pseudorandom bytes.
pub fn p_sha256(out: &mut [byte], secret: &[byte], seed: &[byte]) {
    let want = out.len();
    let mut written = 0usize;
    // A(0) = seed
    let mut a: Vec<byte> = seed.to_vec();

    while written < want {
        // A(i) = HMAC_SHA256(secret, A(i-1))
        let ai = hmac_sha256(secret, &a);
        a = ai.to_vec();

        // output_i = HMAC_SHA256(secret, A(i) || seed)
        let mut input: Vec<byte> = Vec::with_capacity(32 + seed.len());
        input.extend_from_slice(&a);
        input.extend_from_slice(seed);
        let block = hmac_sha256(secret, &input);

        let copy_len = core::cmp::min(block.len(), want - written);
        out[written..written + copy_len].copy_from_slice(&block[..copy_len]);
        written += copy_len;
    }
}

/// TLS 1.2 PRF(secret, label, seed) → fills out.
pub fn prf12(out: &mut [byte], secret: &[byte], label: &[byte], seed: &[byte]) {
    let mut label_seed: Vec<byte> = Vec::with_capacity(label.len() + seed.len());
    label_seed.extend_from_slice(label);
    label_seed.extend_from_slice(seed);
    p_sha256(out, secret, &label_seed);
}

/// Derive master secret (RFC 5246 §8.1):
///   master_secret = PRF(premaster, "master secret", client_random || server_random, 48)
pub fn derive_master_secret(
    premaster: &[byte],
    client_random: &[byte; 32],
    server_random: &[byte; 32],
) -> [byte; 48] {
    let mut seed: Vec<byte> = Vec::with_capacity(64);
    seed.extend_from_slice(client_random);
    seed.extend_from_slice(server_random);
    let mut master = [0u8; 48];
    prf12(&mut master, premaster, b"master secret", &seed);
    master
}

/// Derive key block (RFC 5246 §6.3) and split into KeyMaterial.
///
/// key_block = PRF(master, "key expansion", server_random || client_random, 104)
///   [0..20]   client_mac_key (HMAC-SHA1 = 20 bytes)
///   [20..40]  server_mac_key
///   [40..56]  client_write_key (AES-128 = 16 bytes)
///   [56..72]  server_write_key
///   [72..88]  client_write_IV
///   [88..104] server_write_IV
pub fn derive_key_material(
    master: &[byte; 48],
    client_random: &[byte; 32],
    server_random: &[byte; 32],
) -> KeyMaterial {
    let mut seed: Vec<byte> = Vec::with_capacity(64);
    seed.extend_from_slice(server_random);
    seed.extend_from_slice(client_random);

    let mut block = [0u8; 104];
    prf12(&mut block, master, b"key expansion", &seed);

    let mut km = KeyMaterial::default();
    km.client.mac_key.copy_from_slice(&block[0..20]);
    km.server.mac_key.copy_from_slice(&block[20..40]);
    km.client.enc_key.copy_from_slice(&block[40..56]);
    km.server.enc_key.copy_from_slice(&block[56..72]);
    km.client.iv.copy_from_slice(&block[72..88]);
    km.server.iv.copy_from_slice(&block[88..104]);
    km
}

// ─── MAC computation ──────────────────────────────────────────────────
//
// RFC 5246 §6.2.3.1:
//   MAC(MAC_write_key, seq_num || TLSCompressed.type ||
//       TLSCompressed.version || TLSCompressed.length ||
//       TLSCompressed.fragment)

fn compute_mac(
    mac_key: &[byte; 20],
    seq: u64,
    record_type: byte,
    plaintext: &[byte],
) -> [byte; SHA1_SIZE] {
    let seq_bytes = seq.to_be_bytes();
    let len_be = (plaintext.len() as u16).to_be_bytes(); // goishlint:ignore GOISH005

    let mut input: Vec<byte> = Vec::with_capacity(8 + 1 + 2 + 2 + plaintext.len());
    input.extend_from_slice(&seq_bytes);
    input.push(record_type);
    input.push(TLS_VERSION_MAJOR);
    input.push(TLS_VERSION_MINOR);
    input.extend_from_slice(&len_be);
    input.extend_from_slice(plaintext);

    hmac_sha1(mac_key, &input)
}

// ─── encrypt_record ───────────────────────────────────────────────────

/// Encrypt one TLS record. Returns the full wire bytes
/// (5-byte header + explicit_iv + ciphertext).
pub fn encrypt_record(
    record_type: byte,
    seq: u64,
    dir: &DirectionKeys,
    plaintext: &[byte],
) -> (slice<byte>, error) {
    // 1. Compute MAC
    let mac = compute_mac(&dir.mac_key, seq, record_type, plaintext);

    // 2. Build content = plaintext || MAC || PKCS7-padding
    let pt_len = plaintext.len();
    let mac_len = SHA1_SIZE;
    let total_before_pad = pt_len + mac_len;
    let pad_len = AES_BLOCK_SIZE - (total_before_pad % AES_BLOCK_SIZE);
    // each pad byte has value (pad_len - 1)
    let pad_byte = (pad_len - 1) as byte; // goishlint:ignore GOISH005
    let total = total_before_pad + pad_len;

    let mut to_enc: Vec<byte> = Vec::with_capacity(total);
    to_enc.extend_from_slice(plaintext);
    to_enc.extend_from_slice(&mac);
    for _ in 0..pad_len {
        to_enc.push(pad_byte);
    }

    // 3. Generate random explicit IV (TLS 1.2 per-record)
    //
    // Go: conn.go:500 — `if _, err := io.ReadFull(rand, explicitNonce);
    //     err != nil { return nil, err }`.
    //
    // The result is checked, but the branch is UNREACHABLE today and
    // saying so is the point. goish's `crypto::rand::Read` matches Go's
    // contract: on a read failure it calls `fatal`, which diverges, so
    // it can neither return a non-nil error nor short-read. The `let _
    // =` this replaced was therefore correct, and an earlier version of
    // this comment claiming it left a zero IV — the BEAST precondition
    // — was wrong. See the correction in the commit that added this
    // note.
    //
    // Kept because it costs nothing and it is the check Go writes; if
    // that never-fails contract is ever relaxed, this is already
    // right.
    let mut iv_buf = [0u8; AES_BLOCK_SIZE];
    {
        let mut iv_slice = slice::<byte>::__from_vec(alloc::vec![0u8; AES_BLOCK_SIZE]);
        let (n, rerr) = rand::Read(&mut iv_slice);
        if !rerr.IsNil() {
            return (slice::<byte>::__from_vec(Vec::new()), rerr);
        }
        // A short read is as dangerous as an error: the untouched tail
        // stays zero. Go uses ReadFull, which treats it the same way.
        if n as usize != AES_BLOCK_SIZE {
            return (
                slice::<byte>::__from_vec(Vec::new()),
                errors::New("tls: short read from random source"),
            );
        }
        let iv_vec = iv_slice.__into_vec();
        iv_buf.copy_from_slice(&iv_vec[..AES_BLOCK_SIZE]);
    }

    // 4. AES-128-CBC encrypt
    let key_slice = slice::<byte>::__from_vec(dir.enc_key.to_vec());
    let (cipher_opt, _) = aes::NewCipher(key_slice);
    let cipher = match cipher_opt {
        Some(c) => c,
        None => {
            return (
                slice::<byte>::__from_vec(Vec::new()),
                errors::New("tls: AES key error"),
            )
        }
    };

    let iv_slice = slice::<byte>::__from_vec(iv_buf.to_vec());
    let mut encrypter = NewCBCEncrypter(cipher, iv_slice);

    let mut dst_slice = slice::<byte>::__from_vec(alloc::vec![0u8; total]);
    let src_slice = slice::<byte>::__from_vec(to_enc);
    encrypter.CryptBlocks(&mut dst_slice, src_slice);
    let ct = dst_slice.__into_vec();

    // 5. Build wire record: 5-byte header + iv(16) + ciphertext
    let payload_len = AES_BLOCK_SIZE + total;
    let mut out: Vec<byte> = Vec::with_capacity(5 + payload_len);
    out.push(record_type);
    out.push(TLS_VERSION_MAJOR);
    out.push(TLS_VERSION_MINOR);
    let plen = (payload_len as u16).to_be_bytes(); // goishlint:ignore GOISH005
    out.extend_from_slice(&plen);
    out.extend_from_slice(&iv_buf);
    out.extend_from_slice(&ct[..total]);

    (slice::<byte>::__from_vec(out), errors::nil)
}

// ─── decrypt_record ───────────────────────────────────────────────────

/// Decrypt one TLS record fragment (everything after the 5-byte header).
/// Returns the decrypted plaintext.
// go: sdk 1.25.5 crypto/tls/conn.go:281-326 extractPadding
// goishlint:ignore GOISH014 extract_padding — record.rs is invented
//     code being retired (see the file header); the anchor cites the
//     Go function this one is a verbatim port of, which is the only
//     part of this file that is.
/// Return, in constant time, the length of the padding to remove from
/// the end of `payload`, and a mask that is 255 if the padding is valid
/// and 0 otherwise.
///
/// Verbatim from Go, including the two details that matter:
///   * it examines a FIXED 256 bytes (or the whole payload if shorter)
///     rather than stopping at the claimed length, so the time taken
///     does not depend on where the padding went wrong;
///   * it zeroes the padding length on failure, which keeps the
///     unchecked bytes inside the MAC. Go's comment: "an attacker that
///     could distinguish MAC failures from padding failures could mount
///     an attack similar to POODLE in SSL 3.0".
fn extract_padding(payload: &[byte]) -> (usize, byte) {
    if payload.is_empty() {
        return (0, 0);
    }

    let mut padding_len = payload[payload.len() - 1];
    let t = (payload.len() - 1).wrapping_sub(padding_len as usize);  // goishlint:ignore GOISH005 — constant-time sign-bit broadcast; the width is the point
    // If len(payload)-1 >= paddingLen the MSB of t is zero.
    let mut good: byte = ((!(t as i64) >> 63) & 0xff) as byte;  // goishlint:ignore GOISH005 — constant-time sign-bit broadcast; the width is the point

    // The maximum possible padding length plus the length field itself.
    // The length of the padded data is public, so the bound is too.
    let mut to_check = 256usize;
    if to_check > payload.len() {
        to_check = payload.len();
    }

    for i in 0..to_check {
        let t = (padding_len as usize).wrapping_sub(i);  // goishlint:ignore GOISH005 — constant-time sign-bit broadcast; the width is the point
        // If i <= paddingLen the MSB of t is zero.
        let mask: byte = ((!(t as i64) >> 63) & 0xff) as byte;  // goishlint:ignore GOISH005 — constant-time sign-bit broadcast; the width is the point
        let b = payload[payload.len() - 1 - i];
        good &= !(mask & padding_len ^ mask & b);
    }

    // AND the bits of `good` together and spread the result.
    good &= good << 4;
    good &= good << 2;
    good &= good << 1;
    good = ((good as i8) >> 7) as byte;  // goishlint:ignore GOISH005 — constant-time sign-bit broadcast; the width is the point

    // Zero the padding length on error, so unchecked bytes stay in the MAC.
    padding_len &= good;

    return (padding_len as usize + 1, good);  // goishlint:ignore GOISH005 — constant-time sign-bit broadcast; the width is the point
}

// go: none — goish idiom: Go writes the fold as
//     `subtle.ConstantTimeCompare(...) & int(paddingGood)`; the MAC
//     comparison here already produces a difference mask, so this turns
//     that into the same 255/0 shape without branching on it.
/// 255 when `a == b`, 0 otherwise, without a branch.
fn ctEq(a: byte, b: byte) -> byte {
    let x = a ^ b;
    // x == 0 -> 255, else 0
    return ((((x as i32) - 1) >> 31) & 0xff) as byte;  // goishlint:ignore GOISH005 — constant-time sign-bit broadcast; the width is the point
}

pub fn decrypt_record(
    record_type: byte,
    seq: u64,
    dir: &DirectionKeys,
    fragment: &[byte],
) -> (slice<byte>, error) {
    if fragment.len() < AES_BLOCK_SIZE {
        return (
            slice::<byte>::__from_vec(Vec::new()),
            errors::New("tls: fragment too short for IV"),
        );
    }
    let (iv_bytes, ciphertext) = fragment.split_at(AES_BLOCK_SIZE);
    if ciphertext.is_empty() || ciphertext.len() % AES_BLOCK_SIZE != 0 {
        return (
            slice::<byte>::__from_vec(Vec::new()),
            errors::New("tls: ciphertext not a multiple of block size"),
        );
    }

    // 1. AES-128-CBC decrypt
    let key_slice = slice::<byte>::__from_vec(dir.enc_key.to_vec());
    let (cipher_opt, _) = aes::NewCipher(key_slice);
    let cipher = match cipher_opt {
        Some(c) => c,
        None => {
            return (
                slice::<byte>::__from_vec(Vec::new()),
                errors::New("tls: AES key error"),
            )
        }
    };

    let iv_slice = slice::<byte>::__from_vec(iv_bytes.to_vec());
    let mut decrypter = NewCBCDecrypter(cipher, iv_slice);

    let mut dst_slice = slice::<byte>::__from_vec(alloc::vec![0u8; ciphertext.len()]);
    let src_slice = slice::<byte>::__from_vec(ciphertext.to_vec());
    decrypter.CryptBlocks(&mut dst_slice, src_slice);
    let dst_vec = dst_slice.__into_vec();

    // 2. Strip PKCS7 padding, in constant time.
    if dst_vec.is_empty() {
        return (
            slice::<byte>::__from_vec(Vec::new()),
            errors::New("tls: empty decrypted data"),
        );
    }
    let (to_remove, padding_good) = extract_padding(&dst_vec);
    if to_remove > dst_vec.len() {
        // Cannot happen once `good` is 0 — extract_padding zeroes the
        // length on failure — but the slice below must not panic.
        return (
            slice::<byte>::__from_vec(Vec::new()),
            errors::New("tls: bad record MAC"),
        );
    }
    let without_pad = &dst_vec[..dst_vec.len() - to_remove];

    // 3. Verify and strip MAC
    if without_pad.len() < SHA1_SIZE {
        return (
            slice::<byte>::__from_vec(Vec::new()),
            errors::New("tls: bad record MAC"),
        );
    }
    let mac_start = without_pad.len() - SHA1_SIZE;
    let plaintext = &without_pad[..mac_start];
    let their_mac = &without_pad[mac_start..];

    let expected_mac = compute_mac(&dir.mac_key, seq, record_type, plaintext);

    // Go: conn.go:452 — `macAndPaddingGood :=
    //     subtle.ConstantTimeCompare(localMAC, remoteMAC) & int(paddingGood)`,
    //     and ONE error for either. Go's own comment says why: "Depending
    //     on what value of paddingLen was returned on bad padding,
    //     distinguishing bad MAC from bad padding can lead to an attack."
    //
    // This returned three different errors — "bad padding length", "bad
    // padding bytes", "MAC verification failed" — and left the padding
    // loop on the first byte that did not match. Both halves of a
    // padding oracle: a distinguishable answer and a shorter one.
    let mut diff: byte = 0;
    for i in 0..SHA1_SIZE {
        diff |= their_mac[i] ^ expected_mac[i];
    }
    // `diff == 0` and `padding_good == 255` folded into one branch, so
    // the two failures are indistinguishable to the caller.
    let mac_ok: byte = ctEq(diff, 0);
    if (mac_ok & padding_good) != 255 {
        return (
            slice::<byte>::__from_vec(Vec::new()),
            errors::New("tls: bad record MAC"),
        );
    }

    // Go: conn.go:82 — `if len(data) > maxPlaintext { ...
    //     c.sendAlert(alertRecordOverflow) }`, applied to the DECRYPTED
    //     bytes. The record-length bound in `read_record` caps the
    //     ciphertext at maxCiphertext (16384+2048); the plaintext that
    //     comes out of it must still fit maxPlaintext (16384), and the
    //     ~2 KiB between the two is exactly what this catches.
    if plaintext.len() > super::common::maxPlaintext as usize {
        return (
            slice::<byte>::__from_vec(Vec::new()),
            errors::New("tls: oversized record received"),
        );
    }

    (slice::<byte>::__from_vec(plaintext.to_vec()), errors::nil)
}

// ─── encode_record (unencrypted) ─────────────────────────────────────

/// Wrap bytes in an unencrypted 5-byte TLS record header.
pub fn encode_record(record_type: byte, body: &[byte]) -> slice<byte> {
    let len_be = (body.len() as u16).to_be_bytes(); // goishlint:ignore GOISH005
    let mut out: Vec<byte> = Vec::with_capacity(5 + body.len());
    out.push(record_type);
    out.push(TLS_VERSION_MAJOR);
    out.push(TLS_VERSION_MINOR);
    out.extend_from_slice(&len_be);
    out.extend_from_slice(body);
    slice::<byte>::__from_vec(out)
}

// ─── decode_x509_rsa_pubkey ───────────────────────────────────────────
//
// Extract an RSA public key from a DER-encoded X.509 Certificate.
//
// X.509 Certificate ASN.1 structure (RFC 5280):
//   Certificate ::= SEQUENCE {
//     tbsCertificate  TBSCertificate,
//     ...
//   }
//   TBSCertificate ::= SEQUENCE {
//     version         [0] EXPLICIT INTEGER OPTIONAL,
//     serialNumber    INTEGER,
//     signature       AlgorithmIdentifier,
//     issuer          Name,
//     validity        Validity,
//     subject         Name,
//     subjectPublicKeyInfo  SubjectPublicKeyInfo,
//     ...
//   }
//   SubjectPublicKeyInfo ::= SEQUENCE {
//     algorithm  AlgorithmIdentifier,
//     subjectPublicKey  BIT STRING
//   }
//   RSAPublicKey ::= SEQUENCE {
//     modulus    INTEGER,
//     exponent   INTEGER
//   }
//
// We walk the ASN.1 tree to reach SubjectPublicKeyInfo, then parse
// the RSA key from the BIT STRING payload.

/// Parse an RSA public key from a DER-encoded X.509 certificate.
/// Returns the public key or an error.
pub fn decode_x509_rsa_pubkey(cert_der: &[byte]) -> (rsa::PublicKey, error) {
    let der_slice = slice::<byte>::__from_vec(cert_der.to_vec());
    let nil_key = rsa::PublicKey::default();

    // outer Certificate SEQUENCE
    let (cert_rv, _, err) = asn1::ParseRaw(der_slice);
    if !err.IsNil() {
        return (
            nil_key,
            errors::New("tls/x509: failed to parse Certificate SEQUENCE"),
        );
    }
    if cert_rv.Tag != asn1::TagSequence {
        return (
            nil_key,
            errors::New("tls/x509: Certificate is not a SEQUENCE"),
        );
    }

    // TBSCertificate SEQUENCE
    let (tbs_rv, _, err) = asn1::ParseRaw(cert_rv.Bytes.clone());
    if !err.IsNil() {
        return (
            nil_key,
            errors::New("tls/x509: failed to parse TBSCertificate SEQUENCE"),
        );
    }
    if tbs_rv.Tag != asn1::TagSequence {
        return (
            nil_key,
            errors::New("tls/x509: TBSCertificate is not a SEQUENCE"),
        );
    }

    // Walk TBSCertificate fields to find SubjectPublicKeyInfo.
    // Fields in order: [version], serialNumber, signature, issuer, validity, subject, SPKI, ...
    // We skip fields until we reach SPKI (a SEQUENCE containing an AlgorithmIdentifier SEQUENCE
    // followed by a BIT STRING).
    let (spki_bytes, spki_err) = find_spki_in_tbs(&tbs_rv.Bytes);
    if !spki_err.IsNil() {
        return (nil_key, spki_err);
    }

    // SubjectPublicKeyInfo SEQUENCE
    let (spki_rv, _, err) = asn1::ParseRaw(spki_bytes.clone());
    if !err.IsNil() {
        return (
            nil_key,
            errors::New("tls/x509: failed to parse SubjectPublicKeyInfo"),
        );
    }
    if spki_rv.Tag != asn1::TagSequence {
        return (
            nil_key,
            errors::New("tls/x509: SubjectPublicKeyInfo is not a SEQUENCE"),
        );
    }

    // AlgorithmIdentifier SEQUENCE (skip it)
    let (_, rest_after_alg, err) = asn1::ParseRaw(spki_rv.Bytes.clone());
    if !err.IsNil() {
        return (
            nil_key,
            errors::New("tls/x509: failed to parse AlgorithmIdentifier in SPKI"),
        );
    }

    // BIT STRING containing RSAPublicKey
    let (bits_rv, _, err) = asn1::ParseRaw(rest_after_alg.clone());
    if !err.IsNil() {
        return (
            nil_key,
            errors::New("tls/x509: failed to parse BIT STRING in SPKI"),
        );
    }
    if bits_rv.Tag != asn1::TagBitString {
        return (
            nil_key,
            errors::New("tls/x509: expected BIT STRING in SPKI"),
        );
    }
    // BIT STRING: first byte is unused-bits count; skip it
    let bs_bytes = bits_rv.Bytes;
    let bs_raw: &[byte] = &bs_bytes;
    if bs_raw.is_empty() {
        return (nil_key, errors::New("tls/x509: empty BIT STRING in SPKI"));
    }
    let rsa_der = slice::<byte>::__from_vec(bs_raw[1..].to_vec());

    // RSAPublicKey ::= SEQUENCE { modulus INTEGER, exponent INTEGER }
    let (rsa_rv, _, err) = asn1::ParseRaw(rsa_der.clone());
    if !err.IsNil() {
        return (
            nil_key,
            errors::New("tls/x509: failed to parse RSAPublicKey SEQUENCE"),
        );
    }
    if rsa_rv.Tag != asn1::TagSequence {
        return (
            nil_key,
            errors::New("tls/x509: RSAPublicKey is not a SEQUENCE"),
        );
    }

    let (n_rv, rest_rsa, err) = asn1::ParseRaw(rsa_rv.Bytes.clone());
    if !err.IsNil() || n_rv.Tag != asn1::TagInteger {
        return (
            nil_key,
            errors::New("tls/x509: failed to parse RSA modulus"),
        );
    }
    let (n_int, err) = asn1::ParseBigInt(n_rv.Bytes.clone());
    if !err.IsNil() {
        return (
            nil_key,
            errors::New("tls/x509: failed to decode RSA modulus"),
        );
    }

    let (e_rv, _, err) = asn1::ParseRaw(rest_rsa.clone());
    if !err.IsNil() || e_rv.Tag != asn1::TagInteger {
        return (
            nil_key,
            errors::New("tls/x509: failed to parse RSA public exponent"),
        );
    }
    let (e_val, err) = asn1::ParseInt64(e_rv.Bytes.clone());
    if !err.IsNil() {
        return (
            nil_key,
            errors::New("tls/x509: failed to decode RSA public exponent"),
        );
    }

    (rsa::PublicKey { N: n_int, E: e_val }, errors::nil)
}

/// Walk the TBSCertificate body to find the SubjectPublicKeyInfo element.
/// Returns (SPKI DER bytes, error).
fn find_spki_in_tbs(tbs_body: &slice<byte>) -> (slice<byte>, error) {
    let mut rest = tbs_body.clone();
    let empty = slice::<byte>::__from_vec(Vec::new());

    // Field index: 0=version[optional], 1=serial, 2=signature, 3=issuer, 4=validity, 5=subject, 6=SPKI
    let mut field = 0usize;

    while rest.Len() > 0 {
        let (_rv, next_rest, err) = asn1::ParseRaw(rest.clone());
        if !err.IsNil() {
            return (
                empty,
                errors::New("tls/x509: error parsing TBSCertificate field"),
            );
        }

        // version is optional and context-specific [0]
        // If first field is context-specific class (ClassContextSpecific = 2), it's version
        // We detect it by checking if the tag byte's class bits == 2 (context-specific)
        // In raw DER: tag byte for [0] EXPLICIT is 0xA0 (10100000)
        let is_explicit_version = field == 0 && {
            let raw: &[byte] = &rest;
            !raw.is_empty() && (raw[0] & 0xC0) == 0x80
        };

        if is_explicit_version {
            // Skip version, don't increment our "effective" field count
        } else {
            field += 1;
        }

        if field == 6 {
            // This is the SPKI
            // We need to reconstruct the full TLV bytes for ParseRaw to re-parse
            // Actually we already have rv.Bytes (the content) and rv.Tag
            // Let's just reconstruct the full DER element from rest up to next_rest
            // The element spans rest[0 .. rest.Len() - next_rest.Len()]
            let rest_raw: &[byte] = &rest;
            let next_raw: &[byte] = &next_rest;
            let elem_len = rest_raw.len() - next_raw.len();
            return (
                slice::<byte>::__from_vec(rest_raw[..elem_len].to_vec()),
                errors::nil,
            );
        }

        rest = next_rest;
    }

    (
        empty,
        errors::New("tls/x509: SubjectPublicKeyInfo not found in TBSCertificate"),
    )
}

// ─── AES-128-GCM record layer ─────────────────────────────────────────
//
// For TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F):
//
//   key_block = PRF(master, "key expansion", server_random || client_random, 40)
//     [0..16]   client_write_key
//     [16..32]  server_write_key
//     [32..36]  client_write_iv  (4 bytes fixed)
//     [36..40]  server_write_iv
//
//   Encrypted fragment layout:
//     explicit_nonce (8 bytes BE seq_num) || ciphertext_and_tag
//
//   nonce_12 = write_iv(4) || explicit_nonce(8)
//   aad = seq_num(8 BE) || record_type(1) || version(2) || plaintext_len(2 BE)

/// GCM-mode session keys for one direction.
#[derive(Clone, Default)]
pub struct AeadDirectionKeys {
    /// 16-byte AES-128 encryption/decryption key.
    pub enc_key: [byte; 16],
    /// 4-byte implicit IV (fixed nonce prefix).
    pub iv: [byte; 4],
}

/// All GCM key material negotiated for the ECDHE-GCM cipher suite.
#[derive(Clone, Default)]
pub struct AeadKeyMaterial {
    pub client: AeadDirectionKeys,
    pub server: AeadDirectionKeys,
}

/// Derive 40-byte key block for AES-128-GCM and split into AeadKeyMaterial.
pub fn derive_aead_key_material(
    master: &[byte; 48],
    client_random: &[byte; 32],
    server_random: &[byte; 32],
) -> AeadKeyMaterial {
    let mut seed: Vec<byte> = Vec::with_capacity(64);
    seed.extend_from_slice(server_random);
    seed.extend_from_slice(client_random);

    let mut block = [0u8; 40];
    prf12(&mut block, master, b"key expansion", &seed);

    let mut km = AeadKeyMaterial::default();
    km.client.enc_key.copy_from_slice(&block[0..16]);
    km.server.enc_key.copy_from_slice(&block[16..32]);
    km.client.iv.copy_from_slice(&block[32..36]);
    km.server.iv.copy_from_slice(&block[36..40]);
    km
}

/// Encrypt one TLS record using AES-128-GCM. Returns the full wire bytes
/// (5-byte header + 8-byte explicit_nonce + ciphertext_and_tag).
pub fn encrypt_record_aead(
    record_type: byte,
    seq: u64,
    dir: &AeadDirectionKeys,
    plaintext: &[byte],
) -> (slice<byte>, error) {
    // Build the 12-byte nonce: fixed_iv(4) || seq_num_BE(8)
    let explicit_nonce = seq.to_be_bytes();
    let mut nonce12 = [0u8; 12];
    nonce12[..4].copy_from_slice(&dir.iv);
    nonce12[4..].copy_from_slice(&explicit_nonce);

    // Build AAD: seq_num(8 BE) || record_type(1) || version(2) || plaintext_len(2 BE)
    let pt_len = plaintext.len() as u16; // goishlint:ignore GOISH005
    let mut aad = [0u8; 13];
    aad[..8].copy_from_slice(&explicit_nonce);
    aad[8] = record_type;
    aad[9] = TLS_VERSION_MAJOR;
    aad[10] = TLS_VERSION_MINOR;
    aad[11..13].copy_from_slice(&pt_len.to_be_bytes());

    // Create AES block cipher and GCM wrapper
    let key_slice = slice::<byte>::__from_vec(dir.enc_key.to_vec());
    let (cipher_opt, _) = aes::NewCipher(key_slice);
    let cipher = match cipher_opt {
        Some(c) => c,
        None => {
            return (
                slice::<byte>::__from_vec(Vec::new()),
                errors::New("tls: AES-GCM key error"),
            )
        }
    };

    let (gcm_opt, gerr) = crate::crypto::cipher::NewGCM(cipher);
    if !gerr.IsNil() {
        return (slice::<byte>::__from_vec(Vec::new()), gerr);
    }
    let gcm = match gcm_opt {
        Some(g) => g,
        None => {
            return (
                slice::<byte>::__from_vec(Vec::new()),
                errors::New("tls: AES-GCM init error"),
            )
        }
    };

    use crate::crypto::cipher::AEAD as AEADTrait;
    let nonce_s = slice::<byte>::__from_vec(nonce12.to_vec());
    let pt_s = slice::<byte>::__from_vec(plaintext.to_vec());
    let aad_s = slice::<byte>::__from_vec(aad.to_vec());
    let empty_dst = slice::<byte>::__from_vec(Vec::new());

    let ct_tag = gcm.Seal(empty_dst, nonce_s, pt_s, aad_s);
    let ct_tag_v = ct_tag.__into_vec();

    // Wire record: header(5) + explicit_nonce(8) + ciphertext_and_tag
    let payload_len = 8 + ct_tag_v.len();
    let mut out: Vec<byte> = Vec::with_capacity(5 + payload_len);
    out.push(record_type);
    out.push(TLS_VERSION_MAJOR);
    out.push(TLS_VERSION_MINOR);
    let plen_be = (payload_len as u16).to_be_bytes(); // goishlint:ignore GOISH005
    out.extend_from_slice(&plen_be);
    out.extend_from_slice(&explicit_nonce);
    out.extend_from_slice(&ct_tag_v);

    (slice::<byte>::__from_vec(out), errors::nil)
}

/// Decrypt one TLS AEAD record fragment (everything after the 5-byte header).
/// Returns the decrypted plaintext.
pub fn decrypt_record_aead(
    record_type: byte,
    seq: u64,
    dir: &AeadDirectionKeys,
    fragment: &[byte],
) -> (slice<byte>, error) {
    if fragment.len() < 8 {
        return (
            slice::<byte>::__from_vec(Vec::new()),
            errors::New("tls: AEAD fragment too short for explicit nonce"),
        );
    }
    let explicit_nonce = &fragment[..8];
    let ct_and_tag = &fragment[8..];

    if ct_and_tag.len() < 16 {
        return (
            slice::<byte>::__from_vec(Vec::new()),
            errors::New("tls: AEAD ciphertext too short for tag"),
        );
    }

    // Build 12-byte nonce
    let mut nonce12 = [0u8; 12];
    nonce12[..4].copy_from_slice(&dir.iv);
    nonce12[4..].copy_from_slice(explicit_nonce);

    // The plaintext length is ciphertext_and_tag.len() - 16
    let plain_len = ct_and_tag.len() - 16;
    let pt_len_be = (plain_len as u16).to_be_bytes(); // goishlint:ignore GOISH005

    // Build AAD: seq_num(8 BE) || record_type(1) || version(2) || plaintext_len(2 BE)
    let seq_bytes = seq.to_be_bytes();
    let mut aad = [0u8; 13];
    aad[..8].copy_from_slice(&seq_bytes);
    aad[8] = record_type;
    aad[9] = TLS_VERSION_MAJOR;
    aad[10] = TLS_VERSION_MINOR;
    aad[11..13].copy_from_slice(&pt_len_be);

    let key_slice = slice::<byte>::__from_vec(dir.enc_key.to_vec());
    let (cipher_opt, _) = aes::NewCipher(key_slice);
    let cipher = match cipher_opt {
        Some(c) => c,
        None => {
            return (
                slice::<byte>::__from_vec(Vec::new()),
                errors::New("tls: AES-GCM key error"),
            )
        }
    };

    let (gcm_opt, gerr) = crate::crypto::cipher::NewGCM(cipher);
    if !gerr.IsNil() {
        return (slice::<byte>::__from_vec(Vec::new()), gerr);
    }
    let gcm = match gcm_opt {
        Some(g) => g,
        None => {
            return (
                slice::<byte>::__from_vec(Vec::new()),
                errors::New("tls: AES-GCM init error"),
            )
        }
    };

    use crate::crypto::cipher::AEAD as AEADTrait;
    let nonce_s = slice::<byte>::__from_vec(nonce12.to_vec());
    let ct_s = slice::<byte>::__from_vec(ct_and_tag.to_vec());
    let aad_s = slice::<byte>::__from_vec(aad.to_vec());
    let empty_dst = slice::<byte>::__from_vec(Vec::new());

    let (pt_s, derr) = gcm.Open(empty_dst, nonce_s, ct_s, aad_s);
    if !derr.IsNil() {
        return (slice::<byte>::__from_vec(Vec::new()), derr);
    }

    // Go: conn.go:82 — `if len(data) > maxPlaintext { ...
    //     c.sendAlert(alertRecordOverflow) }`, applied to the DECRYPTED
    //     bytes. The record-length bound in `read_record` caps the
    //     ciphertext at maxCiphertext (16384+2048); the plaintext that
    //     comes out of it must still fit maxPlaintext (16384), and the
    //     ~2 KiB between the two is exactly what this catches.
    if pt_s.Len() > super::common::maxPlaintext {
        return (
            slice::<byte>::__from_vec(Vec::new()),
            errors::New("tls: oversized record received"),
        );
    }

    (pt_s, errors::nil)
}

// ─── read_record ──────────────────────────────────────────────────────

/// Read exactly one TLS record from `conn`.
/// Returns `(content_type, fragment_bytes, error)`.
pub fn read_record(conn: &mut dyn crate::io::Reader) -> (byte, slice<byte>, error) {
    let empty = slice::<byte>::__from_vec(Vec::new());
    // Read 5-byte header
    let mut hdr = [0u8; 5];
    let mut off = 0usize;
    while off < 5 {
        let remaining = 5 - off;
        let mut buf = slice::<byte>::__from_vec(alloc::vec![0u8; remaining]);
        let (n, err) = conn.Read(&mut buf);
        if !err.IsNil() {
            return (0, empty, err);
        }
        let nv = n as usize; // goishlint:ignore GOISH005
        if nv == 0 {
            return (
                0,
                empty,
                errors::New("tls: unexpected EOF in record header"),
            );
        }
        let chunk = buf.__into_vec();
        hdr[off..off + nv].copy_from_slice(&chunk[..nv]);
        off += nv;
    }

    let content_type = hdr[0];
    let payload_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize; // goishlint:ignore GOISH005

    // Go: conn.go:673 — `if c.vers == VersionTLS13 && n > maxCiphertextTLS13
    // || n > maxCiphertext { c.sendAlert(alertRecordOverflow); ... }`
    //
    // This read no length limit at all: a u16 caps the damage at 64 KiB,
    // but every record between 18433 and 65535 bytes was accepted and
    // processed where Go refuses it with alertRecordOverflow. That is a
    // peer-controlled input deciding how much this client allocates and
    // parses, on the handshake path, and nothing reported it.
    //
    // Go applies a TIGHTER bound once the version is known to be TLS
    // 1.3 (maxCiphertextTLS13, 16384+256). This function is handed a
    // bare `io::Reader` and has no connection state, so it enforces the
    // general bound only. `conn.rs`'s `readRecordOrCCS` — the ported
    // record layer, which this file exists to be replaced by — does the
    // version-dependent check properly.
    if payload_len > super::common::maxCiphertext as usize {
        return (
            content_type,
            empty,
            errors::New("tls: oversized record received"),
        );
    }

    if payload_len == 0 {
        return (content_type, empty, errors::nil);
    }

    // Read payload
    let mut payload: Vec<byte> = alloc::vec![0u8; payload_len];
    let mut read_off = 0usize;
    while read_off < payload_len {
        let remaining = payload_len - read_off;
        let mut buf = slice::<byte>::__from_vec(alloc::vec![0u8; remaining]);
        let (n, err) = conn.Read(&mut buf);
        if !err.IsNil() {
            return (content_type, empty, err);
        }
        let nv = n as usize; // goishlint:ignore GOISH005
        if nv == 0 {
            return (
                content_type,
                empty,
                errors::New("tls: unexpected EOF in record payload"),
            );
        }
        let chunk = buf.__into_vec();
        payload[read_off..read_off + nv].copy_from_slice(&chunk[..nv]);
        read_off += nv;
    }

    (
        content_type,
        slice::<byte>::__from_vec(payload),
        errors::nil,
    )
}
