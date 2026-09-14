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

// go: none — goish-only: an array-shaped HMAC-SHA1 for the CBC MAC
// below. Go writes `hmac.New(sha1.New, key)` inline in
// cipher_suites.go's macSHA1; this is the same call with the fixed-size
// result the record codec's arrays want.
//
// It lost its anchor for a while by accident: a TLS 1.2 PRF banner sat
// directly above it, so GOISH014 read that block as the anchor block
// and reported it malformed. The banner belonged to `p_sha256`, which
// is gone; it now lives with `prf12`.
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

// ─── TLS 1.2 PRF ─────────────────────────────────────────────────────
//
// RFC 5246 §5:
//   PRF(secret, label, seed) = P_SHA256(secret, label + seed)
//
//   P_SHA256(secret, seed) = HMAC_SHA256(secret, A(1) + seed) +
//                             HMAC_SHA256(secret, A(2) + seed) + ...
//   where A(0) = seed,  A(i) = HMAC_SHA256(secret, A(i-1))
//
// P_SHA256 and the TLS 1.2 PRF built on it USED TO LIVE HERE, 42 lines
// of HMAC ladder. Go declares `prf12` exactly once (prf.go), delegating
// to crypto/internal/fips140/tls12.PRF; goish declared it twice, and
// this was the second — hand-rolled, SHA-256 only, deriving the master
// secret and the key block for the invented TLS 1.2 handshake.
//
// Found mechanically, by asking which free functions goish defines more
// often than Go does. That question had already turned up a fourth
// `hasPort` and a third SubjectPublicKeyInfo walk; this was its third
// answer, and the first one in key derivation.
//
// The two agreed. `tls_prf_dup_smoke` is the proof and it predates the
// deletion deliberately: 315 vectors from Go 1.25.5's own tls12.PRF
// (scripts/goref.sh crypto/internal/fips140/tls12, committed as
// examples/testdata/tls12_prf_ref.txt), each run through BOTH
// implementations, so neither could be graded against the other. 630
// green checks are what made removing this safe rather than hopeful.
//
// The table stays. It now pins this adapter — the label||seed splice
// and the keyLen handling — against Go, which is where the last
// remaining chance of divergence lives.

/// TLS 1.2 PRF(secret, label, seed) → fills out.
pub fn prf12(out: &mut [byte], secret: &[byte], label: &[byte], seed: &[byte]) {
    let derived = super::prf::prf12(
        crate::crypto::sha256::NewHash
            as fn() -> alloc::boxed::Box<dyn crate::hash::Hash + Send + Sync>,
        slice::<byte>::__from_vec(secret.to_vec()),
        crate::gostring::string::from_bytes(label),
        slice::<byte>::__from_vec(seed.to_vec()),
        crate::int(crate::int64(out.len())),
    );
    let d: &[byte] = &derived;
    out.copy_from_slice(d);
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

// go: none — goish-only: the two lengths conn.go computes inline as
// `payload[:n]` and `payload[n+macSize:]`, extracted so the Lucky13
// property is testable. What Lucky13 needs is that their SUM does not
// move with the padding length — the hash then sees the same number of
// bytes, and so does the same number of compression-function blocks,
// whatever padding was stripped.
//
// `decrypt_record` calls this rather than repeating the arithmetic, so
// `tls_lucky13_smoke` is testing the live expressions and not a copy
// of them.
/// `(mac_start, extra_start)` for a decrypted block of `total` bytes
/// from which `to_remove` padding bytes were stripped.
///
/// PRECONDITION: `total - to_remove >= SHA1_SIZE`, i.e. what is left
/// after the padding still holds a MAC. `decrypt_record` checks that
/// and returns "bad record MAC" first; this panics rather than
/// returning a wrapped length, because a caller that has not checked
/// is about to index a slice with it.
#[doc(hidden)]
pub fn __mac_split(total: usize, to_remove: usize) -> (usize, usize) {
    let without_pad = total - to_remove;
    let mac_start = without_pad - SHA1_SIZE;
    return (mac_start, mac_start + SHA1_SIZE);
}

fn compute_mac(
    mac_key: &[byte; 20],
    seq: u64,
    record_type: byte,
    plaintext: &[byte],
    extra: &[byte],
) -> [byte; SHA1_SIZE] {
    // DELEGATES SINCE 2026-09-14, and gained a parameter doing it.
    //
    // This was a hand-rolled second copy of cipher_suites.go's
    // `tls10MAC`, and it had no `extra` at all. That argument is Go's
    // Lucky13 countermeasure: after taking the Sum it writes the
    // stripped PADDING into the same hash, so the number of
    // compression-function blocks is the same whatever the padding
    // length was. Without it the MAC's cost tracks how much padding was
    // removed, which is the timing signal Lucky13 reads.
    //
    // conn.rs — the record layer `tls::Dial` actually runs — passes it
    // (conn.rs, mirroring conn.go:443). This copy did not, and §1's
    // 2026-09-04 audit of record.rs fixed the padding ORACLE two lines
    // below without noticing the padding TIMING here. Auditing a
    // function is not auditing the one beside it.
    //
    // Not reachable from `tls::Dial`: the only non-example caller is
    // the invented TLS 1.2 handshake, which refuses outright unless the
    // caller passes skip_verify.
    let mut h = super::cipher_suites::macSHA1(slice::<byte>::__from_vec(mac_key.to_vec()));
    // Go's `record[:recordHeaderLen]`, with the length field holding
    // the PLAINTEXT length — conn.go rewrites record[3:5] to n before
    // the call.
    let len_be = (crate::uint16(plaintext.len())).to_be_bytes();
    let header = alloc::vec![
        record_type,
        TLS_VERSION_MAJOR,
        TLS_VERSION_MINOR,
        len_be[0],
        len_be[1],
    ];
    let res = super::cipher_suites::tls10MAC(
        &mut *h,
        slice::<byte>::new(),
        slice::<byte>::__from_vec(seq.to_be_bytes().to_vec()),
        slice::<byte>::__from_vec(header),
        slice::<byte>::__from_vec(plaintext.to_vec()),
        slice::<byte>::__from_vec(extra.to_vec()),
    );
    let v: &[byte] = &res;
    let mut out = [0u8; SHA1_SIZE];
    let n = core::cmp::min(v.len(), SHA1_SIZE);
    out[..n].copy_from_slice(&v[..n]);
    return out;
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
    // Go: tls10MAC(..., payload, nil) — nothing to pad over yet.
    let mac = compute_mac(&dir.mac_key, seq, record_type, plaintext, &[]);

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
// go: none — goish-only: reach `extract_padding` from an example, so
// it can be driven over the same Go vectors as conn.rs's port. Private
// otherwise; see tls_extractpadding_dup_smoke.
#[doc(hidden)]
pub fn __extract_padding(payload: &[byte]) -> (usize, byte) {
    return extract_padding(payload);
}

fn extract_padding(payload: &[byte]) -> (usize, byte) {
    // HAND-ROLLED HERE UNTIL 2026-09-14. conn.rs carries the anchored
    // port of conn.go:281-314, and this was a second copy of the CBC
    // padding check — the function §1's 2026-09-04 audit found a
    // padding oracle beside.
    //
    // The two were not even written alike. Go computes `t` in `uint`
    // and broadcasts with `byte(int32(^t) >> 31)`, narrowing to 32 bits
    // on purpose; conn.rs mirrors that. This used `i64` and `>> 63`.
    // Both were right, because `^t` is either all-high-bits-set or a
    // small positive in every reachable case so bits 31 and 63 agree —
    // "happens to agree" being exactly what a second copy leaves you
    // relying on.
    //
    // `tls_extractpadding_dup_smoke` is the evidence and predates the
    // change: 1,041 vectors from Go's own (unexported) extractPadding
    // via `scripts/goref.sh crypto/tls`, run through both. It stays,
    // and it is sharp — narrowing the 256-byte scan bound to 255 turns
    // exactly one row red, the only input that can tell the two apart.
    //
    // The `to_vec` is a copy of the record payload, once per record.
    // Acceptable here and nowhere hotter: this path is the invented
    // handshake's, not `tls::Dial`'s, and ROADMAP §1 has the file slated
    // for retirement. The alternative — keeping a second constant-time
    // padding check to save a memcpy the AES decrypt beside it dwarfs —
    // is the wrong trade.
    let (to_remove, good) =
        super::conn::extractPadding(slice::<byte>::__from_vec(payload.to_vec()));
    return (to_remove as usize, good);  // goishlint:ignore GOISH005 — int -> usize for the caller's slice indexing
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
    let (mac_start, extra_start) = __mac_split(dst_vec.len(), to_remove);
    let plaintext = &without_pad[..mac_start];
    let their_mac = &without_pad[mac_start..];

    // Go: tls10MAC(..., payload[:n], payload[n+macSize:]) — the trailing
    // argument is the PADDING that was just stripped, hashed after the
    // Sum so the block count does not track the padding length.
    let extra = &dst_vec[extra_start..];
    let expected_mac = compute_mac(&dir.mac_key, seq, record_type, plaintext, extra);

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
// Delegates to crypto/x509. This used to be a hand-rolled walk down to
// the SubjectPublicKeyInfo — outer SEQUENCE, TBSCertificate, count six
// fields, step over the AlgorithmIdentifier, take the BIT STRING — plus
// its own RSAPublicKey decoder. That was written when crypto/x509 was
// not ported. It is, and the file said so: "stays goish-only until
// crypto/x509 is ported and can supply it".
//
// The duplicate was not merely redundant. It STEPPED OVER the
// AlgorithmIdentifier without reading it, so it returned a perfectly
// good 2048-bit key from an RSASSA-PSS certificate, where the real
// parser reports PublicKeyAlgorithm 0 and no key at all — an
// RSA-PSS-only key handed back for PKCS#1 v1.5 use. It also skipped
// Go's `N.Sign() <= 0` and `E <= 0` checks (x509.go parsePublicKey),
// so a negative modulus parsed fine.
//
// Not a vulnerability: the two callers are the invented client
// handshakes, which do no certificate verification at all and now
// refuse unless the caller passes skip_verify. It is one less parser.

/// Parse an RSA public key from a DER-encoded X.509 certificate.
/// Returns the public key or an error.
pub fn decode_x509_rsa_pubkey(cert_der: &[byte]) -> (rsa::PublicKey, error) {
    let nil_key = rsa::PublicKey::default();
    let (cert, err) =
        crate::crypto::x509::ParseCertificate(slice::<byte>::__from_vec(cert_der.to_vec()));
    if !err.IsNil() {
        return (nil_key, err);
    }
    // Belt and braces, and measured as such: deleting this leaves the
    // table in x509_ecdsa_smoke fully green, because ParseCertificate
    // already declines to produce a key for an SPKI it does not
    // recognise and the downcast below catches that. It stays as the
    // explicit statement of which algorithm this function is for, so a
    // future x509 that learns to parse RSA-PSS into an rsa::PublicKey
    // does not silently widen it.
    if cert.PublicKeyAlgorithm != crate::crypto::x509::RSA {
        return (
            nil_key,
            errors::New("tls/x509: certificate public key is not RSA"),
        );
    }
    match cert.PublicKey.as_any().downcast_ref::<rsa::PublicKey>() {
        Some(k) => {
            return (k.clone(), errors::nil);
        }
        None => {
            return (
                nil_key,
                errors::New("tls/x509: certificate public key is not RSA"),
            );
        }
    }
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
