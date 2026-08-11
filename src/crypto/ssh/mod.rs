// crypto/ssh — minimum-viable SSH-2.0 client for goish.
//
// Implements:
//   - SSH binary packet framing (RFC 4253 §6)
//   - Version exchange (RFC 4253 §4)
//   - KEXINIT (RFC 4253 §7)
//   - Diffie-Hellman Group 14 with SHA-256 (RFC 8268)
//   - Key derivation (RFC 4253 §7.2)
//   - NEWKEYS (RFC 4253 §7.3)
//   - Password authentication (RFC 4252 §8)
//   - Channel open / exec / data / close (RFC 4254)
//
// Algorithms:
//   KEX:        diffie-hellman-group14-sha256
//   Host key:   ssh-ed25519
//   Cipher:     aes128-ctr (both directions)
//   MAC:        hmac-sha2-256 (both directions)
//   Compression: none
//
// Auth methods: Password (via PasswordAuth), PublicKey (via
//   PublicKeyAuth with ssh-ed25519).
//
// NOTE: This is a client-only implementation. No server mode.

#![allow(non_snake_case, non_upper_case_globals, dead_code, unused_imports)]
#![allow(unused_mut, unused_variables)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::crypto::cipher::Block as CipherBlock;
use crate::errors::{self as errors, ErrorTrait, error};
use crate::goslice::slice;
use crate::gostring::string;
use crate::io;
use crate::io::{Reader as IoReader, Writer as IoWriter};
use crate::math::big::Int as BigInt;
use crate::sync::Mutex;
use crate::types::{byte, int};

// ─── SSH message type constants ───────────────────────────────────────────

const SSH_MSG_DISCONNECT: byte = 1;
const SSH_MSG_IGNORE: byte = 2;
const SSH_MSG_SERVICE_REQUEST: byte = 5;
const SSH_MSG_SERVICE_ACCEPT: byte = 6;
const SSH_MSG_KEXINIT: byte = 20;
const SSH_MSG_NEWKEYS: byte = 21;
const SSH_MSG_KEXDH_INIT: byte = 30;
const SSH_MSG_KEXDH_REPLY: byte = 31;
const SSH_MSG_USERAUTH_REQUEST: byte = 50;
const SSH_MSG_USERAUTH_FAILURE: byte = 51;
const SSH_MSG_USERAUTH_SUCCESS: byte = 52;
const SSH_MSG_USERAUTH_BANNER: byte = 53;
const SSH_MSG_CHANNEL_OPEN: byte = 90;
const SSH_MSG_CHANNEL_OPEN_CONFIRMATION: byte = 91;
const SSH_MSG_CHANNEL_OPEN_FAILURE: byte = 92;
const SSH_MSG_CHANNEL_WINDOW_ADJUST: byte = 93;
const SSH_MSG_CHANNEL_DATA: byte = 94;
const SSH_MSG_CHANNEL_EXTENDED_DATA: byte = 95;
const SSH_MSG_CHANNEL_EOF: byte = 96;
const SSH_MSG_CHANNEL_CLOSE: byte = 97;
const SSH_MSG_CHANNEL_REQUEST: byte = 98;
const SSH_MSG_CHANNEL_SUCCESS: byte = 99;
const SSH_MSG_CHANNEL_FAILURE: byte = 100;

// ─── DH Group 14 constants (RFC 3526, 2048-bit MODP) ──────────────────────

/// DH Group 14 prime (2048 bits), hex-encoded (upper-case, no spaces).
const DH_GROUP14_P_HEX: &str =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74\
     020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437\
     4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
     EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05\
     98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB\
     9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
     E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718\
     3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

// ─── Error type ───────────────────────────────────────────────────────────

#[derive(Clone, Default)]
pub struct SshError {
    pub msg: string,
}

impl ErrorTrait for SshError {
    fn Error(&self) -> string {
        self.msg.clone()
    }
}

fn ssh_err<S: Into<string>>(s: S) -> error {
    errors::Wrap(SshError { msg: s.into() })
}

// ─── Wire encoding helpers ────────────────────────────────────────────────

#[inline]
fn put_u32(buf: &mut Vec<byte>, n: u32) {
    buf.push((n >> 24) as u8); // goishlint:ignore GOISH005
    buf.push((n >> 16) as u8); // goishlint:ignore GOISH005
    buf.push((n >> 8) as u8);  // goishlint:ignore GOISH005
    buf.push(n as u8);         // goishlint:ignore GOISH005
}

#[inline]
fn get_u32(buf: &[byte], off: usize) -> (u32, usize) {
    if off + 4 > buf.len() { return (0, off); }
    let v = ((buf[off] as u32) << 24) | ((buf[off+1] as u32) << 16) // goishlint:ignore GOISH005
          | ((buf[off+2] as u32) << 8) | (buf[off+3] as u32);        // goishlint:ignore GOISH005
    (v, off + 4)
}

fn put_ssh_string(buf: &mut Vec<byte>, data: &[byte]) {
    put_u32(buf, data.len() as u32); // goishlint:ignore GOISH005
    buf.extend_from_slice(data);
}

fn get_ssh_string(buf: &[byte], off: usize) -> (Vec<byte>, usize) {
    if off + 4 > buf.len() { return (Vec::new(), off); }
    let (len, off2) = get_u32(buf, off);
    let end = off2 + len as usize; // goishlint:ignore GOISH005
    if end > buf.len() { return (Vec::new(), off2); }
    (buf[off2..end].to_vec(), end)
}

#[inline]
fn put_bool(buf: &mut Vec<byte>, b: bool) {
    buf.push(if b { 1 } else { 0 });
}

#[inline]
fn get_bool(buf: &[byte], off: usize) -> (bool, usize) {
    if off >= buf.len() { return (false, off); }
    (buf[off] != 0, off + 1)
}

/// Encode an mpint: strip leading zeros; add 0x00 prefix if high bit set.
fn put_mpint(buf: &mut Vec<byte>, bytes: &[byte]) {
    let mut start = 0usize;
    while start < bytes.len() && bytes[start] == 0 { start += 1; }
    let trimmed = &bytes[start..];
    let needs_zero = !trimmed.is_empty() && (trimmed[0] & 0x80) != 0;
    let len = trimmed.len() + if needs_zero { 1 } else { 0 };
    put_u32(buf, len as u32); // goishlint:ignore GOISH005
    if needs_zero { buf.push(0x00); }
    buf.extend_from_slice(trimmed);
}

/// Read an mpint; returns unsigned big-endian bytes with no leading zeros.
fn get_mpint(buf: &[byte], off: usize) -> (Vec<byte>, usize) {
    let (data, new_off) = get_ssh_string(buf, off);
    let mut start = 0usize;
    while start < data.len() && data[start] == 0 { start += 1; }
    (data[start..].to_vec(), new_off)
}

fn name_list_bytes(names: &[&str]) -> Vec<byte> {
    let mut buf: Vec<byte> = Vec::new();
    for (i, n) in names.iter().enumerate() {
        if i > 0 { buf.push(b','); }
        buf.extend_from_slice(n.as_bytes());
    }
    buf
}

// ─── AES-128-CTR stream ───────────────────────────────────────────────────

struct Aes128Ctr {
    cipher: crate::crypto::aes::Block,
    ctr: [byte; 16],
    ks_buf: Vec<byte>,
    ks_pos: usize,
}

impl Aes128Ctr {
    fn new(key: &[byte], iv: &[byte]) -> Self {
        let key_slice: slice<byte> = slice::__from_vec(key.to_vec());
        let (opt_cipher, err) = crate::crypto::aes::NewCipher(key_slice);
        if !err.IsNil() {
            panic!("ssh: aes key error");
        }
        let cipher = opt_cipher.expect("ssh: aes None");
        let mut ctr = [0u8; 16];
        let copy_len = iv.len().min(16);
        ctr[..copy_len].copy_from_slice(&iv[..copy_len]);
        Aes128Ctr { cipher, ctr, ks_buf: Vec::new(), ks_pos: 0 }
    }

    fn xor_keystream(&mut self, data: &mut [byte]) {
        let mut pos = 0usize;
        while pos < data.len() {
            if self.ks_pos >= self.ks_buf.len() {
                self.ks_buf.resize(16, 0);
                self.ks_pos = 0;
                let src: slice<byte> = slice::__from_vec(self.ctr.to_vec());
                let mut dst: slice<byte> = slice::__from_vec(alloc::vec![0u8; 16]);
                self.cipher.Encrypt(&mut dst, src);
                let v = dst.__into_vec();
                self.ks_buf[..16].copy_from_slice(&v);
                // increment counter big-endian
                let mut i = 15i32;
                while i >= 0 {
                    self.ctr[i as usize] = self.ctr[i as usize].wrapping_add(1);
                    if self.ctr[i as usize] != 0 { break; }
                    i -= 1;
                }
            }
            data[pos] ^= self.ks_buf[self.ks_pos];
            self.ks_pos += 1;
            pos += 1;
        }
    }
}

// ─── Raw I/O helpers ─────────────────────────────────────────────────────

/// Read exactly `n` bytes from a `crate::net::TCPConn`.
fn read_exact_tcp(conn: &mut crate::net::TCPConn, n: usize) -> (Vec<byte>, error) {
    let mut buf: Vec<byte> = alloc::vec![0u8; n];
    let mut total = 0usize;
    while total < n {
        let mut tmp: slice<byte> = slice::__from_vec(alloc::vec![0u8; n - total]);
        let (got, err) = conn.Read(&mut tmp);
        if !err.IsNil() { return (Vec::new(), err); }
        if got == 0 { return (Vec::new(), ssh_err("ssh: unexpected EOF")); }
        let g = got as usize;
        let v = tmp.__into_vec();
        buf[total..total+g].copy_from_slice(&v[..g]);
        total += g;
    }
    (buf, errors::nil)
}

/// Write all bytes to a `crate::net::TCPConn`.
fn write_all_tcp(conn: &mut crate::net::TCPConn, data: &[byte]) -> error {
    let s: slice<byte> = slice::__from_vec(data.to_vec());
    let (_, err) = conn.Write(s);
    err
}

// ─── Packet framing ───────────────────────────────────────────────────────

struct Framing {
    seq_r: u32,
    seq_w: u32,
    cipher_r: Option<Aes128Ctr>,
    cipher_w: Option<Aes128Ctr>,
    mac_key_r: Option<Vec<byte>>,
    mac_key_w: Option<Vec<byte>>,
}

impl Framing {
    fn new() -> Self {
        Framing {
            seq_r: 0, seq_w: 0,
            cipher_r: None, cipher_w: None,
            mac_key_r: None, mac_key_w: None,
        }
    }

    /// Read one SSH binary packet.
    fn read_packet(&mut self, conn: &mut crate::net::TCPConn) -> (Vec<byte>, error) {
        // Read first 4 bytes (may be encrypted)
        let (mut hdr, err) = read_exact_tcp(conn, 4);
        if !err.IsNil() { return (Vec::new(), err); }
        if let Some(ref mut c) = self.cipher_r { c.xor_keystream(&mut hdr); }
        let (pkt_len, _) = get_u32(&hdr, 0);
        if pkt_len > 35000 || pkt_len < 5 {
            return (Vec::new(), ssh_err("ssh: implausible packet length"));
        }
        let mac_len: usize = if self.mac_key_r.is_some() { 32 } else { 0 };
        let (mut rest, err) = read_exact_tcp(conn, pkt_len as usize + mac_len);
        if !err.IsNil() { return (Vec::new(), err); }
        // Decrypt rest (not MAC)
        if let Some(ref mut c) = self.cipher_r {
            c.xor_keystream(&mut rest[..pkt_len as usize]);
        }
        // Verify MAC
        if let Some(ref mac_key) = self.mac_key_r {
            let mac_actual = &rest[pkt_len as usize..pkt_len as usize + mac_len];
            let mut mac_data: Vec<byte> = Vec::new();
            put_u32(&mut mac_data, self.seq_r);
            mac_data.extend_from_slice(&hdr);
            mac_data.extend_from_slice(&rest[..pkt_len as usize]);
            let expected = hmac_sha256(mac_key, &mac_data);
            if expected.as_slice() != mac_actual {
                return (Vec::new(), ssh_err("ssh: MAC verification failed"));
            }
        }
        self.seq_r = self.seq_r.wrapping_add(1);
        let pad_len = rest[0] as usize;
        let payload_len = (pkt_len as usize) - 1 - pad_len;
        if payload_len == 0 || 1 + payload_len > pkt_len as usize {
            return (Vec::new(), ssh_err("ssh: bad padding length"));
        }
        (rest[1..1+payload_len].to_vec(), errors::nil)
    }

    /// Write one SSH binary packet.
    fn write_packet(&mut self, conn: &mut crate::net::TCPConn, payload: &[byte]) -> error {
        let block_size: usize = if self.cipher_w.is_some() { 16 } else { 8 };
        let need = 1 + payload.len();
        let rem = need % block_size;
        let mut pad_len = if rem == 0 { block_size } else { block_size - rem };
        if pad_len < 4 { pad_len += block_size; }
        let pkt_len = (1 + payload.len() + pad_len) as u32; // goishlint:ignore GOISH005

        let mut pkt: Vec<byte> = Vec::with_capacity(4 + pkt_len as usize + 32);
        put_u32(&mut pkt, pkt_len);
        pkt.push(pad_len as byte); // goishlint:ignore GOISH005
        pkt.extend_from_slice(payload);
        for _ in 0..pad_len { pkt.push(0u8); }

        let mac: Vec<byte> = if let Some(ref mac_key) = self.mac_key_w {
            let mut mac_data: Vec<byte> = Vec::new();
            put_u32(&mut mac_data, self.seq_w);
            mac_data.extend_from_slice(&pkt);
            hmac_sha256(mac_key, &mac_data)
        } else {
            Vec::new()
        };

        if let Some(ref mut c) = self.cipher_w { c.xor_keystream(&mut pkt); }
        let err = write_all_tcp(conn, &pkt);
        if !err.IsNil() { return err; }
        if !mac.is_empty() {
            let err = write_all_tcp(conn, &mac);
            if !err.IsNil() { return err; }
        }
        self.seq_w = self.seq_w.wrapping_add(1);
        errors::nil
    }
}

// ─── HMAC-SHA2-256 helper ─────────────────────────────────────────────────

fn hmac_sha256(key: &[byte], data: &[byte]) -> Vec<byte> {
    use crate::hash::Hash as HashTrait;
    let key_slice: slice<byte> = slice::__from_vec(key.to_vec());
    let mut h = crate::crypto::hmac::New(crate::crypto::sha256::NewHash, key_slice);
    let data_slice: slice<byte> = slice::__from_vec(data.to_vec());
    let _ = io::Writer::Write(&mut h, data_slice);
    let empty: slice<byte> = slice::__from_vec(Vec::new());
    let out = h.Sum(empty);
    out.__into_vec()
}

// ─── SHA-256 helper ───────────────────────────────────────────────────────

fn sha256_hash(data: &[byte]) -> [byte; 32] {
    let s: slice<byte> = slice::__from_vec(data.to_vec());
    crate::crypto::sha256::Sum256(s)
}

// ─── DH Group 14 ──────────────────────────────────────────────────────────

fn dh_group14_p() -> BigInt {
    let mut p = BigInt::new();
    p.SetString(string::from_static(DH_GROUP14_P_HEX), 16);
    p
}

fn dh_exp(g: u64, x_bytes: &[byte], p: &BigInt) -> Vec<byte> {
    let mut base = BigInt::new();
    base.SetInt64(g as i64); // goishlint:ignore GOISH005
    let mut exp_int = BigInt::new();
    let exp_slice: slice<byte> = slice::__from_vec(x_bytes.to_vec());
    exp_int.SetBytes(exp_slice);
    let mut result = BigInt::new();
    result.Exp(&base, &exp_int, p);
    let out = result.Bytes();
    out.__into_vec()
}

fn dh_shared_secret(f_bytes: &[byte], x_bytes: &[byte], p: &BigInt) -> Vec<byte> {
    let mut f = BigInt::new();
    let f_slice: slice<byte> = slice::__from_vec(f_bytes.to_vec());
    f.SetBytes(f_slice);
    let mut x = BigInt::new();
    let x_slice: slice<byte> = slice::__from_vec(x_bytes.to_vec());
    x.SetBytes(x_slice);
    let mut result = BigInt::new();
    result.Exp(&f, &x, p);
    let out = result.Bytes();
    out.__into_vec()
}

// ─── Key derivation ───────────────────────────────────────────────────────

fn derive_key(k_mpint: &[byte], h: &[byte], letter: byte, session_id: &[byte], needed: usize) -> Vec<byte> {
    let mut out: Vec<byte> = Vec::new();
    let mut prev: Vec<byte> = Vec::new();
    while out.len() < needed {
        let mut data: Vec<byte> = Vec::new();
        data.extend_from_slice(k_mpint);
        data.extend_from_slice(h);
        if out.is_empty() {
            data.push(letter);
            data.extend_from_slice(session_id);
        } else {
            data.extend_from_slice(&prev);
        }
        let hash = sha256_hash(&data);
        prev = hash.to_vec();
        out.extend_from_slice(&hash);
    }
    out.truncate(needed);
    out
}

// ─── KEXINIT ──────────────────────────────────────────────────────────────

const KEX_ALGOS: &[&str]      = &["diffie-hellman-group14-sha256"];
const HOST_KEY_ALGOS: &[&str] = &["ssh-ed25519"];
const CIPHER_ALGOS: &[&str]   = &["aes128-ctr"];
const MAC_ALGOS: &[&str]      = &["hmac-sha2-256"];
const COMPRESS_ALGOS: &[&str] = &["none"];
const LANG_ALGOS: &[&str]     = &[];

fn build_kexinit(cookie: &[byte; 16]) -> Vec<byte> {
    let mut buf: Vec<byte> = Vec::new();
    buf.extend_from_slice(cookie);
    put_ssh_string(&mut buf, &name_list_bytes(KEX_ALGOS));
    put_ssh_string(&mut buf, &name_list_bytes(HOST_KEY_ALGOS));
    put_ssh_string(&mut buf, &name_list_bytes(CIPHER_ALGOS));
    put_ssh_string(&mut buf, &name_list_bytes(CIPHER_ALGOS));
    put_ssh_string(&mut buf, &name_list_bytes(MAC_ALGOS));
    put_ssh_string(&mut buf, &name_list_bytes(MAC_ALGOS));
    put_ssh_string(&mut buf, &name_list_bytes(COMPRESS_ALGOS));
    put_ssh_string(&mut buf, &name_list_bytes(COMPRESS_ALGOS));
    put_ssh_string(&mut buf, &name_list_bytes(LANG_ALGOS));
    put_ssh_string(&mut buf, &name_list_bytes(LANG_ALGOS));
    put_bool(&mut buf, false);
    put_u32(&mut buf, 0);
    buf
}

// ─── Ed25519 host key verification ───────────────────────────────────────

fn parse_ed25519_pubkey(blob: &[byte]) -> Option<[byte; 32]> {
    let (key_type, off) = get_ssh_string(blob, 0);
    if key_type != b"ssh-ed25519" { return None; }
    let (key_bytes, _) = get_ssh_string(blob, off);
    if key_bytes.len() != 32 { return None; }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&key_bytes);
    Some(arr)
}

fn verify_ed25519_sig(key_blob: &[byte], sig_blob: &[byte], message: &[byte]) -> bool {
    let pk_bytes = match parse_ed25519_pubkey(key_blob) {
        Some(b) => b,
        None => return false,
    };
    let (sig_type, off) = get_ssh_string(sig_blob, 0);
    if sig_type != b"ssh-ed25519" { return false; }
    let (sig_bytes, _) = get_ssh_string(sig_blob, off);
    if sig_bytes.len() != 64 { return false; }
    let pk_slice: slice<byte> = slice::__from_vec(pk_bytes.to_vec());
    let pub_key = crate::crypto::ed25519::PublicKey(pk_slice);
    let msg_slice: slice<byte> = slice::__from_vec(message.to_vec());
    let sig_slice: slice<byte> = slice::__from_vec(sig_bytes);
    crate::crypto::ed25519::Verify(&pub_key, msg_slice, sig_slice)
}

// ─── AuthMethod ───────────────────────────────────────────────────────────

pub trait AuthMethod: Send + Sync {
    fn method(&self) -> &'static str;
    fn auth_payload(&self, user: &str, session_id: &[byte]) -> Vec<byte>;
}

pub struct PasswordAuth {
    pub password: string,
}

impl AuthMethod for PasswordAuth {
    fn method(&self) -> &'static str { "password" }
    fn auth_payload(&self, user: &str, _session_id: &[byte]) -> Vec<byte> {
        let mut buf: Vec<byte> = Vec::new();
        buf.push(SSH_MSG_USERAUTH_REQUEST);
        put_ssh_string(&mut buf, user.as_bytes());
        put_ssh_string(&mut buf, b"ssh-connection");
        put_ssh_string(&mut buf, b"password");
        put_bool(&mut buf, false);
        put_ssh_string(&mut buf, self.password.as_bytes());
        buf
    }
}

pub struct PublicKeyAuth {
    pub private_key: crate::crypto::ed25519::PrivateKey,
}

impl AuthMethod for PublicKeyAuth {
    fn method(&self) -> &'static str { "publickey" }
    fn auth_payload(&self, user: &str, session_id: &[byte]) -> Vec<byte> {
        let pk = self.private_key.PublicKey();
        let pk_raw: Vec<byte> = pk.0.__into_vec();

        let mut pk_blob: Vec<byte> = Vec::new();
        put_ssh_string(&mut pk_blob, b"ssh-ed25519");
        put_ssh_string(&mut pk_blob, &pk_raw);

        // sig_data = string(session_id) || USERAUTH_REQUEST header
        let mut sig_data: Vec<byte> = Vec::new();
        put_ssh_string(&mut sig_data, session_id);
        sig_data.push(SSH_MSG_USERAUTH_REQUEST);
        put_ssh_string(&mut sig_data, user.as_bytes());
        put_ssh_string(&mut sig_data, b"ssh-connection");
        put_ssh_string(&mut sig_data, b"publickey");
        put_bool(&mut sig_data, true);
        put_ssh_string(&mut sig_data, b"ssh-ed25519");
        put_ssh_string(&mut sig_data, &pk_blob);

        let opts = crate::crypto::ed25519::Options::default();
        let mut rng = crate::crypto::rand::RandReader;
        let sig_data_slice: slice<byte> = slice::__from_vec(sig_data);
        let (sig_bytes, _) = self.private_key.Sign(&mut rng, sig_data_slice, &opts);
        let sv = sig_bytes.__into_vec();

        let mut sig_blob: Vec<byte> = Vec::new();
        put_ssh_string(&mut sig_blob, b"ssh-ed25519");
        put_ssh_string(&mut sig_blob, &sv);

        let mut buf: Vec<byte> = Vec::new();
        buf.push(SSH_MSG_USERAUTH_REQUEST);
        put_ssh_string(&mut buf, user.as_bytes());
        put_ssh_string(&mut buf, b"ssh-connection");
        put_ssh_string(&mut buf, b"publickey");
        put_bool(&mut buf, true);
        put_ssh_string(&mut buf, b"ssh-ed25519");
        put_ssh_string(&mut buf, &pk_blob);
        put_ssh_string(&mut buf, &sig_blob);
        buf
    }
}

// ─── HostKeyCallback ─────────────────────────────────────────────────────

pub type HostKeyCallback = Box<dyn Fn(&str, &[byte]) -> error + Send + Sync>;

pub fn InsecureIgnoreHostKey() -> HostKeyCallback {
    Box::new(|_addr, _key_blob| errors::nil)
}

pub fn FixedHostKey(expected: slice<byte>) -> HostKeyCallback {
    let exp_vec: Vec<byte> = expected.__into_vec();
    Box::new(move |_addr, key_blob| {
        if key_blob == exp_vec.as_slice() { errors::nil }
        else { ssh_err("ssh: host key mismatch") }
    })
}

// ─── ClientConfig ────────────────────────────────────────────────────────

pub struct ClientConfig {
    pub User: string,
    pub Auth: Vec<Box<dyn AuthMethod>>,
    pub HostKeyCallback: HostKeyCallback,
}

impl ClientConfig {
    pub fn new() -> Self {
        ClientConfig {
            User: string::from_static(""),
            Auth: Vec::new(),
            HostKeyCallback: InsecureIgnoreHostKey(),
        }
    }
}

// ─── Inner connection state ───────────────────────────────────────────────

struct ConnInner {
    conn: crate::net::TCPConn,
    framing: Framing,
    session_id: Vec<byte>,
}

impl ConnInner {
    fn send(&mut self, payload: &[byte]) -> error {
        self.framing.write_packet(&mut self.conn, payload)
    }

    fn recv(&mut self) -> (Vec<byte>, error) {
        loop {
            let (pkt, err) = self.framing.read_packet(&mut self.conn);
            if !err.IsNil() { return (Vec::new(), err); }
            if pkt.is_empty() { continue; }
            match pkt[0] {
                SSH_MSG_IGNORE => continue,
                SSH_MSG_DISCONNECT => return (Vec::new(), ssh_err("ssh: server disconnected")),
                _ => return (pkt, errors::nil),
            }
        }
    }
}

// ─── Client ──────────────────────────────────────────────────────────────

pub struct Client {
    inner: Arc<Mutex<ConnInner>>,
    next_channel: Arc<Mutex<u32>>,
}

impl Client {
    pub fn NewSession(&self) -> (Session, error) {
        let local_chan: u32 = {
            let mut nc = self.next_channel.Lock();
            let c = *nc;
            *nc = c + 1;
            c
        };
        let initial_window: u32 = 1 << 21;
        let max_packet: u32 = 1 << 15;

        let mut buf: Vec<byte> = Vec::new();
        buf.push(SSH_MSG_CHANNEL_OPEN);
        put_ssh_string(&mut buf, b"session");
        put_u32(&mut buf, local_chan);
        put_u32(&mut buf, initial_window);
        put_u32(&mut buf, max_packet);

        let err = self.inner.Lock().send(&buf);
        if !err.IsNil() {
            return (Session::dead(self.inner.clone(), local_chan), err);
        }

        loop {
            let (pkt, err) = self.inner.Lock().recv();
            if !err.IsNil() {
                return (Session::dead(self.inner.clone(), local_chan), err);
            }
            if pkt.is_empty() { continue; }
            match pkt[0] {
                SSH_MSG_CHANNEL_OPEN_CONFIRMATION => {
                    let (_, off1) = get_u32(&pkt, 1);
                    let (remote_chan, _) = get_u32(&pkt, off1);
                    return (Session { inner: self.inner.clone(), local_chan, remote_chan }, errors::nil);
                }
                SSH_MSG_CHANNEL_OPEN_FAILURE => {
                    let (code, off1) = get_u32(&pkt, 1);
                    let (reason, _) = get_ssh_string(&pkt, off1);
                    let reason_str = core::str::from_utf8(&reason).unwrap_or("?");
                    let code_s = crate::strconv::Itoa(code as int); // goishlint:ignore GOISH005
                    let mut msgv: Vec<byte> = Vec::new();
                    msgv.extend_from_slice(b"ssh: channel open failed: code=");
                    msgv.extend_from_slice(code_s.as_bytes());
                    msgv.extend_from_slice(b" reason=");
                    msgv.extend_from_slice(reason_str.as_bytes());
                    return (Session::dead(self.inner.clone(), local_chan),
                        ssh_err(string::from_bytes(&msgv)));
                }
                _ => {}
            }
        }
    }
}

// ─── Session ─────────────────────────────────────────────────────────────

pub struct Session {
    inner: Arc<Mutex<ConnInner>>,
    local_chan: u32,
    remote_chan: u32,
}

impl Session {
    fn dead(inner: Arc<Mutex<ConnInner>>, local_chan: u32) -> Self {
        Session { inner, local_chan, remote_chan: 0 }
    }

    pub fn CombinedOutput<S: Into<string>>(&mut self, cmd: S) -> (slice<byte>, error) {
        let cmd_str: string = cmd.into();
        let err = self.start_exec(cmd_str.as_ref());
        if !err.IsNil() { return (slice::__from_vec(Vec::new()), err); }
        let (data, err) = self.collect_output();
        (slice::__from_vec(data), err)
    }

    pub fn Run<S: Into<string>>(&mut self, cmd: S) -> error {
        let cmd_str: string = cmd.into();
        let err = self.start_exec(cmd_str.as_ref());
        if !err.IsNil() { return err; }
        let (_, err) = self.collect_output();
        err
    }

    fn start_exec(&mut self, cmd: &str) -> error {
        let mut buf: Vec<byte> = Vec::new();
        buf.push(SSH_MSG_CHANNEL_REQUEST);
        put_u32(&mut buf, self.remote_chan);
        put_ssh_string(&mut buf, b"exec");
        put_bool(&mut buf, true);
        put_ssh_string(&mut buf, cmd.as_bytes());
        let err = self.inner.Lock().send(&buf);
        if !err.IsNil() { return err; }
        loop {
            let (pkt, err) = self.inner.Lock().recv();
            if !err.IsNil() { return err; }
            if pkt.is_empty() { continue; }
            match pkt[0] {
                SSH_MSG_CHANNEL_SUCCESS => return errors::nil,
                SSH_MSG_CHANNEL_FAILURE => return ssh_err("ssh: exec request failed"),
                SSH_MSG_CHANNEL_WINDOW_ADJUST => {}
                _ => {}
            }
        }
    }

    fn collect_output(&mut self) -> (Vec<byte>, error) {
        let mut out: Vec<byte> = Vec::new();
        let mut exit_code: i32 = 0;
        let remote_chan = self.remote_chan;
        loop {
            let (pkt, err) = self.inner.Lock().recv();
            if !err.IsNil() { return (out, err); }
            if pkt.is_empty() { continue; }
            match pkt[0] {
                SSH_MSG_CHANNEL_DATA => {
                    let (data, _) = get_ssh_string(&pkt, 5);
                    out.extend_from_slice(&data);
                    let _ = self.send_window_adjust(remote_chan, data.len() as u32); // goishlint:ignore GOISH005
                }
                SSH_MSG_CHANNEL_EXTENDED_DATA => {
                    let (data, _) = get_ssh_string(&pkt, 9);
                    out.extend_from_slice(&data);
                    let _ = self.send_window_adjust(remote_chan, data.len() as u32); // goishlint:ignore GOISH005
                }
                SSH_MSG_CHANNEL_REQUEST => {
                    let (req_type, off) = get_ssh_string(&pkt, 5);
                    let (_, off2) = get_bool(&pkt, off);
                    if req_type == b"exit-status" {
                        let (code, _) = get_u32(&pkt, off2);
                        exit_code = code as i32; // goishlint:ignore GOISH005
                    }
                }
                SSH_MSG_CHANNEL_EOF => {}
                SSH_MSG_CHANNEL_CLOSE => {
                    let mut close_pkt: Vec<byte> = Vec::new();
                    close_pkt.push(SSH_MSG_CHANNEL_CLOSE);
                    put_u32(&mut close_pkt, remote_chan);
                    let _ = self.inner.Lock().send(&close_pkt);
                    break;
                }
                SSH_MSG_CHANNEL_WINDOW_ADJUST => {}
                _ => {}
            }
        }
        if exit_code != 0 {
            let code_s = crate::strconv::Itoa(exit_code as int); // goishlint:ignore GOISH005
            let mut msgv: Vec<byte> = Vec::new();
            msgv.extend_from_slice(b"ssh: process exited with status ");
            msgv.extend_from_slice(code_s.as_bytes());
            return (out, ssh_err(string::from_bytes(&msgv)));
        }
        (out, errors::nil)
    }

    fn send_window_adjust(&mut self, remote_chan: u32, n: u32) -> error {
        let mut buf: Vec<byte> = Vec::new();
        buf.push(SSH_MSG_CHANNEL_WINDOW_ADJUST);
        put_u32(&mut buf, remote_chan);
        put_u32(&mut buf, n);
        self.inner.Lock().send(&buf)
    }
}

// ─── Dial ────────────────────────────────────────────────────────────────

/// `ssh.Dial(network, addr, cfg)` — connect to an SSH server.
pub fn Dial<N: Into<string>, A: Into<string>>(
    network: N,
    addr: A,
    cfg: ClientConfig,
) -> (Client, error) {
    let network: string = network.into();
    let addr: string = addr.into();

    // 1. TCP connection
    let (mut conn, err) = crate::net::Dial(network.clone(), addr.clone());
    if !err.IsNil() { return (make_dead_client(), err); }

    // 2. Version exchange
    let client_version: &[byte] = b"SSH-2.0-Goish_0.1\r\n";
    let err = write_all_tcp(&mut conn, client_version);
    if !err.IsNil() { return (make_dead_client(), err); }
    let (server_version_raw, err) = read_line_lf_tcp(&mut conn, 256);
    if !err.IsNil() { return (make_dead_client(), err); }
    if !server_version_raw.starts_with(b"SSH-2.0") {
        return (make_dead_client(), ssh_err("ssh: server does not speak SSH 2.0"));
    }

    let mut framing = Framing::new();

    // 3. KEXINIT
    let mut client_cookie = [0u8; 16];
    {
        let mut s: slice<byte> = slice::__from_vec(client_cookie.to_vec());
        let mut rng = crate::crypto::rand::RandReader;
        let _ = io::Reader::Read(&mut rng, &mut s);
        let v = s.__into_vec();
        client_cookie.copy_from_slice(&v);
    }
    let client_kexinit = build_kexinit(&client_cookie);
    let mut our_kexinit_pkt: Vec<byte> = Vec::new();
    our_kexinit_pkt.push(SSH_MSG_KEXINIT);
    our_kexinit_pkt.extend_from_slice(&client_kexinit);
    let err = framing.write_packet(&mut conn, &our_kexinit_pkt);
    if !err.IsNil() { return (make_dead_client(), err); }

    let (server_kexinit_pkt, err) = framing.read_packet(&mut conn);
    if !err.IsNil() { return (make_dead_client(), err); }
    if server_kexinit_pkt.is_empty() || server_kexinit_pkt[0] != SSH_MSG_KEXINIT {
        return (make_dead_client(), ssh_err("ssh: expected KEXINIT"));
    }
    let i_c = our_kexinit_pkt.clone();
    let i_s = server_kexinit_pkt.clone();

    // 4. DH KEX
    let mut x_bytes = [0u8; 32];
    {
        let mut s: slice<byte> = slice::__from_vec(x_bytes.to_vec());
        let mut rng = crate::crypto::rand::RandReader;
        let _ = io::Reader::Read(&mut rng, &mut s);
        let v = s.__into_vec();
        x_bytes.copy_from_slice(&v);
    }
    let p = dh_group14_p();
    let e_bytes = dh_exp(2, &x_bytes, &p);

    let mut kexdh_init: Vec<byte> = Vec::new();
    kexdh_init.push(SSH_MSG_KEXDH_INIT);
    put_mpint(&mut kexdh_init, &e_bytes);
    let err = framing.write_packet(&mut conn, &kexdh_init);
    if !err.IsNil() { return (make_dead_client(), err); }

    let (kexdh_reply, err) = framing.read_packet(&mut conn);
    if !err.IsNil() { return (make_dead_client(), err); }
    if kexdh_reply.is_empty() || kexdh_reply[0] != SSH_MSG_KEXDH_REPLY {
        return (make_dead_client(), ssh_err("ssh: expected KEXDH_REPLY"));
    }

    let (ks_blob, off1) = get_ssh_string(&kexdh_reply, 1);
    let (f_mpint_raw, off2) = get_mpint(&kexdh_reply, off1);
    let (sig_blob, _) = get_ssh_string(&kexdh_reply, off2);

    let k_bytes = dh_shared_secret(&f_mpint_raw, &x_bytes, &p);

    // Compute H
    let mut hash_input: Vec<byte> = Vec::new();
    let vc = trim_crlf(b"SSH-2.0-Goish_0.1");
    let vs = trim_crlf(&server_version_raw);
    put_ssh_string(&mut hash_input, &vc);
    put_ssh_string(&mut hash_input, &vs);
    put_ssh_string(&mut hash_input, &i_c);
    put_ssh_string(&mut hash_input, &i_s);
    put_ssh_string(&mut hash_input, &ks_blob);
    put_mpint(&mut hash_input, &e_bytes);
    put_mpint(&mut hash_input, &f_mpint_raw);
    put_mpint(&mut hash_input, &k_bytes);
    let h = sha256_hash(&hash_input);
    let h_slice = h.to_vec();

    if !verify_ed25519_sig(&ks_blob, &sig_blob, &h_slice) {
        return (make_dead_client(), ssh_err("ssh: host key signature verification failed"));
    }

    let addr_str = addr.as_ref();
    let err = (cfg.HostKeyCallback)(addr_str, &ks_blob);
    if !err.IsNil() { return (make_dead_client(), err); }

    let session_id = h_slice.clone();

    // Send NEWKEYS
    let err = framing.write_packet(&mut conn, &[SSH_MSG_NEWKEYS]);
    if !err.IsNil() { return (make_dead_client(), err); }

    // Read NEWKEYS
    let (newkeys_reply, err) = framing.read_packet(&mut conn);
    if !err.IsNil() { return (make_dead_client(), err); }
    if newkeys_reply.is_empty() || newkeys_reply[0] != SSH_MSG_NEWKEYS {
        return (make_dead_client(), ssh_err("ssh: expected NEWKEYS"));
    }

    // 5. Derive keys
    let mut k_mpint_buf: Vec<byte> = Vec::new();
    put_mpint(&mut k_mpint_buf, &k_bytes);

    let iv_c2s  = derive_key(&k_mpint_buf, &h_slice, b'A', &session_id, 16);
    let iv_s2c  = derive_key(&k_mpint_buf, &h_slice, b'B', &session_id, 16);
    let key_c2s = derive_key(&k_mpint_buf, &h_slice, b'C', &session_id, 16);
    let key_s2c = derive_key(&k_mpint_buf, &h_slice, b'D', &session_id, 16);
    let mac_c2s = derive_key(&k_mpint_buf, &h_slice, b'E', &session_id, 32);
    let mac_s2c = derive_key(&k_mpint_buf, &h_slice, b'F', &session_id, 32);

    framing.cipher_w   = Some(Aes128Ctr::new(&key_c2s, &iv_c2s));
    framing.mac_key_w  = Some(mac_c2s);
    framing.cipher_r   = Some(Aes128Ctr::new(&key_s2c, &iv_s2c));
    framing.mac_key_r  = Some(mac_s2c);

    // 6. Service request
    let mut svc_req: Vec<byte> = Vec::new();
    svc_req.push(SSH_MSG_SERVICE_REQUEST);
    put_ssh_string(&mut svc_req, b"ssh-userauth");
    let err = framing.write_packet(&mut conn, &svc_req);
    if !err.IsNil() { return (make_dead_client(), err); }

    let (svc_accept, err) = framing.read_packet(&mut conn);
    if !err.IsNil() { return (make_dead_client(), err); }
    if svc_accept.is_empty() || svc_accept[0] != SSH_MSG_SERVICE_ACCEPT {
        return (make_dead_client(), ssh_err("ssh: service request rejected"));
    }

    // 7. Authentication
    let user_str = cfg.User.as_ref();
    let mut auth_ok = false;
    let mut ci = ConnInner { conn, framing, session_id: session_id.clone() };

    for method in &cfg.Auth {
        let payload = method.auth_payload(user_str, &session_id);
        let err = ci.send(&payload);
        if !err.IsNil() { return (make_dead_client(), err); }
        loop {
            let (auth_reply, err) = ci.recv();
            if !err.IsNil() { return (make_dead_client(), err); }
            if auth_reply.is_empty() { continue; }
            match auth_reply[0] {
                SSH_MSG_USERAUTH_SUCCESS => { auth_ok = true; break; }
                SSH_MSG_USERAUTH_FAILURE => { break; }
                SSH_MSG_USERAUTH_BANNER => {}
                _ => { break; }
            }
        }
        if auth_ok { break; }
    }
    if !auth_ok {
        return (make_dead_client(), ssh_err("ssh: authentication failed"));
    }

    let client = Client {
        inner: Arc::new(Mutex::new(ci)),
        next_channel: Arc::new(Mutex::new(0u32)),
    };
    (client, errors::nil)
}

fn make_dead_client() -> Client {
    // Build a dead TCPConn via a dead()-equivalent: dial to a port that
    // immediately fails. Instead, use a placeholder by constructing
    // ConnInner with a dead conn (fd=-1).
    // Since TCPConn::dead() is pub(crate), we can't use it directly.
    // Instead, use a Dial that fails and recover.
    // We create a real (invalid) TCPConn by doing a failed Dial.
    let (dead_conn, _) = crate::net::Dial("tcp", "0.0.0.0:0");
    // dead_conn is invalid but satisfies the type.
    Client {
        inner: Arc::new(Mutex::new(ConnInner {
            conn: dead_conn,
            framing: Framing::new(),
            session_id: Vec::new(),
        })),
        next_channel: Arc::new(Mutex::new(0u32)),
    }
}

// ─── I/O helpers for version exchange ────────────────────────────────────

fn read_line_lf_tcp(conn: &mut crate::net::TCPConn, max_len: usize) -> (Vec<byte>, error) {
    let mut line: Vec<byte> = Vec::new();
    loop {
        let (b, err) = read_exact_tcp(conn, 1);
        if !err.IsNil() { return (Vec::new(), err); }
        if b[0] == b'\n' { break; }
        if b[0] != b'\r' { line.push(b[0]); }
        if line.len() > max_len { return (Vec::new(), ssh_err("ssh: version line too long")); }
    }
    (line, errors::nil)
}

fn trim_crlf(b: &[byte]) -> Vec<byte> {
    let mut v = b.to_vec();
    while v.ends_with(b"\r") || v.ends_with(b"\n") { v.pop(); }
    v
}

// ─── Public constructor helpers ───────────────────────────────────────────

pub fn Password<S: Into<string>>(pw: S) -> Box<dyn AuthMethod> {
    Box::new(PasswordAuth { password: pw.into() })
}

pub fn PublicKeys(key: crate::crypto::ed25519::PrivateKey) -> Box<dyn AuthMethod> {
    Box::new(PublicKeyAuth { private_key: key })
}

// ─── Unit test helpers ────────────────────────────────────────────────────

pub fn test_kexinit_roundtrip() -> bool {
    let cookie = [0x42u8; 16];
    let payload = build_kexinit(&cookie);
    if payload.len() < 16 { return false; }
    for i in 0..16 { if payload[i] != 0x42 { return false; } }
    true
}

pub fn test_dh_group14_small_exp() -> bool {
    let p = dh_group14_p();
    let x_bytes = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]; // x = 1
    let e = dh_exp(2, &x_bytes, &p);
    e == [0x02u8].as_slice()
}

pub fn test_key_derivation() -> bool {
    let k_bytes = [0u8; 32];
    let mut k_mpint: Vec<byte> = Vec::new();
    put_mpint(&mut k_mpint, &k_bytes);
    let h = [0xABu8; 32];
    let session_id = h.to_vec();
    let key_e = derive_key(&k_mpint, &h, b'E', &session_id, 32);
    let key_f = derive_key(&k_mpint, &h, b'F', &session_id, 32);
    key_e.len() == 32 && key_f.len() == 32 && key_e != key_f
}

pub fn test_packet_framing() -> bool {
    let key = [0u8; 16];
    let iv = [0u8; 16];
    let mut enc = Aes128Ctr::new(&key, &iv);
    let mut dec = Aes128Ctr::new(&key, &iv);
    let original = [0x01u8, 0x02, 0x03, 0x04, 0x05];
    let mut buf = original.clone();
    enc.xor_keystream(&mut buf);
    dec.xor_keystream(&mut buf);
    buf == original
}

pub fn test_hmac_sha256() -> bool {
    let key = [0x0bu8; 20];
    let data = b"Hi There";
    let mac = hmac_sha256(&key, data);
    mac.len() == 32
}

pub fn test_mpint_encoding() -> bool {
    let mut buf: Vec<byte> = Vec::new();
    put_mpint(&mut buf, &[0x80u8, 0x00u8]); // high bit set, needs zero prefix
    // Result: [0,0,0,3, 0x00, 0x80, 0x00]
    // buf[0..4] = big-endian length = 3
    // buf[4] = 0x00 (zero prefix because high bit of 0x80 is set)
    // buf[5] = 0x80
    // buf[6] = 0x00
    buf.len() == 7 && buf[3] == 3 && buf[4] == 0x00 && buf[5] == 0x80
}
