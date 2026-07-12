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

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::errors::{self, error};
use crate::goslice::slice;
use crate::gostring::string;
use crate::sync::Mutex;
use crate::types::{byte, int};

pub mod record;
pub mod key_schedule;
pub mod handshake_client_tls13;
pub mod session;
mod handshake_client;

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
}

// Common TLS protocol-version constants.
pub const VersionTLS10: u16 = 0x0301;
pub const VersionTLS11: u16 = 0x0302;
pub const VersionTLS12: u16 = 0x0303;
pub const VersionTLS13: u16 = 0x0304;

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
            crate::fmt::Printf!("[tls-debug] plaintext TLS Alert: level=%d desc=%d\n",
                if frag.is_empty() { 0i64 } else { frag[0] as i64 }, desc as i64);
            if desc == 0 {
                return (0, crate::io::EOF.into());
            }
            return (0, crate::errors::New("tls: received alert from server"));
        }

        let plaintext = {
            let mut st = self.state.Lock();
            let seq = st.server_seq;
            st.server_seq += 1;
            crate::fmt::Printf!("[tls-debug] conn.Read: suite=0x%04x is_tls13=%v rtype=%d seq=%d frag_len=%d\n",
                st.keys.suite as u64, st.keys.is_tls13, rtype as i64, seq, frag.len() as i64);
            if st.keys.is_tls13 {
                // TLS 1.3: decrypt inner content
                use handshake_client_tls13::tls13_decrypt_record_suite;
                let tks = key_schedule::TrafficKeys {
                    key: st.keys.tls13_server_key[..tls13_key_len(&st.keys)].to_vec(),
                    iv: st.keys.tls13_server_iv.to_vec(),
                };
                let (inner, inner_type, derr) = tls13_decrypt_record_suite(&tks, seq, &frag, st.keys.suite);
                if !derr.IsNil() { return (0, derr); }
                // inner_type is the real content type:
                // 22 = RECORD_HANDSHAKE (post-handshake, e.g. NewSessionTicket) → skip
                // 21 = RECORD_ALERT (encrypted alert, e.g. close_notify) → return EOF
                // 23 = RECORD_APPLICATION → return data
                crate::fmt::Printf!("[tls-debug] conn.Read: inner_type=%d inner_len=%d\n",
                    inner_type as i64, inner.len() as i64);
                if inner_type == record::RECORD_HANDSHAKE {
                    let msg_type = if inner.is_empty() { 0u8 } else { inner[0] };
                    crate::fmt::Printf!("[tls-debug] conn.Read: post-handshake msg type=%d\n",
                        msg_type as i64);
                    if msg_type == 24 {
                        // KeyUpdate (RFC 8446 §4.6.3): update server application traffic keys.
                        // KeyUpdate body: type(1) + len(3) + request_update(1) = 5 bytes.
                        // Derive new server_app_secret via HKDF-Expand-Label(..., "traffic upd", ...).
                        let suite_id = st.keys.suite;
                        if let Some(cs) = key_schedule::cipher_suite_tls13(suite_id) {
                            let old_secret = st.keys.tls13_server_app_secret.clone();
                            if !old_secret.is_empty() {
                                let new_secret = key_schedule::next_traffic_secret(cs.hash_fn, &old_secret);
                                let new_keys = key_schedule::traffic_keys(cs.hash_fn, &new_secret, cs.key_len);
                                let key_len = new_keys.key.len().min(32);
                                let iv_len = new_keys.iv.len().min(12);
                                st.keys.tls13_server_key = [0u8; 32];
                                st.keys.tls13_server_key[..key_len].copy_from_slice(&new_keys.key[..key_len]);
                                st.keys.tls13_server_iv = [0u8; 12];
                                st.keys.tls13_server_iv[..iv_len].copy_from_slice(&new_keys.iv[..iv_len]);
                                st.keys.tls13_server_app_secret = new_secret;
                                st.server_seq = 0;
                                crate::fmt::Printf!("[tls-debug] KeyUpdate: rotated server app keys, seq reset to 0\n");
                            } else {
                                crate::fmt::Printf!("[tls-debug] KeyUpdate: server_app_secret is empty, cannot rotate\n");
                            }
                        } else {
                            crate::fmt::Printf!("[tls-debug] KeyUpdate: unknown suite 0x%04x, skipping key rotation\n",
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
                                        crate::fmt::Printf!("[tls-debug] NewSessionTicket: stored for %s (lifetime=%ds, ticket_len=%d)\n",
                                            sn_str,
                                            nst.ticket_lifetime as i64,
                                            state.ticket.len() as i64);
                                        session::put(server_name, state);
                                    } else {
                                        crate::fmt::Printf!("[tls-debug] NewSessionTicket: unknown suite 0x%04x, dropping\n",
                                            suite_id as u64);
                                    }
                                } else {
                                    crate::fmt::Printf!("[tls-debug] NewSessionTicket: no resumption_master_secret, dropping\n");
                                }
                                return Conn::Read(self, b);
                            }
                            None => {
                                crate::fmt::Printf!("[tls-debug] NewSessionTicket: parse failed (len=%d)\n",
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
                    crate::fmt::Printf!("[tls-debug] encrypted alert level=%d desc=%d\n",
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
    pub fn Write(&mut self, b: &[byte]) -> (int, error) {
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

        let wire = {
            let mut st = self.state.Lock();
            let seq = st.client_seq;
            st.client_seq += 1;
            let wire_s = if st.keys.is_tls13 {
                use handshake_client_tls13::tls13_encrypt_record_suite;
                let tks = key_schedule::TrafficKeys {
                    key: st.keys.tls13_client_key[..tls13_key_len(&st.keys)].to_vec(),
                    iv: st.keys.tls13_client_iv.to_vec(),
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

    /// `(*tls.Conn).SetDeadline(t)` — forward deadline to the underlying TCP conn.
    /// This is NOT part of Go's tls.Conn public API (Go uses context cancellation
    /// instead) but we expose it as a Goish extension so the HTTP Transport can
    /// apply per-request timeouts to HTTPS connections.
    pub fn SetDeadline(&self, t: crate::time::Time) -> error {
        let conn_guard = self.inner_conn.Lock();
        (**conn_guard).SetDeadline(t)
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
