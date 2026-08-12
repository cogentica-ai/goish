// go: file crypto/internal/fips140/tls13/tls13.go decls: ExpandLabel, extract, deriveSecret, NewEarlySecret, EarlySecret.ResumptionBinderKey, EarlySecret.ClientEarlyTrafficSecret, EarlySecret.HandshakeSecret, HandshakeSecret.ClientHandshakeTrafficSecret, HandshakeSecret.ServerHandshakeTrafficSecret, HandshakeSecret.MasterSecret, MasterSecret.ClientApplicationTrafficSecret, MasterSecret.ServerApplicationTrafficSecret, MasterSecret.ResumptionMasterSecret, MasterSecret.ExporterMasterSecret, EarlySecret.EarlyExporterMasterSecret, ExporterMasterSecret.Exporter, TestingOnlyExporterSecret
//
// crypto/internal/fips140/tls13 — the TLS 1.3 key schedule of RFC 8446
// §7.1, allowed by FIPS 140-3 IG 2.4.B Resolution 7.
//
// We don't set the service indicator in this package but we delegate that
// to the underlying functions because the TLS 1.3 KDF does not have a
// standard of its own.
//
// Deviations from tls13[go] @ Go 1.25.5:
//
//   * Go's `[H hash.Hash](hash func() H, …)` generic collapses to the
//     `hash::HashFunc` factory that goish's
//     `hkdf`/`hmac` already take, so `NewEarlySecret`'s
//     `func() hash.Hash { return h() }` re-wrap is the identity here and
//     the field simply stores `h`.
//   * `hash.Hash` is a composite goish interface (it embeds
//     `io::Writer`), which means it has no nil sentinel — see AGENTS.md
//     §9a. The nilable `transcript hash.Hash` parameter is therefore
//     spelled `Option<&(dyn Hash + Send + Sync + 'static)>`, and Go's
//     nilable `newSecret []byte` in `extract` is an empty slice.

#![allow(non_snake_case, non_upper_case_globals)]
#![allow(non_camel_case_types)] // Go names (hashFn mirrors `func() hash.Hash`)

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::crypto::internal::fips140::hkdf;
use crate::crypto::internal::fips140deps::byteorder;
use crate::goslice::slice;
use crate::gostring::string;
use crate::hash::{Hash, HashFunc, IntoHashFunc};
use crate::io;
use crate::types::{byte, int};
use crate::append;

/// The hash factory every key-schedule stage carries. Go spells it
/// `func() hash.Hash`.
type hashFn = HashFunc;

// go: none — goish spells Go's untyped `nil` []byte argument as an
// empty slice; this is the shared constructor for it.
fn empty() -> slice<byte> {
    return slice::__from_vec(Vec::new());
}

// go: sdk 1.25.5 crypto/internal/fips140/tls13/tls13.go:19-40 ExpandLabel
/// `tls13.ExpandLabel(hash, secret, label, context, length)` —
/// HKDF-Expand-Label from RFC 8446 §7.1.
pub fn ExpandLabel<L: Into<string>>(
    hash: impl IntoHashFunc,
    secret: slice<byte>,
    label: L,
    context: slice<byte>,
    length: int,
) -> slice<byte> {
    let label = label.into();
    // Go: if len("tls13 ")+len(label) > 255 || len(context) > 255 { panic(…) }
    //
    // It should be impossible for this to panic: labels are fixed
    // strings, and context is either a fixed-length computed hash, or
    // parsed from a field which has the same length limitation.
    //
    // Another reasonable approach might be to return a randomized slice
    // if we encounter an error, which would break the connection, but
    // avoid panicking. This would perhaps be safer but significantly
    // more confusing to users.
    if 6 + label.Len() > 255 || context.Len() > 255 {
        panic!("tls13: label or context too long");
    }

    // Go: hkdfLabel := make([]byte, 0, 2+1+len("tls13 ")+len(label)+1+len(context))
    let hkdfLabel = slice::__from_vec(Vec::with_capacity(
        2 + 1 + 6 + (label.Len() as usize) + 1 + (context.Len() as usize),
    ));
    // Go: hkdfLabel = byteorder.BEAppendUint16(hkdfLabel, uint16(length))
    let hkdfLabel = byteorder::BEAppendUint16(hkdfLabel, crate::uint16(length));
    // Go: hkdfLabel = append(hkdfLabel, byte(len("tls13 ")+len(label)))
    let hkdfLabel = append!(hkdfLabel, crate::byte(6 + label.Len()));
    // Go: hkdfLabel = append(hkdfLabel, "tls13 "...)
    let hkdfLabel = append!(hkdfLabel, crate::bytes("tls13 ")...);
    // Go: hkdfLabel = append(hkdfLabel, label...)
    let hkdfLabel = append!(hkdfLabel, crate::bytes(label.clone())...);
    // Go: hkdfLabel = append(hkdfLabel, byte(len(context)))
    let hkdfLabel = append!(hkdfLabel, crate::byte(context.Len()));
    // Go: hkdfLabel = append(hkdfLabel, context...)
    let hkdfLabel = append!(hkdfLabel, context...);

    // Go: return hkdf.Expand(hash, secret, string(hkdfLabel), length)
    let raw: &[byte] = &hkdfLabel;
    return hkdf::Expand(hash, secret, string::from_bytes(raw), length);
}

// go: sdk 1.25.5 crypto/internal/fips140/tls13/tls13.go:42-47 extract
/// Go: `func extract[H](hash func() H, newSecret, currentSecret []byte)`.
/// A nil `newSecret` becomes a zero string of the hash's output length.
fn extract(hash: hashFn, newSecret: slice<byte>, currentSecret: slice<byte>) -> slice<byte> {
    // Go: if newSecret == nil { newSecret = make([]byte, hash().Size()) }
    let newSecret = if newSecret.Len() == 0 {
        let size = hash.Call().Size();
        slice::__from_vec(alloc::vec![0u8; size as usize])
    } else {
        newSecret
    };
    // Go: return hkdf.Extract(hash, newSecret, currentSecret)
    return hkdf::Extract(hash, newSecret, currentSecret);
}

// go: sdk 1.25.5 crypto/internal/fips140/tls13/tls13.go:49-54 deriveSecret
/// Go: `func deriveSecret[H](hash func() H, secret []byte, label string,
/// transcript hash.Hash) []byte`. A nil `transcript` is a fresh, empty
/// hash — i.e. Transcript-Hash("").
fn deriveSecret(
    hash: impl IntoHashFunc,
    secret: slice<byte>,
    label: &'static str,
    transcript: Option<&(dyn Hash + Send + Sync + 'static)>,
) -> slice<byte> {
    let hash = hash.into_hash_func();
    // Go: if transcript == nil { transcript = hash() }
    let fresh: Option<Box<dyn Hash + Send + Sync>> = match transcript {
        Some(_) => None,
        None => Some(hash.Call()),
    };
    let transcript: &(dyn Hash + Send + Sync) = match transcript {
        Some(t) => t,
        None => &**fresh.as_ref().unwrap(),
    };
    // Go: return ExpandLabel(hash, secret, label, transcript.Sum(nil),
    //                        transcript.Size())
    return ExpandLabel(
        hash,
        secret,
        string::from_static(label),
        transcript.Sum(empty()),
        transcript.Size(),
    );
}

// Go: tls13.go:56-66 — the RFC 8446 §7.1 label constants.
const resumptionBinderLabel: &str = "res binder";
const clientEarlyTrafficLabel: &str = "c e traffic";
const clientHandshakeTrafficLabel: &str = "c hs traffic";
const serverHandshakeTrafficLabel: &str = "s hs traffic";
const clientApplicationTrafficLabel: &str = "c ap traffic";
const serverApplicationTrafficLabel: &str = "s ap traffic";
const earlyExporterLabel: &str = "e exp master";
const exporterLabel: &str = "exp master";
const resumptionLabel: &str = "res master";

// Go: tls13.go:68-71
//   type EarlySecret struct { secret []byte; hash func() hash.Hash }
/// The Early Secret stage of the key schedule.
pub struct EarlySecret {
    secret: slice<byte>,
    hash: hashFn,
}

// Go: tls13.go:90-93
//   type HandshakeSecret struct { secret []byte; hash func() hash.Hash }
/// The Handshake Secret stage of the key schedule.
pub struct HandshakeSecret {
    secret: slice<byte>,
    hash: hashFn,
}

// Go: tls13.go:115-118
//   type MasterSecret struct { secret []byte; hash func() hash.Hash }
/// The Master Secret stage of the key schedule.
pub struct MasterSecret {
    secret: slice<byte>,
    hash: hashFn,
}

// Go: tls13.go:146-149
//   type ExporterMasterSecret struct { secret []byte; hash func() hash.Hash }
/// The exporter_master_secret, from which RFC 8446 §7.5 exporters derive.
pub struct ExporterMasterSecret {
    secret: slice<byte>,
    hash: hashFn,
}

// go: sdk 1.25.5 crypto/internal/fips140/tls13/tls13.go:73-78 NewEarlySecret
/// `tls13.NewEarlySecret(h, psk)` — enter the key schedule at the Early
/// Secret with the given pre-shared key. A nil PSK is a zero string.
pub fn NewEarlySecret(h: impl IntoHashFunc, psk: slice<byte>) -> EarlySecret {
    let h = h.into_hash_func();
    // Go: return &EarlySecret{ secret: extract(h, psk, nil),
    //                          hash: func() hash.Hash { return h() } }
    return EarlySecret {
        secret: extract(h.clone(), psk, empty()),
        hash: h,
    };
}

impl EarlySecret {
    // go: sdk 1.25.5 crypto/internal/fips140/tls13/tls13.go:80-82 EarlySecret.ResumptionBinderKey
    /// Derive the binder_key.
    pub fn ResumptionBinderKey(&self) -> slice<byte> {
        // Go: return deriveSecret(s.hash, s.secret, resumptionBinderLabel, nil)
        return deriveSecret(
            self.hash.clone(),
            self.secret.clone(),
            resumptionBinderLabel,
            None,
        );
    }

    // go: sdk 1.25.5 crypto/internal/fips140/tls13/tls13.go:84-88 EarlySecret.ClientEarlyTrafficSecret
    /// Derive the client_early_traffic_secret from the early secret and
    /// the transcript up to the ClientHello.
    pub fn ClientEarlyTrafficSecret(
        &self,
        transcript: &(dyn Hash + Send + Sync + 'static),
    ) -> slice<byte> {
        // Go: return deriveSecret(s.hash, s.secret, clientEarlyTrafficLabel, transcript)
        return deriveSecret(
            self.hash.clone(),
            self.secret.clone(),
            clientEarlyTrafficLabel,
            Some(transcript),
        );
    }

    // go: sdk 1.25.5 crypto/internal/fips140/tls13/tls13.go:95-101 EarlySecret.HandshakeSecret
    /// Advance to the Handshake Secret with the (EC)DHE shared secret.
    pub fn HandshakeSecret(&self, sharedSecret: slice<byte>) -> HandshakeSecret {
        // Go: derived := deriveSecret(s.hash, s.secret, "derived", nil)
        let derived = deriveSecret(self.hash.clone(), self.secret.clone(), "derived", None);
        // Go: return &HandshakeSecret{ secret: extract(s.hash, sharedSecret, derived),
        //                              hash: s.hash }
        return HandshakeSecret {
            secret: extract(self.hash.clone(), sharedSecret, derived),
            hash: self.hash.clone(),
        };
    }

    // go: sdk 1.25.5 crypto/internal/fips140/tls13/tls13.go:160-167 EarlySecret.EarlyExporterMasterSecret
    /// Derive the early exporter_master_secret from the early secret and
    /// the transcript up to the ClientHello.
    pub fn EarlyExporterMasterSecret(
        &self,
        transcript: &(dyn Hash + Send + Sync + 'static),
    ) -> ExporterMasterSecret {
        // Go: return &ExporterMasterSecret{
        //         secret: deriveSecret(s.hash, s.secret, earlyExporterLabel, transcript),
        //         hash: s.hash }
        return ExporterMasterSecret {
            secret: deriveSecret(
                self.hash.clone(),
                self.secret.clone(),
                earlyExporterLabel,
                Some(transcript),
            ),
            hash: self.hash.clone(),
        };
    }
}

impl HandshakeSecret {
    // go: sdk 1.25.5 crypto/internal/fips140/tls13/tls13.go:103-107 HandshakeSecret.ClientHandshakeTrafficSecret
    /// Derive the client_handshake_traffic_secret from the handshake
    /// secret and the transcript up to the ServerHello.
    pub fn ClientHandshakeTrafficSecret(
        &self,
        transcript: &(dyn Hash + Send + Sync + 'static),
    ) -> slice<byte> {
        // Go: return deriveSecret(s.hash, s.secret, clientHandshakeTrafficLabel, transcript)
        return deriveSecret(
            self.hash.clone(),
            self.secret.clone(),
            clientHandshakeTrafficLabel,
            Some(transcript),
        );
    }

    // go: sdk 1.25.5 crypto/internal/fips140/tls13/tls13.go:109-113 HandshakeSecret.ServerHandshakeTrafficSecret
    /// Derive the server_handshake_traffic_secret from the handshake
    /// secret and the transcript up to the ServerHello.
    pub fn ServerHandshakeTrafficSecret(
        &self,
        transcript: &(dyn Hash + Send + Sync + 'static),
    ) -> slice<byte> {
        // Go: return deriveSecret(s.hash, s.secret, serverHandshakeTrafficLabel, transcript)
        return deriveSecret(
            self.hash.clone(),
            self.secret.clone(),
            serverHandshakeTrafficLabel,
            Some(transcript),
        );
    }

    // go: sdk 1.25.5 crypto/internal/fips140/tls13/tls13.go:120-126 HandshakeSecret.MasterSecret
    /// Advance to the Master Secret.
    pub fn MasterSecret(&self) -> MasterSecret {
        // Go: derived := deriveSecret(s.hash, s.secret, "derived", nil)
        let derived = deriveSecret(self.hash.clone(), self.secret.clone(), "derived", None);
        // Go: return &MasterSecret{ secret: extract(s.hash, nil, derived), hash: s.hash }
        return MasterSecret {
            secret: extract(self.hash.clone(), empty(), derived),
            hash: self.hash.clone(),
        };
    }
}

impl MasterSecret {
    // go: sdk 1.25.5 crypto/internal/fips140/tls13/tls13.go:128-132 MasterSecret.ClientApplicationTrafficSecret
    /// Derive the client_application_traffic_secret_0 from the master
    /// secret and the transcript up to the server Finished.
    pub fn ClientApplicationTrafficSecret(
        &self,
        transcript: &(dyn Hash + Send + Sync + 'static),
    ) -> slice<byte> {
        // Go: return deriveSecret(s.hash, s.secret, clientApplicationTrafficLabel, transcript)
        return deriveSecret(
            self.hash.clone(),
            self.secret.clone(),
            clientApplicationTrafficLabel,
            Some(transcript),
        );
    }

    // go: sdk 1.25.5 crypto/internal/fips140/tls13/tls13.go:134-138 MasterSecret.ServerApplicationTrafficSecret
    /// Derive the server_application_traffic_secret_0 from the master
    /// secret and the transcript up to the server Finished.
    pub fn ServerApplicationTrafficSecret(
        &self,
        transcript: &(dyn Hash + Send + Sync + 'static),
    ) -> slice<byte> {
        // Go: return deriveSecret(s.hash, s.secret, serverApplicationTrafficLabel, transcript)
        return deriveSecret(
            self.hash.clone(),
            self.secret.clone(),
            serverApplicationTrafficLabel,
            Some(transcript),
        );
    }

    // go: sdk 1.25.5 crypto/internal/fips140/tls13/tls13.go:140-144 MasterSecret.ResumptionMasterSecret
    /// Derive the resumption_master_secret from the master secret and the
    /// transcript up to the client Finished.
    pub fn ResumptionMasterSecret(
        &self,
        transcript: &(dyn Hash + Send + Sync + 'static),
    ) -> slice<byte> {
        // Go: return deriveSecret(s.hash, s.secret, resumptionLabel, transcript)
        return deriveSecret(
            self.hash.clone(),
            self.secret.clone(),
            resumptionLabel,
            Some(transcript),
        );
    }

    // go: sdk 1.25.5 crypto/internal/fips140/tls13/tls13.go:151-158 MasterSecret.ExporterMasterSecret
    /// Derive the exporter_master_secret from the master secret and the
    /// transcript up to the server Finished.
    pub fn ExporterMasterSecret(
        &self,
        transcript: &(dyn Hash + Send + Sync + 'static),
    ) -> ExporterMasterSecret {
        // Go: return &ExporterMasterSecret{
        //         secret: deriveSecret(s.hash, s.secret, exporterLabel, transcript),
        //         hash: s.hash }
        return ExporterMasterSecret {
            secret: deriveSecret(
                self.hash.clone(),
                self.secret.clone(),
                exporterLabel,
                Some(transcript),
            ),
            hash: self.hash.clone(),
        };
    }
}

impl ExporterMasterSecret {
    // go: sdk 1.25.5 crypto/internal/fips140/tls13/tls13.go:169-174 ExporterMasterSecret.Exporter
    /// `ems.Exporter(label, context, length)` — RFC 8446 §7.5 keying
    /// material exporter.
    pub fn Exporter<L: Into<string>>(
        &self,
        label: L,
        context: slice<byte>,
        length: int,
    ) -> slice<byte> {
        // Go: secret := deriveSecret(s.hash, s.secret, label, nil)
        //
        // Unlike every other call site the label here is caller-supplied,
        // so it cannot be a `&'static str`; deriveSecret's body is
        // inlined for that one parameter.
        let label = label.into();
        let fresh = self.hash.Call();
        let secret = ExpandLabel(
            self.hash.clone(),
            self.secret.clone(),
            label,
            fresh.Sum(empty()),
            fresh.Size(),
        );
        // Go: h := s.hash(); h.Write(context)
        let mut h = self.hash.Call();
        let _ = io::Writer::Write(&mut h, context);
        // Go: return ExpandLabel(s.hash, secret, "exporter", h.Sum(nil), length)
        return ExpandLabel(
            self.hash.clone(),
            secret,
            string::from_static("exporter"),
            h.Sum(empty()),
            length,
        );
    }
}

// go: sdk 1.25.5 crypto/internal/fips140/tls13/tls13.go:176-178 TestingOnlyExporterSecret
/// Go: `func TestingOnlyExporterSecret(s *ExporterMasterSecret) []byte`.
pub fn TestingOnlyExporterSecret(s: &ExporterMasterSecret) -> slice<byte> {
    // Go: return s.secret
    return s.secret.clone();
}
