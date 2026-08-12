// go: file crypto/tls/ech.go decls: echConfigErr.Error, parseECHConfig, parseECHConfigList
//
// crypto/tls — Encrypted Client Hello (draft-ietf-tls-esni), config
// parsing.
//
// **Partial port.** ech.go is 668 lines; what is here is the ECHConfig
// wire parser, which depends on nothing but cryptobyte. The rest —
// pickECHConfig, encodeInnerClientHello, the HPKE sealing and the
// retry-config path — hangs on the ClientHello types and the handshake
// state machine. goish ships no ECH support, so nothing here is wired
// into a handshake; it is the parser Go's own tests drive directly.
//
// goishlint:ignore GOISH018 Error, buildRetryConfigList, computeAndUpdateOuterECHExtension, decodeInnerClientHello, decryptECHExtension, decryptECHPayload, encodeInnerClientHello, encodeOuterExtensions, extractRawExtensions, generateOuterECHExt, init, marshalEncryptedClientHelloConfigList, parseECHExt, pickECHCipherSuite, pickECHConfig, processECHClientHello, sendECHRetryConfigs, skipUint16LengthPrefixed, skipUint8LengthPrefixed, validDNSName — the ClientHello-dependent half; see the banner. ROADMAP.md.
// goishlint:ignore GOISH019 echExtension, echConfig, echCipher, echConfigErr, echContext, echServerContext, echClientContext — the parser's shapes are here; the handshake-side ones are not.
// goishlint:ignore GOISH021 ECHRejectionError, echAcceptConfirmationLabel, echClientContext, echContext, echExtType, echHRRAcceptConfirmationLabel, echServerContext, errIllegalECHExt, errInvalidECHExt, errMalformedECHConfigList, errMalformedECHExt, innerECHExt, outerECHExt, rawExtension, sortedSupportedAEADs — same.

#![allow(non_snake_case, dead_code)]

extern crate alloc;
use alloc::vec::Vec;

use super::common::extensionEncryptedClientHello;
use crate::crypto::cryptobyte::String as CBString;
use crate::error;
use crate::goslice::slice;
use crate::gostring::string;
use crate::types::{byte, uint16, uint8};

// Go: ech.go — `type echCipher struct { KDFID, AEADID uint16 }`
/// An HPKE symmetric cipher suite offered by an ECHConfig.
#[derive(Clone, Copy, Default, PartialEq, Debug)]
pub(crate) struct echCipher {
    pub KDFID: uint16,
    pub AEADID: uint16,
}

// Go: ech.go — `type echExtension struct { Type uint16; Data []byte }`
/// An unrecognised ECHConfig extension, kept verbatim.
#[derive(Clone, Default, PartialEq)]
pub(crate) struct echExtension {
    pub Type: uint16,
    pub Data: slice<byte>,
}

// Go: ech.go — `type echConfig struct { … }`
/// A parsed ECHConfig.
#[derive(Clone, Default, PartialEq)]
pub(crate) struct echConfig {
    pub raw: slice<byte>,

    pub Version: uint16,
    pub Length: uint16,

    pub ConfigID: uint8,
    pub KemID: uint16,
    pub PublicKey: slice<byte>,
    pub SymmetricCipherSuite: slice<echCipher>,

    pub MaxNameLength: uint8,
    pub PublicName: slice<byte>,
    pub Extensions: slice<echExtension>,
}

// Go: ech.go — `type echConfigErr struct { field string }`
/// A malformed-ECHConfig error naming the field that failed.
#[derive(Clone, Default, PartialEq)]
pub(crate) struct echConfigErr {
    pub field: string,
}

impl echConfigErr {
    // go: sdk 1.25.5 crypto/tls/ech.go:66-71 echConfigErr.Error
    /// Go: `"tls: malformed ECHConfig"`, or `"…, invalid %s field"`.
    pub(crate) fn Error(&self) -> string {
        // Go: if e.field == "" { return "tls: malformed ECHConfig" }
        if self.field == string::from_static("") {
            return string::from_static("tls: malformed ECHConfig");
        }
        // Go: return fmt.Sprintf("tls: malformed ECHConfig, invalid %s field", e.field)
        return crate::fmt::Sprintf!(
            "tls: malformed ECHConfig, invalid %s field",
            self.field.clone()
        );
    }
}

impl crate::errors::ErrorTrait for echConfigErr {
    // go: none — goish idiom: Go's *echConfigErr satisfies `error` by
    // having an `Error() string` method; goish needs the impl spelled.
    fn Error(&self) -> string {
        return echConfigErr::Error(self);
    }
}

// go: none — goish idiom: Go writes `&echConfigErr{"version"}` inline;
// naming the constructor keeps each site to one line as Go's is.
fn ecErr(field: &'static str) -> error {
    return crate::errors::Wrap(echConfigErr {
        field: string::from_static(field),
    });
}

// go: sdk 1.25.5 crypto/tls/ech.go:73-135 parseECHConfig
/// Parse one ECHConfig from `enc`.
///
/// Returns `(skip, config, err)`. `skip` is true for a config whose
/// version this implementation does not recognise: Go consumes it and
/// reports success with an EMPTY config, so the caller drops it rather
/// than failing the whole list. That is what makes an ECHConfigList
/// forward-compatible, and it is the one behaviour here worth not
/// simplifying.
pub(crate) fn parseECHConfig(enc: slice<byte>) -> (bool, echConfig, error) {
    // Go: s := cryptobyte.String(enc); ec.raw = []byte(enc)
    let mut s = CBString::New(enc.clone());
    let mut ec = echConfig::default();
    ec.raw = enc.clone();
    // Go: if !s.ReadUint16(&ec.Version) { … "version" }
    if !s.ReadUint16(&mut ec.Version) {
        return (false, echConfig::default(), ecErr("version"));
    }
    // Go: if !s.ReadUint16(&ec.Length) { … "length" }
    if !s.ReadUint16(&mut ec.Length) {
        return (false, echConfig::default(), ecErr("length"));
    }
    // Go: if len(ec.raw) < int(ec.Length)+4 { … "length" }
    if ec.raw.Len() < crate::int(ec.Length) + 4 {
        return (false, echConfig::default(), ecErr("length"));
    }
    // Go: ec.raw = ec.raw[:ec.Length+4]
    ec.raw = enc.slice(0, crate::int(ec.Length) + 4);
    // Go: if ec.Version != extensionEncryptedClientHello {
    //         s.Skip(int(ec.Length)); return true, echConfig{}, nil
    //     }
    if ec.Version != extensionEncryptedClientHello {
        s.Skip(crate::int(ec.Length));
        return (true, echConfig::default(), crate::errors::nil);
    }
    // Go: if !s.ReadUint8(&ec.ConfigID) { … "config_id" }
    if !s.ReadUint8(&mut ec.ConfigID) {
        return (false, echConfig::default(), ecErr("config_id"));
    }
    // Go: if !s.ReadUint16(&ec.KemID) { … "kem_id" }
    if !s.ReadUint16(&mut ec.KemID) {
        return (false, echConfig::default(), ecErr("kem_id"));
    }
    // Go: if !readUint16LengthPrefixed(&s, &ec.PublicKey) { … "public_key" }
    if !super::handshake_messages::readUint16LengthPrefixed(&mut s, &mut ec.PublicKey) {
        return (false, echConfig::default(), ecErr("public_key"));
    }
    // Go: var cipherSuites cryptobyte.String
    //     if !s.ReadUint16LengthPrefixed(&cipherSuites) { … "cipher_suites" }
    let mut cipherSuites = CBString::New(slice::__from_vec(Vec::new()));
    if !s.ReadUint16LengthPrefixed(&mut cipherSuites) {
        return (false, echConfig::default(), ecErr("cipher_suites"));
    }
    let mut suites: Vec<echCipher> = Vec::new();
    while !cipherSuites.Empty() {
        let mut c = echCipher::default();
        if !cipherSuites.ReadUint16(&mut c.KDFID) {
            return (false, echConfig::default(), ecErr("cipher_suites kdf_id"));
        }
        if !cipherSuites.ReadUint16(&mut c.AEADID) {
            return (false, echConfig::default(), ecErr("cipher_suites aead_id"));
        }
        suites.push(c);
    }
    ec.SymmetricCipherSuite = slice::__from_vec(suites);
    // Go: if !s.ReadUint8(&ec.MaxNameLength) { … "maximum_name_length" }
    if !s.ReadUint8(&mut ec.MaxNameLength) {
        return (false, echConfig::default(), ecErr("maximum_name_length"));
    }
    // Go: var publicName cryptobyte.String
    //     if !s.ReadUint8LengthPrefixed(&publicName) { … "public_name" }
    let mut publicName = CBString::New(slice::__from_vec(Vec::new()));
    if !s.ReadUint8LengthPrefixed(&mut publicName) {
        return (false, echConfig::default(), ecErr("public_name"));
    }
    ec.PublicName = publicName.0.clone();
    // Go: var extensions cryptobyte.String
    //     if !s.ReadUint16LengthPrefixed(&extensions) { … "extensions" }
    let mut extensions = CBString::New(slice::__from_vec(Vec::new()));
    if !s.ReadUint16LengthPrefixed(&mut extensions) {
        return (false, echConfig::default(), ecErr("extensions"));
    }
    let mut exts: Vec<echExtension> = Vec::new();
    while !extensions.Empty() {
        let mut e = echExtension::default();
        if !extensions.ReadUint16(&mut e.Type) {
            return (false, echConfig::default(), ecErr("extensions type"));
        }
        let mut data = CBString::New(slice::__from_vec(Vec::new()));
        if !extensions.ReadUint16LengthPrefixed(&mut data) {
            return (false, echConfig::default(), ecErr("extensions data"));
        }
        e.Data = data.0.clone();
        exts.push(e);
    }
    ec.Extensions = slice::__from_vec(exts);

    // Go: return false, ec, nil
    return (false, ec, crate::errors::nil);
}

// go: sdk 1.25.5 crypto/tls/ech.go:137-160 parseECHConfigList
/// Parse an ECHConfigList: a uint16 length followed by back-to-back
/// ECHConfigs. Configs whose version is unrecognised are dropped.
pub(crate) fn parseECHConfigList(data: slice<byte>) -> (slice<echConfig>, error) {
    // Go: s := cryptobyte.String(data); var length uint16
    //     if !s.ReadUint16(&length) { return nil, errMalformedECHConfigList }
    let mut s = CBString::New(data.clone());
    let mut length: uint16 = 0;
    if !s.ReadUint16(&mut length) {
        return (
            slice::__from_vec(Vec::new()),
            crate::errors::New("tls: malformed ECHConfigList"),
        );
    }
    // Go: if length != uint16(len(data)-2) { return nil, errMalformedECHConfigList }
    if crate::int(length) != data.Len() - 2 {
        return (
            slice::__from_vec(Vec::new()),
            crate::errors::New("tls: malformed ECHConfigList"),
        );
    }
    // Go: for len(s) > 0 { … }
    let mut configs: Vec<echConfig> = Vec::new();
    let mut rest = data.slice(2, data.Len());
    while rest.Len() > 0 {
        // Go: if len(s) < 4 { return nil, errors.New("tls: malformed ECHConfig") }
        if rest.Len() < 4 {
            return (
                slice::__from_vec(Vec::new()),
                crate::errors::New("tls: malformed ECHConfig"),
            );
        }
        // Go: configLen := uint16(s[2])<<8 | uint16(s[3])
        let configLen = (crate::int(rest[2]) << 8) | crate::int(rest[3]);
        let (skip, ec, err) = parseECHConfig(rest.clone());
        if err != crate::errors::nil {
            return (slice::__from_vec(Vec::new()), err);
        }
        // Go: s = s[configLen+4:]
        if configLen + 4 > rest.Len() {
            return (
                slice::__from_vec(Vec::new()),
                crate::errors::New("tls: malformed ECHConfig"),
            );
        }
        rest = rest.slice(configLen + 4, rest.Len());
        // Go: if !skip { configs = append(configs, ec) }
        if !skip {
            configs.push(ec);
        }
    }
    // Go: return configs, nil
    return (slice::__from_vec(configs), crate::errors::nil);
}
