// crypto/tls — Go's `crypto/tls` package, minimal stub for ports that
// reference `*tls.Config` as a value carrier.
//
// Goish v1 ships only the type surface — `Config` as a struct with the
// most commonly-touched public fields (InsecureSkipVerify, ServerName,
// MinVersion, RootCAs). No actual TLS handshake plumbing yet; that
// requires a TLS implementation crate which is out of scope for the
// no_std runtime today. Ports that pass `*tls.Config` around for
// configuration purposes can compile against this surface; ports that
// actually negotiate TLS will need the handshake layer (deferred).
//
// Reference: Go 1.25 `src/crypto/tls/common.go` `type Config struct`.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use crate::gostring::string;

/// `tls.Config` (Go 1.25 src/crypto/tls/common.go) — TLS-protocol
/// settings. Goish v1 carries the value-typed fields most commonly
/// touched by leaf ports; the full Go struct has dozens of fields
/// spanning callbacks and connection pools that aren't wired yet.
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
}

// Common TLS protocol-version constants (Go 1.25 common.go).
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
        // Treat a zero-value Config as nil (no fields populated).
        self.ServerName == crate::gostring::string::from_static("")
            && !self.InsecureSkipVerify
            && self.MinVersion == 0
            && self.MaxVersion == 0
    }
}
impl PartialEq<Config> for crate::nilval::Nil {
    fn eq(&self, other: &Config) -> bool {
        other.eq(self)
    }
}
