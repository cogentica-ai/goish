// go: file crypto/tls/common_string.go decls: SignatureScheme.String, CurveID.String, ClientAuthType.String
// go: waived _ — the `func _()` blocks stringer emits are compile-time value-drift assertions; goish keeps the constants explicit and needs no such probe.
//
// crypto/tls — `String()` for SignatureScheme, CurveID and
// ClientAuthType.
//
// Go generates this file with
// `stringer -linecomment -type=SignatureScheme,CurveID,ClientAuthType`,
// which packs the names into concatenated string constants and slices
// them with an index table. The three `func _()` blocks it emits are
// compile-time assertions that the constant values have not drifted —
// an "invalid array index" error if they have.
//
// Deviations from common_string[go] @ Go 1.25.5:
//
//   * The concatenated-name-plus-index-table encoding is spelled as a
//     `match` returning the name directly. The generated form exists to
//     avoid a relocation per string in the Go binary; it is not
//     observable behaviour, and reproducing the byte offsets by hand
//     would be a transcription risk for no gain. The *outputs* are
//     identical, including the `Type(N)` fallbacks, and are pinned
//     against Go in `examples/tls_common_smoke.rs`.
//     goishlint:ignore GOISH021 _SignatureScheme_name_0, _SignatureScheme_name_1, _SignatureScheme_name_2, _SignatureScheme_name_3, _SignatureScheme_name_4, _SignatureScheme_name_5, _SignatureScheme_name_6, _SignatureScheme_name_7, _SignatureScheme_name_8, _SignatureScheme_index_8, _CurveID_name_0, _CurveID_name_1, _CurveID_name_2, _CurveID_index_0, _ClientAuthType_name, _ClientAuthType_index — the stringer packing tables; see above
//   * Go's three `func _()` drift assertions are not ported: they are a
//     `stringer` artefact guarding regeneration, and goishlint's
//     fidelity tier already diffs the constants against common.go.
//     goishlint:ignore GOISH018 _ — the stringer drift-assertion stubs

#![allow(non_snake_case)]

use super::common::{
    ClientAuthType, CurveID, SignatureScheme, CurveP256, CurveP384, CurveP521, ECDSAWithP256AndSHA256,
    ECDSAWithP384AndSHA384, ECDSAWithP521AndSHA512, ECDSAWithSHA1, Ed25519, NoClientCert,
    PKCS1WithSHA1, PKCS1WithSHA256, PKCS1WithSHA384, PKCS1WithSHA512, PSSWithSHA256, PSSWithSHA384,
    PSSWithSHA512, RequireAndVerifyClientCert, RequireAnyClientCert, RequestClientCert,
    VerifyClientCertIfGiven, X25519, X25519MLKEM768,
};
use crate::gostring::string;
use crate::strconv;

impl SignatureScheme {
    // go: sdk 1.25.5 crypto/tls/common_string.go:41-64 SignatureScheme.String
    /// Go: the generated `switch` over the packed name table.
    pub fn String(&self) -> string {
        return match *self {
            PKCS1WithSHA1 => string::from_static("PKCS1WithSHA1"),
            ECDSAWithSHA1 => string::from_static("ECDSAWithSHA1"),
            PKCS1WithSHA256 => string::from_static("PKCS1WithSHA256"),
            ECDSAWithP256AndSHA256 => string::from_static("ECDSAWithP256AndSHA256"),
            PKCS1WithSHA384 => string::from_static("PKCS1WithSHA384"),
            ECDSAWithP384AndSHA384 => string::from_static("ECDSAWithP384AndSHA384"),
            PKCS1WithSHA512 => string::from_static("PKCS1WithSHA512"),
            ECDSAWithP521AndSHA512 => string::from_static("ECDSAWithP521AndSHA512"),
            // Go: case 2052 <= i && i <= 2055 — the PSS block plus Ed25519,
            // sliced out of one packed constant.
            PSSWithSHA256 => string::from_static("PSSWithSHA256"),
            PSSWithSHA384 => string::from_static("PSSWithSHA384"),
            PSSWithSHA512 => string::from_static("PSSWithSHA512"),
            Ed25519 => string::from_static("Ed25519"),
            // Go: default: "SignatureScheme(" + strconv.FormatInt(int64(i), 10) + ")"
            _ => {
                string::from_static("SignatureScheme(")
                    + strconv::FormatInt(crate::int64(self.0), 10)
                    + string::from_static(")")
            }
        };
    }
}

impl CurveID {
    // go: sdk 1.25.5 crypto/tls/common_string.go:87-99 CurveID.String
    /// Go: the generated `switch` over the packed name table.
    pub fn String(&self) -> string {
        return match *self {
            // Go: case 23 <= i && i <= 25 — sliced out of one constant.
            CurveP256 => string::from_static("CurveP256"),
            CurveP384 => string::from_static("CurveP384"),
            CurveP521 => string::from_static("CurveP521"),
            X25519 => string::from_static("X25519"),
            X25519MLKEM768 => string::from_static("X25519MLKEM768"),
            // Go: default: "CurveID(" + strconv.FormatInt(int64(i), 10) + ")"
            _ => {
                string::from_static("CurveID(")
                    + strconv::FormatInt(crate::int64(self.0), 10)
                    + string::from_static(")")
            }
        };
    }
}

impl ClientAuthType {
    // go: sdk 1.25.5 crypto/tls/common_string.go:115-120 ClientAuthType.String
    /// Go: bounds-check against the index table, else slice the name out.
    pub fn String(&self) -> string {
        return match *self {
            NoClientCert => string::from_static("NoClientCert"),
            RequestClientCert => string::from_static("RequestClientCert"),
            RequireAnyClientCert => string::from_static("RequireAnyClientCert"),
            VerifyClientCertIfGiven => string::from_static("VerifyClientCertIfGiven"),
            RequireAndVerifyClientCert => string::from_static("RequireAndVerifyClientCert"),
            // Go: if i < 0 || i >= len(index)-1 { return "ClientAuthType(" + … + ")" }
            _ => {
                string::from_static("ClientAuthType(")
                    + strconv::FormatInt(crate::int64(self.0), 10)
                    + string::from_static(")")
            }
        };
    }
}
