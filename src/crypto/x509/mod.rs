// go: package crypto/x509

#![allow(non_snake_case, non_upper_case_globals)]

pub mod pkix;

mod cert_pool;
mod goish_rsa_der;
mod oid;
mod parser;
mod pem_decrypt;
mod pkcs1;
mod pkcs8;
mod root;
mod root_unix;
mod sec1;
mod verify;
mod x509;

pub use cert_pool::{CertPool, NewCertPool, SystemCertPool};
pub use goish_rsa_der::{goishParsePKCS1RSAPrivateKey, goishParsePKCS8RSAPrivateKey};
pub use oid::{OIDFromInts, ParseOID, OID};
pub use parser::{ParseCertificate, ParseCertificates, ParseRevocationList};
pub use pem_decrypt::{
    DecryptPEMBlock, EncryptPEMBlock, IncorrectPasswordError, IsEncryptedPEMBlock, PEMCipher,
    PEMCipher3DES, PEMCipherAES128, PEMCipherAES192, PEMCipherAES256, PEMCipherDES,
};
pub use pkcs1::{
    MarshalPKCS1PrivateKey, MarshalPKCS1PublicKey, ParsePKCS1PrivateKey, ParsePKCS1PublicKey,
};
pub use pkcs8::{MarshalPKCS8PrivateKey, ParsePKCS8PrivateKey};
pub use root::SetFallbackRoots;
pub use sec1::{MarshalECPrivateKey, ParseECPrivateKey};
pub use verify::{
    CANotAuthorizedForExtKeyUsage, CANotAuthorizedForThisName, CertificateInvalidError, Expired,
    HostnameError, IncompatibleUsage, InvalidReason, NameConstraintsWithoutSANs, NameMismatch,
    NoValidChains, NotAuthorizedToSign, SystemRootsError, TooManyConstraints, TooManyIntermediates,
    UnconstrainedName, UnknownAuthorityError, VerifyOptions,
};
pub use x509::{
    Certificate, CertificateRequest, ConstraintViolationError, CreateCertificate,
    CreateCertificateRequest, CreateRevocationList, DSAWithSHA1, DSAWithSHA256, ECDSAWithSHA1,
    ECDSAWithSHA256, ECDSAWithSHA384, ECDSAWithSHA512, Ed25519, ErrUnsupportedAlgorithm,
    ExtKeyUsage, ExtKeyUsageAny, ExtKeyUsageClientAuth, ExtKeyUsageCodeSigning,
    ExtKeyUsageEmailProtection, ExtKeyUsageIPSECEndSystem, ExtKeyUsageIPSECTunnel,
    ExtKeyUsageIPSECUser, ExtKeyUsageMicrosoftCommercialCodeSigning,
    ExtKeyUsageMicrosoftKernelCodeSigning, ExtKeyUsageMicrosoftServerGatedCrypto,
    ExtKeyUsageNetscapeServerGatedCrypto, ExtKeyUsageOCSPSigning, ExtKeyUsageServerAuth,
    ExtKeyUsageTimeStamping, InsecureAlgorithmError, KeyUsage, KeyUsageCRLSign, KeyUsageCertSign,
    KeyUsageContentCommitment, KeyUsageDataEncipherment, KeyUsageDecipherOnly,
    KeyUsageDigitalSignature, KeyUsageEncipherOnly, KeyUsageKeyAgreement, KeyUsageKeyEncipherment,
    MD2WithRSA, MD5WithRSA, MarshalPKIXPublicKey, ParseCRL, ParseCertificateRequest, ParseDERCRL,
    ParsePKIXPublicKey, PolicyMapping, PublicKeyAlgorithm, PureEd25519, RevocationList,
    RevocationListEntry, SHA1WithRSA, SHA256WithRSA, SHA256WithRSAPSS, SHA384WithRSA,
    SHA384WithRSAPSS, SHA512WithRSA, SHA512WithRSAPSS, SignatureAlgorithm,
    UnhandledCriticalExtension, UnknownPublicKeyAlgorithm, UnknownSignatureAlgorithm, DSA, ECDSA,
    RSA,
};
