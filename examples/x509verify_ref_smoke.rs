// x509verify_ref_smoke — crypto/x509 CHAIN VERIFICATION against a running Go.
// (crypto/x509/verify.rs, cert_pool.rs)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_x509verify_ref.go` run in
// `package x509_test` by `scripts/goref.sh`. goish matched Go on all 63
// lines — no defects found.
//
// Parsing a certificate is one job; deciding whether to TRUST it is a
// different one, and it is the one that gates access. x509_ref_smoke
// measures the first. This measures the second: chain building,
// expiry, hostname matching, name constraints, basic constraints,
// extended key usage and path length — every rule whose failure mode is
// "the wrong certificate is accepted".
//
// The fifteen certificates are built by GO and carried here as DER, so
// both sides verify the same bytes. That matters more here than for
// parsing: a chain built by the code under test, out of keys it chose,
// is a chain that agrees with itself no matter what its rules are.
//
// The refusals, and why each is load-bearing:
//
//   * A leaf whose issuer is not in Roots or Intermediates is
//     "certificate signed by unknown authority" — including the case
//     where the intermediate is simply missing, which is the most
//     common misconfiguration there is and must NOT quietly succeed.
//   * Expiry is reported with the exact instant on both sides of the
//     comparison ("current time … is after …"), and the same
//     certificate verifies fine at a time inside its window. A port
//     that compared against the wall clock rather than
//     opts.CurrentTime would pass today and fail in 2031.
//   * MaxPathLen 0 on an intermediate stops it minting further CAs:
//     `pathlen-exceeded` is the chain that tries. Without the check,
//     any leaf could become an issuer.
//   * A certificate WITHOUT the CA bit cannot sign, and the error
//     nests the reason inside the outer "unknown authority" — pinned
//     verbatim, because callers log it.
//   * NAME CONSTRAINTS in both directions: a leaf outside the
//     permitted subtree is refused as "not permitted by any
//     constraint", and one inside an EXCLUDED subtree names the
//     constraint that excluded it. This is the mechanism that lets a
//     CA be delegated safely, and a port that skipped it would let a
//     constrained intermediate sign for anyone.
//   * EKU: a ClientAuth-only leaf fails a ServerAuth requirement. An
//     EMPTY KeyUsages list means ServerAuth, not "anything" — the
//     `leaf/none` line pins that the default is a real requirement.
//
// The hostname family is where a wildcard rule one character too
// generous becomes a certificate for someone else's host:
//
//   * "*.example.com" matches ONE label: www.example.com passes,
//     a.b.example.com does not. Matching is case-insensitive and a
//     trailing dot is accepted.
//   * An EMPTY DNSName skips the check entirely and the chain
//     verifies — so a caller that forgets to set it gets no hostname
//     validation at all and no error saying so. Pinned because it is
//     the quiet failure, not a loud one.
//   * A literal "*.example.com" as the requested host MATCHES the
//     wildcard. Also pinned, because it looks like a bug and is not.
//   * IP SANs are matched as IPs, not strings.
//   * A certificate whose only name is in the CommonName is refused
//     outright — "relies on legacy Common Name field, use SANs
//     instead" — rather than silently honoured. Modern Go does not
//     fall back to CN, and neither does this.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use alloc::vec::Vec;
use goish::crypto::x509;
use goish::encoding::hex;
use goish::errors::error;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::strings;
use goish::syscall;
use goish::time;
use goish::types::int;
const GO: [&str; 63] = [
    "der root           3082014e3081f5a003020102020101300a06082a8648ce3d040302300f310d300b06035504031304726f6f74301e170d3230303130313030303030305a170d3430303130313030303030305a300f310d300b06035504031304726f6f743059301306072a8648ce3d020106082a8648ce3d030107034200049256c56f56aa075c6b60e5da152095f41fd4c2370550aa335082a307a5f7cecbff28e6100ca24428cb3e91c8a45e160faf8e9ad5032211d3a01413007ac99098a3423040300e0603551d0f0101ff040403020204300f0603551d130101ff040530030101ff301d0603551d0e0416041474ea51aa6de293ca1092e1c981da9eba764b700d300a06082a8648ce3d04030203480030450221008958b3f264ed1ec40ef2ef81b91e6bf3c734b19baede5ee2eb17ec35d4c1682a0220328e024aa6664fceea0bae975331ae48e115c2be9571cbea9d642c39b567cba4",
    "der inter          308201743082011aa003020102020102300a06082a8648ce3d040302300f310d300b06035504031304726f6f74301e170d3230303130313030303030305a170d3430303130313030303030305a3010310e300c06035504031305696e7465723059301306072a8648ce3d020106082a8648ce3d030107034200049256c56f56aa075c6b60e5da152095f41fd4c2370550aa335082a307a5f7cecbff28e6100ca24428cb3e91c8a45e160faf8e9ad5032211d3a01413007ac99098a3663064300e0603551d0f0101ff04040302020430120603551d130101ff040830060101ff020100301d0603551d0e0416041474ea51aa6de293ca1092e1c981da9eba764b700d301f0603551d2304183016801474ea51aa6de293ca1092e1c981da9eba764b700d300a06082a8648ce3d0403020348003045022100efbcc7ad327fcad32ea85baf403038d5c88ba048df54b88b7ef40e70c916bc05022059533d2bcc73c1318475a559c47c0af1738e1b3d3457e99b617e32d2b1666fb0",
    "der leaf           3082017230820119a003020102020103300a06082a8648ce3d0403023010310e300c06035504031305696e746572301e170d3230303130313030303030305a170d3430303130313030303030305a300f310d300b060355040313046c6561663059301306072a8648ce3d020106082a8648ce3d030107034200049256c56f56aa075c6b60e5da152095f41fd4c2370550aa335082a307a5f7cecbff28e6100ca24428cb3e91c8a45e160faf8e9ad5032211d3a01413007ac99098a365306330130603551d25040c300a06082b06010505070301301f0603551d2304183016801474ea51aa6de293ca1092e1c981da9eba764b700d302b0603551d1104243022820b6578616d706c652e636f6d820d2a2e6578616d706c652e636f6d8704c0000201300a06082a8648ce3d0403020347003044022015c1900734837e76c04e89478e7fe69c8057cd5aefecdcd4aa3172b04579ee6f02204d7968bdfa06fbf5a1876a7cb1d800e66f62d18ce3b549c0a25ca9321e3f422d",
    "der expired        3082014c3081f2a003020102020104300a06082a8648ce3d0403023010310e300c06035504031305696e746572301e170d3230303130313030303030305a170d3231303130313030303030305a30123110300e06035504031307657870697265643059301306072a8648ce3d020106082a8648ce3d030107034200049256c56f56aa075c6b60e5da152095f41fd4c2370550aa335082a307a5f7cecbff28e6100ca24428cb3e91c8a45e160faf8e9ad5032211d3a01413007ac99098a33b3039301f0603551d2304183016801474ea51aa6de293ca1092e1c981da9eba764b700d30160603551d11040f300d820b6578616d706c652e636f6d300a06082a8648ce3d0403020349003046022100ffc57ddf77db07d97c51dc6237b8f0af7138272b351763cfafd5cf4242bdaaa3022100b8266229d5e4a9f2fd7d70c235934f1a633b82bde48a6c14cb942b6ff8bc5b51",
    "der notyet         3082014b3081f1a003020102020105300a06082a8648ce3d0403023010310e300c06035504031305696e746572301e170d3330303130313030303030305a170d3430303130313030303030305a3011310f300d060355040313066e6f747965743059301306072a8648ce3d020106082a8648ce3d030107034200049256c56f56aa075c6b60e5da152095f41fd4c2370550aa335082a307a5f7cecbff28e6100ca24428cb3e91c8a45e160faf8e9ad5032211d3a01413007ac99098a33b3039301f0603551d2304183016801474ea51aa6de293ca1092e1c981da9eba764b700d30160603551d11040f300d820b6578616d706c652e636f6d300a06082a8648ce3d0403020349003046022100c99f701f2efe22dbaf1d2a791e8cc6e717c2de02f73115173316de69075c6bf7022100f34b72dbb3bd93bc96af1a34c4b84b64404a85aaefdad0c1dd8697396b47f1d4",
    "der sub-inter      308201763082011ca003020102020106300a06082a8648ce3d0403023010310e300c06035504031305696e746572301e170d3230303130313030303030305a170d3430303130313030303030305a301431123010060355040313097375622d696e7465723059301306072a8648ce3d020106082a8648ce3d030107034200049256c56f56aa075c6b60e5da152095f41fd4c2370550aa335082a307a5f7cecbff28e6100ca24428cb3e91c8a45e160faf8e9ad5032211d3a01413007ac99098a3633061300e0603551d0f0101ff040403020204300f0603551d130101ff040530030101ff301d0603551d0e0416041474ea51aa6de293ca1092e1c981da9eba764b700d301f0603551d2304183016801474ea51aa6de293ca1092e1c981da9eba764b700d300a06082a8648ce3d040302034800304502207eef5bffa02cd77adea40eb49bf9d8829f16a84b8986f0f907c4e83f5269ce2a022100a95ca789e66078c1ddc7af7e91650cd737448849243e8cb5118b2998b1cc0f48",
    "der deep-leaf      308201563081fda003020102020107300a06082a8648ce3d040302301431123010060355040313097375622d696e746572301e170d3230303130313030303030305a170d3430303130313030303030305a30143112301006035504031309646565702d6c6561663059301306072a8648ce3d020106082a8648ce3d030107034200049256c56f56aa075c6b60e5da152095f41fd4c2370550aa335082a307a5f7cecbff28e6100ca24428cb3e91c8a45e160faf8e9ad5032211d3a01413007ac99098a340303e301f0603551d2304183016801474ea51aa6de293ca1092e1c981da9eba764b700d301b0603551d11041430128210646565702e6578616d706c652e636f6d300a06082a8648ce3d040302034800304502202d36c8863788a8079baa415f6e78cf840947e1c2acf093dd261c945a1a5b860e022100e5cd49c7f63399dff4af69989708f57973893d5c53411354b232a5edcb0b48e7",
    "der non-ca         3082013e3081e6a003020102020108300a06082a8648ce3d040302300f310d300b06035504031304726f6f74301e170d3230303130313030303030305a170d3430303130313030303030305a3011310f300d060355040313066e6f6e2d63613059301306072a8648ce3d020106082a8648ce3d030107034200049256c56f56aa075c6b60e5da152095f41fd4c2370550aa335082a307a5f7cecbff28e6100ca24428cb3e91c8a45e160faf8e9ad5032211d3a01413007ac99098a331302f300c0603551d130101ff04023000301f0603551d2304183016801474ea51aa6de293ca1092e1c981da9eba764b700d300a06082a8648ce3d040302034700304402203dc0591aa4f27ba96fddb3258ca0a1f24abf0a58cdb896410012652cd8e01207022056493e6a0da1e4b6b4268e24c943218cf7bfeb1fa705c3650e4379ebd0366961",
    "der non-ca-child   308201373081dda003020102020109300a06082a8648ce3d0403023011310f300d060355040313066e6f6e2d6361301e170d3230303130313030303030305a170d3430303130313030303030305a3017311530130603550403130c6e6f6e2d63612d6368696c643059301306072a8648ce3d020106082a8648ce3d030107034200049256c56f56aa075c6b60e5da152095f41fd4c2370550aa335082a307a5f7cecbff28e6100ca24428cb3e91c8a45e160faf8e9ad5032211d3a01413007ac99098a320301e301c0603551d110415301382116368696c642e6578616d706c652e636f6d300a06082a8648ce3d0403020349003046022100fc932ed6f3c0b89b6171bb9b65cb2fdf9f89094318fd083e3b5d4790cdee28a90221009082c4e214c5af7b93cba5c8ca56b08fc5400b1aaa084fe6a5ad09aab1975f72",
    "der nc-inter       308201a93082014fa00302010202010a300a06082a8648ce3d040302300f310d300b06035504031304726f6f74301e170d3230303130313030303030305a170d3430303130313030303030305a30133111300f060355040313086e632d696e7465723059301306072a8648ce3d020106082a8648ce3d030107034200049256c56f56aa075c6b60e5da152095f41fd4c2370550aa335082a307a5f7cecbff28e6100ca24428cb3e91c8a45e160faf8e9ad5032211d3a01413007ac99098a38197308194300e0603551d0f0101ff040403020204300f0603551d130101ff040530030101ff301d0603551d0e0416041474ea51aa6de293ca1092e1c981da9eba764b700d301f0603551d2304183016801474ea51aa6de293ca1092e1c981da9eba764b700d30310603551d1e042a3028a010300e820c676f6f642e6578616d706c65a114301282106261642e676f6f642e6578616d706c65300a06082a8648ce3d040302034800304502206c5a9408aaa3cd16808ce76d48d856b3912db4e196a1f158355172da8c7e23d9022100fc5bba4bbc9379af9972f4633ad4c6dfd1d9d604dcd2781b1d02d79ad3457742",
    "der nc-in          308201513081f9a00302010202010b300a06082a8648ce3d04030230133111300f060355040313086e632d696e746572301e170d3230303130313030303030305a170d3430303130313030303030305a3010310e300c060355040313056e632d696e3059301306072a8648ce3d020106082a8648ce3d030107034200049256c56f56aa075c6b60e5da152095f41fd4c2370550aa335082a307a5f7cecbff28e6100ca24428cb3e91c8a45e160faf8e9ad5032211d3a01413007ac99098a341303f301f0603551d2304183016801474ea51aa6de293ca1092e1c981da9eba764b700d301c0603551d11041530138211686f73742e676f6f642e6578616d706c65300a06082a8648ce3d0403020347003044022053b5a061c94bcbd13956865983de65c519344a8bdf957256b9850f797835937002200fd2b1763cb95086245c94b094dcbd10018d76335cde712e8ceeed4a81b4236c",
    "der nc-out         308201523081faa00302010202010c300a06082a8648ce3d04030230133111300f060355040313086e632d696e746572301e170d3230303130313030303030305a170d3430303130313030303030305a3011310f300d060355040313066e632d6f75743059301306072a8648ce3d020106082a8648ce3d030107034200049256c56f56aa075c6b60e5da152095f41fd4c2370550aa335082a307a5f7cecbff28e6100ca24428cb3e91c8a45e160faf8e9ad5032211d3a01413007ac99098a341303f301f0603551d2304183016801474ea51aa6de293ca1092e1c981da9eba764b700d301c0603551d11041530138211686f73742e6576696c2e6578616d706c65300a06082a8648ce3d040302034700304402205ad5ee3537ea91977289cb58a48d313273ba280a744a56953b57a2d97d14d6350220379bc6864755922e53a1c852d3be66ce8a96d2e213d21d12ac03149a8d8ed8a7",
    "der nc-excluded    3082015d30820103a00302010202010d300a06082a8648ce3d04030230133111300f060355040313086e632d696e746572301e170d3230303130313030303030305a170d3430303130313030303030305a3016311430120603550403130b6e632d6578636c756465643059301306072a8648ce3d020106082a8648ce3d030107034200049256c56f56aa075c6b60e5da152095f41fd4c2370550aa335082a307a5f7cecbff28e6100ca24428cb3e91c8a45e160faf8e9ad5032211d3a01413007ac99098a3453043301f0603551d2304183016801474ea51aa6de293ca1092e1c981da9eba764b700d30200603551d11041930178215686f73742e6261642e676f6f642e6578616d706c65300a06082a8648ce3d0403020348003045022100aff98e1572837ef55e9034802d320be83d95726fc895222c34e5b76294e199fb02200f6b88ce22fb238c7a078262e3b2e55a8e2911f1a3248393044549cf21164102",
    "der client-only    308201643082010ba00302010202010e300a06082a8648ce3d0403023010310e300c06035504031305696e746572301e170d3230303130313030303030305a170d3430303130313030303030305a3016311430120603550403130b636c69656e742d6f6e6c793059301306072a8648ce3d020106082a8648ce3d030107034200049256c56f56aa075c6b60e5da152095f41fd4c2370550aa335082a307a5f7cecbff28e6100ca24428cb3e91c8a45e160faf8e9ad5032211d3a01413007ac99098a350304e30130603551d25040c300a06082b06010505070302301f0603551d2304183016801474ea51aa6de293ca1092e1c981da9eba764b700d30160603551d11040f300d820b6578616d706c652e636f6d300a06082a8648ce3d040302034700304402205b7f5579fede7c910c7b16b4ddc879620408f24332f8a6a1b30b9929aa62f551022077bd820d20fd3b96c8f77160c7e3981d6b7f273cc18cec26d53b8e18d42d2bad",
    "der cn-only        3082013b3081e1a00302010202010f300a06082a8648ce3d0403023010310e300c06035504031305696e746572301e170d3230303130313030303030305a170d3430303130313030303030305a3019311730150603550403130e636e2e6578616d706c652e636f6d3059301306072a8648ce3d020106082a8648ce3d030107034200049256c56f56aa075c6b60e5da152095f41fd4c2370550aa335082a307a5f7cecbff28e6100ca24428cb3e91c8a45e160faf8e9ad5032211d3a01413007ac99098a3233021301f0603551d2304183016801474ea51aa6de293ca1092e1c981da9eba764b700d300a06082a8648ce3d0403020349003046022100ba910b4766ebcec66f09c5f279305898f41c79aa2fe71de409ed5d979586360502210082c43cce3ec0921e3165c32fee7f7153e04be03b9576328b41aeb0695d709c18",
    "verify full-chain                   -> chains=1 [leaf>inter>root]",
    "verify no-intermediate              -> err=\"x509: certificate signed by unknown authority\"",
    "verify intermediate-as-root         -> chains=1 [leaf>inter]",
    "verify empty-roots                  -> err=\"x509: certificate signed by unknown authority\"",
    "verify root-verifies-itself         -> chains=1 [root]",
    "verify inter-as-leaf                -> chains=1 [inter>root]",
    "verify expired                      -> err=\"x509: certificate has expired or is not yet valid: current time 2025-06-01T00:00:00Z is after 2021-01-01T00:00:00Z\"",
    "verify expired-at-valid-time        -> chains=1 [expired>inter>root]",
    "verify not-yet-valid                -> err=\"x509: certificate has expired or is not yet valid: current time 2025-06-01T00:00:00Z is before 2030-01-01T00:00:00Z\"",
    "verify pathlen-exceeded             -> err=\"x509: too many intermediates for path length constraint\"",
    "verify non-ca-signer                -> err=\"x509: certificate signed by unknown authority (possibly because of \\\"x509: invalid signature: parent certificate cannot sign this kind of certificate\\\" while trying to verify candidate authority certificate \\\"non-ca\\\")\"",
    "verify nc-permitted                 -> chains=1 [nc-in>nc-inter>root]",
    "verify nc-outside                   -> err=\"x509: a root or intermediate certificate is not authorized to sign for this name: DNS name \\\"host.evil.example\\\" is not permitted by any constraint\"",
    "verify nc-excluded                  -> err=\"x509: a root or intermediate certificate is not authorized to sign for this name: DNS name \\\"host.bad.good.example\\\" is excluded by constraint \\\"bad.good.example\\\"\"",
    "verify dns:example.com              -> chains=1 [leaf>inter>root]",
    "verify dns:EXAMPLE.COM              -> chains=1 [leaf>inter>root]",
    "verify dns:www.example.com          -> chains=1 [leaf>inter>root]",
    "verify dns:a.b.example.com          -> err=\"x509: certificate is valid for example.com, *.example.com, not a.b.example.com\"",
    "verify dns:.example.com             -> err=\"x509: certificate is valid for example.com, *.example.com, not .example.com\"",
    "verify dns:example.com.             -> chains=1 [leaf>inter>root]",
    "verify dns:wwwexample.com           -> err=\"x509: certificate is valid for example.com, *.example.com, not wwwexample.com\"",
    "verify dns:com                      -> err=\"x509: certificate is valid for example.com, *.example.com, not com\"",
    "verify dns:<empty>                  -> chains=1 [leaf>inter>root]",
    "verify dns:*.example.com            -> chains=1 [leaf>inter>root]",
    "verify dns:192.0.2.1                -> chains=1 [leaf>inter>root]",
    "verify dns:192.0.2.2                -> err=\"x509: certificate is valid for 192.0.2.1, not 192.0.2.2\"",
    "verify dns:xn--e1afmkfd.example.com -> chains=1 [leaf>inter>root]",
    "hostname leaf/example.com       -> err=<nil>",
    "hostname leaf/a.example.com     -> err=<nil>",
    "hostname leaf/a.b.example.com   -> err=x509: certificate is valid for example.com, *.example.com, not a.b.example.com",
    "hostname leaf/ip                -> err=<nil>",
    "hostname leaf/ip-wrong          -> err=x509: certificate is valid for 192.0.2.1, not 192.0.2.2",
    "hostname leaf/trailing-dot      -> err=<nil>",
    "hostname leaf/empty             -> err=x509: certificate is valid for example.com, *.example.com, not ",
    "hostname cn-only/cn             -> err=x509: certificate relies on legacy Common Name field, use SANs instead",
    "hostname cn-only/other          -> err=x509: certificate is not valid for any names, but wanted to match other.example.com",
    "verify eku:leaf/server              -> chains=1 [leaf>inter>root]",
    "verify eku:leaf/client              -> err=\"x509: certificate specifies an incompatible key usage\"",
    "verify eku:leaf/any                 -> chains=1 [leaf>inter>root]",
    "verify eku:leaf/none                -> chains=1 [leaf>inter>root]",
    "verify eku:client-only/server       -> err=\"x509: certificate specifies an incompatible key usage\"",
    "verify eku:client-only/client       -> chains=1 [client-only>inter>root]",
    "sigfrom leaf<-inter      -> err=<nil>",
    "sigfrom leaf<-root       -> err=<nil>",
    "sigfrom inter<-root      -> err=<nil>",
    "sigfrom root<-root       -> err=<nil>",
    "sigfrom leaf<-nonca      -> err=x509: invalid signature: parent certificate cannot sign this kind of certificate",
    "sigfrom inter<-leaf      -> err=x509: invalid signature: parent certificate cannot sign this kind of certificate",
];

fn chk(failed: &mut int, ln: &mut int, got: string) {
    if *ln >= GO.len() as int {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln + 1, got);
        *failed += 1;
        *ln += 1;
        return;
    }
    let want = s(GO[*ln as usize]);
    *ln += 1;
    if got == want {
        return;
    }
    fmt::Printf!("[!!] line %d FAIL\n  got  %q\n  want %q\n", *ln, got, want);
    *failed += 1;
}

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}
fn errText(err: error) -> string {
    if err == goish::nil {
        return s("<nil>");
    }
    return err.Error();
}
// The certificates Go built, carried as DER so the goish side verifies
// the SAME bytes. A chain built by the code under test, out of keys it
// chose, is a chain that agrees with itself.
const DER_ROOT: &str = "3082014e3081f5a003020102020101300a06082a8648ce3d040302300f310d300b06035504031304726f6f74301e170d3230303130313030303030305a170d3430303130313030303030305a300f310d300b06035504031304726f6f743059301306072a8648ce3d020106082a8648ce3d030107034200049256c56f56aa075c6b60e5da152095f41fd4c2370550aa335082a307a5f7cecbff28e6100ca24428cb3e91c8a45e160faf8e9ad5032211d3a01413007ac99098a3423040300e0603551d0f0101ff040403020204300f0603551d130101ff040530030101ff301d0603551d0e0416041474ea51aa6de293ca1092e1c981da9eba764b700d300a06082a8648ce3d04030203480030450221008958b3f264ed1ec40ef2ef81b91e6bf3c734b19baede5ee2eb17ec35d4c1682a0220328e024aa6664fceea0bae975331ae48e115c2be9571cbea9d642c39b567cba4";
const DER_INTER: &str = "308201743082011aa003020102020102300a06082a8648ce3d040302300f310d300b06035504031304726f6f74301e170d3230303130313030303030305a170d3430303130313030303030305a3010310e300c06035504031305696e7465723059301306072a8648ce3d020106082a8648ce3d030107034200049256c56f56aa075c6b60e5da152095f41fd4c2370550aa335082a307a5f7cecbff28e6100ca24428cb3e91c8a45e160faf8e9ad5032211d3a01413007ac99098a3663064300e0603551d0f0101ff04040302020430120603551d130101ff040830060101ff020100301d0603551d0e0416041474ea51aa6de293ca1092e1c981da9eba764b700d301f0603551d2304183016801474ea51aa6de293ca1092e1c981da9eba764b700d300a06082a8648ce3d0403020348003045022100efbcc7ad327fcad32ea85baf403038d5c88ba048df54b88b7ef40e70c916bc05022059533d2bcc73c1318475a559c47c0af1738e1b3d3457e99b617e32d2b1666fb0";
const DER_LEAF: &str = "3082017230820119a003020102020103300a06082a8648ce3d0403023010310e300c06035504031305696e746572301e170d3230303130313030303030305a170d3430303130313030303030305a300f310d300b060355040313046c6561663059301306072a8648ce3d020106082a8648ce3d030107034200049256c56f56aa075c6b60e5da152095f41fd4c2370550aa335082a307a5f7cecbff28e6100ca24428cb3e91c8a45e160faf8e9ad5032211d3a01413007ac99098a365306330130603551d25040c300a06082b06010505070301301f0603551d2304183016801474ea51aa6de293ca1092e1c981da9eba764b700d302b0603551d1104243022820b6578616d706c652e636f6d820d2a2e6578616d706c652e636f6d8704c0000201300a06082a8648ce3d0403020347003044022015c1900734837e76c04e89478e7fe69c8057cd5aefecdcd4aa3172b04579ee6f02204d7968bdfa06fbf5a1876a7cb1d800e66f62d18ce3b549c0a25ca9321e3f422d";
const DER_EXPIRED: &str = "3082014c3081f2a003020102020104300a06082a8648ce3d0403023010310e300c06035504031305696e746572301e170d3230303130313030303030305a170d3231303130313030303030305a30123110300e06035504031307657870697265643059301306072a8648ce3d020106082a8648ce3d030107034200049256c56f56aa075c6b60e5da152095f41fd4c2370550aa335082a307a5f7cecbff28e6100ca24428cb3e91c8a45e160faf8e9ad5032211d3a01413007ac99098a33b3039301f0603551d2304183016801474ea51aa6de293ca1092e1c981da9eba764b700d30160603551d11040f300d820b6578616d706c652e636f6d300a06082a8648ce3d0403020349003046022100ffc57ddf77db07d97c51dc6237b8f0af7138272b351763cfafd5cf4242bdaaa3022100b8266229d5e4a9f2fd7d70c235934f1a633b82bde48a6c14cb942b6ff8bc5b51";
const DER_NOTYET: &str = "3082014b3081f1a003020102020105300a06082a8648ce3d0403023010310e300c06035504031305696e746572301e170d3330303130313030303030305a170d3430303130313030303030305a3011310f300d060355040313066e6f747965743059301306072a8648ce3d020106082a8648ce3d030107034200049256c56f56aa075c6b60e5da152095f41fd4c2370550aa335082a307a5f7cecbff28e6100ca24428cb3e91c8a45e160faf8e9ad5032211d3a01413007ac99098a33b3039301f0603551d2304183016801474ea51aa6de293ca1092e1c981da9eba764b700d30160603551d11040f300d820b6578616d706c652e636f6d300a06082a8648ce3d0403020349003046022100c99f701f2efe22dbaf1d2a791e8cc6e717c2de02f73115173316de69075c6bf7022100f34b72dbb3bd93bc96af1a34c4b84b64404a85aaefdad0c1dd8697396b47f1d4";
const DER_SUB_INTER: &str = "308201763082011ca003020102020106300a06082a8648ce3d0403023010310e300c06035504031305696e746572301e170d3230303130313030303030305a170d3430303130313030303030305a301431123010060355040313097375622d696e7465723059301306072a8648ce3d020106082a8648ce3d030107034200049256c56f56aa075c6b60e5da152095f41fd4c2370550aa335082a307a5f7cecbff28e6100ca24428cb3e91c8a45e160faf8e9ad5032211d3a01413007ac99098a3633061300e0603551d0f0101ff040403020204300f0603551d130101ff040530030101ff301d0603551d0e0416041474ea51aa6de293ca1092e1c981da9eba764b700d301f0603551d2304183016801474ea51aa6de293ca1092e1c981da9eba764b700d300a06082a8648ce3d040302034800304502207eef5bffa02cd77adea40eb49bf9d8829f16a84b8986f0f907c4e83f5269ce2a022100a95ca789e66078c1ddc7af7e91650cd737448849243e8cb5118b2998b1cc0f48";
const DER_DEEP_LEAF: &str = "308201563081fda003020102020107300a06082a8648ce3d040302301431123010060355040313097375622d696e746572301e170d3230303130313030303030305a170d3430303130313030303030305a30143112301006035504031309646565702d6c6561663059301306072a8648ce3d020106082a8648ce3d030107034200049256c56f56aa075c6b60e5da152095f41fd4c2370550aa335082a307a5f7cecbff28e6100ca24428cb3e91c8a45e160faf8e9ad5032211d3a01413007ac99098a340303e301f0603551d2304183016801474ea51aa6de293ca1092e1c981da9eba764b700d301b0603551d11041430128210646565702e6578616d706c652e636f6d300a06082a8648ce3d040302034800304502202d36c8863788a8079baa415f6e78cf840947e1c2acf093dd261c945a1a5b860e022100e5cd49c7f63399dff4af69989708f57973893d5c53411354b232a5edcb0b48e7";
const DER_NON_CA: &str = "3082013e3081e6a003020102020108300a06082a8648ce3d040302300f310d300b06035504031304726f6f74301e170d3230303130313030303030305a170d3430303130313030303030305a3011310f300d060355040313066e6f6e2d63613059301306072a8648ce3d020106082a8648ce3d030107034200049256c56f56aa075c6b60e5da152095f41fd4c2370550aa335082a307a5f7cecbff28e6100ca24428cb3e91c8a45e160faf8e9ad5032211d3a01413007ac99098a331302f300c0603551d130101ff04023000301f0603551d2304183016801474ea51aa6de293ca1092e1c981da9eba764b700d300a06082a8648ce3d040302034700304402203dc0591aa4f27ba96fddb3258ca0a1f24abf0a58cdb896410012652cd8e01207022056493e6a0da1e4b6b4268e24c943218cf7bfeb1fa705c3650e4379ebd0366961";
const DER_NON_CA_CHILD: &str = "308201373081dda003020102020109300a06082a8648ce3d0403023011310f300d060355040313066e6f6e2d6361301e170d3230303130313030303030305a170d3430303130313030303030305a3017311530130603550403130c6e6f6e2d63612d6368696c643059301306072a8648ce3d020106082a8648ce3d030107034200049256c56f56aa075c6b60e5da152095f41fd4c2370550aa335082a307a5f7cecbff28e6100ca24428cb3e91c8a45e160faf8e9ad5032211d3a01413007ac99098a320301e301c0603551d110415301382116368696c642e6578616d706c652e636f6d300a06082a8648ce3d0403020349003046022100fc932ed6f3c0b89b6171bb9b65cb2fdf9f89094318fd083e3b5d4790cdee28a90221009082c4e214c5af7b93cba5c8ca56b08fc5400b1aaa084fe6a5ad09aab1975f72";
const DER_NC_INTER: &str = "308201a93082014fa00302010202010a300a06082a8648ce3d040302300f310d300b06035504031304726f6f74301e170d3230303130313030303030305a170d3430303130313030303030305a30133111300f060355040313086e632d696e7465723059301306072a8648ce3d020106082a8648ce3d030107034200049256c56f56aa075c6b60e5da152095f41fd4c2370550aa335082a307a5f7cecbff28e6100ca24428cb3e91c8a45e160faf8e9ad5032211d3a01413007ac99098a38197308194300e0603551d0f0101ff040403020204300f0603551d130101ff040530030101ff301d0603551d0e0416041474ea51aa6de293ca1092e1c981da9eba764b700d301f0603551d2304183016801474ea51aa6de293ca1092e1c981da9eba764b700d30310603551d1e042a3028a010300e820c676f6f642e6578616d706c65a114301282106261642e676f6f642e6578616d706c65300a06082a8648ce3d040302034800304502206c5a9408aaa3cd16808ce76d48d856b3912db4e196a1f158355172da8c7e23d9022100fc5bba4bbc9379af9972f4633ad4c6dfd1d9d604dcd2781b1d02d79ad3457742";
const DER_NC_IN: &str = "308201513081f9a00302010202010b300a06082a8648ce3d04030230133111300f060355040313086e632d696e746572301e170d3230303130313030303030305a170d3430303130313030303030305a3010310e300c060355040313056e632d696e3059301306072a8648ce3d020106082a8648ce3d030107034200049256c56f56aa075c6b60e5da152095f41fd4c2370550aa335082a307a5f7cecbff28e6100ca24428cb3e91c8a45e160faf8e9ad5032211d3a01413007ac99098a341303f301f0603551d2304183016801474ea51aa6de293ca1092e1c981da9eba764b700d301c0603551d11041530138211686f73742e676f6f642e6578616d706c65300a06082a8648ce3d0403020347003044022053b5a061c94bcbd13956865983de65c519344a8bdf957256b9850f797835937002200fd2b1763cb95086245c94b094dcbd10018d76335cde712e8ceeed4a81b4236c";
const DER_NC_OUT: &str = "308201523081faa00302010202010c300a06082a8648ce3d04030230133111300f060355040313086e632d696e746572301e170d3230303130313030303030305a170d3430303130313030303030305a3011310f300d060355040313066e632d6f75743059301306072a8648ce3d020106082a8648ce3d030107034200049256c56f56aa075c6b60e5da152095f41fd4c2370550aa335082a307a5f7cecbff28e6100ca24428cb3e91c8a45e160faf8e9ad5032211d3a01413007ac99098a341303f301f0603551d2304183016801474ea51aa6de293ca1092e1c981da9eba764b700d301c0603551d11041530138211686f73742e6576696c2e6578616d706c65300a06082a8648ce3d040302034700304402205ad5ee3537ea91977289cb58a48d313273ba280a744a56953b57a2d97d14d6350220379bc6864755922e53a1c852d3be66ce8a96d2e213d21d12ac03149a8d8ed8a7";
const DER_NC_EXCLUDED: &str = "3082015d30820103a00302010202010d300a06082a8648ce3d04030230133111300f060355040313086e632d696e746572301e170d3230303130313030303030305a170d3430303130313030303030305a3016311430120603550403130b6e632d6578636c756465643059301306072a8648ce3d020106082a8648ce3d030107034200049256c56f56aa075c6b60e5da152095f41fd4c2370550aa335082a307a5f7cecbff28e6100ca24428cb3e91c8a45e160faf8e9ad5032211d3a01413007ac99098a3453043301f0603551d2304183016801474ea51aa6de293ca1092e1c981da9eba764b700d30200603551d11041930178215686f73742e6261642e676f6f642e6578616d706c65300a06082a8648ce3d0403020348003045022100aff98e1572837ef55e9034802d320be83d95726fc895222c34e5b76294e199fb02200f6b88ce22fb238c7a078262e3b2e55a8e2911f1a3248393044549cf21164102";
const DER_CLIENT_ONLY: &str = "308201643082010ba00302010202010e300a06082a8648ce3d0403023010310e300c06035504031305696e746572301e170d3230303130313030303030305a170d3430303130313030303030305a3016311430120603550403130b636c69656e742d6f6e6c793059301306072a8648ce3d020106082a8648ce3d030107034200049256c56f56aa075c6b60e5da152095f41fd4c2370550aa335082a307a5f7cecbff28e6100ca24428cb3e91c8a45e160faf8e9ad5032211d3a01413007ac99098a350304e30130603551d25040c300a06082b06010505070302301f0603551d2304183016801474ea51aa6de293ca1092e1c981da9eba764b700d30160603551d11040f300d820b6578616d706c652e636f6d300a06082a8648ce3d040302034700304402205b7f5579fede7c910c7b16b4ddc879620408f24332f8a6a1b30b9929aa62f551022077bd820d20fd3b96c8f77160c7e3981d6b7f273cc18cec26d53b8e18d42d2bad";
const DER_CN_ONLY: &str = "3082013b3081e1a00302010202010f300a06082a8648ce3d0403023010310e300c06035504031305696e746572301e170d3230303130313030303030305a170d3430303130313030303030305a3019311730150603550403130e636e2e6578616d706c652e636f6d3059301306072a8648ce3d020106082a8648ce3d030107034200049256c56f56aa075c6b60e5da152095f41fd4c2370550aa335082a307a5f7cecbff28e6100ca24428cb3e91c8a45e160faf8e9ad5032211d3a01413007ac99098a3233021301f0603551d2304183016801474ea51aa6de293ca1092e1c981da9eba764b700d300a06082a8648ce3d0403020349003046022100ba910b4766ebcec66f09c5f279305898f41c79aa2fe71de409ed5d979586360502210082c43cce3ec0921e3165c32fee7f7153e04be03b9576328b41aeb0695d709c18";
fn parse(h: &str) -> x509::Certificate {
    let (der, _) = hex::DecodeString(h);
    let (c, e) = x509::ParseCertificate(der);
    if e != goish::nil {
        fmt::Printf!("[!!] parse-err=%q\n", e.Error());
    }
    return c;
}
fn pool(certs: &[&x509::Certificate]) -> x509::CertPool {
    let mut p = x509::NewCertPool();
    for c in certs.iter() {
        p.AddCert((*c).clone());
    }
    return p;
}
fn show(
    failed: &mut int,
    ln: &mut int,
    label: string,
    chains: slice<slice<x509::Certificate>>,
    err: error,
) {
    if err != goish::nil {
        chk(
            failed,
            ln,
            fmt::Sprintf!("verify %-28s -> err=%q", label, err.Error()),
        );
        return;
    }
    let mut parts: Vec<string> = Vec::new();
    for i in 0..chains.Len() {
        let ch = chains[i].clone();
        let mut names: Vec<string> = Vec::new();
        for j in 0..ch.Len() {
            names.push(ch[j].Subject.CommonName.clone());
        }
        parts.push(strings::Join(slice::<string>::__from_vec(names), s(">")));
    }
    chk(
        failed,
        ln,
        fmt::Sprintf!(
            "verify %-28s -> chains=%d [%s]",
            label,
            chains.Len(),
            strings::Join(slice::<string>::__from_vec(parts), s(" | "))
        ),
    );
}
fn utc(y: int, mo: time::Month, d: int) -> time::Time {
    return time::Date(y, mo, d, 0, 0, 0, 0, time::UTC);
}
fn opts(
    roots: x509::CertPool,
    inters: Option<x509::CertPool>,
    now: time::Time,
    dns: string,
    eku: slice<x509::ExtKeyUsage>,
) -> x509::VerifyOptions {
    return x509::VerifyOptions {
        DNSName: dns,
        Intermediates: inters,
        Roots: Some(roots),
        CurrentTime: now,
        KeyUsages: eku,
        ..Default::default()
    };
}
#[goish::main]
fn main() {
    let mut failed: int = 0;
    let mut ln: int = 0;
    let all: [(&str, &str); 15] = [
        ("root", DER_ROOT),
        ("inter", DER_INTER),
        ("leaf", DER_LEAF),
        ("expired", DER_EXPIRED),
        ("notyet", DER_NOTYET),
        ("sub-inter", DER_SUB_INTER),
        ("deep-leaf", DER_DEEP_LEAF),
        ("non-ca", DER_NON_CA),
        ("non-ca-child", DER_NON_CA_CHILD),
        ("nc-inter", DER_NC_INTER),
        ("nc-in", DER_NC_IN),
        ("nc-out", DER_NC_OUT),
        ("nc-excluded", DER_NC_EXCLUDED),
        ("client-only", DER_CLIENT_ONLY),
        ("cn-only", DER_CN_ONLY),
    ];
    let mut certs: Vec<x509::Certificate> = Vec::new();
    for (name, h) in all.iter() {
        let c = parse(h);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("der %-14s %s", s(name), s(h)),
        );
        let _ = name;
        certs.push(c);
    }
    let root = certs[0].clone();
    let inter = certs[1].clone();
    let leaf = certs[2].clone();
    let expired = certs[3].clone();
    let notyet = certs[4].clone();
    let subInter = certs[5].clone();
    let deepLeaf = certs[6].clone();
    let nonCA = certs[7].clone();
    let nonCAChild = certs[8].clone();
    let ncInter = certs[9].clone();
    let ncIn = certs[10].clone();
    let ncOut = certs[11].clone();
    let ncExcluded = certs[12].clone();
    let clientOnly = certs[13].clone();
    let cnOnly = certs[14].clone();
    let now = utc(2025, time::June, 1);
    let noEku = slice::<x509::ExtKeyUsage>::__from_vec(Vec::new());
    let cases: [(&str, &x509::Certificate, x509::VerifyOptions); 14] = [
        (
            "full-chain",
            &leaf,
            opts(
                pool(&[&root]),
                Some(pool(&[&inter])),
                now.clone(),
                string::new(),
                noEku.clone(),
            ),
        ),
        (
            "no-intermediate",
            &leaf,
            opts(
                pool(&[&root]),
                None,
                now.clone(),
                string::new(),
                noEku.clone(),
            ),
        ),
        (
            "intermediate-as-root",
            &leaf,
            opts(
                pool(&[&inter]),
                None,
                now.clone(),
                string::new(),
                noEku.clone(),
            ),
        ),
        (
            "empty-roots",
            &leaf,
            opts(
                x509::NewCertPool(),
                Some(pool(&[&inter])),
                now.clone(),
                string::new(),
                noEku.clone(),
            ),
        ),
        (
            "root-verifies-itself",
            &root,
            opts(
                pool(&[&root]),
                None,
                now.clone(),
                string::new(),
                noEku.clone(),
            ),
        ),
        (
            "inter-as-leaf",
            &inter,
            opts(
                pool(&[&root]),
                None,
                now.clone(),
                string::new(),
                noEku.clone(),
            ),
        ),
        (
            "expired",
            &expired,
            opts(
                pool(&[&root]),
                Some(pool(&[&inter])),
                now.clone(),
                string::new(),
                noEku.clone(),
            ),
        ),
        (
            "expired-at-valid-time",
            &expired,
            opts(
                pool(&[&root]),
                Some(pool(&[&inter])),
                utc(2020, time::January, 1).Add(time::Hour),
                string::new(),
                noEku.clone(),
            ),
        ),
        (
            "not-yet-valid",
            &notyet,
            opts(
                pool(&[&root]),
                Some(pool(&[&inter])),
                now.clone(),
                string::new(),
                noEku.clone(),
            ),
        ),
        (
            "pathlen-exceeded",
            &deepLeaf,
            opts(
                pool(&[&root]),
                Some(pool(&[&inter, &subInter])),
                now.clone(),
                string::new(),
                noEku.clone(),
            ),
        ),
        (
            "non-ca-signer",
            &nonCAChild,
            opts(
                pool(&[&root]),
                Some(pool(&[&nonCA])),
                now.clone(),
                string::new(),
                noEku.clone(),
            ),
        ),
        (
            "nc-permitted",
            &ncIn,
            opts(
                pool(&[&root]),
                Some(pool(&[&ncInter])),
                now.clone(),
                string::new(),
                noEku.clone(),
            ),
        ),
        (
            "nc-outside",
            &ncOut,
            opts(
                pool(&[&root]),
                Some(pool(&[&ncInter])),
                now.clone(),
                string::new(),
                noEku.clone(),
            ),
        ),
        (
            "nc-excluded",
            &ncExcluded,
            opts(
                pool(&[&root]),
                Some(pool(&[&ncInter])),
                now.clone(),
                string::new(),
                noEku.clone(),
            ),
        ),
    ];
    for (label, cert, o) in cases.into_iter() {
        let (chains, e) = cert.Verify(o);
        show(&mut failed, &mut ln, s(label), chains, e);
    }
    for host in [
        "example.com",
        "EXAMPLE.COM",
        "www.example.com",
        "a.b.example.com",
        ".example.com",
        "example.com.",
        "wwwexample.com",
        "com",
        "",
        "*.example.com",
        "192.0.2.1",
        "192.0.2.2",
        "xn--e1afmkfd.example.com",
    ] {
        let o = opts(
            pool(&[&root]),
            Some(pool(&[&inter])),
            now.clone(),
            s(host),
            noEku.clone(),
        );
        let (chains, e) = leaf.Verify(o);
        let shown = if host == "" { s("<empty>") } else { s(host) };
        show(
            &mut failed,
            &mut ln,
            string::from("dns:") + shown,
            chains,
            e,
        );
    }
    let hosts: [(&str, &x509::Certificate, &str); 9] = [
        ("leaf/example.com", &leaf, "example.com"),
        ("leaf/a.example.com", &leaf, "a.example.com"),
        ("leaf/a.b.example.com", &leaf, "a.b.example.com"),
        ("leaf/ip", &leaf, "192.0.2.1"),
        ("leaf/ip-wrong", &leaf, "192.0.2.2"),
        ("leaf/trailing-dot", &leaf, "example.com."),
        ("leaf/empty", &leaf, ""),
        ("cn-only/cn", &cnOnly, "cn.example.com"),
        ("cn-only/other", &cnOnly, "other.example.com"),
    ];
    for (name, cert, host) in hosts.iter() {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "hostname %-22s -> err=%s",
                s(name),
                errText(cert.VerifyHostname(s(host)))
            ),
        );
    }
    let ekuAny = slice::<x509::ExtKeyUsage>::__from_vec(alloc::vec![x509::ExtKeyUsageAny]);
    let ekuServer =
        slice::<x509::ExtKeyUsage>::__from_vec(alloc::vec![x509::ExtKeyUsageServerAuth]);
    let ekuClient =
        slice::<x509::ExtKeyUsage>::__from_vec(alloc::vec![x509::ExtKeyUsageClientAuth]);
    let ekus: [(&str, &x509::Certificate, slice<x509::ExtKeyUsage>); 6] = [
        ("leaf/server", &leaf, ekuServer.clone()),
        ("leaf/client", &leaf, ekuClient.clone()),
        ("leaf/any", &leaf, ekuAny.clone()),
        ("leaf/none", &leaf, noEku.clone()),
        ("client-only/server", &clientOnly, ekuServer.clone()),
        ("client-only/client", &clientOnly, ekuClient.clone()),
    ];
    for (label, cert, eku) in ekus.into_iter() {
        let o = opts(
            pool(&[&root]),
            Some(pool(&[&inter])),
            now.clone(),
            string::new(),
            eku,
        );
        let (chains, e) = cert.Verify(o);
        show(
            &mut failed,
            &mut ln,
            string::from("eku:") + s(label),
            chains,
            e,
        );
    }
    let sigs: [(&str, &x509::Certificate, &x509::Certificate); 6] = [
        ("leaf<-inter", &leaf, &inter),
        ("leaf<-root", &leaf, &root),
        ("inter<-root", &inter, &root),
        ("root<-root", &root, &root),
        ("leaf<-nonca", &leaf, &nonCA),
        ("inter<-leaf", &inter, &leaf),
    ];
    for (label, child, parent) in sigs.iter() {
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "sigfrom %-16s -> err=%s",
                s(label),
                errText(child.CheckSignatureFrom(parent))
            ),
        );
    }
    if ln != GO.len() as int {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln, GO.len() as int);
        failed += 1;
    }
    if failed == 0 {
        fmt::Printf!("ok %d/%d\n", ln, ln);
        return;
    }
    fmt::Printf!("FAILED %d of %d\n", failed, ln);
    syscall::Exit(1);
}
