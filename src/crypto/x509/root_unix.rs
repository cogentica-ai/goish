// go: file crypto/x509/root_unix.go decls: loadSystemRoots, readUniqueDirectoryEntries, isSameDirSymlink
//
// The Unix platform trust store: the `SSL_CERT_FILE` / `SSL_CERT_DIR`
// overrides and the well-known bundle paths.
//
// **This is the only platform file goish ports.** Go ships
// `root_darwin.go`, `root_windows.go`, `root_plan9.go`, `root_js.go`,
// `root_wasip1.go` and `root_omit.go` alongside it, selected by build
// tag. goish v1 is linux/amd64 only, so `root_unix.go` — whose build tag
// includes `linux` — is the correct and only route. The other variants
// are out of scope, not missing.
//
// Deviations from root_unix[go] @ Go 1.25.5:
//
//   * `certFiles` / `certDirectories` live in `root_linux.go`, not
//     `root_unix.go`. They are package-level `var`s of heap slices;
//     goish has no const slice, so each is a function — the idiom
//     `x509.rs` already uses for its OID vars. `root_linux.go`'s `init()`
//     appends two Android paths when `goos.IsAndroid == 1`; goish is
//     linux/amd64, so that branch is dead and is not ported.
//   * `Certificate.systemVerify` is a two-line `return nil, nil` stub on
//     Unix — the hook the darwin/windows files fill in. `Verify` never
//     reaches it on linux (its caller is inside the
//     `runtime.GOOS == "windows" || "darwin" || "ios"` arm), so it is not
//     ported. See verify.rs's banner.
//   * `loadSystemRoots` returns `(*CertPool, error)` and hands back a nil
//     pool with the error. goish returns `(CertPool, error)`; on failure
//     the pool is the zero value, whose `Len()` is 0. `root.rs`'s
//     `initSystemRoots` is what converts that into the `Option<CertPool>`
//     the rest of the package sees.
//   * `readUniqueDirectoryEntries` reuses `files[:0]` as the output
//     backing array — a Go alias trick that needs `uniq` and `files` to
//     share one allocation. goish builds a fresh slice; same elements,
//     same order.
//
// goishlint:ignore GOISH018 systemVerify — the Unix `return nil, nil` platform-verifier stub, unreachable on linux/amd64; see the banner.
// goishlint:ignore GOISH021 certFileEnv, certDirEnv, certFiles, certDirectories — `certFiles`/`certDirectories` are heap-slice `var`s in root_linux.go, spelled as functions; see the banner.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::cert_pool::{CertPool, NewCertPool};
use crate::error;
use crate::errors;
use crate::goslice::slice;
use crate::gostring::string;
use crate::io::fs;
use crate::os;
use crate::path::filepath;
use crate::strings;

// Go: root_unix.go:16-26
/// The environment variable which identifies where to locate the SSL
/// certificate file. If set this overrides the system default.
const certFileEnv: &str = "SSL_CERT_FILE";

/// The environment variable which identifies which directory to check
/// for SSL certificate files. If set this overrides the system default.
/// It is a colon separated list of directories.
/// See <https://www.openssl.org/docs/man1.0.2/man1/c_rehash.html>.
const certDirEnv: &str = "SSL_CERT_DIR";

// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
// Go declares this at root_linux.go lines 9-17: possible certificate
// files; stop after finding one.
fn certFiles() -> slice<string> {
    let mut v: Vec<string> = Vec::with_capacity(6);
    // Debian/Ubuntu/Gentoo etc.
    v.push(string::from("/etc/ssl/certs/ca-certificates.crt"));
    // Fedora/RHEL 6
    v.push(string::from("/etc/pki/tls/certs/ca-bundle.crt"));
    // OpenSUSE
    v.push(string::from("/etc/ssl/ca-bundle.pem"));
    // OpenELEC
    v.push(string::from("/etc/pki/tls/cacert.pem"));
    // CentOS/RHEL 7
    v.push(string::from("/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"));
    // Alpine Linux
    v.push(string::from("/etc/ssl/cert.pem"));
    return slice::__from_vec(v);
}

// go: none — goish idiom: Go declares this as a package-level `var` of a heap-allocated slice; goish has no const slice, so it is a function. Same name, same value.
// Go declares this at root_linux.go lines 19-23: possible directories
// with certificate files; all will be read.
fn certDirectories() -> slice<string> {
    let mut v: Vec<string> = Vec::with_capacity(2);
    // SLES10/SLES11, https://golang.org/issue/12139
    v.push(string::from("/etc/ssl/certs"));
    // Fedora/RHEL
    v.push(string::from("/etc/pki/tls/certs"));
    return slice::__from_vec(v);
}

// go: sdk 1.25.5 crypto/x509/root_unix.go:32-82 loadSystemRoots
pub(super) fn loadSystemRoots() -> (CertPool, error) {
    let mut roots = NewCertPool();

    let mut files = certFiles();
    let f = os::Getenv(certFileEnv);
    if f.Len() != 0 {
        files = crate::append!(slice::<string>::new(), f);
    }

    let mut firstErr: error = errors::nil;
    for (_, file) in crate::range!(files) {
        let (data, err) = os::ReadFile(file);
        if err == crate::nil {
            roots.AppendCertsFromPEM(data);
            break;
        }
        if firstErr == crate::nil && !os::IsNotExist(err.clone()) {
            firstErr = err;
        }
    }

    let mut dirs = certDirectories();
    let d = os::Getenv(certDirEnv);
    if d.Len() != 0 {
        // OpenSSL and BoringSSL both use ":" as the SSL_CERT_DIR separator.
        // See:
        //  * https://golang.org/issue/35325
        //  * https://www.openssl.org/docs/man1.0.2/man1/c_rehash.html
        dirs = strings::Split(d, ":");
    }

    for (_, directory) in crate::range!(dirs) {
        let (fis, err) = readUniqueDirectoryEntries(&directory);
        if err != crate::nil {
            if firstErr == crate::nil && !os::IsNotExist(err.clone()) {
                firstErr = err;
            }
            continue;
        }
        for (_, fi) in crate::range!(fis) {
            let (data, err) = os::ReadFile(directory.clone() + string::from("/") + fi.Name());
            if err == crate::nil {
                roots.AppendCertsFromPEM(data);
            }
        }
    }

    if roots.len() > 0 || firstErr == crate::nil {
        return (roots, errors::nil);
    }

    return (CertPool::default(), firstErr);
}

// go: sdk 1.25.5 crypto/x509/root_unix.go:84-98 readUniqueDirectoryEntries
/// Like `os::ReadDir` but omits symlinks that point within the directory.
pub(super) fn readUniqueDirectoryEntries(
    dir: &string,
) -> (slice<Arc<dyn fs::DirEntry + Send + Sync>>, error) {
    let (files, err) = os::ReadDir(dir.clone());
    if err != crate::nil {
        return (slice::new(), err);
    }
    // Go reuses `files[:0]` as the output backing array; goish builds a
    // fresh slice. See the banner.
    let mut uniq: slice<Arc<dyn fs::DirEntry + Send + Sync>> = slice::new();
    for (_, f) in crate::range!(files) {
        if !isSameDirSymlink(&f, dir) {
            uniq = crate::append!(uniq, f.clone());
        }
    }
    return (uniq, errors::nil);
}

// go: sdk 1.25.5 crypto/x509/root_unix.go:100-108 isSameDirSymlink
/// Report whether `f` in `dir` is a symlink with a target not containing
/// a slash.
pub(super) fn isSameDirSymlink(
    f: &Arc<dyn fs::DirEntry + Send + Sync>,
    dir: &string,
) -> bool {
    if f.Type().0 & fs::ModeSymlink.0 == 0 {
        return false;
    }
    let joined = filepath::Join(crate::append!(
        crate::append!(slice::<string>::new(), dir.clone()),
        f.Name()
    ));
    let (target, err) = os::Readlink(joined);
    return err == crate::nil && !strings::Contains(target, "/");
}
