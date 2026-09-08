// go: file crypto/x509/pem_decrypt.go decls: rfc1423Algo.deriveKey, IsEncryptedPEMBlock, DecryptPEMBlock, EncryptPEMBlock, cipherByName, cipherByKey
//
// RFC 1423 PEM encryption — the legacy `DEK-Info` scheme OpenSSL writes
// for password-protected private keys.
//
// Go marks all four exported entry points Deprecated, and the reason is
// worth repeating: the scheme does not authenticate its ciphertext, so
// it is vulnerable to padding-oracle attacks that recover the plaintext.
// It is ported because real PEM files in the wild carry it, not because
// anything new should use it.
//
// Self-contained, and picked for that: it touches crypto/{aes,cipher,
// des,md5}, encoding/{hex,pem}, errors, io and strings — every one at
// 100% in goish — and references none of x509.go's types. `verify.go` is
// the file that needs `net/netip`, not this one.
//
// Deviations from pem_decrypt[go] @ Go 1.25.5:
//
//   * Go's `rfc1423Algo.cipherFunc` is a struct field of type
//     `func(key []byte) (cipher.Block, error)` — an interface-returning
//     function value, which makes the table uniform. goish's
//     `cipher::NewCBCEncrypter<B: Block>` is generic and its three
//     constructors return three *different* concrete types
//     (`des::Cipher`, `des::TripleDESCipher`, `aes::Block`), so there is
//     no single fn pointer to store. The field is replaced by
//     `newBlock`, which dispatches on the algorithm and returns
//     `pemBlock` — an enum over the three, implementing `cipher::Block`
//     by delegation. Static dispatch instead of a vtable; AGENTS.md §5
//     rule 3 rules out a `dyn` field, and this keeps the same table
//     shape.
//   * Go returns `*rfc1423Algo` and compares against nil; goish returns
//     `Option<&'static rfc1423Algo>`.
//   * `EncryptPEMBlock` takes `rand io.Reader`; goish spells it
//     `&mut dyn io::Reader`, as elsewhere in the tree.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;

use alloc::vec::Vec;

use crate::crypto::{aes, cipher, des, md5};
use crate::encoding::hex;
use crate::encoding::pem;
use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::gostring::string;
use crate::hash::Hash;
use crate::io;
use crate::strings;
use crate::types::{byte, int};

// Go: pem_decrypt.go:23 — `type PEMCipher int`
/// The encryption algorithm used by [`EncryptPEMBlock`].
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct PEMCipher(pub int);

// Go: pem_decrypt.go:26-34 — `const ( _ PEMCipher = iota; PEMCipherDES; … )`
pub const PEMCipherDES: PEMCipher = PEMCipher(1);
pub const PEMCipher3DES: PEMCipher = PEMCipher(2);
pub const PEMCipherAES128: PEMCipher = PEMCipher(3);
pub const PEMCipherAES192: PEMCipher = PEMCipher(4);
pub const PEMCipherAES256: PEMCipher = PEMCipher(5);

// Go: pem_decrypt.go:36-42
//   type rfc1423Algo struct {
//       cipher PEMCipher; name string
//       cipherFunc func(key []byte) (cipher.Block, error)
//       keySize, blockSize int
//   }
/// A method for enciphering a PEM block. See the banner for why
/// `cipherFunc` is absent.
struct rfc1423Algo {
    cipher: PEMCipher,
    name: &'static str,
    keySize: int,
    blockSize: int,
}

// Go: pem_decrypt.go:46-79 — `var rfc1423Algos = []rfc1423Algo{…}`.
// The ivSize numbers were taken from the OpenSSL source.
static rfc1423Algos: [rfc1423Algo; 5] = [
    rfc1423Algo {
        cipher: PEMCipherDES,
        name: "DES-CBC",
        keySize: 8,
        blockSize: des::BlockSize,
    },
    rfc1423Algo {
        cipher: PEMCipher3DES,
        name: "DES-EDE3-CBC",
        keySize: 24,
        blockSize: des::BlockSize,
    },
    rfc1423Algo {
        cipher: PEMCipherAES128,
        name: "AES-128-CBC",
        keySize: 16,
        blockSize: aes::BlockSize,
    },
    rfc1423Algo {
        cipher: PEMCipherAES192,
        name: "AES-192-CBC",
        keySize: 24,
        blockSize: aes::BlockSize,
    },
    rfc1423Algo {
        cipher: PEMCipherAES256,
        name: "AES-256-CBC",
        keySize: 32,
        blockSize: aes::BlockSize,
    },
];

// go: none — goish idiom: the three concrete block types Go reaches
// through `cipher.Block`. See the banner.
enum pemBlock {
    Des(des::Cipher),
    TripleDes(des::TripleDESCipher),
    Aes(aes::Block),
}

impl cipher::Block for pemBlock {
    // go: none — goish idiom: delegation, standing in for Go's interface.
    fn BlockSize(&self) -> int {
        return match self {
            pemBlock::Des(b) => b.BlockSize(),
            pemBlock::TripleDes(b) => b.BlockSize(),
            pemBlock::Aes(b) => b.BlockSize(),
        };
    }

    // go: none — goish idiom: see BlockSize.
    fn Encrypt(&self, dst: &mut slice<byte>, src: slice<byte>) {
        match self {
            pemBlock::Des(b) => b.Encrypt(dst, src),
            pemBlock::TripleDes(b) => b.Encrypt(dst, src),
            pemBlock::Aes(b) => b.Encrypt(dst, src),
        }
    }

    // go: none — goish idiom: see BlockSize.
    fn Decrypt(&self, dst: &mut slice<byte>, src: slice<byte>) {
        match self {
            pemBlock::Des(b) => b.Decrypt(dst, src),
            pemBlock::TripleDes(b) => b.Decrypt(dst, src),
            pemBlock::Aes(b) => b.Decrypt(dst, src),
        }
    }
}

// go: none — goish idiom: Go stores `cipherFunc` in the table and calls
// `ciph.cipherFunc(key)`. See the banner.
fn newBlock(alg: &rfc1423Algo, key: slice<byte>) -> (Option<pemBlock>, error) {
    if alg.cipher == PEMCipherDES {
        let (c, err) = des::NewCipher(key);
        if err != nil {
            return (None, err);
        }
        return (Some(pemBlock::Des(c.unwrap())), nil.into());
    }
    if alg.cipher == PEMCipher3DES {
        let (c, err) = des::NewTripleDESCipher(key);
        if err != nil {
            return (None, err);
        }
        return (Some(pemBlock::TripleDes(c.unwrap())), nil.into());
    }
    let (c, err) = aes::NewCipher(key);
    if err != nil {
        return (None, err);
    }
    return (Some(pemBlock::Aes(c.unwrap())), nil.into());
}

impl rfc1423Algo {
    // go: sdk 1.25.5 crypto/x509/pem_decrypt.go:82-97 rfc1423Algo.deriveKey
    /// Stretch the password into a key of the size this cipher requires.
    /// The algorithm was derived from the OpenSSL source.
    fn deriveKey(&self, password: slice<byte>, salt: slice<byte>) -> slice<byte> {
        let mut hash = md5::New();
        let mut out: Vec<byte> = alloc::vec![0u8; self.keySize as usize];
        let mut digest: slice<byte> = slice::default();

        let mut i: int = 0;
        while i < crate::int(out.len()) {
            Hash::Reset(&mut hash);
            let _ = hash.Write(digest.clone());
            let _ = hash.Write(password.clone());
            let _ = hash.Write(salt.clone());
            digest = hash.Sum(slice::default());
            let d = digest.as_ref();
            let n = core::cmp::min(d.len(), out.len() - i as usize);
            out[i as usize..i as usize + n].copy_from_slice(&d[..n]);
            i += crate::int(d.len());
        }
        return slice::__from_vec(out);
    }
}

// go: sdk 1.25.5 crypto/x509/pem_decrypt.go:104-107 IsEncryptedPEMBlock
/// Whether the PEM block is password encrypted according to RFC 1423.
///
/// Deprecated: legacy PEM encryption is insecure by design — see the
/// banner.
pub fn IsEncryptedPEMBlock(b: &pem::Block) -> bool {
    let (_, ok) = b.Headers.Get("DEK-Info");
    return ok;
}

goish::var! {
    /// Returned when an incorrect password is detected.
    pub IncorrectPasswordError: error = "x509: decryption password incorrect";
}

// go: sdk 1.25.5 crypto/x509/pem_decrypt.go:124-186 DecryptPEMBlock
/// Decrypt a PEM block encrypted according to RFC 1423, returning the
/// DER bytes. The `DEK-Info` header selects the algorithm.
///
/// Because of deficiencies in the format it is not always possible to
/// detect an incorrect password; in those cases no error is returned but
/// the decrypted bytes are random noise.
///
/// Deprecated: legacy PEM encryption is insecure by design — see the
/// banner.
pub fn DecryptPEMBlock(b: &pem::Block, password: slice<byte>) -> (slice<byte>, error) {
    let (dek, ok) = b.Headers.Get("DEK-Info");
    if !ok {
        return (
            slice::default(),
            crate::errors::New("x509: no DEK-Info header in block"),
        );
    }

    let (mode, hexIV, ok) = strings::Cut(dek, ",");
    if !ok {
        return (
            slice::default(),
            crate::errors::New("x509: malformed DEK-Info header"),
        );
    }

    let ciph = match cipherByName(mode) {
        Some(c) => c,
        None => {
            return (
                slice::default(),
                crate::errors::New("x509: unknown encryption mode"),
            );
        }
    };
    let (iv, err) = hex::DecodeString(hexIV.as_ref());
    if err != nil {
        return (slice::default(), err);
    }
    if iv.Len() != ciph.blockSize {
        return (
            slice::default(),
            crate::errors::New("x509: incorrect IV size"),
        );
    }

    // Based on the OpenSSL implementation: the salt is the first 8 bytes
    // of the initialization vector.
    let key = ciph.deriveKey(password, slice::__from_vec(iv.as_ref()[..8].to_vec()));
    let (block, err) = newBlock(ciph, key);
    if err != nil {
        return (slice::default(), err);
    }
    let block = block.unwrap();

    if b.Bytes.Len() % cipher::Block::BlockSize(&block) != 0 {
        return (
            slice::default(),
            crate::errors::New("x509: encrypted PEM data is not a multiple of the block size"),
        );
    }

    let mut data: slice<byte> = slice::__from_vec(alloc::vec![0u8; b.Bytes.Len() as usize]);
    let mut dec = cipher::NewCBCDecrypter(block, iv);
    cipher::BlockMode::CryptBlocks(&mut dec, &mut data, b.Bytes.clone());

    // Blocks are padded so that the last n bytes are all equal to n, from
    // 1 to blocksize inclusive. See RFC 1423. Bad padding is taken to
    // mean a bad password.
    let dlen = data.Len();
    if dlen == 0 || dlen % ciph.blockSize != 0 {
        return (
            slice::default(),
            crate::errors::New("x509: invalid padding"),
        );
    }
    let last = crate::int(data[dlen - 1]);
    if dlen < last {
        return (slice::default(), IncorrectPasswordError.into());
    }
    if last == 0 || last > ciph.blockSize {
        return (slice::default(), IncorrectPasswordError.into());
    }
    for v in data.as_ref()[(dlen - last) as usize..].iter() {
        if crate::int(*v) != last {
            return (slice::default(), IncorrectPasswordError.into());
        }
    }
    return (
        slice::__from_vec(data.as_ref()[..(dlen - last) as usize].to_vec()),
        nil.into(),
    );
}

// go: sdk 1.25.5 crypto/x509/pem_decrypt.go:195-232 EncryptPEMBlock
/// Return a PEM block of `blockType` holding `data` encrypted with `alg`
/// and `password`, according to RFC 1423.
///
/// Deprecated: legacy PEM encryption is insecure by design — see the
/// banner.
pub fn EncryptPEMBlock<S: Into<string>>(
    rand: &mut dyn io::Reader,
    blockType: S,
    data: slice<byte>,
    password: slice<byte>,
    alg: PEMCipher,
) -> (Option<pem::Block>, error) {
    let ciph = match cipherByKey(alg) {
        Some(c) => c,
        None => {
            return (None, crate::errors::New("x509: unknown encryption mode"));
        }
    };
    let mut iv: slice<byte> = slice::__from_vec(alloc::vec![0u8; ciph.blockSize as usize]);
    let (_, err) = io::ReadFull(rand, &mut iv);
    if err != nil {
        let mut msg = strings::Builder::new();
        let _ = msg.WriteString("x509: cannot generate IV: ");
        let _ = msg.WriteString(err.Error());
        return (None, crate::errors::New(msg.String()));
    }
    // The salt is the first 8 bytes of the initialization vector,
    // matching the key derivation in DecryptPEMBlock.
    let key = ciph.deriveKey(password, slice::__from_vec(iv.as_ref()[..8].to_vec()));
    let (block, err) = newBlock(ciph, key);
    if err != nil {
        return (None, err);
    }
    let mut enc = cipher::NewCBCEncrypter(block.unwrap(), iv.clone());
    let pad = ciph.blockSize - data.Len() % ciph.blockSize;
    let mut encrypted: Vec<byte> = Vec::with_capacity((data.Len() + pad) as usize);
    // We could save this copy by encrypting all the whole blocks in the
    // data separately, but it doesn't seem worth the additional code.
    encrypted.extend_from_slice(data.as_ref());
    // See RFC 1423, Section 1.1.
    let mut i: int = 0;
    while i < pad {
        encrypted.push(crate::byte(pad));
        i += 1;
    }
    let mut encrypted = slice::__from_vec(encrypted);
    let src = encrypted.clone();
    cipher::BlockMode::CryptBlocks(&mut enc, &mut encrypted, src);

    let mut headers = crate::gomap::map::<string, string>::new();
    headers.Set("Proc-Type", "4,ENCRYPTED");
    let mut dek = strings::Builder::new();
    let _ = dek.WriteString(ciph.name);
    let _ = dek.WriteString(",");
    let _ = dek.WriteString(hex::EncodeToString(iv.as_ref()));
    headers.Set(string::from_static("DEK-Info"), dek.String());

    return (
        Some(pem::Block {
            Type: blockType.into(),
            Headers: headers,
            Bytes: encrypted,
        }),
        nil.into(),
    );
}

// go: sdk 1.25.5 crypto/x509/pem_decrypt.go:234-242 cipherByName
fn cipherByName(name: string) -> Option<&'static rfc1423Algo> {
    for alg in rfc1423Algos.iter() {
        if alg.name.as_bytes() == name.as_bytes() {
            return Some(alg);
        }
    }
    return None;
}

// go: sdk 1.25.5 crypto/x509/pem_decrypt.go:244-252 cipherByKey
fn cipherByKey(key: PEMCipher) -> Option<&'static rfc1423Algo> {
    for alg in rfc1423Algos.iter() {
        if alg.cipher == key {
            return Some(alg);
        }
    }
    return None;
}
