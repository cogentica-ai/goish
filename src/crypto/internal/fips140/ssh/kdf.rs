// go: file crypto/internal/fips140/ssh/kdf.go decls: Keys
//
// crypto/internal/fips140/ssh — the SSH KDF as specified in RFC 4253
// §7.2 and allowed by SP 800-135 Revision 1.
//
// Deviations from kdf[go] @ Go 1.25.5:
//
//   * Go's `[Hash hash.Hash](hash func() Hash, …)` generic collapses to
//     the `impl IntoHashFunc` factory the rest of the
//     module already takes.
//   * Go's `var ServerKeys, ClientKeys Direction` are assigned in an
//     `init()`; their `[]byte` tags are not const-evaluable in Rust, so
//     they are `goish::lazy::Lazy<Direction>` statics. They stay public
//     fields (AGENTS.md §5 rule 2) — no accessor pair.
//
// goishlint:ignore GOISH018 — kdf.go's `init` exists only to fill in
// ServerKeys and ClientKeys, which the two Lazy initialisers above do
// verbatim on first access. There is nothing else in its body.

#![allow(non_snake_case, non_upper_case_globals)]

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::goslice::slice;
use crate::hash::{Hash, IntoHashFunc};
use crate::io;
use crate::lazy::Lazy;
use crate::types::{byte, int};

// Go: kdf.go:14-18
//   type Direction struct { ivTag, keyTag, macKeyTag []byte }
/// Which side of the connection a key set is for. The three fields are
/// the RFC 4253 §7.2 single-character derivation tags.
#[derive(Clone)]
pub struct Direction {
    ivTag: slice<byte>,
    keyTag: slice<byte>,
    macKeyTag: slice<byte>,
}

// go: none — Go writes the tags as `[]byte{'B'}` composite literals
// inline in init(); this is the one-byte-slice constructor for them.
fn tag(c: byte) -> slice<byte> {
    return slice::__from_vec(alloc::vec![c]);
}

// Go: kdf.go:20-25 — `var ServerKeys, ClientKeys Direction`, assigned in init().
/// `ssh.ServerKeys` — tags 'B', 'D', 'F'.
pub static ServerKeys: Lazy<Direction> = Lazy::new(|| Direction {
    ivTag: tag(b'B'),
    keyTag: tag(b'D'),
    macKeyTag: tag(b'F'),
});

/// `ssh.ClientKeys` — tags 'A', 'C', 'E'.
pub static ClientKeys: Lazy<Direction> = Lazy::new(|| Direction {
    ivTag: tag(b'A'),
    keyTag: tag(b'C'),
    macKeyTag: tag(b'E'),
});

// go: sdk 1.25.5 crypto/internal/fips140/ssh/kdf.go:27-55 Keys
/// `ssh.Keys(hash, d, K, H, sessionID, ivKeyLen, keyLen, macKeyLen)` —
/// derive the IV, encryption and MAC keys for one direction.
pub fn Keys(
    hash: impl IntoHashFunc,
    d: &Direction,
    K: slice<byte>,
    H: slice<byte>,
    sessionID: slice<byte>,
    ivKeyLen: int,
    keyLen: int,
    macKeyLen: int,
) -> (slice<byte>, slice<byte>, slice<byte>) {
    let hash = hash.into_hash_func();
    // Go: h := hash()
    let mut h = hash.Call();

    // go: none — Go's `generateKeyMaterial` is a closure inside Keys, not
    // a package-level decl; it is covered by Keys' own anchor above.
    //
    // Go: generateKeyMaterial := func(tag []byte, length int) []byte { … }
    //
    // Rust closures cannot capture `h` mutably and be called three times
    // while `h` is also read, so this is a nested fn taking `h` by
    // &mut — the body is otherwise verbatim.
    fn generateKeyMaterial(
        h: &mut Box<dyn Hash + Send + Sync>,
        K: &slice<byte>,
        H: &slice<byte>,
        sessionID: &slice<byte>,
        tag: &slice<byte>,
        length: int,
    ) -> slice<byte> {
        // Go: var key []byte
        let mut key = slice::__from_vec(Vec::<byte>::new());
        // Go: for len(key) < length { … }
        while key.Len() < length {
            // Go: h.Reset(); h.Write(K); h.Write(H)
            h.Reset();
            let _ = io::Writer::Write(h, K.clone());
            let _ = io::Writer::Write(h, H.clone());
            // Go: if len(key) == 0 { h.Write(tag); h.Write(sessionID) }
            //     else { h.Write(key) }
            if key.Len() == 0 {
                let _ = io::Writer::Write(h, tag.clone());
                let _ = io::Writer::Write(h, sessionID.clone());
            } else {
                let _ = io::Writer::Write(h, key.clone());
            }
            // Go: key = h.Sum(key)
            key = h.Sum(key);
        }
        // Go: return key[:length]
        let raw: &[byte] = &key;
        return slice::__from_vec(raw[..length as usize].to_vec());
    }

    // Go: ivKey = generateKeyMaterial(d.ivTag, ivKeyLen)
    let ivKey = generateKeyMaterial(&mut h, &K, &H, &sessionID, &d.ivTag, ivKeyLen);
    // Go: key = generateKeyMaterial(d.keyTag, keyLen)
    let key = generateKeyMaterial(&mut h, &K, &H, &sessionID, &d.keyTag, keyLen);
    // Go: macKey = generateKeyMaterial(d.macKeyTag, macKeyLen)
    let macKey = generateKeyMaterial(&mut h, &K, &H, &sessionID, &d.macKeyTag, macKeyLen);

    // Go: return
    return (ivKey, key, macKey);
}
