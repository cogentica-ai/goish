// go: file strings/replace.go decls: NewReplacer, Replacer.build, trieNode.add, genericReplacer.lookup, makeGenericReplacer, genericReplacer.Replace, genericReplacer.WriteString, makeSingleStringReplacer, singleStringReplacer.Replace, singleStringReplacer.WriteString, byteReplacer.Replace, byteReplacer.WriteString, byteStringReplacer.Replace, byteStringReplacer.WriteString, Replacer.Replace, Replacer.WriteString
//
// go: waived Replacer.buildOnce — Go defers the trie build to the first
//     Replace behind a sync.Once so NewReplacer stays allocation-free.
//     A goish `&self` method cannot lazily initialise without interior
//     mutability, which would cost Replacer the Clone its callers use,
//     so NewReplacer builds eagerly and `build` is a free function.
// go: waived getStringWriter — exists only to reach io.StringWriter
//     when the caller's io.Writer also implements it, saving one
//     string->[]byte copy. goish's io::Writer already takes
//     slice<byte> and there is no io::StringWriter to assert for.
//
// goishlint:ignore GOISH018 Replacer.buildOnce, appendSliceWriter.Write, getStringWriter — two Go
//     shapes with no goish counterpart. `buildOnce` exists so Go's
//     `NewReplacer` can stay allocation-free and defer the trie build
//     to the first `Replace` behind a `sync.Once`; a goish `&self`
//     method cannot lazily initialise without interior mutability,
//     which would cost `Replacer` the `Clone` its callers already use,
//     so `NewReplacer` builds eagerly and `build` is a free function.
//     `appendSliceWriter`, `stringWriter` and `getStringWriter` exist
//     only to reach `io.StringWriter` when the caller's `io.Writer`
//     also implements it, saving a string->[]byte copy; goish's
//     `io::Writer` already takes `slice<byte>` and there is no
//     `io::StringWriter` to type-assert for.
//
// goishlint:ignore GOISH021 replacer, appendSliceWriter, stringWriter, countCutOff — `replacer` is Go's
//     interface over the four algorithms; goish spells it as the enum
//     below, since the implementation set is closed and goish avoids
//     `dyn`. `countCutOff` tunes which of two counting loops
//     `byteStringReplacer.Replace` uses — both produce the same
//     `newSize`, and goish keeps the cheaper one unconditionally.
//
// strings/replace.go — `Replacer`, and the four algorithms it picks
// between.
//
// `NewReplacer` does not replace anything; `build` chooses how:
//
//   * one pattern longer than a byte      singleStringReplacer, which
//                                         is Boyer-Moore (search.rs)
//   * every old AND new exactly one byte  byteReplacer, a 256-byte
//                                         translation table
//   * every old one byte, news vary       byteStringReplacer, a
//                                         256-entry table of slices
//   * anything else                       genericReplacer, a trie
//
// The trie is the interesting one. Keys are matched neither
// shortest- nor longest-first: each carries a priority — higher for an
// earlier argument — and `lookup` walks the whole path taking the
// highest-priority complete key it passes. That is what Go's "the old
// string comparisons are done in argument order" means, and it is why
// `NewReplacer("a", "1", "ab", "2")` turns "ab" into "1b" while
// `NewReplacer("ab", "2", "a", "1")` turns it into "2".

#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::convert::int as toint;
use crate::errors::{error, nil};
use crate::goslice::slice;
use crate::gostring::string;
use crate::io;
use crate::types::{byte, int};

use super::search::{makeStringFinder, stringFinder};

// go: sdk 1.25.5 strings/replace.go:12-18 Replacer
// goishlint:ignore GOISH019 Replacer — Go's fields are `once
//     sync.Once`, `r replacer` and `oldnew []string`. goish builds `r`
//     in `NewReplacer` (see the GOISH018 waiver at the top of the
//     file), so there is no deferred build for `once` to guard and no
//     `oldnew` to keep until it runs. Nothing observable is dropped.
/// `strings.Replacer` — replaces a list of strings with replacements.
///
/// Go's fields are `once sync.Once`, `r replacer` and `oldnew []string`;
/// goish builds `r` in `NewReplacer` (see the GOISH018 waiver above), so
/// the `once` and the retained `oldnew` have nothing left to do.
#[derive(Clone)]
pub struct Replacer {
    r: replacer,
}

// go: none — goish idiom: Go's `replacer` is an interface with two
//     methods and exactly four implementations, all in this file.
//     goish spells a closed implementation set as an enum rather than
//     a `dyn` trait object; the two methods dispatch below.
#[derive(Clone)]
enum replacer {
    generic(genericReplacer),
    single(singleStringReplacer),
    byte_(byteReplacer),
    byteString(byteStringReplacer),
}

impl replacer {
    // go: none — goish idiom: the `replacer` interface's `Replace`,
    //     dispatched over the closed enum instead of a `dyn` method
    //     table. Each arm is one of the four Go implementations.
    fn Replace(&self, s: &string) -> string {
        return match self {
            replacer::generic(r) => r.Replace(s),
            replacer::single(r) => r.Replace(s),
            replacer::byte_(r) => r.Replace(s),
            replacer::byteString(r) => r.Replace(s),
        };
    }

    // go: none — goish idiom: the `replacer` interface's `WriteString`,
    //     dispatched over the same enum.
    fn WriteString(&self, w: &mut dyn io::Writer, s: &string) -> (int, error) {
        return match self {
            replacer::generic(r) => r.WriteString(w, s),
            replacer::single(r) => r.WriteString(w, s),
            replacer::byte_(r) => r.WriteString(w, s),
            replacer::byteString(r) => r.WriteString(w, s),
        };
    }
}

// go: sdk 1.25.5 strings/replace.go:26-36 NewReplacer
/// A new [`Replacer`] from a list of old, new string pairs.
///
/// Replacements are performed in the order they appear in the target
/// string, without overlapping matches. The old string comparisons are
/// done in argument order. Panics, as Go does, on an odd argument
/// count.
///
/// Go's variadic `oldnew ...string` is goish's `slice<string>`.
pub fn NewReplacer(oldnew: slice<string>) -> Replacer {
    if oldnew.Len() % 2 == 1 {
        panic!("strings.NewReplacer: odd argument count");
    }
    return Replacer { r: build(&oldnew) };
}

// go: sdk 1.25.5 strings/replace.go:43-92 Replacer.build
// goishlint:ignore GOISH014 — the anchor names Go's `(*Replacer).build`,
//     a method on the half-built Replacer. goish builds before the
//     Replacer exists, so it is a free function over the same slice.
fn build(oldnew: &slice<string>) -> replacer {
    let n = oldnew.Len();
    if n == 2 && oldnew[0].Len() > 1 {
        return replacer::single(makeSingleStringReplacer(
            oldnew[0].clone(),
            oldnew[1].clone(),
        ));
    }

    let mut allNewBytes = true;
    let mut i: int = 0;
    while i < n {
        if oldnew[i].Len() != 1 {
            return replacer::generic(makeGenericReplacer(oldnew));
        }
        if oldnew[i + 1].Len() != 1 {
            allNewBytes = false;
        }
        i += 2;
    }

    if allNewBytes {
        let mut r = byteReplacer { table: [0; 256] };
        let mut i = 0usize;
        while i < 256 {
            r.table[i] = i as byte; // goishlint:ignore GOISH005 - `byte(i)` on a loop index.
            i += 1;
        }
        // The first occurrence of an old->new map takes precedence over
        // the others with the same old string, so walk backwards.
        let mut i: int = n - 2;
        while i >= 0 {
            let o = oldnew[i].as_bytes()[0];
            let nb = oldnew[i + 1].as_bytes()[0];
            r.table[o as usize] = nb;
            i -= 2;
        }
        return replacer::byte_(r);
    }

    let mut r = byteStringReplacer {
        replacements: (0..256).map(|_| None).collect(),
        toReplace: Vec::with_capacity((n / 2) as usize),
    };
    // Same precedence rule, same backwards walk.
    let mut i: int = n - 2;
    while i >= 0 {
        let o = oldnew[i].as_bytes()[0];
        let nb = oldnew[i + 1].clone();
        // Avoid counting repetitions multiple times.
        if r.replacements[o as usize].is_none() {
            // Go writes `string([]byte{o})` rather than `string(o)`, so
            // a byte above 0x7f does not become a two-byte UTF-8
            // sequence.
            r.toReplace.push(string::from_bytes(&[o]));
        }
        r.replacements[o as usize] = Some(nb.as_bytes().to_vec());
        i -= 2;
    }
    return replacer::byteString(r);
}

impl Replacer {
    // go: sdk 1.25.5 strings/replace.go:94-98 Replacer.Replace
    /// A copy of `s` with all replacements performed.
    pub fn Replace<S: Into<string>>(&self, s: S) -> string {
        let s: string = s.into();
        return self.r.Replace(&s);
    }

    // go: sdk 1.25.5 strings/replace.go:100-104 Replacer.WriteString
    /// Writes `s` to `w` with all replacements performed.
    pub fn WriteString<S: Into<string>>(&self, w: &mut dyn io::Writer, s: S) -> (int, error) {
        let s: string = s.into();
        return self.r.WriteString(w, &s);
    }
}

// ───── the trie ──────────────────────────────────────────────────────

// go: sdk 1.25.5 strings/replace.go:106-155 trieNode
/// A node in a lookup trie for prioritized key/value pairs. Keys and
/// values may both be empty.
///
/// Go's worked example: the trie holding "ax", "ay", "bcbc", "x" and
/// "xy" has eight nodes, of which n0, n1 and n4 are partial keys and
/// n2, n3, n5, n6, n7 are complete ones.
///
/// A node has zero, one or more children: no children when `prefix`,
/// `next` and `table` are all empty; one child in `next` when `prefix`
/// and `next` are set; and all of them in `table` otherwise. A prefix
/// is preferred when there is one child, but the root always uses a
/// table for lookup speed.
#[derive(Clone, Default)]
struct trieNode {
    // Go: value string — empty if this node is not a complete key.
    value: string,
    // Go: priority int — higher is more important; positive only for a
    // complete key.
    priority: int,
    // Go: prefix string — the difference in keys between this node and
    // `next`.
    prefix: string,
    // Go: next *trieNode
    next: Option<Box<trieNode>>,
    // Go: table []*trieNode — indexed by the next key byte remapped
    // through genericReplacer.mapping. An empty Vec is Go's nil.
    table: Vec<Option<Box<trieNode>>>,
}

impl trieNode {
    // go: sdk 1.25.5 strings/replace.go:158-219 trieNode.add
    // goishlint:ignore GOISH020 — Go passes the whole
    //     `*genericReplacer` and reads two fields off it; goish passes
    //     those two fields, because the replacer is already borrowed
    //     mutably through its own `root` while this runs.
    fn add(
        &mut self,
        key: &[u8],
        val: &string,
        priority: int,
        tableSize: int,
        mapping: &[byte; 256],
    ) {
        if key.is_empty() {
            if self.priority == 0 {
                self.value = val.clone();
                self.priority = priority;
            }
            return;
        }

        if self.prefix.Len() != 0 {
            // The prefix has to be split among multiple nodes.
            let pfx = self.prefix.as_bytes().to_vec();
            // Length of the longest common prefix.
            let mut n = 0usize;
            while n < pfx.len() && n < key.len() {
                if pfx[n] != key[n] {
                    break;
                }
                n += 1;
            }
            if n == pfx.len() {
                self.next
                    .as_mut()
                    .unwrap()
                    .add(&key[n..], val, priority, tableSize, mapping);
            } else if n == 0 {
                // The first byte differs, so start a new lookup table
                // here: what is currently prefix[0] leads to
                // prefixNode, and key[0] leads to keyNode.
                let prefixNode: Box<trieNode> = if pfx.len() == 1 {
                    self.next.take().unwrap()
                } else {
                    Box::new(trieNode {
                        prefix: string::from_bytes(&pfx[1..]),
                        next: self.next.take(),
                        ..Default::default()
                    })
                };
                let mut keyNode: Box<trieNode> = Box::new(trieNode::default());
                self.table = (0..tableSize as usize).map(|_| None).collect();
                self.table[mapping[pfx[0] as usize] as usize] = Some(prefixNode);
                keyNode.add(&key[1..], val, priority, tableSize, mapping);
                self.table[mapping[key[0] as usize] as usize] = Some(keyNode);
                self.prefix = string::new();
                self.next = None;
            } else {
                // Insert a new node after the common section of the
                // prefix.
                let mut next = Box::new(trieNode {
                    prefix: string::from_bytes(&pfx[n..]),
                    next: self.next.take(),
                    ..Default::default()
                });
                self.prefix = string::from_bytes(&pfx[..n]);
                next.add(&key[n..], val, priority, tableSize, mapping);
                self.next = Some(next);
            }
        } else if !self.table.is_empty() {
            // Insert into the existing table.
            let m = mapping[key[0] as usize] as usize;
            if self.table[m].is_none() {
                self.table[m] = Some(Box::new(trieNode::default()));
            }
            self.table[m]
                .as_mut()
                .unwrap()
                .add(&key[1..], val, priority, tableSize, mapping);
        } else {
            self.prefix = string::from_bytes(key);
            let mut next = Box::new(trieNode::default());
            next.add(&[], val, priority, tableSize, mapping);
            self.next = Some(next);
        }
    }
}

// go: sdk 1.25.5 strings/replace.go:257-267 genericReplacer
/// The fully generic algorithm, used when nothing faster applies.
#[derive(Clone)]
struct genericReplacer {
    root: trieNode,
    // Go: tableSize int — the number of unique key bytes.
    tableSize: int,
    // Go: mapping [256]byte — key byte to a dense table index.
    mapping: [byte; 256],
}

// go: sdk 1.25.5 strings/replace.go:268-298 makeGenericReplacer
fn makeGenericReplacer(oldnew: &slice<string>) -> genericReplacer {
    let mut r = genericReplacer {
        root: trieNode::default(),
        tableSize: 0,
        mapping: [0; 256],
    };
    // Find each byte used, then assign them each an index.
    let mut i: int = 0;
    while i < oldnew.Len() {
        for b in oldnew[i].as_bytes().iter() {
            r.mapping[*b as usize] = 1;
        }
        i += 2;
    }

    let mut k = 0usize;
    while k < 256 {
        r.tableSize += toint(r.mapping[k]);
        k += 1;
    }

    let mut index: byte = 0;
    let mut k = 0usize;
    while k < 256 {
        if r.mapping[k] == 0 {
            r.mapping[k] = r.tableSize as byte; // goishlint:ignore GOISH005 - `byte(r.tableSize)`.
        } else {
            r.mapping[k] = index;
            index += 1;
        }
        k += 1;
    }
    // Ensure the root node uses a lookup table, for performance.
    r.root.table = (0..r.tableSize as usize).map(|_| None).collect();

    let n = oldnew.Len();
    let (tableSize, mapping) = (r.tableSize, r.mapping);
    let mut i: int = 0;
    while i < n {
        let key = oldnew[i].as_bytes().to_vec();
        r.root.add(&key, &oldnew[i + 1], n - i, tableSize, &mapping);
        i += 2;
    }
    return r;
}

impl genericReplacer {
    // go: sdk 1.25.5 strings/replace.go:210-255 genericReplacer.lookup
    /// Walks down the trie, taking the value and key length of the
    /// highest-priority complete key on the path.
    fn lookup(&self, s: &[u8], ignoreRoot: bool) -> (string, int, bool) {
        let mut val = string::new();
        let mut keylen: int = 0;
        let mut found = false;
        let mut bestPriority: int = 0;
        let mut node: Option<&trieNode> = Some(&self.root);
        let mut isRoot = true;
        let mut s = s;
        let mut n: int = 0;
        while let Some(nd) = node {
            if nd.priority > bestPriority && !(ignoreRoot && isRoot) {
                bestPriority = nd.priority;
                val = nd.value.clone();
                keylen = n;
                found = true;
            }
            isRoot = false;

            if s.is_empty() {
                break;
            }
            if !nd.table.is_empty() {
                let index = self.mapping[s[0] as usize];
                if toint(index) == self.tableSize {
                    break;
                }
                node = nd.table[index as usize].as_deref();
                s = &s[1..];
                n += 1;
            } else if nd.prefix.Len() != 0 && s.starts_with(nd.prefix.as_bytes()) {
                let plen = nd.prefix.as_bytes().len();
                n += toint(plen);
                s = &s[plen..];
                node = nd.next.as_deref();
            } else {
                break;
            }
        }
        return (val, keylen, found);
    }

    // go: sdk 1.25.5 strings/replace.go:328-333 genericReplacer.Replace
    fn Replace(&self, s: &string) -> string {
        let mut buf: Vec<u8> = Vec::with_capacity(s.as_bytes().len());
        self.write_into(&mut buf, s);
        return string::from_bytes(&buf);
    }

    // go: sdk 1.25.5 strings/replace.go:336-375 genericReplacer.WriteString
    fn WriteString(&self, w: &mut dyn io::Writer, s: &string) -> (int, error) {
        let mut buf: Vec<u8> = Vec::with_capacity(s.as_bytes().len());
        self.write_into(&mut buf, s);
        return w.Write(slice::__from_vec(buf));
    }

    // go: none — goish idiom: Go's `Replace` and `WriteString` share one
    //     body by both writing through an `io.StringWriter`, with
    //     `Replace` passing an `appendSliceWriter` over a local buffer.
    //     goish has no `io::StringWriter`, so the shared body writes
    //     into the buffer directly and the two callers differ only in
    //     what they do with it.
    fn write_into(&self, buf: &mut Vec<u8>, s: &string) {
        let sb = s.as_bytes();
        let mut last = 0usize;
        let mut prevMatchEmpty = false;
        let mut i = 0usize;
        while i <= sb.len() {
            // Fast path: s[i] is not a prefix of any pattern.
            if i != sb.len() && self.root.priority == 0 {
                let index = self.mapping[sb[i] as usize] as usize;
                if toint(index) == self.tableSize || self.root.table[index].is_none() {
                    i += 1;
                    continue;
                }
            }

            // Ignore the empty match iff the previous loop found one.
            let (val, keylen, m) = self.lookup(&sb[i..], prevMatchEmpty);
            prevMatchEmpty = m && keylen == 0;
            if m {
                buf.extend_from_slice(&sb[last..i]);
                buf.extend_from_slice(val.as_bytes());
                i += keylen as usize;
                last = i;
                continue;
            }
            i += 1;
        }
        if last != sb.len() {
            buf.extend_from_slice(&sb[last..]);
        }
    }
}

// ───── single string ─────────────────────────────────────────────────

// go: sdk 1.25.5 strings/replace.go:379-383 singleStringReplacer
/// Used when there is exactly one pattern and it is longer than a byte.
#[derive(Clone)]
struct singleStringReplacer {
    finder: stringFinder,
    // Go: value string — what replaces the pattern when found.
    value: string,
}

// go: sdk 1.25.5 strings/replace.go:385-387 makeSingleStringReplacer
fn makeSingleStringReplacer(pattern: string, value: string) -> singleStringReplacer {
    return singleStringReplacer {
        finder: makeStringFinder(pattern),
        value,
    };
}

impl singleStringReplacer {
    // go: sdk 1.25.5 strings/replace.go:389-408 singleStringReplacer.Replace
    fn Replace(&self, s: &string) -> string {
        let sb = s.as_bytes();
        let mut buf: Vec<u8> = Vec::new();
        let mut i = 0usize;
        let mut matched = false;
        loop {
            let m = self.finder.next(&sb[i..]);
            if m == -1 {
                break;
            }
            matched = true;
            let m = m as usize;
            buf.reserve(m + self.value.as_bytes().len());
            buf.extend_from_slice(&sb[i..i + m]);
            buf.extend_from_slice(self.value.as_bytes());
            i += m + self.finder.patternLen();
        }
        if !matched {
            return s.clone();
        }
        buf.extend_from_slice(&sb[i..]);
        return string::from_bytes(&buf);
    }

    // go: sdk 1.25.5 strings/replace.go:405-432 singleStringReplacer.WriteString
    fn WriteString(&self, w: &mut dyn io::Writer, s: &string) -> (int, error) {
        let out = self.Replace(s);
        return w.Write(slice::__from_vec(out.as_bytes().to_vec()));
    }
}

// ───── byte tables ───────────────────────────────────────────────────

// go: sdk 1.25.5 strings/replace.go:438-438 byteReplacer
/// Used when every old and new value is a single byte: a 256-entry
/// translation table indexed by the old byte.
#[derive(Clone)]
struct byteReplacer {
    table: [byte; 256],
}

impl byteReplacer {
    // go: sdk 1.25.5 strings/replace.go:440-455 byteReplacer.Replace
    fn Replace(&self, s: &string) -> string {
        let sb = s.as_bytes();
        // Go allocates `buf` lazily, and returns `s` untouched when it
        // stayed nil.
        let mut buf: Option<Vec<u8>> = None;
        let mut i = 0usize;
        while i < sb.len() {
            let b = sb[i];
            if self.table[b as usize] != b {
                if buf.is_none() {
                    buf = Some(sb.to_vec());
                }
                buf.as_mut().unwrap()[i] = self.table[b as usize];
            }
            i += 1;
        }
        return match buf {
            None => s.clone(),
            Some(v) => string::from_bytes(&v),
        };
    }

    // go: sdk 1.25.5 strings/replace.go:457-487 byteReplacer.WriteString
    fn WriteString(&self, w: &mut dyn io::Writer, s: &string) -> (int, error) {
        let out = self.Replace(s);
        return w.Write(slice::__from_vec(out.as_bytes().to_vec()));
    }
}

// go: sdk 1.25.5 strings/replace.go:491-499 byteStringReplacer
/// Used when every old value is a single byte but the new values vary
/// in size: a 256-entry table of replacement slices, `None` meaning
/// "do not replace".
#[derive(Clone)]
struct byteStringReplacer {
    // Go: replacements [256][]byte — a fixed array, since a Go slice
    // header is two words and the whole thing is 4 KiB it happily puts
    // on a stack that grows.
    //
    // goish heaps it. An `[Option<Vec<u8>>; 256]` is 6 KiB, and every
    // way of building one in place — `array::from_fn`, an inline-const
    // repeat — materialises it in a stack slot, then the enum below
    // copies it again on the way out of `build`. A goroutine stack
    // starts at 64 KiB, and `html::EscapeString` calls `NewReplacer`
    // inside the serve goroutine, so that overflowed and took the
    // connection's goroutine with it. Length is still exactly 256 and
    // every index is a byte, so nothing else changes.
    replacements: Vec<Option<Vec<u8>>>,
    // Go: toReplace []string — the bytes that get replaced, each held
    // as a one-byte string because Go's `Count` takes a string.
    toReplace: Vec<string>,
}

impl byteStringReplacer {
    // go: sdk 1.25.5 strings/replace.go:510-548 byteStringReplacer.Replace
    fn Replace(&self, s: &string) -> string {
        let sb = s.as_bytes();
        // Go's `newSize` is an `int`, and it must be: a replacement
        // shorter than the byte it replaces makes `len(rep) - 1`
        // negative, which a `usize` cannot hold.
        let mut newSize: int = toint(sb.len());
        let mut anyChanges = false;
        // Go picks between `Count` per replaced byte and one pass over
        // the string, on the `countCutOff` ratio. Both compute the same
        // newSize; goish always takes the single pass, which is the
        // cheaper of the two whenever there is more than one pattern.
        let mut i = 0usize;
        while i < sb.len() {
            if let Some(rep) = &self.replacements[sb[i] as usize] {
                // The -1 is because one byte is replaced by
                // len(replacements[b]) bytes.
                newSize += toint(rep.len()) - 1;
                anyChanges = true;
            }
            i += 1;
        }
        if !anyChanges {
            return s.clone();
        }
        let mut buf: Vec<u8> = Vec::with_capacity(newSize as usize);
        let mut i = 0usize;
        while i < sb.len() {
            match &self.replacements[sb[i] as usize] {
                Some(rep) => buf.extend_from_slice(rep),
                None => buf.push(sb[i]),
            }
            i += 1;
        }
        return string::from_bytes(&buf);
    }

    // go: sdk 1.25.5 strings/replace.go:550-578 byteStringReplacer.WriteString
    fn WriteString(&self, w: &mut dyn io::Writer, s: &string) -> (int, error) {
        let out = self.Replace(s);
        return w.Write(slice::__from_vec(out.as_bytes().to_vec()));
    }
}

// go: none — goish idiom: keeps `nil` in scope for the `error` half of
//     the tuples above without an unused-import warning when a build
//     configuration drops one of the four algorithms.
#[allow(dead_code)]
fn __nil_error() -> error {
    return nil;
}

// The three writer methods behind `getStringWriter`, waived out of the
// coverage denominator for the reason already given in the GOISH018
// ignore at the top of this file: `appendSliceWriter` and
// `stringWriter` exist only so Go can reach `io.StringWriter` when a
// caller's `io.Writer` also implements it, saving a string->[]byte
// copy. goish's `io::Writer` already takes `slice<byte>` and there is
// no `io::StringWriter` to type-assert for, so the two shims and their
// methods have nothing to be.
//
// go: waived appendSliceWriter.Write — a shim for Go's io.StringWriter fast path; no goish counterpart.
// go: waived appendSliceWriter.WriteString — likewise.
// go: waived stringWriter.WriteString — likewise.
