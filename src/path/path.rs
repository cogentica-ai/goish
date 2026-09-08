// go: file path/path.go decls: lazybuf.index, lazybuf.append, lazybuf.string, Clean, Split, Join, Ext, Base, IsAbs, Dir
//
// path.go — Clean, Split, Join, Ext, Base, IsAbs, Dir, and the
// lazybuf they share.

extern crate alloc;
use alloc::vec::Vec;

use crate::goslice::slice;
use crate::gostring::string;
use crate::types::byte;

pub(super) const SEP: byte = b'/';

// ─── lazybuf — lazily constructed path buffer (path.go:20) ─────────────

struct LazyBuf<'a> {
    s: &'a [u8],
    buf: Option<Vec<u8>>,
    w: usize,
}

impl<'a> LazyBuf<'a> {
    // go: none — goish idiom: Go writes `lazybuf{s: path}` inline and
    //     the zero value of the other two fields is what it wants.
    //     Rust's needs the constructor spelled.
    fn new(s: &'a [u8]) -> Self {
        return Self { s, buf: None, w: 0 };
    }

    // go: sdk 1.25.5 path/path.go:26-31 index
    fn index(&self, i: usize) -> byte {
        return match &self.buf {
            Some(b) => b[i],
            None => self.s[i],
        };
    }

    // go: sdk 1.25.5 path/path.go:33-44 append
    fn append(&mut self, c: byte) {
        if self.buf.is_none() {
            if self.w < self.s.len() && self.s[self.w] == c {
                self.w += 1;
                return;
            }
            let mut b = alloc::vec![0u8; self.s.len()];
            b[..self.w].copy_from_slice(&self.s[..self.w]);
            self.buf = Some(b);
        }
        let b = self.buf.as_mut().unwrap();
        b[self.w] = c;
        self.w += 1;
    }

    // go: sdk 1.25.5 path/path.go:46-51 lazybuf.string
    // goishlint:ignore GOISH014 - the anchor names the GO symbol,
    //     `string`, which in Rust is the name of goish's string TYPE.
    //     The method is `finish` for that reason.
    fn finish(self) -> string {
        return match self.buf {
            None => string::from_bytes(&self.s[..self.w]),
            Some(b) => string::from_bytes(&b[..self.w]),
        };
    }
}

// ─── Clean / Split / Join / Ext / Base / IsAbs / Dir ──────────────────

// go: sdk 1.25.5 path/path.go:72-138 Clean
/// `path.Clean(p)` — shortest path equivalent by purely lexical processing.
/// Mirrors path.go:72.
pub fn Clean<S: Into<string>>(p: S) -> string {
    let path_s = p.into();
    let path = path_s.as_bytes();
    if path.is_empty() {
        return string::from_static(".");
    }

    let rooted = path[0] == SEP;
    let n = path.len();

    let mut out = LazyBuf::new(path);
    let mut r: usize = 0;
    let mut dotdot: usize = 0;
    if rooted {
        out.append(SEP);
        r = 1;
        dotdot = 1;
    }

    while r < n {
        if path[r] == SEP {
            r += 1;
        } else if path[r] == b'.' && (r + 1 == n || path[r + 1] == SEP) {
            r += 1;
        } else if path[r] == b'.'
            && r + 1 < n
            && path[r + 1] == b'.'
            && (r + 2 == n || path[r + 2] == SEP)
        {
            r += 2;
            if out.w > dotdot {
                out.w -= 1;
                while out.w > dotdot && out.index(out.w) != SEP {
                    out.w -= 1;
                }
            } else if !rooted {
                if out.w > 0 {
                    out.append(SEP);
                }
                out.append(b'.');
                out.append(b'.');
                dotdot = out.w;
            }
        } else {
            if rooted && out.w != 1 || !rooted && out.w != 0 {
                out.append(SEP);
            }
            while r < n && path[r] != SEP {
                out.append(path[r]);
                r += 1;
            }
        }
    }

    if out.w == 0 {
        return string::from_static(".");
    }
    return out.finish();
}

// go: sdk 1.25.5 path/path.go:145-148 Split
/// `path.Split(p)` — splits at the final slash. Returns `(dir, file)`.
/// Mirrors path.go:145.
pub fn Split<S: Into<string>>(p: S) -> (string, string) {
    let p = p.into();
    let bytes = p.as_bytes();
    let mut i: isize = bytes.len() as isize - 1;
    while i >= 0 && bytes[i as usize] != SEP {
        i -= 1;
    }
    let cut = (i + 1) as usize;
    return (
        string::from_bytes(&bytes[..cut]),
        string::from_bytes(&bytes[cut..]),
    );
}

// go: sdk 1.25.5 path/path.go:155-173 Join
/// `path.Join(elem...)` — joins with `/`, then Cleans. Empty elements
/// are skipped. Mirrors path.go:155.
pub fn Join(elem: slice<string>) -> string {
    let v = elem.__into_vec();
    let size: usize = v.iter().map(|e| e.as_bytes().len()).sum();
    if size == 0 {
        return string::new();
    }
    let mut buf: Vec<u8> = Vec::with_capacity(size + v.len() - 1);
    for e in v {
        let eb = e.as_bytes();
        if !buf.is_empty() || !eb.is_empty() {
            if !buf.is_empty() {
                buf.push(SEP);
            }
            buf.extend_from_slice(eb);
        }
    }
    return Clean(string::__from_vec(buf));
}

// go: sdk 1.25.5 path/path.go:179-186 Ext
/// `path.Ext(p)` — extension at final dot of final element.
/// Mirrors path.go:179.
pub fn Ext<S: Into<string>>(p: S) -> string {
    let p = p.into();
    let bytes = p.as_bytes();
    let mut i: isize = bytes.len() as isize - 1;
    while i >= 0 && bytes[i as usize] != SEP {
        if bytes[i as usize] == b'.' {
            return string::from_bytes(&bytes[i as usize..]);
        }
        i -= 1;
    }
    return string::new();
}

// go: sdk 1.25.5 path/path.go:192-209 Base
/// `path.Base(p)` — last element of path. Mirrors path.go:192.
pub fn Base<S: Into<string>>(p: S) -> string {
    let p = p.into();
    let bytes = p.as_bytes();
    if bytes.is_empty() {
        return string::from_static(".");
    }
    let mut end = bytes.len();
    while end > 0 && bytes[end - 1] == SEP {
        end -= 1;
    }
    let trimmed = &bytes[..end];
    let mut i: isize = trimmed.len() as isize - 1;
    while i >= 0 && trimmed[i as usize] != SEP {
        i -= 1;
    }
    let last = if i >= 0 {
        &trimmed[(i + 1) as usize..]
    } else {
        trimmed
    };
    if last.is_empty() {
        return string::from_static("/");
    }
    return string::from_bytes(last);
}

// go: sdk 1.25.5 path/path.go:212-214 IsAbs
/// `path.IsAbs(p)` — leading slash. Mirrors path.go:212.
pub fn IsAbs<S: Into<string>>(p: S) -> bool {
    let p = p.into();
    let bytes = p.as_bytes();
    return !bytes.is_empty() && bytes[0] == SEP;
}

// go: sdk 1.25.5 path/path.go:223-226 Dir
/// `path.Dir(p)` — all but last element, Cleaned. Mirrors path.go:223.
pub fn Dir<S: Into<string>>(p: S) -> string {
    let (dir, _) = Split(p);
    return Clean(dir);
}

// go: waived lazybuf.string — ported as `fn finish` a few lines above, under a GOISH014 ignore: Go's method is named `string`, which is the name of goish's string TYPE, so the port cannot carry Go's spelling. port_coverage credits an anchored Recv.Method key only when the method name exists as a fn, and deliberately so — loosening that guard would let a stray anchor credit a declaration nobody wrote.
