// go: package net/http
//
// go: file net/http/clone.go decls: cloneURLValues, cloneURL, cloneMultipartForm, cloneMultipartFileHeader, cloneOrMakeHeader
//
// The deep copies Request.Clone needs. Every one is unexported in Go
// and every one carries the same warning:
//
//   "should be an internal detail, but widely used packages access it
//    using linkname. Do not remove or change the type signature."
//
// goish has no linkname, so nothing outside the package can reach them
// — but the signatures are Go's regardless, because the point of the
// file is that they are load-bearing for callers Go cannot see.
//
// **Three of these five exist to preserve Go's nil-map-versus-empty-map
// distinction, and goish's `map` does not have one.** `map` has no nil
// state: `nil` converts to an empty map and `m == nil` is defined as
// `len(m) == 0` (gomap.rs, "Nil support"). So cloneURLValues cannot
// return a nil for a nil, and cloneOrMakeHeader's make-a-fresh-one
// branch is unreachable. The functions are ported in Go's shape with
// the tests written the way goish defines them, and this note is here
// so nobody later reads the collapsed branch as a porting mistake. It
// is a property of goish's map, and fixing it belongs there.
//
// Go's cloneURL also gives the copy its own Userinfo, the one URL field
// behind a pointer. goish's URL has no `User` field at all — see
// net/http/url.rs, which is a second copy of net/url — so there is
// nothing to deep-copy and the whole URL is values.

#![allow(non_snake_case)]
#![allow(dead_code)]

extern crate alloc;

use crate::gomap::map;
use crate::goslice::slice;
use crate::gostring::string;
use crate::mime::multipart::{FileHeader, Form};
use crate::types::int;

use super::header::Header;
use super::url::URL;

// go: sdk 1.25.5 net/http/clone.go:23-30 cloneURLValues
/// Go: "http.Header and url.Values have the same representation, so
/// temporarily treat it like http.Header, which does have a clone."
///
/// goish's Header WRAPS the map rather than being it, so the free type
/// conversion is a map clone instead — the same operation Header.Clone
/// performs, one independent `slice<string>` per key.
pub fn cloneURLValues(v: &map<string, slice<string>>) -> map<string, slice<string>> {
    // Go returns nil for nil. goish's map has no nil, and its `== nil`
    // means len == 0, so an empty in gives an empty out — which is the
    // same answer under goish's definition.
    let mut out: map<string, slice<string>> = map::new();
    for (k, vv) in v.__iter() {
        out.Set(k.clone(), vv.clone());
    }
    return out;
}

// go: sdk 1.25.5 net/http/clone.go:41-52 cloneURL
/// Go copies the URL struct by value and then gives the copy its own
/// Userinfo — the one field behind a pointer, and therefore the one a
/// shallow copy would share with the original.
///
/// goish's URL is values throughout (no `User` field), so the struct
/// copy IS the deep copy and there is no second step to perform.
pub fn cloneURL(u: Option<&URL>) -> Option<URL> {
    let u = match u {
        Some(u) => u,
        None => return None,
    };
    return Some(u.clone());
}

// go: sdk 1.25.5 net/http/clone.go:63-82 cloneMultipartForm
/// A nil Form clones to nil. Go builds the File map only inside
/// `if f.File != nil`, so a form with no files keeps a nil File map
/// rather than growing an empty one — a distinction goish's map does
/// not carry, per the module note.
pub fn cloneMultipartForm(f: Option<&Form>) -> Option<Form> {
    let f = match f {
        Some(f) => f,
        None => return None,
    };
    let mut f2 = Form::default();
    f2.Value = cloneURLValues(&f.Value);
    let mut m: map<string, slice<FileHeader>> = map::new();
    for (k, vv) in f.File.__iter() {
        let mut vv2: alloc::vec::Vec<FileHeader> =
            alloc::vec::Vec::with_capacity(crate::builtin::__make_size(vv.Len()));
        let mut i: int = 0;
        while i < vv.Len() {
            // Go: vv2[i] = cloneMultipartFileHeader(v). The input is a
            // non-nil element of the map, so the None arm cannot fire.
            if let Some(c) = cloneMultipartFileHeader(Some(&vv[i])) {
                vv2.push(c);
            }
            i += 1;
        }
        m.Set(k.clone(), slice::__from_vec(vv2));
    }
    f2.File = m;
    return Some(f2);
}

// go: sdk 1.25.5 net/http/clone.go:93-101 cloneMultipartFileHeader
/// Go copies the FileHeader by value and then replaces `Header` with a
/// clone — the one field that is a map, and so the one a shallow copy
/// would share.
pub fn cloneMultipartFileHeader(fh: Option<&FileHeader>) -> Option<FileHeader> {
    let fh = match fh {
        Some(fh) => fh,
        None => return None,
    };
    let mut fh2 = fh.clone();
    fh2.Header = cloneURLValues(&fh.Header);
    return Some(fh2);
}

// go: sdk 1.25.5 net/http/clone.go:115-121 cloneOrMakeHeader
/// Go: "cloneOrMakeHeader invokes Header.Clone but if the result is
/// nil, it'll instead make and return a non-nil Header."
///
/// The nil branch is the entire reason the function exists — a caller
/// about to Set a key cannot be handed a nil map. goish's Header wraps
/// a map that is never nil, so Clone always returns something usable
/// and the branch below can never be taken. Kept, because the day
/// goish's map grows a nil state it must be here already.
pub fn cloneOrMakeHeader(hdr: &Header) -> Header {
    let clone = hdr.Clone();
    if clone.Len() == 0 && hdr.Len() == 0 {
        return Header::new();
    }
    return clone;
}
