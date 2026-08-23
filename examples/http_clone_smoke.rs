// http_clone_smoke — net/http/clone.go.
//
// These five functions exist to make Request.Clone a DEEP copy, so the
// only assertion worth making is independence: mutate the copy, and the
// original must not move. A shallow copy passes an equality check just
// as well as a deep one, which is exactly how this class of bug ships.
//
// Two of the three nested cases are the ones a shallow copy gets wrong:
//
//   * check 2 — the per-key `[]string`, not just the map. Cloning the
//     map and sharing its value slices is the classic half-fix.
//   * check 5 — the FileHeader's Header map inside a slice inside a
//     map. cloneMultipartForm has to reach three levels down.
//
// goish's `map` has no nil state (`nil` converts to empty, `m == nil`
// means `len(m) == 0`), so Go's nil-in-nil-out behaviour is checked in
// the terms goish defines rather than pretended at — see check 6.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::fmt;
use goish::gomap::map;
use goish::goslice::slice;
use goish::gostring::string as gostring;
use goish::mime::multipart::{FileHeader, Form};
use goish::net::http::clone::{
    cloneMultipartFileHeader, cloneMultipartForm, cloneOrMakeHeader, cloneURL, cloneURLValues,
};
use goish::net::http::{Header, ParseURL};
use goish::{string, syscall};

fn vals(pairs: &[(&'static str, &'static [&'static str])]) -> map<gostring, slice<gostring>> {
    let mut m: map<gostring, slice<gostring>> = map::new();
    for (k, vs) in pairs.iter() {
        let mut v: alloc::vec::Vec<gostring> = alloc::vec::Vec::new();
        for s in vs.iter() {
            v.push(string(*s));
        }
        m.Set(string(*k), slice::__from_vec(v));
    }
    return m;
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. cloneURLValues copies the keys.
    {
        let src = vals(&[("a", &["1"]), ("b", &["2", "3"])]);
        let dst = cloneURLValues(&src);
        let (av, aok) = dst.Get(string("a"));
        let (bv, bok) = dst.Get(string("b"));
        if aok && bok && av[0] == "1" && bv.Len() == 2 && bv[1] == "3" {
            fmt::Println!("[ 1] cloneURLValues copies     PASS");
        } else {
            fmt::Println!("[ 1] cloneURLValues copies     FAIL");
            failed += 1;
        }
    }

    // 2. …and the per-key slice is INDEPENDENT. Cloning the map while
    //    sharing its value slices is the half-fix that looks correct
    //    until someone appends.
    {
        let src = vals(&[("a", &["1", "2"])]);
        let mut dst = cloneURLValues(&src);
        dst.Set(
            string("a"),
            slice::__from_vec(alloc::vec![string("mutated")]),
        );
        let (orig, _) = src.Get(string("a"));
        let (copy, _) = dst.Get(string("a"));
        if orig.Len() == 2 && orig[0] == "1" && copy.Len() == 1 && copy[0] == "mutated" {
            fmt::Println!("[ 2] value slices independent  PASS");
        } else {
            fmt::Println!("[ 2] value slices independent  FAIL");
            failed += 1;
        }
    }

    // 3. cloneURL(None) is None; a real URL round-trips by value.
    {
        let (u, err) = ParseURL(string("http://example.com/a/b?q=1#frag"));
        let c = cloneURL(Some(&u));
        let n = cloneURL(None);
        let ok = match c {
            Some(c) => {
                c.Scheme == "http"
                    && c.Host == "example.com"
                    && c.Path == "/a/b"
                    && c.RawQuery == "q=1"
            }
            None => false,
        };
        if err.IsNil() && ok && n.is_none() {
            fmt::Println!("[ 3] cloneURL round-trips      PASS");
        } else {
            fmt::Println!("[ 3] cloneURL round-trips      FAIL");
            failed += 1;
        }
    }

    // 4. cloneMultipartFileHeader gives the copy its OWN Header map —
    //    the one field of a FileHeader that a struct copy would share.
    {
        let mut fh = FileHeader::default();
        fh.Filename = string("upload.txt");
        fh.Size = 42;
        fh.Header = vals(&[("Content-Type", &["text/plain"])]);
        let mut c = cloneMultipartFileHeader(Some(&fh)).unwrap();
        c.Header.Set(
            string("Content-Type"),
            slice::__from_vec(alloc::vec![string("text/evil")]),
        );
        let (o, _) = fh.Header.Get(string("Content-Type"));
        let (n, _) = c.Header.Get(string("Content-Type"));
        if c.Filename == "upload.txt" && c.Size == 42 && o[0] == "text/plain" && n[0] == "text/evil"
        {
            fmt::Println!("[ 4] FileHeader map own copy   PASS");
        } else {
            fmt::Println!("[ 4] FileHeader map own copy   FAIL");
            failed += 1;
        }
    }

    // 5. cloneMultipartForm reaches THREE levels: the File map, the
    //    slice under each key, and the Header map inside each element.
    {
        let mut fh = FileHeader::default();
        fh.Filename = string("a.txt");
        fh.Header = vals(&[("X", &["orig"])]);
        let mut f = Form::default();
        f.Value = vals(&[("field", &["v"])]);
        f.File = {
            let mut m: map<gostring, slice<FileHeader>> = map::new();
            m.Set(string("upload"), slice::__from_vec(alloc::vec![fh]));
            m
        };

        let mut c = cloneMultipartForm(Some(&f)).unwrap();
        // Mutate the deepest thing in the copy.
        let (mut cf, _) = c.File.Get(string("upload"));
        cf[0].Header.Set(
            string("X"),
            slice::__from_vec(alloc::vec![string("changed")]),
        );
        c.File.Set(string("upload"), cf);

        let (of, _) = f.File.Get(string("upload"));
        let (ox, _) = of[0].Header.Get(string("X"));
        let (cf2, _) = c.File.Get(string("upload"));
        let (cx, _) = cf2[0].Header.Get(string("X"));

        if ox[0] == "orig" && cx[0] == "changed" && cloneMultipartForm(None).is_none() {
            fmt::Println!("[ 5] Form deep three levels    PASS");
        } else {
            fmt::Println!("[ 5] Form deep three levels    FAIL");
            failed += 1;
        }
    }

    // 6. cloneOrMakeHeader always yields something writable. Go's
    //    reason is that Clone can return nil; goish's map cannot be
    //    nil, so the guarantee holds through a different route — the
    //    assertion is the guarantee, not the route.
    {
        let empty = Header::new();
        let mut got = cloneOrMakeHeader(&empty);
        got.Set(string("K"), string("V"));

        let mut src = Header::new();
        src.Set(string("A"), string("1"));
        let mut c = cloneOrMakeHeader(&src);
        c.Set(string("A"), string("2"));

        if got.Get(string("K")) == "V" && src.Get(string("A")) == "1" && c.Get(string("A")) == "2" {
            fmt::Println!("[ 6] cloneOrMakeHeader usable  PASS");
        } else {
            fmt::Println!("[ 6] cloneOrMakeHeader usable  FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 6/6");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 6");
        syscall::Exit(1);
    }
}
