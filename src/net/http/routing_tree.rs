// go: package net/http
//
// go: file net/http/routing_tree.go decls: routingNode.addPattern, routingNode.addSegments, routingNode.set, routingNode.addChild, routingNode.findChild, routingNode.match, routingNode.matchMethodAndPath, routingNode.matchPath, firstSegment, routingNode.matchingMethods, routingNode.matchingMethodsPath
//
// Go: the decision tree ServeMux matches against. Level one is host,
// level two is method, the rest are path segments. Two special child
// keys: "/" for a trailing slash from "{$}", and "" for a single
// wildcard.
//
// The ORDER of the three attempts in matchPath is the whole routing
// rule, and it is load-bearing: literal first, then single wildcard,
// then multi. Go can rely on it because registration already rejected
// any two patterns that overlap without one being more specific — that
// is what pattern.go's conflict lattice is for. Reordering these makes
// "/a/b" lose to "/a/{x}" with nothing to detect it.
//
// Go calls several of these methods on a NIL receiver — `n.findChild(k)`
// may return nil and the result is immediately used as a receiver, with
// the method's first line being `if n == nil`. Rust has no nil
// receiver, so those become associated functions taking
// `Option<&routingNode>`, which is the same thing spelled out.

#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::goslice::slice;
use crate::gostring::string;
use crate::strings;

use super::mapping::mapping;
use super::pattern::{pathUnescape, pattern, segment};
use super::server::Handler;

// go: sdk 1.25.5 net/http/routing_tree.go:27-40 routingNode
/// Go: "A routingNode is a node in the decision tree. The same struct
/// is used for leaf and interior nodes."
#[derive(Default)]
pub struct routingNode {
    /// Go: "A leaf node holds a single pattern and the Handler it was
    /// registered with."
    pub pattern: Option<pattern>,
    pub handler: Option<Arc<dyn Handler>>,

    /// Go: "An interior node maps parts of the incoming request to
    /// child nodes."
    pub children: mapping<string, Box<routingNode>>,
    /// Go: "child with multi wildcard".
    pub multiChild: Option<Box<routingNode>>,
    /// Go: "optimization: child with key """.
    pub emptyChild: Option<Box<routingNode>>,
}

impl routingNode {
    // go: sdk 1.25.5 net/http/routing_tree.go:44-51 routingNode.addPattern
    /// Go: "addPattern adds a pattern and its associated Handler to the
    /// tree at root."
    pub fn addPattern(&mut self, p: &pattern, h: Arc<dyn Handler>) {
        // Go: "First level of tree is host."
        let n = self.addChild(p.host.clone());
        // Go: "Second level of tree is method."
        let n = n.addChild(p.method.clone());
        // Go: "Remaining levels are path."
        n.addSegments(&p.segments, p, h);
    }

    // go: sdk 1.25.5 net/http/routing_tree.go:56-74 routingNode.addSegments
    /// Go: "addSegments adds the given segments to the tree rooted at
    /// n. If there are no segments, then n is a leaf node that holds
    /// the given pattern and handler."
    pub fn addSegments(&mut self, segs: &slice<segment>, p: &pattern, h: Arc<dyn Handler>) {
        if segs.Len() == 0 {
            self.set(p, h);
            return;
        }
        let seg = segs[0].clone();
        if seg.multi {
            if segs.Len() != 1 {
                panic!("multi wildcard not last");
            }
            let mut c = Box::new(routingNode::default());
            c.set(p, h);
            self.multiChild = Some(c);
        } else if seg.wild {
            let rest = segs.slice(1, segs.Len());
            self.addChild(string::new()).addSegments(&rest, p, h);
        } else {
            let rest = segs.slice(1, segs.Len());
            self.addChild(seg.s.clone()).addSegments(&rest, p, h);
        }
    }

    // go: sdk 1.25.5 net/http/routing_tree.go:78-84 routingNode.set
    /// Go: "set sets the pattern and handler for n, which must be a
    /// leaf node."
    pub fn set(&mut self, p: &pattern, h: Arc<dyn Handler>) {
        if self.pattern.is_some() || self.handler.is_some() {
            panic!("non-nil leaf fields");
        }
        self.pattern = Some(p.clone());
        self.handler = Some(h);
    }

    // go: sdk 1.25.5 net/http/routing_tree.go:88-101 routingNode.addChild
    /// Go: "addChild adds a child node with the given key to n if one
    /// does not exist, and returns the child."
    pub fn addChild(&mut self, key: string) -> &mut routingNode {
        if key.Len() == 0 {
            if self.emptyChild.is_none() {
                self.emptyChild = Some(Box::new(routingNode::default()));
            }
            return self.emptyChild.as_mut().unwrap();
        }
        // Go checks findChild first and returns the existing child;
        // Rust's borrow checker will not allow the probe and the insert
        // to overlap, so the probe answers a bool.
        let exists = self.children.find(&key).1;
        if !exists {
            self.children
                .add(key.clone(), Box::new(routingNode::default()));
        }
        return self.children.findMut(&key).unwrap();
    }

    // go: sdk 1.25.5 net/http/routing_tree.go:105-111 routingNode.findChild
    /// Go: "findChild returns the child of n with the given key, or nil
    /// if there is no child with that key."
    pub fn findChild(&self, key: &string) -> Option<&routingNode> {
        if key.Len() == 0 {
            return self.emptyChild.as_deref();
        }
        let (r, _) = self.children.find(key);
        return r.map(|b| &**b);
    }

    // go: sdk 1.25.5 net/http/routing_tree.go:117-127 routingNode.match
    // goishlint:ignore GOISH014 - `match` is a Rust keyword, so the only
    // spelling is the raw identifier `r#match`; the rule compares the
    // anchor's Go ident to the Rust name literally and does not strip
    // the `r#`. port_coverage had the same gap, fixed in 319dacb.
    /// Go: "match returns the leaf node under root that matches the
    /// arguments, and a list of values for pattern wildcards in the
    /// order that the wildcards appear. For example, if the request
    /// path is "/a/b/c" and the pattern is "/{x}/b/{y}", then the
    /// second return value will be []string{"a", "c"}."
    pub fn r#match(
        &self,
        host: &string,
        method: &string,
        path: &string,
    ) -> (Option<&routingNode>, slice<string>) {
        if host.Len() != 0 {
            // Go: "There is a host. If there is a pattern that
            // specifies that host and it matches, we are done. If the
            // pattern doesn't match, fall through to try patterns with
            // no host."
            let (l, m) = matchMethodAndPath(self.findChild(host), method, path);
            if l.is_some() {
                return (l, m);
            }
        }
        return matchMethodAndPath(self.emptyChild.as_deref(), method, path);
    }

    // go: sdk 1.25.5 net/http/routing_tree.go:219-227 routingNode.matchingMethods
    /// Go: "matchingMethods adds to methodSet all the methods that
    /// would result in a match if passed to routingNode.match with the
    /// given host and path."
    pub fn matchingMethods(
        &self,
        host: &string,
        path: &string,
        methodSet: &mut crate::gomap::map<string, bool>,
    ) {
        if host.Len() != 0 {
            matchingMethodsPath(self.findChild(host), path, methodSet);
        }
        matchingMethodsPath(self.emptyChild.as_deref(), path, methodSet);
        let (get, _) = methodSet.Get(string::from_static("GET"));
        if get {
            methodSet.Set(string::from_static("HEAD"), true);
        }
    }
}

// go: sdk 1.25.5 net/http/routing_tree.go:132-148 routingNode.matchMethodAndPath
/// Go: "matchMethodAndPath matches the method and path. The receiver
/// should be a child of the root."
///
/// A free function because Go calls it on a possibly-nil receiver.
pub fn matchMethodAndPath<'a>(
    n: Option<&'a routingNode>,
    method: &string,
    path: &string,
) -> (Option<&'a routingNode>, slice<string>) {
    let n = match n {
        Some(n) => n,
        None => return (None, slice::new()),
    };
    let (l, m) = matchPath(n.findChild(method), path, slice::new());
    if l.is_some() {
        // Go: "Exact match of method name."
        return (l, m);
    }
    if *method == "HEAD" {
        // Go: "GET matches HEAD too."
        let (l, m) = matchPath(n.findChild(&string::from_static("GET")), path, slice::new());
        if l.is_some() {
            return (l, m);
        }
    }
    // Go: "No exact match; try patterns with no method."
    return matchPath(n.emptyChild.as_deref(), path, slice::new());
}

// go: sdk 1.25.5 net/http/routing_tree.go:154-199 routingNode.matchPath
/// Go: "matchPath matches a path. matchPath calls itself recursively.
/// The matches argument holds the wildcard matches found so far."
pub fn matchPath<'a>(
    n: Option<&'a routingNode>,
    path: &string,
    matches: slice<string>,
) -> (Option<&'a routingNode>, slice<string>) {
    let n = match n {
        Some(n) => n,
        None => return (None, slice::new()),
    };
    // Go: "If path is empty, then we are done. If n is a leaf node, we
    // found a match; return it. If n is an interior node (which means
    // it has a nil pattern), then we failed to match."
    if path.Len() == 0 {
        if n.pattern.is_none() {
            return (None, slice::new());
        }
        return (Some(n), matches);
    }
    let (seg, rest) = firstSegment(path);
    // Go: "First try matching against patterns that have a literal for
    // this position. We know by construction that such patterns are
    // more specific than those with a wildcard at this position."
    {
        let (c, m) = matchPath(n.findChild(&seg), &rest, matches.clone());
        if c.is_some() {
            return (c, m);
        }
    }
    // Go: "If matching a literal fails, try again with patterns that
    // have a single wildcard... We skip this step if the segment is a
    // trailing slash, because single wildcards don't match trailing
    // slashes."
    if seg != "/" {
        let mut next = matches.clone();
        next = crate::append!(next, seg.clone());
        let (c, m) = matchPath(n.emptyChild.as_deref(), &rest, next);
        if c.is_some() {
            return (c, m);
        }
    }
    // Go: "Lastly, match the pattern (there can be at most one) that
    // has a multi wildcard in this position to the rest of the path."
    if let Some(c) = n.multiChild.as_deref() {
        let mut matches = matches;
        // Go: "Don't record a match for a nameless wildcard (which
        // arises from a trailing slash in the pattern)."
        let last = c.pattern.as_ref().map(|p| p.lastSegment().s.clone());
        if let Some(l) = last {
            if l.Len() != 0 {
                // Go: path[1:] — remove initial slash.
                let tail = string::from_bytes(&path.as_bytes()[1..]);
                matches = crate::append!(matches, pathUnescape(tail));
            }
        }
        return (Some(c), matches);
    }
    return (None, slice::new());
}

// go: sdk 1.25.5 net/http/routing_tree.go:205-215 firstSegment
/// Go: "firstSegment splits path into its first segment, and the rest.
/// The path must begin with "/". If path consists of only a slash,
/// firstSegment returns ("/", ""). The segment is returned unescaped,
/// if possible."
pub fn firstSegment(path: &string) -> (string, string) {
    if *path == "/" {
        return (string::from_static("/"), string::new());
    }
    // Go: path = path[1:] — drop initial slash.
    let path = string::from_bytes(&path.as_bytes()[1..]);
    let mut i = strings::IndexByte(path.clone(), b'/');
    if i < 0 {
        i = path.Len();
    }
    let iu = crate::builtin::__make_size(i);
    let b = path.as_bytes();
    return (
        pathUnescape(string::from_bytes(&b[..iu])),
        string::from_bytes(&b[iu..]),
    );
}

// go: sdk 1.25.5 net/http/routing_tree.go:229-242 routingNode.matchingMethodsPath
/// Go: "Don't look at the empty child. If there were an empty child, it
/// would match on any method, but we only call this when we fail to
/// match on a method."
pub fn matchingMethodsPath(
    n: Option<&routingNode>,
    path: &string,
    set: &mut crate::gomap::map<string, bool>,
) {
    let n = match n {
        Some(n) => n,
        None => return,
    };
    // Go passes a closure to eachPair; goish's borrow rules will not let
    // that closure also hold `set` mutably while `n.children` is
    // borrowed, so the methods are collected first and applied after.
    let mut hits: Vec<string> = Vec::new();
    n.children
        .eachPair(&mut |method: &string, c: &Box<routingNode>| {
            let (p, _) = matchPath(Some(&**c), path, slice::new());
            if p.is_some() {
                hits.push(method.clone());
            }
            return true;
        });
    for m in hits.into_iter() {
        set.Set(m, true);
    }
}
