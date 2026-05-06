// container — Go's `container` family.
//
// Goish v1 ports `container/heap`, `container/list`, and
// `container/ring`. `ring` accepts a slim deviation: nodes form a
// strong-ref cycle through next/prev, so dropping the last user handle
// does not reclaim the ring's memory (matches Go's deferred GC of
// unreachable cyclic data; bounded by user usage).
//
// Reference: /share/go/src/container/

#![allow(non_snake_case)]

pub mod heap;
pub mod list;
pub mod ring;
