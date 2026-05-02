// container — Go's `container` family.
//
// Goish v1 ports `container/heap`. `container/list` and
// `container/ring` are pointer-soup designs that don't map cleanly
// to Rust ownership without `Rc<RefCell<_>>` everywhere; they land
// in a later milestone if a caller actually needs them.
//
// Reference: /share/go/src/container/

#![allow(non_snake_case)]

pub mod heap;
