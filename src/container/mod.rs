// container — Go's `container` family.
//
// Goish v1 ports `container/heap` and `container/list`.
// `container/ring` remains unported — its API is a free-floating
// circular ring with no owning container, which means cycle-breaking
// would have to live inside Element drop with extra machinery.
//
// Reference: /share/go/src/container/

#![allow(non_snake_case)]

pub mod heap;
pub mod list;
