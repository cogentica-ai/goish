// sync/atomic — Go's atomic primitives.
//
// One `.rs` per `.go` (§33): the declarations live in type.rs,
// value.rs, doc.rs and doc_64.rs, matching Go's own file layout.
// The FILE is type.rs so the Go origin is traceable; the MODULE is
// `type_` because `type` is a Rust keyword, which is what the
// `#[path]` below reconciles.

mod doc;
mod doc_64;
#[path = "type.rs"]
mod type_;
mod value;

pub use doc::*;
pub use doc_64::*;
pub use type_::*;
pub use value::*;
