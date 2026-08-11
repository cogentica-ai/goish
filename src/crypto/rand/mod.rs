// go: package crypto/rand

mod rand;
mod text;
mod util;

pub use rand::{reader, register_rand_impls, Read, Reader};
pub use text::Text;
pub use util::{Int, Prime};

/// Compatibility alias for the pre-port spelling of Go's unexported
/// `reader` type. Consumers across `crypto/` and `examples/` name it in
/// type and value position (`let mut rng = RandReader;`); the alias
/// keeps them compiling while the canonical name matches Go.
pub use rand::reader as RandReader;
