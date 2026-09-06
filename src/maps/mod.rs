// maps — module root for Go's `maps` package (Go 1.21+).
//
// Companion to `gomap::map<K, V>`: the functional API that complements
// method-style access. The port is split one `.rs` per `.go` —
// `maps.rs` for maps.go, `iter.rs` for maps/iter.go — and this file
// only re-exports, which is what a module root may hold (GOISH015).
//
//   Go                                   goish
//   ──────────────────────────────────   ──────────────────────────────────
//   ks := maps.Keys(m)                   let ks = maps::Keys(&m);
//   ok := maps.Equal(m1, m2)             let ok = maps::Equal(&m1, &m2);
//   c := maps.Clone(m)                   let c = maps::Clone(&m);
//
// `Keys` and `Values` return Go's `iter.Seq[K]` / `iter.Seq[V]`. A note
// here used to say they returned `slice<K>` "since we don't yet ship an
// iter package", two paragraphs below the sentence recording that the
// iter package had arrived and all three functions were ported.

mod iter;
mod maps;

pub use iter::{All, Collect, Insert, Keys, Values};
pub use maps::{Clone, Copy, DeleteFunc, Equal, EqualFunc};
