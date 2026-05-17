// compress — Go's `compress` parent package.
//
// Submodules:
//   * `flate` — DEFLATE compressed data format (RFC 1951).
//   * `lzw`   — Lempel-Ziv-Welch (GIF/PDF flavor).
//   * `zlib`  — zlib compressed data format (RFC 1950).

pub mod flate;
pub mod lzw;
pub mod zlib;
