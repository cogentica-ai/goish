// go: namespace compress
//
// compress — Go's `compress` parent package.
//
// Submodules:
//   * `bzip2` — bzip2 decompression.
//   * `flate` — DEFLATE compressed data format (RFC 1951).
//   * `gzip`  — gzip file format (RFC 1952).
//   * `lzw`   — Lempel-Ziv-Welch (GIF/PDF flavor).
//   * `zlib`  — zlib compressed data format (RFC 1950).

pub mod bzip2;
pub mod flate;
pub mod gzip;
pub mod lzw;
pub mod zlib;
