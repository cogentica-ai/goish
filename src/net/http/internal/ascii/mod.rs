// net/http/internal/ascii — ASCII-only fast paths used by net/http.
//
//   Go                                       goish
//   ──────────────────────────────────────   ─────────────────────────────────
//   ascii.EqualFold(s, t)                    ascii::EqualFold(s, t)  — bool
//   ascii.IsPrint(s)                         ascii::IsPrint(s)       — bool
//   ascii.Is(s)                              ascii::Is(s)            — bool
//   ascii.ToLower(s)                         ascii::ToLower(s)       — (string, bool)
//
// The code lives in print.rs, mirroring Go's single print.go, because
// anchored code may not sit in a module root (GOISH015).

#![allow(non_snake_case)]

mod print;

pub use print::{EqualFold, Is, IsPrint, ToLower};
