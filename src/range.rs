// range — Go's `for ... range` loop, ported as the `range!` macro.
//
// Different Go types give different shapes:
//   - slices/arrays  → (int index, &value)
//   - strings        → (int byte-offset, rune)        ← UTF-8 decode
//   - maps           → (&key, &value)                 ← M5+
//   - chans          → value                          ← M16
//   - int (Go 1.22)  → int                            ← M5+
//
// The `range!` macro auto-borrows its argument and forwards to the
// `RangeIter` trait. Mirrors v0's design (see goish-v0/src/range.rs).
//
//   // Go:    for i, r := range s
//   // goish: for (i, r) in range!(s)

use crate::goslice::slice;
use crate::gostring::string;
use crate::types::{int, rune};
use crate::unicode::utf8;

pub trait RangeIter {
    type Item;
    type Iter: Iterator<Item = Self::Item>;
    fn range(self) -> Self::Iter;
}

#[macro_export]
macro_rules! range {
    ($iter:expr) => {
        $crate::range::RangeIter::range(&$iter)
    };
}

// ─── slices / arrays / slice → (int, &T) ─────────────────────────────

pub struct SliceRangeIter<'a, T> {
    slice: &'a [T],
    i: usize,
}

impl<'a, T> Iterator for SliceRangeIter<'a, T> {
    type Item = (int, &'a T);
    fn next(&mut self) -> Option<Self::Item> {
        if self.i >= self.slice.len() {
            return None;
        }
        let v = &self.slice[self.i];
        let idx = self.i as int;
        self.i += 1;
        Some((idx, v))
    }
}

impl<'a, T> RangeIter for &'a [T] {
    type Item = (int, &'a T);
    type Iter = SliceRangeIter<'a, T>;
    fn range(self) -> Self::Iter {
        SliceRangeIter { slice: self, i: 0 }
    }
}

impl<'a, T, const N: usize> RangeIter for &'a [T; N] {
    type Item = (int, &'a T);
    type Iter = SliceRangeIter<'a, T>;
    fn range(self) -> Self::Iter {
        SliceRangeIter { slice: self, i: 0 }
    }
}

impl<'a, T> RangeIter for &'a slice<T> {
    type Item = (int, &'a T);
    type Iter = SliceRangeIter<'a, T>;
    fn range(self) -> Self::Iter {
        SliceRangeIter {
            slice: &**self, // Deref<Target=[T]>
            i: 0,
        }
    }
}

// `range!(&x)` where `x: &slice<T>` → `&&slice<T>`.
// Needed when iterating over a borrowed slice handle inside a struct field.
impl<'a, T> RangeIter for &&'a slice<T> {
    type Item = (int, &'a T);
    type Iter = SliceRangeIter<'a, T>;
    fn range(self) -> Self::Iter {
        SliceRangeIter {
            slice: &***self,
            i: 0,
        }
    }
}

// ─── string → (int byte-offset, rune) — UTF-8 decode per step ───────

pub struct StringRangeIter<'a> {
    bytes: &'a [u8],
    i: usize,
}

impl<'a> Iterator for StringRangeIter<'a> {
    type Item = (int, rune);
    fn next(&mut self) -> Option<Self::Item> {
        if self.i >= self.bytes.len() {
            return None;
        }
        let off = self.i as int;
        let (r, sz) = utf8::DecodeRune(&self.bytes[self.i..]);
        // DecodeRune returns sz=1 even for invalid sequences, so we
        // always make progress.
        self.i += sz as usize;
        Some((off, r))
    }
}

impl<'a> RangeIter for &'a string {
    type Item = (int, rune);
    type Iter = StringRangeIter<'a>;
    fn range(self) -> Self::Iter {
        StringRangeIter {
            bytes: self.as_bytes(),
            i: 0,
        }
    }
}

// Bonus: byte-string literal `b"..."` is `&[u8; N]`, already covered
// by the &[T; N] impl above. Plain &'static str maps to a UTF-8 walk
// like string — reuse the StringRangeIter.

impl<'a> RangeIter for &'a &str {
    type Item = (int, rune);
    type Iter = StringRangeIter<'a>;
    fn range(self) -> Self::Iter {
        StringRangeIter {
            bytes: self.as_bytes(),
            i: 0,
        }
    }
}

// ─── map<K, V> → (&K, &V) — bucket-walk order (Go randomized) ──────

use crate::gomap::{map, MapRefIter};

impl<'a, K, V> RangeIter for &'a map<K, V>
where
    K: crate::gomap::GoHash + PartialEq,
    V: Default,
{
    type Item = (&'a K, &'a V);
    type Iter = MapRefIter<'a, K, V>;
    fn range(self) -> Self::Iter {
        self.__iter()
    }
}

// `range!(&m)` where `m: &map<K,V>` → `&&map<K,V>`.
// Needed when iterating over a borrowed map handle inside a struct field.
impl<'a, K, V> RangeIter for &&'a map<K, V>
where
    K: crate::gomap::GoHash + PartialEq,
    V: Default,
{
    type Item = (&'a K, &'a V);
    type Iter = MapRefIter<'a, K, V>;
    fn range(self) -> Self::Iter {
        (**self).__iter()
    }
}
