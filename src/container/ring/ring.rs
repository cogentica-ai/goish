// go: file container/ring/ring.go decls: Ring.init, Ring.Next, Ring.Prev, Ring.Move, New, Ring.Link, Ring.Unlink, Ring.Len, Ring.Do
//
// The `decls:` manifest above lists ring.go's funcs and methods only.
// GOISH017 matches a manifest entry against Rust `fn` items, so naming
// the `Ring` type there would report it as a dropped port. It is not
// dropped — it carries its own `// go: sdk` anchor below.
//
// container/ring/ring.go — operations on circular lists.
//
// A ring has no beginning or end: a handle on any element is a handle
// on the whole ring. `Link` is the only structural operation, and
// `Unlink` is defined in terms of it — `r.Link(r.Move(n+1))` — which
// is why splicing two rings together and cutting a subring out of one
// are the same four pointer writes. Go's comment about not using
// multiple assignment there (LHS evaluation order is unspecified) is
// reproduced with the writes in the same order.
//
// container/ring — circular doubly-linked list.
//
// Line-by-line port of:
//   go1.25.5/src/
//     container/ring/ring.go
//
// Slim deviations from Go:
//
//   * Go's `*Ring` (a nullable pointer) maps to goish `Ring<T>`, a
//     thin `Rc<RefCell<Inner<T>>>` wrapper. Cloning a `Ring<T>` aliases
//     the same node — exactly like assigning `*Ring` in Go.
//
//   * Operations that return `*Ring` map to `Ring<T>` returns; callers
//     that would test `r != nil` use `Option<Ring<T>>` instead. This
//     applies to `New(n)` (Go: returns nil if n<=0) and `Unlink(n)`
//     (Go: returns nil if n<=0).
//
//   * `Value` is exposed via `Value()` / `SetValue()` methods, mirroring
//     `container/list`'s pattern. The underlying value is `Option<T>`
//     so a freshly-allocated ring has a `nil` value (Go zero-value
//     equivalent).
//
//   * `Do(f)` takes `&T` (Go takes `any`); the closure runs once per
//     ring element in forward order. Nodes whose value is unset are
//     skipped (Go would pass a nil interface).
//
//   * Goish has no GC. The doubly-linked structure forms a strong-ref
//     cycle through `next` / `prev`, so when the last user-held `Ring<T>`
//     handle drops, the ring's nodes are NOT reclaimed (cycle keeps
//     them alive). This matches Go's deferred GC behavior in the sense
//     that a "lost" ring is harmless in practice — long-lived rings
//     are the typical use case. Memory cost is bounded by user usage.
//
// Reference: container/ring/ring.go

#![allow(non_snake_case)]

extern crate alloc;
use alloc::rc::Rc;
use core::cell::RefCell;

use crate::types::int;

// go: sdk 1.25.5 container/ring/ring.go:13-16 Ring
//
// Go: ring.go:13
//   type Ring struct {
//       next, prev *Ring
//       Value      any
//   }
struct Inner<T> {
    next: Option<Rc<RefCell<Inner<T>>>>,
    prev: Option<Rc<RefCell<Inner<T>>>>,
    value: Option<T>,
}

/// `Ring<T>` is a single element of a circular list. Cloning a handle
/// aliases the same node (Go: `var r2 *Ring = r1`).
pub struct Ring<T> {
    inner: Rc<RefCell<Inner<T>>>,
}

impl<T> Clone for Ring<T> {
    // go: none — goish idiom: `Ring<T>` is an `Rc` handle, so cloning
    //     one aliases the same node, as copying a Go `*Ring` does.
    fn clone(&self) -> Self {
        return Ring {
            inner: Rc::clone(&self.inner),
        };
    }
}

impl<T> Ring<T> {
    // go: none — goish idiom: Go writes `new(Ring)` inline in `New`;
    //     goish needs a constructor because `Inner`'s fields are private.
    /// Construct a single-element ring with no value (Go: `new(Ring)`).
    /// The node's `next` / `prev` are uninitialised until first
    /// observed — `init()` lazily makes the node a 1-element ring on
    /// the first `Next` / `Prev` / `Move` call.
    pub fn new() -> Ring<T> {
        return Ring {
            inner: Rc::new(RefCell::new(Inner {
                next: None,
                prev: None,
                value: None,
            })),
        };
    }

    // go: none — goish idiom: Go hands back a `*Ring` it already has;
    //     goish has to rewrap the `Rc` in a handle to return it.
    fn from_inner(inner: Rc<RefCell<Inner<T>>>) -> Ring<T> {
        return Ring { inner };
    }

    // go: sdk 1.25.5 container/ring/ring.go:18-22 Ring.init
    // Go: ring.go:18
    //   func (r *Ring) init() *Ring {
    //       r.next = r
    //       r.prev = r
    //       return r
    //   }
    fn init(&self) -> Ring<T> {
        let self_rc = Rc::clone(&self.inner);
        let mut inner = self.inner.borrow_mut();
        inner.next = Some(Rc::clone(&self_rc));
        inner.prev = Some(self_rc);
        return Ring {
            inner: Rc::clone(&self.inner),
        };
    }

    // go: sdk 1.25.5 container/ring/ring.go:25-30 Ring.Next
    // Go: ring.go:25
    //   func (r *Ring) Next() *Ring {
    //       if r.next == nil {
    //           return r.init()
    //       }
    //       return r.next
    //   }
    pub fn Next(&self) -> Ring<T> {
        let next = self.inner.borrow().next.clone();
        return match next {
            None => self.init(),
            Some(n) => Ring::from_inner(n),
        };
    }

    // go: sdk 1.25.5 container/ring/ring.go:33-38 Ring.Prev
    // Go: ring.go:33
    //   func (r *Ring) Prev() *Ring {
    //       if r.next == nil {
    //           return r.init()
    //       }
    //       return r.prev
    //   }
    pub fn Prev(&self) -> Ring<T> {
        let (next_unset, prev) = {
            let b = self.inner.borrow();
            (b.next.is_none(), b.prev.clone())
        };
        if next_unset {
            return self.init();
        }
        // After init(), prev is always Some.
        return Ring::from_inner(prev.expect("prev set after init"));
    }

    // go: sdk 1.25.5 container/ring/ring.go:42-57 Ring.Move
    // Go: ring.go:42
    //   func (r *Ring) Move(n int) *Ring {
    //       if r.next == nil {
    //           return r.init()
    //       }
    //       switch {
    //       case n < 0:
    //           for ; n < 0; n++ { r = r.prev }
    //       case n > 0:
    //           for ; n > 0; n-- { r = r.next }
    //       }
    //       return r
    //   }
    pub fn Move(&self, n: int) -> Ring<T> {
        if self.inner.borrow().next.is_none() {
            return self.init();
        }
        let mut cur = Rc::clone(&self.inner);
        let mut k = n;
        if k < 0 {
            while k < 0 {
                let p = cur.borrow().prev.clone().expect("prev set");
                cur = p;
                k += 1;
            }
        } else if k > 0 {
            while k > 0 {
                let nx = cur.borrow().next.clone().expect("next set");
                cur = nx;
                k -= 1;
            }
        }
        return Ring::from_inner(cur);
    }

    // go: none — goish idiom: Go exposes `Ring.Value` as a public
    //     field. goish keeps it behind a `RefCell`, so reading it is a
    //     method; a public field would have to hand out a borrow guard.
    /// Read access for `Value` — clones out the stored value (or `None`
    /// if unset). Go users write `r.Value`; goish users write `r.Value()`.
    pub fn Value(&self) -> Option<T>
    where
        T: Clone,
    {
        return self.inner.borrow().value.clone();
    }

    // go: none — goish idiom: the write half of `Value`; see there.
    /// Write access for `Value`. Go users write `r.Value = v`; goish
    /// users write `r.SetValue(v)`.
    pub fn SetValue(&self, v: T) {
        self.inner.borrow_mut().value = Some(v);
    }

    // go: sdk 1.25.5 container/ring/ring.go:90-102 Ring.Link
    // Go: ring.go:90
    //   func (r *Ring) Link(s *Ring) *Ring {
    //       n := r.Next()
    //       if s != nil {
    //           p := s.Prev()
    //           // Note: Cannot use multiple assignment because
    //           // evaluation order of LHS is not specified.
    //           r.next = s
    //           s.prev = r
    //           n.prev = p
    //           p.next = n
    //       }
    //       return n
    //   }
    pub fn Link(&self, s: &Ring<T>) -> Ring<T> {
        let n = self.Next();
        // Go's `if s != nil` — in goish, `s` is always present (we have
        // a reference). Callers wrap in `Option<&Ring<T>>` if they need
        // the nil-check. Mirror Go's body unconditionally.
        let p = s.Prev();
        // r.next = s
        self.inner.borrow_mut().next = Some(Rc::clone(&s.inner));
        // s.prev = r
        s.inner.borrow_mut().prev = Some(Rc::clone(&self.inner));
        // n.prev = p
        n.inner.borrow_mut().prev = Some(Rc::clone(&p.inner));
        // p.next = n
        p.inner.borrow_mut().next = Some(Rc::clone(&n.inner));
        return n;
    }

    // go: sdk 1.25.5 container/ring/ring.go:107-112 Ring.Unlink
    // Go: ring.go:107
    //   func (r *Ring) Unlink(n int) *Ring {
    //       if n <= 0 {
    //           return nil
    //       }
    //       return r.Link(r.Move(n + 1))
    //   }
    pub fn Unlink(&self, n: int) -> Option<Ring<T>> {
        if n <= 0 {
            return None;
        }
        return Some(self.Link(&self.Move(n + 1)));
    }

    // go: sdk 1.25.5 container/ring/ring.go:116-125 Ring.Len
    // Go: ring.go:116
    //   func (r *Ring) Len() int {
    //       n := 0
    //       if r != nil {
    //           n = 1
    //           for p := r.Next(); p != r; p = p.next {
    //               n++
    //           }
    //       }
    //       return n
    //   }
    pub fn Len(&self) -> int {
        // `r` is never nil in goish (we have a value); start at 1.
        let mut n: int = 1;
        let r_ptr = Rc::as_ptr(&self.inner);
        let mut cur = self.Next().inner;
        while !Rc::ptr_eq(&cur, &self.inner) && Rc::as_ptr(&cur) != r_ptr {
            // ptr_eq alone is enough; the second comparison is redundant
            // but matches a safety belt against stale stored pointers.
            n += 1;
            let nx = cur.borrow().next.clone();
            match nx {
                Some(node) => cur = node,
                None => break, // Should not happen on a valid ring.
            }
        }
        return n;
    }

    // go: sdk 1.25.5 container/ring/ring.go:129-136 Ring.Do
    // Go: ring.go:129
    //   func (r *Ring) Do(f func(any)) {
    //       if r != nil {
    //           f(r.Value)
    //           for p := r.Next(); p != r; p = p.next {
    //               f(p.Value)
    //           }
    //       }
    //   }
    pub fn Do<F>(&self, mut f: F)
    where
        F: FnMut(&T),
    {
        // Apply f to self.Value (skip if unset).
        if let Some(v) = self.inner.borrow().value.as_ref() {
            f(v);
        }
        let mut cur = self.Next().inner;
        while !Rc::ptr_eq(&cur, &self.inner) {
            // Snapshot the next pointer first to avoid holding the
            // borrow across f's invocation.
            let nx = cur.borrow().next.clone();
            if let Some(v) = cur.borrow().value.as_ref() {
                f(v);
            }
            match nx {
                Some(node) => cur = node,
                None => break,
            }
        }
    }
}

// go: sdk 1.25.5 container/ring/ring.go:60-73 New
// Go: ring.go:60
//   func New(n int) *Ring {
//       if n <= 0 {
//           return nil
//       }
//       r := new(Ring)
//       p := r
//       for i := 1; i < n; i++ {
//           p.next = &Ring{prev: p}
//           p = p.next
//       }
//       p.next = r
//       r.prev = p
//       return r
//   }
pub fn New<T>(n: int) -> Option<Ring<T>> {
    if n <= 0 {
        return None;
    }
    let r = Ring::<T>::new();
    let mut p_rc = Rc::clone(&r.inner);
    let mut i: int = 1;
    while i < n {
        // p.next = &Ring{prev: p}
        let next_inner = Rc::new(RefCell::new(Inner::<T> {
            next: None,
            prev: Some(Rc::clone(&p_rc)),
            value: None,
        }));
        p_rc.borrow_mut().next = Some(Rc::clone(&next_inner));
        // p = p.next
        p_rc = next_inner;
        i += 1;
    }
    // p.next = r
    p_rc.borrow_mut().next = Some(Rc::clone(&r.inner));
    // r.prev = p
    r.inner.borrow_mut().prev = Some(p_rc);
    return Some(r);
}
