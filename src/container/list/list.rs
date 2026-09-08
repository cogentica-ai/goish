// go: file container/list/list.go decls: Element.Next, Element.Prev, List.Init, New, List.Len, List.Front, List.Back, List.lazyInit, List.insert, List.insertValue, List.remove, List.move, List.Remove, List.PushFront, List.PushBack, List.InsertBefore, List.InsertAfter, List.MoveToFront, List.MoveToBack, List.MoveBefore, List.MoveAfter, List.PushBackList, List.PushFrontList
//
// goishlint:ignore GOISH019 Element, List — goish models Go's ring of
//     `*Element` pointers as a slab: `ListInner` holds a `BTreeMap` of
//     nodes keyed by id (`nodes`, `next_id`) instead of an inline
//     `root` Element, and a node carries no `list` back-pointer because
//     the owning list is reached through the handle's `Weak`. Rust has
//     no GC, so a literal pointer ring would be a reference cycle.
//
// The `decls:` manifest above lists list.go's funcs and methods only.
// GOISH017 matches a manifest entry against Rust `fn` items, so naming
// the `Element` and `List` types there would report both as dropped
// ports. They are not dropped — each carries its own `// go: sdk`
// anchor below.
//
// container/list — doubly linked list.
//
// Line-by-line port of:
//   go1.25.5/src/
//     container/list/list.go
//
// Slim deviations:
//
//   * Go's `*Element` pointers map to goish `Element<T>` handles.
//     Each handle carries a `Weak<RefCell<ListInner<T>>>` and an
//     opaque node id. This avoids ownership cycles in Rust without
//     a GC: the chain is held together by `u64` ids in a slab map,
//     not by `Rc` pointers between nodes.
//
//   * Element values live in a shared `Rc<RefCell<T>>`. Both the
//     slab and any outstanding `Element<T>` handle share the same
//     cell, so `Remove` can still return the element's value after
//     unlinking — matching Go's `return e.Value` semantics where
//     the *Element struct keeps its Value field intact post-remove.
//
//   * `Element<T>.Value` is exposed as `Value()` / `SetValue()`
//     methods rather than a public field — direct field access
//     would require leaking a `Ref<T>` borrow guard, which is not
//     a goish-shaped surface. Go users write `e.Value`; goish
//     users write `e.Value()`.
//
//   * `Init()` does not return `*List` (no method chaining via
//     pointers in goish). Callers can still use it to clear a
//     list in-place.
//
//   * `List<T>` is a thin `Rc<...>` wrapper, so `let l2 = l.clone()`
//     produces an aliased handle to the same underlying list (same
//     as Go's `var l2 *List = l`).

#![allow(non_snake_case)]

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::rc::{Rc, Weak};
use core::cell::RefCell;

use crate::types::int;

// Sentinel id used for the implicit `&l.root` element.
const ROOT_ID: u64 = 0;
const FIRST_REAL_ID: u64 = 1;

// go: sdk 1.25.5 container/list/list.go:15-28 Element
//
// Go: list.go:14
//   type Element struct {
//       next, prev *Element
//       list *List
//       Value any
//   }
//
// Slab-side representation (stored in `ListInner.nodes`).
struct Node<T> {
    next: u64,
    prev: u64,
    // None only for the sentinel root; non-root nodes always carry a value.
    value: Option<Rc<RefCell<T>>>,
}

// go: sdk 1.25.5 container/list/list.go:48-51 List
//
// Go: list.go:46
//   type List struct {
//       root Element
//       len  int
//   }
struct ListInner<T> {
    nodes: BTreeMap<u64, Node<T>>,
    next_id: u64,
    len: int,
}

impl<T> ListInner<T> {
    // go: none — goish idiom: the seeded zero value. Go's zero `List` is
    //     usable as-is and `lazyInit` repairs it on first use; goish's
    //     slab needs its root row inserted, which is what this does.
    fn new() -> Self {
        let mut nodes = BTreeMap::new();
        // Go: l.root.next = &l.root; l.root.prev = &l.root
        nodes.insert(
            ROOT_ID,
            Node {
                next: ROOT_ID,
                prev: ROOT_ID,
                value: None,
            },
        );
        return ListInner {
            nodes,
            next_id: FIRST_REAL_ID,
            len: 0,
        };
    }

    // go: sdk 1.25.5 container/list/list.go:92-100 insert
    // Go: list.go:92
    //   func (l *List) insert(e, at *Element) *Element {
    //       e.prev = at
    //       e.next = at.next
    //       e.prev.next = e
    //       e.next.prev = e
    //       e.list = l
    //       l.len++
    //       return e
    //   }
    fn insert(&mut self, value: Rc<RefCell<T>>, at: u64) -> u64 {
        let new_id = self.next_id;
        self.next_id += 1;
        let at_next = self.nodes.get(&at).expect("at must exist").next;
        self.nodes.insert(
            new_id,
            Node {
                next: at_next,
                prev: at,
                value: Some(value),
            },
        );
        // e.prev.next = e
        self.nodes.get_mut(&at).expect("at exists").next = new_id;
        // e.next.prev = e
        self.nodes.get_mut(&at_next).expect("at_next exists").prev = new_id;
        self.len += 1;
        return new_id;
    }

    // go: sdk 1.25.5 container/list/list.go:103-105 insertValue
    // Go: list.go:103
    //   func (l *List) insertValue(v any, at *Element) *Element {
    //       return l.insert(&Element{Value: v}, at)
    //   }
    //
    // Go allocates the Element here and hands it to `insert`; goish's
    // slab allocates the node id inside `insert`, so what crosses this
    // boundary is the value cell rather than a built Element.
    fn insertValue(&mut self, v: Rc<RefCell<T>>, at: u64) -> u64 {
        return self.insert(v, at);
    }

    // go: sdk 1.25.5 container/list/list.go:85-89 lazyInit
    // Go: list.go:85
    //   func (l *List) lazyInit() {
    //       if l.root.next == nil { l.Init() }
    //   }
    //
    // Go's zero List has a root whose links are nil; goish's slab has
    // no root entry at all until it is seeded, so "the root is missing"
    // is the same condition and re-seeding it is the same repair.
    fn lazyInit(&mut self) {
        if self.nodes.contains_key(&ROOT_ID) {
            return;
        }
        self.nodes.insert(
            ROOT_ID,
            Node {
                next: ROOT_ID,
                prev: ROOT_ID,
                value: None,
            },
        );
        self.next_id = FIRST_REAL_ID;
        self.len = 0;
    }

    // go: sdk 1.25.5 container/list/list.go:108-115 remove
    // Go: list.go:107
    //   func (l *List) remove(e *Element) {
    //       e.prev.next = e.next
    //       e.next.prev = e.prev
    //       e.next = nil
    //       e.prev = nil
    //       e.list = nil
    //       l.len--
    //   }
    fn remove(&mut self, e: u64) {
        let (prev, next) = match self.nodes.get(&e) {
            Some(n) => (n.prev, n.next),
            None => return,
        };
        if let Some(p) = self.nodes.get_mut(&prev) {
            p.next = next;
        }
        if let Some(n) = self.nodes.get_mut(&next) {
            n.prev = prev;
        }
        self.nodes.remove(&e);
        self.len -= 1;
    }

    // go: sdk 1.25.5 container/list/list.go:118-129 move
    // goishlint:ignore GOISH014 — Go's name is `move`, a Rust keyword, so
    //     the fn below is the raw identifier `r#move`. GOISH014 compares
    //     the anchor's symbol against the Rust spelling and sees a
    //     mismatch; GOISH017/018 strip the escape and need the symbol to
    //     be there. This suppression is per-function, not file-wide, so
    //     every other fn here is still required to carry an anchor.
    //
    // Go: list.go:117
    //   func (l *List) move(e, at *Element) {
    //       if e == at { return }
    //       e.prev.next = e.next
    //       e.next.prev = e.prev
    //
    //       e.prev = at
    //       e.next = at.next
    //       e.prev.next = e
    //       e.next.prev = e
    //   }
    fn r#move(&mut self, e: u64, at: u64) {
        if e == at {
            return;
        }
        // Detach e from its current spot.
        let (e_prev, e_next) = {
            let n = self.nodes.get(&e).expect("e exists");
            (n.prev, n.next)
        };
        self.nodes.get_mut(&e_prev).expect("ep").next = e_next;
        self.nodes.get_mut(&e_next).expect("en").prev = e_prev;
        // Splice in after at.
        let at_next = self.nodes.get(&at).expect("at exists").next;
        {
            let en = self.nodes.get_mut(&e).expect("e2");
            en.prev = at;
            en.next = at_next;
        }
        self.nodes.get_mut(&at).expect("at2").next = e;
        self.nodes.get_mut(&at_next).expect("an2").prev = e;
    }
}

// ─── Public List<T> ─────────────────────────────────────────────────

/// Go: list.go:46
///   type List struct { ... }
///
/// `List<T>` is the goish handle. The underlying state lives in
/// `Rc<RefCell<ListInner<T>>>` so multiple handles can alias the
/// same list (same as Go aliasing `*List` pointers).
pub struct List<T> {
    inner: Rc<RefCell<ListInner<T>>>,
}

impl<T> Clone for List<T> {
    // go: none — goish idiom: `List<T>` is an `Rc` handle, so cloning one
    //     aliases the same list, as copying a Go `*List` does.
    fn clone(&self) -> List<T> {
        return List {
            inner: Rc::clone(&self.inner),
        };
    }
}

impl<T: Clone> List<T> {
    // go: none — goish idiom: Go's `New` is a package function, and the
    //     free `New` below is its counterpart. This inherent form is the
    //     spelling goish callers reach for on a generic type.
    /// Go: list.go:62  — `func New() *List { return new(List).Init() }`
    pub fn New() -> List<T> {
        return List {
            inner: Rc::new(RefCell::new(ListInner::new())),
        };
    }

    // go: sdk 1.25.5 container/list/list.go:54-59 List.Init
    /// Go: list.go:54
    ///   func (l *List) Init() *List {
    ///       l.root.next = &l.root
    ///       l.root.prev = &l.root
    ///       l.len = 0
    ///       return l
    ///   }
    pub fn Init(&self) {
        let mut inner = self.inner.borrow_mut();
        inner.nodes.clear();
        inner.nodes.insert(
            ROOT_ID,
            Node {
                next: ROOT_ID,
                prev: ROOT_ID,
                value: None,
            },
        );
        inner.next_id = FIRST_REAL_ID;
        inner.len = 0;
    }

    // go: sdk 1.25.5 container/list/list.go:66-66 List.Len
    /// Go: list.go:66  — `func (l *List) Len() int { return l.len }`
    pub fn Len(&self) -> int {
        return self.inner.borrow().len;
    }

    // go: sdk 1.25.5 container/list/list.go:69-74 List.Front
    /// Go: list.go:69
    ///   func (l *List) Front() *Element {
    ///       if l.len == 0 { return nil }
    ///       return l.root.next
    ///   }
    pub fn Front(&self) -> Option<Element<T>> {
        let inner = self.inner.borrow();
        if inner.len == 0 {
            return None;
        }
        let head_id = inner.nodes.get(&ROOT_ID)?.next;
        let value = inner.nodes.get(&head_id)?.value.clone()?;
        return Some(Element {
            list: Rc::downgrade(&self.inner),
            id: head_id,
            value,
        });
    }

    // go: sdk 1.25.5 container/list/list.go:77-82 List.Back
    /// Go: list.go:77
    ///   func (l *List) Back() *Element { ... }
    pub fn Back(&self) -> Option<Element<T>> {
        let inner = self.inner.borrow();
        if inner.len == 0 {
            return None;
        }
        let tail_id = inner.nodes.get(&ROOT_ID)?.prev;
        let value = inner.nodes.get(&tail_id)?.value.clone()?;
        return Some(Element {
            list: Rc::downgrade(&self.inner),
            id: tail_id,
            value,
        });
    }

    // go: sdk 1.25.5 container/list/list.go:134-141 List.Remove
    /// Go: list.go:134
    ///   func (l *List) Remove(e *Element) any {
    ///       if e.list == l { l.remove(e) }
    ///       return e.Value
    ///   }
    pub fn Remove(&self, e: &Element<T>) -> T {
        let same = e
            .list
            .upgrade()
            .map(|rc| Rc::ptr_eq(&rc, &self.inner))
            .unwrap_or(false);
        if same {
            let mut inner = self.inner.borrow_mut();
            if inner.nodes.contains_key(&e.id) && e.id != ROOT_ID {
                inner.remove(e.id);
            }
        }
        // The element handle keeps the value cell alive, so this
        // succeeds even after the slab entry is gone — matches Go's
        // `return e.Value`.
        return e.value.borrow().clone();
    }

    // go: sdk 1.25.5 container/list/list.go:144-147 List.PushFront
    /// Go: list.go:144
    ///   func (l *List) PushFront(v any) *Element {
    ///       l.lazyInit()
    ///       return l.insertValue(v, &l.root)
    ///   }
    pub fn PushFront(&self, v: T) -> Element<T> {
        let value = Rc::new(RefCell::new(v));
        let id = {
            let mut inner = self.inner.borrow_mut();
            // Go: l.lazyInit(); return l.insertValue(v, &l.root)
            inner.lazyInit();
            inner.insertValue(value.clone(), ROOT_ID)
        };
        return Element {
            list: Rc::downgrade(&self.inner),
            id,
            value,
        };
    }

    // go: sdk 1.25.5 container/list/list.go:150-153 List.PushBack
    /// Go: list.go:150
    ///   func (l *List) PushBack(v any) *Element {
    ///       l.lazyInit()
    ///       return l.insertValue(v, l.root.prev)
    ///   }
    pub fn PushBack(&self, v: T) -> Element<T> {
        let value = Rc::new(RefCell::new(v));
        let id = {
            let mut inner = self.inner.borrow_mut();
            // Go: l.lazyInit(); return l.insertValue(v, l.root.prev)
            inner.lazyInit();
            let tail = inner.nodes.get(&ROOT_ID).expect("root").prev;
            inner.insertValue(value.clone(), tail)
        };
        return Element {
            list: Rc::downgrade(&self.inner),
            id,
            value,
        };
    }

    // go: sdk 1.25.5 container/list/list.go:158-164 List.InsertBefore
    /// Go: list.go:158
    ///   func (l *List) InsertBefore(v any, mark *Element) *Element {
    ///       if mark.list != l { return nil }
    ///       return l.insertValue(v, mark.prev)
    ///   }
    pub fn InsertBefore(&self, v: T, mark: &Element<T>) -> Option<Element<T>> {
        let same = mark
            .list
            .upgrade()
            .map(|rc| Rc::ptr_eq(&rc, &self.inner))
            .unwrap_or(false);
        if !same {
            return None;
        }
        let value = Rc::new(RefCell::new(v));
        let id = {
            let mut inner = self.inner.borrow_mut();
            let mark_prev = inner.nodes.get(&mark.id)?.prev;
            inner.insertValue(value.clone(), mark_prev)
        };
        return Some(Element {
            list: Rc::downgrade(&self.inner),
            id,
            value,
        });
    }

    // go: sdk 1.25.5 container/list/list.go:169-175 List.InsertAfter
    /// Go: list.go:169
    ///   func (l *List) InsertAfter(v any, mark *Element) *Element {
    ///       if mark.list != l { return nil }
    ///       return l.insertValue(v, mark)
    ///   }
    pub fn InsertAfter(&self, v: T, mark: &Element<T>) -> Option<Element<T>> {
        let same = mark
            .list
            .upgrade()
            .map(|rc| Rc::ptr_eq(&rc, &self.inner))
            .unwrap_or(false);
        if !same {
            return None;
        }
        if !self.inner.borrow().nodes.contains_key(&mark.id) {
            return None;
        }
        let value = Rc::new(RefCell::new(v));
        let id = {
            let mut inner = self.inner.borrow_mut();
            inner.insertValue(value.clone(), mark.id)
        };
        return Some(Element {
            list: Rc::downgrade(&self.inner),
            id,
            value,
        });
    }

    // go: sdk 1.25.5 container/list/list.go:180-186 List.MoveToFront
    /// Go: list.go:180
    ///   func (l *List) MoveToFront(e *Element) {
    ///       if e.list != l || l.root.next == e { return }
    ///       l.move(e, &l.root)
    ///   }
    pub fn MoveToFront(&self, e: &Element<T>) {
        let same = e
            .list
            .upgrade()
            .map(|rc| Rc::ptr_eq(&rc, &self.inner))
            .unwrap_or(false);
        if !same {
            return;
        }
        let mut inner = self.inner.borrow_mut();
        let head = match inner.nodes.get(&ROOT_ID) {
            Some(r) => r.next,
            None => return,
        };
        if head == e.id {
            return;
        }
        if !inner.nodes.contains_key(&e.id) || e.id == ROOT_ID {
            return;
        }
        inner.r#move(e.id, ROOT_ID);
    }

    // go: sdk 1.25.5 container/list/list.go:191-197 List.MoveToBack
    /// Go: list.go:191
    ///   func (l *List) MoveToBack(e *Element) {
    ///       if e.list != l || l.root.prev == e { return }
    ///       l.move(e, l.root.prev)
    ///   }
    pub fn MoveToBack(&self, e: &Element<T>) {
        let same = e
            .list
            .upgrade()
            .map(|rc| Rc::ptr_eq(&rc, &self.inner))
            .unwrap_or(false);
        if !same {
            return;
        }
        let mut inner = self.inner.borrow_mut();
        let tail = match inner.nodes.get(&ROOT_ID) {
            Some(r) => r.prev,
            None => return,
        };
        if tail == e.id {
            return;
        }
        if !inner.nodes.contains_key(&e.id) || e.id == ROOT_ID {
            return;
        }
        inner.r#move(e.id, tail);
    }

    // go: sdk 1.25.5 container/list/list.go:202-207 List.MoveBefore
    /// Go: list.go:202
    ///   func (l *List) MoveBefore(e, mark *Element) {
    ///       if e.list != l || e == mark || mark.list != l { return }
    ///       l.move(e, mark.prev)
    ///   }
    pub fn MoveBefore(&self, e: &Element<T>, mark: &Element<T>) {
        let same_e = e
            .list
            .upgrade()
            .map(|rc| Rc::ptr_eq(&rc, &self.inner))
            .unwrap_or(false);
        let same_m = mark
            .list
            .upgrade()
            .map(|rc| Rc::ptr_eq(&rc, &self.inner))
            .unwrap_or(false);
        if !same_e || e.id == mark.id || !same_m {
            return;
        }
        let mut inner = self.inner.borrow_mut();
        if !inner.nodes.contains_key(&e.id) || !inner.nodes.contains_key(&mark.id) {
            return;
        }
        let mark_prev = inner.nodes.get(&mark.id).expect("mark").prev;
        inner.r#move(e.id, mark_prev);
    }

    // go: sdk 1.25.5 container/list/list.go:212-217 List.MoveAfter
    /// Go: list.go:212
    ///   func (l *List) MoveAfter(e, mark *Element) {
    ///       if e.list != l || e == mark || mark.list != l { return }
    ///       l.move(e, mark)
    ///   }
    pub fn MoveAfter(&self, e: &Element<T>, mark: &Element<T>) {
        let same_e = e
            .list
            .upgrade()
            .map(|rc| Rc::ptr_eq(&rc, &self.inner))
            .unwrap_or(false);
        let same_m = mark
            .list
            .upgrade()
            .map(|rc| Rc::ptr_eq(&rc, &self.inner))
            .unwrap_or(false);
        if !same_e || e.id == mark.id || !same_m {
            return;
        }
        let mut inner = self.inner.borrow_mut();
        if !inner.nodes.contains_key(&e.id) || !inner.nodes.contains_key(&mark.id) {
            return;
        }
        inner.r#move(e.id, mark.id);
    }

    // go: sdk 1.25.5 container/list/list.go:221-226 List.PushBackList
    /// Go: list.go:221
    ///   func (l *List) PushBackList(other *List) {
    ///       l.lazyInit()
    ///       for i, e := other.Len(), other.Front(); i > 0; i, e = i-1, e.Next() {
    ///           l.insertValue(e.Value, l.root.prev)
    ///       }
    ///   }
    ///
    /// Snapshots `other`'s values up-front so the same-list case
    /// (`l.PushBackList(l)`) terminates cleanly — matches Go's
    /// loop-bounded behavior (`i = other.Len()` is captured once).
    pub fn PushBackList(&self, other: &List<T>) {
        let snap = snapshot_forward(other);
        let mut inner = self.inner.borrow_mut();
        // Go: l.lazyInit()
        inner.lazyInit();
        for v in snap {
            // Go: l.insertValue(e.Value, l.root.prev)
            let tail = inner.nodes.get(&ROOT_ID).expect("root").prev;
            inner.insertValue(Rc::new(RefCell::new(v)), tail);
        }
    }

    // go: sdk 1.25.5 container/list/list.go:230-235 List.PushFrontList
    /// Go: list.go:230
    ///   func (l *List) PushFrontList(other *List) {
    ///       l.lazyInit()
    ///       for i, e := other.Len(), other.Back(); i > 0; i, e = i-1, e.Prev() {
    ///           l.insertValue(e.Value, &l.root)
    ///       }
    ///   }
    pub fn PushFrontList(&self, other: &List<T>) {
        let snap = snapshot_backward(other);
        let mut inner = self.inner.borrow_mut();
        // Go: l.lazyInit()
        inner.lazyInit();
        for v in snap {
            // Go: l.insertValue(e.Value, &l.root)
            inner.insertValue(Rc::new(RefCell::new(v)), ROOT_ID);
        }
    }
}

// go: none — goish idiom: see `snapshot_backward`.
fn snapshot_forward<T: Clone>(l: &List<T>) -> alloc::vec::Vec<T> {
    let oi = l.inner.borrow();
    let mut out = alloc::vec::Vec::with_capacity(oi.len as usize);
    let mut cur = oi.nodes.get(&ROOT_ID).expect("root").next;
    while cur != ROOT_ID {
        let n = oi.nodes.get(&cur).expect("node");
        if let Some(v) = &n.value {
            out.push(v.borrow().clone());
        }
        cur = n.next;
    }
    return out;
}

// go: none — goish idiom: `PushFrontList` walks `other` backwards while
//     holding `self`'s borrow, so the values are snapshotted first. Go
//     needs no snapshot: it captures `other.Len()` once and its loop is
//     bounded by that count even when `other == l`.
fn snapshot_backward<T: Clone>(l: &List<T>) -> alloc::vec::Vec<T> {
    let oi = l.inner.borrow();
    let mut out = alloc::vec::Vec::with_capacity(oi.len as usize);
    let mut cur = oi.nodes.get(&ROOT_ID).expect("root").prev;
    while cur != ROOT_ID {
        let n = oi.nodes.get(&cur).expect("node");
        if let Some(v) = &n.value {
            out.push(v.borrow().clone());
        }
        cur = n.prev;
    }
    return out;
}

// go: sdk 1.25.5 container/list/list.go:62-62 New
// Go: list.go:62  — `func New() *List`
//
// Free-fn convenience matching `list.New()`.
pub fn New<T: Clone>() -> List<T> {
    return List::New();
}

// ─── Element<T> ─────────────────────────────────────────────────────

/// Go: list.go:14
///   type Element struct { next, prev *Element; list *List; Value any }
///
/// `Element<T>` is a handle. The handle holds a `Weak` reference to
/// the owning list plus the node id, so the handle outliving the
/// list is safe (post-drop methods become no-ops or return None).
pub struct Element<T> {
    list: Weak<RefCell<ListInner<T>>>,
    id: u64,
    value: Rc<RefCell<T>>,
}

impl<T> Clone for Element<T> {
    // go: none — goish idiom: `Element<T>` is a handle, so cloning one
    //     aliases the same node, as copying a Go `*Element` does.
    fn clone(&self) -> Element<T> {
        return Element {
            list: self.list.clone(),
            id: self.id,
            value: Rc::clone(&self.value),
        };
    }
}

impl<T: Clone> Element<T> {
    // go: none — goish idiom: the read half of `SetValue`; see there.
    /// Go: `e.Value` field — read access (clone).
    pub fn Value(&self) -> T {
        return self.value.borrow().clone();
    }

    // go: none — goish idiom: Go exposes `Element.Value` as a public
    //     field. goish keeps the value in a shared `RefCell` so that
    //     `Remove` can still return it after unlinking, and a public
    //     field would have to hand out the borrow guard.
    /// Go: `e.Value = v` — write access. Visible through every
    /// outstanding handle that shares this value cell.
    pub fn SetValue(&self, v: T) {
        *self.value.borrow_mut() = v;
    }

    // go: sdk 1.25.5 container/list/list.go:31-36 Element.Next
    /// Go: list.go:31
    ///   func (e *Element) Next() *Element {
    ///       if p := e.next; e.list != nil && p != &e.list.root {
    ///           return p
    ///       }
    ///       return nil
    ///   }
    pub fn Next(&self) -> Option<Element<T>> {
        let rc = self.list.upgrade()?;
        let inner = rc.borrow();
        let n = inner.nodes.get(&self.id)?;
        let next_id = n.next;
        if next_id == ROOT_ID {
            return None;
        }
        let value = inner.nodes.get(&next_id)?.value.clone()?;
        return Some(Element {
            list: self.list.clone(),
            id: next_id,
            value,
        });
    }

    // go: sdk 1.25.5 container/list/list.go:39-44 Element.Prev
    /// Go: list.go:39
    ///   func (e *Element) Prev() *Element { ... }
    pub fn Prev(&self) -> Option<Element<T>> {
        let rc = self.list.upgrade()?;
        let inner = rc.borrow();
        let n = inner.nodes.get(&self.id)?;
        let prev_id = n.prev;
        if prev_id == ROOT_ID {
            return None;
        }
        let value = inner.nodes.get(&prev_id)?.value.clone()?;
        return Some(Element {
            list: self.list.clone(),
            id: prev_id,
            value,
        });
    }
}
