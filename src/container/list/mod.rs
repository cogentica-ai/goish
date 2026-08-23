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
        ListInner {
            nodes,
            next_id: FIRST_REAL_ID,
            len: 0,
        }
    }

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
        new_id
    }

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
    fn move_after(&mut self, e: u64, at: u64) {
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
    fn clone(&self) -> List<T> {
        List {
            inner: Rc::clone(&self.inner),
        }
    }
}

impl<T: Clone> List<T> {
    /// Go: list.go:62  — `func New() *List { return new(List).Init() }`
    pub fn New() -> List<T> {
        List {
            inner: Rc::new(RefCell::new(ListInner::new())),
        }
    }

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

    /// Go: list.go:66  — `func (l *List) Len() int { return l.len }`
    pub fn Len(&self) -> int {
        self.inner.borrow().len
    }

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
        Some(Element {
            list: Rc::downgrade(&self.inner),
            id: head_id,
            value,
        })
    }

    /// Go: list.go:77
    ///   func (l *List) Back() *Element { ... }
    pub fn Back(&self) -> Option<Element<T>> {
        let inner = self.inner.borrow();
        if inner.len == 0 {
            return None;
        }
        let tail_id = inner.nodes.get(&ROOT_ID)?.prev;
        let value = inner.nodes.get(&tail_id)?.value.clone()?;
        Some(Element {
            list: Rc::downgrade(&self.inner),
            id: tail_id,
            value,
        })
    }

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
        e.value.borrow().clone()
    }

    /// Go: list.go:144
    ///   func (l *List) PushFront(v any) *Element {
    ///       l.lazyInit()
    ///       return l.insertValue(v, &l.root)
    ///   }
    pub fn PushFront(&self, v: T) -> Element<T> {
        let value = Rc::new(RefCell::new(v));
        let id = {
            let mut inner = self.inner.borrow_mut();
            inner.insert(value.clone(), ROOT_ID)
        };
        Element {
            list: Rc::downgrade(&self.inner),
            id,
            value,
        }
    }

    /// Go: list.go:150
    ///   func (l *List) PushBack(v any) *Element {
    ///       l.lazyInit()
    ///       return l.insertValue(v, l.root.prev)
    ///   }
    pub fn PushBack(&self, v: T) -> Element<T> {
        let value = Rc::new(RefCell::new(v));
        let id = {
            let mut inner = self.inner.borrow_mut();
            let tail = inner.nodes.get(&ROOT_ID).expect("root").prev;
            inner.insert(value.clone(), tail)
        };
        Element {
            list: Rc::downgrade(&self.inner),
            id,
            value,
        }
    }

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
            inner.insert(value.clone(), mark_prev)
        };
        Some(Element {
            list: Rc::downgrade(&self.inner),
            id,
            value,
        })
    }

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
            inner.insert(value.clone(), mark.id)
        };
        Some(Element {
            list: Rc::downgrade(&self.inner),
            id,
            value,
        })
    }

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
        inner.move_after(e.id, ROOT_ID);
    }

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
        inner.move_after(e.id, tail);
    }

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
        inner.move_after(e.id, mark_prev);
    }

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
        inner.move_after(e.id, mark.id);
    }

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
        for v in snap {
            let tail = inner.nodes.get(&ROOT_ID).expect("root").prev;
            inner.insert(Rc::new(RefCell::new(v)), tail);
        }
    }

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
        for v in snap {
            inner.insert(Rc::new(RefCell::new(v)), ROOT_ID);
        }
    }
}

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
    out
}

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
    out
}

// Go: list.go:62  — `func New() *List`
//
// Free-fn convenience matching `list.New()`.
pub fn New<T: Clone>() -> List<T> {
    List::New()
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
    fn clone(&self) -> Element<T> {
        Element {
            list: self.list.clone(),
            id: self.id,
            value: Rc::clone(&self.value),
        }
    }
}

impl<T: Clone> Element<T> {
    /// Go: `e.Value` field — read access (clone).
    pub fn Value(&self) -> T {
        self.value.borrow().clone()
    }

    /// Go: `e.Value = v` — write access. Visible through every
    /// outstanding handle that shares this value cell.
    pub fn SetValue(&self, v: T) {
        *self.value.borrow_mut() = v;
    }

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
        Some(Element {
            list: self.list.clone(),
            id: next_id,
            value,
        })
    }

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
        Some(Element {
            list: self.list.clone(),
            id: prev_id,
            value,
        })
    }
}
