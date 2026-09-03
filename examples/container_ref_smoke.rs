// container_ref_smoke — container/heap, container/list and container/ring against a running Go.
// (container/heap/heap.go, container/list/list.go, container/ring/ring.go)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_container_ref.go` run in
// `package heap_test` by `scripts/goref.sh`. goish matched Go on all 36
// lines — no defects found.
//
// These packages have no I/O and no hostile input, so what there is to
// get wrong is the INVARIANT — and every failure is a wrong ANSWER
// rather than an error. A heap that is not a heap still returns
// something from Pop. A list whose Remove leaves a stale pointer still
// iterates. A ring whose Unlink miscounts still walks. So the cases
// here are the degenerate ones, where an invariant is easiest to break
// and hardest to notice.
//
// heap is pinned as a SEQUENCE OF SLICE STATES, not just as the order
// things come out. It is not a sorted container: Pop returns the
// minimum, but the backing slice is in heap order, and a caller reading
// it directly sees an arrangement the package never promised. Printing
// it after every push and pop pins the arrangement Go actually
// produces, which is the only thing that makes two implementations
// interchangeable for a caller who looks.
//
// Also pinned: Fix after mutating an element in place, Remove from the
// middle, and duplicates coming out in the right multiplicity.
//
// list's awkward cases are the ones that look like no-ops and are not:
// MoveToFront on the element already at the front, MoveToBack on the
// one already at the back, and Remove of an element that has ALREADY
// been removed — which returns its value and leaves the list untouched
// rather than corrupting it. PushBackList and PushFrontList with the
// SAME list are pinned too, since a naive implementation splices a
// list into itself and loops forever.
//
// ring's are the sizes nobody tests: a ring of one whose Next is
// itself, Unlink(0) returning nil, and New(0) and New(-1) returning nil
// rather than an empty ring.
//
// One line was removed from this reference rather than pinned. It read
// the heap's slice and called heap.Pop in the same Printf, and Go
// printed the POST-pop value: the spec orders function calls left to
// right but leaves non-call operands unordered against them, so which
// value appears is a coin toss. Both sides now sequence the two
// explicitly. A reference that pins unspecified behaviour is a
// reference that fails on a compiler upgrade for no reason.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use alloc::vec::Vec;
use goish::container::heap;
use goish::container::heap::Interface;
use goish::container::list;
use goish::container::ring;
use goish::fmt;
use goish::goslice::slice;
use goish::gostring::string;
use goish::strings;
use goish::syscall;
use goish::types::int;
const GO: [&str; 36] = [
    "heap before-init=[5 2 9 1 7]",
    "heap after-init=[1 2 9 5 7]",
    "heap push 0  -> [0 2 1 5 7 9]",
    "heap push 6  -> [0 2 1 5 7 9 6]",
    "heap push 3  -> [0 2 1 3 7 9 6 5]",
    "heap pop -> 0  rest=[1 2 5 3 7 9 6]",
    "heap pop -> 1  rest=[2 3 5 6 7 9]",
    "heap pop -> 2  rest=[3 6 5 9 7]",
    "heap pop -> 3  rest=[5 6 7 9]",
    "heap pop -> 5  rest=[6 9 7]",
    "heap pop -> 6  rest=[7 9]",
    "heap pop -> 7  rest=[9]",
    "heap pop -> 9  rest=[]",
    "heap empty len=0",
    "heap single=[42] pop=42 len=0",
    "heap corrupted=[99 2 3 4 5]",
    "heap fixed=[2 4 3 99 5] min=2",
    "heap remove(2)=3 rest=[1 2 6 4 5]",
    "heap duplicates -> [1 1 3 3 3]",
    "list empty len=0 front-nil=true back-nil=true",
    "list after-push -> [c a b] len=3",
    "list after-insert -> [c a y x b]",
    "list move-to-front -> [b c a y x]",
    "list move-to-back -> [b a y x c]",
    "list move-noop -> [b a y x c]",
    "list remove(a)=a -> [b y x c]",
    "list remove-twice=a -> [b y x c] len=4",
    "list concat -> [p q 1 p q] len=5",
    "list zero-value -> [z] len=1",
    "ring len=5 -> [0 1 2 3 4]",
    "ring move(2) -> 2 move(-2) -> 3",
    "ring prev=4 next=1",
    "ring after-link r-len=8 joined-len=8 r=[0 100 101 102 1 2 3 4]",
    "ring after-unlink r-len=5 cut-len=3 cut=[100 101 102]",
    "ring one len=1 next-is-self=true unlink0-nil=true",
    "ring new(0)-nil=true new(-1)-nil=true",
];

fn chk(failed: &mut int, ln: &mut int, got: string) {
    if *ln >= GO.len() as int {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln + 1, got);
        *failed += 1;
        *ln += 1;
        return;
    }
    let want = s(GO[*ln as usize]);
    *ln += 1;
    if got == want {
        return;
    }
    fmt::Printf!("[!!] line %d FAIL\n  got  %q\n  want %q\n", *ln, got, want);
    *failed += 1;
}

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}
struct IntHeap(Vec<int>);
impl heap::Interface for IntHeap {
    type Item = int;
    fn Len(&self) -> int {
        return self.0.len() as int;
    }
    fn Less(&self, i: int, j: int) -> bool {
        return self.0[i as usize] < self.0[j as usize];
    }
    fn Swap(&mut self, i: int, j: int) {
        self.0.swap(i as usize, j as usize);
    }
    fn Push(&mut self, x: int) {
        self.0.push(x);
    }
    fn Pop(&mut self) -> int {
        return self.0.pop().unwrap();
    }
}
fn dumpVec(v: &[int]) -> string {
    let mut parts: Vec<string> = Vec::new();
    for x in v.iter() {
        parts.push(fmt::Sprintf!("%d", *x));
    }
    return string::from("[") + strings::Join(slice::<string>::__from_vec(parts), s(" ")) + "]";
}
fn dumpList(l: &list::List<string>) -> string {
    let mut parts: Vec<string> = Vec::new();
    let mut e = l.Front();
    while let Some(el) = e {
        parts.push(el.Value());
        e = el.Next();
    }
    return string::from("[") + strings::Join(slice::<string>::__from_vec(parts), s(" ")) + "]";
}
fn dumpRing(r: &ring::Ring<string>) -> string {
    let parts = alloc::sync::Arc::new(goish::sync::Mutex::new(Vec::<string>::new()));
    let pc = parts.clone();
    r.Do(move |v: &string| {
        pc.Lock().push(v.clone());
    });
    let v = parts.Lock().clone();
    return string::from("[") + strings::Join(slice::<string>::__from_vec(v), s(" ")) + "]";
}
#[goish::main]
fn main() {
    let mut failed: int = 0;
    let mut ln: int = 0;
    {
        let mut h = IntHeap(alloc::vec![5, 2, 9, 1, 7]);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("heap before-init=%s", dumpVec(&h.0)),
        );
        heap::Init(&mut h);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("heap after-init=%s", dumpVec(&h.0)),
        );
        for v in [0i64, 6, 3] {
            heap::Push(&mut h, v);
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("heap push %-2d -> %s", v, dumpVec(&h.0)),
            );
        }
        while h.0.len() > 0 {
            let min = heap::Pop(&mut h);
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!("heap pop -> %-2d rest=%s", min, dumpVec(&h.0)),
            );
        }
        let mut e = IntHeap(Vec::new());
        heap::Init(&mut e);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("heap empty len=%d", e.Len()),
        );
        heap::Push(&mut e, 42);
        let single = dumpVec(&e.0);
        let popped = heap::Pop(&mut e);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("heap single=%s pop=%d len=%d", single, popped, e.Len()),
        );
        let mut f = IntHeap(alloc::vec![1, 2, 3, 4, 5]);
        heap::Init(&mut f);
        f.0[0] = 99;
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("heap corrupted=%s", dumpVec(&f.0)),
        );
        heap::Fix(&mut f, 0);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("heap fixed=%s min=%d", dumpVec(&f.0), f.0[0]),
        );
        let mut g = IntHeap(alloc::vec![1, 2, 3, 4, 5, 6]);
        heap::Init(&mut g);
        let removed = heap::Remove(&mut g, 2);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("heap remove(2)=%d rest=%s", removed, dumpVec(&g.0)),
        );
        let mut d = IntHeap(alloc::vec![3, 3, 3, 1, 1]);
        heap::Init(&mut d);
        let mut got: Vec<int> = Vec::new();
        while d.Len() > 0 {
            got.push(heap::Pop(&mut d));
        }
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("heap duplicates -> %s", dumpVec(&got)),
        );
    }
    {
        let l = list::New::<string>();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "list empty len=%d front-nil=%v back-nil=%v",
                l.Len(),
                l.Front().is_none(),
                l.Back().is_none()
            ),
        );
        let a = l.PushBack(s("a"));
        let b = l.PushBack(s("b"));
        let c = l.PushFront(s("c"));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("list after-push -> %s len=%d", dumpList(&l), l.Len()),
        );
        l.InsertBefore(s("x"), &b);
        l.InsertAfter(s("y"), &a);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("list after-insert -> %s", dumpList(&l)),
        );
        l.MoveToFront(&b);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("list move-to-front -> %s", dumpList(&l)),
        );
        l.MoveToBack(&c);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("list move-to-back -> %s", dumpList(&l)),
        );
        let f = l.Front().unwrap();
        l.MoveToFront(&f);
        let bk = l.Back().unwrap();
        l.MoveToBack(&bk);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("list move-noop -> %s", dumpList(&l)),
        );
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("list remove(a)=%s -> %s", l.Remove(&a), dumpList(&l)),
        );
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "list remove-twice=%s -> %s len=%d",
                l.Remove(&a),
                dumpList(&l),
                l.Len()
            ),
        );
        let l2 = list::New::<string>();
        l2.PushBack(s("p"));
        l2.PushBack(s("q"));
        let l3 = list::New::<string>();
        l3.PushBack(s("1"));
        l3.PushBackList(&l2);
        l3.PushFrontList(&l2);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("list concat -> %s len=%d", dumpList(&l3), l3.Len()),
        );
        let z = list::List::<string>::New();
        z.PushBack(s("z"));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("list zero-value -> %s len=%d", dumpList(&z), z.Len()),
        );
    }
    {
        let r0 = ring::New::<string>(5).unwrap();
        let mut cur = r0.clone();
        for i in 0..5 {
            cur.SetValue(fmt::Sprintf!("%d", i as int));
            cur = cur.Next();
        }
        let r = cur;
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("ring len=%d -> %s", r.Len(), dumpRing(&r)),
        );
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "ring move(2) -> %s move(-2) -> %s",
                r.Move(2).Value(),
                r.Move(-2).Value()
            ),
        );
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!("ring prev=%s next=%s", r.Prev().Value(), r.Next().Value()),
        );
        let s0 = ring::New::<string>(3).unwrap();
        let mut sc = s0.clone();
        for i in 0..3 {
            sc.SetValue(fmt::Sprintf!("%d", (100 + i) as int));
            sc = sc.Next();
        }
        let joined = r.Link(&sc);
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "ring after-link r-len=%d joined-len=%d r=%s",
                r.Len(),
                joined.Len(),
                dumpRing(&r)
            ),
        );
        let cut = r.Unlink(3).unwrap();
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "ring after-unlink r-len=%d cut-len=%d cut=%s",
                r.Len(),
                cut.Len(),
                dumpRing(&cut)
            ),
        );
        let one = ring::New::<string>(1).unwrap();
        one.SetValue(s("solo"));
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "ring one len=%d next-is-self=%v unlink0-nil=%v",
                one.Len(),
                one.Next().Value() == one.Value() && one.Len() == 1,
                one.Unlink(0).is_none()
            ),
        );
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "ring new(0)-nil=%v new(-1)-nil=%v",
                ring::New::<string>(0).is_none(),
                ring::New::<string>(-1).is_none()
            ),
        );
    }
    if ln != GO.len() as int {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln, GO.len() as int);
        failed += 1;
    }
    if failed == 0 {
        fmt::Printf!("ok %d/%d\n", ln, ln);
        return;
    }
    fmt::Printf!("FAILED %d of %d\n", failed, ln);
    syscall::Exit(1);
}
