// container_heap_smoke — exercise container/heap.
// (container/heap/heap.go)
//
// Checks 1-7 are hand-written. Checks 8-10 compare the backing array
// after every operation against a running Go 1.25.5
// (tools/gen_heap_ref.go, run through scripts/goref.sh). Checking the
// exact array, not just the minimum, is the point: a heap with the
// wrong sift order still answers Pop correctly for a while.

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::container::heap::{self, Interface};
use goish::fmt;
use goish::syscall;
use goish::types::int;

// IntHeap: a min-heap of i64. Mirrors Go's example_test.go.
struct IntHeap(alloc::vec::Vec<i64>);

impl heap::Interface for IntHeap {
    type Item = i64;
    fn Len(&self) -> int {
        self.0.len() as int
    }
    fn Less(&self, i: int, j: int) -> bool {
        self.0[i as usize] < self.0[j as usize]
    }
    fn Swap(&mut self, i: int, j: int) {
        self.0.swap(i as usize, j as usize);
    }
    fn Push(&mut self, x: i64) {
        self.0.push(x);
    }
    fn Pop(&mut self) -> i64 {
        self.0.pop().unwrap()
    }
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. Push then Pop yields ascending order (min-heap).
    {
        let mut h = IntHeap(alloc::vec::Vec::new());
        for v in [3i64, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5] {
            heap::Push(&mut h, v);
        }
        let mut got = alloc::vec::Vec::new();
        while h.Len() > 0 {
            got.push(heap::Pop(&mut h));
        }
        let want: alloc::vec::Vec<i64> = alloc::vec![1, 1, 2, 3, 3, 4, 5, 5, 5, 6, 9];
        if got == want {
            fmt::Println!("[ 1] Push/Pop ascending      PASS");
        } else {
            fmt::Println!("[ 1] Push/Pop ascending      FAIL");
            failed += 1;
        }
    }

    // 2. Init on an unsorted vec produces valid heap.
    {
        let mut h = IntHeap(alloc::vec![5i64, 3, 7, 1, 9, 2, 8]);
        heap::Init(&mut h);
        // The min should be at index 0.
        let min = heap::Pop(&mut h);
        if min == 1 {
            fmt::Println!("[ 2] Init heapifies          PASS");
        } else {
            fmt::Println!("[ 2] Init heapifies          FAIL min={}", min);
            failed += 1;
        }
    }

    // 3. Empty heap.
    {
        let mut h = IntHeap(alloc::vec::Vec::new());
        heap::Init(&mut h);
        if h.Len() == 0 {
            fmt::Println!("[ 3] Empty heap              PASS");
        } else {
            fmt::Println!("[ 3] Empty heap              FAIL");
            failed += 1;
        }
    }

    // 4. Single-element heap: Push then Pop.
    {
        let mut h = IntHeap(alloc::vec::Vec::new());
        heap::Push(&mut h, 42);
        let v = heap::Pop(&mut h);
        if v == 42 && h.Len() == 0 {
            fmt::Println!("[ 4] Single Push/Pop         PASS");
        } else {
            fmt::Println!("[ 4] Single Push/Pop         FAIL");
            failed += 1;
        }
    }

    // 5. Remove at index. Build heap, remove middle, verify ordering.
    {
        let mut h = IntHeap(alloc::vec![1i64, 2, 3, 4, 5]);
        heap::Init(&mut h);
        // Remove element at index 2 (value depends on heap layout).
        let removed = heap::Remove(&mut h, 2);
        // After removal, sequential Pops should yield ascending order
        // of the remaining 4 elements.
        let mut got = alloc::vec::Vec::new();
        while h.Len() > 0 {
            got.push(heap::Pop(&mut h));
        }
        // Removed value should be one of {1,2,3,4,5}, and got should
        // contain the remaining 4 in ascending order.
        let mut all = got.clone();
        all.push(removed);
        all.sort();
        let want: alloc::vec::Vec<i64> = alloc::vec![1, 2, 3, 4, 5];
        // Ensure got is sorted (heap property).
        let mut sorted_got = got.clone();
        sorted_got.sort();
        if all == want && got == sorted_got {
            fmt::Println!("[ 5] Remove at index         PASS");
        } else {
            fmt::Println!("[ 5] Remove at index         FAIL");
            failed += 1;
        }
    }

    // 6. Fix after element mutation.
    {
        let mut h = IntHeap(alloc::vec![1i64, 5, 10, 15, 20]);
        heap::Init(&mut h);
        // Mutate root to a much larger value, then Fix.
        h.0[0] = 100;
        heap::Fix(&mut h, 0);
        // Now the root should be the smallest of the remaining set.
        let min = heap::Pop(&mut h);
        if min == 5 {
            fmt::Println!("[ 6] Fix re-establishes      PASS");
        } else {
            fmt::Println!("[ 6] Fix re-establishes      FAIL min={}", min);
            failed += 1;
        }
    }

    // 7. Stress: random ints in, sorted out.
    {
        let mut h = IntHeap(alloc::vec::Vec::new());
        let inputs: alloc::vec::Vec<i64> =
            alloc::vec![42, 7, 19, 3, 100, -5, 0, 88, 33, -42, 50, 21, 99, -1, 64,];
        for v in &inputs {
            heap::Push(&mut h, *v);
        }
        let mut got = alloc::vec::Vec::new();
        while h.Len() > 0 {
            got.push(heap::Pop(&mut h));
        }
        let mut want = inputs.clone();
        want.sort();
        if got == want {
            fmt::Println!("[ 7] Stress 15 ints sorted   PASS");
        } else {
            fmt::Println!("[ 7] Stress 15 ints sorted   FAIL");
            failed += 1;
        }
    }

    // 8. Init and Push against Go's exact backing array. A wrong sift
    //    order still yields the right minimum, so only the full array
    //    catches it.
    {
        let mut h = IntHeap(alloc::vec![5i64, 2, 9, 1, 7, 3, 8, 0, 4, 6]);
        heap::Init(&mut h);
        let mut ok = h.0 == alloc::vec![0i64, 1, 3, 2, 6, 9, 8, 5, 4, 7];
        heap::Push(&mut h, -1i64);
        ok = ok && h.0 == alloc::vec![-1i64, 0, 3, 2, 1, 9, 8, 5, 4, 7, 6];
        heap::Push(&mut h, 10i64);
        ok = ok && h.0 == alloc::vec![-1i64, 0, 3, 2, 1, 9, 8, 5, 4, 7, 6, 10];
        let v = heap::Pop(&mut h);
        ok = ok && v == -1 && h.0 == alloc::vec![0i64, 1, 3, 2, 6, 9, 8, 5, 4, 7, 10];
        if ok {
            fmt::Println!("[ 8] Init/Push/Pop vs Go     PASS");
        } else {
            fmt::Println!("[ 8] Init/Push/Pop vs Go     FAIL");
            failed += 1;
        }
    }

    // 9. Remove from the middle, then from the end. The middle case is
    //    the one that needs `down` first and `up` only if `down` made
    //    no progress — the replacement can belong either side of the
    //    hole.
    {
        let mut h = IntHeap(alloc::vec![0i64, 1, 3, 2, 6, 9, 8, 5, 4, 7, 10]);
        let r = heap::Remove(&mut h, 3);
        let mut ok = r == 2 && h.0 == alloc::vec![0i64, 1, 3, 4, 6, 9, 8, 5, 10, 7];
        let last = h.Len() - 1;
        let r2 = heap::Remove(&mut h, last);
        ok = ok && r2 == 7 && h.0 == alloc::vec![0i64, 1, 3, 4, 6, 9, 8, 5, 10];
        if ok {
            fmt::Println!("[ 9] Remove vs Go            PASS");
        } else {
            fmt::Println!("[ 9] Remove vs Go            FAIL");
            failed += 1;
        }
    }

    // 10. Fix after mutating an element in place, in both directions,
    //     then drain in order.
    {
        let mut h = IntHeap(alloc::vec![0i64, 1, 3, 4, 6, 9, 8, 5, 10]);
        h.0[2] = -5;
        heap::Fix(&mut h, 2);
        let mut ok = h.0 == alloc::vec![-5i64, 1, 0, 4, 6, 9, 8, 5, 10];
        h.0[0] = 99;
        heap::Fix(&mut h, 0);
        ok = ok && h.0 == alloc::vec![0i64, 1, 8, 4, 6, 9, 99, 5, 10];
        let mut out: alloc::vec::Vec<i64> = alloc::vec::Vec::new();
        while h.Len() > 0 {
            out.push(heap::Pop(&mut h));
        }
        ok = ok && out == alloc::vec![0i64, 1, 4, 5, 6, 8, 9, 10, 99];
        if ok {
            fmt::Println!("[10] Fix/drain vs Go         PASS");
        } else {
            fmt::Println!("[10] Fix/drain vs Go         FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        fmt::Println!("ok 10/10");
        syscall::Exit(0);
    } else {
        fmt::Println!("FAIL", failed, "of 10");
        syscall::Exit(1);
    }
}
