// container_heap_smoke — exercise container/heap.
// (container/heap/heap.go)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::container::heap::{self, Interface};
use goish::types::int;
use goish::{syscall, Println};

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
            Println!("[ 1] Push/Pop ascending      PASS");
        } else {
            Println!("[ 1] Push/Pop ascending      FAIL");
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
            Println!("[ 2] Init heapifies          PASS");
        } else {
            Println!("[ 2] Init heapifies          FAIL min={}", min);
            failed += 1;
        }
    }

    // 3. Empty heap.
    {
        let mut h = IntHeap(alloc::vec::Vec::new());
        heap::Init(&mut h);
        if h.Len() == 0 {
            Println!("[ 3] Empty heap              PASS");
        } else {
            Println!("[ 3] Empty heap              FAIL");
            failed += 1;
        }
    }

    // 4. Single-element heap: Push then Pop.
    {
        let mut h = IntHeap(alloc::vec::Vec::new());
        heap::Push(&mut h, 42);
        let v = heap::Pop(&mut h);
        if v == 42 && h.Len() == 0 {
            Println!("[ 4] Single Push/Pop         PASS");
        } else {
            Println!("[ 4] Single Push/Pop         FAIL");
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
            Println!("[ 5] Remove at index         PASS");
        } else {
            Println!("[ 5] Remove at index         FAIL");
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
            Println!("[ 6] Fix re-establishes      PASS");
        } else {
            Println!("[ 6] Fix re-establishes      FAIL min={}", min);
            failed += 1;
        }
    }

    // 7. Stress: random ints in, sorted out.
    {
        let mut h = IntHeap(alloc::vec::Vec::new());
        let inputs: alloc::vec::Vec<i64> = alloc::vec![
            42, 7, 19, 3, 100, -5, 0, 88, 33, -42, 50, 21, 99, -1, 64,
        ];
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
            Println!("[ 7] Stress 15 ints sorted   PASS");
        } else {
            Println!("[ 7] Stress 15 ints sorted   FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 7/7");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 7");
        syscall::Exit(1);
    }
}
