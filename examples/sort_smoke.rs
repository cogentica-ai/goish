// sort_smoke — exercise the slim sort package.
// (sort/sort.go + sort/search.go)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use goish::sort;
use goish::types::{float64, int};
use goish::{slice, string, syscall, Println};

// IntSlice: replicates Go's sort.IntSlice — implements Interface for an
// int slice so we can drive `sort::Sort` directly.
struct IntSlice(alloc::vec::Vec<int>);

impl sort::Interface for IntSlice {
    fn Len(&self) -> int {
        self.0.len() as int
    }
    fn Less(&self, i: int, j: int) -> bool {
        self.0[i as usize] < self.0[j as usize]
    }
    fn Swap(&mut self, i: int, j: int) {
        self.0.swap(i as usize, j as usize);
    }
}

#[goish::main]
fn main() {
    let mut failed = 0;

    // 1. sort::Sort on Interface — heapsort an unsorted IntSlice.
    {
        let mut s = IntSlice(alloc::vec![5, 1, 4, 2, 8, 0, 3]);
        sort::Sort(&mut s);
        let want: alloc::vec::Vec<int> = alloc::vec![0, 1, 2, 3, 4, 5, 8];
        if s.0 == want {
            Println!("[ 1] Sort Interface           PASS");
        } else {
            Println!("[ 1] Sort Interface           FAIL");
            failed += 1;
        }
    }

    // 2. sort::IsSorted on Interface — sorted, then unsorted.
    {
        let s_ok = IntSlice(alloc::vec![1, 2, 3, 4, 5]);
        let s_no = IntSlice(alloc::vec![1, 3, 2, 4, 5]);
        if sort::IsSorted(&s_ok) && !sort::IsSorted(&s_no) {
            Println!("[ 2] IsSorted Interface       PASS");
        } else {
            Println!("[ 2] IsSorted Interface       FAIL");
            failed += 1;
        }
    }

    // 3. sort::Reverse — wrap an IntSlice; Sort then yields descending.
    {
        let s = IntSlice(alloc::vec![3, 1, 4, 1, 5, 9, 2, 6]);
        let mut rev = sort::Reverse(s);
        sort::Sort(&mut rev);
        let want: alloc::vec::Vec<int> = alloc::vec![9, 6, 5, 4, 3, 2, 1, 1];
        if rev.inner.0 == want {
            Println!("[ 3] Reverse                  PASS");
        } else {
            Println!("[ 3] Reverse                  FAIL");
            failed += 1;
        }
    }

    // 4. sort::Search — first index where f(i) is true.
    {
        let n = sort::Search(10, |i| i >= 7);
        let m = sort::Search(10, |_| false); // never true → returns n
        let z = sort::Search(0, |_| true);   // empty → returns 0
        if n == 7 && m == 10 && z == 0 {
            Println!("[ 4] Search basic             PASS");
        } else {
            Println!("[ 4] Search basic             FAIL n={} m={} z={}", n, m, z);
            failed += 1;
        }
    }

    // 5. sort::Find — 3-way cmp, returns (i, found).
    {
        // a sorted slice; cmp(i) compares target=4 against a[i]
        let a: [int; 6] = [1, 2, 4, 4, 5, 7];
        let (i, ok) = sort::Find(a.len() as int, |i| {
            let v = a[i as usize];
            // cmp returns >0 when target > a[i] (search must move right).
            // To find target=4: cmp = sign(4 - a[i])  …actually Go's contract
            // is "cmp(i) > 0 for leading prefix, cmp(i) == 0 in middle, < 0 suffix".
            // For target=4 in a sorted ascending array, that means we want
            // cmp(i) = sign(4 - a[i])  (positive when a[i] < 4, zero when equal,
            // negative when a[i] > 4) — which is the natural encoding.
            if 4 > v { 1 } else if 4 == v { 0 } else { -1 }
        });
        // Should find the first 4 (index 2).
        let (j, no) = sort::Find(a.len() as int, |i| {
            let v = a[i as usize];
            if 6 > v { 1 } else if 6 == v { 0 } else { -1 }
        });
        if i == 2 && ok && j == 5 && !no {
            Println!("[ 5] Find 3-way cmp           PASS");
        } else {
            Println!(
                "[ 5] Find 3-way cmp           FAIL i={} ok={} j={} no={}",
                i, ok as int, j, no as int
            );
            failed += 1;
        }
    }

    // 6. sort::SearchInts — binary search in a sorted []int.
    {
        let a: goish::slice<int> = slice!([]int{1, 3, 5, 7, 9, 11});
        let i3 = sort::SearchInts(&a, 3);   // present at 1
        let i4 = sort::SearchInts(&a, 4);   // would insert at 2
        let i12 = sort::SearchInts(&a, 12); // beyond end → 6
        let i0 = sort::SearchInts(&a, 0);   // before start → 0
        if i3 == 1 && i4 == 2 && i12 == 6 && i0 == 0 {
            Println!("[ 6] SearchInts               PASS");
        } else {
            Println!(
                "[ 6] SearchInts               FAIL {} {} {} {}",
                i3, i4, i12, i0
            );
            failed += 1;
        }
    }

    // 7. sort::SearchStrings — binary search in sorted []string.
    {
        let a: goish::slice<goish::gostring::string> = slice!([]goish::gostring::string{
            string("apple"),
            string("banana"),
            string("cherry"),
            string("date"),
        });
        let i = sort::SearchStrings(&a, string("cherry"));
        let j = sort::SearchStrings(&a, string("blueberry"));
        if i == 2 && j == 2 {
            Println!("[ 7] SearchStrings            PASS");
        } else {
            Println!("[ 7] SearchStrings            FAIL i={} j={}", i, j);
            failed += 1;
        }
    }

    // 8. sort::Ints! macro — in-place sort of slice<int>.
    {
        let mut nums: goish::slice<int> = slice!([]int{5, 2, 8, 1, 9, 3, 7});
        sort::Ints!(nums);
        let want: alloc::vec::Vec<int> = alloc::vec![1, 2, 3, 5, 7, 8, 9];
        let raw: &[int] = &nums;
        if raw == want.as_slice() {
            Println!("[ 8] Ints! macro              PASS");
        } else {
            Println!("[ 8] Ints! macro              FAIL");
            failed += 1;
        }
    }

    // 9. sort::Strings! macro — in-place sort of slice<string>.
    {
        let mut s: goish::slice<goish::gostring::string> = slice!([]goish::gostring::string{
            string("delta"),
            string("alpha"),
            string("charlie"),
            string("bravo"),
        });
        sort::Strings!(s);
        let raw: &[goish::gostring::string] = &s;
        let ok = raw.len() == 4
            && raw[0] == string("alpha")
            && raw[1] == string("bravo")
            && raw[2] == string("charlie")
            && raw[3] == string("delta");
        if ok {
            Println!("[ 9] Strings! macro           PASS");
        } else {
            Println!("[ 9] Strings! macro           FAIL");
            failed += 1;
        }
    }

    // 10. sort::Float64s! macro — NaN-before-others ordering.
    {
        let nan: float64 = float64::NAN;
        let mut xs: goish::slice<float64> = slice!([]float64{3.0, 1.0, nan, 2.0});
        sort::Float64s!(xs);
        let raw: &[float64] = &xs;
        // After sort: NaN first, then 1.0, 2.0, 3.0.
        let ok = raw.len() == 4 && raw[0].is_nan() && raw[1] == 1.0 && raw[2] == 2.0 && raw[3] == 3.0;
        if ok {
            Println!("[10] Float64s! NaN first      PASS");
        } else {
            Println!("[10] Float64s! NaN first      FAIL");
            failed += 1;
        }
    }

    // 11. *AreSorted predicates.
    {
        let a: goish::slice<int> = slice!([]int{1, 2, 3, 4, 5});
        let b: goish::slice<int> = slice!([]int{1, 3, 2, 4, 5});
        let s: goish::slice<goish::gostring::string> = slice!([]goish::gostring::string{
            string("a"), string("b"), string("c"),
        });
        let nan: float64 = float64::NAN;
        let f: goish::slice<float64> = slice!([]float64{nan, 1.0, 2.0, 3.0}); // NaN first → sorted
        if sort::IntsAreSorted(&a)
            && !sort::IntsAreSorted(&b)
            && sort::StringsAreSorted(&s)
            && sort::Float64sAreSorted(&f)
        {
            Println!("[11] AreSorted predicates     PASS");
        } else {
            Println!("[11] AreSorted predicates     FAIL");
            failed += 1;
        }
    }

    if failed == 0 {
        Println!("ok 11/11");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 11");
        syscall::Exit(1);
    }
}

