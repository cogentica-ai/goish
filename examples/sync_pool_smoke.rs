// sync_pool_smoke — exercise sync.Pool (slim port).
// (sync/pool.go)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicI64, Ordering};
use goish::runtime::sched::schedule;
use goish::sync::{Pool, WaitGroup};
use goish::{go, syscall, Println, KB};

#[goish::main]
fn main() {
    go!(|| run_tests());
    schedule();
}

fn run_tests() {
    let mut failed = 0;

    // 1. Empty pool: Get calls New.
    {
        let p: Pool<i64> = Pool::new(|| 42);
        let v = p.Get();
        if v == 42 {
            Println!("[ 1] Get on empty calls New  PASS");
        } else {
            Println!("[ 1] Get on empty calls New  FAIL got={}", v);
            failed += 1;
        }
    }

    // 2. Put then Get returns the same value.
    {
        let p: Pool<i64> = Pool::new(|| 0);
        p.Put(99);
        let v = p.Get();
        if v == 99 {
            Println!("[ 2] Put → Get round-trip   PASS");
        } else {
            Println!("[ 2] Put → Get round-trip   FAIL got={}", v);
            failed += 1;
        }
    }

    // 3. Multi-Put, multi-Get drains in LIFO order (impl detail; test
    //    that we got back exactly what we Put).
    {
        let p: Pool<i64> = Pool::new(|| -1);
        p.Put(1);
        p.Put(2);
        p.Put(3);
        let mut got: alloc::vec::Vec<i64> = alloc::vec::Vec::new();
        got.push(p.Get());
        got.push(p.Get());
        got.push(p.Get());
        let mut sorted = got.clone();
        sorted.sort();
        if sorted == alloc::vec![1, 2, 3] && p.__len() == 0 {
            Println!("[ 3] Put/Get drains          PASS");
        } else {
            Println!("[ 3] Put/Get drains          FAIL");
            failed += 1;
        }
    }

    // 4. Get past empty: keeps minting from New.
    {
        let counter = alloc::sync::Arc::new(AtomicI64::new(0));
        let counter_clone = counter.clone();
        let p: Pool<i64> = Pool::new(move || {
            counter_clone.fetch_add(1, Ordering::Relaxed) + 100
        });
        let v1 = p.Get();
        let v2 = p.Get();
        let v3 = p.Get();
        if v1 == 100 && v2 == 101 && v3 == 102 && counter.load(Ordering::Relaxed) == 3 {
            Println!("[ 4] New called per Get      PASS");
        } else {
            Println!("[ 4] New called per Get      FAIL");
            failed += 1;
        }
    }

    // 5. New is NOT called when the pool has items.
    {
        let counter = alloc::sync::Arc::new(AtomicI64::new(0));
        let counter_clone = counter.clone();
        let p: Pool<i64> = Pool::new(move || {
            counter_clone.fetch_add(1, Ordering::Relaxed);
            -1
        });
        p.Put(7);
        p.Put(8);
        let _ = p.Get();
        let _ = p.Get();
        if counter.load(Ordering::Relaxed) == 0 {
            Println!("[ 5] New unused when stocked PASS");
        } else {
            Println!("[ 5] New unused when stocked FAIL count={}", counter.load(Ordering::Relaxed));
            failed += 1;
        }
    }

    // 6. Concurrent Put/Get from goroutines.
    {
        let p: Pool<i64> = Pool::new(|| 0);
        let wg = WaitGroup::new();
        for tid in 0..4i64 {
            let pp = &p;
            wg.GoStack(64 * goish::KB, move || {
                for i in 0..50 {
                    pp.Put(tid * 1000 + i);
                    let _ = pp.Get();
                }
            });
        }
        wg.Wait();
        // After all 4 routines balance Put+Get, pool should be empty.
        if p.__len() == 0 {
            Println!("[ 6] Concurrent Put/Get      PASS");
        } else {
            Println!("[ 6] Concurrent Put/Get      FAIL len={}", p.__len() as i64);
            failed += 1;
        }
    }

    // 7. Heterogeneous T: pool of allocated buffers (Vec<u8>).
    {
        let p: Pool<alloc::vec::Vec<u8>> = Pool::new(|| alloc::vec::Vec::with_capacity(1024));
        let mut buf = p.Get();
        buf.push(0xab);
        buf.push(0xcd);
        let len_before = buf.len();
        // Reset and return.
        buf.clear();
        p.Put(buf);
        let buf2 = p.Get();
        if len_before == 2 && buf2.len() == 0 && buf2.capacity() >= 1024 {
            Println!("[ 7] Buffer reuse            PASS");
        } else {
            Println!("[ 7] Buffer reuse            FAIL");
            failed += 1;
        }
    }

    // 8. __len reflects state.
    {
        let p: Pool<i64> = Pool::new(|| 0);
        if p.__len() != 0 {
            Println!("[ 8] __len tracks items      FAIL initial");
            failed += 1;
        } else {
            p.Put(1);
            p.Put(2);
            p.Put(3);
            let after_put = p.__len();
            let _ = p.Get();
            let after_get = p.__len();
            if after_put == 3 && after_get == 2 {
                Println!("[ 8] __len tracks items      PASS");
            } else {
                Println!("[ 8] __len tracks items      FAIL put={} get={}", after_put as i64, after_get as i64);
                failed += 1;
            }
        }
    }

    if failed == 0 {
        Println!("ok 8/8");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 8");
        syscall::Exit(1);
    }
}
