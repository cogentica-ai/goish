// textproto_pipeline_smoke — exercise net/textproto.Pipeline.
// (net/textproto/pipeline.go)

#![no_std]
#![no_main]
#![allow(non_snake_case)]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicU64, Ordering};

use goish::net::textproto::Pipeline;
use goish::runtime::sched::schedule;
use goish::sync::WaitGroup;
use goish::{go, syscall, Println, KB};

#[goish::main]
fn main() {
    // Run the test body in a dedicated goroutine — main can't block
    // on Sema-based waits (it has no current_g).
    go!(stack(64 * KB), || run_tests());
    schedule();
}

fn run_tests() {
    let mut failed = 0;

    // 1. Next() returns sequential ids starting at 0.
    {
        let p = Pipeline::new();
        let a = p.Next();
        let b = p.Next();
        let c = p.Next();
        if a == 0 && b == 1 && c == 2 {
            Println!("[ 1] Next sequential         PASS");
        } else {
            Println!("[ 1] Next sequential         FAIL");
            failed += 1;
        }
    }

    // 2. Single-thread Start/End on id 0 doesn't block.
    {
        let p = Pipeline::new();
        let id = p.Next();
        p.StartRequest(id);
        p.EndRequest(id);
        p.StartResponse(id);
        p.EndResponse(id);
        Println!("[ 2] Single id no block      PASS");
    }

    // 3. FIFO request ordering: spawn N goroutines that race to
    //    Start+End — must pass through the gate in id order.
    {
        const N: u64 = 16;
        let p = alloc::sync::Arc::new(Pipeline::new());
        let order: alloc::sync::Arc<[AtomicU64; N as usize]> =
            alloc::sync::Arc::new(core::array::from_fn(|_| AtomicU64::new(u64::MAX)));
        let counter = alloc::sync::Arc::new(AtomicU64::new(0));

        let wg = WaitGroup::new();
        for _ in 0..N {
            let id = p.Next();
            let p_c = p.clone();
            let order_c = order.clone();
            let counter_c = counter.clone();
            wg.GoStack(64 * KB, move || {
                p_c.StartRequest(id);
                let slot = counter_c.fetch_add(1, Ordering::SeqCst);
                order_c[slot as usize].store(id, Ordering::SeqCst);
                p_c.EndRequest(id);
            });
        }
        wg.Wait();

        let mut ok = true;
        for i in 0..N as usize {
            if order[i].load(Ordering::SeqCst) != i as u64 {
                ok = false;
                break;
            }
        }
        if ok {
            Println!("[ 3] FIFO request ordering   PASS");
        } else {
            Println!("[ 3] FIFO request ordering   FAIL");
            failed += 1;
        }
    }

    // 4. FIFO response ordering: same but for the response sequencer.
    {
        const N: u64 = 16;
        let p = alloc::sync::Arc::new(Pipeline::new());
        let order: alloc::sync::Arc<[AtomicU64; N as usize]> =
            alloc::sync::Arc::new(core::array::from_fn(|_| AtomicU64::new(u64::MAX)));
        let counter = alloc::sync::Arc::new(AtomicU64::new(0));

        let wg = WaitGroup::new();
        for _ in 0..N {
            let id = p.Next();
            let p_c = p.clone();
            let order_c = order.clone();
            let counter_c = counter.clone();
            wg.GoStack(64 * KB, move || {
                p_c.StartResponse(id);
                let slot = counter_c.fetch_add(1, Ordering::SeqCst);
                order_c[slot as usize].store(id, Ordering::SeqCst);
                p_c.EndResponse(id);
            });
        }
        wg.Wait();

        let mut ok = true;
        for i in 0..N as usize {
            if order[i].load(Ordering::SeqCst) != i as u64 {
                ok = false;
                break;
            }
        }
        if ok {
            Println!("[ 4] FIFO response ordering  PASS");
        } else {
            Println!("[ 4] FIFO response ordering  FAIL");
            failed += 1;
        }
    }

    // 5. Independent request/response sequencers.
    {
        let p = Pipeline::new();
        let id0 = p.Next();
        let id1 = p.Next();
        p.StartRequest(id0);
        p.EndRequest(id0);
        p.StartResponse(id0);
        p.EndResponse(id0);
        p.StartRequest(id1);
        p.EndRequest(id1);
        p.StartResponse(id1);
        p.EndResponse(id1);
        Println!("[ 5] Independent sequencers  PASS");
    }

    if failed == 0 {
        Println!("ok 5/5");
        syscall::Exit(0);
    } else {
        Println!("FAIL", failed, "of 5");
        syscall::Exit(1);
    }
}
