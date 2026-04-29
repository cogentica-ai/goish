// spawn_million — spawn 1,000,000 goroutines, hold them parked,
// expose memory stats so an external process can measure.
//
// Lifecycle:
//
//   1. Print PID + baseline /proc/self/status.
//   2. Spawn N goroutines, each at minimum stack (default 2 KiB
//      via stackpool). Each goroutine increments SPAWNED then
//      blocks on a chan recv (release barrier).
//   3. Once all N are parked, print "PARKED" + memory snapshot.
//      Sleep `HOLD_SECS` so an external process (`spawn_million.sh`
//      or any /proc reader) can sample VmRSS / VmSize.
//   4. Send N broadcasts on the release chan; each goroutine wakes,
//      decrements WG, and exits.
//   5. Print "EXITED" + final memory snapshot.
//
// **Build in release mode for tightest frames** — debug builds will
// likely exceed 2 KiB on chan-recv paths even at minimum stack.
//
// Runs in foreground; pair with `examples/spawn_million.sh` (or
// any external `cat /proc/<pid>/status` loop).

#![no_std]
#![no_main]

extern crate alloc;
extern crate goish;

use core::sync::atomic::{AtomicI64, Ordering};
use goish::gochan::chan;
use goish::runtime::sched::{schedule, Gosched};
use goish::sync::WaitGroup;
use goish::{go, make, syscall, time, KB};

/// Number of goroutines to spawn. Override at compile time via
/// `--cfg goish_spawn_million_n=NNN` if you want a different count.
const N: i64 = 1_000_000;

/// How long to hold parked so an external sampler can read /proc.
const HOLD_SECS: i64 = 30;

/// Per-goroutine stack class. 2 KiB is the M26 minimum (carved from
/// stackpool). If the goroutine's body exceeds 2 KiB in this build's
/// frame size, bump to `4 * KB` or higher. Release mode usually fits.
const STACK_PER_G: usize = 2 * KB;

fn die(msg: &[u8]) -> ! {
    syscall::Write(syscall::STDERR, msg.as_ptr(), msg.len());
    syscall::Exit(1)
}

fn print(msg: &[u8]) {
    syscall::Write(syscall::STDOUT, msg.as_ptr(), msg.len());
}

fn print_dec(mut n: i64) {
    if n < 0 {
        print(b"-");
        n = -n;
    }
    let mut buf = [0u8; 24];
    let mut i = buf.len();
    if n == 0 {
        i -= 1;
        buf[i] = b'0';
    } else {
        while n > 0 {
            i -= 1;
            buf[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
    }
    print(&buf[i..]);
}

/// Read /proc/self/status, print VmPeak / VmSize / VmRSS / VmHWM /
/// VmData / Threads lines.
fn print_proc_status(label: &[u8]) {
    static PATH: &[u8] = b"/proc/self/status\0";
    let fd = syscall::Open(PATH.as_ptr(), syscall::O_RDONLY | syscall::O_CLOEXEC, 0);
    if fd < 0 {
        return;
    }
    let mut buf = [0u8; 4096];
    let n = syscall::Read(fd, buf.as_mut_ptr(), buf.len());
    syscall::Close(fd);
    if n <= 0 {
        return;
    }
    print(label);
    print(b":\n");
    let data = &buf[..(n as usize)];
    for prefix in [
        b"VmPeak:" as &[u8],
        b"VmSize:",
        b"VmHWM:",
        b"VmRSS:",
        b"VmData:",
        b"Threads:",
    ] {
        if let Some(line) = find_line(data, prefix) {
            print(b"  ");
            print(line);
            print(b"\n");
        }
    }
    print(b"\n");
}

fn find_line<'a>(data: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    let mut i = 0;
    while i + prefix.len() <= data.len() {
        let line_start = i;
        if &data[i..i + prefix.len()] == prefix {
            let mut j = i;
            while j < data.len() && data[j] != b'\n' {
                j += 1;
            }
            return Some(&data[line_start..j]);
        }
        while i < data.len() && data[i] != b'\n' {
            i += 1;
        }
        i += 1;
    }
    None
}

#[goish::main]
fn main() {
    let pid = syscall::Getpid();
    print(b"goish PID: ");
    print_dec(pid as i64);
    print(b"\n");
    print(b"target: spawn ");
    print_dec(N);
    print(b" goroutines @ ");
    print_dec(STACK_PER_G as i64);
    print(b" B/stack, hold ");
    print_dec(HOLD_SECS);
    print(b"s\n\n");

    print_proc_status(b"baseline");

    static SPAWNED: AtomicI64 = AtomicI64::new(0);
    static EXITED: AtomicI64 = AtomicI64::new(0);
    static WG: WaitGroup = WaitGroup::new();

    let release: chan<()> = make!(chan ());
    WG.Add(N);

    print(b"spawning... ");

    for _ in 0..N {
        let r = release.clone();
        go!(stack(STACK_PER_G), move || {
            SPAWNED.fetch_add(1, Ordering::Relaxed);
            let _ = r.Recv();
            EXITED.fetch_add(1, Ordering::Relaxed);
            WG.Done();
        });
    }

    print(b"all spawned (boxes leaked)\n\n");

    // Sampler goroutine: wait for parking to settle, sample, hold,
    // then release everyone.
    let release_for_drv = release.clone();
    go!(stack(64 * KB), move || {
        // Wait until all spawned Gs have hit the chan.Recv path.
        // Approximation: SPAWNED counter == N, then yield extras to
        // let them all reach the parked state.
        loop {
            if SPAWNED.load(Ordering::Acquire) == N {
                break;
            }
            for _ in 0..1000 {
                Gosched();
            }
        }
        for _ in 0..256 {
            Gosched();
        }
        print_proc_status(b"PARKED");

        print(b"holding ");
        print_dec(HOLD_SECS);
        print(b"s for external sampler...\n");
        time::Sleep(time::Second * HOLD_SECS);

        print(b"releasing all goroutines...\n");
        for _ in 0..N {
            release_for_drv.Send(());
        }
        WG.Wait();
        print_proc_status(b"EXITED");

        let exited = EXITED.load(Ordering::Acquire);
        if exited != N {
            print(b"FAIL: exited=");
            print_dec(exited);
            print(b" expected=");
            print_dec(N);
            print(b"\n");
            die(b"spawn_million: not all goroutines exited\n");
        }
        print(b"PASS\n");
    });

    schedule();
}
