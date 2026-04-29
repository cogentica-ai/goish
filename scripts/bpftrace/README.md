# bpftrace observability scripts

Lightweight uprobes that count goish runtime allocator entry points
without modifying the binary or perturbing performance. Useful for
detecting leaks (open / close imbalance) without rebuilding for
debug-counter mode.

## Requirements

- `bpftrace` ≥ 0.16 (Ubuntu 22.04+ has it: `apt install bpftrace`).
- Root, because uprobe attach is privileged. Wrap calls in `sudo`.
- A goish binary built with debug symbols (default for `cargo build`,
  not for `--release` unless you set `[profile.release] debug = true`).

## Scripts

### `netpoll_leak.bt`

Counts every call to `goish::runtime::netpoll::open` and matching
`close` calls; prints a delta on exit. Stack-trace samples (top 5
unique by frequency) are included so you can attribute imbalance
to a specific call site.

```
sudo ./scripts/bpftrace/netpoll_leak.bt path/to/binary &
path/to/binary <its args>
sudo pkill -INT bpftrace
```

Or use the wrapper:

```
sudo ./scripts/bpftrace/netpoll_run.sh \
    target/x86_64-unknown-linux-gnu/debug/examples/conn_drop_no_leak
```

## Interpreting output

```
=== netpoll registration report ===
open  count : 201
close count : 201
delta       : 0 (positive = unbalanced opens)
```

- `delta == 0`: every PollDesc that was registered with epoll was
  also unregistered. No fd-leaks. Healthy.
- `delta > 0`: some Conn or Listener never got Close()'d (or
  Drop()'d). Walk the open call sites in the report; the high-count
  one is the leak source.
- `delta < 0`: shouldn't happen — close was called more times than
  open. Indicates a Drop+Close double-call, or a logic bug.

## What this does NOT track

- PollDesc *memory* — intentionally never freed (see
  `feedback_no_arc_polldesc.md`). The "leak" we'd track here is
  kernel-fd leakage, not bytes.
- G allocations — would need separate uprobes on `scheduler::go` /
  `goexit`. Future addition.
- Stack regions — track via probes on the M26 stackpool API.
- mmap regions — track via syscall tracepoints
  (`tracepoint:syscalls:sys_enter_mmap` etc.).

## Why bpftrace and not gdb / printf?

- Zero binary modification — works on the same binary stress runs use.
- Zero overhead when not running.
- Stack traces aggregated, not interleaved with stdout.
- Exits cleanly on `kill -INT`, prints the END block report.

## Troubleshooting

**"failed to attach uprobe"** — symbol mangling differs across rustc
versions. Run `nm --demangle <binary> | grep netpoll` and adjust the
quoted symbol names in the .bt script if the demangled form differs
from `goish::runtime::netpoll::open` etc.

**"bpftrace currently only supports running as the root user"** —
prepend `sudo`. The wrapper script does this for you.

**Empty report (counts all 0)** — bpftrace attached to the wrong
binary path, or attached after the binary already exited. Use the
wrapper script which sleeps 300ms after attach before launching.
