# Port goish to aarch64-apple-darwin — staged, boot-first

> Every "Go does X" claim below was checked against the Go tree on this machine
> (`$(go env GOROOT)/src`, go1.26.4). Verified citations are marked with the file and line.

## Context

goish is a `no_std` Rust reimplementation of Go's stdlib and runtime (271k LOC; 18k of it in
`src/runtime` + `src/syscall`). It ships its own ELF `_start`, raw Linux syscalls, a Go-shaped
page allocator, an M:N scheduler with stackful goroutines, an epoll netpoller, SIGURG async
preemption and SIGSEGV backtraces.

It is **x86_64-linux only, unconditionally**. A repo-wide grep finds **zero** `cfg(target_arch)`
and **zero** `cfg(target_os)` gates in `src/` or `goish-macros/`. Syscall numbers, kernel struct
layouts, the TLS mechanism, register names, page size and the `GOARCH` string are all
unconditional. The port starts from no cfg infrastructure at all.

The development machine is Apple Silicon (`arm64`, 16 KiB pages). The goal is an
`aarch64-apple-darwin` build that runs here.

**The x86_64-linux regression gate does run on this machine** — measured 2026-08-21, not assumed.
The earlier reading ("no cross-linker is present, the project cannot be built or run natively")
was wrong, and its root cause is a PATH trap: `/opt/homebrew/bin/{rustc,cargo}` shadow the rustup
shims and ship **only** the host std, so a cross-build dies with `error[E0463]: can't find crate
for 'core' — the x86_64-unknown-linux-gnu target may not be installed` even though `rustup target
list --installed` shows it. Both are rustc 1.97.1, so `rustc -vV` cannot tell them apart; only
`which -a rustc` can. `~/.cargo/bin/cargo` compiles the crate clean.

Two pieces make the gate work:

- **Link:** a cc-style → `ld.lld` shim around `rust-lld` from the rustup sysroot — it drops
  `-m64`/`-nodefaultlibs`/`-nostartfiles`/`-no-pie` and unwraps `-Wl,`. (`zig cc` was tried first
  and is a dead end: `-target x86_64-linux-gnu` rejects `-static`, and `-target x86_64-linux-musl`
  rejects `--no-dynamic-linker` while sub-compiling a libc we never link.)
- **Run:** `docker run --platform linux/amd64` on the local colima VM. That VM is `vmType: vz`
  with `rosetta: false`, so amd64 is **qemu-user binfmt emulation**, not Rosetta.

Measured on that path: **12 probed examples all cross-link, and all 12 pass under emulation** —
`hello` (prints `Hello, World!`, exit 0), `alloc_smoke`, `alloc_mheap`, `chan_unbuffered`,
`chan_buffered`, `chan_select_stress`, `conn_deadline_smoke`, `conn_drop_no_leak`,
`sigaltstack_offline_proof`, `preempt_sysmon`, `spawn_density`, `x509_parse_smoke`. So the
netpoller, the sigaltstack proof and sysmon preemption all survive qemu-user. One caveat, which is
the fidelity warning below in miniature: `chan_select_stress` was **SIGKILLed (rc=137) at default
VM memory** and passed only when the container was given `--memory=8g`.

`scripts/e2e_runner.sh` itself needs **no source change** to drive this — verified by running it
unmodified inside the container over the built subset (5 iterations, 5 pass, 0 fail). Two things
it does need: `ARTIFACTS` pointed outside the bind-mount (the default `scripts/.e2e-artifacts`
would be written into the repo as root), and a `FILTER` that matches exactly what was built — the
runner enumerates targets, not binaries, so every unbuilt example is reported as `:missing` and
counted as a failure. That is the same pressure behind the planned `e2e_runner.sh:30,80` change to
take the allowlist as an input filter.

**Two limits, both load-bearing:**

- **Disk.** A full `cargo build --examples` needs ~50 GiB — each debug example is a ~47 MiB
  static ELF and there are 595 of them. It filled this disk at example 458 of 595. Build the
  allowlist, not `--examples`, locally.
- **Fidelity.** qemu-user does not reproduce x86 TSO for multithreaded programs and its
  signal/thread timing is its own; `chan_select_stress` ran 11.5 s wall / 28.9 s user, and see its
  SIGKILL above. Claim this gate as **compile + functional smoke only**. `ubuntu-latest` CI stays the sole
  authority for M5, M8, M12 and for anything `make e2e-full` exists to catch.

The shim and the docker invocation currently live in a scratch dir. If they become the dev gate
they belong in `scripts/` — but that adds a macOS-host dev path to a Linux-only-CI repo, which is
a repo-shape decision, not an implementation detail.

### The one thing that must be actively accepted

**A static, libc-free Mach-O is impossible.** Apple removed static `crt0.o`; every macOS
executable links `libSystem.dylib`, is loaded by dyld, and must be PIE. The README's headline
claim — *"no `glibc`, no `ld.so` … `ldd` reports not a dynamic executable"* — cannot hold on
Darwin. Everything else survives: no GC, no language runtime to initialize, goish's own
scheduler, allocator and netpoller.

**Go made exactly this concession**: it abandoned raw Darwin syscalls in 1.12 and routes
everything through libSystem via `libcCall` (`runtime/sys_darwin.go`, trampolines in
`runtime/sys_darwin_arm64.s:490-566`). Raw `svc #0x80` does function but is unsupported by Apple
*and cannot create threads* — `bsdthread_create` requires prior pthread-runtime registration.
Since libSystem is linked regardless, raw syscalls buy nothing. The honest framing for the
README: goish is libc-free **on Linux**; on Darwin it is libSystem-only, matching Go itself.

Following Go here is also what keeps the provenance thesis intact — Go supports darwin/arm64, so
every line has a citable original. All 17 anchor-target files were confirmed present locally.

### What is *not* a problem

`src/crypto/`, `src/hash/`, `src/xxh3/`, `src/math/`, `src/bytes/`, `src/strings/`,
`src/encoding/`, `src/compress/`, `src/reflect/`, `src/sort/`, `src/slices/` and the top-level
`src/*.rs` contain **zero** x86 intrinsics, SIMD, cpuid or `asm!`. Every crypto primitive is
already the scalar `_noasm`/`generic` path. `src/sync/` is pure `core::sync::atomic`. Byte order
goes through `from_le_bytes`/`to_be_bytes` with no transmutes. The port is confined to the
runtime, syscall and build layers, plus tooling.

---

## The linux/aarch64 question — opened 2026-08-21, not yet decided

`plan.md`'s "Explicitly out of scope" deprioritizes `aarch64-unknown-linux-gnu` as "not the chosen
target." A probe reopens it, because the local VM changes the arithmetic.

**The colima VM is natively aarch64** — 5 cores, and its `/proc/cpuinfo` Features line carries the
full modern set including `aes pmull sha1 sha2 sha3 sha512 lrcpc dcpop atomics bf16 i8mm` **and
`dit`**. `docker run --platform linux/arm64` is therefore *native execution*, not emulation: none of
the qemu-user fidelity caveats above apply to it.

**The link path is proven.** The same `rust-lld` shim with `-m aarch64linux` links a `#![no_std]`
`#![no_main]` probe against the existing Linux rustflags; `file` reports *ELF 64-bit LSB
executable, ARM aarch64, statically linked*, and it runs in the arm64 container and exits 0. **The
static, libc-free binary property survives** — so does the ELF section trick: the probe also
declares `#[link_section = "goish_rt_text"]` with one `u64` slot and reads
`__start_goish_rt_text`/`__stop_goish_rt_text`, which **ld.lld synthesizes**; it printed `bytes=8`.
That is the measured fact the "53 `link_section` sites vanish" claim rests on.

**The compile probe.** `rustup target add aarch64-unknown-linux-gnu`, that shim, the existing Linux
rustflags. `cargo build --target aarch64-unknown-linux-gnu --example hello` fails in the `goish`
**lib** with **41 errors across exactly 3 files** (cargo's 42nd line is its own
"due to 41 previous errors" summary):

| File | Errors | What |
|---|---|---|
| `src/syscall/mod.rs` | 36 | the `syscall0..6` stubs' `rax`/`rdi`/`rsi`/`rdx`/`r10`/`r8`/`r9` register constraints |
| `src/runtime/sched/m.rs` | 3 | `lock add dword ptr fs:[{off}]` / `lock xadd`, and `mov {}, rbp` / `mov {}, rsp` |
| `src/runtime/rand.rs` | 2 | `rdtsc` |

No other file in the 271k-LOC tree raised an error — but the compile **aborted**, so what is
proven is that nothing surfaced in the phases that ran; monomorphization and codegen never
happened. Read it as strong corroboration of the "What is *not* a problem" section, not as proof
the rest of the tree builds.

**That is the compile tip, not the port.** The dangerous residue is the code that compiles clean and
is *wrong at runtime*, because goish defines its own `ucontext`/`Gobuf` rather than importing libc's:

- `sched/gobuf.rs` — 97 x86 register-name sites, all plain struct fields
- `runtime/preempt.rs` — 70 sites plus **23 `REG_*` mcontext indices**
- `runtime/segv.rs` — 15 sites plus 4 `REG_*`
- `runtime/mod.rs` 16, `sched/grow.rs` 14, `sched/g.rs` 8, `runtime/spin.rs` 4, `sched/mod.rs` 4,
  `sched/scheduler.rs` 3, `sched/stack.rs` 1

**And the entry stub is not in the 42 at all** — `goish-macros/src/lib.rs:49`'s `global_asm!`
(`mov rdi, [rsp]`) lives in the *example* crate, which never got compiled because the lib failed
first. The error count grows once the lib builds. Full inventory: **14 files** carry x86 register
names, every one of them under `src/runtime/`, `src/syscall/mod.rs`, or `goish-macros/`.

**What linux/aarch64 removes that darwin/arm64 does not.** The entire OS half. ELF `.init_array`
and `__start_`/`__stop_` section-bound symbols both exist, so **the M1 blocker and all 53
`link_section` sites simply vanish** (measured above). futex, epoll, raw `svc #0`, `clone`,
in-image DWARF (so `runtime/symbolize/` keeps `file:line` instead of degrading to `dladdr`), and
the static libc-free binary all survive — the README's headline claim holds unchanged.

**Page size, measured not assumed:** `getconf PAGESIZE` in the arm64 container returns **4096**
(kernel `6.8.0-100-generic`), so **M2's page-size inversion does not arise on this VM**. Scope that
claim to this kernel — arm64 Linux ships 4K, 16K or 64K depending on config, so a CI runner or a
different distro can reintroduce exactly the Darwin problem. M2 stays a real milestone for
darwin/arm64 either way.

**What it does not remove.** M4 (TLS), M5 (AAPCS64 context switch, `d8`–`d15`, x30, no red zone),
M8 (SIGURG preemption), M11 (CPU feature detection) and M12 (weak memory) apply in full. Those are
the five hardest milestones; only their *OS* surface changes.

**One genuine Linux/arm64 constraint — it is not a renumber.** Verified in the local GOROOT
(go1.26.4): `syscall/zsysnum_linux_arm64.go` is generated from `asm-generic/unistd.h` and contains
**no** `SYS_OPEN`, `SYS_DUP2`, `SYS_POLL`, `SYS_EPOLL_CREATE`, `SYS_FORK` or `SYS_PIPE`, all six of
which `zsysnum_linux_amd64.go` does define. goish uses four of them today:

- `SYS_OPEN` — `syscall/mod.rs:20,484`, `net/dnsconfig.rs:317` → `openat`
- `SYS_FORK` — `syscall/mod.rs:67,503` (whose own comment notes x86_64 "still ships the legacy
  `SYS_FORK` (57)") → `clone`. Go never uses `SYS_FORK` on *any* Linux arch:
  `syscall/exec_linux.go:340-342` calls `rawVforkSyscall(SYS_CLONE, …)`, and `SYS_CLONE` exists on
  both (`zsysnum_linux_arm64.go:228` = 220, `zsysnum_linux_amd64.go:63` = 56). So goish already
  diverges from Go here on x86_64; arm64 just makes it mandatory.
- `SYS_DUP2` — `syscall/mod.rs:70` → `dup3`
- `SYS_POLL` — `syscall/mod.rs:1780,2095` → `ppoll`

Each needs a **different call**, not a different number, so `zsysnum_linux_arm64.rs` is not a pure
renumber of the amd64 table and the M0 syscall split has to allow for that. `Open` is the easy one
— Go's own `syscall/syscall_linux.go:279-281` is already `openat(_AT_FDCWD, …)` on every Linux
arch, so the port follows rather than invents.

**The netpoller, by contrast, is a pure renumber.** goish already uses the modern trio —
`SYS_EPOLL_CREATE1`/`SYS_EPOLL_CTL`/`SYS_EPOLL_PWAIT` (`syscall/mod.rs:60-62,1710,1724,1758`) — and
all three exist on arm64 (`zsysnum_linux_arm64.go:27-29`). Note Go itself has to remap here:
`syscall_linux_arm64.go:16` binds `EpollWait` to `SYS_EPOLL_PWAIT` because plain `epoll_wait` is
another of the legacy calls arm64 dropped. goish landed on the right side of that by accident.

**The strongest argument for taking this on.** M12 says x86 CI gives "literally zero signal" on
weak memory and is "not a milestone without the arm64 CI job." A native aarch64 Linux target makes
that audit runnable **on this machine, today, with zero Darwin work**. The same VM reports `dit`,
which is precisely the feature M11 flags `crypto/subtle/dit.rs` for silently dropping.

**The decision taken (2026-08-21): (b).** linux/aarch64 goes in front of darwin/arm64, so each
milestone changes *one* variable — arch-on-Linux first, then OS-on-arm64 — instead of both at
once. Cost, as expected: the `_GOOS_GOARCH` file-suffix scheme carries three tuples from M0 rather
than two, and `port_lint`/`port_coverage`'s `--goos`/`--goarch` pair has to be real from the start
rather than a later refit.

### M1 on linux/aarch64 — landed

`make run-arm64` prints `Hello, World!` and exits 0, from a `statically linked` ELF 64-bit LSB
executable, ARM aarch64, run natively in the arm64 container. **The libc-free static-binary
property survives on this target** — the concession at the top of this document is a Darwin
concession, not an arm64 one.

What runs on arm64 today: the entry stub, `args`, `flags`, the thread pointer, the dlmalloc
bootstrap heap, `mheap`, `mcentral`, the P array, `setup_main_g0`, `symbolize::init` and the
SIGSEGV handler install. What does not: the scheduler. `gogo` is M5, so the staged `__goish_rt0`
calls the user main **directly on g0** — which means `current_g()` is `None` while it runs and any
blocking primitive fatals with "outside of any goroutine" instead of parking. That is the M1
contract here, and it is why `scripts/linux_arm64_examples.txt` starts at `hello` and not at the
channel examples.

Files added, all following the `_GOOS_GOARCH` convention:

| Area | amd64 | arm64 |
|---|---|---|
| raw syscall instruction | `sys/sys_linux_amd64.rs` | `sys/sys_linux_arm64.rs` |
| syscall numbers | `syscall/zsysnum_linux_amd64.rs` | `syscall/zsysnum_linux_arm64.rs` |
| whole-function asm | `syscall/asm_linux_amd64.rs` | `syscall/asm_linux_arm64.rs` |
| thread pointer | `sched/tls/tls_linux_amd64.rs` | `sched/tls/tls_linux_arm64.rs` |
| context switch | `sched/gobuf_asm_amd64.rs` | `sched/gobuf_asm_arm64.rs` (M5 aborts) |
| stack pivot | `sched/grow_asm_amd64.rs` | `sched/grow_asm_arm64.rs` (real) |
| preempt trampoline | `runtime/preempt_asm_amd64.rs` | `runtime/preempt_asm_arm64.rs` (M8 abort) |
| cycle counter | `runtime/cputicks/cputicks_amd64.rs` | `runtime/cputicks/cputicks_linux_arm64.rs` |
| entry stub | `runtime/entry.rs` (both arms, see the file for why it is one file) | — |

**Five findings worth carrying forward, none of which were in the plan:**

1. **`compiler_builtins` pulls in glibc on aarch64.** LLVM's default "outline atomics" route every
   atomic RMW through `__aarch64_ldadd*` helpers that pick LSE or LL/SC at runtime by calling
   `getauxval(AT_HWCAP)`. With `-nodefaultlibs` the link fails on an undefined `getauxval`.
   `-C target-feature=-outline-atomics` inlines the baseline `ldxr`/`stxr` sequences instead. This
   will recur on darwin/arm64.
2. **arm64 Linux `clone` puts TLS in x3, not x5** (`CLONE_BACKWARDS`), and Go cannot be cited for
   it: `runtime/sys_linux_arm64.s:670-686` never passes a TLS argument, because non-cgo Go/arm64
   keeps `g` in R28 rather than the thread pointer (`tls_arm64.s:12-18` short-circuits `load_g` on
   `iscgo`). goish *does* use the thread pointer, so it needs `CLONE_SETTLS` where Go does not.
   Established by experiment — a static arm64 binary cloned a thread with a magic value in x3 and
   the child read it back out of `TPIDR_EL0`. Re-run that probe rather than re-reasoning about it.
3. **`Gobuf`, `preempt.rs`'s `REG_*` indices and the whole `ucontext` compile fine on arm64 and are
   wrong.** rustc does not parse inline-asm strings either, so *neither* the type checker nor the
   error count bounds the port. Only the assembler and the linker do, and they run last.
4. **The legacy-syscall problem is smaller than it looks and the fix is Go's.** Eleven wrappers
   moved to their `*at` forms **on both architectures** — `Open`→`openat(AT_FDCWD, …)` and friends,
   `Fork`→`clone(SIGCHLD, 0)`, `Poll`→`ppoll` — rather than forking per target, because that is
   exactly what `syscall/syscall_linux.go:279-281` and `exec_linux.go:340-342` already do for every
   Linux arch including amd64. Net effect: no per-arch wrapper file was needed at all.
5. **`and sp, sp, #-16` does not encode.** AND (immediate) takes SP as destination but not as
   source. Via a scratch register, and only in the entry stub.

---

### M1 on darwin/arm64 — landed 2026-08-21

`make run-darwin` builds and runs **17 examples natively on macOS**, 17 pass, 0 fail. All four
acceptance criteria hold: `hello` prints `Hello, World!` and exits 0; `file` reports *Mach-O
64-bit executable arm64*; `otool -L` shows `/usr/lib/libSystem.B.dylib` and `otool -l` a valid
`LC_MAIN entryoff 2112`; `codesign -v` is silent. The x86_64-linux regression gate was re-run
after every commit that touched shared code — 12 examples cross-linked and run under `docker
--platform linux/amd64`, 12 pass, 0 fail — and the binary is still `ET_EXEC` with no `PT_INTERP`
and a 92144-byte `goish_rt_text` section, so the static libc-free property is intact.

On this target it is native execution, not emulation. It is the only gate in the tree that needs
neither docker nor qemu.

**Seven findings that change the rest of the plan.**

1. **The wall is M4, not M2 — reorder the ladder.** The plan's ladder implies memory then time
   then threads. Measured against 18 probed examples, the thing that actually gates them is
   `current_m()`: `defer_smoke`, `aes_smoke`, `asn1_smoke` and `atomic_value_smoke` all stop at
   the thread pointer, and nothing stopped at the allocator. M4 unblocks strictly more than M2
   or M3 do, and it is also M6's and M8's prerequisite (both need each M's `pthread_t` in
   `MStorage`). **Take M4 next.**

2. **dlmalloc is gone, so M1 got the allocator for free and M2 is smaller than written.** Plan
   step 12 and part of M2's risk paragraph describe a "pre-mheap dlmalloc `#[global_allocator]`
   path" that no longer exists — `PageAlloc`'s metadata moved to raw `mmap`, so mheap and
   mcentral need nothing but `Mmap` and both come online in M1 here. The 320 GiB `MAP_NORESERVE`
   arena reservation was the plausible failure (16 KiB pages, no overcommit accounting to opt out
   of); measured first, macOS returns a mapping at `0x70_0000_0000`. What remains of M2 is the
   real content: the page-size inversion, `MADV_FREE_REUSABLE`, and the guard-page arithmetic.

3. **Abort stubs that name their milestone are worth the few bytes.** Every unimplemented Darwin
   wrapper prints `goish: syscall::Socket is not implemented on darwin/arm64 yet (M9)` and exits
   2, rather than `unimplemented!()`. Finding 1 above is a *direct read-off* of those messages —
   `unimplemented!()` would have given a panic location and no ordering signal at all. Keep the
   pattern for every future target.

4. **`svc #0x80` works on macOS/arm64 and is still the wrong answer.** Measured before deciding:
   a bare `svc` with `0x2000004` in x16 wrote to fd 1 and returned 14. Rejected because it buys
   exactly one milestone — from M3 on, every primitive the port needs (`pthread_create`,
   `pthread_cond_timedwait_relative_np`, `sysctlbyname`, `arc4random_buf`, `dladdr`,
   `getsectiondata`) is a libSystem function with no syscall behind it. Record the measurement so
   it is not re-litigated.

5. **The constant tables must be generated, not written.** `zerrors_darwin_arm64.rs` and
   `ztypes_darwin_arm64.rs` came from compiling a C program against `$(xcrun --show-sdk-path)`
   and printing the values and `offsetof`/`sizeof`. This is the half of the port rustc cannot
   check, and the divergences are not marginal: SIGURG 23→16 (**goish's own preemption signal**),
   SIGUSR1 10→30, EAGAIN 11→35, ENOSYS 38→78, SOL_SOCKET 1→0xffff, AT_FDCWD -100→-2,
   SA_ONSTACK 0x08000000→1. Linux-only constants are `POISON` (`grep POISON` is the inventory)
   rather than a plausible number.

6. **Two constants had to change *type*, and both were resolvable without touching callers.**
   `S_IF*` are `u16` here because Darwin's `mode_t` is 16-bit and `st_mode` sits at offset 4 with
   `st_nlink` at 6 — there is no room to widen it (Go makes the same split). The termios flag
   words are `u64` because `tcflag_t` is `unsigned long`. Typing the constants to match keeps
   `st.st_mode & S_IFMT` and `termios.Iflag &= !IGNBRK` compiling unchanged on every target.
   `net/parse.rs`'s two `SockaddrIn { .. }` literals became `SockaddrIn::ipv4_host(addr, port)`:
   a BSD sockaddr literal **cannot** be written portably, since `sin_family` is a `u8` at offset 1
   behind a `sin_len` byte. Constructors are the portable surface for any `#[repr(C)]` type whose
   layout is per-OS.

7. **`#[link_section]` on Mach-O needs the attributes, not just the segment pair.**
   `"__TEXT,__goish_rt_text"` links but makes ld64 treat it as data, warning that its symbols
   carry unwind information outside a code section. The correct spelling is
   `"__TEXT,__goish_rt_text,regular,pure_instructions"`. A runtime-code section the linker does
   not believe is code is the wrong footing for the M8 PC-range check that will read it.

**Files added.** Following `_GOOS_GOARCH` throughout:

| Area | linux/amd64 | linux/arm64 | darwin/arm64 |
|---|---|---|---|
| raw system interface | `sys/sys_linux_amd64.rs` | `sys/sys_linux_arm64.rs` | `sys/sys_darwin_arm64.rs` (libSystem + 3 return adapters) |
| Go-shaped wrappers | `syscall/syscall_linux.rs` | ← same | `syscall/syscall_darwin.rs` |
| constants | `syscall/zsysnum_linux_amd64.rs` | `zsysnum_linux_arm64.rs` | `syscall/zerrors_darwin_arm64.rs` (no `zsysnum` — libSystem has no numbers) |
| struct layouts | in `syscall_linux.rs` | ← same | `syscall/ztypes_darwin_arm64.rs` |
| thread pointer | `sched/tls/tls_linux_amd64.rs` | `tls_linux_arm64.rs` | `tls_darwin_arm64.rs` (a pthread TSD slot, read via `TPIDRRO_EL0` — M4a) |
| cycle counter | `cputicks/cputicks_amd64.rs` | `cputicks_linux_arm64.rs` | `cputicks_darwin_arm64.rs` (`mach_absolute_time`) |
| boot | `runtime/mod.rs` `__goish_rt0` | ← same | `runtime/rt0_darwin.rs` (4 steps, not 15) |
| entry | `runtime/entry.rs` `_start` | ← same | `runtime/entry.rs` — a C `main`, not a stub |

**The file-move hazard, resolved and needing maintainer confirmation.** Splitting
`syscall/mod.rs` into a dispatcher plus `syscall_linux.rs` moved 2033 grandfathered lines to a
path with no baseline entry, which hard-fails `port_lint.py`'s "a file absent from the baseline
must be clean" invariant. `lint_baseline.json`'s single key was renamed in place — a one-line
diff, counts conserved exactly (`GOISH005: 70, GOISH014: 115, GOISH015: 1, GOISH016: 1,
GOISH023: 112`, total 12674 unchanged). **This is unverified**: `goishlint` is closed source and
in neither an agent's environment nor CI, so the maintainer should re-run `port_lint.py --update`
and confirm the per-rule counts did not move. The four `#[path]` attribute lines added to
`syscall_linux.rs` are the only content change and are the only plausible source of drift.

**Tooling, checked rather than assumed.** `port_coverage.py` globs directories rather than
walking the module tree, so the files reachable only through `#[path]` stay visible: the
`syscall` scope reports 86/634 = 13.6% and 9 `.rs` files both before and after, byte-identical.
`anchor_check.py src` reports exactly the same census before and after (3384 anchors, 2259 ok,
803 RANGE_WRONG, 64 RANGE_FAT, 207 END_SHORT, 31 NOT_FOUND, 20 MISSING_FILE, 1806 BARE) — the
new files introduce zero findings, and the 803 wrong ranges are pre-existing drift from running
against the local Go 1.26.4 rather than the pinned 1.25.5 SDK. Note the trap the script's own
header warns about: with `GOROOT` unset every anchor reports `MISSING_FILE`, which reads as a
catastrophe and is a missing environment variable.

**What M1 does not do here.** The full skip list is in `runtime/rt0_darwin.rs`. The two that
produce no error at all, and so are the easiest to trip over:

- **`__run_pkg_inits` is a no-op** — every `goish::import!` port `init()` silently does not run
  (M10). Missing initialisation, not a link failure.
- **`current_g()` is `None` throughout**, so any blocking primitive fatals rather than parking
  (M5).

---

### M4a on darwin/arm64 — main-thread TLS, landed 2026-09-23

`current_m()` works on the main thread. `make run-darwin` runs **63 examples natively, 63 pass**
(the 17 from M1 plus a 46-example cross-section). Over the 487 `_smoke` examples that do not use
`goish::import!` and were not already on the allowlist, **272 now pass**.

**What landed.** `sched/tls/tls_darwin_arm64.rs` is Go's scheme, not a `pthread_getspecific`
wrapper: `tlsinit` (`runtime/sys_darwin_arm64.go`) allocates a key, writes a magic value through
`pthread_setspecific`, and scans the TSD array at `TPIDRRO_EL0 & ~7` to learn the key's byte
offset; `load_g`/`save_g` (`runtime/tls_arm64.s`) then read and write that slot directly. goish's
thread pointer is the slot's *contents* — `&MStorage.tls_self`, the value `fs`/`TPIDR_EL0` hold
on Linux — so `current_m`, `acquirem` and `locks_inc::<OFF>` port unchanged. `setup_main_tls`
calls `tls::init()` first on this target; `setup_main_g0` takes its bounds from
`pthread_get_stackaddr_np`/`_stacksize_np` instead of `/proc/self/maps`; `MStorage` gains a
macOS-only `pthread` field (the `pthread_t` M6 and M8 signal through); `Gettid` and `Sigaltstack`
are real.

**Four findings.**

1. **The plan's M4 row said "ship `pthread_getspecific` first", and that was the wrong order.**
   Not for speed: the direct read is the only form `acquirem`/`releasem` can eventually take as
   one `asm!` block inside `goish_rt_text` (`mrs; and; ldr; ldr; ldadd`) — which is what M8's
   SIGURG PC filter needs to protect their window — and a `pthread_getspecific` call could never
   sit inside that block. **The block does not exist yet**: measured with `objdump` on a debug
   `defer_smoke`, `acquirem` reaches `locks_inc` by `bl` into ordinary `__text`, on linux/arm64
   too. amd64 is immune (one `fs`-relative instruction is correct anywhere); arm64 is not, and
   M8 must close it — see its row. The library call is used exactly once, in `init`, to
   cross-check the direct read against it. An unset offset aborts
   loudly rather than reading TSD slot 0, which holds the thread's `pthread_t` and would
   dereference to plausible garbage instead of faulting.

2. **libpthread's main-thread bounds are right on this macOS, and the argv cap still matters.**
   Measured: `top=0x16d988000`, `size=0x7fc000` (8 MiB less one 16 KiB page), `sp` and `argv`
   both inside. `argv` sits 0x1808 below the top, so the Linux cap (`g0` stops at `argv − 8`)
   applies unchanged and is load-bearing here too — without it M5's first `mcall` would run
   scheduler frames over the environment block, exactly the Linux `exec::LookPath` bug.
   `main_stack_bounds` still checks `sp` is inside rather than trusting the numbers.

3. **Fixing an abort can turn it into a hang, and did.** With `current_m()` working, `go!` no
   longer aborted — it queued a G that nothing on this target can run (no `gogo` until M5), and
   callers spinning on `Gosched()` (a no-op off-goroutine) hung: 59 of the probe's examples
   timed out, every `http_*` server test and the `grow_*` family among them. **One exited 0:
   `io_pipe_smoke` runs all its checks inside `go!`, so it "passed" having checked nothing.**
   `scheduler::enqueue_runnable` now aborts naming M5 on `aarch64`, restoring finding 3 of M1 —
   all 60 now fail loudly. M5 deletes the guard. The general rule: **when a milestone removes a
   loud abort, re-probe for what was relying on it**, and treat exit 0 as a claim to check.

4. **The next wall is M3, not M5.** By count over the remaining 215: `ClockGettime` 61 and
   `SchedGetaffinity` 15 (M3), `go!` 60 (M5), `Socket` 24 (M9), raw `syscallN` call sites 19,
   the M2 file surface ~20. `aes_smoke`, `asn1_smoke` and `atomic_value_smoke` — named by M1 as
   stopping at `current_m()` — now stop at `ClockGettime`. M3 is also the smallest milestone left:
   `clock_gettime`, `nanosleep`, `arc4random_buf` and `sysctlbyname` are single libSystem calls.

**Not done in M4a, and why.** Worker Ms via `pthread_create`, and `start_sysmon`: both are
threads with nothing to run before `gogo`, so they land with M5. One trap waiting there — Linux
workers see `TLS_READY` from their first instruction because `CLONE_SETTLS` plants the thread
pointer atomically with the clone; `pthread_create` has no equivalent, so the M5 start routine
must call `tls::set_base` before anything takes a `SpinLock`.

**Gates.** darwin/arm64: native, 63/63. linux/amd64 and linux/arm64: **compile-and-link only**
(`hello`, `defer_smoke`, `chan_unbuffered`, `sched_swap` via `scripts/cross_lld.py`) — the docker
CLI colima needs was not installed on the host, so neither ran. The shared-code changes are a
pure extract-function in `setup_main_g0` and an `if cfg!(target_arch = "aarch64")` that
compiles away on x86_64, but that is argument, not measurement; re-run `make run-arm64` and the
amd64 smoke before relying on it. `goishlint` did not run either (closed source). `anchor_check.py src` (GOROOT on the local Go
1.26.4) reports M1's census unchanged — 2259 ok, 803 RANGE_WRONG, 64 RANGE_FAT, 207 END_SHORT,
31 NOT_FOUND, 20 MISSING_FILE, 1806 BARE — with no finding in any file M4a touched.

---

### M3 on darwin/arm64 — time, identity, entropy, CPU count, landed 2026-09-23

Real now: `ClockGettime`, `Nanosleep`, `Getpid`/`Getppid`, `Getuid`/`Geteuid`/`Getgid`/`Getegid`,
`Getgroups`, `Uname`, `Kill`, `Getrandom` (over `arc4random_buf`, Go's darwin `readRandom`), and
`num_cpus` (over `sysctl({CTL_HW, HW_NCPU})`, Go's darwin `getCPUCount` — `SchedGetaffinity`
stays an abort, since Darwin has no affinity mask to fake). `rand::init` runs in the Darwin boot.
`make run-darwin`: **74/74**. Checked directly against the host: `Nanosleep(200ms)` then
`time.Since` reads 204–210 ms; `Unix()` matches `date +%s`; `NumCPU` = `hw.ncpu` = 12.

**Three findings.**

1. **Darwin's `CLOCK_MONOTONIC` is not Linux's, and passing it through would have been wrong
   silently.** It counts time asleep: measured **~463,882 s (5.4 days) ahead** of
   `CLOCK_UPTIME_RAW` on a laptop that had slept. Go's `nanotime` does not count sleep on either
   OS — darwin's `nanotime1` reads `mach_absolute_time` scaled by the timebase. `CLOCK_UPTIME_RAW`
   is exactly that clock with the scaling applied (measured within 166 ns of the hand
   conversion — the generated table's comment, which said "without the unit conversion", was
   wrong and is fixed). `runtime::sysmon::NANOTIME_CLOCK` names the right id per OS, and both
   monotonic readers (`monotonic_ns`, `time::Now`) use it; `ClockGettime` itself stays a truthful
   wrapper over Darwin's ids.

2. **"numer == denom == 1 on Apple Silicon" was wrong.** Go's comment says it is *common*; the
   port notes had upgraded that to a fact about this hardware. Measured: **125/3** — a 24 MHz
   counter, 41.67 ns per tick. Nothing read ticks as nanoseconds (`cputicks` wants seed bits
   only), so no bug shipped, but the next person to reach for `mach_absolute_time` for a duration
   would have been off by ~42×. Both comments are corrected.

3. **M5 is now the wall, by a wide margin.** Of the 80 examples that stopped at an M3 wrapper
   after M4a, 11 pass, **52 now stop at `go!` (M5)**, 13 at `runtime.Callers` (M6 —
   `symbolize::init` does not run, so `testing` panics "zero callers found"), 1 at M2.
   `aes_smoke`, `asn1_smoke` and `atomic_value_smoke` are among the 52. Across all 215 examples
   still failing: M5 132, M9 sockets 24, M6 15+2, M2 file surface 20.

Not a bug, recorded so nobody chases it: `testing_benchmark_run_smoke` timed out in the 20 s
probe; run to completion it is 8/8 in 19.7 s — CPU-bound benchmark ramping in a debug build.

**Gates.** darwin/arm64 native, 74/74. linux/amd64 and linux/arm64: compile and link only (docker
still unavailable). The one Linux-visible change is `time::Now` reading
`NANOTIME_CLOCK` — `CLOCK_MONOTONIC` on Linux, the same id as before.

---

### M2, M6–M10 on darwin/arm64 — the whole suite, landed 2026-09-23

The allowlist is gone: `make e2e TARGET=aarch64-apple-darwin` builds and runs every declared
example, the same task as Linux, and both workflows run it as `e2e (macos-latest)` /
`e2e-race (macos-latest)`. The decisions that differ from the ladder above:

1. **M7 is `__ulock_wait2`/`__ulock_wake`, not `pthread_cond`.** `syscall::Futex` keeps its
   Linux contract over the kernel's address-keyed wait queue, so `note.rs` and sysmon are
   unchanged. The deciding fact: `sysmon::wake` runs in a signal handler, and a ulock wake is
   one async-signal-safe syscall where `pthread_cond_signal` is not. Workers and sysmon are
   pthreads on caller-owned stacks (`sched::start_os_thread`), with a trampoline that plants
   the TSD thread pointer before anything takes a SpinLock.
2. **M9 translates the epoll surface onto kqueue** rather than giving netpoll a second
   backend: EV_CLEAR for EPOLLET, read-side EOF wakes writers (Go's `netpoll_kqueue.go`), and
   the break is `EVFILT_USER`/`NOTE_TRIGGER`, relayed when a non-blocking sweep consumes it.
   Socket type bits are applied with `fcntl` plus `SO_NOSIGPIPE`.
3. **M10 uses `__DATA,__goish_init`** walked between ld64's `section$start`/`section$end`
   symbols — the same mechanism now gives `rt_section` real bounds, which M8 needed.
4. **M6 symbolization is not degraded after all.** Names come from the loaded image's
   `LC_SYMTAB`; `file:line` from the dSYM (`split-debuginfo=packed`,
   `debuginfo=line-tables-only` for this target only, ~8 MB of DWARF per example). The debug
   map was measured unusable: rustc deletes the example's own objects after linking, and CI
   builds non-incrementally.
5. **M8 resumes through a second signal.** arm64 has no memory-indirect branch and goish
   interrupts arbitrary Rust, so once every register is restored none is free to jump through
   (Go spends its reserved R27). The trampoline saves everything, yields, and ends in `brk`;
   the SIGTRAP handler writes the saved file into the signal context and sigreturn restores it
   exactly. `locks_inc`/`locks_dec` became an inline `ldaddal` so `acquirem`/`releasem` never
   leave `goish_rt_text`. linux/arm64 still has neither.
6. **The Linux numbers were in more places than `syscall`.** `os`'s `O_*` flags, net's errno
   and `F_DUPFD_CLOEXEC` literals, `os::Root`'s ELOOP, the signal-name table, and the errno
   message table were all Linux values; each is now read from `syscall` per target, the tables
   generated from Go's `zerrors_darwin_arm64.go`. The resolver also never read `/etc/hosts`.
7. **Ref smokes get Go's darwin output, never a looser assertion.** Where the platform really
   differs (APFS directory sizes, `/private/tmp`, ETIMEDOUT's text, Directory Services user
   lookup, BSD socket-option readback), the darwin table is generated by running the Go
   reference on darwin/arm64. Examples of Linux-only kernel interfaces Go itself does not offer
   on darwin (inotify/fanotify, `syscall.Openat`, amd64 signal frames and vector state) print
   SKIP.

---

## Verified facts that shape the plan

| Claim | Verdict | Source |
|---|---|---|
| Go calls libSystem on Darwin, not raw syscalls | ✅ | `runtime/sys_darwin_arm64.s:490-566` (`libcCallInfo` trampolines) |
| Threads via `pthread_create` | ✅ | `runtime/os_darwin.go:233-258` |
| Per-thread signals via `pthread_kill` | ✅ | `runtime/os_darwin.go:489-491` (`signalM`) |
| Futex replacement is `pthread_cond_timedwait_relative_np` | ✅ | `runtime/os_darwin.go:36-71` (`semacreate`/`semasleep`) |
| `physPageSize` is queried, not pinned | ✅ | `runtime/os_darwin.go:148-153` (`osinit` → `getPageSize()`) |
| `MADV_DONTNEED` is not the Darwin release path | ✅ | `runtime/mem_darwin.go:23-34` uses `_MADV_FREE_REUSABLE` (0x7) / `_MADV_FREE_REUSE` |
| Reservations are `PROT_NONE` mmap, not `MAP_NORESERVE` | ✅ | `runtime/mem_darwin.go:57-63` (`sysReserveOS`) |
| kqueue wake is `EVFILT_USER` + `NOTE_TRIGGER` | ✅ | `runtime/netpoll_kqueue_event.go:18,40-41` (a pipe variant exists for other BSDs) |
| **x18 is forbidden, not merely reserved** | ✅ | `runtime/mkpreempt.go:573` — *"R18 is not used, skip"*; no `R18` anywhere in `preempt_arm64.s` |
| ~~macOS arm64 has a 47-bit VA, geometry must be re-derived~~ | ❌ **WRONG** | `runtime/malloc.go:213` — `heapAddrBits` is **48** on darwin/arm64; only **ios**/arm64 drops to 40. `malloc.go:314`: `arenaBaseOffset = 0` on arm64. **`mheap/consts.rs` ports unchanged.** |
| ~~`TPIDRRO_EL0` is read-only, so reads must go through TSD calls~~ | ❌ **WRONG** | `runtime/tls_arm64.h:22-25` + `tls_arm64.s:21-26` — Go *reads* `MRS TPIDRRO_EL0`, masks the low 3 bits ("Darwin sometimes returns unaligned pointers"), and indexes by a `pthread_key`-derived offset. Read-only applies to the *slot allocation*, not the read. |
| ~~`posix_spawn` is the correct Darwin `os/exec` answer~~ | ❌ **WRONG** | `syscall/exec_libc2.go:55,85` — Go uses `libc_fork` + exec on Darwin, same shape as Linux |

---

## The M1 blocker found during design review

**Mach-O has neither `.init_array` nor `__start_`/`__stop_` section-bound symbols.**

- `src/lib.rs:359-377` — `__run_pkg_inits()` walks `extern { static __init_array_start; static
  __init_array_end; }`, ELF linker-provided symbols, over `#[link_section = ".init_array"]` slots.
- `src/runtime/rt_section.rs:39-41` — `__start_goish_rt_text` / `__stop_goish_rt_text`, relying on
  the SysV rule that a section named as a valid C identifier gets auto-generated bound symbols.

ld64 generates no such symbols, and `#[link_section = "goish_rt_text"]` is not a well-formed
Mach-O section spec (Mach-O requires `"__SEGMENT,__section"`). There are **53 `link_section` sites
across 9 files** — `scheduler.rs` ×22, `gochan.rs` ×10, `spin.rs` ×8, `sched/p.rs` ×5,
`rt_section.rs` ×4, `goish-macros` ×3, `lib.rs` ×2, `sched/m.rs` ×2, `preempt.rs` ×1 — every one a
link-time failure.

This lands **in M1**, because `#[goish::main]` unconditionally injects `::goish::__run_pkg_inits()`
into every user main. M1's answer: a `#[cfg(target_os = "macos")]` no-op `__run_pkg_inits`, cfg'd
section names (`"__TEXT,__goish_rt_text"`), and `is_in_runtime()` returning `false` on Darwin —
safe, because M1 installs no signal handlers. Real section bounds come later via
`getsectiondata(&_mh_execute_header, …)`.

**Ordering trap for M10:** do *not* map `goish::import!` onto `__DATA,__mod_init_func`. dyld runs
those before `main` — before `goish::init()` and before the allocator is up, so a port `init()`
that allocates would fault. Keep a private section and walk it explicitly.

---

## Milestone 0 — cfg scaffolding (lands entirely on the x86 path)

**Governing principle: separate files over inline `#[cfg]` arms.** A cfg'd-out file still exists
on disk, so `anchor_check.py`, `port_lint.py` and `port_coverage.py` — all source-parsing, not
compiling — see arm64/Darwin code from a Linux host and vice versa. Go solved this with
`_GOOS_GOARCH.go` suffixes, and `src/internal/syscall/unix/sysnum_linux_amd64.rs` shows the repo
has already adopted the convention.

**Prerequisite: Go 1.25.5.** `anchor_check.py` accepts an `sdk <ver>` spec; the local toolchain is
1.26.4 and the pinned SDK is absent.

**`goishlint` is closed source and is the maintainer's to run.** `port_lint.py:binary()` wants
`$GOISHLINT` or `../goishlint/target/release/goishlint`; neither exists in an agent's environment,
and `provenance.yml:22-23` states outright that the linter "is a separate binary and is not in this
workflow" — so CI does not run it either. Consequence for the file-move protocol below: **the
ratchet cannot be the gate an implementer checks.** Replace it with an invariant that is
independently verifiable without the binary — every move lands as a commit `git diff -M --stat`
reports as *pure renames, zero content lines changed* — and leave `port_lint.py --update` to the
maintainer as a separate, reviewable step.

- **`src/sys/` facade** — the *only* place raw `syscall`/`svc` instructions or `extern "C"`
  libSystem declarations may appear. `sys_linux_amd64.rs` (the `syscall0..6` stubs moved verbatim
  from `syscall/mod.rs:194-270`), `sys_darwin_arm64.rs`, and `consts_*` carrying `PHYS_PAGE_SIZE`.
- **Keep goish's internal ABI as negative-errno.** `sys::write()` returns `n` or `-EAGAIN`. On
  Linux that is the unchanged kernel return. Darwin needs **three** adapters, not one:
  `errno_ret` (`write`/`read`/`open` → `-1` + `__error()`), `direct_ret` (`pthread_*` → positive
  errno as the return value, errno untouched), `ptr_ret` (`mmap` → `MAP_FAILED`). Read `__error()`
  in the same `unsafe` block with no intervening libSystem call. This one decision preserves all
  ~96 wrappers in `src/syscall/mod.rs` and every caller; only the numeric `Errno` table is
  per-OS — and those numbers genuinely differ (`EAGAIN` 35 vs 11), so audit literal `Errno(`
  values across `src/os`, `src/net`, `src/io`.
- **Split `src/syscall/mod.rs`** (2137 lines) the way Go's own `syscall` package is split:
  `syscall_linux.rs`, `zerrors_linux_amd64.rs`, `ztypes_linux_amd64.rs`,
  `zsysnum_linux_amd64.rs`, and Darwin siblings. Anchors: `syscall/syscall_darwin.go`,
  `zerrors_darwin_arm64.go`, `ztypes_darwin_arm64.go`, `zsyscall_darwin_arm64.go`.
- **`Gobuf` → parallel per-arch structs**, not renamed fields. Outside `sched/gobuf.rs` only
  **six** sites touch its fields and all six touch `.rsp` — add `sp()`/`set_sp()` accessors and
  convert them. A shared struct would be a lie: amd64 stores 7 GPRs + pc (SysV makes xmm
  caller-saved, so no FP state); arm64 needs x19–x28 (**not x18**), x29, x30, sp, pc **and
  d8–d15** — 22 slots. Anchors: `runtime/asm_arm64.s`, `runtime/stubs_arm64.go`.
- **Signal context → accessor functions, not `REG_*` indices.** `segv.rs:27` indexes
  `(*ctx).uc_mcontext.gregs[REG_RIP]`; on Darwin `uc_mcontext` is a **pointer**, so that form
  cannot survive. New `src/runtime/sigctx/` with `pc/set_pc/sp/set_sp/fp/set_fp` (+ arm64 `lr`)
  returning by value. Bonus: the FP-chain walk ports **unchanged in structure** — Apple's ABI
  mandates a frame pointer and the arm64 frame record is `[x29]`/`[x29+8]`, identical in shape to
  the x86 `[rbp]`/`[rbp+8]` chain. Consolidate the three duplicated walkers (`segv.rs:289-324`,
  `runtime/mod.rs:296-308`, `sched/m.rs:341-364`) into one while there.
- **The proc-macro trap, solved properly.** A proc macro runs on the *host*, so `cfg!()` inside
  `goish-macros` reads the wrong values. Rather than emitting `#[cfg]`-gated alternatives, strip
  arch knowledge from the macro **entirely**: `goish-macros/src/lib.rs:48-58` emits
  `::goish::__goish_entry!();` and the per-target bodies live in normal `src/` files behind a
  `macro_rules!`. cfg is then evaluated by rustc at target-compile time (the only correct time),
  `goish-macros` never needs a target dimension, and the arch code sits where the lint and anchor
  tooling can see it.
- **`GOOS`/`GOARCH`** (`runtime/mod.rs:54-59`) become cfg-derived; anchor to
  `internal/goos/goos.go` / `internal/goarch/goarch.go`. Fix the two examples that assert
  `"amd64"` (`runtime_goos_goarch_smoke.rs`, `runtime_stubs_smoke.rs`) to derive from `cfg!`.
- **Fix two latent bugs that are wrong on Linux today**: `src/net/dnsclient.rs:60` hardcodes raw
  syscall `228` instead of the existing `SYS_CLOCK_GETTIME`; `src/internal/syscall/unix/mod.rs:5`
  declares `mod sysnum_linux_amd64;` with no cfg gate.

**Done when:** `make e2e` and `make lint` on x86_64-linux are byte-identical to before.

### The 595 examples — an allowlist, not source edits

Counted 2026-08-21: **595** `examples/*.rs` (596 including one in a subdirectory) and **418**
`[[example]]` blocks in `Cargo.toml`, none of which uses `required-features` today. Cargo has **no cfg-conditional `required-features`**, so a feature table cannot be driven by
target tuple; that road is closed. Editing 418 `[[example]]` blocks is churn with no payoff.

Instead: `scripts/darwin_examples.txt`, a newline-delimited allowlist, with `make build-darwin`
expanding it into explicit `--example` flags. `--examples` is never used on Darwin. The
allowlist starts at one line (`hello`) and grows monotonically — **it is the per-milestone
acceptance artifact and the CI job definition**, a ratchet in the same spirit as
`lint_baseline.json`. `examples/sigaltstack_offline_proof.rs` (x86 inline asm) simply never
enters the list until it has an arm64 counterpart.

---

## Milestone 1 — boot + hello world

**Target: `examples/hello.rs`.** 14 lines, allocation-free, calls `syscall::Write(STDOUT, …)`.
Its own header reads *"Milestone 1 smoke test … proves syscall + _start + rt0 + macro all work
end-to-end"* — it was goish's original milestone 1 on Linux and it is the right one here.
No threads, no scheduler, no netpoller, no signals.

**`.cargo/config.toml`** gains exactly one flag:
```toml
[target.aarch64-apple-darwin]
rustflags = ["-C", "force-frame-pointers=yes"]
```
Every bare-metal flag is dropped: `-nostartfiles` (no crt0 exists), `-nodefaultlibs` (we *want*
libSystem), `-static` (impossible), `--no-dynamic-linker` (ld64 rejects it),
`relocation-model=static` (PIE is mandatory). The existing `[build] target` pin stays — it exists
so those flags don't leak into `goish-macros`, and since the host tuple *is*
`aarch64-apple-darwin`, this block does leak; `force-frame-pointers` is harmless to a proc macro
and Apple's ABI mandates the frame pointer anyway. Darwin builds pass `--target` explicitly.

**Steps, in dependency order:**

1. `.cargo/config.toml` block — until `cargo build --target aarch64-apple-darwin` reaches a
   *compile* error rather than a config error.
2. `src/sys/` facade + `sys_linux_amd64.rs` (verbatim move). **Linux e2e must be identical.**
3. `src/sys/sys_darwin_arm64.rs`: `write`, `read`, `exit`, `mmap`, `munmap`, `mprotect`,
   `__error`, the three return adapters, `PHYS_PAGE_SIZE = 16384`.
4. The `src/syscall/` split — **standalone commit**, see the ratchet protocol below.
5. `syscall_darwin.rs` + `zerrors`/`ztypes`: just `Write`/`Read`/`Exit`/`Mmap`/`Munmap`/
   `Mprotect` and the errno table; everything else `unimplemented!()`.
6. `goish-macros/src/lib.rs:48-58` → `::goish::__goish_entry!();`. **This is the riskiest "no-op"
   in M1** — it touches every example on Linux. Its own commit, full `make e2e-full`.
7. `src/lib.rs` + `runtime/entry_linux_amd64.rs` (the moved `global_asm!`) + `entry_darwin.rs`
   (`#[no_mangle] extern "C" fn main(argc, argv, envp, apple) -> i32`).
8. `src/lib.rs:359-377` — `#[cfg(target_os = "macos")]` no-op `__run_pkg_inits`.
9. `rt_section.rs` + the 8 `link_section` files — cfg the section name; `is_in_runtime()` →
   `false` on Darwin.
10. `runtime/mod.rs:615` — `__goish_rt0` grows an `envp` parameter and its body splits into
    stages. The Darwin arm runs **only**: `args::__set` → `flags::init_from_envp` → dlmalloc heap
    bootstrap → `__goish_main()` → `sys::exit(0)`. Skipped: `setup_main_tls`, `rand::init`
    (rdtsc), `mheap_init`, `mcentral_init`, `register_m_storage`, `setup_main_g0`,
    `bootstrap_ps`, `bootstrap_workers`, `start_sysmon`, the SIGPIPE `RtSigaction`,
    `preempt::install`, `symbolize::init`.
11. `runtime/flags.rs:29` — split `init_from_argv` into `init_from_argv` + `init_from_envp(envp)`.
    **envp arrives as `main`'s 3rd argument on Darwin**; the `envp = argv + argc + 1` ELF-stack
    walk is invalid there. Linux keeps computing it and calls the same `init_from_envp`.
12. ~~`runtime/heap.rs` — the pre-mheap dlmalloc `#[global_allocator]` path~~ — **void**.
    Written when `heap.rs` still had a dlmalloc tier; it does not, and `mheap_init` +
    `mcentral_init` need nothing but `Mmap`. Both run in M1. See finding 2 above.
13. `runtime/mod.rs:899` `#[panic_handler]` — Darwin arm skips the TLS-dependent `panic_recover`
    check; write via `sys::write(2, …)` and `sys::exit(2)`.
14. `scripts/darwin_examples.txt` (one line: `hello`) + `make build-darwin`.

**Done when all four hold:** `hello` prints `Hello, World!` and exits 0; `file` reports Mach-O
arm64, `otool -L` shows `libSystem.B.dylib`, `otool -l` shows a valid `LC_MAIN` entryoff;
`codesign -v` passes (ld64's ad-hoc signature — never add a `strip`/`objcopy` step, it would
invalidate it and the binary would not execute at all); and `make e2e` on x86_64-linux is
unchanged with zero new lint findings.

Watch: `main` must not be `-> !` (dyld expects a normal `main`) — call `sys::exit(0)` explicitly
rather than falling off the end. And Mach-O symbols carry a leading underscore
(`___goish_rt0`), while `.type`/`.size`/ELF `.section` directives hard-error and `int3` becomes
`brk #0` — prefer `sym` operands over literal symbol names to avoid the whole class.

---

## Milestone ladder

Each milestone ends with its examples added to the allowlist, green on Darwin, and **Linux e2e
unchanged**.

| M | Goal | Main risk | Go anchors |
|---|---|---|---|
| **2 — Memory & 16 KiB pages** | ~~mheap + mcentral online~~ (**done in M1** — see finding 2 above; dlmalloc is gone, so both need only `Mmap`). What is left: `madvise` semantics, the page-size inversion, guard-page arithmetic | The kernel/allocator page ordering **inverts**: Linux has kernel 4 KiB < Go page 8 KiB, Darwin has kernel 16 KiB > Go page 8 KiB, so one Go page is *half* a kernel page and `madvise`/`mprotect` cannot act on it. Introduce a `PHYS_PAGE_SIZE` distinct from `PAGE_SHIFT=13` (keep the latter — Go uses 8 KiB everywhere) and scavenge only in multiples of it, collapsing the three hardcoded `4096` copies (`sched/stack.rs:144`, `segv.rs:31`, `grow.rs:344`). `MADV_DONTNEED` at `stack.rs:386` — the mechanism the million-goroutine demo rests on — neither releases nor zeroes on Darwin. `MAP_NORESERVE` doesn't exist. Second-order: a 64 KiB goroutine stack now loses 16 KiB (25%) to its guard page. **`mheap/consts.rs` needs no change** — `heapAddrBits` is 48 and `arenaBaseOffset` is 0 on arm64. | `runtime/malloc.go`, `runtime/mem_darwin.go` |
| **3 — Time, entropy, CPU count** (**done 2026-09-23** — see above) | `time.Now`, `nanotime`, PRNG seed, `num_cpus` | `rdtsc` (`runtime/rand.rs:31-44`) → `mrs cntvct_el0` or `mach_absolute_time`; `Getrandom` → `arc4random_buf`; `SchedGetaffinity` → `sysctlbyname("hw.logicalcpu")` | `runtime/sys_darwin.go`, `runtime/os_darwin.go` (`getncpu`, `readRandom`) |
| **4 — Threads + TLS** | N worker Ms; `current_m()` works | `acquirem`/`releasem` (`sched/m.rs:285-322`) are deliberately `lock add`/`lock xadd` on `fs:[…]` so the RMW cannot land on the wrong M after a SIGURG-induced migration; TSD cannot reproduce that single-instruction property and the invariant needs re-establishing. Ship `pthread_getspecific` first; the 3-instruction `MRS TPIDRRO_EL0` fast path is a separate, deferrable step whose entry condition is *read `tls_arm64.s` first*. **Store each M's `pthread_t` in `MStorage`** — M6 and M8 both need it. `setup_main_g0` gets *simpler*: `pthread_get_stackaddr_np` replaces the `/proc/self/maps` parse. | `runtime/os_darwin.go:233-258`, `runtime/tls_arm64.s:21-26` |
| **5 — Context switch (AAPCS64)** | goroutines run; `go!` works | Return address is in **x30, not on the stack**, so `swap_context`'s "`ret` pops PC off the target stack" design and `gogo`'s red-zone-avoiding `jmp` both need restructuring, not transliterating. **`d8`–`d15` are callee-saved** — SysV has no equivalent, so this is strictly more work than the amd64 version, and omitting them corrupts float state silently. **Never touch x18.** No red zone. | `runtime/asm_arm64.s` (`gogo`, `mcall`, `systemstack`), `runtime/stubs_arm64.go` |
| **6 — Signals: SIGSEGV + backtrace** (**done 2026-09-24** — Darwin raises SIGBUS, not SIGSEGV, for a guard-page hit, so both are caught; `file:line` comes from the dSYM after all, see `symbolize/macho.rs`) | crash → backtrace, guard-page detection | `uc_mcontext` is a pointer; BSD `sigaction` has **no `sa_restorer`**, so `SigreturnTrampoline` (which hardcodes `rt_sigreturn=15`) is Linux-only. **DWARF is not in the linked Mach-O image** — it lives in `.o` files and `.dSYM` bundles, so `runtime/symbolize/` (which mmaps `/proc/self/exe` and parses ELF) degrades to `dladdr()`: symbol name, no `file:line`. A permanent fidelity regression on Darwin; document rather than build a dSYM parser. | `runtime/signal_arm64.go`, `runtime/defs_darwin_arm64.go` |
| **7 — Futex → pthread cond** | M parking/waking; `note.rs`; `sync` | Must land with or after M4 — it adds `pthread_mutex_t`/`pthread_cond_t` to `MStorage`, whose offset-0 `tls_self` invariant is load-bearing for asm. All 10 futex consumers. | `runtime/os_darwin.go:31-92` |
| **8 — Async preemption** | SIGURG preemption; sysmon retakes | Rewrite `preempt.rs:349-521`: `stp`/`ldp` instead of `fxsave64`, NZCV/FPSR via `mrs`/`msr` instead of `pushfq`/`popfq`, no 128-byte red-zone skip, **x18 excluded**. `pthread_kill` replaces `Tgkill` (`sysmon.rs:408`). The `goish_rt_text` PC-range filter needs the Mach-O `getsectiondata` walk. **On both arm64 targets `acquirem`/`releasem` must first become one inline-asm RMW** (`mrs; [and; ldr;] ldr; ldadd`) — today they `bl` out of `goish_rt_text` into `locks_inc` in debug builds, so the filter cannot see the window (M4a finding 1). Re-derive `ASYNC_PREEMPT_STACK`. | `runtime/preempt_arm64.s`, `runtime/os_darwin.go:489` |
| **9 — kqueue netpoller** | `net`, TCP, HTTP examples | Wake is `EVFILT_USER` + `NOTE_TRIGGER`, **not** a self-pipe (Go uses the pipe variant only on other BSDs). No `accept4` → `accept` + `fcntl`. `EV_CLEAR` ≈ `EPOLLET` but `kevent` batches changes and events in one call. | `runtime/netpoll_kqueue.go`, `netpoll_kqueue_event.go` |
| **10 — Package init** | `goish::import!` on Darwin | `getsectiondata` bounds; **not** `__mod_init_func` (dyld runs it pre-allocator) | `runtime/proc.go` (`doInit`) |
| **11 — CPU features** | AES/PMULL/SHA/DIT detection | Perf-only — all crypto is scalar today, so nothing regresses. **Exception:** `crypto/subtle/dit.rs` is a hardcoded no-op standing in for Go's `DITSupported`, which is *true on arm64 with FEAT_DIT* — on this target that silently drops a timing guarantee Go provides. Also fix `xor_generic.rs:33 supportsUnaligned` and `tls/cipher_suites.rs:1164 hasAESGCMHardwareSupport`. | `internal/cpu/cpu_arm64_darwin.go` |
| **12 — Weak-memory audit** | scheduler/chan/allocator correct under non-TSO | x86 TSO has been hiding every sloppy `Ordering`, and **x86 CI gives literally zero signal** — this is not a milestone without the arm64 CI job. Priority: `runtime/lockfree_ring.rs`, sudog publication in `gochan.rs`, `runqput`/`runqget`/`runqsteal` in `sched/scheduler.rs`, `note.rs`. Grepping `Ordering::Relaxed` is a fine *method* but an unusable *gate*. | `runtime/proc.go` runq comments (they call out acquire/release specifically for arm64), `internal/runtime/atomic/atomic_arm64.go` |

---

## Build, CI and provenance tooling

- **`Makefile:59`** — add `--target $(TARGET)` to `build`; on Linux this is a no-op since the
  `[build]` pin already puts artifacts there, so it cannot regress. Add `build-darwin`/
  `e2e-darwin` reading the allowlist. **Done, and simpler than written:** there is no
  `e2e-darwin` — `make e2e TARGET=aarch64-apple-darwin` (and `e2e-full`) builds and runs the
  allowlist, via `E2E_ALLOWLIST` keyed on TARGET, so every platform runs the same tasks.
- **`scripts/e2e_runner.sh:30,80`** — take the allowlist as an input filter rather than globbing
  the examples directory. **Done** as `EXAMPLES_FILE=`; it cannot be a FILTER, since most
  allowlist entries are auto-discovered examples the runner's Cargo.toml scan never sees. The
  runner also resolves `timeout`/`gtimeout`, since macOS ships neither.
- **`scripts/port_coverage.py:38-42`** — `SKIP_FILE` excludes `_arm64.go` **and** `_darwin.go`.
  Do **not** just edit the regex: that makes the denominator jump and the headline coverage
  number drop overnight, becoming uninterpretable exactly when it is most needed. Make it a
  function of a `--goos`/`--goarch` pair defaulting to `linux/amd64` (preserving today's numbers)
  and report the two targets separately.
- **CI** — `e2e.yml:32` and `e2e-race.yml:45` stay on `ubuntu-latest` + x86_64; that is the green
  baseline and is non-negotiable. Add `e2e-darwin.yml` on `macos-latest` (Apple Silicon) running
  only the allowlist. M12's definition of done is `make e2e-full` (50 loops) green there.
  **Done as a matrix, not a new file:** `e2e.yml` and `e2e-race.yml` each run one job over
  `ubuntu-latest`/x86_64 and `macos-latest`/aarch64-apple-darwin, the same `make e2e` /
  `e2e-full` with only TARGET differing. The Linux entries keep their check names.
- **Anchors** — write them with file path and symbol, then let `anchor_check.py --fix` /
  `anchor_port.py` populate the line ranges. **Never hand-guess a range**: the checker resolves by
  symbol name and ignores the range, so a wrong range passes tier-2 silently (229 of 1802 were
  wrong when first measured — hence the `anchors` make target).
- **`lint_baseline.json` needs no per-target dimension**, because it is keyed by `(file, rule)`
  and cfg'd-out files still exist on disk. **Verify this before relying on it**: add a
  `#[cfg(target_os = "macos")]` file with a deliberate violation and check `port_lint.py --new`
  fires on Linux. If `goishlint` type-checks rather than parses, cfg'd-out files vanish from the
  scan and the ratchet silently becomes host-dependent.
- **README** — the scope statement, the static-linking claim, and every build/run command example
  (lines ~92, 108, 282, 328-331, 338, 354, 358, 427-428).

### The file-move hazard — the highest-risk process step

Splitting `syscall/mod.rs` creates new file paths. The old file carries thousands of
grandfathered findings; the new paths have **no baseline entry**, and `port_lint.py`'s core
invariant is that a file absent from the baseline must be clean. The split hard-fails the
ratchet. Same for `gobuf.rs` → `gobuf_amd64.rs`, `preempt.rs`'s mcontext block → `sigctx/`, and
the entry stub → `entry_linux_amd64.rs`.

**Mandatory protocol:** each move is a standalone commit changing only file paths — no logic
edits, not one. The gate an implementer can actually check is `git diff -M --stat` reporting the
commit as **pure renames with zero content lines changed**; anything else is a logic edit smuggled
inside a rename. `port_lint.py --update` and the conserved-per-rule-count review then follow as a
separate maintainer step (see the goishlint note in M0 — the binary is closed source and is in
neither an agent's environment nor CI). Do not let `--update` *be* the check: it always "works",
which is exactly why this is the step most likely to be defeated by a rushed implementer.

---

## Explicitly out of scope

- **Preserving the libc-free / static-binary property on Darwin.** Impossible.
- **In-process DWARF backtraces.** `dladdr()` symbol names only; no `file:line`. Permanent.
- **arm64 crypto assembly.** M11 delivers *detection*; the AES/SHA/PMULL/NEON kernels are a
  separate multi-quarter effort orthogonal to "does goish run". Portable Rust paths stay in use.
- **`os/exec` subprocesses.** Go *does* use `libc_fork` + exec on Darwin
  (`syscall/exec_libc2.go:55,85`), so this is translatable rather than a rewrite — but `pipe2`
  doesn't exist (`pipe` + `fcntl`) and fork-in-a-multithreaded-process rules are stricter.
  `examples/cmd_stdin_test.rs` and `cmd_stdout_pipe_test.rs` are **knowingly excluded** from the
  Darwin allowlist until this is taken on.
- **`goish::import!` on Darwin before M10.** Every example using it must stay off the allowlist —
  easy to miss, and it produces silently-missing initialization rather than a link error.
- **`x86_64-apple-darwin`** (Rosetta / Intel Macs) and any iOS target. Every Darwin `#[cfg]` in the tree is `all(target_os = "macos", target_arch = "aarch64")`, so an Intel build fails to resolve rather than silently taking an arm64 path.
- ~~**`aarch64-unknown-linux-gnu`.** Not the chosen target~~ — **in scope as of 2026-08-21**, and
  M1 has landed on it. See "The linux/aarch64 question" above.

---

## Verification

- **Every milestone, on x86_64-linux (regression gate):** `make e2e` + `make lint`. After
  anything touching M5, M8 or M12, `make e2e-full`. This can run locally (see Context) via the
  `rust-lld` shim + `docker run --platform linux/amd64` — but only as compile-and-smoke, and only
  over the allowlist, never `--examples` (~50 GiB). Run `e2e_runner.sh` itself *inside* the amd64
  container with the repo bind-mounted — verified to need no source change, given `ARTIFACTS`
  outside the mount and a `FILTER` matching what was built. (The alternative, wrapping each binary,
  would need a `RUNNER` hook at its three `"$bin"` execs, lines 158/162/164.)
- **M1:** the four criteria above (`hello` output, `file`/`otool`, `codesign -v`, Linux
  unchanged).
- **M2–M5:** `alloc_smoke`, `alloc_mheap`, `chan_unbuffered`, `chan_buffered`, `sched_swap`
  natively, added to the allowlist as they go green.
- **M8:** an arm64 counterpart to `sigaltstack_offline_proof`, `preempt_sysmon`, and a deliberate
  null-deref confirming the x29-chain backtrace.
- **M9:** `http_hello`, `conn_deadline_smoke`, `conn_drop_no_leak`.
- **M12:** `make e2e-full` (50 loops) across the full allowlist on the `macos-latest` runner.
  This is the only thing that will surface a weak-ordering bug.
- **Provenance, continuously:** `make lint` and `make anchors` with `GOROOT` on the Go 1.25.5 SDK.
- **`spawn_million`, once M2–M5 land:** the README's "~2 GiB virtual / ~2.4 GiB peak RSS" is
  4 KiB-page arithmetic and the sub-page 2 KiB stackpool is built on it. Re-measure at 16 KiB
  rather than re-quoting.
