# goish-v1 — top-level convenience targets.
#
# Most targets just shell out to scripts/ — keep this file thin.

CARGO     ?= cargo
TARGET    ?= x86_64-unknown-linux-gnu
PROFILE   ?= debug
# LOOPS empty = tiered mode (per-test loop counts; see e2e_runner.sh).
# LOOPS=N forces a uniform count for every example.
LOOPS     ?=
TIER1     ?= 1
TIER2     ?= 10
TIER3     ?= 50
TIMEOUT   ?= 15
FILTER    ?=
EXCLUDE   ?=
ARTIFACTS ?= scripts/.e2e-artifacts

EXAMPLES_DIR := target/$(TARGET)/$(PROFILE)/examples

SCOPE     ?= src

ARM64_TARGET    ?= aarch64-unknown-linux-gnu
ARM64_ALLOWLIST ?= scripts/linux_arm64_examples.txt

DARWIN_TARGET    ?= aarch64-apple-darwin

# `make e2e` / `e2e-full` are the same tasks on every platform, over
# every declared example; only TARGET differs:
#
#     make e2e                                  # x86_64 Linux
#     make e2e TARGET=aarch64-apple-darwin      # macOS, natively

# `cargo` on PATH is not necessarily the rustup shim, and only the rustup
# toolchain has the cross targets. A Homebrew rust installs to
# /opt/homebrew/bin, comes first on PATH, and ships ONLY the host std —
# so `cargo build --target <anything else>` fails with
#
#     error[E0463]: can't find crate for `core`
#     note: the <target> target may not be installed
#
# even though `rustup target list --installed` shows the target present.
# Both are the same rustc version, so `rustc -vV` cannot tell them apart;
# only `which -a cargo` can. Resolve through rustup for cross builds and
# leave $(CARGO) alone for the native path.
#
# RUSTC has to be set too, and that is the non-obvious half: `rustup
# which cargo` returns the real binary inside the toolchain, not the
# ~/.cargo/bin shim, and that binary still looks up `rustc` on PATH — so
# a rustup cargo happily drives a Homebrew rustc straight back into the
# same error. Pinning both is what makes this work from a bare `make`.
CARGO_CROSS ?= $(shell rustup which cargo 2>/dev/null || echo $(CARGO))

# Everything below is a no-op on a Linux host: $(CARGO) and the system cc
# already do the right thing, CROSS_ENV and *_LINKER stay empty, and the
# recipes expand exactly as they do in CI. Only a non-Linux development
# host needs any of it.
ifeq ($(shell uname -s),Darwin)

# RUSTC has to be pinned too, and that is the non-obvious half: `rustup
# which cargo` returns the real binary inside the toolchain, not the
# ~/.cargo/bin shim, and that binary still looks up `rustc` on PATH — so
# a rustup cargo happily drives a Homebrew rustc straight back into the
# same error. Pinning both is what makes this work from a bare `make`.
RUSTC_CROSS ?= $(shell rustup which rustc 2>/dev/null)
ifneq ($(RUSTC_CROSS),)
CROSS_ENV := RUSTC=$(RUSTC_CROSS)
endif

# The linker has to be told how to emit ELF; see scripts/cross_lld.py.
# Note this applies to the DEFAULT target too — `.cargo/config.toml` pins
# `[build] target = x86_64-unknown-linux-gnu`, so even a bare `make build`
# on a Mac is a cross build.
ARM64_LINKER := CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=$(CURDIR)/scripts/cross_lld.py \
                GOISH_CROSS_TARGET=$(ARM64_TARGET)
HOST_LINKER  := CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=$(CURDIR)/scripts/cross_lld.py

endif

.PHONY: all build e2e e2e-full e2e-build e2e-quick e2e-clean clean help \
        lint lint-new lint-update anchors manifests ifaces split-brain \
        provenance-proof build-arm64 run-arm64

help:
	@echo "goish-v1 make targets:"
	@echo "  build         cargo build --examples"
	@echo "  e2e           build + run every example at its TIER's loop count:"
	@echo "                functional=1, memory=10, races/stress=50"
	@echo "                (per-test classification lives in e2e_runner.sh)"
	@echo "  e2e-full      everything at 50 loops — REQUIRED before committing"
	@echo "                scheduler / allocator / runtime-core changes"
	@echo "  e2e-build     just build all examples (no run)"
	@echo "  e2e-quick     cargo clean + e2e with LOOPS=5 (smoke check)"
	@echo "  e2e-clean     remove e2e artifacts"
	@echo "  provenance-proof  mutation proofs for scripts/anchor_check.py (needs node>=24)"
	@echo "  lint          goishlint as a ratchet: fails only on NEW findings"
	@echo "                (SCOPE=src/crypto to narrow; run before every commit)"
	@echo "  lint-new      findings in files absent from the baseline — a newly"
	@echo "                ported file is expected to be clean"
	@echo "  lint-update   re-record the baseline after fixing findings"
	@echo "  clean         cargo clean"
	@echo "  build-arm64   build the aarch64-unknown-linux-gnu allowlist"
	@echo "                (scripts/linux_arm64_examples.txt)"
	@echo "  run-arm64     build-arm64 + run each entry under linux/arm64"
	@echo "  e2e TARGET=aarch64-apple-darwin"
	@echo "                every example, natively on macOS"
	@echo
	@echo "Knobs (env or make var):"
	@echo "  LOOPS=N       force uniform iterations per example (disables tiers)"
	@echo "  TIER1/2/3=N   override a tier's loop count (default 1/10/50)"
	@echo "  TIMEOUT=N     per-iteration timeout in seconds (default 15)"
	@echo "  FILTER=regex  only run examples matching regex"
	@echo "  EXCLUDE=regex skip examples matching regex"
	@echo "                (default skips http_hello, spawn_million,"
	@echo "                 spawn_density, preempt_sysmon)"
	@echo "  ARTIFACTS=dir failure-log dir (default scripts/.e2e-artifacts)"
	@echo
	@echo "Examples:"
	@echo "  make e2e"
	@echo "  make e2e LOOPS=100"
	@echo "  make e2e FILTER='^chan_'"
	@echo "  make e2e LOOPS=10 TIMEOUT=30 FILTER='^http_'"

# The target is pinned explicitly — `--target` for `build`,
# CARGO_BUILD_TARGET for `e2e-build`, whose script puts its own
# arguments after `build` — rather than left to the `.cargo/config.toml`
# pin: a CARGO_BUILD_TARGET in the caller's environment would otherwise
# override it and turn these into a build for the wrong target.
build:
	$(CROSS_ENV) $(HOST_LINKER) $(if $(CROSS_ENV),$(CARGO_CROSS),$(CARGO)) build --target $(TARGET) --examples

# FILTER already chooses which examples the runner executes. Apply the same
# selection before compilation so focused package checks do not build hundreds
# of unrelated static binaries. With no FILTER, the full build is unchanged.
e2e-build:
	@bash scripts/e2e_build_test.sh
	@FILTER='$(FILTER)' CARGO_BUILD_TARGET=$(TARGET) $(CROSS_ENV) $(HOST_LINKER) bash scripts/e2e_build.sh $(if $(CROSS_ENV),$(CARGO_CROSS),$(CARGO))

# ─── aarch64-unknown-linux-gnu ────────────────────────────────────────
#
# Allowlist-driven, never `--examples`: each debug example is a ~47 MiB
# static ELF and there are ~595 of them. The list is the acceptance
# artifact — a milestone lands when its examples are in it and green.
ARM64_EXAMPLES := $(shell grep -v '^\#' $(ARM64_ALLOWLIST) | grep -v '^$$')

# Fails early and legibly rather than 200 lines into a cargo error.
.PHONY: arm64-preflight
arm64-preflight:
	@rustup target list --installed 2>/dev/null | grep -qx '$(ARM64_TARGET)' || { \
		echo "goish: the $(ARM64_TARGET) std is not installed."; \
		echo "       run: rustup target add $(ARM64_TARGET)"; \
		exit 1; }
	@command -v $(CARGO_CROSS) >/dev/null || { \
		echo "goish: no cargo with cross targets found (looked for $(CARGO_CROSS))."; \
		echo "       install rustup, or set CARGO_CROSS=/path/to/cargo"; \
		exit 1; }

build-arm64: arm64-preflight
	$(CROSS_ENV) $(ARM64_LINKER) $(CARGO_CROSS) build --target $(ARM64_TARGET) \
		$(foreach e,$(ARM64_EXAMPLES),--example $(e))

# Run the allowlist. On an Apple Silicon host `docker run --platform
# linux/arm64` is NATIVE execution, not emulation, so this is a real
# gate rather than a smoke test — the one place a weak-memory bug can
# actually show up before the arm64 CI job exists.
run-arm64: build-arm64
	@command -v docker >/dev/null || { \
		echo "goish: run-arm64 needs docker to provide a linux/arm64 userland."; \
		echo "       on an Apple Silicon host that is NATIVE execution, not emulation."; \
		exit 1; }
	@for e in $(ARM64_EXAMPLES); do \
		printf '%-40s' "$$e"; \
		docker run --rm --platform linux/arm64 \
			-v "$$PWD:/w" -w /w/target/$(ARM64_TARGET)/$(PROFILE)/examples \
			debian:bookworm-slim "./$$e" && echo "  [ok]" || echo "  [FAIL]"; \
	done

e2e: e2e-build
	@$(if $(LOOPS),LOOPS=$(LOOPS),) \
		TIER1=$(TIER1) TIER2=$(TIER2) TIER3=$(TIER3) \
		TIMEOUT=$(TIMEOUT) \
		$(if $(FILTER),FILTER='$(FILTER)',) \
		$(if $(EXCLUDE),EXCLUDE='$(EXCLUDE)',) \
		ARTIFACTS=$(ARTIFACTS) \
		TARGET_DIR=target/$(TARGET)/$(PROFILE) \
		bash scripts/e2e_runner.sh

e2e-full:
	@$(MAKE) e2e LOOPS=50

e2e-quick: clean
	@$(MAKE) e2e LOOPS=5

e2e-clean:
	rm -rf $(ARTIFACTS)

# The lint backlog is grandfathered by scripts/lint_baseline.json; these
# targets let it shrink and never grow. See scripts/port_lint.py.
lint: anchors manifests ifaces split-brain spin-park
	@python3 scripts/port_lint.py --check --scope $(SCOPE)

# anchor_check.py is the only thing standing behind the README's "every
# anchor is machine-checked" claim, so it gets checked too: gates/ plants
# deliberately broken anchors in src/crypto (range moved, symbol deleted,
# `.og` typo, range starting inside the declaration above, ...) and
# confirms the checker goes red on each, stays green on a clean tree, and
# exits 2 ("cannot decide") when its evidence is unusable. Every mutation
# is undone afterwards. Needs node >= 24; the Go 1.25.5 toolchain is
# fetched by GOTOOLCHAIN if absent. See CONTRIBUTING.md, "Provenance".
provenance-proof:
	@GOROOT="$$(GOTOOLCHAIN=go1.25.5 go env GOROOT)"; export GOROOT; \
	test -d gates/node_modules || (cd gates && npm ci); \
	cd gates && npx redproof check && npx redproof prove

# goishlint resolves an anchored symbol by name and never looks at the
# line range, so a range can point at a different function - or nothing -
# with every tier-2 check still green. 229 of 1802 were wrong when this
# was first measured. Cheap to check, so check it every time.
anchors:
	@python3 scripts/anchor_check.py $(SCOPE)

# A SpinLock guard held across a park is fatal at run time
# ("schedule: holding locks"), but only on the contended path that
# actually parks — which is exactly the path a smoke does not walk.
# This is the same defect found statically. It FAILS the build: unlike
# the reporting checks above there is no legitimate instance, and one
# reached a downstream port before anything here noticed. Allocation
# under a guard is deliberately not flagged (the allocator masks
# preemption and cannot park), so a finding here is always real.
spin-park:
	@python3 scripts/spin_park_check.py $(SCOPE)

# Go satisfies an interface structurally; goish needs impl + hook +
# registry entry, and two of the three looks finished while the
# assertion silently misses. That has cost real defects here — CGI and
# HTTPS handlers whose writer could not flush, a ResponseController
# where every method answered "not supported". Reports rather than
# fails: some zero-implementor interfaces are extension points.
ifaces:
	@python3 scripts/iface_check.py

# A `decls:` manifest naming a Go METHOD by its bare name is an
# incomplete provenance claim, and where Go declares that name on more
# than one type it is an unreadable one. It also silently drops the
# declaration out of --by-decl coverage, or - worse, because nothing
# flags it - credits it to a case-insensitive twin: Go's unexported
# `List.remove` was being matched to goish's public `List.Remove`.
manifests:
	@python3 scripts/manifest_qual_check.py $(SCOPE)

# Rust needs a trait impl written separately from the inherent method,
# and when neither forwards to the other the type has TWO
# implementations of one operation. `io::Writer for File` drifted that
# way: io::Copy onto a full disk said "write failed" while f.Write on
# the same file said "no space left on device". Reports rather than
# fails: a deliberate divergence is fine when it is written down.
split-brain:
	@python3 scripts/hook_pair_check.py
	@python3 scripts/split_brain_check.py

lint-new:
	@python3 scripts/port_lint.py --new --scope $(SCOPE)

lint-update:
	@python3 scripts/port_lint.py --update --scope $(SCOPE)

clean:
	$(CARGO) clean
