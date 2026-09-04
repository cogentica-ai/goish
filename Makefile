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

.PHONY: all build e2e e2e-full e2e-build e2e-quick e2e-clean clean help \
        lint lint-new lint-update

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
	@echo "  lint          goishlint as a ratchet: fails only on NEW findings"
	@echo "                (SCOPE=src/crypto to narrow; run before every commit)"
	@echo "  lint-new      findings in files absent from the baseline — a newly"
	@echo "                ported file is expected to be clean"
	@echo "  lint-update   re-record the baseline after fixing findings"
	@echo "  clean         cargo clean"
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

build e2e-build:
	$(CARGO) build --examples

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
lint: anchors ifaces split-brain
	@python3 scripts/port_lint.py --check --scope $(SCOPE)

# goishlint resolves an anchored symbol by name and never looks at the
# line range, so a range can point at a different function - or nothing -
# with every tier-2 check still green. 229 of 1802 were wrong when this
# was first measured. Cheap to check, so check it every time.
anchors:
	@python3 scripts/anchor_check.py $(SCOPE)

# Go satisfies an interface structurally; goish needs impl + hook +
# registry entry, and two of the three looks finished while the
# assertion silently misses. That has cost real defects here — CGI and
# HTTPS handlers whose writer could not flush, a ResponseController
# where every method answered "not supported". Reports rather than
# fails: some zero-implementor interfaces are extension points.
ifaces:
	@python3 scripts/iface_check.py

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
