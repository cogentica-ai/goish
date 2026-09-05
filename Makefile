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

build:
	$(CARGO) build --examples

# FILTER already chooses which examples the runner executes. Apply the same
# selection before compilation so focused package checks do not build hundreds
# of unrelated static binaries. With no FILTER, the full build is unchanged.
e2e-build:
	@bash scripts/e2e_build_test.sh
	@FILTER='$(FILTER)' bash scripts/e2e_build.sh $(CARGO)

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
lint: anchors
	@python3 scripts/port_lint.py --check --scope $(SCOPE)

# goishlint resolves an anchored symbol by name and never looks at the
# line range, so a range can point at a different function - or nothing -
# with every tier-2 check still green. 229 of 1802 were wrong when this
# was first measured. Cheap to check, so check it every time.
anchors:
	@python3 scripts/anchor_check.py $(SCOPE)

lint-new:
	@python3 scripts/port_lint.py --new --scope $(SCOPE)

lint-update:
	@python3 scripts/port_lint.py --update --scope $(SCOPE)

clean:
	$(CARGO) clean
