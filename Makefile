# goish-v1 — top-level convenience targets.
#
# Most targets just shell out to scripts/ — keep this file thin.

CARGO     ?= cargo
TARGET    ?= x86_64-unknown-linux-gnu
PROFILE   ?= debug
LOOPS     ?= 50
TIMEOUT   ?= 15
FILTER    ?=
EXCLUDE   ?=
ARTIFACTS ?= scripts/.e2e-artifacts

EXAMPLES_DIR := target/$(TARGET)/$(PROFILE)/examples

.PHONY: all build e2e e2e-build e2e-quick e2e-clean clean help

help:
	@echo "goish-v1 make targets:"
	@echo "  build         cargo build --examples"
	@echo "  e2e           build + run every example LOOPS times (default 50)"
	@echo "  e2e-build     just build all examples (no run)"
	@echo "  e2e-quick     cargo clean + e2e with LOOPS=5 (smoke check)"
	@echo "  e2e-clean     remove e2e artifacts"
	@echo "  clean         cargo clean"
	@echo
	@echo "Knobs (env or make var):"
	@echo "  LOOPS=N       iterations per example (default 50)"
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
	@LOOPS=$(LOOPS) TIMEOUT=$(TIMEOUT) \
		$(if $(FILTER),FILTER='$(FILTER)',) \
		$(if $(EXCLUDE),EXCLUDE='$(EXCLUDE)',) \
		ARTIFACTS=$(ARTIFACTS) \
		TARGET_DIR=target/$(TARGET)/$(PROFILE) \
		bash scripts/e2e_runner.sh

e2e-quick: clean
	@$(MAKE) e2e LOOPS=5

e2e-clean:
	rm -rf $(ARTIFACTS)

clean:
	$(CARGO) clean
