#!/usr/bin/env bash
# The library test target must compile (#27).
#
# `cargo test` builds the lib against the standard test harness, which
# depends on `std` — and `std` supplies a `panic_impl`. goish supplies
# its own `#[panic_handler]`, so unless that handler is gated on
# `cfg(not(test))` the target fails with a duplicate lang item and
# `cargo check --all-targets` fails with it. That took the standard
# validation gate away from every downstream crate, which then had to
# enumerate `--bins --examples` instead.
#
# Gating the handler is a one-line fix and a one-line regression, which
# is exactly why it needs a gate rather than a comment. This lives in
# `e2e-build` because that is what CI invokes; `make lint` is not run by
# any workflow.
#
# BUILD, NOT CHECK, and that distinction is the whole point. There are
# TWO collisions and `check` only reaches one of them:
#
#   panic_impl            a duplicate LANG ITEM. The front end catches
#                         it, so `cargo check` fails. This is the one
#                         the issue reports.
#   rust_eh_personality   a duplicate SYMBOL. Nothing catches it until
#                         the linker runs, so `cargo check` passes and
#                         `cargo build --all-targets` and `cargo test`
#                         still fail.
#
# Gating the panic handler alone satisfies every acceptance criterion in
# the issue and leaves the target unable to link. So this gate links.
#
# It does not RUN the target: goish's runtime supplies its own entry
# point and init, so the std harness starts it in a state where the
# first scheduler or allocator touch segfaults. Making it run is a
# different and much larger question than making it compile.
set -euo pipefail
cd "$(dirname "$0")/.."
CARGO="${1:-cargo}"

if ! out=$("$CARGO" build --lib --tests --message-format=short 2>&1); then
    echo "$out" | grep -E 'error|duplicate' | head -20 || true
    echo
    echo "LIB TEST TARGET DOES NOT BUILD (#27)."
    echo "duplicate lang item \`panic_impl\`  -> the #[panic_handler] in"
    echo "    src/runtime/mod.rs lost its #[cfg(not(test))] gate."
    echo "duplicate symbol rust_eh_personality -> the stub in the same"
    echo "    file lost its #[cfg(not(test))] gate."
    exit 1
fi
echo 'LIB_TEST_TARGET_OK cargo build --lib --tests (compiles and links)'
