#!/usr/bin/env bash
# goref — run a throwaway Go test *inside* a writable copy of GOROOT, so
# it can import `crypto/internal/...` packages and reach unexported
# symbols. This is how ported packages get ground truth: instead of
# transcribing published vectors (which has twice produced a corrupted
# literal that looked plausible), generate the expected values from the
# very implementation being ported.
#
#   scripts/goref.sh <go-import-path> <ref-test-file> [extra-test-file...]
#
#   scripts/goref.sh crypto/internal/fips140/tls13 /tmp/zz_ref_test.go
#
# The file must declare `package <pkg>` (the internal package's own name,
# NOT <pkg>_test) and a `func TestGoishRef(t *testing.T)` that prints the
# vectors. It is copied in as zz_ref_test.go and removed afterwards.
#
# EXTRA FILES exist for the packages `testing` itself depends on. An
# internal test of `os` cannot import `testing` or `fmt` — both import
# `os`, so the test binary will not build:
#
#   imports fmt from zz_ref_test.go
#   imports os from print.go: import cycle not allowed in test
#
# Go's own answer is export_test.go: a `package os` file with no heavy
# imports that hands internals to the EXTERNAL `package os_test`, which
# may import whatever it likes. Pass that shim as an extra file and
# write the ref test as `package os_test`:
#
#   scripts/goref.sh os tools/gen_x_ref.go tools/gen_x_export.go
#
# Extras are copied in as zz_ref_extra<N>_test.go, so they are test-only
# and never join the package proper.
#
# The GOROOT copy is cached under $TMPDIR; delete it to refresh.
#
# CGO: this runs with whatever CGO_ENABLED the environment has, and a
# handful of packages have TWO implementations selected by it — os/user
# is the clearest (getpwuid through cgo, or reading /etc/passwd without
# it), and net's resolver is another. If the port reads the files
# itself, generate the reference with CGO_ENABLED=0 or the diff will
# show Go's OTHER implementation and every line will look like a defect:
#
#   CGO_ENABLED=0 scripts/goref.sh os/user tools/gen_osuser_ref.go
#
# That mistake cost a full round of investigation on os/user; the smoke
# it produced records which implementation it pins.
set -euo pipefail

pkg="${1:?usage: goref.sh <import-path> <ref-test-file> [extra-test-file...]}"
ref="${2:?usage: goref.sh <import-path> <ref-test-file> [extra-test-file...]}"
shift 2
extras=("$@")

sysroot="$(go env GOROOT)"
work="${GOREF_DIR:-${TMPDIR:-/tmp}/goref}"
root="$work/goroot"

if [ ! -d "$root" ]; then
    echo "goref: seeding writable GOROOT at $root (one time, ~220 MB)" >&2
    mkdir -p "$work"
    cp -r "$sysroot" "$root"
    chmod -R u+w "$root"
fi

dst="$root/src/$pkg/zz_ref_test.go"
[ -d "$root/src/$pkg" ] || { echo "goref: no such package: $pkg" >&2; exit 1; }
copied=("$dst")
cp "$ref" "$dst"
n=0
for e in ${extras+"${extras[@]}"}; do
    n=$((n + 1))
    x="$root/src/$pkg/zz_ref_extra${n}_test.go"
    cp "$e" "$x"
    copied+=("$x")
done
trap 'rm -f "${copied[@]}"' EXIT

cd "$root/src"
GOROOT="$root" GOCACHE="$work/cache" GOPATH="$work/path" \
    go test "$pkg" -run TestGoishRef -v -count=1 2>&1 |
    grep -v -e '^=== RUN' -e '^--- PASS' -e '^PASS$' -e '^ok  '
