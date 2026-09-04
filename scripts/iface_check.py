#!/usr/bin/env python3
"""Find interface assertions that can never hit.

Go satisfies an interface STRUCTURALLY: a type with the right methods
has the interface, and there is nothing to wire up. goish resolves the
same assertion through a runtime registry, so a concrete type needs
THREE things before `cast!(x, Iface)` or `errors::AsIface::<Iface>`
finds it:

  1. the trait impl,
  2. the `__goish_as_dyn_any` hook on that impl,
  3. `__goish_register_<Iface>_impl::<Concrete>()` at init.

Two of three looks finished and behaves like nothing at all: the
assertion misses, silently, and the caller takes the "not supported"
branch. That has happened repeatedly in this tree - net/http/cgi's
response and crypto/tls's tlsResponse both had impl and hook and no
registration, so every CGI and every HTTPS handler saw a writer that
could not flush; ResponseController's four capability interfaces had no
implementor at all, so every method answered ErrNotSupported on the
server's own writer.

Two checks, and they fail differently:

  UNREGISTERED  a type implements a trait that something asserts on,
                and is never registered for it. This is the CGI shape
                and is almost always a defect.

  NO_IMPLEMENTOR  a trait is asserted on and NOTHING registers for it.
                Sometimes a defect, sometimes correct: Go's
                `rwUnwrapper` has no stdlib implementor either - it is
                an extension point for user middleware. Reported for
                review rather than as a failure, which is why --strict
                exists.

Exit status is 0 unless --strict is given and either check has
findings, so the script is safe to run in a pre-commit hook by default.
"""

import argparse
import collections
import os
import re
import sys

SRC = "src"

# Trait names that are macro placeholders in doc examples, not real
# assertion targets.
PLACEHOLDERS = {"Iface", "J", "Other", "Trait", "T", "SomeInterface"}


def rs_files(root):
    for dirpath, _, names in os.walk(root):
        for n in names:
            if n.endswith(".rs"):
                yield os.path.join(dirpath, n)


def scope_of(path):
    """The module a file belongs to, for telling same-named types apart.

    `net/http/cgi/child.rs` and `net/http/responsewriter.rs` both declare
    a type called `response`. Keyed on the bare name they are one type,
    and a registration for either looks like a registration for both —
    which is exactly how the CGI Flusher defect would slip past this
    check. The registration for a type is written in the module that
    declares it in every case in this tree, so the file is a good
    discriminator.
    """
    return os.path.dirname(path) + "/" + os.path.basename(path)


def scan():
    targets = {}           # trait -> set of "file:line" assertion sites
    registrations = collections.defaultdict(set)   # trait -> {(scope, concrete)}
    impls = collections.defaultdict(set)           # trait -> {(scope, concrete)}

    asserts_re = re.compile(
        r"AsIface::<(?:crate::)?d!\(([A-Za-z_:]+)\)>"
        r"|cast!\(\s*[^,]+,\s*([A-Za-z_:][A-Za-z0-9_:]*)\s*\)"
    )
    reg_re = re.compile(r"__goish_register_([A-Za-z_]+)_impl::<\s*([A-Za-z_][A-Za-z0-9_:<>, ]*?)\s*>")
    impl_re = re.compile(
        r"^\s*impl(?:<[^>]*>)?\s+(?:[A-Za-z_][A-Za-z0-9_:]*::)*([A-Za-z_][A-Za-z0-9_]*)"
        r"\s+for\s+([A-Za-z_][A-Za-z0-9_:]*)"
    )

    for path in rs_files(SRC):
        with open(path, encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh, 1):
                stripped = line.lstrip()
                is_comment = stripped.startswith("//")
                if not is_comment:
                    for m in asserts_re.finditer(line):
                        name = m.group(1) or m.group(2)
                        if not name:
                            continue
                        short = name.split("::")[-1]
                        if short in PLACEHOLDERS:
                            continue
                        targets.setdefault(short, set()).add(f"{path}:{i}")
                    for m in reg_re.finditer(line):
                        registrations[m.group(1)].add(
                            (scope_of(path), m.group(2).split("::")[-1]))
                    m = impl_re.match(line)
                    if m:
                        impls[m.group(1)].add((scope_of(path), m.group(2).split("::")[-1]))
    return targets, registrations, impls


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--strict", action="store_true",
                    help="exit non-zero when any finding is reported")
    args = ap.parse_args()

    targets, registrations, impls = scan()

    unregistered = []
    for trait in sorted(targets):
        regs = registrations.get(trait, set())
        reg_names = {name for _, name in regs}
        for scope, concrete in sorted(impls.get(trait, set())):
            # A registration in the SAME module is the normal case. A
            # registration elsewhere counts too, but only when the name
            # is unambiguous tree-wide — otherwise `response` in
            # net/http/cgi would be covered by `response` in
            # net/http/responsewriter, which is a different type.
            same_module = (scope, concrete) in regs
            impl_scopes = {sc for sc, nm in impls[trait] if nm == concrete}
            ambiguous = len(impl_scopes) > 1
            if same_module:
                continue
            if not ambiguous and concrete in reg_names:
                continue
            unregistered.append((trait, concrete, scope))

    no_impl = [t for t in sorted(targets) if not registrations.get(t)]

    print(f"iface_check: {len(targets)} asserted interface(s) under {SRC}/")

    if unregistered:
        print(f"\n  UNREGISTERED ({len(unregistered)}) — implemented, asserted on, never registered:")
        for trait, concrete, scope in unregistered:
            site = sorted(targets[trait])[0]
            print(f"    {scope}: {concrete} implements {trait} but is not registered for it")
            print(f"      asserted at {site}")

    if no_impl:
        print(f"\n  NO_IMPLEMENTOR ({len(no_impl)}) — asserted on, nothing registered:")
        for trait in no_impl:
            site = sorted(targets[trait])[0]
            print(f"    {trait:<24} asserted at {site}")
        print("      (some are legitimate: Go's rwUnwrapper has no stdlib")
        print("       implementor either — it is a user-middleware hook.)")

    if not unregistered and not no_impl:
        print("  OK — every asserted interface has a registered implementor.")

    if args.strict and (unregistered or no_impl):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
