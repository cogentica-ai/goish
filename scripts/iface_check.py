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

  BOXED_UNREGISTERED  a concrete type is handed out as `Box<dyn Trait>`
                by some constructor and has no registration anywhere,
                while another type boxed as that SAME trait does. This
                is the shape the first two checks cannot see, because
                all three legs can be present on the WRONG type:
                `sha3::NewHash256` boxed a `crypto::sha3::SHA3`
                wrapper while the impl, the hook and the registration
                all sat on the `fips140::sha3::Digest` inside it, so
                HMAC's `marshalable` assertion missed and its cached
                ipad/opad path was dead for SHA-3 alone. Every earlier
                tier read that as correctly wired.

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


def base_type(name):
    """The bare type name a registration or impl names.

    A registration can be for a generic instantiation —
    `__goish_register_unmarshaler_impl::<nistCurve<nistec::P256Point>>()`
    — and the type being registered is `nistCurve`, not the parameter
    inside the angle brackets. Splitting on `::` alone yields
    `P256Point>` and the registration then matches nothing, which is
    how crypto/elliptic's four nistec curves read as UNREGISTERED after
    they had been registered.
    """
    name = name.split("<")[0]
    return name.split("::")[-1].strip()


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



def module_of(path):
    """`src/crypto/sha3/sha3.rs` -> `crypto::sha3`.

    BOXED_UNREGISTERED needs type identity that survives the bare-name
    collapse: `sha256::Digest`, `md5::Digest` and `sha1::Digest` are
    three types with one base name, and comparing base names made the
    sibling count 1 where it should have been 3 — which silently
    disabled the check on the defect it was written for.
    """
    d = os.path.dirname(path)
    if d.startswith(SRC + os.sep):
        d = d[len(SRC) + 1:]
    elif d == SRC:
        d = ""
    return d.replace(os.sep, "::")


def qualified(path, name):
    m = module_of(path)
    return f"{m}::{name}" if m else name


def reg_key(full):
    """`crate::crypto::sha3::SHA3` -> `crypto::sha3::SHA3`."""
    full = full.split("<")[0].strip()
    if full.startswith("crate::"):
        full = full[len("crate::"):]
    return full


def scan():
    targets = {}           # trait -> set of "file:line" assertion sites
    registrations = collections.defaultdict(set)   # trait -> {(scope, concrete)}
    impls = collections.defaultdict(set)           # trait -> {(scope, concrete)}
    boxed = collections.defaultdict(set)   # trait -> {(concrete, "file:line")}
    reg_full = collections.defaultdict(set)  # trait -> {module-qualified concrete}
    fn_ret = {}            # bare fn name -> concrete return type

    asserts_re = re.compile(
        r"AsIface::<(?:crate::)?d!\(([A-Za-z_:]+)\)>"
        r"|cast!\(\s*[^,]+,\s*([A-Za-z_:][A-Za-z0-9_:]*)\s*\)"
    )
    reg_re = re.compile(r"__goish_register_([A-Za-z_]+)_impl::<\s*([A-Za-z_][A-Za-z0-9_:<>, ]*?)\s*>\s*\(")
    # `pub fn NewHash() -> Box<dyn Hash + Send + Sync>` and the
    # `Box::new(...)` that follows it.
    boxfn_re = re.compile(
        r"fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*->\s*"
        r"(?:alloc::boxed::)?Box<\s*dyn\s+(?:[A-Za-z_][A-Za-z0-9_]*::)*([A-Za-z_][A-Za-z0-9_]*)")
    boxnew_re = re.compile(r"Box::new\(\s*([A-Za-z_][A-Za-z0-9_:]*)")
    # `pub fn New256() -> SHA3 {` — the plain constructor a boxed one wraps.
    plainfn_re = re.compile(
        r"fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*->\s*"
        r"((?:[A-Za-z_][A-Za-z0-9_]*::)*[A-Za-z_][A-Za-z0-9_]*)\s*\{")
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
                            (scope_of(path), base_type(m.group(2))))
                        reg_full[m.group(1)].add(reg_key(m.group(2)))
                    m = impl_re.match(line)
                    if m:
                        impls[m.group(1)].add((scope_of(path), base_type(m.group(2))))
    # Second pass: resolve each boxed constructor to a concrete type.
    #
    # Resolution is per-FILE first and only then tree-wide, for the same
    # reason scope_of exists above: bare names collide. `New256` is
    # declared in both crypto/sha3 (returning the SHA3 wrapper) and
    # crypto/internal/fips140/sha3 (returning Digest). Resolving by bare
    # name tree-wide picked whichever the directory walk reached first,
    # which silently resolved the wrapper to the Digest — and the
    # Digest IS registered, so the check reported nothing on the very
    # defect it was written for.
    local_ret = {}          # path -> {fn name -> concrete return type}
    local_types = {}        # path -> {struct names declared there}
    boxed_raw = collections.defaultdict(set)   # trait -> {(fnname, path, line)}
    for path in rs_files(SRC):
        with open(path, encoding="utf-8", errors="replace") as fh:
            src = fh.read()
        here = {}
        for m in plainfn_re.finditer(src):
            name, ret = m.group(1), m.group(2)
            if ret in ("Self", "String", "bool", "int"):
                continue
            # Only a BARE return type can be qualified with this file's
            # module. A path-qualified one (`fsha3::Digest`) is very
            # often a use-alias, and prefixing the local module invents
            # a type that does not exist — which is exactly what made
            # this check report `fips140hash::Digest`, a name found
            # nowhere in the tree. Unresolvable is reported as nothing.
            if "::" in ret:
                continue
            here[name] = ret
            fn_ret.setdefault(name, ret)
        local_ret[path] = here
        local_types[path] = set(re.findall(r"^\s*(?:pub(?:\([^)]*\))?\s+)?struct\s+([A-Za-z_][A-Za-z0-9_]*)",
                                           src, re.M))
        for m in boxfn_re.finditer(src):
            trait = m.group(2)
            line = src[:m.start()].count("\n") + 1
            tail = src[m.end():m.end() + 600]
            bm = boxnew_re.search(tail)
            if not bm:
                continue
            boxed_raw[trait].add((base_type(bm.group(1)), path, line))

    resolved = collections.defaultdict(set)
    for trait, entries in boxed_raw.items():
        for name, path, line in entries:
            local = local_ret.get(path, {}).get(name)
            if local is None:
                # `Box::new(Type { .. })` names the type directly; a
                # call we could not resolve locally is skipped rather
                # than guessed.
                if name and name[:1].isupper() and name in local_types.get(path, set()):
                    local = name
                else:
                    continue
            resolved[trait].add((qualified(path, local), f"{path}:{line}"))

    return targets, registrations, impls, resolved, reg_full


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--strict", action="store_true",
                    help="exit non-zero when any finding is reported")
    args = ap.parse_args()

    targets, registrations, impls, boxed, reg_full = scan()

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

    # A type boxed as `dyn C` whose SIBLINGS — the other types handed
    # out as that same `dyn C` — are registered for some target trait T,
    # while it is not.
    #
    # "Registered for nothing at all" was the first cut and it missed
    # the defect this check exists for: `crypto::sha3::SHA3` WAS
    # registered, for Hash and Writer, and only `marshalable` was
    # absent. The signal is per-target, not per-type.
    boxed_unregistered = []
    SIBLING_MIN = 2   # below this the "everyone else does it" claim is noise
    for carrier in sorted(boxed):
        entries = sorted(boxed[carrier])
        names = {c for c, _ in entries}
        for target in sorted(reg_full):
            # Only traits something actually ASSERTS on. Without this
            # the check reports types not registered for
            # BinaryMarshaler and friends, which nothing in the tree
            # asserts, so the registration would be unreachable code —
            # the very thing this file exists to find, inverted.
            if target not in targets:
                continue
            reg_names = reg_full[target]
            covered = names & reg_names
            if len(covered) < SIBLING_MIN:
                continue
            # One finding per (carrier, target, type), not per
            # constructor — sha3 has four constructors boxing the same
            # wrapper and repeating them four times buries the signal.
            seen_here = set()
            for concrete, site in entries:
                if concrete in reg_names or concrete in seen_here:
                    continue
                seen_here.add(concrete)
                boxed_unregistered.append((carrier, target, concrete, site,
                                           len(covered)))

    print(f"iface_check: {len(targets)} asserted interface(s) under {SRC}/")

    if unregistered:
        print(f"\n  UNREGISTERED ({len(unregistered)}) — implemented, asserted on, never registered:")
        for trait, concrete, scope in unregistered:
            site = sorted(targets[trait])[0]
            print(f"    {scope}: {concrete} implements {trait} but is not registered for it")
            print(f"      asserted at {site}")

    if boxed_unregistered:
        print(f"\n  BOXED_UNREGISTERED ({len(boxed_unregistered)}) — handed out as an "
              f"interface, never registered:")
        for carrier, target, concrete, site, n in boxed_unregistered:
            print(f"    {site}: `{concrete}` is boxed as `dyn {carrier}` but is not")
            print(f"      registered for `{target}`, which {n} of its siblings are")
        print("      (an assertion for that trait on this carrier misses for this")
        print("       type alone — impl, hook and registration can all exist on an")
        print("       INNER type, which is what sha3 did.)")

    if no_impl:
        print(f"\n  NO_IMPLEMENTOR ({len(no_impl)}) — asserted on, nothing registered:")
        for trait in no_impl:
            site = sorted(targets[trait])[0]
            print(f"    {trait:<24} asserted at {site}")
        print("      (some are legitimate: Go's rwUnwrapper has no stdlib")
        print("       implementor either — it is a user-middleware hook.)")

    if not unregistered and not no_impl and not boxed_unregistered:
        print("  OK — every asserted interface has a registered implementor.")

    if args.strict and (unregistered or no_impl or boxed_unregistered):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
