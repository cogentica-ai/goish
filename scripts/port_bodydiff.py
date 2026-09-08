#!/usr/bin/env python3
"""Triage aid for the one defect class the lint tier cannot see.

GOISH018 compares signatures, arity and struct fields. It never reads
the statements inside a function, so a port that forgot to emit an
extension passes every tier-2 check. Two shipped that way:
`encryptedExtensionsMsg.marshal` dropped three extensions and
`serverHelloMsg.marshal` dropped six, both under valid anchors.

This compares the call multiset of each anchored goish function against
its Go source and reports calls Go makes more often. It depends on
anchor ranges being correct - run scripts/anchor_check.py first, or the
output is noise about the wrong function entirely.

**This is triage, not a gate.** The general mode has a high false
positive rate, all from legitimate differences:

  - goish extracts a helper Go inlines twice
    (Conn.verifyServerCertificate -> verifyChainAgainstRoots)
  - goish binds a Go func value to a local first
    (`suite.cipher(...)` -> `let cipherFn = ...; cipherFn(...)`)
  - a Rust operator replaces a Go call (bytes.Equal -> ==,
    slices.Clone -> derive(Clone))
  - a documented deviation (no weak pointers, no RWMutex, no QUIC)
  - goish merges two identical Go switch arms
  - a package that deliberately EXPORTS Go's unexported names. Callers
    then spell the capitalised form, so every lowercase Go name reads as
    0/N. encoding/asn1 does this on purpose (so asn1_marshal_smoke can
    reach the parsers) and produced seven such rows on 2026-09-06 —
    parseBool, checkInteger, parseBitString, parseBase128Int,
    parseNumericString and two more — all false. Triaged by grepping the
    callers for the capitalised name: asn1.rs:343 calls ParseBool.

Run on src/os the same day it found a TRUE one that hand-reading had
missed: `ignoringEINTR 0/1` on Truncate, Symlink and Link. Go wraps ten
syscalls in an EINTR retry and goish calls each once. Reading the two
bodies side by side does not surface that, because the difference is a
WRAPPER around Go's call rather than anything inside either body — which
is the shape this tool is for.

  --emit  restricts the comparison to cryptobyte builder/parser calls.
          Those have no operator or helper equivalent, so a deficit is
          nearly always either a dropped field or an obvious refactor.
          This is the mode worth running routinely.

Last full triage: 2026-09-04, 1844 anchored fns, 12 deficits, all 12
checked by hand and all 12 false positives. Written down so the next
reader does not re-derive it:

  clientHelloMsg.unmarshal     -10. Uses the real cryptobyte String's
                               METHODS (`s.ReadUint8LengthPrefixed()`)
                               where Go uses this file's free functions.
                               clientHello is ported against real
                               cryptobyte; the other messages use the
                               older `builder` mini-port.
  buildCertExtensions          -4. The AddBytes are in
                               `serialiseConstraints`, a helper goish
                               extracts and Go inlines.
  certificateRequestMsgTLS13   -4. goish merges Go's two identical arms
    .unmarshal                 for SignatureAlgorithms and
                               SignatureAlgorithmsCert and splits them
                               after; the deficit is the duplicate.
  encryptedExtensionsMsg       -2. `extData.0.clone().__into_vec()`
    .unmarshal                 where Go writes make() + CopyBytes. Both
                               extensions ARE handled.
  Sign (ecdsa_legacy)          -2. Both `Empty()` checks are in
                               `parseSignature`, extracted into
                               ecdsa.rs.
  parseNameConstraintsExtension -1. The third `Empty()` is in
                               `nameConstraintValues`, the extracted
                               form of Go's `getValues` closure.
  serverHelloMsg.marshal       -1. `AddBytes` where Go writes
                               `addBytesWithLength(b, m.random, 32)`.
                               The mini-port builder has no `AddValue`,
                               so the LENGTH CHECK is not enforced on
                               this path — noted at the `builder` block.
                               No observable difference: unmarshal reads
                               the random with `ReadBytes(&random, 32)`
                               on both sides, so a wrong length cannot
                               reach it.
  serverHelloMsg.unmarshal     -1. Reads the ECH extension into a local
                               and assigns, where Go uses CopyBytes.
  Builder.AddUintNLengthPrefixed  -1 each. Go's method calls the shared
                               `addLengthPrefixed`; the tool counts the
                               method's own name against it.

So the class this exists to catch — a dropped field under a valid
anchor — currently has no instances.

General mode, `src/net/http`, triaged 2026-09-05: 1047 anchored fns,
502 deficits. Only the top few were checked; the rest is UNTRIAGED and
the count is dominated by the legitimate differences listed above.
What the top of that list means, so it is not re-derived:

  ReverseProxy.ServeHTTP    -51. REAL, and already recorded as ROADMAP
                            2m. The anchor is claimed by the slim
                            `reverseProxyHandler`, which has no hooks;
                            the exported `ReverseProxy` has no
                            ServeHTTP at all. The missing calls name
                            exactly what is absent — getErrorHandler,
                            copyHeader, the Rewrite-path Header.Del.
  ReverseProxy              -33. Same finding: getErrorHandler 0/7 and
    .handleUpgradeResponse  Errorf 0/7 are the error reporting the
                            slim path replaces with a bare status.
  persistConn.readLoop      -32. goish has no readLoop — ROADMAP 2h.
  Transport.dialConn        -59. Mostly `Close` in Go's error paths,
                            where goish's Drop handles the conn.
  response.WriteHeader      -10. WAS REAL: checkWriteHeaderCode 0/1.
                            The guard was ported, anchored, and called
                            only from httptest's recorder, so the
                            server put invalid status codes on the
                            wire — WriteHeader(-1) emitted the
                            syntactically invalid line
                            `HTTP/1.1 00-1 status code -1`. Fixed and
                            pinned by http_writeheader_code_ref_smoke.
                            This is the one real find from the general
                            mode so far, and it was below the top ten.
  ServeMux.findHandler      -18. FALSE POSITIVE. goish reaches the
                            same behaviour with a different call
                            structure. Diffed against Go across nine
                            routing probes — trailing-slash redirect,
                            /a/../x, //x, /./x, host:port stripping,
                            405-with-Allow, 404, and /x/.. — and all
                            nine agree. Already pinned: mux_ref_smoke
                            covers 405-with-Allow and the /a/../admin
                            redirect, http_mux_routing_smoke covers
                            //double.

Sampled elsewhere 2026-09-06, top entries only, all FALSE POSITIVES —
recorded so the same six are not re-checked:

  os.ReadDir, io/fs.ReadDir,   `SortFunc 0/1`. All three DO sort; they
  ioutil.ReadDir               use Rust's `sort_by`, which the tool
                               cannot see as SortFunc.
  multipart.Reader.readForm    `CopyN 0/2`. Every bound is present —
                               maxParts 1000, the +10MB maxMemoryBytes
                               budget, the 200-byte mapEntryOverhead,
                               ErrMessageTooLarge. Go's
                               `maxFileMemoryBytes--` guard is absent
                               and correctly so: it exists because Go
                               computes `maxFileMemoryBytes+1` for
                               CopyN, and goish compares instead of
                               adding, so there is nothing to overflow.
  base64 decodeQuantum         `CorruptInputError 0/8`. goish routes
                               through a `corrupt(n)` helper; covered
                               by base64_ref_smoke.
  bufio Err* vars              `New 1/4`. Several vars share one Go
                               anchor range, so each is charged for all
                               the New calls in the block. Same
                               artifact as net/http's transport.go
                               err* block.
"""
import os, re, sys, collections

GOROOT = os.environ.get("GOROOT") or \
    "/nix/store/60z37432vmgkg54krwr1z057bqwp7583-go-1.25.5/share/go/src"

# `go env GOROOT` prints the INSTALL root (/usr/local/go); the sources
# live under its `src`. Accept either spelling, because the failure
# mode of guessing wrong is silent: every anchored file resolves to a
# path that does not exist, every Go body reads as empty, and the
# script reports "0 anchored fns, 0 with a deficit" — which looks
# exactly like a clean sweep.
if not os.path.isdir(os.path.join(GOROOT, "crypto", "tls")):
    _alt = os.path.join(GOROOT, "src")
    if os.path.isdir(os.path.join(_alt, "crypto", "tls")):
        GOROOT = _alt
    else:
        sys.exit("port_bodydiff: no Go sources under %r (tried it and %r).\n"
                 "Set GOROOT to the Go install root or its src directory."
                 % (GOROOT, _alt))

ANCHOR = re.compile(r"//\s*go:\s*sdk\s+\S+\s+(\S+):(\d+)-(\d+)\s+(\S+)")
CALL = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(")
EMIT = re.compile(r"^(AddUint\d+|AddBytes|AddUint\d+LengthPrefixed|addBytesWithLength|"
                  r"ReadUint\d+|ReadBytes|ReadUint\d+LengthPrefixed|readUint\d+LengthPrefixed|"
                  r"Skip|Empty|CopyBytes)$")

IGNORE = {
    "clone","unwrap","to_vec","len","Len","from_vec","__from_vec","into","new",
    "as_slice","as_bytes","is_empty","iter","collect","Some","None","Box","push",
    "extend_from_slice","from_static","from_bytes","String","Vec","format","vec",
    "map","unwrap_or","as_ref","as_mut","expect","min","max","cmp","default",
    "Default","with_capacity","resize","to_string","downcast_ref","is","filter",
    "take","and_then","unwrap_or_default","get","into_vec","__into_vec","slice",
    "copy_from_slice","enumerate","zip","rev","Clone","Equal","make","append",
    "cap","copy","string","byte","int","uint16","uint8","uint32","uint64",
    "int32","int64","bool","panic","recover","print","println","func","range",
    "delete","clear",
}

_cache = {}


def go_src(g):
    if g not in _cache:
        fp = os.path.join(GOROOT, g)
        _cache[g] = open(fp, errors="replace").read().split("\n") \
            if os.path.exists(fp) else None
    return _cache[g]


def strip_comments(text):
    out = []
    for l in text.split("\n"):
        if l.lstrip().startswith("//"):
            continue
        out.append(re.sub(r"//.*$", "", l))
    return "\n".join(out)


def calls(text, emit_only):
    c = collections.Counter()
    for m in CALL.finditer(text):
        n = m.group(1)
        if emit_only:
            if EMIT.match(n):
                c[n] += 1
        elif n not in IGNORE:
            c[n] += 1
    return c


def rs_body(lines, i):
    while i < len(lines) and not re.search(r"\bfn\s+[A-Za-z_]", lines[i]):
        i += 1
        if i > len(lines):
            return None
    if i >= len(lines):
        return None
    depth, started, buf = 0, False, []
    while i < len(lines):
        buf.append(lines[i])
        depth += lines[i].count("{") - lines[i].count("}")
        if "{" in lines[i]:
            started = True
        if started and depth <= 0:
            break
        i += 1
    return "\n".join(buf)


def main():
    emit_only = "--emit" in sys.argv
    roots = [a for a in sys.argv[1:] if not a.startswith("--")] or ["src/crypto"]
    found, checked = [], 0
    for root in roots:
        for dp, _, names in os.walk(root):
            for n in sorted(names):
                if not n.endswith(".rs"):
                    continue
                p = os.path.join(dp, n)
                lines = open(p, errors="replace").read().split("\n")
                for i, l in enumerate(lines):
                    m = ANCHOR.search(l)
                    if not m:
                        continue
                    g, a, b, sym = m.group(1), int(m.group(2)), int(m.group(3)), m.group(4)
                    src = go_src(g)
                    if src is None:
                        continue
                    rb = rs_body(lines, i + 1)
                    if rb is None:
                        continue
                    checked += 1
                    gc = calls(strip_comments("\n".join(src[a - 1:b])), emit_only)
                    if not gc:
                        continue
                    rc = calls(strip_comments(rb), emit_only)
                    miss = {k: (v, rc.get(k, 0)) for k, v in gc.items() if rc.get(k, 0) < v}
                    if miss:
                        found.append((sum(v - h for v, h in miss.values()),
                                      sym, g, a, b, p, miss))
    found.sort(key=lambda x: -x[0])
    mode = "emit/parse calls only" if emit_only else "all calls"
    print(f"port_bodydiff ({mode}): {checked} anchored fns, {len(found)} with a deficit\n")
    for sc, sym, g, a, b, p, miss in found[:30]:
        items = ", ".join(f"{k} {h}/{v}" for k, (v, h) in
                          sorted(miss.items(), key=lambda x: -(x[1][0] - x[1][1]))[:6])
        print(f"-{sc:<3d} {sym:<46s} {g}:{a}-{b}")
        print(f"      {p}")
        print(f"      {items}")
    if found:
        print("\nTriage each by hand - see the module docstring for the "
              "legitimate differences this cannot tell from a real drop.")
    return 0


sys.exit(main())
