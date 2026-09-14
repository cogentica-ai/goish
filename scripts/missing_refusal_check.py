#!/usr/bin/env python3
"""missing_refusal_check — refusals Go makes that the goish port does not.

A refusal goish never makes is invisible to every other tier. The
function is anchored, port_coverage counts it, port_bodydiff finds the
body faithful, goishlint is silent, and an example may even test it —
and it lets something through. Three of the six §1 findings of
2026-09-14 were exactly this: `ExpandLabel` without Go's length guard,
`tls10MAC` without the Lucky13 extra write, the PSK/suite pairing check
absent entirely.

Two modes, because the precise one only works for crypto/tls.

  --alerts   (default) crypto/tls only. For every `sendAlert` in Go with
             an errors.New/fmt.Errorf message beside it, check that
             message text appears somewhere in the goish port. sendAlert
             is the densest marker of "Go refuses here" in that package,
             and the message makes the match specific.

  --errors   every package. For every Go file some goish file claims to
             port, check each errors.New/fmt.Errorf literal against the
             whole goish PACKAGE. Broader, noisier, untriaged.

Run --alerts in CI-adjacent checks if you like; do NOT gate on --errors.

VALIDATED BY PERTURBATION, which is the only reason to trust a checker
that reports OK. Replacing the text of one real refusal in
handshake_server_tls13.rs takes --alerts from 6 findings to 7. A
checker that cannot find the bug that motivates it is worse than none.

Known limits, all of which make it MISS things rather than invent them:
  * it matches by message TEXT, so a port that keeps the message and
    drops the `sendAlert` looks fine;
  * a refusal goish words differently is a false positive;
  * --errors searches the package, not the file, because goish splits
    one Go file across several .rs (server.go -> server.rs +
    responsewriter.rs + server_tls.rs) and cites some of them only in
    prose. Searching per-file reported 177 where the package-wide
    answer is 137.

As of 2026-09-14 --alerts reports SIX, and all six sit inside Go's
`c.quic != nil` blocks — goish ships no QUIC transport and waives those
declarations. So every non-QUIC refusal Go makes in conn.go,
handshake_client.go, handshake_server.go, handshake_client_tls13.go,
handshake_server_tls13.go and ech.go has a counterpart in the port.
That is worth knowing next to the invented-code findings: the PORTED
code keeps its guards, the hand-written code loses them.
"""
import re, os, sys, subprocess, collections

GOROOT = subprocess.check_output(['go', 'env', 'GOROOT']).decode().strip()

TLS_PAIRS = [
    ('crypto/tls/handshake_server_tls13.go', 'src/crypto/tls/handshake_server_tls13.rs'),
    ('crypto/tls/handshake_client_tls13.go', 'src/crypto/tls/handshake_client_tls13.rs'),
    ('crypto/tls/conn.go', 'src/crypto/tls/conn.rs'),
    ('crypto/tls/handshake_client.go', 'src/crypto/tls/handshake_client.rs'),
    ('crypto/tls/handshake_server.go', 'src/crypto/tls/handshake_server.rs'),
    ('crypto/tls/ech.go', 'src/crypto/tls/ech.rs'),
]

MSG = re.compile(r'(?:errors\.New|fmt\.Errorf)\("([^"]{12,})"')


def key_of(msg, minlen):
    k = msg.split('%')[0].strip()
    return k if len(k) >= minlen else None


def alerts():
    total = 0
    for gof, rsf in TLS_PAIRS:
        g = os.path.join(GOROOT, 'src', gof)
        if not os.path.isfile(g) or not os.path.isfile(rsf):
            continue
        glines = open(g).read().split('\n')
        rsrc = open(rsf).read()
        for i, l in enumerate(glines):
            if 'sendAlert(' not in l or l.strip().startswith('//'):
                continue
            msg = None
            for j in range(i, min(i + 4, len(glines))):
                m = MSG.search(glines[j])
                if m:
                    msg = m.group(1)
                    break
            if not msg:
                continue
            k = key_of(msg, 12)
            if k and k not in rsrc:
                print("  %s:%d  %r\n      port: %s" % (gof, i + 1, k, rsf))
                total += 1
    print("--alerts: %d Go refusal(s) with no matching text in the port" % total)
    return total


def errors_mode():
    gofiles = set()
    for root, dirs, fs in os.walk('src'):
        for f in fs:
            if not f.endswith('.rs'):
                continue
            src = open(os.path.join(root, f)).read()
            gofiles |= set(re.findall(r'go:\s*file\s+(\S+\.go)\b', src[:4000]))
            gofiles |= set(re.findall(r'go:\s*sdk\s+\S+\s+(\S+\.go):', src))

    blobs = {}

    def pkgblob(pkg):
        if pkg in blobs:
            return blobs[pkg]
        d = os.path.join('src', pkg)
        b = None
        if os.path.isdir(d):
            b = '\n'.join(open(os.path.join(d, f)).read()
                          for f in sorted(os.listdir(d)) if f.endswith('.rs'))
        blobs[pkg] = b
        return b

    per = collections.Counter()
    total = 0
    for gof in sorted(gofiles):
        g = os.path.join(GOROOT, 'src', gof)
        if not os.path.isfile(g):
            continue
        blob = pkgblob(os.path.dirname(gof))
        if blob is None:
            continue
        for m in MSG.finditer(open(g).read()):
            k = key_of(m.group(1), 16)
            if k and k not in blob:
                per[gof] += 1
                total += 1
    print("--errors: %d Go error literal(s) absent from the whole goish package" % total)
    for gof, n in per.most_common(20):
        print("  %-46s %d" % (gof, n))
    return total


if __name__ == '__main__':
    if '--errors' in sys.argv:
        errors_mode()
    else:
        alerts()
