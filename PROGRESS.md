# Progress

Where the port actually stands, and how much of it is *proven* rather
than merely counted. Numbers are regenerated with
`scripts/port_coverage.py`; the last full refresh was 2026-08-15, with
the `compress` row refreshed 2026-08-17 and the `hash` and `encoding`
rows 2026-08-30.

> **Whole-tree total recomputed 2026-09-06** — the pass over every
> subtree this note used to say was needed.
>
> The per-package sections further down were written 2026-08-15 and
> spot-checked 2026-09-06. Their COVERAGE figures are exact, not
> floors: crypto 1722/1722, net/http 639/639 across twelve packages,
> testing 217/247, all reproduced to the digit. Their ANCHOR counts
> had drifted and are corrected — those move with every commit
> touching an anchored file, which is why a ratio is worth quoting and
> a count is not.

## The whole tree — 5102 / 11142 functions (45.8%)

Across the 165 packages of the Go 1.25.5 standard library that have a
goish port: **110 are at 100%**. Was 4452 / 11061 (40.3%) across 169
packages with 89 at 100% on 2026-08-15.

**Two denominators, and they are not interchangeable.** The figure
above counts only packages that HAVE a port, which is what the older
number counted and the only basis on which the two can be compared.
Counting every package `port_coverage.py` can see, ported or not, the
same 5102 functions are **5102 / 14699 = 34.7% across 314 packages** —
a lower percentage from a larger denominator, not a regression. Quoting
one against the other would say coverage fell in a month when it rose.

Reproduce both rather than citing these: run
`scripts/port_coverage.py <subtree> --json` over the entries in `src/`
and sum, filtering on `ported > 0` for the first figure and not for the
second.

The anchors are not spread evenly, and that is the single most
important thing on this page. `crypto/`, `net/` and `testing/` together
held **92%** of them at the last refresh; on 2026-09-06 they hold
**58%** (3638 of 6284). The concentration has broken up because the
rest of the tree gained anchors, not because those three lost any.

The ratio is the durable fact; the two counts drift with every commit
that touches an anchored file, so re-count them rather than quoting
these — `grep -rc "// go: sdk" src/` does it.

Coverage says a name exists; an anchor is what lets goishlint diff the
port against the Go file it came from. The corollary is the one
ROADMAP.md 2b is about: a file with NO anchor is not merely unmeasured,
it is invisible to every tier here, and reading three such files
against their Go on 2026-09-04 produced eight defects across four
packages.

| subtree | ported | % | anchors |
|---|--:|--:|--:|
| `crypto` | 1431/1447 | 98.9% | **3059** |
| `net` | 966/1413 | 68.4% | **2071** |
| `math` | 333/661 | 50.4% | 155 |
| `testing` | 217/247 | 87.9% | 449 |
| `encoding` | 234/999 | 23.4% | 407 |
| `compress` | 150/150 | 100.0% | 303 |
| `os` | 148/366 | 40.4% | 127 |
| `bytes` | 107/107 | 100.0% | 149 |
| `strings` | 98/98 | 100.0% | 154 |
| `archive` | 79/182 | 43.4% | 160 |
| `time` | 107/184 | 58.2% | 234 |
| `sync` | 68/126 | 54.0% | 148 |
| `hash` | 98/114 | 86.0% | 338 |
| `mime` | 73/89 | 82.0% | 113 |
| `bufio` | 48/48 | 100.0% | 81 |
| `unicode` | 52/52 | 100.0% | 131 |
| `io` | 74/79 | 93.7% | 206 |
| `text` | 47/271 | 17.3% | 82 |
| `runtime` | 88/2722 | 3.2% | 40 |

Every row above was regenerated with `scripts/port_coverage.py` on
2026-09-05. Four rows carried figures that were not merely stale but
misleading: `net` was recorded at 55.8% and is 68.4%, `os` at 30.6% and
is 40.4%, `time` at 38.6% and is 58.2%, and `archive` at 39.0% with
**0 anchors** where it now has 160 — archive/tar's sparse half landed
in between.

`io`, `text` and `runtime` are new rows; they were large enough to
matter and were simply absent.

Within `net`, the entire jump since the last refresh is **`net/http`,
now complete: 639/639 functions (100.0%) across all twelve of its
packages, with 1476 `// go:` lines** — see its section below.

So: `math` at 46.4% and `crypto/x509` at 100% are not comparable
claims. The first means 307 functions share a name with Go's; the second
means 158 functions were each diffed against the Go source and their
outputs checked byte-for-byte against a running Go. Treat unanchored
subtrees as working code, not as verified ports.

`compress` used to be the clearest illustration of the gap, because
both halves were visible inside one subtree. It no longer is: as of
2026-08-30 the whole subtree is anchored. The paragraph below is kept
because the *shape* of the problem it describes is still what the rest
of the tree looks like. Its 42 `// go:` lines — 34 of them
`sdk` anchors — are **all** in `compress/bzip2`, ported 2026-08-17:
20/20 functions by name and by declaration, every one citing
its Go file and line range, and checked against Go's own test vectors
plus seven `testdata/` corpora — 567 KB of English text, 16 KB of
random bytes, a 1 MiB sawtooth and the issue-5747 overrun case — all
byte-identical to a running Go. `flate`, `gzip`, `lzw` and `zlib` carried
122 name-level ports and zero anchors between them. Same subtree, same
percentage column, two different claims.

`flate` has since been split the way `bzip2` already was, one Go file
at a time: **all seven of its Go files are now their own
anchored files**, with 161 anchors between them and zero unverified
names. `src/compress/flate/mod.rs` is module wiring plus one
goish-only test shim, and the whole package is goishlint-clean. The
recovered declarations are the ones that had been inlined or replaced
by a Rust idiom — `writeSlice`/`writeMark` at the decompressor's call
site, and `byLiteral`/`byFreq`'s `sort`/`Len`/`Less`/`Swap`, which had
been two `sort_by` closures. `flate` is 91/91 now — complete, with
`makeReader` waived: Go decides at run time whether its source already
satisfies `flate.Reader` and wraps it in a `bufio.Reader` if not, while
goish's `Decompressor<R>` is generic over that bound, so the choice is
made at compile time by which constructor is called. `compress/zlib`, `compress/gzip` and `compress/lzw` followed the same
day, each split into its two Go files and anchored. **`compress` is now
150/150 with 303 anchors and zero unverified names** — the first
multi-package subtree in the tree where every counted name is one
goishlint can diff against Go, and where every `.rs` file ports exactly
one `.go` file.

Both halves are checked against a running Go rather than against
themselves. Six DEFLATE streams from Go's own compressor — chosen to
drive `dist < length` run-length expansion, the 32 KiB window wrap and
`readFlush`'s cursor reset — inflate to 236 KB that matches byte for
byte; and in the other direction goish's compressor at
DefaultCompression emits **byte-identical output to Go's** for all six,
which is the only check that reaches the Huffman generator's output
rather than its round-trip. Nothing in the format requires two
compressors to agree, so that is a statement about the port, not about
DEFLATE.

`hash` moved for the same reason and in the same shape. **`hash/crc64`
(19/19, 49 `// go:` lines), `hash/adler32` (13/13, 34) and `hash/fnv`
(17/17, 162) are complete and anchored, and `hash/crc32` is 29/33
(87.9%, 71)** — ported 2026-08-30. In each case that is the whole of
every portable Go file in the package, including the fast paths, the
128-bit FNV pair, and the marshal/unmarshal/Clone surface the earlier
slim ports had skipped. None of the four is a name match: `crc64`'s
`Checksum` is checked byte-for-byte against a running Go at eight
lengths straddling both of Go's path thresholds (64 bytes and 2048)
for ISO, ECMA and a custom polynomial, `crc32`'s at nine straddling
its `slicing8Cutoff` of 16 for IEEE, Castagnoli and Koopman,
`adler32`'s at ten straddling its `nmax`=5552 block boundary, `fnv`'s
128-bit digests over six inputs, and every marshaled state — the crc32
and crc64 table checksums included — matches Go's byte for byte.

`crc32`'s remaining 4 are all of crc32_amd64.go: three assembly
symbols (`castagnoliSSE42`, `castagnoliSSE42Triple`, `ieeeCLMUL`) and
`castagnoliShift`, which exists only to feed them. goish ports
crc32_otherarch.go — the `!amd64` half of Go's own build — instead, so
"no hardware CRC-32" is a true statement about this runtime rather
than a stub. `maphash` (20/32) is the one `hash` package still short,
blocked on `internal/abi`.

`encoding/pem` moved the same way, and is the clearest small case of
why the anchor column is the one to read. It counted 5/8 and carried
**zero** anchors: every name in it matched Go by name only, so a
dropped argument or an invented body would have been invisible to
GOISH018. It is now 8/8 with 18 anchors — the three that were missing
are `lineBreaker`'s `Write` and `Close` and `writeHeader`, i.e. the
whole of the 64-column line-breaking Encode does — and its output is
checked byte-for-byte against a running Go on either side of a line
boundary, over the RFC 1421 §4.6.1.1 header ordering, and through
`Decode` over leading junk, trailing junk and an unterminated BEGIN.

`container/list` is the same story one size smaller: 20/23 with zero
anchors, now 23/23 with 35. The three that were missing were `lazyInit`,
`insertValue` and `move` — the whole of the link surgery every public
method funnels through — and its element order is now replayed against
a running Go step by step, including the no-ops Go documents for a
foreign element and for moving an element relative to itself. `ring` (17
anchors) and `heap` (15) followed the same day, so the subtree is
38/38 with **67 anchors and zero unverified names** — the first whole
subtree in the tree where every counted name is one goishlint can diff
against Go.

**`text/scanner` is a new package, ported from scratch on 2026-08-30:
28/28 with 54 anchors and zero unverified names.** It is the first port
in a while that was not a repair, and it is checked the way a repair
would be: six sources are tokenised to EOF and every token is compared
with a running Go as a `kind|text|line:column` triple — 69 tokens in
all, plus the error counts, so a wrong token kind, a wrong token text
and a wrong position each fail separately. The cases cover Go source
with every literal form, ident-only and comment-keeping modes, fourteen
numeric literals of which five are malformed, unterminated string, char
and raw-string literals, and non-ASCII identifiers and comments.

The one bug the comparison caught was Rust's, not the port's: Go's
`for s.Whitespace&(1<<uint(ch)) != 0` shifts by `uint(-1)` at EOF, which
Go defines as 0, and Rust panics on. The width test is now written out
with the reason next to it.

`text/tabwriter` is the fourth in the same sweep: 17/20 with zero
anchors, now 19/19 with 26 and one declaration waived. The waived one
is `handlePanic`, and it is the honest kind — Go's is a deferred
`recover()` that turns a `panic(osError{err})` thrown deep inside
`format` back into a returned error, and goish v1 aborts on panic
rather than unwinding, so there is nothing to build it on. The error it
carries travels in a latched field instead. Recovered along the way:
`append`, `dump`, and the `vbar`/`hbar` package vars, which had been
inlined as literals. Its output is now checked byte-for-byte against a
running Go across sixteen layouts — every flag, both escape modes, a
ragged table, a form feed and non-ASCII cells.

`encoding/hex` (17/17, 25 anchors) and `encoding/ascii85` (9/9, 15)
followed, and hex is the one that repaid the anchoring immediately.
Its `InvalidByteError` message was `encoding/hex: invalid byte: 0x67`
where Go's is `encoding/hex: invalid byte: U+0067 'g'` — Go formats the
byte with `%#U`. A second helper produced a *third* spelling, in
decimal. All three were plausible, none matched, and nothing could see
it until the port was diffed against a running Go. The typed error now
formats `%#U` and the helper routes through it.

`encoding/csv` (17/17, 25 anchors) went the same way, and the
comparison corrected the *documentation* rather than the code: its
writer quotes a field whose first rune is white space but not one that
ends in white space, which is asymmetric enough that a header comment
claiming otherwise had to be rewritten twice before it matched what Go
and the port both do.

`encoding/base64` was 15/21 and is now **21/21 with 32 anchors**. The
six that were missing were the whole configurable half of the package —
`NewEncoding` for a runtime alphabet, `WithPadding`, `Strict` — plus
the decoder internals `decodeQuantum`, `assemble32` and `assemble64`.
The old decoder ignored the configured padding character entirely, did
not enforce padding at all ("not strictly enforced in v1", said the
comment) and had no strict mode; it now runs Go's three-loop `Decode`
with the fast paths bailing to `decodeQuantum`, and its error offsets
match Go's on fourteen malformed inputs.

`encoding/base32` was 12/20 with zero anchors and is now **20/20 with
42 anchors**, split into a module root and a `base32.rs` that ports
base32.go whole. The eight missing declarations were the entire
streaming half — `NewEncoder`/`Write`/`Close`, `NewDecoder`/`Read`,
`readEncodedData`, `stripNewlines` — plus `WithPadding`, and every one
of them was blocked until `io.WriteCloser` landed. `NewEncoding` is now
a `const fn`, so `StdEncoding` and `HexEncoding` are `static`s rather
than lock-guarded functions rebuilt on every call, which is what Go's
package-level `var`s are.

The streaming decoder is where the fidelity is. `readEncodedData`
turns a short read at EOF into `io.ErrUnexpectedEOF`, but only for a
padded encoding — an unpadded message may end on any byte — and the
distinction is invisible from the one-shot API. All four encodings
(std, hex, unpadded, and one with a `'.'` pad character) are now
checked against a running Go: the one-shot vectors, both length
formulas across a full quantum, a byte-at-a-time `NewEncoder` so every
five-byte boundary falls inside a `Write`, a `NewDecoder` round-trip
through `io::ReadAll`, CRLF interleaved every three characters, three
truncated inputs, and four `CorruptInputError` offsets.

`mime/quotedprintable` is the first of the `mime` subtree to be
anchored: 7/15 with zero anchors, now **15/15 with 29**, split into a
`reader.rs` and a `writer.rs` so each ports exactly one Go file. All
eight missing declarations were the writer's internals — `write`,
`encode`, `checkLastByte`, `insertSoftLineBreak`, `insertCRLF` — and the
reader's `fromHex`, `readHexByte` and `isQPDiscardWhitespace`; the code
existed under invented snake_case names, so a name-matching counter
could not see it and goishlint could not diff it.

What the anchoring caught was the error text, again. Both of the
reader's errors had been flattened: `fmt.Errorf("quotedprintable:
invalid hex byte 0x%02x", b)` had become a constant with no byte in it,
and `"invalid bytes after =: %q"` had lost its `%q` payload. A caller
matching on the message would have failed against both. All three texts
are now produced by `fmt::Errorf!` with Go's verbs and checked
character-for-character, which also confirms goish's `%02x` and `%q`
agree with Go's on these inputs.

The decoder is mostly a catalogue of what it tolerates — Go documents
four deviations from RFC 2045, all leniency — so the smoke is 35 decode
vectors from a running Go, most of them malformed, plus thirteen encode
vectors run twice (once per `Write`, once per byte), the 76-column rule
at four lengths, the whitespace-before-a-soft-break case, and the
`checkLastByte` rule that re-encodes a trailing space or tab. `qp_smoke`
is now declared in Cargo.toml — it never was, so e2e had never run it.

`mime/multipart`'s writer half followed: 18/36 with 8 anchors is now
24/36 with 29, and writer.go is complete. The six that were missing
were `CreatePart` and everything that hangs off it — `CreateFormFile`,
`CreateFormField`, `escapeQuotes`, `randomBoundary`, and the `part`
type with its `Write` and `close`. goish had gone around the problem
instead: `CreatePart` returns an `io.Writer` backed by a `*part` that
holds a back-pointer to its `*Writer`, and a Rust struct cannot hold
that, so the port had replaced the whole idea with a `WritePart(header,
body)` that took the body up front.

`part` is now a *borrow* of the Writer, and the two fields that have to
outlive the handle — `closed` and the last write error — live in
`Writer.lastpart`, which is the field Go reaches them through anyway.
That turns Go's documented rule ("after calling CreatePart, any
previous part may no longer be written to") from a runtime error into a
borrow-checker error: the old handle cannot still be alive. The one Go
behaviour that becomes untestable as a result is the
"multipart: can't write to finished part" message, and the smoke says
so where the check would have been.

`WritePart` and `WriteFile` stay as goish-only conveniences, anchored
`// go: none`, because `net/http/fs.rs` emits a headers-only part
through the first one. The whole message is now compared byte-for-byte
against a running Go — two fields, a file part and a raw part whose
headers were set out of order, since Go emits header keys sorted and
repeated values in insertion order — along with the twelve-case
`SetBoundary` table (a space is legal anywhere but the last byte) and
`FormDataContentType`'s tspecials quoting.

`mime` itself came next — grammar.go and mediatype.go, split out of a
512-line `mod.rs` into `grammar.rs` and `mediatype.rs`, taking the
package from 12/38 with zero anchors to 22/38 with 19. The ten that
were missing were all of RFC 2231: `decode2231Enc`,
`percentHexUnescape`, `ishex`, `unhex`, `consumeValue`,
`consumeMediaParam`, `checkMediaTypeDisposition`, `ishex`'s callers,
and the two character-class predicates. The old `ParseMediaType` had
no continuation handling at all and the old `FormatMediaType` said so
in its own doc comment: "skips RFC 2231 percent-encoding for non-ASCII
parameter values".

That matters because none of RFC 2231 is reachable from an ordinary
Content-Type. A parameter value may be split across `name*0`, `name*1`,
… and any piece may be percent-encoded by a further `*` suffix, with
the charset carried on the first piece only — so `title*0*=us-ascii'en'…;
title*1=more%20; title*2*=…` stitches into one value in which `more%20`
stays percent-encoded, because piece 1 has no trailing star. goish now
does exactly that, and `attachment; filename*=UTF-8''foo-%c3%a4.html`
decodes.

grammar.go is the one place the port could not be literal. Go writes
both character classes as 128-bit constant bitmaps and tests a byte
with `(1<<c)&low | (1<<(c-64))&high`, relying on Go's rule that a shift
of 64 or more is zero — which is how `c >= 128` falls out as false with
no range check, and how `c-64` wrapping for small `c` does no harm.
Rust panics on both, so the halves are selected by a comparison and the
constants are kept verbatim. The smoke counts the whole 0..255 domain
of each class (15 tspecials, 79 token characters) so a mistranscribed
bit cannot hide.

Checked against a running Go: 40 `ParseMediaType` vectors — type,
parameter map and error text each compared separately — and 14
`FormatMediaType` vectors, including the `charset*=utf-8''%C3%A4` form
a non-ASCII value forces. `mime_parse_smoke`, `mime_extensions_smoke`
and `mime_multipart_reader_smoke` are now declared in Cargo.toml; none
of the three ever was.

`mime/encodedword.go` followed, and it was pure anchoring: all twelve
"missing" declarations already existed under invented snake_case names
— `bEncode`, `qEncode`, `writeQString`, `openWord`, `closeWord`,
`splitWord`, `qDecode`, `readHexByte`, `fromHex`, `hasNonWhitespace`,
`isUTF8`, `needsEncoding` — so a name-matching counter read 12/38 for
a file that was substantially complete. It is 34/38 with 47 anchors
now, and only type.go's OS mime-database half is left.

The diff against Go found the error text, for the third time this
cycle. `fromHex` was hand-rolled against an upper-case hex table and
said `mime: invalid hex byte 0x5A`, where Go's
`fmt.Errorf("mime: invalid hex byte %#02x", b)` says `0x5a`. It now
goes through `fmt::Errorf!`.

RFC 2047 caps an encoded-word at 75 characters, so a long UTF-8 value
is split across several and a multi-byte rune must never straddle the
join — which is the entire reason `bEncode` and `qEncode` are separate
from the one-word case, and is invisible to any test that encodes short
ASCII. `encodedword_smoke` now carries Go's exact output for "é"×40,
"a"×100+"é" and "日"×30 under both encoders, plus 17 `Decode` vectors
with their error texts and 13 `DecodeHeader` vectors — including the
rule that a word which fails to decode is copied through verbatim and
is still not an error, and that only *white space* between two words is
deleted. It is now declared in Cargo.toml; it never was.

`bufio` is now **48/48 with 81 anchors** and completely goishlint-clean
— the fourth package after `compress`, `container` and
`mime/quotedprintable` to be finished rather than merely covered. It had
read 42/48 with 7 anchors from a single 1374-line `mod.rs`; it is now a
module root plus `bufio.rs` and `scan.rs`, one per Go file, with Go's
two `var` sentinel blocks living in the file that declares them.

Six declarations were "missing" and five of those were renames —
`readErr`, `setErr`, `writeBuf` — or code inlined at its one call site:
`collectFragments` was spelled out inside `ReadBytes`, and `dropCR`
inside `ScanLines`. The sixth was a real defect.

`isSpace` was an ASCII-only `matches!` over six bytes, and `ScanWords`
walked its input a **byte** at a time. Go's `isSpace` is a rune
predicate with its own table — scan.go carries a copy rather than pull
in the unicode tables — covering NBSP (U+00A0), NEL (U+0085), the whole
U+2000..U+200A run, OGHAM SPACE MARK, LINE and PARAGRAPH SEPARATOR,
NARROW NBSP, MEDIUM MATHEMATICAL SPACE and IDEOGRAPHIC SPACE. So goish's
`ScanWords` did not split on any of them, and its advance was `i + 1`
where Go's is `i + width`, which would have left the tail bytes of a
multi-byte space in the next token. Both loops now step by rune width,
and the smoke checks all ten separators against a running Go.

Getting the reference needed one twist worth recording: `testing`
imports `bufio`, so `scripts/goref.sh`'s in-package test file is an
import cycle here. `tools/gen_bufio_ref.go` is `package bufio_test`
instead, which is legal in the same directory and is how Go's own
bufio tests are written.

`unicode/utf8` is **17/17 with 36 anchors**, split out of a module root
into `utf8.rs`. It had read 15/17 with zero anchors, and the two that
were missing — `encodeRuneNonASCII` and `appendRuneNonASCII` — were the
non-ASCII halves Go factors out so the ASCII path stays inlineable. The
port had folded them into a validate-then-encode `EncodeRune`, which
gets the same answer by a different route; both now follow Go's shape,
where a negative rune is made unsigned so it falls into the same default
arm as an out-of-range one. Go's whole constant set (`tx`, `t2`..`t4`,
`maskx`, `rune1Max`..`rune3Max`, `runeErrorByte0`..`2`) came with them.

The decoder needed no change, and proving that was the point. It is now
checked against a running Go on 27 inputs, all but nine of them
malformed: overlong encodings of NUL, U+007F, U+0800 and U+10000; both
ends of the surrogate block; two values above U+10FFFF; the 0xFE and
0xFF bytes that can never appear; and truncated two-, three- and
four-byte sequences. Every one returns `(RuneError, 1)` — the size-1
part being what stops a caller looping forever — and `FullRune`
separates "truncated" from "invalid but complete" on the same table.
`EncodeRune`, `AppendRune`, `RuneLen` and `ValidRune` are checked on 20
runes covering every boundary of the surrogate block and both sides of
U+10FFFF.

`tools/gen_utf8_ref.go` is `package utf8_test`, for the same reason
`gen_bufio_ref.go` is: `testing` reaches `unicode/utf8`, so an
in-package ref file is an import cycle.

`unicode/utf16` was already 8/8 — and wrong. Anchoring it, splitting it
into `utf16.rs` and diffing it against a running Go turned up a
precedence bug that had silently broken every code point from **U+20000
upward**.

Go's `DecodeRune` ends with

    return (r1-surr1)<<10 | (r2 - surr2) + surrSelf

and in Go `|` and `+` share the additive precedence level and associate
left to right, so that reads `(((r1-surr1)<<10) | (r2-surr2)) +
surrSelf`. Rust binds `+` tighter than `|`, so the same characters mean
`x | (y + surrSelf)` — which ORs the 0x10000 bit into a position the
shifted high half already occupies, and loses it. Below U+20000 the
high half is small enough that the bit survives, which is why every
emoji (U+1F600 and friends) round-tripped and nothing noticed. `DecodeRune(0xDBFF,
0xDFFF)` returned U+FFFFF instead of U+10FFFF.

The same expression is the tail of `Decode`, so the whole
supplementary-plane-2-and-up range was affected — including CJK
Extension B, which `crypto/x509` and `encoding/asn1` can both carry in
a BMPString. A grep for the same `A | B + C` shape across the tree found
no other instance: every other `|`-with-`+` has the `+` inside an index
expression, where it is unambiguous.

utf16 is now 8/8 with 16 anchors, checked against Go on 17 runes,
9 surrogate pairs, 9 `Encode` round-trips and 8 raw `Decode` sequences
the encoder would never emit.

`unicode` itself is now **48/52 with 111 anchors**, split into
`graphic.rs`, `letter.rs`, `digit.rs` and one merged `tables.rs`. It had
been a documented approximation, and the documentation was honest about
it — `IsTitle` was a stub returning `false` with a note that "multi-byte
titlecase codepoints like U+01C5 require Unicode tables not yet
shipped", `IsPunct` carried a caveat that it counted `^` and `` ` `` as
punctuation "for the slim path", and `IsUpper`/`IsLower`/`IsDigit` were
ASCII-only. `IsSymbol`, `IsOneOf` and `isExcludingLatin` did not exist.

The fix is the data. Go's Latin-1 `properties` bit array — 256 entries —
plus the `_P`, `_S`, `_Lt`, `_Lu`, `_Ll`, `_Nd` and `_White_Space` range
tables were transcribed from Go's tables.go, and every predicate is now
Go's own two-step: a bit test below U+0100, `isExcludingLatin` above it.
That corrects, among others: `^` and `` ` `` are Symbol, not Punct;
U+00A1 is Punct while U+00A2 is Symbol; U+00AA, U+00B5 and U+00BA are
letters; U+00A0 is Graphic but not Print; U+0660 and U+0966 are digits;
U+2160 and U+2070 are numbers but not digits; U+2028 is a space but
U+200B is not; and the six title-case letters are title-case.

`unicode_graphic_ref_smoke` checks all 256 Latin-1 code points against
thirteen predicates at once as a bitmask, then the population count of
each predicate over a fixed 128k-rune sample of the whole domain —
every rune below U+10000 plus every 17th above it. A transcribed table
that is short a range, or carries an extra one, moves exactly one of
those thirteen numbers, and all thirteen match Go.

The case machinery followed in the same cycle, so **`unicode` is
52/52 — the fifth package finished rather than merely covered.** Go's
`CaseRanges` (328 ranges, each an upper/lower/title delta triple) is
transcribed, and `To`, `to`, `convertCase` and `lookupCaseRange` are
ported, along with `CaseRange`, `SpecialCase`, the four case indices and
`casetables.go`'s `TurkishCase`/`AzeriCase`.

`convertCase` is the part a flat rune-to-rune table hides. A range whose
delta is `UpperLower` is an alternating `Upper Lower Upper Lower …`
sequence, and the mapping comes from the *parity of the offset* within
the range rather than a fixed shift — Go clears or sets the low bit of
the offset, taking the bit from the case index, which works because
`UpperCase` and `TitleCase` are even while `LowerCase` is odd.
U+01C4..U+01C6 is one such range, and it is also a title-case triple:
`ToTitle(0x01C4)` is 0x01C5, not 0x01C4.

`unicode_case_ref_smoke` checks 46 spot mappings across all four
functions, then a checksum of `ToUpper`/`ToLower`/`ToTitle` over the same
128k-rune sample the graphic smoke uses. All three checksums match Go
exactly, which is the strongest statement available that 328
transcribed ranges carry the same deltas Go's do.

`strings/replace.go` and `strings/search.go` are ported whole, taking
`strings` from 76/101 with **one** anchor to 83/101 with 36. The
`Replacer` that was there described itself as a "slim port … linear
scan-and-replace … sufficient for HTTP-style sanitization", and it was
missing three things Go has: `WriteString`, any handling of an empty
`old` string, and the algorithm selection.

Go's `NewReplacer` does not replace anything — `build` picks one of
four implementations from the shape of the arguments: Boyer-Moore
(`search.go`, ported here too) for a single multi-byte pattern, a
256-byte translation table when every old *and* new is one byte, a
256-entry table of slices when only the olds are, and a trie otherwise.

The trie is the part a linear scan cannot reproduce. Keys are matched
neither shortest- nor longest-first: each carries a priority, higher
for an earlier argument, and `lookup` walks the whole path taking the
highest-priority complete key it passes. `("a","1","ab","2")` turns
"ab" into "1b" while `("ab","2","a","1")` turns it into "2" — which a
first-match scan also gets right — but
`("abc","1","abd","2","ab","3")` turns "abc" into "1" and "abe" into
"3e", which it does not. And `("", "X")` on "ab" is "XaXbX": the old
code's `!ob.is_empty()` guard dropped empty patterns silently.

`strings_replacer_smoke` runs 70 vectors from a running Go across all
four algorithms, checking `Replace`, `WriteString`'s bytes and
`WriteString`'s returned count, plus the priority rule, the empty
pattern, the first-pair-wins rule for a repeated old, and the
no-overlapping-matches rule.

One Rust-specific bug turned up on the way: `byteStringReplacer.Replace`
sizes its output with `newSize += len(rep) - 1`, which goes negative in
Go's `int` when a replacement is shorter than the byte it replaces, and
underflows a `usize`. Replacing `"b"` with `""` panicked before the
`int` was restored.

**Seven of the eight long-standing `net/http` e2e failures were one
bug**, and it was in `httptest.Server.Close`. Every one of them ended
the same way — `httptest.Server blocked in Close after 5 seconds,
waiting for connections: fd N in state idle` — after all of the
example's own assertions had passed.

Go's `Close` force-closes every StateIdle and StateNew conn, and its
netpoller wakes whichever goroutine is parked reading them. goish's
`closeConn` called `shutdown(2)` on the fd instead, on the reasoning
that shutdown wakes a blocked reader. It does — a reader blocked in the
*syscall*. A goish keep-alive conn between requests is parked in the
**netpoller**, which `shutdown` does not notify, so the conn stayed
idle and `Close` waited forever.

The http server already had the right mechanism for this and had
written down why: `closeIdleConns` slams the read deadline into the past
(goish's `aLongTimeAgo`), the parked read returns a timeout, and the
*serve loop* closes its own fd — so an fd always has exactly one
closer. `httptest` now asks for the same kick through
`Server.__kick_conn_fd`, and keeps the `shutdown` so the peer still sees
the connection end.

`http_client_reuse`, `http_connstate`, `http_expect_continue`,
`http_httptest_server`, `http_pprof`, `http_transferwriter` and
`http_url_userinfo` all pass now; the `[h-n]` slice is 186/187.
`http_closenotify_smoke` is the eighth and is a different defect —
CloseNotify does not fire when the client goes away mid-handler, and
the request context is not cancelled by that event either.

`strings/strings.go`'s cutset trim family followed, taking `strings`
from 83/101 to **96/98 with 59 anchors** — 98%, with three declarations
waived out of the denominator. `strings.rs` is the first slice of
strings.go to move out of the module root.

`Trim`, `TrimLeft` and `TrimRight` had been a single rune-decoding
scan. Go dispatches three ways on the shape of the cutset, and the
dispatch is the point: a one-byte ASCII cutset is a byte comparison, an
all-ASCII cutset becomes a 128-bit bitmap (`asciiSet`) tested with a
shift and an and, and only a cutset holding a non-ASCII rune pays for
decoding. All six helpers — `trimLeftByte`/`ASCII`/`Unicode` and their
right-hand twins — plus `makeASCIISet` and `asciiSet.contains` are
ported, and the three paths are checked to agree on 168 vectors: twelve
cutsets crossed with fourteen inputs, including a cutset byte that is
also a UTF-8 continuation byte, a multi-byte cutset rune, an input that
is entirely cutset, and invalid UTF-8.

`ToUpperSpecial`, `ToLowerSpecial` and `ToTitleSpecial` are new, and
were unportable until `unicode::SpecialCase` landed an hour earlier.
They are checked against Go on the runes Turkish moves: `'i'`
upper-cases to the dotted U+0130 and `'I'` lower-cases to the dotless
U+0131, while the plain mappings do neither.

Two stale section headers went with them. `ToUpper`/`ToLower` were
labelled "ASCII-only for v1" and `EqualFold` the same; both had in fact
routed through `unicode` for some time, and both are now *correct* as
well as routed, since `unicode` reached 52/52. `ToTitle`'s doc claimed
non-ASCII runes "pass through unchanged until the SpecialCasing tables
ship" — they have, so U+01C4 maps to U+01C5. The smoke pins all of it,
including `EqualFold` walking the fold orbit so `'K'` equals U+212A
KELVIN SIGN and the two sigmas equal each other.

Waived, with reasons: `copyCheck` (Go's `Builder` holds an `addr
*Builder` self pointer and panics when it finds itself copied; a goish
`Builder` owns its `Vec` and a copy is a deep copy, so there is no
aliasing to detect), `buildOnce` and `getStringWriter`.

`strings/iter.go` closed the package: **`strings` is 98/98 with 67
anchors**, three declarations waived, and `iter.rs` is its second file
out of the module root.

`FieldsSeq` and `FieldsFuncSeq` were the last two missing. Each yields
exactly what its slice-building twin returns without building the
slice, so every vector is checked twice — against Go, and against
`Fields`/`FieldsFunc`/`Split`/`SplitAfter` on the same input. Three of
the field cases split on a non-ASCII space (NBSP, LINE SEPARATOR,
IDEOGRAPHIC SPACE), which reaches `unicode::IsSpace` rather than an
ASCII table — the same distinction that was wrong in `bufio`'s
`ScanWords`.

The check that matters most is the last one: a `yield` returning
`false` has to stop the walk. That is the entire reason these return an
iterator rather than a slice, and a port that eagerly collected and
then replayed would pass every other vector and fail only this one.
Both `SplitSeq` and `FieldsSeq` are stopped after two elements and
compared against what Go's `break` inside a `range` produces.

`strings`' four remaining single-file units — builder.go, reader.go,
clone.go and compare.go — came out of the module root next, taking the
package from 67 anchors to **101** with no change in coverage: every
one of those declarations was already there, matched by name and proven
by nothing.

Diffing them against Go found the defect that pattern keeps finding.
`Builder::Grow(n)` computed the headroom it already had and reserved
only the difference:

    let avail = capacity - len;
    if extra > avail { buf.reserve(extra - avail) }

But Rust's `Vec::reserve(additional)` already means "room for
`additional` more past the current length" — it is the whole of Go's
`Grow`, and subtracting `avail` first under-reserves by exactly that
amount. `Grow(64)` on a Builder holding "abc" with capacity 8 reserved
56 and left `Cap()` at 56, so a caller who grew specifically to avoid a
reallocation still got one. Go's contract is "after Grow(n), at least n
bytes can be written without another allocation".

`Reader` needed no change, and the point of the exercise was proving
that. Its behaviour is all in the edges — `UnreadByte` and `UnreadRune`
are errors unless they directly follow the matching read, `prevRune` is
invalidated by every other operation so an `UnreadRune` after a
`ReadByte` fails, `Seek` accepts a position past the end but not a
negative one, and `ReadAt` never moves the cursor — and the rest of the
tree only ever reads it to exhaustion. All of it, including the six
exact error strings, now matches a running Go.

The rest of strings.go followed, and **`strings` is now split one Rust
file per Go file end to end** — 153 anchors, and a `mod.rs` that is 81
lines of `mod`, `pub use` and one registration hook. Every one of its
98 declarations is anchored to the Go lines it came from; none is a
name match any more.

The move carried 42 more functions into `strings.rs` and forced the
nine goish-only helpers underneath them to say what they are: four
borrowed-bytes scanners standing in for `bytealg`'s assembly
(`index_byte`, `index_bytes`, `last_index_bytes`, `count_bytes`), two
byte-level prefix/suffix tests the trim helpers and the Boyer-Moore
finder share, `is_ascii_space` for the `asciiSpace` array Go indexes,
`map_runes` for the non-ASCII tail of `ToUpper`/`ToLower`, and `sub`
for `s[low:high]` — free in Go, an allocation here.

A 42-line header claiming the package was a "subset for M10 launch —
the most-used operations" went with it. It has not been a subset for
some time.

`bytes` is the same shape `strings` was in when this cycle started —
84/107 with **one** anchor — and it is being taken the same way. Its
`iter.go` was absent entirely: `Lines`, `SplitSeq`, `SplitAfterSeq`,
`FieldsSeq`, `FieldsFuncSeq` and the shared `splitSeq` are all new, in
their own `iter.rs`. 90/107 with 8 anchors now.

Go full-slices every fragment these yield — `s[:i:i]`, capping capacity
at length — so a caller who appends to a yielded line cannot write into
the bytes of the next one. A goish `slice<byte>` handed out of an
iterator already owns its bytes, so the aliasing that three-index
slicing defends against cannot arise; the values yielded are identical,
and the file says so rather than dropping the `:i` silently.

Checked against Go the same way `strings/iter.go` was: every vector
twice, once against the Seq and once against `Split`/`SplitAfter`/
`Fields`/`FieldsFunc`, plus the early-stop rule for all three of
`SplitSeq`, `FieldsSeq` and `Lines`. `Lines` is the one that separates
the two packages' empty cases — it yields nothing for an empty slice
where `SplitSeq` yields one empty fragment.

`bytes/bytes.go`'s trim family and case mappings followed, taking
`bytes` to **100/107 with 31 anchors**, and turning up two defects.

**The cutset was matched byte-wise, not rune-wise.** Go's cutset is a
`string` decoded as runes: `Trim(s, "é")` strips the two-byte é, not
the bytes 0xC3 and 0xA9 wherever they turn up. goish's loop asked
`cutset.contains(&byte)`, so a lone 0xC3 at the head of a slice — a
continuation byte belonging to no complete rune — was stripped under
cutset "é", and so was a pair of bare 0xA9s. Go leaves all of them
alone. The three-way dispatch is ported now: one ASCII byte is a byte
comparison, an all-ASCII cutset a 128-bit bitmap, and only a cutset
holding a non-ASCII rune pays for decoding.

**`ToUpper` and `ToLower` were ASCII-only.** The loop upper-cased
'a'..'z' and passed every byte at or above 0x80 through untouched, so
`ToUpper([]byte("café"))` came back "CAFé". Go takes the ASCII fast
path only when the *whole* slice is ASCII and otherwise maps rune-wise
through `unicode.ToUpper`. Both now do, and `ToTitle`'s claim that
non-ASCII bytes "pass through unchanged" is retired with them.

Go also returns a *copy* from the ASCII path even when nothing changes
— `append([]byte(""), s...)` — where goish returned the input handle.
That matters for a `[]byte` in a way it does not for a string: the
caller may write into the result. The copy is back.

192 trim vectors from a running Go — twelve cutsets crossed with
sixteen inputs, hitting all three dispatch paths — plus 80
TrimPrefix/TrimSuffix vectors, TrimSpace, and the Turkish special
cases.

`bytes/buffer.go` came out of the module root next — **104/107 with 73
anchors** — and with it the growth machinery that had been missing
entirely. `tryGrowByReslice`, `grow`, `growSlice` and `readSlice` are
all new, and `empty()` with them; Go's `Read`, `Next` and `ReadByte`
each branch on `empty()`, and goish had spelled that condition three
times instead.

The growth policy is three steps and only the last allocates: reset
when the buffer is logically empty but `off` has walked forward, try a
reslice into capacity already owned, then either slide the live bytes
down over the consumed prefix — worth it only when that alone buys
enough room — or double through `growSlice`. goish had `Grow` reserve
directly on the Vec and nothing else, so a Buffer written and drained
repeatedly never recovered the consumed prefix.

`bytes_buffer_smoke` pins the observable half against a running Go:
Len/Cap/Available across a write-drain-write cycle, `Grow(n)` leaving
Len alone while guaranteeing n bytes of headroom, `Next` past the end,
`WriteTo` from the read cursor, `ReadFrom`, and both exact refusal
messages —

    bytes.Buffer: UnreadByte: previous operation was not a successful read
    bytes.Buffer: UnreadRune: previous operation was not a successful ReadRune

— including the rule that a `ReadByte` between a `ReadRune` and an
`UnreadRune` invalidates the unread. `Truncate` is the one that catches
a port reading the wrong index: it counts from the start of the
*unread* portion, so on "abcdef" with two bytes already read,
`Truncate(1)` leaves "c".

`bytes_buffer_io_smoke` turned out never to have been declared in
Cargo.toml, so e2e had never run it. It is now.

**`bytes` is 107/107 with 91 anchors** — the seventh package finished
this cycle. `reader.go` came out of the module root, and the last three
declarations were renames of functions that had been there all along
under invented names: `genSplit`, `isSeparator` and `indexBytePortable`,
the last being Go's own portable `IndexByte` and exactly what goish had
written as `index_byte`.

`bytes.Reader` needed no change, and proving that was the point — the
rest of the tree only ever reads one to exhaustion. Its edges now match
a running Go: `UnreadByte`/`UnreadRune` refusing unless they directly
follow the matching read, `prevRune` invalidated by every other
operation, `Seek` taking a position past the end but not a negative one,
`ReadAt` never moving the cursor, and all six exact refusal messages —
which say "at beginning of slice" where the `strings` version says
"string".

`encoding/binary` is split rather than finished: varint.go is now its
own anchored `varint.rs` at 8/8 with 13 anchors, including the
`ReadUvarint`/`ReadVarint` pair that was missing, while binary.go's
half stays in `mod.rs`, still 15 unanchored names and still short the
reflection-driven `Encode`/`Decode`/`Size` surface. Both varint
overflow rules are now checked against a running Go, including the one
that refuses to read an eleventh byte at all
(golang.org/issue/41185) — a guard whose absence would be invisible
until it read past a buffer.

`iter` (0/4) and `database` (0/130) have directories but no ported
functions. `iter` is a squatter — goish fakes Go 1.23 iterator support
with slices wherever it is needed.

## crypto/ — 1722 / 1722 declarations (100.0%)

**All 66 crypto packages are at 100% by receiver-qualified
declaration**, with 26 declarations waived out of the denominator on
in-tree justifications (24 of them the QUIC transport surface). The
name-level counter reads 1431/1447 (98.9%) only because the QUIC
waiver is recorded per declaration: the 16 residual *names*
(`quicSetReadSecret`, `HandleData`, …) are exactly that waived
surface. There is no unported non-QUIC function left.

| | |
|---|--:|
| ported (by declaration) | 1722 |
| remaining, portable | 0 |
| remaining, assembly stubs | 0 |
| waived (resolved elsewhere by design) | 26 |
| provenance anchors | 3041 |
| unverified names (see below) | 0 |

Complete and byte-checked against Go: `tls` (the full client and
server handshakes — `handshake_loopback` runs the ported client and
server against each other), `x509` (158/158 by name, 169/169 by
declaration), `ecdsa`,
`ecdh`, `rsa`, `elliptic`, `cipher`, `aes`, `sha1/256/512/3`, `hmac`,
`hkdf`, `pbkdf2`, `mlkem`, `nistec` + `fiat`, `bigmod`,
`edwards25519`, `ed25519`, `dsa`, `rand`, `sysrand`, `drbg`, `entropy`,
`x509/pkix`, `tls12`/`tls13` key schedules, and the rest of the
`fips140` tree.

Assembly stubs are counted separately on purpose: a Go func with no body
is not something you port by reading Go. That column is now **zero** —
`crypto/sha1`, `sha256` and `sha512` read as small gaps for a while and
turned out to be measurement, not assembly (see the `--by-decl` note
below).

## net/http — 639 / 639 functions (100.0%)

**All twelve packages are at 100.0%**, with 1534 `// go:` lines (the
root package alone carries 1107; both were 1476 and 1085 on
2026-08-15 and drift upward with ordinary work) and 33 declarations waived on in-tree
justifications. This is an anchored port, not a name match: request
and response bodies stream both directions through the ported
`transfer.go` machinery, the client pools connections through Go's
full `getConn`/`persistConn` call graph (idle reaping, GetBody rewind,
sentinel-mapped retries, Expect: 100-continue), and the server runs
`connReader` with Go's total-head byte limit (431/501 paths included).

| package | ported | | package | ported |
|---|--:|---|---|--:|
| `.` (root) | 465/465 | | `cgi` | 15/15 |
| `httputil` | 47/47 | | `pprof` | 13/13 |
| `fcgi` | 28/28 | | `internal` | 12/12 |
| `httptest` | 28/28 | | `internal/ascii` | 5/5 |
| `cookiejar` | 21/21 | | `httptrace` | 4/4 |

`net/http/pprof` serves from a new `runtime/pprof` user-registry
(`Profile.Add` captures real stacks via `runtime::Callers`; `WriteTo`
symbolizes live through `runtime::FuncForPC`); the CPU, trace and
protobuf arms return Go-shaped unsupported errors rather than fake
output.

## testing/ — 217 / 247 functions (87.9%)

The root package is at **141/149 (94.6%)**, and `fstest` (38/38),
`iotest` (11/11) and `slogtest` (10/10) are complete; 431 `// go:`
lines across the tree. `testing.B`, `testing.M` and `t.Parallel()` are
ported. The root's eight missing functions are the fuzzing entry
points (`testing.F` is not ported), the profiling hooks
(`writeProfiles`/`before`/`after`) and the synctest bridge — excluding
fuzzing and profiling, the tree reads 97.3%. Still open: `quick`
(7/14, blocked on a real `reflect` redesign — goish's `reflect` is a
value tree), `internal/testdeps` (10/21, the fuzz/profile plumbing),
and `synctest` (0/4).

## The percentages are optimistic, and by how much

`port_coverage.py` counts **unique names, not declarations**. Go methods
that share a name across types collapse into one entry — and a name
counts as ported when **any one** type implements it.

| | |
|---|--:|
| crypto/ Go declarations (receiver-qualified) | 1722 |
| unique names — what the metric counts | 1447 |
| invisible to the metric | **275 (16%)** |

`crypto/tls` is the extreme case: **350 declarations behind 291 counted
names**, because `marshal`/`unmarshal` repeat across fifteen message
types. `handshake_messages.go` alone collapses 52 declarations → 17
names. So porting a seventh `marshal` method cannot move the number,
and the first one made all fifteen look done.

This was found by measurement, not estimate: six verbatim message ports
landed with byte-exact vectors and the percentage did not move.

`--by-decl` reports the receiver-qualified figure, on both sides:

| | by name | by declaration |
|---|--:|--:|
| crypto/ | 1431/1447 (98.9%) | **1722/1722 (100.0%)** |
| crypto/tls | 275/291 (94.5%) | 350/350 (100.0%) |

`--by-decl` had an understating defect of its own, found the same way:
15 ported, anchored declarations read MISSING because goish ports a Go
method whose receiver is a `&mut` value type as a *free fn* (sha1's
`digest.checkSum`, des's `desCipher.generateSubkeys`, …), and the
matcher only synthesized `Recv.Method` keys from Rust `impl` blocks.
The fix credits an anchored `Recv.Method` when the fn exists in the
same file — sound now that `anchor_check.py` verifies every range
names exactly that declaration and `make lint` gates on it. With the
handshake/dial work now finished, the by-declaration residual is zero;
the 24 QUIC declarations are waived with in-tree justifications (dead
code without a QUIC transport).

The first thing it found was concrete: `crypto/x509` read 100% by name
while missing `CertificateRequest.CheckSignature` and
`RevocationList.CheckSignatureFrom` — both credited because
`Certificate` has same-named methods. Both are now ported, and x509 is
169/169 either way.

The anchors do not have this problem — `anchor_by_name.py` keys methods
by `Recv.Method`, so the 2238 anchors are receiver-qualified and
GOISH018 diffs each one individually. **Anchor counts are the honest
signal; percentages are an upper bound.** Fixing the counter is a small
change to `scan_go` and would restate every figure here downward.

## What "ported" means here

Three tiers, weakest to strongest. The distinction matters because every
one of the defects found this cycle passed the weak tier and failed the
strong one.

1. **Name match** — a goish `fn` shares a Go declaration's name. This is
   what a coverage percentage counts, and on its own it proves nothing.
   `crypto/ecdsa` read "present" for four sessions while holding 915
   lines of hand-rolled P-256 with no Go counterpart.
2. **Anchored** — the fn carries `// go: sdk 1.25.5 <file>:<lines>
   <Symbol>`, so goishlint's fidelity tier (GOISH017-021) opens the Go
   file and diffs signature, arity and struct fields against it. A
   dropped argument or a renamed field fails the build gate.
   **goishlint resolves the symbol by name and never reads the line
   range** — 401 of 1892 ranges were wrong when first measured, some
   pointing hundreds of lines away at a different function.
   `scripts/anchor_check.py` now gates `make lint` on that.
3. **Ground-truthed** — an example asserts values generated by
   `scripts/goref.sh`, which runs a throwaway test *inside* a writable
   GOROOT copy so it can reach unexported symbols. Expectations are
   generated, never transcribed.

`port_coverage.py` reports tier-1 counts and flags anything still at
tier 1 as **UNVERIFIED**. That number went 121 → 3 this cycle, and is
now **0**: the last flag (`prf12`) turned out to be shadowing from
`tls/record.rs` — the hand-written pre-verbatim record layer, which
defines an *invented* `prf12` while the real port sits anchored in
`prf.rs`. record.rs and session.rs now carry explicit goish-only
legacy banners and are slated for deletion once the remaining
handshake declarations replace their call sites.

### Why byte-exactness, specifically

Four defects landed in one package while compiling cleanly and producing
plausible, well-formed DER. A field-comparison test would have passed
every one:

- `reflect::Zero` answered `Invalid` for composite kinds, so `asn1`'s
  OPTIONAL-omission test never fired — an empty element inside every
  `AlgorithmIdentifier` Go writes bare.
- `reflect::Zero(Kind::Interface)` lost the type of a nil interface, so
  `asn1.Unmarshal` into anything reaching an X.509 Name — every CRL —
  failed outright.
- `asn1::ParseBigInt` was not a port at all: it mishandled negative DER
  INTEGERs in both sign and magnitude. Reachable from
  `Certificate.SerialNumber`, which RFC 5280 permits to be negative.
- `crypto/rsa`'s `PrivateKey.Sign` dropped Go's PSS arm, so a caller
  asking for PSS silently received a PKCS#1 v1.5 signature.

Two more of the same shape turned up in `crypto/tls`, and they matter
for what they say about the *lint* tier rather than the port:

- `encryptedExtensionsMsg.marshal` emitted only `alpnProtocol` and
  `serverNameAck`, dropping `quicTransportParameters`, `earlyData` and
  `echRetryConfigs`.
- `serverHelloMsg.marshal` dropped `ocspStapling`, `ticketSupported`,
  `secureRenegotiationSupported`, `extendedMasterSecret`, `scts` and
  `encryptedClientHello` — six extensions.

Both carried a `// go: sdk` anchor naming the exact Go line range.
**GOISH018 compares signatures, arity and struct fields — not the
statements inside a function.** An extension a port forgot to emit is
therefore invisible to tier 2 and visible only at tier 3. There is now a
sweep in `tls_common_smoke` that marshals all seventeen message types
with every field populated and diffs the wire against `goref.sh`; it is
the only thing standing between this class of defect and a release.

## Test suite

417 examples are declared in `Cargo.toml` and run by `make e2e` at
tiered loop counts — deterministic ones once, memory-subsystem ones ×10,
and the race-sensitive scheduler/chan/select/timer/server families ×50.
**Only declared examples run**; an `examples/*.rs` file without an
`[[example]]` block is invisible to CI.

Local verification is `cargo check --lib`, `cargo build --examples`,
`make lint`, and the individual binaries a change touches. `make e2e`
belongs on CI.

### `make lint` is a ratchet

`scripts/lint_baseline.json` records goishlint's finding count per
**(file, rule)**; `make lint` fails only when a pair increases. Two
consequences: a file absent from the baseline must be lint-clean, and
fixing file A cannot pay for a regression in file B. Current total:
13081.

## Known defects, open

Each is reproduced and recorded rather than worked around. Both need
`make e2e-full` to validate, so neither is bundled into a port.
(A third, `Timer::Stop()` leaving its sleeper goroutine pinned, was
fixed in `3b97cc5` — one goroutine per timer, zero post-Stop lifetime,
tripwired by `time_stop_no_pin_smoke`.)

- **`goish::cast!` cannot succeed on a `goany::Any` carrier.** It
  resolves through the blanket `HasDynAny for T`, probing the wrapper's
  `TypeId` and never the payload's. Silent — a comma-ok assertion
  reports `false`. Use `.As::<dyn Trait + Send + Sync>()`. See
  CONTRIBUTING.md §9b.
- **`crypto/ecdsa::PrivateKey` does not implement `crypto::Signer`**
  (Go's does), so an ECDSA key cannot yet sign an X.509 certificate.

### Structural divergences, pinned by assertions

- `time::Parse` rejects a numeric zone offset where Go accepts one —
  `time::Time` carries no `Location`. RFC 5280 requires `Z` in
  certificates, so certificate parsing is unaffected.
- goish value types collapse two Go states into one: `big::Int` (nil vs
  present-and-zero) and `time::Time` (year 1 vs Unix epoch). The common
  case is correct in both; the rare one is documented at the symptom and
  at the cause, with the `goref.sh` bytes for each.

## CI

Two workflows: `e2e.yml` on every push (`make e2e LOOPS=1`) and
`e2e-race.yml` nightly (stress families ×50). Dispatch the full sweep by
hand after any scheduler, allocator or `runtime/` change:

```bash
gh workflow run e2e-race.yml --repo cogentica-ai/goish -f mode=full --ref <branch>
```
