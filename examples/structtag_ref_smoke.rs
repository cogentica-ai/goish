// structtag_ref_smoke — reflect.StructTag against a running Go.
// (reflect/type.go StructTag.Get / StructTag.Lookup)
//
// Every expectation below is what a real Go 1.25.5 prints: the lines in
// GO are the verbatim output of `tools/gen_structtag_ref.go` run in
// `package reflect_test` by `scripts/goref.sh`.
//
// StructTag is the smallest piece of reflect with the widest blast
// radius: encoding/json, encoding/xml and every codec that names fields
// reads its answers. It is a hand-written parser over a string nobody
// validates, so its failure mode is not an error — it is a tag that
// silently stops being seen.
//
// The rule that matters most is that a MALFORMED pair ENDS the scan.
// Not skips it; ends it. So
//
//     `bad json:"name"`
//
// hides the json key entirely, because "bad" has no colon and the
// parser stops there. A field annotated that way is marshalled under
// its Go name with no warning anywhere, which is how a struct quietly
// changes its wire format. `bad-then-good` pins the same thing with a
// valid pair BEFORE the bad one and another after: the first is found,
// the last is not.
//
// Thirty-four tags are crossed with seven lookup keys, which is what
// makes the quiet cases visible:
//
//   * An EMPTY value is a PRESENT key. `json:""` returns ("", true)
//     where an absent key returns ("", false) — the whole reason
//     Lookup exists beside Get, and a caller using Get alone cannot
//     tell the two apart.
//   * Values are strconv-unquoted, so `json:"na\"me"` yields a name
//     containing a quote and `json:"na\\me"` one containing a
//     backslash. An INVALID escape makes the pair unparseable and,
//     again, ends the scan.
//   * A duplicate key resolves to the FIRST occurrence.
//   * Keys match exactly: `JSON:` and `json:` are different keys.
//   * Separators are spaces only — a TAB or a NEWLINE between pairs
//     stops the scan, which is easy to get wrong by reaching for a
//     generic whitespace test.
//
// Note what CANNOT be written in Go source: `go vet` refuses a
// malformed struct tag at build time ("bad syntax for struct tag
// pair") and refuses a tag on an unexported field. So the malformed
// cases are strings rather than struct fields not out of convenience —
// a string is the only way such a tag reaches the parser at all, which
// is exactly why the silent-truncation behaviour matters: it is
// reached by tags that were BUILT, not written.
//
// Two defects found, both in reachability rather than in the parser:
//
//   * reflect.Kind had a String() that fmt could not reach, so `%v` on
//     a Kind did not compile. Same shape as io/fs's FileMode two
//     commits ago — a String the printer cannot dispatch to because
//     nothing implements Stringer. reflect.Type had it too.
//   * StructTag had no way to read its raw text back. Go's is
//     `type StructTag string`, so a caller writes `string(f.Tag)`;
//     goish's is a struct with a private field and offered nothing at
//     all.
//
// One structural deviation, not measured here: goish's
// `#[goish::reflect]` exposes only EXPORTED fields, so the struct
// section carries no unexported field. That is documented in
// reflect/mod.rs and is a property of the descriptor macro rather than
// of StructTag.

#![no_std]
#![no_main]
#![allow(non_snake_case)]
extern crate alloc;
extern crate goish;
use goish::fmt;
use goish::gostring::string;
use goish::reflect;
use goish::syscall;
use goish::types::int;
const GO: [&str; 246] = [
    "tag empty                    key=\"json\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag empty                    key=\"xml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag empty                    key=\"yaml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag empty                    key=\"JSON\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag empty                    key=\"bad\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag empty                    key=\"\"    -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag empty                    key=\"x\"   -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag simple                   key=\"json\" -> lookup=\"name\"         ok=true  get=\"name\" same=true",
    "tag simple                   key=\"xml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag simple                   key=\"yaml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag simple                   key=\"JSON\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag simple                   key=\"bad\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag simple                   key=\"\"    -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag simple                   key=\"x\"   -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag two-keys                 key=\"json\" -> lookup=\"name\"         ok=true  get=\"name\" same=true",
    "tag two-keys                 key=\"xml\" -> lookup=\"Name\"         ok=true  get=\"Name\" same=true",
    "tag two-keys                 key=\"yaml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag two-keys                 key=\"JSON\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag two-keys                 key=\"bad\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag two-keys                 key=\"\"    -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag two-keys                 key=\"x\"   -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag three-keys               key=\"json\" -> lookup=\"a\"            ok=true  get=\"a\" same=true",
    "tag three-keys               key=\"xml\" -> lookup=\"b\"            ok=true  get=\"b\" same=true",
    "tag three-keys               key=\"yaml\" -> lookup=\"c\"            ok=true  get=\"c\" same=true",
    "tag three-keys               key=\"JSON\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag three-keys               key=\"bad\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag three-keys               key=\"\"    -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag three-keys               key=\"x\"   -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag leading-space            key=\"json\" -> lookup=\"name\"         ok=true  get=\"name\" same=true",
    "tag leading-space            key=\"xml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag leading-space            key=\"yaml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag leading-space            key=\"JSON\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag leading-space            key=\"bad\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag leading-space            key=\"\"    -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag leading-space            key=\"x\"   -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag trailing-space           key=\"json\" -> lookup=\"name\"         ok=true  get=\"name\" same=true",
    "tag trailing-space           key=\"xml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag trailing-space           key=\"yaml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag trailing-space           key=\"JSON\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag trailing-space           key=\"bad\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag trailing-space           key=\"\"    -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag trailing-space           key=\"x\"   -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag multi-space              key=\"json\" -> lookup=\"a\"            ok=true  get=\"a\" same=true",
    "tag multi-space              key=\"xml\" -> lookup=\"b\"            ok=true  get=\"b\" same=true",
    "tag multi-space              key=\"yaml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag multi-space              key=\"JSON\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag multi-space              key=\"bad\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag multi-space              key=\"\"    -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag multi-space              key=\"x\"   -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag no-space-between         key=\"json\" -> lookup=\"a\"            ok=true  get=\"a\" same=true",
    "tag no-space-between         key=\"xml\" -> lookup=\"b\"            ok=true  get=\"b\" same=true",
    "tag no-space-between         key=\"yaml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag no-space-between         key=\"JSON\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag no-space-between         key=\"bad\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag no-space-between         key=\"\"    -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag no-space-between         key=\"x\"   -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag empty-value              key=\"json\" -> lookup=\"\"             ok=true  get=\"\" same=true",
    "tag empty-value              key=\"xml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag empty-value              key=\"yaml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag empty-value              key=\"JSON\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag empty-value              key=\"bad\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag empty-value              key=\"\"    -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag empty-value              key=\"x\"   -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag value-with-options       key=\"json\" -> lookup=\"name,omitempty\" ok=true  get=\"name,omitempty\" same=true",
    "tag value-with-options       key=\"xml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag value-with-options       key=\"yaml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag value-with-options       key=\"JSON\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag value-with-options       key=\"bad\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag value-with-options       key=\"\"    -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag value-with-options       key=\"x\"   -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag value-dash               key=\"json\" -> lookup=\"-\"            ok=true  get=\"-\" same=true",
    "tag value-dash               key=\"xml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag value-dash               key=\"yaml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag value-dash               key=\"JSON\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag value-dash               key=\"bad\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag value-dash               key=\"\"    -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag value-dash               key=\"x\"   -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag value-dash-comma         key=\"json\" -> lookup=\"-,\"           ok=true  get=\"-,\" same=true",
    "tag value-dash-comma         key=\"xml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag value-dash-comma         key=\"yaml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag value-dash-comma         key=\"JSON\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag value-dash-comma         key=\"bad\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag value-dash-comma         key=\"\"    -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag value-dash-comma         key=\"x\"   -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag escaped-quote            key=\"json\" -> lookup=\"na\\\"me\"       ok=true  get=\"na\\\"me\" same=true",
    "tag escaped-quote            key=\"xml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag escaped-quote            key=\"yaml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag escaped-quote            key=\"JSON\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag escaped-quote            key=\"bad\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag escaped-quote            key=\"\"    -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag escaped-quote            key=\"x\"   -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag escaped-backslash        key=\"json\" -> lookup=\"na\\\\me\"       ok=true  get=\"na\\\\me\" same=true",
    "tag escaped-backslash        key=\"xml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag escaped-backslash        key=\"yaml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag escaped-backslash        key=\"JSON\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag escaped-backslash        key=\"bad\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag escaped-backslash        key=\"\"    -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag escaped-backslash        key=\"x\"   -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag escaped-newline          key=\"json\" -> lookup=\"na\\nme\"       ok=true  get=\"na\\nme\" same=true",
    "tag escaped-newline          key=\"xml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag escaped-newline          key=\"yaml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag escaped-newline          key=\"JSON\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag escaped-newline          key=\"bad\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag escaped-newline          key=\"\"    -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag escaped-newline          key=\"x\"   -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag unicode-escape           key=\"json\" -> lookup=\"naéme\"        ok=true  get=\"naéme\" same=true",
    "tag unicode-escape           key=\"xml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag unicode-escape           key=\"yaml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag unicode-escape           key=\"JSON\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag unicode-escape           key=\"bad\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag unicode-escape           key=\"\"    -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag unicode-escape           key=\"x\"   -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag value-with-space         key=\"json\" -> lookup=\"na me\"        ok=true  get=\"na me\" same=true",
    "tag value-with-space         key=\"xml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag value-with-space         key=\"yaml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag value-with-space         key=\"JSON\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag value-with-space         key=\"bad\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag value-with-space         key=\"\"    -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag value-with-space         key=\"x\"   -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag value-with-colon         key=\"json\" -> lookup=\"na:me\"        ok=true  get=\"na:me\" same=true",
    "tag value-with-colon         key=\"xml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag value-with-colon         key=\"yaml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag value-with-colon         key=\"JSON\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag value-with-colon         key=\"bad\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag value-with-colon         key=\"\"    -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag value-with-colon         key=\"x\"   -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag malformed-no-colon       key=\"json\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag malformed-no-colon       key=\"xml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag malformed-no-colon       key=\"yaml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag malformed-no-colon       key=\"JSON\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag malformed-no-colon       key=\"bad\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag malformed-no-colon       key=\"\"    -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag malformed-no-colon       key=\"x\"   -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag malformed-no-quote       key=\"json\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag malformed-no-quote       key=\"xml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag malformed-no-quote       key=\"yaml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag malformed-no-quote       key=\"JSON\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag malformed-no-quote       key=\"bad\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag malformed-no-quote       key=\"\"    -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag malformed-no-quote       key=\"x\"   -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag malformed-unterminated   key=\"json\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag malformed-unterminated   key=\"xml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag malformed-unterminated   key=\"yaml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag malformed-unterminated   key=\"JSON\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag malformed-unterminated   key=\"bad\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag malformed-unterminated   key=\"\"    -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag malformed-unterminated   key=\"x\"   -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag malformed-empty-key      key=\"json\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag malformed-empty-key      key=\"xml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag malformed-empty-key      key=\"yaml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag malformed-empty-key      key=\"JSON\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag malformed-empty-key      key=\"bad\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag malformed-empty-key      key=\"\"    -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag malformed-empty-key      key=\"x\"   -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag malformed-key-space      key=\"json\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag malformed-key-space      key=\"xml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag malformed-key-space      key=\"yaml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag malformed-key-space      key=\"JSON\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag malformed-key-space      key=\"bad\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag malformed-key-space      key=\"\"    -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag malformed-key-space      key=\"x\"   -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag malformed-quote-in-key   key=\"json\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag malformed-quote-in-key   key=\"xml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag malformed-quote-in-key   key=\"yaml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag malformed-quote-in-key   key=\"JSON\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag malformed-quote-in-key   key=\"bad\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag malformed-quote-in-key   key=\"\"    -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag malformed-quote-in-key   key=\"x\"   -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag duplicate-key            key=\"json\" -> lookup=\"first\"        ok=true  get=\"first\" same=true",
    "tag duplicate-key            key=\"xml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag duplicate-key            key=\"yaml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag duplicate-key            key=\"JSON\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag duplicate-key            key=\"bad\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag duplicate-key            key=\"\"    -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag duplicate-key            key=\"x\"   -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag case-differs             key=\"json\" -> lookup=\"lower\"        ok=true  get=\"lower\" same=true",
    "tag case-differs             key=\"xml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag case-differs             key=\"yaml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag case-differs             key=\"JSON\" -> lookup=\"upper\"        ok=true  get=\"upper\" same=true",
    "tag case-differs             key=\"bad\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag case-differs             key=\"\"    -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag case-differs             key=\"x\"   -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag tab-separator            key=\"json\" -> lookup=\"a\"            ok=true  get=\"a\" same=true",
    "tag tab-separator            key=\"xml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag tab-separator            key=\"yaml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag tab-separator            key=\"JSON\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag tab-separator            key=\"bad\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag tab-separator            key=\"\"    -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag tab-separator            key=\"x\"   -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag newline-separator        key=\"json\" -> lookup=\"a\"            ok=true  get=\"a\" same=true",
    "tag newline-separator        key=\"xml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag newline-separator        key=\"yaml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag newline-separator        key=\"JSON\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag newline-separator        key=\"bad\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag newline-separator        key=\"\"    -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag newline-separator        key=\"x\"   -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag bad-then-good            key=\"json\" -> lookup=\"ok\"           ok=true  get=\"ok\" same=true",
    "tag bad-then-good            key=\"xml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag bad-then-good            key=\"yaml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag bad-then-good            key=\"JSON\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag bad-then-good            key=\"bad\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag bad-then-good            key=\"\"    -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag bad-then-good            key=\"x\"   -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag good-after-unterminated  key=\"json\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag good-after-unterminated  key=\"xml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag good-after-unterminated  key=\"yaml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag good-after-unterminated  key=\"JSON\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag good-after-unterminated  key=\"bad\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag good-after-unterminated  key=\"\"    -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag good-after-unterminated  key=\"x\"   -> lookup=\"a json:\"      ok=true  get=\"a json:\" same=true",
    "tag only-spaces              key=\"json\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag only-spaces              key=\"xml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag only-spaces              key=\"yaml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag only-spaces              key=\"JSON\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag only-spaces              key=\"bad\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag only-spaces              key=\"\"    -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag only-spaces              key=\"x\"   -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag invalid-escape           key=\"json\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag invalid-escape           key=\"xml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag invalid-escape           key=\"yaml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag invalid-escape           key=\"JSON\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag invalid-escape           key=\"bad\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag invalid-escape           key=\"\"    -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag invalid-escape           key=\"x\"   -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag control-char-key         key=\"json\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag control-char-key         key=\"xml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag control-char-key         key=\"yaml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag control-char-key         key=\"JSON\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag control-char-key         key=\"bad\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag control-char-key         key=\"\"    -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag control-char-key         key=\"x\"   -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag empty-key-value          key=\"json\" -> lookup=\"\"             ok=true  get=\"\" same=true",
    "tag empty-key-value          key=\"xml\" -> lookup=\"\"             ok=true  get=\"\" same=true",
    "tag empty-key-value          key=\"yaml\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag empty-key-value          key=\"JSON\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag empty-key-value          key=\"bad\" -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag empty-key-value          key=\"\"    -> lookup=\"\"             ok=false get=\"\" same=true",
    "tag empty-key-value          key=\"x\"   -> lookup=\"\"             ok=false get=\"\" same=true",
    "struct name=\"S\" kind=struct numfield=7",
    "field Plain      tag=\"\"                       json=\"\"           ok=false xml=\"\" exported=true",
    "field Named      tag=\"json:\\\"named\\\"\"         json=\"named\"      ok=true  xml=\"\" exported=true",
    "field Omit       tag=\"json:\\\"omit,omitempty\\\"\" json=\"omit,omitempty\" ok=true  xml=\"\" exported=true",
    "field Skipped    tag=\"json:\\\"-\\\"\"             json=\"-\"          ok=true  xml=\"\" exported=true",
    "field Multi      tag=\"json:\\\"m\\\" xml:\\\"x\\\" db:\\\"d\\\"\" json=\"m\"          ok=true  xml=\"x\" exported=true",
    "field Escaped    tag=\"json:\\\"esc\\\\\\\"aped\\\"\"   json=\"esc\\\"aped\"  ok=true  xml=\"\" exported=true",
    "field Empty      tag=\"json:\\\"\\\"\"              json=\"\"           ok=true  xml=\"\" exported=true",
];

fn chk(failed: &mut int, ln: &mut int, got: string) {
    if *ln >= GO.len() as int {
        fmt::Printf!("[!!] extra line %d: %q\n", *ln + 1, got);
        *failed += 1;
        *ln += 1;
        return;
    }
    let want = s(GO[*ln as usize]);
    *ln += 1;
    if got == want {
        return;
    }
    fmt::Printf!("[!!] line %d FAIL\n  got  %q\n  want %q\n", *ln, got, want);
    *failed += 1;
}

fn s(x: &str) -> string {
    return string::from_bytes(x.as_bytes());
}
#[goish::reflect]
pub struct S {
    Plain: string,
    #[tag(r#"json:"named""#)]
    Named: string,
    #[tag(r#"json:"omit,omitempty""#)]
    Omit: string,
    #[tag(r#"json:"-""#)]
    Skipped: string,
    #[tag(r#"json:"m" xml:"x" db:"d""#)]
    Multi: string,
    #[tag(r#"json:"esc\"aped""#)]
    Escaped: string,
    #[tag(r#"json:"""#)]
    Empty: string,
}
#[goish::main]
fn main() {
    let mut failed: int = 0;
    let mut ln: int = 0;
    let tags: [(&str, &'static str); 34] = [
        ("empty", r#""#),
        ("simple", r#"json:"name""#),
        ("two-keys", r#"json:"name" xml:"Name""#),
        ("three-keys", r#"json:"a" xml:"b" yaml:"c""#),
        ("leading-space", r#"   json:"name""#),
        ("trailing-space", r#"json:"name"   "#),
        ("multi-space", r#"json:"a"    xml:"b""#),
        ("no-space-between", r#"json:"a"xml:"b""#),
        ("empty-value", r#"json:"""#),
        ("value-with-options", r#"json:"name,omitempty""#),
        ("value-dash", r#"json:"-""#),
        ("value-dash-comma", r#"json:"-,""#),
        ("escaped-quote", r#"json:"na\"me""#),
        ("escaped-backslash", r#"json:"na\\me""#),
        ("escaped-newline", r#"json:"na\nme""#),
        ("unicode-escape", r#"json:"naéme""#),
        ("value-with-space", r#"json:"na me""#),
        ("value-with-colon", r#"json:"na:me""#),
        ("malformed-no-colon", r#"bad json:"name""#),
        ("malformed-no-quote", r#"json:name xml:"b""#),
        ("malformed-unterminated", r#"json:"name"#),
        ("malformed-empty-key", r#":"name""#),
        ("malformed-key-space", r#"js on:"name""#),
        ("malformed-quote-in-key", r#"js"on:"name""#),
        ("duplicate-key", r#"json:"first" json:"second""#),
        ("case-differs", r#"JSON:"upper" json:"lower""#),
        ("tab-separator", "json:\"a\"\txml:\"b\""),
        ("newline-separator", "json:\"a\"\nxml:\"b\""),
        ("bad-then-good", r#"json:"ok" bad xml:"never""#),
        ("good-after-unterminated", r#"x:"a json:"name""#),
        ("only-spaces", r#"   "#),
        ("invalid-escape", r#"json:"na\qme""#),
        ("control-char-key", "js\u{1}on:\"name\""),
        ("empty-key-value", r#"json:"" xml:"""#),
    ];
    for (name, raw) in tags.iter() {
        let st = reflect::StructTag::__new(raw);
        for key in ["json", "xml", "yaml", "JSON", "bad", "", "x"] {
            let (v, ok) = st.Lookup(key);
            let g = st.Get(key);
            chk(
                &mut failed,
                &mut ln,
                fmt::Sprintf!(
                    "tag %-24s key=%-5q -> lookup=%-14q ok=%-5v get=%q same=%v",
                    s(name),
                    s(key),
                    v.clone(),
                    ok,
                    g.clone(),
                    v == g
                ),
            );
        }
    }
    let rt = reflect::TypeOf(&S {
        Plain: string::new(),
        Named: string::new(),
        Omit: string::new(),
        Skipped: string::new(),
        Multi: string::new(),
        Escaped: string::new(),
        Empty: string::new(),
    });
    chk(
        &mut failed,
        &mut ln,
        fmt::Sprintf!(
            "struct name=%q kind=%v numfield=%d",
            rt.Name(),
            rt.Kind(),
            rt.NumField()
        ),
    );
    for i in 0..rt.NumField() {
        let f = rt.Field(i);
        let (jv, jok) = f.Tag.Lookup("json");
        chk(
            &mut failed,
            &mut ln,
            fmt::Sprintf!(
                "field %-10s tag=%-24q json=%-12q ok=%-5v xml=%q exported=%v",
                s(f.Name),
                f.Tag.String(),
                jv,
                jok,
                f.Tag.Get("xml"),
                f.PkgPath == ""
            ),
        );
    }
    if ln != GO.len() as int {
        fmt::Printf!("[!!] produced %d lines, pinned %d\n", ln, GO.len() as int);
        failed += 1;
    }
    if failed == 0 {
        fmt::Printf!("ok %d/%d\n", ln, ln);
        return;
    }
    fmt::Printf!("FAILED %d of %d\n", failed, ln);
    syscall::Exit(1);
}
