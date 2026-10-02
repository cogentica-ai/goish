// Gate: crypto-provenance-holds.
//
// Promise: every Go citation (`// go: sdk 1.25.5 <file>:<lines> <Symbol>`)
// in src/crypto points at the Go 1.25.5 declaration it names, and none is
// skipped because it is malformed.
//
// How it is checked: scripts/anchor_check.py --rule resolve|form over
// src/crypto, with GOROOT naming a Go 1.25.5 tree. Declaration boundaries
// come from Go's own parser (tools/anchor_decls.go). Exit 0 holds, 1
// breaches, 2 means it cannot decide, which commands() reports as REFUSE.
import { symlink } from 'node:fs/promises';
import { join } from 'node:path';
import {
  defineGate,
  defineMutation,
  defineProofs,
  defineRules,
  mutate,
  proof,
} from 'redproof';
import { commands } from 'redproof/command';

const rules = defineRules({
  resolve: {
    id: 'crypto-provenance/sdk-anchors-resolve',
    description:
      'Each Go citation in src/crypto points at exactly the Go 1.25.5 function, type, method, const or var it names: the whole declaration (its closing brace may be left off) and nothing from the code around it.',
  },
  form: {
    id: 'crypto-provenance/sdk-lines-well-formed',
    description:
      'Every Go citation in src/crypto is complete and readable: it names Go 1.25.5, a .go file inside the Go tree, the lines, and the symbol. A citation that cannot be read is reported, never silently skipped.',
  },
});

const SCOPE = 'src/crypto';
const anchorCheck = (rule: 'resolve' | 'form') => ({
  command: 'python3',
  args: ['scripts/anchor_check.py', '--rule', rule, SCOPE],
  exitCodes: { pass: [0], breach: [1] },
});

const gate = defineGate({
  id: 'crypto-provenance-holds',
  rules,
  check: commands({
    mode: 'sequential',
    description:
      "Read every Go citation in src/crypto and compare it with the Go 1.25.5 source, using Go's own parser to find where each declaration starts and ends. If the Go source or the citations cannot be read, say so instead of passing.",
    entries: [
      { rule: rules.resolve, label: 'anchor_check --rule resolve', ...anchorCheck('resolve') },
      { rule: rules.form, label: 'anchor_check --rule form', ...anchorCheck('form') },
    ],
  }),
});

// Rewrite one exact text in one file; throws when the text is not there
// exactly once, so a proof can never run against an unplanted mutation.
function edit(description: string, path: string, from: string, to: string) {
  return defineMutation({
    description,
    capture: path,
    async apply(ctx) {
      const src = await ctx.files.read(path);
      if (src.split(from).length !== 2) {
        throw new Error(`proof mutation target not found exactly once in ${path}: ${from}`);
      }
      await ctx.files.write(path, src.replace(from, () => to));
    },
  });
}

// Append anchor lines to a file.
function append(description: string, path: string, text: string) {
  return defineMutation({
    description,
    capture: path,
    async apply(ctx) {
      await ctx.files.write(path, (await ctx.files.read(path)) + text);
    },
  });
}

const RC4 = 'src/crypto/rc4/rc4.rs';
const NEW = '// go: sdk 1.25.5 crypto/rc4/rc4.go:33-51 NewCipher';
const SINGLE = '// go: sdk 1.25.5 crypto/rc4/rc4.go:25 KeySizeError';

export const proofs = defineProofs(gate, [
  // Allowed: correct citations pass.
  proof.green('passes the crypto tree as it is today'),
  proof.green(
    'passes correct citations of a grouped const and of a method',
    append(
      'cite md5.go:60-63 for the grouped const magic and md5.go:126-166 for the method digest.Write',
      RC4, '\n// go: sdk 1.25.5 crypto/md5/md5.go:60-63 magic\n// go: sdk 1.25.5 crypto/md5/md5.go:126-166 digest.Write\n'),
  ),
  proof.green(
    'passes a correct one-line citation and leaves non-citation comments alone',
    defineMutation({
      description:
        'add a correct one-line citation of KeySizeError, plus `// go: none`, `// go: waived` and a prose `// Go:` note',
      capture: RC4,
      async apply(ctx) {
        const src = await ctx.files.read(RC4);
        await ctx.files.write(
          RC4,
          src +
            '\n// go: sdk 1.25.5 crypto/rc4/rc4.go:25 KeySizeError\n' +
            '// go: none\n' +
            '// go: waived — not ported, design choice\n' +
            '// Go: rc4.go:25 — prose citation, not an anchor\n',
        );
      },
    }),
  ),

  // Caught: a citation that points at the wrong Go code.
  proof.red(
    rules.resolve,
    'catches a citation that drifted onto the wrong lines',
    edit(
      "move NewCipher's citation from rc4.go:33-51 to rc4.go:57-62, where Cipher.Reset lives",
      RC4, NEW, '// go: sdk 1.25.5 crypto/rc4/rc4.go:57-62 NewCipher'),
  ),
  proof.red(
    rules.resolve,
    'catches a one-line citation that drifted onto the wrong line',
    edit(
      "move KeySizeError's one-line citation from rc4.go:25 to rc4.go:27",
      RC4, SINGLE, '// go: sdk 1.25.5 crypto/rc4/rc4.go:27 KeySizeError'),
  ),
  proof.red(
    rules.resolve,
    'catches a citation of a Go file that does not exist',
    edit(
      "point NewCipher's citation at rc4_gone.go, which is not in Go 1.25.5",
      RC4, NEW, '// go: sdk 1.25.5 crypto/rc4/rc4_gone.go:33-51 NewCipher'),
  ),
  proof.red(
    rules.resolve,
    'catches a citation of a mistyped file name',
    edit(
      "change NewCipher's citation from rc4.go to rc4.og",
      RC4, NEW, '// go: sdk 1.25.5 crypto/rc4/rc4.og:33-51 NewCipher'),
  ),
  proof.red(
    rules.resolve,
    'catches a citation that climbs out of the Go tree',
    edit(
      "point NewCipher's citation at crypto/../../fake.go",
      RC4, NEW, '// go: sdk 1.25.5 crypto/../../fake.go:33-51 NewCipher'),
  ),

  // Caught: a citation whose named symbol is not the declaration there.
  proof.red(
    rules.resolve,
    'catches a citation that names a struct field instead of a declaration',
    append(
      'cite rc4.go:19-23 as `s`, which is a field of Cipher',
      RC4, '\n// go: sdk 1.25.5 crypto/rc4/rc4.go:19-23 s\n'),
  ),
  proof.red(
    rules.resolve,
    'catches a citation that names a local variable instead of a declaration',
    append(
      'cite des/block.go:203-213 as `last`, a local variable inside ksRotate',
      RC4, '\n// go: sdk 1.25.5 crypto/des/block.go:203-213 last\n'),
  ),
  proof.red(
    rules.resolve,
    'catches a citation that names something the cited code only uses',
    append(
      'cite NewCipher\'s lines rc4.go:33-51 as KeySizeError, which NewCipher uses but does not declare',
      RC4, '\n// go: sdk 1.25.5 crypto/rc4/rc4.go:33-51 KeySizeError\n'),
  ),
  proof.red(
    rules.resolve,
    'catches a citation that names a field of a struct inside a type block',
    append(
      'cite go/types/stmt.go:229-234 as `pos`, a field of a struct declared inside `type ( )`',
      RC4, '\n// go: sdk 1.25.5 go/types/stmt.go:229-234 pos\n'),
  ),

  // Caught: a citation that covers too much or too little.
  proof.red(
    rules.resolve,
    'catches a citation that also takes in the end of the function before it',
    append(
      'cite rc4.go:34-61 as Cipher.Reset, which starts inside NewCipher',
      RC4, '\n// go: sdk 1.25.5 crypto/rc4/rc4.go:34-61 Cipher.Reset\n'),
  ),
  proof.red(
    rules.resolve,
    'catches a citation that takes in the end of a function with a long signature',
    append(
      'cite x509/verify.go:600-786 as Certificate.isValid, which starts inside checkNameConstraints',
      RC4, '\n// go: sdk 1.25.5 crypto/x509/verify.go:600-786 Certificate.isValid\n'),
  ),
  proof.red(
    rules.resolve,
    'catches a citation that takes in the end of a multi-line const',
    append(
      'cite subtle/xor_generic.go:18-39 as xorBytes, which starts inside the const supportsUnaligned',
      RC4, '\n// go: sdk 1.25.5 crypto/internal/fips140/subtle/xor_generic.go:18-39 xorBytes\n'),
  ),
  proof.red(
    rules.resolve,
    'catches a citation that starts on the last line of the const before it',
    append(
      'cite subtle/xor_generic.go:20-39 as xorBytes, starting on the last line of supportsUnaligned',
      RC4, '\n// go: sdk 1.25.5 crypto/internal/fips140/subtle/xor_generic.go:20-39 xorBytes\n'),
  ),
  proof.red(
    rules.resolve,
    'catches a citation that starts on the last line of the var before it',
    append(
      'cite gcm/gcm_asm.go:35-44 as init, starting on the last line of supportsAESGCM',
      RC4, '\n// go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/gcm_asm.go:35-44 init\n'),
  ),
  proof.red(
    rules.resolve,
    'catches a citation that stops long before its function ends',
    append(
      'cite x509/verify.go:563-570 as Certificate.checkNameConstraints, which runs to line 621',
      RC4, '\n// go: sdk 1.25.5 crypto/x509/verify.go:563-570 Certificate.checkNameConstraints\n'),
  ),
  proof.red(
    rules.resolve,
    'catches a citation that stops before its multi-line const ends',
    append(
      'cite subtle/xor_generic.go:16-17 as supportsUnaligned, which runs to line 20',
      RC4, '\n// go: sdk 1.25.5 crypto/internal/fips140/subtle/xor_generic.go:16-17 supportsUnaligned\n'),
  ),

  // Caught: a citation that is incomplete or unreadable.
  proof.red(
    rules.form,
    'reports a citation with no symbol instead of skipping it',
    edit(
      "drop the symbol from NewCipher's citation",
      RC4, NEW, '// go: sdk 1.25.5 crypto/rc4/rc4.go:33-51'),
  ),
  proof.red(
    rules.form,
    'reports a one-line citation with no symbol instead of skipping it',
    edit(
      "drop the symbol from KeySizeError's one-line citation",
      RC4, SINGLE, '// go: sdk 1.25.5 crypto/rc4/rc4.go:25'),
  ),
  proof.red(
    rules.form,
    'reports a citation of the wrong Go version',
    edit(
      "change NewCipher's citation from Go 1.25.5 to Go 1.24.0",
      RC4, NEW, '// go: sdk 1.24.0 crypto/rc4/rc4.go:33-51 NewCipher'),
  ),
  proof.red(
    rules.form,
    'reports a wrong Go version in a doc-comment citation',
    edit(
      "turn NewCipher's citation into a `///` doc comment that cites Go 1.24.0",
      RC4, NEW, '/// go: sdk 1.24.0 crypto/rc4/rc4.go:33-51 NewCipher'),
  ),
  proof.red(
    rules.form,
    'reports a wrong Go version hidden in a second citation on the same line',
    edit(
      "put two citations on NewCipher's line, the second citing Go 1.24.0",
      RC4, NEW, '// go: sdk 1.25.5 garbage // go: sdk 1.24.0 crypto/rc4/rc4.go:33-51 NewCipher'),
  ),
  proof.red(
    rules.form,
    'reports a citation written with an unusual space',
    append(
      'add a citation written with a non-breaking space after `//`',
      RC4, '\n//\u00a0go: sdk 1.24.0 crypto/rc4/rc4.go:57-62\n'),
  ),
  proof.red(
    rules.form,
    'reports a citation of a file that is not Go source',
    edit(
      "change NewCipher's citation from rc4.go to rc4.og",
      RC4, NEW, '// go: sdk 1.25.5 crypto/rc4/rc4.og:33-51 NewCipher'),
  ),
  proof.red(
    rules.form,
    'reports a citation of a path outside the Go tree',
    edit(
      "point NewCipher's citation at the absolute path /etc/hosts.go",
      RC4, NEW, '// go: sdk 1.25.5 /etc/hosts.go:33-51 NewCipher'),
  ),

  // Can't decide: missing or unreadable evidence never passes.
  proof.refuse(
    'refuses when there is no src/crypto to check',
    defineMutation({
      description: 'remove src/crypto',
      capture: SCOPE,
      async apply(ctx) {
        await ctx.files.remove(SCOPE);
      },
    }),
  ),
  proof.refuse(
    'refuses when src/crypto has no citations at all',
    defineMutation({
      description: 'replace src/crypto with a single file that has no Go citation',
      capture: SCOPE,
      async apply(ctx) {
        await ctx.files.remove(SCOPE);
        await ctx.files.write(`${SCOPE}/placeholder.rs`, '// no provenance here\n');
      },
    }),
  ),
  proof.refuse(
    'refuses when a crypto source file cannot be read',
    defineMutation({
      description: 'add src/crypto/rc4/dangling.rs as a symlink to nothing',
      capture: 'src/crypto/rc4/dangling.rs',
      async apply(ctx) {
        await symlink('/nonexistent-target', join(ctx.root, 'src/crypto/rc4/dangling.rs'));
      },
    }),
  ),
  proof.refuse(
    "refuses when Go's parser cannot be used",
    defineMutation({
      description: 'replace the parser helper tools/anchor_decls.go with code that does not compile',
      capture: 'tools/anchor_decls.go',
      async apply(ctx) {
        await ctx.files.write('tools/anchor_decls.go', 'package main\nfunc (\n');
      },
    }),
  ),
]);

export default gate;
