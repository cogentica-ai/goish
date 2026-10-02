// Gate: crypto-provenance-holds (Scope A: R1 resolve, R2 form).
// Needs GOROOT to name a Go 1.25.5 tree; anchor_check exits 2 otherwise,
// which commands() classifies as unclassified -> REFUSE.
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
      'Every well-formed `// go: sdk 1.25.5` anchor under src/crypto resolves in the Go 1.25.5 tree: the cited file exists and the cited lines hold exactly one declaration, the named symbol, start no earlier than the end of the previous declaration (on its last line only if that line is a bare closing `}` or `)`), and reach to within one line of the last line of the declaration, all as reported by go/parser.',
  },
  form: {
    id: 'crypto-provenance/sdk-lines-well-formed',
    description:
      'Every line under src/crypto that starts `// go: sdk` is a well-formed anchor naming version 1.25.5, a .go file, a line or line range, and a symbol; no such line is skipped.',
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
      'Run anchor_check.py in its resolve mode and its form mode over src/crypto against the Go 1.25.5 tree in $GOROOT. The resolve mode takes declaration boundaries from tools/anchor_decls.go (go/parser). Exit 0 passes, 1 breaches that Rule, 2 refuses.',
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
  proof.red(
    rules.resolve,
    'detects a citation that no longer resolves',
    edit(
      'move the NewCipher anchor in src/crypto/rc4/rc4.rs from rc4.go:33-51 to rc4.go:57-62',
      RC4, NEW, '// go: sdk 1.25.5 crypto/rc4/rc4.go:57-62 NewCipher'),
  ),
  proof.red(
    rules.resolve,
    'detects an anchor citing a Go file that does not exist',
    edit(
      'point the NewCipher anchor in src/crypto/rc4/rc4.rs at the nonexistent crypto/rc4/rc4_gone.go',
      RC4, NEW, '// go: sdk 1.25.5 crypto/rc4/rc4_gone.go:33-51 NewCipher'),
  ),
  proof.red(
    rules.resolve,
    'detects a single-line anchor that points at a different declaration',
    edit(
      'move the single-line KeySizeError anchor in src/crypto/rc4/rc4.rs from rc4.go:25 to rc4.go:27',
      RC4, SINGLE, '// go: sdk 1.25.5 crypto/rc4/rc4.go:27 KeySizeError'),
  ),
  proof.red(
    rules.form,
    'detects an anchor with no symbol, which the checker skips today',
    edit(
      'delete the symbol from the NewCipher anchor in src/crypto/rc4/rc4.rs',
      RC4, NEW, '// go: sdk 1.25.5 crypto/rc4/rc4.go:33-51'),
  ),
  proof.red(
    rules.form,
    'detects an anchor that cites an unpinned Go version',
    edit(
      'change the NewCipher anchor in src/crypto/rc4/rc4.rs from sdk 1.25.5 to sdk 1.24.0',
      RC4, NEW, '// go: sdk 1.24.0 crypto/rc4/rc4.go:33-51 NewCipher'),
  ),
  proof.red(
    rules.form,
    'detects a single-line anchor that lost its symbol',
    edit(
      'delete the symbol from the single-line KeySizeError anchor in src/crypto/rc4/rc4.rs',
      RC4, SINGLE, '// go: sdk 1.25.5 crypto/rc4/rc4.go:25'),
  ),
  proof.red(
    rules.resolve,
    'detects a mistyped .go extension (rc4.og) instead of skipping it as non-Go',
    edit(
      'change the NewCipher anchor in src/crypto/rc4/rc4.rs to cite rc4.og instead of rc4.go',
      RC4, NEW, '// go: sdk 1.25.5 crypto/rc4/rc4.og:33-51 NewCipher'),
  ),
  proof.red(
    rules.form,
    'detects a mistyped .go extension (rc4.og)',
    edit(
      'change the NewCipher anchor in src/crypto/rc4/rc4.rs to cite rc4.og instead of rc4.go',
      RC4, NEW, '// go: sdk 1.25.5 crypto/rc4/rc4.og:33-51 NewCipher'),
  ),
  proof.red(
    rules.form,
    'detects two anchors on one line that hide an unpinned version',
    edit(
      'replace the NewCipher anchor in src/crypto/rc4/rc4.rs with two on one line, the second sdk 1.24.0',
      RC4, NEW, '// go: sdk 1.25.5 garbage // go: sdk 1.24.0 crypto/rc4/rc4.go:33-51 NewCipher'),
  ),
  proof.red(
    rules.form,
    'detects an unpinned version in a /// doc-comment anchor',
    edit(
      'turn the NewCipher anchor in src/crypto/rc4/rc4.rs into /// go: sdk 1.24.0',
      RC4, NEW, '/// go: sdk 1.24.0 crypto/rc4/rc4.go:33-51 NewCipher'),
  ),
  proof.red(
    rules.form,
    'detects an anchor citing an absolute path outside the Go tree',
    edit(
      'point the NewCipher anchor in src/crypto/rc4/rc4.rs at the absolute path /etc/hosts.go',
      RC4, NEW, '// go: sdk 1.25.5 /etc/hosts.go:33-51 NewCipher'),
  ),
  proof.red(
    rules.resolve,
    'detects an anchor citing a .. path that escapes the Go tree',
    edit(
      'point the NewCipher anchor in src/crypto/rc4/rc4.rs at crypto/../../fake.go',
      RC4, NEW, '// go: sdk 1.25.5 crypto/../../fake.go:33-51 NewCipher'),
  ),
  proof.refuse(
    'refuses when a source file under src/crypto is an unreadable dangling symlink',
    defineMutation({
      description: 'add the dangling symlink src/crypto/rc4/dangling.rs',
      capture: 'src/crypto/rc4/dangling.rs',
      async apply(ctx) {
        await symlink('/nonexistent-target', join(ctx.root, 'src/crypto/rc4/dangling.rs'));
      },
    }),
  ),
  proof.red(
    rules.resolve,
    'detects an anchor whose symbol is a struct field, not a declaration',
    append(
      'append to src/crypto/rc4/rc4.rs the anchor rc4.go:19-23 naming `s`, a field of Cipher',
      RC4, '\n// go: sdk 1.25.5 crypto/rc4/rc4.go:19-23 s\n'),
  ),
  proof.red(
    rules.resolve,
    'detects an anchor whose symbol is only a local assignment inside a function',
    append(
      'append to src/crypto/rc4/rc4.rs the anchor des/block.go:203-213 naming `last`, a local of ksRotate',
      RC4, '\n// go: sdk 1.25.5 crypto/des/block.go:203-213 last\n'),
  ),
  proof.red(
    rules.resolve,
    'detects an anchor whose symbol is only used inside the range, declared elsewhere',
    append(
      'append to src/crypto/rc4/rc4.rs the anchor rc4.go:33-51 naming KeySizeError, which NewCipher uses but does not declare',
      RC4, '\n// go: sdk 1.25.5 crypto/rc4/rc4.go:33-51 KeySizeError\n'),
  ),
  proof.green(
    'accepts a grouped const member block and a method anchor',
    append(
      'append to src/crypto/rc4/rc4.rs valid anchors for the grouped const block md5.go:60-63 (magic) and method digest.Write',
      RC4, '\n// go: sdk 1.25.5 crypto/md5/md5.go:60-63 magic\n// go: sdk 1.25.5 crypto/md5/md5.go:126-166 digest.Write\n'),
  ),
  proof.red(
    rules.resolve,
    'detects a range that starts inside the previous declaration (Cipher.Reset cited from inside NewCipher)',
    append(
      'append to src/crypto/rc4/rc4.rs the anchor rc4.go:34-61 Cipher.Reset, which starts inside NewCipher and swallows its body',
      RC4, '\n// go: sdk 1.25.5 crypto/rc4/rc4.go:34-61 Cipher.Reset\n'),
  ),
  proof.red(
    rules.resolve,
    'detects a field of a struct nested inside a type ( ) block cited as a declaration',
    append(
      'append to src/crypto/rc4/rc4.rs the anchor go/types/stmt.go:229-234 naming `pos`, a field of valueType inside type ( )',
      RC4, '\n// go: sdk 1.25.5 go/types/stmt.go:229-234 pos\n'),
  ),
  proof.red(
    rules.form,
    'detects an sdk anchor written after a non-breaking space, which the strict anchor pattern cannot parse',
    append(
      'append to src/crypto/rc4/rc4.rs the line `//<NBSP>go: sdk 1.24.0 crypto/rc4/rc4.go:57-62`',
      RC4, '\n//\u00a0go: sdk 1.24.0 crypto/rc4/rc4.go:57-62\n'),
  ),
  proof.red(
    rules.resolve,
    'detects a range that stops far short of a function with a multi-line signature',
    append(
      'append to src/crypto/rc4/rc4.rs the anchor x509/verify.go:563-570 Certificate.checkNameConstraints, which ends at 621',
      RC4, '\n// go: sdk 1.25.5 crypto/x509/verify.go:563-570 Certificate.checkNameConstraints\n'),
  ),
  proof.red(
    rules.resolve,
    'detects a range that starts inside the previous multi-line-signature function',
    append(
      'append to src/crypto/rc4/rc4.rs the anchor x509/verify.go:600-786 Certificate.isValid, which starts inside checkNameConstraints',
      RC4, '\n// go: sdk 1.25.5 crypto/x509/verify.go:600-786 Certificate.isValid\n'),
  ),
  proof.red(
    rules.resolve,
    'detects a range that starts inside a brace-less multi-line const',
    append(
      'append to src/crypto/rc4/rc4.rs the anchor subtle/xor_generic.go:18-39 xorBytes, which starts inside the const supportsUnaligned (lines 16-20)',
      RC4, '\n// go: sdk 1.25.5 crypto/internal/fips140/subtle/xor_generic.go:18-39 xorBytes\n'),
  ),
  proof.red(
    rules.resolve,
    'detects a range that stops short of a brace-less multi-line const',
    append(
      'append to src/crypto/rc4/rc4.rs the anchor subtle/xor_generic.go:16-17 supportsUnaligned, which ends at line 20',
      RC4, '\n// go: sdk 1.25.5 crypto/internal/fips140/subtle/xor_generic.go:16-17 supportsUnaligned\n'),
  ),
  proof.refuse(
    'refuses when the Go-parser helper cannot be built',
    defineMutation({
      description: 'replace tools/anchor_decls.go with a file that is not valid Go',
      capture: 'tools/anchor_decls.go',
      async apply(ctx) {
        await ctx.files.write('tools/anchor_decls.go', 'package main\nfunc (\n');
      },
    }),
  ),
  proof.red(
    rules.resolve,
    'detects a range that starts on the last code line of the previous brace-less const',
    append(
      'append to src/crypto/rc4/rc4.rs the anchor subtle/xor_generic.go:20-39 xorBytes, which starts on the last code line (20) of supportsUnaligned',
      RC4, '\n// go: sdk 1.25.5 crypto/internal/fips140/subtle/xor_generic.go:20-39 xorBytes\n'),
  ),
  proof.red(
    rules.resolve,
    'detects a range that starts on the last code line of a previous multi-line var',
    append(
      'append to src/crypto/rc4/rc4.rs the anchor gcm/gcm_asm.go:35-44 init, which starts on the last code line (35) of supportsAESGCM',
      RC4, '\n// go: sdk 1.25.5 crypto/internal/fips140/aes/gcm/gcm_asm.go:35-44 init\n'),
  ),
  proof.green(
    'accepts valid single-line anchors and non-sdk go: lines',
    defineMutation({
      description:
        'append to src/crypto/rc4/rc4.rs a valid single-line sdk anchor plus `// go: none`, `// go: waived` and prose `// Go:` lines',
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
  proof.green('accepts the current crypto tree after the four symbol-less anchors are repaired'),
  proof.refuse(
    'refuses when src/crypto is missing',
    defineMutation({
      description: 'remove src/crypto',
      capture: SCOPE,
      async apply(ctx) {
        await ctx.files.remove(SCOPE);
      },
    }),
  ),
  proof.refuse(
    'refuses when src/crypto holds no sdk anchors',
    defineMutation({
      description: 'replace src/crypto with a directory holding one file with no `// go: sdk` line',
      capture: SCOPE,
      async apply(ctx) {
        await ctx.files.remove(SCOPE);
        await ctx.files.write(`${SCOPE}/placeholder.rs`, '// no provenance here\n');
      },
    }),
  ),
]);

export default gate;
