import { defineConfig } from 'redproof';

// Gates live in this directory; proofs mutate files in the repo root.
export default defineConfig({
  root: '..',
  gatesRoot: 'gates/*.ts',
  refusalExit: 2,
});
