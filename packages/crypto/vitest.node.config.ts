/**
 * Vitest configuration for Node.js unit tests.
 * Runs:
 * - api-surface.test.ts: Compares node.ts vs browser.ts implementations (Node-only)
 * - crypto.test.ts: Tests the package via `import from 'tor-crypto'`
 */

import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    name: 'crypto-node',
    include: ['src/**/*.test.ts'],
    environment: 'node',
  },
});
