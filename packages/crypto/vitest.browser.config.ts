/**
 * Vitest configuration for browser unit tests.
 * Runs crypto.test.ts in a real browser via Playwright.
 * The test imports from 'tor-crypto' which resolves to browser.ts in browser.
 */

import { defineConfig } from 'vitest/config';
import { nodePolyfills } from 'vite-plugin-node-polyfills';

export default defineConfig({
  plugins: [
    nodePolyfills({
      include: ['buffer'],
      globals: {
        Buffer: true,
        global: true,
        process: true,
      },
    }),
  ],
  optimizeDeps: {
    include: [
      'vite-plugin-node-polyfills/shims/buffer',
      'vite-plugin-node-polyfills/shims/global',
      'vite-plugin-node-polyfills/shims/process',
    ],
  },
  test: {
    name: 'crypto-browser',
    include: ['src/crypto.test.ts'],
    browser: {
      enabled: true,
      provider: 'playwright',
      instances: [{ browser: 'chromium' }],
      headless: true,
    },
  },
});
