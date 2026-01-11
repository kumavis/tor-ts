/**
 * Vitest configuration for browser unit tests.
 * These tests run in a real browser environment via Playwright.
 */

import { defineConfig } from 'vitest/config';
import { nodePolyfills } from 'vite-plugin-node-polyfills';
import path from 'path';

export default defineConfig({
  plugins: [
    nodePolyfills({
      include: ['buffer', 'crypto', 'events', 'stream', 'util', 'process', 'assert'],
      globals: {
        Buffer: true,
        global: true,
        process: true,
      },
      overrides: {
        'stream/web': 'web-streams-polyfill/dist/ponyfill.mjs',
      },
    }),
  ],
  resolve: {
    alias: {
      ws: path.resolve(__dirname, 'src/shims/ws.ts'),
      'node:tls': path.resolve(__dirname, 'src/shims/tls.ts'),
      'stream/web': 'web-streams-polyfill/dist/ponyfill.mjs',
    },
  },
  optimizeDeps: {
    include: [
      'vite-plugin-node-polyfills/shims/buffer',
      'vite-plugin-node-polyfills/shims/global',
      'vite-plugin-node-polyfills/shims/process',
      'events',
      'node:assert',
      'node:crypto',
      'node:events',
      'stream',
      'node:stream',
      'node-forge',
    ],
  },
  test: {
    name: 'browser-unit',
    include: ['src/**/*.test.ts'],
    exclude: ['src/**/*.live.test.ts'],
    browser: {
      enabled: true,
      provider: 'playwright',
      instances: [{ browser: 'chromium' }],
      headless: true,
    },
  },
});
