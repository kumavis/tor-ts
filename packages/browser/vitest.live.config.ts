/**
 * Vitest configuration for browser live tests.
 * These tests connect to the real Tor network via Snowflake.
 * They require network access and may take longer to run.
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
  test: {
    name: 'browser-live',
    include: ['src/**/*.live.test.ts'],
    browser: {
      enabled: true,
      provider: 'playwright',
      instances: [{ browser: 'chromium' }],
      headless: true,
    },
    testTimeout: 180_000, // 3 minutes for live network tests
    hookTimeout: 60_000,
  },
});
