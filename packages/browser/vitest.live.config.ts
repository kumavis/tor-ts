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
        // Override crypto to use our shim that provides webcrypto export
        crypto: path.resolve(__dirname, 'src/shims/crypto-webcrypto.ts'),
      },
    }),
  ],
  resolve: {
    alias: {
      ws: path.resolve(__dirname, 'src/shims/ws.ts'),
      'node:tls': path.resolve(__dirname, 'src/shims/tls.ts'),
      'node:crypto': path.resolve(__dirname, 'src/shims/crypto-webcrypto.ts'),
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
      '@reclaimprotocol/tls',
      '@peculiar/x509',
      '@noble/hashes/sha1',
    ],
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
    testTimeout: 600_000, // 10 minutes - consensus download via JS TLS is slow
    hookTimeout: 600_000,
  },
});
