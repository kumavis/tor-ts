import { defineConfig } from 'vite';
import { nodePolyfills } from 'vite-plugin-node-polyfills';
import path from 'path';

const browserShimsPath = path.resolve(__dirname, '../../packages/browser/src/shims');

export default defineConfig({
  // Use base path from env for GitHub Pages deployment
  base: process.env.VITE_BASE_PATH || '/',
  plugins: [
    nodePolyfills({
      include: ['buffer', 'crypto', 'events', 'stream', 'util', 'process', 'assert'],
      globals: {
        Buffer: true,
        global: true,
        process: true,
      },
      overrides: {
        // Use web streams polyfill for stream/web
        'stream/web': 'web-streams-polyfill/dist/ponyfill.mjs',
        // Use our crypto shim that provides webcrypto export for SubtleCrypto TLS
        crypto: path.resolve(browserShimsPath, 'crypto-webcrypto.ts'),
      },
    }),
  ],
  resolve: {
    alias: {
      // Replace 'ws' package with browser WebSocket shim from browser package
      ws: path.resolve(browserShimsPath, 'ws.ts'),
      // Replace node:tls with @reclaimprotocol/tls-based implementation (TLS 1.3)
      'node:tls': path.resolve(browserShimsPath, 'tls.ts'),
      // Tor imports crypto via `node:crypto` - ensure it uses the shim.
      'node:crypto': path.resolve(browserShimsPath, 'crypto-webcrypto.ts'),
      // Stream/web alias for the circuit.ts import
      'stream/web': 'web-streams-polyfill/dist/ponyfill.mjs',
    },
  },
  server: {
    port: 3000,
    open: true,
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
  optimizeDeps: {
    include: ['@reclaimprotocol/tls', 'buffer', 'events', 'web-streams-polyfill'],
  },
});
