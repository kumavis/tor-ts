import { defineConfig } from 'vite';
import { nodePolyfills } from 'vite-plugin-node-polyfills';
import path from 'path';

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
      },
    }),
  ],
  resolve: {
    alias: {
      // Replace 'ws' package with browser WebSocket shim from browser package
      ws: path.resolve(__dirname, '../../packages/browser/src/shims/ws.ts'),
      // Replace node:tls with forge-based implementation
      'node:tls': path.resolve(__dirname, '../../packages/browser/src/shims/tls.ts'),
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
    include: ['node-forge', 'buffer', 'events', 'web-streams-polyfill'],
  },
});
