import { defineConfig } from 'vite';
import { nodePolyfills } from 'vite-plugin-node-polyfills';
import path from 'path';

export default defineConfig({
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
        'stream/web': 'web-streams-polyfill/dist/ponyfill.mjs',
      },
    }),
  ],
  resolve: {
    alias: {
      ws: path.resolve(__dirname, '../../packages/browser/src/shims/ws.ts'),
      'node:tls': path.resolve(__dirname, '../../packages/browser/src/shims/tls.ts'),
      'stream/web': 'web-streams-polyfill/dist/ponyfill.mjs',
    },
  },
  server: {
    port: 3001,
    open: true,
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
  optimizeDeps: {
    include: ['node-forge', 'buffer', 'events', 'web-streams-polyfill', 'd3'],
  },
});
