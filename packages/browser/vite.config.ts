import { defineConfig } from 'vite';
import { nodePolyfills } from 'vite-plugin-node-polyfills';
import path from 'path';

export default defineConfig({
  plugins: [
    nodePolyfills({
      // Include polyfills for Node.js builtins
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
      // Replace 'ws' package with our browser WebSocket shim
      ws: path.resolve(__dirname, 'src/shims/ws.ts'),
      // Replace node:tls with our @reclaimprotocol/tls-based implementation (TLS 1.3)
      'node:tls': path.resolve(__dirname, 'src/shims/tls.ts'),
      // Dependencies that import node:crypto get our minimal shim
      'node:crypto': path.resolve(__dirname, 'src/shims/crypto-webcrypto.ts'),
      // Stream/web polyfill
      'stream/web': 'web-streams-polyfill/dist/ponyfill.mjs',
    },
  },
  build: {
    lib: {
      entry: path.resolve(__dirname, 'src/index.ts'),
      name: 'TorBrowser',
      fileName: 'tor-browser',
      formats: ['es'],
    },
    rollupOptions: {
      output: {
        // Ensure proper chunking for tree-shaking
        manualChunks: undefined,
      },
    },
    sourcemap: true,
    minify: false,
  },
  optimizeDeps: {
    include: ['@reclaimprotocol/tls', 'web-streams-polyfill'],
  },
});
