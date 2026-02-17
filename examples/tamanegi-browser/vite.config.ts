import { defineConfig } from 'vite';
import { nodePolyfills } from 'vite-plugin-node-polyfills';
import path from 'path';

const browserShimsPath = path.resolve(__dirname, '../../packages/browser/src/shims');

export default defineConfig({
  // Use base path from env for GitHub Pages deployment
  base: process.env.VITE_BASE_PATH || '/',
  plugins: [
    {
      name: 'service-worker-allowed-scope',
      configureServer(server) {
        server.middlewares.use((req, res, next) => {
          const path = req.url?.split('?')[0] ?? '';
          if (path.endsWith('sw.ts') || /\/sw-[^/]+\.(ts|js)$/.test(path)) {
            res.setHeader('Service-Worker-Allowed', '/');
          }
          next();
        });
      },
    },
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
    rollupOptions: {
      input: {
        main: path.resolve(__dirname, 'index.html'),
        sw: path.resolve(__dirname, 'src/sw.ts'),
      },
      output: {
        entryFileNames: (chunkInfo) =>
          chunkInfo.name === 'sw' ? 'sw.js' : 'assets/[name]-[hash].js',
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash][extname]',
      },
    },
  },
  optimizeDeps: {
    include: ['@reclaimprotocol/tls', 'buffer', 'events', 'web-streams-polyfill'],
  },
});
