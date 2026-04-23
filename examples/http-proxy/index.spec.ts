/**
 * Example: HTTP Proxy Server over Tor
 *
 * This example demonstrates how to:
 * 1. Establish a Tor circuit (with retry on transient failures)
 * 2. Create an HTTP proxy server that routes traffic through Tor
 * 3. Handle HTTP proxy requests
 *
 * Run with: yarn test:live
 */

import http from 'http';
import test from 'ava';
import httpProxy from 'http-proxy';
import { withTorOperation } from 'tor/build-circuit/mainnet';
import { getTorAgentForUrl } from 'tor/node';

test('proxy HTTP request through Tor circuit', async (t) => {
  // 10 minutes total to cover up to 3 bootstrap attempts on the live network.
  t.timeout(600_000);

  const port = 19234;
  const targetUrl = 'http://example.com/';

  console.log('Connecting to Tor network...');

  // withTorOperation builds a fresh 3-hop circuit for each attempt and
  // retries automatically on transient Tor-network / transport-level failures
  // (ECONNREFUSED to a fallback dir, DESTROY with CHANNEL_CLOSED / TIMEOUT,
  // socket hang-ups, etc.). Each attempt rebinds its own proxy server and
  // reissues the request, so the proxied request stays side-effect-free.
  const body = await withTorOperation(
    async (circuit) => {
      console.log('Circuit established!');

      const proxy = httpProxy.createProxyServer({});
      proxy.on('error', (err, _req, res) => {
        console.error('Proxy error:', err.message);
        if (res && 'writeHead' in res) {
          res.writeHead(502, { 'Content-Type': 'text/plain' });
          res.end('Proxy error: ' + err.message);
        }
      });

      const proxyServer = http.createServer((req, res) => {
        const reqTarget = req.url as string;
        console.log(`Proxying: ${reqTarget}`);
        const agent = getTorAgentForUrl(circuit, reqTarget);
        proxy.web(req, res, {
          target: reqTarget,
          agent,
          changeOrigin: true,
        });
      });

      try {
        await new Promise<void>((resolve) => {
          proxyServer.listen(port, () => {
            console.log(`Proxy server listening on port ${port}`);
            resolve();
          });
        });

        console.log(`Making request through proxy to ${targetUrl}...`);
        return await new Promise<string>((resolve, reject) => {
          const req = http.request(
            {
              host: 'localhost',
              port,
              method: 'GET',
              path: targetUrl,
              headers: { Host: 'example.com' },
            },
            (res) => {
              let data = '';
              res.setEncoding('utf8');
              res.on('data', (chunk) => (data += chunk));
              res.on('end', () => resolve(data));
            }
          );
          req.setTimeout(120_000, () => req.destroy(new Error('timeout')));
          req.on('error', reject);
          req.end();
        });
      } finally {
        proxyServer.close();
      }
    },
    {
      maxAttempts: 3,
      onRetry: (attempt, err) =>
        console.warn(`Attempt ${attempt} hit transient Tor error: ${err.message}. Retrying...`),
    }
  );

  console.log(`Response length: ${body.length} bytes`);
  t.true(body.includes('Example Domain'), 'Response should contain "Example Domain"');
});
