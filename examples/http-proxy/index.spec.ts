/**
 * Example: HTTP Proxy Server over Tor
 *
 * This example demonstrates how to:
 * 1. Establish a Tor circuit
 * 2. Create an HTTP proxy server that routes traffic through Tor
 * 3. Handle HTTP proxy requests
 *
 * Run with: yarn test:live
 */

import http from 'http';
import test from 'ava';
import httpProxy from 'http-proxy';
import { connectRandomCircuitWithSafeBootstrap } from 'tor/build-circuit/mainnet';
import { getTorAgentForUrl } from 'tor/node';

test('proxy HTTP request through Tor circuit', async (t) => {
  t.timeout(300_000); // 5 minutes - Tor bootstrap can be slow

  // Step 1: Establish a Tor circuit
  console.log('Connecting to Tor network...');
  const circuit = await connectRandomCircuitWithSafeBootstrap();
  console.log('Circuit established!');

  // Step 2: Create a proxy server that routes through Tor
  const port = 19234;
  const proxy = httpProxy.createProxyServer({});

  // Handle proxy errors gracefully
  proxy.on('error', (err, _req, res) => {
    console.error('Proxy error:', err.message);
    if (res && 'writeHead' in res) {
      res.writeHead(502, { 'Content-Type': 'text/plain' });
      res.end('Proxy error: ' + err.message);
    }
  });

  const proxyServer = http.createServer((req, res) => {
    // Parse the target URL from the request
    const targetUrl = req.url as string;
    console.log(`Proxying: ${targetUrl}`);

    // Create a Tor agent for this request
    const agent = getTorAgentForUrl(circuit, targetUrl);

    // Forward the request through Tor
    // changeOrigin ensures the Host header is set correctly
    proxy.web(req, res, {
      target: targetUrl,
      agent: agent,
      changeOrigin: true,
    });
  });

  await new Promise<void>((resolve) => {
    proxyServer.listen(port, () => {
      console.log(`Proxy server listening on port ${port}`);
      resolve();
    });
  });

  // Clean up when done
  t.teardown(() => {
    proxyServer.close();
    circuit.destroy();
  });

  // Step 3: Make a request through the proxy
  // Using example.com - IANA-reserved domain guaranteed to always work
  const targetUrl = 'http://example.com/';
  console.log(`Making request through proxy to ${targetUrl}...`);

  const body = await new Promise<string>((resolve, reject) => {
    const req = http.request(
      {
        host: 'localhost',
        port: port,
        method: 'GET',
        path: targetUrl,
        headers: {
          Host: 'example.com',
        },
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

  console.log(`Response length: ${body.length} bytes`);
  t.true(body.includes('Example Domain'), 'Response should contain "Example Domain"');
});
