/**
 * Example: HTTP Proxy Server over Tor
 *
 * This example demonstrates how to:
 * 1. Establish a Tor circuit
 * 2. Create an HTTP proxy server that routes traffic through Tor
 * 3. Handle both HTTP and HTTPS (CONNECT) requests
 *
 * Run with: yarn test:live
 *
 * For interactive use, see the start script which runs the proxy server.
 */

import http from 'http';
import test from 'ava';
import httpProxy from 'http-proxy';
import { connectRandomCircuitWithSafeBootstrap } from 'tor/build-circuit/mainnet';
import { getTorAgentForUrl } from 'tor/node';

test('proxy HTTP request through Tor circuit', async (t) => {
  t.timeout(180_000); // 3 minutes - Tor bootstrap can be slow

  // Step 1: Establish a Tor circuit
  console.log('Connecting to Tor network...');
  const circuit = await connectRandomCircuitWithSafeBootstrap();
  console.log('Circuit established!');

  // Step 2: Create a proxy server that routes through Tor
  const port = 19234;
  const proxy = httpProxy.createProxyServer();

  const proxyServer = http.createServer((req, res) => {
    const target = req.url as string;
    console.log(`Proxying: ${target}`);
    // Create a Tor agent for each request
    const agent = getTorAgentForUrl(circuit, target);
    proxy.web(req, res, { target, agent });
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
  const target = 'http://captive.apple.com';
  console.log(`Making request through proxy to ${target}...`);

  const body = await new Promise<string>((resolve, reject) => {
    const req = http.get({ host: 'localhost', port, path: target }, (res) => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => resolve(data));
    });
    req.setTimeout(60_000, () => req.destroy(new Error('timeout')));
    req.on('error', reject);
  });

  console.log(`Response: ${body.trim()}`);
  t.true(body.includes('Success'));
});
