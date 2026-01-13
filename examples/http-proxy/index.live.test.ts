/**
 * Live test for http-proxy example.
 *
 * Tests that we can establish a Tor circuit and proxy HTTP/HTTPS requests through it.
 * Uses captive.apple.com which returns a simple "Success" response and doesn't
 * block Tor exit nodes like many other services do.
 */

import http from 'http';
import https from 'https';
import test from 'ava';
import httpProxy from 'http-proxy';
import { connectRandomCircuitWithSafeBootstrap } from 'tor/build-circuit/mainnet';
import { getTorAgentForUrl } from 'tor/node';

test.serial('http-proxy: can proxy HTTP request through Tor circuit', async (t) => {
  t.timeout(180_000); // 3 minutes for Tor bootstrap + fetch

  console.log('[test] Setting up Tor circuit...');
  const circuit = await connectRandomCircuitWithSafeBootstrap();
  console.log('[test] Circuit established');

  t.teardown(() => {
    console.log('[test] Destroying circuit');
    circuit.destroy();
  });

  // Use Apple's captive portal detection endpoint - it returns "Success" and doesn't block Tor
  const target = 'http://captive.apple.com';
  console.log(`[test] Testing HTTP request to ${target}...`);

  const agent = getTorAgentForUrl(circuit, target);
  const body = await new Promise<string>((resolve, reject) => {
    const req = http.get(target, { agent }, (res) => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => resolve(data));
    });
    req.setTimeout(60_000, () => {
      req.destroy(new Error('request timeout'));
    });
    req.on('error', reject);
  });

  console.log(`[test] Response via Tor HTTP: ${body.trim()}`);

  // Apple's captive portal returns exactly "Success" when there's internet connectivity
  t.true(
    body.includes('Success'),
    `Response should contain 'Success', got: ${body.substring(0, 100)}`
  );
});

test.serial('http-proxy: can proxy HTTPS request through Tor circuit', async (t) => {
  t.timeout(180_000); // 3 minutes for Tor bootstrap + fetch

  console.log('[test] Setting up Tor circuit...');
  const circuit = await connectRandomCircuitWithSafeBootstrap();
  console.log('[test] Circuit established');

  t.teardown(() => {
    console.log('[test] Destroying circuit');
    circuit.destroy();
  });

  // Use Apple's captive portal detection endpoint over HTTPS
  const target = 'https://captive.apple.com';
  console.log(`[test] Testing HTTPS request to ${target}...`);

  const agent = getTorAgentForUrl(circuit, target);
  const body = await new Promise<string>((resolve, reject) => {
    const req = https.get(target, { agent }, (res) => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => resolve(data));
    });
    req.setTimeout(60_000, () => {
      req.destroy(new Error('request timeout'));
    });
    req.on('error', reject);
  });

  console.log(`[test] Response via Tor HTTPS: ${body.trim()}`);

  // Apple's captive portal returns exactly "Success" when there's internet connectivity
  t.true(
    body.includes('Success'),
    `Response should contain 'Success', got: ${body.substring(0, 100)}`
  );
});

test.serial('http-proxy: proxy server can handle HTTP requests', async (t) => {
  t.timeout(180_000); // 3 minutes for Tor bootstrap + proxy test

  console.log('[test] Setting up Tor circuit...');
  const circuit = await connectRandomCircuitWithSafeBootstrap();
  console.log('[test] Circuit established');

  // Setup proxy server
  const port = 19234; // Use a high port to avoid conflicts
  const proxy = httpProxy.createProxyServer();

  const proxyServer = http.createServer((req, res) => {
    const target = req.url as string;
    console.log(`[proxy] Proxying HTTP request to: ${target}`);
    const agent = getTorAgentForUrl(circuit, target);
    proxy.web(req, res, { target, agent });
  });

  await new Promise<void>((resolve) => {
    proxyServer.listen(port, () => {
      console.log(`[test] Proxy server started on port ${port}`);
      resolve();
    });
  });

  t.teardown(() => {
    console.log('[test] Closing proxy server and destroying circuit');
    proxyServer.close();
    circuit.destroy();
  });

  // Use Apple's captive portal detection endpoint
  const target = 'http://captive.apple.com';
  console.log(`[test] Making request through proxy to ${target}...`);

  const body = await new Promise<string>((resolve, reject) => {
    const req = http.get(
      {
        host: 'localhost',
        port: port,
        path: target,
      },
      (res) => {
        let data = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => (data += chunk));
        res.on('end', () => resolve(data));
      }
    );
    req.setTimeout(60_000, () => {
      req.destroy(new Error('request timeout'));
    });
    req.on('error', reject);
  });

  console.log(`[test] Response via proxy: ${body.trim()}`);

  // Apple's captive portal returns exactly "Success" when there's internet connectivity
  t.true(
    body.includes('Success'),
    `Response should contain 'Success', got: ${body.substring(0, 100)}`
  );
});
