/**
 * Example: Making HTTP requests through Tor using Node's http module
 *
 * This example demonstrates how to:
 * 1. Establish a Tor circuit
 * 2. Create an HTTP agent that routes traffic through Tor
 * 3. Make requests using Node's native http module
 *
 * This is the foundation for building an HTTP proxy server over Tor.
 * See README.md for the full proxy server example.
 *
 * Run with: yarn test:live
 */

import http from 'http';
import test from 'ava';
import { connectRandomCircuitWithSafeBootstrap } from 'tor/build-circuit/mainnet';
import { getTorAgentForUrl } from 'tor/node';

test('http request through Tor circuit', async (t) => {
  t.timeout(300_000); // 5 minutes - Tor bootstrap can be slow

  // Step 1: Establish a Tor circuit
  console.log('Connecting to Tor network...');
  const circuit = await connectRandomCircuitWithSafeBootstrap();
  console.log('Circuit established!');

  // Clean up when done
  t.teardown(() => circuit.destroy());

  // Step 2: Create an agent for the target URL
  // Using example.com - the IANA-reserved domain guaranteed to always work
  const target = 'http://example.com';
  const agent = getTorAgentForUrl(circuit, target);

  // Step 3: Make the request using Node's http module with the Tor agent
  console.log(`Fetching ${target} through Tor...`);

  const body = await new Promise<string>((resolve, reject) => {
    const req = http.get(target, { agent }, (res) => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => resolve(data));
    });
    req.setTimeout(120_000, () => req.destroy(new Error('request timeout')));
    req.on('error', reject);
  });

  console.log(`Response length: ${body.length} bytes`);

  // example.com returns a simple HTML page with "Example Domain" in the title
  t.true(body.includes('Example Domain'), 'Response should contain "Example Domain"');
});
