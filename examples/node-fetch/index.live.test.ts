/**
 * Live test for node-fetch example.
 *
 * Tests that we can establish a Tor circuit and make HTTP requests through it.
 * Uses captive.apple.com which returns a simple "Success" response and doesn't
 * block Tor exit nodes like many other services do.
 */

import test from 'ava';
import fetch from 'node-fetch';
import { connectRandomCircuitWithSafeBootstrap } from 'tor/build-circuit/mainnet';
import { getTorAgentForUrl } from 'tor/node';

test('node-fetch: can fetch through Tor circuit', async (t) => {
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
  console.log(`[test] Fetching ${target} through Tor...`);

  const agent = getTorAgentForUrl(circuit, target);
  const response = await fetch(target, { agent });

  console.log(`[test] Got response: ${response.status}`);
  t.is(response.status, 200, 'Response should be 200 OK');

  const body = await response.text();
  console.log(`[test] Response body: ${body.trim()}`);

  // Apple's captive portal returns exactly "Success" when there's internet connectivity
  t.true(
    body.includes('Success'),
    `Response should contain 'Success', got: ${body.substring(0, 100)}`
  );
});
