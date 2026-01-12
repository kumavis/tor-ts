/**
 * Live test for node-fetch example.
 *
 * Tests that we can establish a Tor circuit and make HTTP requests through it.
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

  const target = 'https://api.ipify.org';
  console.log(`[test] Fetching ${target} through Tor...`);

  const agent = getTorAgentForUrl(circuit, target);
  const response = await fetch(target, { agent });

  console.log(`[test] Got response: ${response.status}`);
  t.is(response.status, 200, 'Response should be 200 OK');

  const ipAddress = await response.text();
  console.log(`[test] IP address via Tor: ${ipAddress}`);

  // Verify we got a valid IP address format (IPv4 or IPv6)
  const ipv4Regex = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
  const ipv6Regex = /^[a-fA-F0-9:]+$/;
  t.true(
    ipv4Regex.test(ipAddress) || ipv6Regex.test(ipAddress),
    `Response should be a valid IP address, got: ${ipAddress}`
  );
});
