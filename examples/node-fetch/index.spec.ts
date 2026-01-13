/**
 * Example: Making HTTP requests through Tor using node-fetch
 *
 * This example demonstrates how to:
 * 1. Establish a Tor circuit using the safe bootstrap method
 * 2. Create an HTTP agent that routes traffic through the circuit
 * 3. Make fetch requests that go through Tor
 *
 * Run with: yarn test:live
 */

import test from 'ava';
import fetch from 'node-fetch';
import { connectRandomCircuitWithSafeBootstrap } from 'tor/build-circuit/mainnet';
import { getTorAgentForUrl } from 'tor/node';

test('fetch through Tor circuit', async (t) => {
  t.timeout(180_000); // 3 minutes - Tor bootstrap can be slow

  // Step 1: Establish a Tor circuit
  // This connects to a fallback directory, downloads the consensus,
  // and builds a 3-hop circuit (Guard → Middle → Exit)
  console.log('Connecting to Tor network...');
  const circuit = await connectRandomCircuitWithSafeBootstrap();
  console.log('Circuit established!');

  // Clean up when done
  t.teardown(() => circuit.destroy());

  // Step 2: Create an agent for the target URL
  // The agent handles routing traffic through the Tor circuit
  const target = 'http://captive.apple.com';
  const agent = getTorAgentForUrl(circuit, target);

  // Step 3: Make the request using node-fetch with the Tor agent
  console.log(`Fetching ${target} through Tor...`);
  const response = await fetch(target, { agent });

  console.log(`Response status: ${response.status}`);
  t.is(response.status, 200);

  const body = await response.text();
  console.log(`Response body: ${body.trim()}`);

  // captive.apple.com returns "Success" when internet is accessible
  t.true(body.includes('Success'));
});
