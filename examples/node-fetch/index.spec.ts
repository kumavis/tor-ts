/**
 * Example: Making HTTP requests through Tor using node-fetch
 *
 * This example demonstrates how to:
 * 1. Establish a Tor circuit using the safe bootstrap method (with retry)
 * 2. Create an HTTP agent that routes traffic through the circuit
 * 3. Make fetch requests that go through Tor
 *
 * Run with: yarn test:live
 */

import test from 'ava';
import fetch from 'node-fetch';
import { withTorOperation } from 'tor/build-circuit/mainnet';
import { getTorAgentForUrl } from 'tor/node';

test('fetch through Tor circuit', async (t) => {
  // 10 minutes total to cover up to 3 attempts through the live Tor network.
  t.timeout(600_000);

  const target = 'http://example.com';
  console.log('Connecting to Tor network...');

  // withTorOperation builds a fresh 3-hop circuit for each attempt and
  // retries automatically on transient Tor-network failures (relay DESTROYs
  // with reasons like CHANNEL_CLOSED/TIMEOUT, transport-level ECONNRESET,
  // etc.). Each attempt runs the whole body from scratch, so only use it
  // for side-effect-free work — for batch workloads call
  // buildCircuitWithRetry + retryTransient per-request instead.
  const { status, body } = await withTorOperation(
    async (circuit) => {
      console.log('Circuit established!');
      const agent = getTorAgentForUrl(circuit, target);
      console.log(`Fetching ${target} through Tor...`);
      const response = await fetch(target, { agent });
      console.log(`Response status: ${response.status}`);
      const text = await response.text();
      console.log(`Response length: ${text.length} bytes`);
      return { status: response.status, body: text };
    },
    {
      maxAttempts: 3,
      onRetry: (attempt, err) =>
        console.warn(`Attempt ${attempt} hit transient Tor error: ${err.message}. Retrying...`),
    }
  );

  t.is(status, 200);
  t.true(body.includes('Example Domain'), 'Response should contain "Example Domain"');
});
