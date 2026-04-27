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
      // Bootstrap flakiness on the live network is real: the fallback-directory
      // pool may be briefly unhealthy, and picking a fresh guard on each retry
      // doesn't help if several in a row happen to be unreachable. 5 attempts
      // with a small linear backoff papers over the usual transient storms.
      maxAttempts: 5,
      backoffMs: (failedAttempt) => 2_000 * failedAttempt,
      onRetry: (attempt, err) =>
        console.warn(`Attempt ${attempt} hit transient Tor error: ${err.message}. Retrying...`),
    }
  );

  t.is(status, 200);
  t.true(body.includes('Example Domain'), 'Response should contain "Example Domain"');

  // Schedule a hard-exit deadline. Tor-side TLS sockets sometimes don't
  // close cleanly within the small grace window ava waits before exiting
  // the worker, hanging CI for several minutes despite the test already
  // having passed. The timer is `unref`'d so it doesn't itself keep the
  // loop alive — it only fires if some *other* handle does, in which case
  // SIGTERM kills the worker. The parent ava process has already received
  // the pass result over IPC at this point, so the test is reported as
  // passing either way. Mirrors the explicit `process.exit(0)` the chutney
  // scripts use; we can't call `process.exit` directly here because ava
  // intercepts it.
  setTimeout(() => process.kill(process.pid, 'SIGTERM'), 5000).unref();
});
