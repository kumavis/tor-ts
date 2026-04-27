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
import type { CircuitHttpsAgent, CircuitHttpAgent } from 'tor/node';

/**
 * Print what's keeping the event loop alive at delay-from-now `ms`. The
 * timer is `unref`'d so it doesn't itself keep the loop alive — if the
 * loop drains naturally we never see this print, and if it doesn't we
 * get a typed snapshot of the leftover handles. Used to diagnose the
 * "ava worker hangs after the test passes" problem; see
 * https://github.com/kumavis/tor-ts/pull/38 for the running discussion.
 */
function dumpHandlesAfter(ms: number, label: string): void {
  const timer = setTimeout(() => {
    const resources = process.getActiveResourcesInfo?.() ?? [];
    const handles =
      (
        process as unknown as { _getActiveHandles?: () => Array<{ constructor: { name: string } }> }
      )._getActiveHandles?.() ?? [];
    const handleNames = handles.map((h) => h?.constructor?.name ?? 'unknown');
    console.log(
      `[diagnostic ${label} +${ms}ms] resources=${resources.length} handles=${handles.length}`
    );
    console.log(`[diagnostic ${label} +${ms}ms] resource types: ${resources.join(', ')}`);
    console.log(`[diagnostic ${label} +${ms}ms] handle types:   ${handleNames.join(', ')}`);
  }, ms);
  timer.unref();
}

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
      // Destroy the agent inside the per-attempt callback's `finally`. A
      // single `agentRef` outside the callback would silently overwrite —
      // and orphan — any agent created on a failed retry, which keeps
      // pooled sockets alive and reintroduces the worker-hang we just
      // fixed.
      const agent: CircuitHttpsAgent | CircuitHttpAgent = getTorAgentForUrl(circuit, target);
      try {
        console.log(`Fetching ${target} through Tor...`);
        const response = await fetch(target, { agent });
        console.log(`Response status: ${response.status}`);
        const text = await response.text();
        console.log(`Response length: ${text.length} bytes`);
        return { status: response.status, body: text };
      } finally {
        agent.destroy();
      }
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

  // Diagnostic: if the worker hangs past these checkpoints, the named
  // handle types are what's keeping the loop alive. Each print uses an
  // `unref()`'d timer so this is a no-op when the loop drains cleanly.
  dumpHandlesAfter(2_000, 'node-fetch');
  dumpHandlesAfter(10_000, 'node-fetch');
  dumpHandlesAfter(60_000, 'node-fetch');
});
