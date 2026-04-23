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

/**
 * Retryable Tor-network failures. These are not bugs in this code — they're
 * the normal, expected condition of the live Tor network. A circuit may die
 * mid-bootstrap because the selected guard's upstream OR-to-OR link dropped,
 * or the exit's TCP connect to the target failed, or a relay is overloaded.
 *
 * Retryable DESTROY reasons (per tor-spec.txt §5.4):
 *   4 HIBERNATING, 5 RESOURCELIMIT, 6 CONNECTFAILED, 7 OR_IDENTITY,
 *   8 CHANNEL_CLOSED, 10 TIMEOUT, 11 DESTROYED
 */
function isRetryableTorError(err: unknown): boolean {
  if (!(err instanceof Error)) return false;
  const msg = err.message;
  if (
    /circuit destroyed: (HIBERNATING|RESOURCELIMIT|CONNECTFAILED|OR_IDENTITY|CHANNEL_CLOSED|TIMEOUT|DESTROYED)/.test(
      msg
    )
  ) {
    return true;
  }
  // Common transport-level transients.
  if (/ECONNRESET|ETIMEDOUT|socket hang up|timed out/i.test(msg)) return true;
  return false;
}

async function fetchThroughTor(target: string): Promise<{ status: number; body: string }> {
  const circuit = await connectRandomCircuitWithSafeBootstrap();
  try {
    console.log('Circuit established!');
    const agent = getTorAgentForUrl(circuit, target);
    console.log(`Fetching ${target} through Tor...`);
    const response = await fetch(target, { agent });
    console.log(`Response status: ${response.status}`);
    const body = await response.text();
    console.log(`Response length: ${body.length} bytes`);
    return { status: response.status, body };
  } finally {
    circuit.destroy();
  }
}

test('fetch through Tor circuit', async (t) => {
  t.timeout(600_000); // 10 minutes total — each attempt can take minutes.

  const target = 'http://example.com';
  console.log('Connecting to Tor network...');

  const maxAttempts = 3;
  let lastError: Error | undefined;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const { status, body } = await fetchThroughTor(target);
      t.is(status, 200);
      t.true(body.includes('Example Domain'), 'Response should contain "Example Domain"');
      return;
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));
      if (attempt < maxAttempts && isRetryableTorError(lastError)) {
        console.warn(
          `Attempt ${attempt} hit transient Tor error: ${lastError.message}. Retrying...`
        );
        continue;
      }
      throw lastError;
    }
  }
  throw lastError ?? new Error('unreachable');
});
