/**
 * Example: HTTP Proxy Server over Tor
 *
 * This example demonstrates how to:
 * 1. Establish a Tor circuit (with retry on transient failures)
 * 2. Create an HTTP proxy server that routes traffic through Tor
 * 3. Handle HTTP proxy requests
 *
 * Run with: yarn test:live
 */

import http from 'http';
import test from 'ava';
import httpProxy from 'http-proxy';
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

test('proxy HTTP request through Tor circuit', async (t) => {
  // 10 minutes total to cover up to 3 bootstrap attempts on the live network.
  t.timeout(600_000);

  const port = 19234;
  const targetUrl = 'http://example.com/';

  console.log('Connecting to Tor network...');

  // Track resources created inside the operation so the test body can
  // tear them down after assertions — http.Agent / https.Agent and
  // httpProxy each retain socket pools and IPC channels that delay the
  // ava worker's natural exit.
  const torAgents: Array<CircuitHttpsAgent | CircuitHttpAgent> = [];
  let proxyRef: ReturnType<typeof httpProxy.createProxyServer> | undefined;

  // withTorOperation builds a fresh 3-hop circuit for each attempt and
  // retries automatically on transient Tor-network / transport-level failures
  // (ECONNREFUSED to a fallback dir, DESTROY with CHANNEL_CLOSED / TIMEOUT,
  // socket hang-ups, etc.). Each attempt rebinds its own proxy server and
  // reissues the request, so the proxied request stays side-effect-free.
  const body = await withTorOperation(
    async (circuit) => {
      console.log('Circuit established!');

      // Reset per-attempt: each retry creates a fresh proxy + agent pool.
      torAgents.length = 0;
      const proxy = httpProxy.createProxyServer({});
      proxyRef = proxy;
      proxy.on('error', (err, _req, res) => {
        console.error('Proxy error:', err.message);
        if (res && 'writeHead' in res) {
          res.writeHead(502, { 'Content-Type': 'text/plain' });
          res.end('Proxy error: ' + err.message);
        }
      });

      const proxyServer = http.createServer((req, res) => {
        const reqTarget = req.url as string;
        console.log(`Proxying: ${reqTarget}`);
        const agent = getTorAgentForUrl(circuit, reqTarget);
        torAgents.push(agent);
        proxy.web(req, res, {
          target: reqTarget,
          agent,
          changeOrigin: true,
        });
      });

      try {
        await new Promise<void>((resolve) => {
          proxyServer.listen(port, () => {
            console.log(`Proxy server listening on port ${port}`);
            resolve();
          });
        });

        console.log(`Making request through proxy to ${targetUrl}...`);
        return await new Promise<string>((resolve, reject) => {
          const req = http.request(
            {
              host: 'localhost',
              port,
              method: 'GET',
              path: targetUrl,
              headers: { Host: 'example.com' },
            },
            (res) => {
              let data = '';
              res.setEncoding('utf8');
              res.on('data', (chunk) => (data += chunk));
              res.on('end', () => resolve(data));
            }
          );
          req.setTimeout(120_000, () => req.destroy(new Error('timeout')));
          req.on('error', reject);
          req.end();
        });
      } finally {
        proxyServer.close();
      }
    },
    {
      // Bootstrap flakiness on the live network is real: the fallback-directory
      // pool may be briefly unhealthy. 5 attempts with a small linear backoff
      // papers over the usual transient storms.
      maxAttempts: 5,
      backoffMs: (failedAttempt) => 2_000 * failedAttempt,
      onRetry: (attempt, err) =>
        console.warn(`Attempt ${attempt} hit transient Tor error: ${err.message}. Retrying...`),
    }
  );

  // Tear down agents + proxy before assertions so ava's worker can drain
  // naturally. node-http-proxy keeps its own internal http.Agent slot;
  // calling .close() releases the listener but doesn't always release
  // pooled sockets.
  for (const agent of torAgents) agent.destroy();
  proxyRef?.close();

  console.log(`Response length: ${body.length} bytes`);
  t.true(body.includes('Example Domain'), 'Response should contain "Example Domain"');

  // Diagnostic: if the worker hangs past these checkpoints, the named
  // handle types are what's keeping the loop alive. Each print uses an
  // `unref()`'d timer so this is a no-op when the loop drains cleanly.
  dumpHandlesAfter(2_000, 'http-proxy');
  dumpHandlesAfter(10_000, 'http-proxy');
  dumpHandlesAfter(60_000, 'http-proxy');
});
