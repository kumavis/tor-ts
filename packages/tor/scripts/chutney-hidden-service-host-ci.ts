/**
 * Chutney integration test for hidden-service hosting.
 *
 * Publishes a v3 onion service via {@link publishHiddenService} on the local
 * chutney network, then connects to it as a client through
 * {@link makeChutneyTorClient} and asserts an HTTP exchange round-trips.
 *
 * The host's `onConnection` callback hands us each accepted incoming stream
 * (one per BEGIN cell). We run a minimal HTTP responder per stream — enough
 * to verify the full INTRODUCE1 → INTRODUCE2 → RENDEZVOUS1 → RENDEZVOUS2 →
 * BEGIN → DATA → END pipeline.
 *
 * Gated via `TOR_TS_CHUTNEY_TESTS` including `hidden-service-host`; OFF by
 * default in `ci-chutney.sh` because it exercises the full HS protocol stack
 * end-to-end and is the most fragile test in the suite.
 */

import type { CircuitStream } from '../src/circuit.ts';
import { publishHiddenService } from '../src/hidden-service-host.ts';
import { makeChutneyTorClient } from '../src/build-circuit/chutney.ts';

const HS_VIRTUAL_PORT = 80;
const EXPECTED_BODY = 'hello-from-tor-ts-hidden-service-host';

async function withTimeout<T>(label: string, ms: number, p: Promise<T>): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeoutP = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
  });
  try {
    return await Promise.race([p, timeoutP]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/** Minimal HTTP/1.1 responder per accepted stream. */
function attachHttpResponder(stream: CircuitStream, log: (msg: string) => void): void {
  let answered = false;
  stream.on('data', (data: Buffer) => {
    if (answered) return;
    answered = true;
    log(`responder: ${data.length}B request on stream=${stream.streamId}`);
    const body = EXPECTED_BODY;
    const response = Buffer.from(
      `HTTP/1.1 200 OK\r\n` +
        `Content-Type: text/plain\r\n` +
        `Content-Length: ${body.length}\r\n` +
        `Connection: close\r\n` +
        `\r\n` +
        body,
      'utf8'
    );
    stream.write(response).catch((err) => log(`write failed: ${err}`));
    // Best-effort: tear down the stream so the client sees END.
    setTimeout(() => stream.destroy(), 50);
  });
}

async function main(): Promise<void> {
  const log = (msg: string) => console.log(`[hs-host-ci] ${msg}`);

  const overallTimeoutMs = 10 * 60_000;
  const perStepTimeoutMs = 120_000;

  log('bootstrapping host TorClient...');
  const hostClient = await withTimeout(
    'makeChutneyTorClient (host)',
    overallTimeoutMs,
    makeChutneyTorClient({ onStatus: (m) => log(`host-client: ${m}`) })
  );

  let host: Awaited<ReturnType<typeof publishHiddenService>> | undefined;
  let visitorClient: Awaited<ReturnType<typeof makeChutneyTorClient>> | undefined;
  try {
    log('publishing hidden service...');
    host = await withTimeout(
      'publishHiddenService',
      overallTimeoutMs,
      publishHiddenService({
        torClient: hostClient,
        port: HS_VIRTUAL_PORT,
        onConnection: (stream) => {
          log(`onConnection: stream=${stream.streamId} dest=${stream.destination}`);
          attachHttpResponder(stream, log);
        },
        numIntroPoints: 2,
        perStepTimeoutMs,
        log: (m) => log(`host: ${m}`),
      })
    );
    log(`onion address: ${host.onion}`);
    log(`active intro points: ${host.numActiveIntroPoints()}`);

    log('waiting 10s for descriptor propagation...');
    await new Promise((r) => setTimeout(r, 10_000));

    log('bootstrapping visitor TorClient...');
    visitorClient = await withTimeout(
      'makeChutneyTorClient (visitor)',
      overallTimeoutMs,
      makeChutneyTorClient({ onStatus: (m) => log(`visitor-client: ${m}`) })
    );

    log('connecting to hidden service...');
    const { circuit } = await withTimeout(
      'connectToHiddenService',
      overallTimeoutMs,
      visitorClient.connectToHiddenService(host.onion, HS_VIRTUAL_PORT, {
        overallTimeoutMs: perStepTimeoutMs,
      })
    );
    log('connected; opening application stream');

    const stream = await withTimeout(
      'open stream',
      30_000,
      circuit.open(`${host.onion}:${HS_VIRTUAL_PORT}`)
    );

    const chunks: Buffer[] = [];
    stream.on('data', (d: Buffer) => chunks.push(Buffer.from(d)));

    const completeP = (async () => {
      const start = Date.now();
      while (Date.now() - start < overallTimeoutMs) {
        const buf = Buffer.concat(chunks);
        const headerEnd = buf.indexOf('\r\n\r\n');
        if (headerEnd !== -1) {
          const headers = buf.subarray(0, headerEnd).toString('utf8');
          const m = headers.match(/\r?\ncontent-length:\s*(\d+)\s*\r?\n/i);
          if (m?.[1]) {
            const cl = Number.parseInt(m[1], 10);
            if (buf.length >= headerEnd + 4 + cl) return;
          }
        }
        await new Promise((r) => setTimeout(r, 50));
      }
      throw new Error('Timed out waiting for HTTP response from hidden service');
    })();

    log('sending HTTP GET');
    const requestText =
      `GET / HTTP/1.1\r\n` + `Host: ${host.onion}\r\n` + `Connection: close\r\n` + `\r\n`;
    await withTimeout(
      'write request',
      perStepTimeoutMs,
      stream.write(Buffer.from(requestText, 'ascii'))
    );

    await withTimeout('await response', overallTimeoutMs, completeP);
    const responseText = Buffer.concat(chunks).toString('utf8');
    log(`response head: ${responseText.split('\r\n')[0] ?? '(none)'}`);

    if (!responseText.includes(' 200 ')) {
      throw new Error(`Expected HTTP 200, got:\n${responseText.slice(0, 400)}`);
    }
    if (!responseText.includes(EXPECTED_BODY)) {
      throw new Error(`Expected body "${EXPECTED_BODY}" in response, got:\n${responseText}`);
    }

    log('PASS — hidden service hosted + reachable end-to-end via chutney');

    stream.destroy();
    circuit.destroy();
  } finally {
    if (host) await host.unpublish();
    if (visitorClient) {
      try {
        visitorClient.destroy();
      } catch {
        // best-effort
      }
    }
    try {
      hostClient.destroy();
    } catch {
      // best-effort
    }
  }
}

main().then(
  () => {
    // Same reason as chutney-hidden-service-ci.ts: channel-padding timers
    // and TLS sockets keep the event loop alive. Force-exit so CI's outer
    // `timeout` doesn't have to.
    process.exit(0);
  },
  (err) => {
    console.error('hs-host CI failed:', err);
    process.exit(1);
  }
);
