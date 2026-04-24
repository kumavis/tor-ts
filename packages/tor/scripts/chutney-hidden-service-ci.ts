import http from 'node:http';
import { once } from 'node:events';
import fs from 'node:fs/promises';
import type net from 'node:net';

import { makeChutneyTorClient } from '../src/build-circuit/chutney.ts';
import { retryTransient } from '../src/build-circuit/mainnet.ts';

async function withTimeout<T>(label: string, ms: number, promise: Promise<T>): Promise<T> {
  let timeout: NodeJS.Timeout | undefined;
  const timeoutP = new Promise<never>((_resolve, reject) => {
    timeout = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
  });
  try {
    return await Promise.race([promise, timeoutP]);
  } finally {
    if (timeout) clearTimeout(timeout);
  }
}

async function waitForFile(path: string, timeoutMs: number): Promise<string> {
  const start = Date.now();
  const deadline = start + timeoutMs;
  while (Date.now() <= deadline) {
    try {
      return await fs.readFile(path, 'utf8');
    } catch {
      await new Promise((r) => setTimeout(r, 250));
    }
  }
  throw new Error(`Timed out waiting for file: ${path}`);
}

const REQUIRED_ENV = [
  'TOR_TS_HS_HOSTNAME_PATH',
  'TOR_TS_HS_TARGET_PORT',
  'TOR_TS_HS_VIRTPORT',
] as const;

function assertEnv(): {
  hostnamePath: string;
  targetPort: number;
  hsVirtPort: number;
} {
  const missing = REQUIRED_ENV.filter((k) => !process.env[k]);
  if (missing.length) {
    throw new Error(
      `Missing required env: ${missing.join(', ')}. CI sets these; for local runs set TOR_TS_HS_HOSTNAME_PATH (e.g. $CHUTNEY_DATA_DIR/nodes/Node-h1/hidden_service/hostname), TOR_TS_HS_TARGET_PORT (e.g. 4747), TOR_TS_HS_VIRTPORT (e.g. 5858).`
    );
  }
  const hostnamePath = process.env.TOR_TS_HS_HOSTNAME_PATH!;
  const targetPort = Number.parseInt(process.env.TOR_TS_HS_TARGET_PORT!, 10);
  const hsVirtPort = Number.parseInt(process.env.TOR_TS_HS_VIRTPORT!, 10);
  if (!Number.isFinite(targetPort) || targetPort <= 0) {
    throw new Error(`Invalid TOR_TS_HS_TARGET_PORT: ${process.env.TOR_TS_HS_TARGET_PORT}`);
  }
  if (!Number.isFinite(hsVirtPort) || hsVirtPort <= 0) {
    throw new Error(`Invalid TOR_TS_HS_VIRTPORT: ${process.env.TOR_TS_HS_VIRTPORT}`);
  }
  return { hostnamePath, targetPort, hsVirtPort };
}

async function main() {
  const expectedBody = 'hello-from-tor-ts-chutney-hidden-service-ci';

  const overallTimeoutMs = 8 * 60_000;
  const perStepTimeoutMs = 90_000;

  const { hostnamePath, targetPort, hsVirtPort } = assertEnv();

  const openSockets = new Set<net.Socket>();
  const server = http.createServer((_req, res) => {
    const body = expectedBody;
    res.statusCode = 200;
    res.setHeader('content-type', 'text/plain');
    // Make response framing deterministic so the client doesn't need to wait for socket close.
    res.setHeader('content-length', Buffer.byteLength(body).toString());
    res.setHeader('connection', 'close');
    res.end(body);
  });
  server.on('connection', (socket) => {
    openSockets.add(socket);
    // Don't keep the process alive because of keepalive sockets.
    socket.unref();
    socket.on('close', () => openSockets.delete(socket));
  });

  try {
    await withTimeout(
      'start local http server',
      10_000,
      (async () => {
        server.listen(targetPort, '127.0.0.1');
        await once(server, 'listening');
        // Don't keep the process alive on server handle.
        server.unref();
      })()
    );

    const onionAddress = (
      await withTimeout(
        'wait for hidden service hostname',
        overallTimeoutMs,
        waitForFile(hostnamePath, overallTimeoutMs)
      )
    )
      .trim()
      .split(/\s+/)[0];
    if (!onionAddress || !onionAddress.endsWith('.onion')) {
      throw new Error(`Invalid onion address read from ${hostnamePath}: "${onionAddress ?? ''}"`);
    }
    console.log('hidden service address:', onionAddress);

    // Create Chutney client
    const client = await withTimeout(
      'create chutney client',
      overallTimeoutMs,
      makeChutneyTorClient({ onStatus: (msg) => console.log(`client: ${msg}`) })
    );

    // Connect to hidden service. Chutney's tiny 8-node network is prone to
    // transient rendezvous failures ("Timed out waiting for relayCommand=37")
    // when the HS-side circuit flakes; retry once with a fresh rendezvous so
    // a single bad try doesn't eat the whole 10-minute CI budget.
    const { circuit } = await retryTransient(
      () =>
        withTimeout(
          'connect to hidden service',
          overallTimeoutMs + 90_000,
          client.connectToHiddenService(onionAddress, hsVirtPort, { overallTimeoutMs })
        ),
      {
        maxAttempts: 2,
        onRetry: (attempt, err) =>
          console.warn(`hs connect attempt ${attempt} failed: ${err.message}. Retrying...`),
      }
    );
    console.log('hs: connected, opening stream');

    // Open stream to the hidden service
    const stream = await withTimeout(
      'open stream',
      30_000,
      circuit.open(`${onionAddress}:${hsVirtPort}`)
    );
    console.log('hs: stream open, issuing HTTP request');

    const responseChunks: Buffer[] = [];
    stream.on('data', (data: Buffer) => {
      responseChunks.push(Buffer.from(data));
    });
    const responseCompleteP = (async () => {
      const start = Date.now();
      while (Date.now() - start < overallTimeoutMs) {
        const buf = Buffer.concat(responseChunks);
        const headerEnd = buf.indexOf('\r\n\r\n');
        if (headerEnd !== -1) {
          const headersText = buf.subarray(0, headerEnd).toString('utf8');
          const m = headersText.match(/\r?\ncontent-length:\s*(\d+)\s*\r?\n/i);
          if (m?.[1]) {
            const contentLength = Number.parseInt(m[1], 10);
            const bodyStart = headerEnd + 4;
            if (buf.length >= bodyStart + contentLength) return;
          }
        }
        await new Promise((r) => setTimeout(r, 25));
      }
      throw new Error('Timed out waiting for complete HTTP response (content-length)');
    })();

    const requestText =
      `GET / HTTP/1.1\r\n` +
      `Host: ${onionAddress}:${hsVirtPort}\r\n` +
      `Connection: close\r\n` +
      `\r\n`;
    await withTimeout(
      'write request',
      perStepTimeoutMs,
      stream.write(Buffer.from(requestText, 'ascii'))
    );
    await withTimeout('read response', overallTimeoutMs, responseCompleteP);
    console.log('hs: response received (content-length satisfied)');

    const responseText = Buffer.concat(responseChunks).toString('utf8');
    if (!responseText.includes('200')) {
      throw new Error(`Expected HTTP 200 in response, got:\n${responseText}`);
    }
    if (!responseText.includes(expectedBody)) {
      throw new Error(`Expected body "${expectedBody}" in response, got:\n${responseText}`);
    }

    console.log('hs: assertions passed, tearing down');
    // Best-effort close to avoid waiting for remote END cells.
    stream.destroy();
    client.destroy();
  } finally {
    // Ensure the process doesn't hang on lingering keepalive connections.
    for (const s of openSockets) s.destroy();
    server.close();
  }
}

main().catch((err) => {
  console.error(err);
  // Force-exit: this script holds open channel padding timers, TLS sockets,
  // and (on failure) pending circuit handshakes. Setting process.exitCode
  // alone is not enough — Node waits for the event loop to drain and the
  // outer `timeout` wrapper eventually SIGTERMs us, stretching a 60-second
  // rendezvous transient into a 15-minute CI job.
  process.exit(1);
});
