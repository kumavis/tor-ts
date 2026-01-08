import http from 'node:http';
import { once } from 'node:events';
import fs from 'node:fs/promises';
import type net from 'node:net';

import { connectToHiddenServiceOverChutney } from '../src/hidden-service.ts';

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

async function main() {
  const expectedBody = 'hello-from-tor-ts-chutney-hidden-service-ci';

  const overallTimeoutMs = 8 * 60_000;
  const perStepTimeoutMs = 90_000;

  // Local HTTP server that the chutney onion-service node will forward to.
  const targetPort = Number.parseInt(process.env.TOR_TS_HS_TARGET_PORT ?? '4748', 10);
  if (!Number.isFinite(targetPort) || targetPort <= 0) {
    throw new Error(`Invalid TOR_TS_HS_TARGET_PORT: ${process.env.TOR_TS_HS_TARGET_PORT ?? ''}`);
  }

  const hostnamePath =
    process.env.TOR_TS_HS_HOSTNAME_PATH ??
    `${process.env.CHUTNEY_DATA_DIR ?? ''}/hs_service/hostname`;

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
    socket.on('close', () => openSockets.delete(socket));
  });

  try {
    await withTimeout(
      'start local http server',
      10_000,
      (async () => {
        server.listen(targetPort, '127.0.0.1');
        await once(server, 'listening');
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

    const { circuit, stream } = await withTimeout(
      'connect to hidden service over chutney',
      overallTimeoutMs + 90_000,
      connectToHiddenServiceOverChutney({ onionAddress, port: 80, overallTimeoutMs })
    );
    console.log('hs: connected, issuing HTTP request');

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
      `GET / HTTP/1.1\r\n` + `Host: ${onionAddress}\r\n` + `Connection: close\r\n` + `\r\n`;
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
    circuit.destroy();
  } finally {
    // Ensure the process doesn't hang on lingering keepalive connections.
    for (const s of openSockets) s.destroy();
    await withTimeout(
      'close local http server',
      10_000,
      (async () => {
        server.close();
        await once(server, 'close');
      })()
    );
  }
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
