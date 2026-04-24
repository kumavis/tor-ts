import http from 'node:http';
import { once } from 'node:events';

import { connectSnowflakeChutneyCircuit } from '../src/tor-chutney.ts';

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

async function main() {
  const expectedBody = 'hello-from-tor-ts-chutney-snowflake-ci';
  const relayUrl = process.env.TOR_TS_SNOWFLAKE_RELAY_URL ?? 'ws://127.0.0.1:9900/';

  const overallTimeoutMs = 2 * 60_000;
  const perStepTimeoutMs = 60_000;
  const port = Number.parseInt(process.env.TOR_TS_TEST_PORT ?? '4747', 10);
  if (!Number.isFinite(port) || port <= 0) {
    throw new Error(`Invalid TOR_TS_TEST_PORT: ${process.env.TOR_TS_TEST_PORT ?? ''}`);
  }

  const server = http.createServer((_req, res) => {
    res.statusCode = 200;
    res.setHeader('content-type', 'text/plain');
    res.end(expectedBody);
  });

  let circuit: Awaited<ReturnType<typeof connectSnowflakeChutneyCircuit>> | undefined;
  try {
    await withTimeout(
      'start local http server',
      10_000,
      (async () => {
        server.listen(port, '127.0.0.1');
        await once(server, 'listening');
      })()
    );

    circuit = await withTimeout(
      'connect snowflake chutney circuit',
      overallTimeoutMs,
      connectSnowflakeChutneyCircuit({ relayUrl })
    );

    const stream = await withTimeout(
      'open stream',
      perStepTimeoutMs,
      circuit.open(`127.0.0.1:${port}`)
    );

    const responseChunks: Buffer[] = [];
    stream.on('data', (data) => {
      responseChunks.push(Buffer.from(data));
    });

    const streamEndedP = new Promise<void>((resolve, reject) => {
      stream.once('end', (err?: Error) => {
        if (err) return reject(err);
        resolve();
      });
    });

    const requestText =
      `GET / HTTP/1.1\r\n` + `Host: 127.0.0.1:${port}\r\n` + `Connection: close\r\n` + `\r\n`;

    await withTimeout(
      'write request',
      perStepTimeoutMs,
      stream.write(Buffer.from(requestText, 'ascii'))
    );
    await withTimeout('read response', overallTimeoutMs, streamEndedP);

    const responseText = Buffer.concat(responseChunks).toString('utf8');
    if (!responseText.includes('200')) {
      throw new Error(`Expected HTTP 200 in response, got:\n${responseText}`);
    }
    if (!responseText.includes(expectedBody)) {
      throw new Error(`Expected body "${expectedBody}" in response, got:\n${responseText}`);
    }
  } finally {
    try {
      circuit?.destroy();
    } catch {
      // ignore
    }
    server.close();
  }
}

main().catch((err) => {
  console.error(err);
  // Force-exit: WebSocket downlink, KCP auto-flush timer, and smux keepalive
  // all hold the event loop open; process.exitCode alone would stretch a
  // fast failure into the outer `timeout` ceiling.
  process.exit(1);
});
