import http from 'node:http';
import { once } from 'node:events';

import { Circuit } from '../src/circuit.ts';
import { TlsChannelConnection } from '../src/channel.ts';
import { getRandomChutneyCircuitPath } from '../src/build-circuit/chutney.ts';

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
  const expectedBody = 'hello-from-tor-ts-chutney-ci';

  const overallTimeoutMs = 2 * 60_000;
  const perStepTimeoutMs = 45_000;
  // Chutney's own `verify` test uses 4747 ("Note the default exit policy").
  // Using a fixed port avoids exit-policy surprises with ephemeral ports.
  const port = Number.parseInt(process.env.TOR_TS_TEST_PORT ?? '4747', 10);
  if (!Number.isFinite(port) || port <= 0) {
    throw new Error(`Invalid TOR_TS_TEST_PORT: ${process.env.TOR_TS_TEST_PORT ?? ''}`);
  }

  const server = http.createServer((_req, res) => {
    res.statusCode = 200;
    res.setHeader('content-type', 'text/plain');
    res.end(expectedBody);
  });

  let circuit: Circuit | undefined;
  try {
    await withTimeout(
      'start local http server',
      10_000,
      (async () => {
        server.listen(port, '127.0.0.1');
        await once(server, 'listening');
      })()
    );

    const path = await withTimeout(
      'get chutney circuit path',
      perStepTimeoutMs,
      getRandomChutneyCircuitPath()
    );
    console.log(
      'selected path:',
      path.map((p) => ({
        rsaIdDigest: p.rsaIdDigest?.toString('hex'),
        linkSpecifiers: p.linkSpecifiers?.map((ls) => ({
          type: ls.type,
          data: ls.data?.toString('hex'),
        })),
      }))
    );
    const channel = new TlsChannelConnection();
    await withTimeout('connect to first hop', perStepTimeoutMs, channel.connectPeerInfo(path[0]));

    circuit = new Circuit({ path, channel });
    await withTimeout('build circuit', perStepTimeoutMs, circuit.connect());

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
        if (err) {
          reject(err);
          return;
        }
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
  // See chutney-hidden-service-ci.ts for why process.exit(1) is needed here.
  process.exit(1);
});
