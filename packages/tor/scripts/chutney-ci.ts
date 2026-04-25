import http from 'node:http';
import { once } from 'node:events';

import { Circuit } from '../src/circuit.ts';
import { TlsChannelConnection } from '../src/channel.ts';
import {
  bootstrapWithChutneyDirectory,
  fetchChutneyConsensusOverCircuit,
  getRandomChutneyCircuitPathSafe,
} from '../src/build-circuit/chutney.ts';

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

function logRaw(label: string): void {
  // Force flush so the partial log survives a SIGTERM from the outer timeout.
  process.stdout.write(`[chutney-ci] ${new Date().toISOString()} ${label}\n`);
}

let currentStep = '<startup>';
let stepStartedAt = Date.now();
function setStep(label: string): void {
  currentStep = label;
  stepStartedAt = Date.now();
  logRaw(label);
}

// Survive a SIGTERM from the outer `timeout` by writing the last known step
// to stdout before the process is forcibly killed. Without this, a hang shows
// up in CI as a bare 'exit code 124' with no breadcrumb.
for (const sig of ['SIGTERM', 'SIGINT'] as const) {
  process.on(sig, () => {
    const elapsed = Date.now() - stepStartedAt;
    process.stdout.write(
      `[chutney-ci] FATAL ${new Date().toISOString()} caught ${sig} during step "${currentStep}" (${elapsed}ms in)\n`
    );
    process.stdout.write('[chutney-ci] active handles: ');
    try {
      const handles = (
        process as unknown as { _getActiveHandles: () => Array<{ constructor: { name: string } }> }
      )._getActiveHandles();
      process.stdout.write(handles.map((h) => h.constructor?.name ?? 'unknown').join(', ') + '\n');
    } catch {
      process.stdout.write('(unavailable)\n');
    }
    process.exit(124);
  });
}

// Also emit a heartbeat every 5s so a hang surfaces as visible "still in step X"
// lines even when the final flush is lost.
const heartbeat = setInterval(() => {
  if (currentStep === '<done>') return;
  const elapsed = Date.now() - stepStartedAt;
  process.stdout.write(
    `[chutney-ci] heartbeat: still in "${currentStep}" (${elapsed}ms elapsed)\n`
  );
}, 5_000);
heartbeat.unref();

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

  let bootstrapCircuit: Circuit | undefined;
  let circuit: Circuit | undefined;
  try {
    setStep('starting local http server');
    await withTimeout(
      'start local http server',
      10_000,
      (async () => {
        server.listen(port, '127.0.0.1');
        await once(server, 'listening');
      })()
    );

    setStep('bootstrap: TLS + 1-hop CREATE_FAST to a chutney relay');
    bootstrapCircuit = await withTimeout(
      'chutney bootstrap',
      perStepTimeoutMs,
      bootstrapWithChutneyDirectory()
    );

    setStep('fetch consensus over bootstrap circuit');
    const consensus = await withTimeout(
      'fetch chutney consensus',
      perStepTimeoutMs,
      fetchChutneyConsensusOverCircuit(bootstrapCircuit)
    );
    setStep(`consensus has ${consensus.relays.length} relays`);

    setStep('look up 3-hop path peer info');
    const path = await withTimeout(
      'lookup chutney 3-hop peer info',
      perStepTimeoutMs,
      getRandomChutneyCircuitPathSafe(bootstrapCircuit, consensus)
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

    setStep('connect TLS to first hop');
    const channel = new TlsChannelConnection();
    await withTimeout('TLS to first hop', perStepTimeoutMs, channel.connectPeerInfo(path[0]!));

    setStep('build 3-hop circuit');
    circuit = new Circuit({ path, channel });
    await withTimeout('build 3-hop circuit', perStepTimeoutMs, circuit.connect());

    // Bootstrap circuit no longer needed once the 3-hop is up.
    bootstrapCircuit.destroy();
    bootstrapCircuit = undefined;

    setStep('open stream to local http server');
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

    setStep('write HTTP request');
    await withTimeout(
      'write request',
      perStepTimeoutMs,
      stream.write(Buffer.from(requestText, 'ascii'))
    );

    setStep('await response');
    await withTimeout('read response', overallTimeoutMs, streamEndedP);

    const responseText = Buffer.concat(responseChunks).toString('utf8');
    if (!responseText.includes('200')) {
      throw new Error(`Expected HTTP 200 in response, got:\n${responseText}`);
    }
    if (!responseText.includes(expectedBody)) {
      throw new Error(`Expected body "${expectedBody}" in response, got:\n${responseText}`);
    }
    setStep('test passed');
  } finally {
    try {
      bootstrapCircuit?.destroy();
    } catch {
      // ignore
    }
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
