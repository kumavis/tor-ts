/**
 * Chutney integration test for the SOCKS5 proxy.
 *
 *  1. Boot a local HTTP server on 127.0.0.1.
 *  2. Bootstrap a chutney 1-hop directory circuit (TLS + CREATE_FAST).
 *  3. Build a 3-hop chutney circuit through the test network.
 *  4. Stand up SocksProxyServer on top of that circuit.
 *  5. Drive a real SOCKS5 client against the proxy and assert we get
 *     the local HTTP server's response back.
 *
 * Mirrors scripts/chutney-ci.ts in structure (per-step labels, heartbeat,
 * SIGTERM diagnostics) so a hang in CI surfaces with a usable breadcrumb.
 */

import http from 'node:http';
import net from 'node:net';
import { once } from 'node:events';

import { Circuit } from '../src/circuit.ts';
import { TlsChannelConnection } from '../src/channel.ts';
import {
  bootstrapWithChutneyDirectory,
  fetchChutneyConsensusOverCircuit,
  getRandomChutneyCircuitPathSafe,
} from '../src/build-circuit/chutney.ts';
import {
  SOCKS_VERSION,
  SocksAddressType,
  SocksAuthMethod,
  SocksCommand,
  SocksProxyServer,
  SocksReply,
} from '../src/socks.ts';

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
  const line = `[chutney-socks-ci] ${new Date().toISOString()} ${label}\n`;
  process.stderr.write(line);
  process.stdout.write(line);
}

let currentStep = '<startup>';
let stepStartedAt = Date.now();
function setStep(label: string): void {
  currentStep = label;
  stepStartedAt = Date.now();
  logRaw(label);
}

for (const sig of ['SIGTERM', 'SIGINT'] as const) {
  process.on(sig, () => {
    const elapsed = Date.now() - stepStartedAt;
    process.stdout.write(
      `[chutney-socks-ci] FATAL ${new Date().toISOString()} caught ${sig} during step "${currentStep}" (${elapsed}ms in)\n`
    );
    process.exit(124);
  });
}

const heartbeat = setInterval(() => {
  if (currentStep === '<done>') return;
  const elapsed = Date.now() - stepStartedAt;
  process.stdout.write(
    `[chutney-socks-ci] heartbeat: still in "${currentStep}" (${elapsed}ms elapsed)\n`
  );
}, 5_000);
heartbeat.unref();

async function main() {
  const expectedBody = 'hello-from-socks-proxy-chutney';

  const overallTimeoutMs = 2 * 60_000;
  const perStepTimeoutMs = 45_000;

  const httpPort = Number.parseInt(process.env.TOR_TS_TEST_PORT ?? '4747', 10);
  if (!Number.isFinite(httpPort) || httpPort <= 0) {
    throw new Error(`Invalid TOR_TS_TEST_PORT: ${process.env.TOR_TS_TEST_PORT ?? ''}`);
  }
  // Bind to 0 by default so two parallel chutney tests can't collide on a
  // hard-coded port; CI can override via TOR_TS_SOCKS_PORT if it needs the
  // port for log assertions.
  const socksPortEnv = process.env.TOR_TS_SOCKS_PORT;
  const socksPort = socksPortEnv === undefined ? 0 : Number.parseInt(socksPortEnv, 10);
  if (!Number.isFinite(socksPort) || socksPort < 0) {
    throw new Error(`Invalid TOR_TS_SOCKS_PORT: ${socksPortEnv ?? ''}`);
  }

  const server = http.createServer((_req, res) => {
    res.statusCode = 200;
    res.setHeader('content-type', 'text/plain');
    res.end(expectedBody);
  });

  let bootstrapCircuit: Circuit | undefined;
  let circuit: Circuit | undefined;
  let socksProxy: SocksProxyServer | undefined;

  try {
    setStep('starting local http server');
    await withTimeout(
      'start local http server',
      10_000,
      (async () => {
        server.listen(httpPort, '127.0.0.1');
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

    setStep('connect TLS to first hop');
    const channel = new TlsChannelConnection();
    await withTimeout('TLS to first hop', perStepTimeoutMs, channel.connectPeerInfo(path[0]!));

    setStep('build 3-hop circuit');
    circuit = new Circuit({ path, channel });
    await withTimeout('build 3-hop circuit', perStepTimeoutMs, circuit.connect());

    bootstrapCircuit.destroy();
    bootstrapCircuit = undefined;

    setStep('start SOCKS proxy');
    socksProxy = new SocksProxyServer({ circuit, port: socksPort, host: '127.0.0.1' });
    await withTimeout('start SOCKS proxy', 10_000, socksProxy.start());
    const addr = socksProxy.address();
    if (!addr || typeof addr === 'string') {
      throw new Error('SOCKS proxy did not bind to a TCP port');
    }
    const boundSocksPort = addr.port;
    setStep(`SOCKS proxy listening on 127.0.0.1:${boundSocksPort}`);

    setStep('GET / through SOCKS proxy');
    const responseText = await withTimeout(
      'SOCKS request',
      overallTimeoutMs,
      makeRequestThroughSocks(boundSocksPort, '127.0.0.1', httpPort)
    );

    if (!responseText.includes('200')) {
      throw new Error(`Expected HTTP 200 in response, got:\n${responseText}`);
    }
    if (!responseText.includes(expectedBody)) {
      throw new Error(`Expected body "${expectedBody}" in response, got:\n${responseText}`);
    }
    setStep('test passed');
  } finally {
    try {
      await socksProxy?.stop();
    } catch {
      // ignore
    }
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

/**
 * Minimal SOCKS5 client: greeting → CONNECT → HTTP request → buffer body
 * → return as text. Kept self-contained on purpose so this test does not
 * depend on the in-tree SOCKS implementation for the client side.
 */
async function makeRequestThroughSocks(
  socksPort: number,
  targetHost: string,
  targetPort: number
): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = net.connect(socksPort, '127.0.0.1', () => {
      socket.write(Buffer.from([SOCKS_VERSION, 0x01, SocksAuthMethod.NO_AUTH]));
    });

    let state: 'greeting' | 'request' | 'connected' = 'greeting';
    let responseData = Buffer.alloc(0);

    socket.setTimeout(60_000);
    socket.on('timeout', () => {
      socket.destroy();
      reject(new Error('SOCKS client socket timeout'));
    });

    socket.on('data', (data: Buffer) => {
      if (state === 'greeting') {
        if (data.length < 2 || data[0] !== SOCKS_VERSION || data[1] !== SocksAuthMethod.NO_AUTH) {
          socket.destroy();
          reject(new Error(`SOCKS greeting failed: ${data.toString('hex')}`));
          return;
        }
        const hostBytes = Buffer.from(targetHost, 'ascii');
        const request = Buffer.concat([
          Buffer.from([
            SOCKS_VERSION,
            SocksCommand.CONNECT,
            0x00,
            SocksAddressType.DOMAIN,
            hostBytes.length,
          ]),
          hostBytes,
          Buffer.from([(targetPort >> 8) & 0xff, targetPort & 0xff]),
        ]);
        socket.write(request);
        state = 'request';
      } else if (state === 'request') {
        if (data.length < 2 || data[0] !== SOCKS_VERSION || data[1] !== SocksReply.SUCCEEDED) {
          socket.destroy();
          reject(new Error(`SOCKS CONNECT failed: ${data.toString('hex')}`));
          return;
        }
        const httpRequest =
          `GET / HTTP/1.1\r\n` +
          `Host: ${targetHost}:${targetPort}\r\n` +
          `Connection: close\r\n` +
          `\r\n`;
        socket.write(httpRequest);
        state = 'connected';
      } else {
        responseData = Buffer.concat([responseData, data]);
      }
    });

    socket.on('end', () => {
      resolve(responseData.toString('utf8'));
    });

    socket.on('error', reject);
  });
}

main().then(
  () => {
    setStep('<done>');
    process.exit(0);
  },
  (err) => {
    console.error(err);
    process.exit(1);
  }
);
