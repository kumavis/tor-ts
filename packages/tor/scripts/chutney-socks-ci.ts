/**
 * Chutney integration test for SOCKS proxy over Tor.
 *
 * This test:
 * 1. Starts a local HTTP server
 * 2. Builds a Tor circuit through Chutney
 * 3. Starts a SOCKS5 proxy server using the circuit
 * 4. Makes a request through the SOCKS proxy to the HTTP server
 * 5. Verifies the response
 */

import http from 'node:http';
import net from 'node:net';
import { once } from 'node:events';

import { Circuit } from '../src/circuit.ts';
import { TlsChannelConnection } from '../src/channel.ts';
import { getRandomChutneyCircuitPath } from '../src/build-circuit/chutney.ts';
import { SocksProxyServer } from '../src/socks.ts';

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
  const expectedBody = 'hello-from-socks-proxy-test';

  const overallTimeoutMs = 2 * 60_000;
  const perStepTimeoutMs = 45_000;
  const httpPort = Number.parseInt(process.env.TOR_TS_TEST_PORT ?? '4747', 10);
  const socksPort = Number.parseInt(process.env.TOR_TS_SOCKS_PORT ?? '1080', 10);

  if (!Number.isFinite(httpPort) || httpPort <= 0) {
    throw new Error(`Invalid TOR_TS_TEST_PORT: ${process.env.TOR_TS_TEST_PORT ?? ''}`);
  }
  if (!Number.isFinite(socksPort) || socksPort <= 0) {
    throw new Error(`Invalid TOR_TS_SOCKS_PORT: ${process.env.TOR_TS_SOCKS_PORT ?? ''}`);
  }

  // Start HTTP server
  const server = http.createServer((_req, res) => {
    res.statusCode = 200;
    res.setHeader('content-type', 'text/plain');
    res.end(expectedBody);
  });

  let circuit: Circuit | undefined;
  let socksProxy: SocksProxyServer | undefined;

  try {
    await withTimeout(
      'start local http server',
      10_000,
      (async () => {
        server.listen(httpPort, '127.0.0.1');
        await once(server, 'listening');
        console.log(`HTTP server listening on port ${httpPort}`);
      })()
    );

    // Build Tor circuit
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
    console.log('Tor circuit established');

    // Start SOCKS proxy
    socksProxy = new SocksProxyServer({
      circuit,
      port: socksPort,
      host: '127.0.0.1',
    });

    await withTimeout('start SOCKS proxy', 10_000, socksProxy.start());
    console.log(`SOCKS proxy listening on port ${socksPort}`);

    // Make request through SOCKS proxy
    const response = await withTimeout(
      'SOCKS proxy request',
      overallTimeoutMs,
      makeRequestThroughSocks(socksPort, '127.0.0.1', httpPort)
    );

    // Verify response
    if (!response.includes('200')) {
      throw new Error(`Expected HTTP 200 in response, got:\n${response}`);
    }
    if (!response.includes(expectedBody)) {
      throw new Error(`Expected body "${expectedBody}" in response, got:\n${response}`);
    }

    console.log('SOCKS proxy test passed!');
  } finally {
    try {
      await socksProxy?.stop();
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
 * Make an HTTP request through a SOCKS5 proxy
 */
async function makeRequestThroughSocks(
  socksPort: number,
  targetHost: string,
  targetPort: number
): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = net.connect(socksPort, '127.0.0.1', () => {
      // Send SOCKS5 greeting (version 5, 1 method, NO_AUTH)
      socket.write(Buffer.from([0x05, 0x01, 0x00]));
    });

    let state: 'greeting' | 'request' | 'connected' = 'greeting';
    let responseData = Buffer.alloc(0);

    socket.on('data', (data) => {
      if (state === 'greeting') {
        // Verify greeting response
        if (data[0] !== 0x05 || data[1] !== 0x00) {
          socket.destroy();
          reject(new Error(`SOCKS greeting failed: ${data.toString('hex')}`));
          return;
        }

        // Send CONNECT request
        const hostBytes = Buffer.from(targetHost, 'ascii');
        const request = Buffer.concat([
          Buffer.from([0x05, 0x01, 0x00, 0x03, hostBytes.length]),
          hostBytes,
          Buffer.from([(targetPort >> 8) & 0xff, targetPort & 0xff]),
        ]);
        socket.write(request);
        state = 'request';
      } else if (state === 'request') {
        // Verify CONNECT response
        if (data[0] !== 0x05 || data[1] !== 0x00) {
          socket.destroy();
          reject(new Error(`SOCKS CONNECT failed: ${data.toString('hex')}`));
          return;
        }

        // Send HTTP request
        const httpRequest =
          `GET / HTTP/1.1\r\n` +
          `Host: ${targetHost}:${targetPort}\r\n` +
          `Connection: close\r\n` +
          `\r\n`;
        socket.write(httpRequest);
        state = 'connected';
      } else if (state === 'connected') {
        responseData = Buffer.concat([responseData, data]);
      }
    });

    socket.on('end', () => {
      resolve(responseData.toString('utf8'));
    });

    socket.on('error', reject);

    socket.on('timeout', () => {
      socket.destroy();
      reject(new Error('Socket timeout'));
    });

    socket.setTimeout(60_000);
  });
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
