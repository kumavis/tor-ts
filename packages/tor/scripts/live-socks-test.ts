/**
 * Live SOCKS proxy test against mainnet Tor.
 *
 * This test:
 * 1. Builds a real Tor circuit through mainnet
 * 2. Starts a SOCKS5 proxy server using the circuit
 * 3. Makes a request through the SOCKS proxy to a real external server
 * 4. Verifies the response
 *
 * Run with: TOR_LIVE_TEST=1 node --experimental-transform-types scripts/live-socks-test.ts
 */

import net from 'node:net';

import { connectRandomCircuitWithSafeBootstrap } from '../src/build-circuit/mainnet.ts';
import { SocksProxyServer } from '../src/socks.ts';
import type { Circuit } from '../src/circuit.ts';

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
  // Only run if explicitly enabled
  if (process.env.TOR_LIVE_TEST !== '1') {
    console.log('Skipping live test (set TOR_LIVE_TEST=1 to run)');
    return;
  }

  const overallTimeoutMs = 5 * 60_000;
  const perStepTimeoutMs = 2 * 60_000;
  const socksPort = Number.parseInt(process.env.TOR_TS_SOCKS_PORT ?? '1080', 10);

  let circuit: Circuit | undefined;
  let socksProxy: SocksProxyServer | undefined;

  try {
    console.log('Building Tor circuit via safe bootstrap...');
    circuit = await withTimeout(
      'build circuit',
      perStepTimeoutMs,
      connectRandomCircuitWithSafeBootstrap()
    );
    console.log('Tor circuit established');

    // Start SOCKS proxy
    socksProxy = new SocksProxyServer({
      circuit,
      port: socksPort,
      host: '127.0.0.1',
    });

    await withTimeout('start SOCKS proxy', 10_000, socksProxy.start());
    console.log(`SOCKS proxy listening on port ${socksPort}`);

    // Make request through SOCKS proxy to example.com
    console.log('Making request through SOCKS proxy to example.com...');
    const response = await withTimeout(
      'SOCKS proxy request',
      overallTimeoutMs,
      makeRequestThroughSocks(socksPort, 'example.com', 80)
    );

    // Verify response
    if (!response.includes('200')) {
      throw new Error(`Expected HTTP 200 in response, got:\n${response}`);
    }
    if (!response.includes('Example Domain')) {
      throw new Error(`Expected "Example Domain" in response, got:\n${response}`);
    }

    console.log('Live SOCKS proxy test passed!');
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
          `GET / HTTP/1.1\r\n` + `Host: ${targetHost}\r\n` + `Connection: close\r\n` + `\r\n`;
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

    socket.setTimeout(120_000);
  });
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
