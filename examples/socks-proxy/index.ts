/**
 * Example: SOCKS5 proxy server over Tor (Node.js).
 *
 * Bootstraps a 3-hop circuit on the live network, stands up a SOCKS5
 * listener on `127.0.0.1:1080`, and bridges accepted SOCKS clients
 * onto the circuit. Stays up until SIGINT/SIGTERM.
 *
 * Run with:
 *
 *   yarn workspace tor-example-socks-proxy start
 *
 * Then in another terminal, point any SOCKS5 client at it:
 *
 *   curl --socks5-hostname localhost:1080 https://check.torproject.org
 *   curl --socks5-hostname localhost:1080 http://example.com
 *
 * Stop with Ctrl-C.
 *
 * Environment:
 *   TOR_TS_SOCKS_PORT  — port to bind (default 1080).
 *   TOR_TS_SOCKS_HOST  — host to bind (default 127.0.0.1).
 */

import { connectRandomCircuitWithSafeBootstrap, retryTransient } from 'tor/build-circuit/mainnet';
import { SocksProxyServer } from 'tor/socks';

async function main() {
  const port = Number.parseInt(process.env.TOR_TS_SOCKS_PORT ?? '1080', 10);
  const host = process.env.TOR_TS_SOCKS_HOST ?? '127.0.0.1';
  if (!Number.isFinite(port) || port < 0 || port > 65535) {
    throw new Error(`Invalid TOR_TS_SOCKS_PORT: ${process.env.TOR_TS_SOCKS_PORT ?? ''}`);
  }

  console.log('Bootstrapping a Tor circuit on the live network...');
  // Bootstrap may flake transiently (a fallback dir is rebooting, a guard
  // hangs, etc.). retryTransient + the default isRetryableTorError
  // predicate handle the usual cases; everything else propagates.
  const circuit = await retryTransient(connectRandomCircuitWithSafeBootstrap, {
    maxAttempts: 5,
    backoffMs: (failed) => 2_000 * failed,
    onRetry: (attempt, err) =>
      console.warn(`Bootstrap attempt ${attempt} failed: ${err.message}. Retrying...`),
  });
  console.log('Tor circuit established.');

  const server = new SocksProxyServer({ circuit, port, host });

  // Surface protocol-level diagnostics so unexpected client behaviour is
  // visible during development. Without these listeners SocksProxyServer
  // still emits the events; they just go unobserved.
  server.on('connect', ({ destination }: { destination: string }) => {
    console.log(`SOCKS CONNECT → ${destination}`);
  });
  server.on('resolve', ({ query }: { query: string }) => {
    console.log(`SOCKS RESOLVE → ${query}`);
  });
  server.on('connectionError', (err: Error) => {
    console.warn(`SOCKS connection error: ${err.message}`);
  });

  await server.start();
  const addr = server.address();
  if (!addr || typeof addr === 'string') {
    throw new Error('SOCKS server did not bind to a TCP port');
  }
  console.log(`SOCKS5 proxy listening on ${addr.address}:${addr.port}`);
  console.log(`Try:  curl --socks5-hostname ${addr.address}:${addr.port} http://example.com`);
  console.log('Press Ctrl-C to stop.');

  // Graceful shutdown — destroy active client sockets via server.stop()
  // before tearing down the circuit so any in-flight stream sees a clean
  // RELAY_END rather than a half-open socket.
  let stopping = false;
  const stop = async (signal: string) => {
    if (stopping) return;
    stopping = true;
    console.log(`\nReceived ${signal}; shutting down.`);
    try {
      await server.stop();
    } catch (err) {
      console.warn(`Error stopping server: ${(err as Error).message}`);
    }
    try {
      circuit.destroy();
    } catch {
      // Circuit may already have been destroyed by a DESTROY cell.
    }
    process.exit(0);
  };
  process.on('SIGINT', () => void stop('SIGINT'));
  process.on('SIGTERM', () => void stop('SIGTERM'));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
