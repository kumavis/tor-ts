/**
 * Regression: TlsChannelConnection.connect() must reject on TCP failure rather
 * than crashing the process. The original code attached no 'error' listener
 * to the tls.Socket and awaited only the 'secureConnect' event — so an
 * ECONNREFUSED surfaced as an unhandled EventEmitter 'error' and killed Node.
 * That was the http-proxy CI failure pattern.
 */

import test from 'ava';
import net from 'node:net';
import { TlsChannelConnection } from './channel.ts';
import { AddressTypes } from './messaging.ts';

async function findFreePort(): Promise<number> {
  const server = net.createServer();
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (typeof address === 'string' || address === null) {
    server.close();
    throw new Error('failed to bind test server');
  }
  const port = address.port;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}

test('TlsChannelConnection.connect rejects on ECONNREFUSED (not uncaught)', async (t) => {
  // Find a port that nothing is listening on. tls.connect to it will produce
  // ECONNREFUSED. Before the fix, this crashed the Node worker.
  const closedPort = await findFreePort();

  const channel = new TlsChannelConnection({ enablePadding: false });
  await t.throwsAsync(
    channel.connect({ type: AddressTypes.IPv4, ip: '127.0.0.1', port: closedPort }),
    { message: /ECONNREFUSED|connect/ }
  );
});
