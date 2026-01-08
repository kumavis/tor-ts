import test from 'ava';
import { once } from 'node:events';
import { WebSocketServer } from 'ws';
import type WebSocket from 'ws';
import { SnowflakeWsDownlink } from './snowflake/ws-downlink.ts';
import { TURBOTUNNEL_TOKEN } from './snowflake/turbotunnel.ts';
import { EncapsulationDecoder, encodeEncapsulatedData } from './snowflake/encapsulation.ts';

function rawDataToUint8Array(data: WebSocket.RawData): Uint8Array {
  if (typeof data === 'string') return new TextEncoder().encode(data);
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (Array.isArray(data)) return Uint8Array.from(Buffer.concat(data));
  if (ArrayBuffer.isView(data))
    return Uint8Array.from(new Uint8Array(data.buffer, data.byteOffset, data.byteLength));
  return Uint8Array.from(data);
}

test('snowflake ws downlink: sends turbotunnel preamble then encapsulated packets', async (t) => {
  const wss = new WebSocketServer({ port: 0 });
  const addr = wss.address();
  if (typeof addr === 'string' || addr === null) {
    wss.close();
    t.fail('unexpected ws server address');
    return;
  }
  const url = `ws://127.0.0.1:${addr.port}/`;

  const serverSeen: { preamble: Uint8Array; packets: Uint8Array[] } = {
    preamble: new Uint8Array(0),
    packets: [],
  };

  wss.on('connection', (sock: WebSocket) => {
    const dec = new EncapsulationDecoder();
    let sawPreamble = false;
    sock.on('message', (data: WebSocket.RawData) => {
      const chunk = rawDataToUint8Array(data);

      // First message contains the preamble (token+clientID).
      if (!sawPreamble) {
        sawPreamble = true;
        serverSeen.preamble = new Uint8Array(chunk);
        return;
      }

      // Next messages are encapsulated packets.
      dec.push(chunk);
      for (;;) {
        const p = dec.popData();
        if (!p) break;
        serverSeen.packets.push(new Uint8Array(p));
      }
    });

    // Echo back one packet after we see one.
    const interval = setInterval(() => {
      if (serverSeen.packets.length > 0) {
        clearInterval(interval);
        sock.send(encodeEncapsulatedData(Uint8Array.from([9, 9, 9])));
      }
    }, 10);
  });

  const client = new SnowflakeWsDownlink({ url });
  await client.connect();
  client.sendPacket(Uint8Array.from([1, 2, 3]));

  const [pkt] = (await once(client, 'packet')) as [Uint8Array];
  t.deepEqual(pkt, Uint8Array.from([9, 9, 9]));

  // Verify token prefix on server side.
  t.deepEqual(serverSeen.preamble.slice(0, 8), TURBOTUNNEL_TOKEN);
  t.is(serverSeen.preamble.byteLength, 16);
  t.deepEqual(serverSeen.packets[0], Uint8Array.from([1, 2, 3]));

  client.close();
  wss.close();
});

test.serial('snowflake ws downlink: optional live relay connect', async (t) => {
  if (!process.env.SNOWFLAKE_LIVE) {
    t.pass();
    return;
  }
  const client = new SnowflakeWsDownlink({ url: 'wss://snowflake.torproject.net/' });
  await client.connect();
  // If the server immediately closes for protocol reasons, we’ll see 'close' quickly.
  const race = await Promise.race([
    once(client, 'close').then(() => 'close'),
    new Promise<'open-stable'>((resolve) => setTimeout(() => resolve('open-stable'), 500)),
  ]);
  client.close();
  t.is(race, 'open-stable');
});
