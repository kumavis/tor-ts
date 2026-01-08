import test from 'ava';
import { SnowflakeWsStack } from './snowflake/snowflake-ws-stack.ts';

test.serial('snowflake live: open smux stream over ws downlink (optional)', async (t) => {
  if (!process.env.SNOWFLAKE_LIVE) {
    t.pass();
    return;
  }

  const stack = new SnowflakeWsStack({ relayUrl: 'wss://snowflake.torproject.net/' });
  await stack.connect();

  const stream = await stack.openTorStream();
  // Just write a tiny payload; Tor would start TLS here. We want to see if the stream stays alive briefly.
  stream.write(new Uint8Array([0x00]));

  await new Promise((r) => setTimeout(r, 500));
  await stack.close();
  t.pass();
});
