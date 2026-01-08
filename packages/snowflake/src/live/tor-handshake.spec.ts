import test from 'ava';

import { SnowflakeTlsChannelConnection } from '../tor-channel.ts';

const liveTest = isLiveEnabled() ? test.serial : test.serial.skip;

liveTest('snowflake live: complete Tor link handshake over ws downlink (optional)', async (t) => {
  t.timeout(60_000);

  const channel = new SnowflakeTlsChannelConnection();
  await channel.connect({ relayUrl: 'wss://snowflake.torproject.net/' });
  channel.destroy();
  t.pass();
});

function isLiveEnabled(): boolean {
  const v = process.env.SNOWFLAKE_LIVE?.toLowerCase();
  return v === '1' || v === 'true';
}
