import test from 'ava';

import { SnowflakeTlsChannelConnection } from '../tor-channel.ts';

test.serial(
  'snowflake live: complete Tor link handshake over ws downlink (optional)',
  async (t) => {
    t.timeout(60_000);

    const channel = new SnowflakeTlsChannelConnection();
    await channel.connect({ relayUrl: 'wss://snowflake.torproject.net/' });
    channel.destroy();
    t.pass();
  }
);
