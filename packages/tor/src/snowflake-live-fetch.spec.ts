import test from 'ava';
import https from 'node:https';
import { connectSnowflakeCircuit } from './build-circuit/mainnet.ts';
import { getTorAgentForUrl } from './node.ts';

test.serial('snowflake live: build circuit and fetch ipify (optional)', async (t) => {
  if (!process.env.SNOWFLAKE_LIVE) {
    t.pass();
    return;
  }
  t.timeout(120_000);

  const target = 'https://api.ipify.org';
  const circuit = await connectSnowflakeCircuit({ relayUrl: 'wss://snowflake.torproject.net/' });

  const body = await new Promise<string>((resolve, reject) => {
    const agent = getTorAgentForUrl(circuit, target);
    const req = https.get(target, { agent }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    });
    req.on('error', reject);
  });

  circuit.destroy();
  t.truthy(body.trim().length > 0);
});

