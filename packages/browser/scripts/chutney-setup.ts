import assert from 'node:assert/strict';
import { once } from 'node:events';
import { readFile } from 'node:fs/promises';
import http from 'node:http';
import type { TestProject } from 'vitest/node';
import { discoverChutneyAuthorities } from '../../tor/src/build-circuit/chutney.ts';
import type { ChutneyBrowserFixture } from '../src/chutney/fixture.ts';

export default async function setup(project: TestProject): Promise<() => Promise<void>> {
  // Browser instances inherit the root setup. Own the HTTP listener once;
  // their injected context also inherits the values provided by this root.
  if (!project.isRootProject()) return async () => {};

  const hostnamePath = process.env.TOR_TS_HS_HOSTNAME_PATH;
  const relayUrl = process.env.TOR_TS_SNOWFLAKE_RELAY_URL;
  assert(hostnamePath && relayUrl, 'Run this test through ci-chutney-snowflake.sh');
  const hostname = (await readFile(hostnamePath, 'utf8')).trim();
  const expectedBody = 'hello-from-real-browser-through-snowflake-onion';
  const fixture: ChutneyBrowserFixture = {
    relayUrl,
    onionUrl: `http://${hostname}:5858/`,
    expectedBody,
    trustedAuthorities: await discoverChutneyAuthorities(),
  };
  project.provide('chutney', fixture);

  const server = http.createServer((_request, response) => {
    response.writeHead(200, {
      'content-type': 'text/plain',
      'content-length': Buffer.byteLength(expectedBody),
      connection: 'close',
    });
    response.end(expectedBody);
  });
  server.listen(Number(process.env.TOR_TS_TEST_PORT ?? 4747), '127.0.0.1');
  await once(server, 'listening');
  return async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  };
}
