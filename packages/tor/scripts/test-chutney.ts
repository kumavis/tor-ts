/**
 * Chutney development/testing script.
 *
 * Uses direct HTTP requests for directory lookups (dangerous* methods).
 * This is acceptable for a test script that builds a bootstrap circuit
 * to a local Chutney test network.
 */

import net from 'node:net';

import { Circuit } from '../src/circuit.ts';
import type { PeerInfo } from '../src/circuit.ts';
import { TlsChannelConnection } from '../src/channel.ts';
import { linkSpecifierToAddressAndPort } from '../src/messaging.ts';
import {
  dangerouslyDownloadMicrodescFromDirectory,
  parseMicroDescConsensus,
  dangerouslyLookupPeerInfo,
} from '../src/build-circuit/directory.ts';
import type { MicroDescNodeInfo } from '../src/build-circuit/directory.ts';

async function getStandardChutneyCircuitPath() {
  const loopback = '127.0.0.1';
  const directoryServer = `${loopback}:7000`;
  const microDescContent = await dangerouslyDownloadMicrodescFromDirectory(directoryServer);
  // Chutney uses local test authorities, not mainnet - skip verification
  const consensus = await parseMicroDescConsensus(microDescContent, {
    keyCertificates: [],
    dangerouslySkipSignatureVerification: true,
  });
  const microDescNodeInfos = consensus.relays;

  // Build a circuit plan with specific onion_router_port's, but ensure all entries are found
  const wantedPorts = [5004, 5001, 5000];
  const circuitPlan: Array<MicroDescNodeInfo> = wantedPorts.map((port) => {
    const nodeInfo = microDescNodeInfos.find((nodeInfo) => nodeInfo.onion_router_port === port);
    if (!nodeInfo) {
      throw new Error(`Relay with onion_router_port ${port} not found in consensus`);
    }
    return nodeInfo;
  });

  const circuitPeerInfos: Array<PeerInfo> = await Promise.all(
    circuitPlan.map(async (relayInfo) => {
      return await dangerouslyLookupPeerInfo(directoryServer, relayInfo);
    })
  );
  // reverse so that gateway is first and exit is last
  circuitPeerInfos.reverse();

  return circuitPeerInfos;
}

// choose relays
const circuitPeerInfos = await getStandardChutneyCircuitPath();

const gatewayPeerInfo = circuitPeerInfos[0];
const gatewayAddress = linkSpecifierToAddressAndPort(gatewayPeerInfo.linkSpecifiers[0]);

const channel = new TlsChannelConnection();
await channel.connect(gatewayAddress);
const circuit = new Circuit({
  path: circuitPeerInfos,
  channel,
});
await circuit.connect();
console.log('circuit established');

const port = 1234;
const server = net.createServer();
server.listen(port, () => {
  console.log(`Server started and listening on port ${port}`);
});
server.on('connection', async (socket) => {
  console.log('New client connected');
  const circuitStream = await circuit.open('kumavis.me:80');
  console.log('connection established');

  circuitStream.on('data', (data) => {
    console.log(`Received data from end: ${data.length}`);
    socket.write(data);
  });
  circuitStream.on('error', (err) => {
    console.log('circuit disconnected with error:', err.message);
    socket.end();
  });
  circuitStream.on('end', () => {
    console.log('circuit disconnected');
    socket.end();
  });
  socket.on('data', (data) => {
    console.log(`Received data from start: ${data.length}`);
    circuitStream.write(data);
  });
  socket.on('error', (err) => {
    console.log('Client errored', err);
    circuitStream.destroy();
  });
  socket.on('end', () => {
    console.log('Client disconnected');
  });
});
