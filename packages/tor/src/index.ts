// const circuitPeerInfos = await getStandardChutneyCircuitPath()

// const gatewayPeerInfo = circuitPeerInfos[0]
// const gatewayAddress = linkSpecifierToAddressAndPort(gatewayPeerInfo.linkSpecifiers[0])

// const channel = new TlsChannelConnection()
// await channel.connect(gatewayAddress)
// const circuit = new Circuit({
//   path: circuitPeerInfos,
//   channel,
// })

export * as chutney from './build-circuit/chutney.ts';
export * as mainnet from './build-circuit/mainnet.ts';
// export * as messaging from './messaging'
// export * as circuit from './circuit'
// export * as channel from './channel'
export { Circuit } from './circuit.ts';
export { TlsChannelConnection } from './channel.ts';
export * as hiddenService from './hidden-service.ts';
export {
  DirectoryClient,
  lookupOnionKey,
  lookupPeerInfo,
  lookupPeerInfoWithEd25519IdentityKey,
  extractNtorOnionKeyFromDescriptor,
  extractEd25519IdentityFromDescriptor,
  parseMicroDescConsensus,
  type MicroDescNodeInfo,
  type MicroDescConsensus,
  type DirectoryResponse,
} from './directory-client.ts';

// Fallback directories for safe bootstrap
export {
  FALLBACK_DIRECTORIES,
  getRandomFallbackDirectory,
  parseFallbackEntry,
  type FallbackDirectory,
} from './fallback-dirs.ts';
