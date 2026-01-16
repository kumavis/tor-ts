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
export { shuffleInPlace } from './util.ts';
export * as hiddenService from './hidden-service.ts';
// Consensus parsing (from build-circuit/directory)
export {
  parseMicroDescConsensus,
  parseAndVerifyConsensus,
  dangerouslyTrustUnverifiedConsensus,
  type MicroDescNodeInfo,
  type VerifiedMicroDescConsensus,
  type UnverifiedMicroDescConsensus,
  type VerifyConsensusOptions,
  type ParseAndVerifyConsensusResult,
} from './build-circuit/directory.ts';

// Directory client
export {
  DirectoryClient,
  lookupOnionKey,
  lookupPeerInfo,
  lookupPeerInfoWithEd25519IdentityKey,
  extractNtorOnionKeyFromDescriptor,
  extractEd25519IdentityFromDescriptor,
  // Microdescriptor parsing
  parseMicrodescriptor,
  parseMicrodescriptorBatch,
  fetchExitPolicies,
  // Consensus fetching
  fetchAndVerifyConsensus,
  type FetchConsensusOptions,
  type FetchConsensusResult,
  type DirectoryResponse,
  type ParsedMicrodescriptor,
  type DownloadProgress,
  type DownloadProgressCallback,
} from './directory-client.ts';

// Consensus signature verification (from consensus-signature)
export {
  DIRECTORY_AUTHORITIES,
  verifyConsensusSignatures,
  parseConsensusSignatures,
  parseAllKeyCertificates,
  findAuthorityByFingerprint,
  extractAuthorityFingerprints,
  type ConsensusSignature,
  type ConsensusVerificationResult,
  type DirectoryAuthorityIdentity,
  type AuthorityKeyCertificate,
  type SignatureVerificationResult,
} from './consensus-signature.ts';

// Consensus manager
export {
  ConsensusManager,
  isConsensusFresh,
  isConsensusTtlValid as isConsensusValid,
  type ConsensusManagerOptions,
  type ConsensusStatus,
  type ConsensusRefreshOptions,
  type ConsensusUpdateListener,
} from './consensus-manager.ts';

// Exit policy parsing and matching
export {
  parsePortList,
  parseExitPolicySummary,
  policyAllowsPort,
  policyAllowsAllPorts,
  policyAllowsAnyPort,
  policyRejectsAll,
  DEFAULT_TARGET_PORTS,
  type ExitPolicy,
  type PortRange,
} from './exit-policy.ts';

// Fallback directories for safe bootstrap
export {
  FALLBACK_DIRECTORIES,
  FALLBACK_DIRS_DATA,
  getRandomFallbackDirectory,
  fallbackToPeerInfo,
  parseFallbackEntry,
  type FallbackDirectory,
  type FallbackDirEntry,
  type FallbackDirsData,
} from './fallback-dirs.ts';
