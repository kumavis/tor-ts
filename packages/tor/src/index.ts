export * as chutney from './build-circuit/chutney.ts';
export * as mainnet from './build-circuit/mainnet.ts';
// export * as messaging from './messaging'
// export * as circuit from './circuit'
// export * as channel from './channel'
export { Circuit, DEFAULT_CIRCUIT_BUILD_TIMEOUT_MS, MAX_CIRCUIT_DIRTINESS_MS } from './circuit.ts';
export {
  TlsChannelConnection,
  ChannelManager as GenericChannelManager,
  createTlsChannelManager,
  isTlsChannelAlive,
  type TlsChannelManager,
  type ChannelFactory,
  type ChannelHealthCheck,
} from './channel.ts';
export { shuffleInPlace } from './util.ts';
export * as hiddenService from './hidden-service.ts';
export * as hiddenServiceHost from './hidden-service-host.ts';
export {
  publishHiddenService,
  HiddenServiceHost,
  generateHiddenServiceKeys,
  loadHiddenServiceKeys,
  computeOnionAddress,
  deriveBlindedPrivateKey,
  signWithBlindedKey,
  deriveTimePeriodKeys,
  generateIntroPointKeys,
  generateDescriptor,
  buildEstablishIntroPayload,
  parseIntroduce2,
  decryptIntroduce2,
  completeHsNtorServer,
  type PublishHiddenServiceOptions,
  type HsHost,
  type HiddenServiceKeys,
  type TimePeriodKeys,
  type IntroductionPoint,
  type Introduce2Parsed,
  type Introduce2Decrypted,
} from './hidden-service-host.ts';
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
  // Note: MicrodescProgressCallback is exported from microdesc-manager.ts
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

// Microdescriptor manager
export {
  MicrodescManager,
  InMemoryMicrodescStorage,
  type MicrodescStorage,
  type MicrodescManagerOptions,
  type MicrodescProgressCallback,
  type CachedMicrodesc,
  type UpdateFromConsensusOptions,
} from './microdesc-manager.ts';

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

// Stream retry logic
export {
  RelayEndError,
  RelayEndReasons,
  RelayEndReasonNames,
  getStreamRetryBehavior,
  isRetryableEndReason,
  type StreamRetryBehavior,
} from './relay-cell.ts';

// Directory request retry constants
export { MAX_DIRECTORY_REQUEST_RETRIES } from './directory-client.ts';

// Tor Client (shared across all platforms)
export {
  TorClient,
  type TorClientDeps,
  type BuildGeneralCircuitFn,
  type FetchOverCircuitFn,
  type FetchOptions,
  type FetchResponse,
  type HsConnectionResult,
  type CircuitResult,
} from './client.ts';

// Chutney Tor Client (test network)
export {
  makeChutneyTorClient,
  type ChutneyTorClient,
  type ChutneyTorClientOptions,
} from './build-circuit/chutney.ts';

// Node.js Tor Client (main network)
export {
  makeNodejsTorClient,
  type NodeTorClient,
  type NodeTorClientOptions,
} from './build-circuit/node-client.ts';

// Node.js HTTP fetch over Tor
export { fetchViaTorCircuit } from './http-fetch.ts';

// SOCKS5 proxy server over a Tor circuit
export {
  SocksProxyServer,
  createSocksProxy,
  SOCKS_VERSION,
  SOCKS_USERPASS_VERSION,
  SocksAuthMethod,
  SocksCommand,
  SocksAddressType,
  SocksReply,
  parseSocksGreeting,
  buildSocksGreetingResponse,
  parseSocksRequest,
  buildSocksReply,
  parseSocksUserPass,
  buildSocksUserPassResponse,
  socksGreetingFrameLength,
  socksRequestFrameLength,
  socksUserPassFrameLength,
  socksReplyForOpenError,
  socksReplyForRelayEndReason,
  formatTorDestination,
  type SocksGreeting,
  type SocksRequest,
  type SocksAuth,
  type SocksConnectionContext,
  type SocksCircuitFactory,
  type SocksServerOptions,
} from './socks.ts';
