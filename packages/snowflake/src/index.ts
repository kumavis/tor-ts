export {
  EncapsulationDecoder,
  EncapsulationTooLongError,
  encodeEncapsulatedData,
} from './encapsulation.ts';
export { TURBOTUNNEL_TOKEN, buildTurbotunnelPreamble, newClientId } from './turbotunnel.ts';
export { SnowflakeWsDownlink } from './ws-downlink.ts';
export { SnowflakeWsStack } from './snowflake-ws-stack.ts';
export * as kcp from './kcp/index.ts';
export * as smux from './smux/index.ts';

// Optional Tor integration (kept in this package per repo preference)
export { SnowflakeTlsChannelConnection } from './tor/channel.ts';
export { connectSnowflakeChutneyCircuit } from './tor/chutney.ts';
