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

// WebRTC transport
export { SnowflakeBrokerClient } from './broker.ts';
export type { BrokerClientOptions, BrokerAnswer } from './broker.ts';
export { SnowflakeWebRtcDownlink } from './webrtc-downlink.ts';
export type { SnowflakeWebRtcDownlinkOptions } from './webrtc-downlink.ts';
export { SnowflakeWebRtcStack } from './snowflake-webrtc-stack.ts';
export type { SnowflakeWebRtcStackOptions } from './snowflake-webrtc-stack.ts';

// Optional Tor integration (kept in this package per repo preference)
export { SnowflakeTlsChannelConnection } from './tor-channel.ts';
export { SnowflakeWebRtcTlsChannelConnection } from './tor-channel-webrtc.ts';
export type { SnowflakeWebRtcChannelOptions } from './tor-channel-webrtc.ts';
export { connectSnowflakeChutneyCircuit } from './tor-chutney.ts';
