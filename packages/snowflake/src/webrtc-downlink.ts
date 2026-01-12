/**
 * WebRTC-based Snowflake downlink transport.
 *
 * Similar to WS downlink but uses RTCDataChannel for communication.
 * This provides better censorship resistance through domain fronting
 * and WebRTC's natural NAT traversal capabilities.
 *
 * Protocol compatible with:
 * gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2
 */

import { EventEmitter } from 'node:events';
import { EncapsulationDecoder, encodeEncapsulatedData } from './encapsulation.ts';
import type { ClientId } from './turbotunnel.ts';
import { buildTurbotunnelPreamble, newClientId } from './turbotunnel.ts';
import { SnowflakeBrokerClient } from './broker.ts';
import type { BrokerClientOptions } from './broker.ts';

export type SnowflakeWebRtcDownlinkOptions = {
  /**
   * Client ID for turbotunnel multiplexing.
   * Generated automatically if not provided.
   */
  clientId?: ClientId;

  /**
   * Broker client options for WebRTC signaling.
   */
  broker?: BrokerClientOptions;

  /**
   * Custom ICE servers for NAT traversal.
   * Defaults to Google's public STUN servers.
   */
  iceServers?: RTCIceServer[];

  /**
   * RTCPeerConnection factory (for testing/polyfills).
   * Defaults to globalThis.RTCPeerConnection.
   */
  RTCPeerConnection?: typeof RTCPeerConnection;

  /**
   * Timeout for ICE gathering in milliseconds.
   * Defaults to 10000 (10 seconds).
   */
  iceGatheringTimeout?: number;

  /**
   * Maximum retries if no proxy is available.
   * Defaults to 3.
   */
  maxRetries?: number;

  /**
   * Delay between retries in milliseconds.
   * Defaults to 2000 (2 seconds).
   */
  retryDelay?: number;
};

const DEFAULT_ICE_SERVERS: RTCIceServer[] = [
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun1.l.google.com:19302' },
  { urls: 'stun:stun2.l.google.com:19302' },
];

/**
 * Snowflake downlink using WebRTC for transport.
 *
 * Events:
 * - 'packet': Emitted when a KCP packet is received
 * - 'close': Emitted when the connection is closed
 * - 'error': Emitted on errors
 * - 'connected': Emitted when WebRTC connection is established
 */
export class SnowflakeWebRtcDownlink extends EventEmitter {
  readonly clientId: ClientId;
  private readonly broker: SnowflakeBrokerClient;
  private readonly iceServers: RTCIceServer[];
  private readonly RTCPeerConnectionCtor: typeof RTCPeerConnection;
  private readonly iceGatheringTimeout: number;
  private readonly maxRetries: number;
  private readonly retryDelay: number;

  private peerConnection: RTCPeerConnection | undefined;
  private dataChannel: RTCDataChannel | undefined;
  private readonly dec = new EncapsulationDecoder();
  private connected = false;
  private turbotunnelSent = false;

  constructor(opts: SnowflakeWebRtcDownlinkOptions = {}) {
    super();
    this.clientId = opts.clientId ?? newClientId();
    this.broker = new SnowflakeBrokerClient(opts.broker);
    this.iceServers = opts.iceServers ?? DEFAULT_ICE_SERVERS;
    this.RTCPeerConnectionCtor = opts.RTCPeerConnection ?? globalThis.RTCPeerConnection;
    this.iceGatheringTimeout = opts.iceGatheringTimeout ?? 10000;
    this.maxRetries = opts.maxRetries ?? 3;
    this.retryDelay = opts.retryDelay ?? 2000;

    if (!this.RTCPeerConnectionCtor) {
      throw new Error(
        'RTCPeerConnection not available. In Node.js, provide an RTCPeerConnection polyfill.'
      );
    }
  }

  /**
   * Connect to a Snowflake proxy via the broker.
   * This creates a WebRTC connection and sets up the data channel.
   */
  async connect(): Promise<void> {
    if (this.peerConnection) {
      throw new Error('already connected');
    }

    let lastError: Error | undefined;

    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      try {
        await this.attemptConnect();
        return;
      } catch (err) {
        lastError = err instanceof Error ? err : new Error(String(err));

        // Check if it's a "no proxy" error - worth retrying
        const isNoProxy =
          lastError.message.includes('no proxy') || lastError.message.includes('no proxies');

        if (!isNoProxy || attempt === this.maxRetries - 1) {
          throw lastError;
        }

        // Wait before retrying
        await new Promise((resolve) => setTimeout(resolve, this.retryDelay));
      }
    }

    throw lastError ?? new Error('connection failed');
  }

  private async attemptConnect(): Promise<void> {
    // Create peer connection with ICE servers
    const pc = new this.RTCPeerConnectionCtor({
      iceServers: this.iceServers,
    });
    this.peerConnection = pc;

    // Create the data channel before creating the offer
    // The Snowflake protocol uses an unreliable, unordered data channel
    const dc = pc.createDataChannel('snowflake', {
      ordered: false,
      maxRetransmits: 0, // Unreliable delivery
    });
    dc.binaryType = 'arraybuffer';
    this.dataChannel = dc;

    // Set up data channel handlers
    this.setupDataChannelHandlers(dc);

    // Create SDP offer
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);

    // Wait for ICE gathering to complete (or timeout)
    await this.waitForIceGathering(pc);

    // Get the complete SDP with ICE candidates
    const sdpOffer = pc.localDescription?.sdp;
    if (!sdpOffer) {
      throw new Error('failed to generate SDP offer');
    }

    // Send offer to broker and get proxy's answer
    const response = await this.broker.negotiate(sdpOffer);

    if (response.error) {
      pc.close();
      this.cleanup();
      throw new Error(`broker error: ${response.error}`);
    }

    // Apply the proxy's SDP answer
    await pc.setRemoteDescription({
      type: 'answer',
      sdp: response.answer,
    });

    // Wait for data channel to open
    await this.waitForDataChannelOpen(dc);
  }

  private setupDataChannelHandlers(dc: RTCDataChannel): void {
    dc.onopen = () => {
      this.connected = true;

      // Send turbotunnel preamble as soon as channel opens
      if (!this.turbotunnelSent) {
        this.turbotunnelSent = true;
        const preamble = buildTurbotunnelPreamble(this.clientId);
        // Use slice() to get a proper ArrayBuffer copy
        const arrayBuffer = preamble.buffer.slice(
          preamble.byteOffset,
          preamble.byteOffset + preamble.byteLength
        ) as ArrayBuffer;
        dc.send(arrayBuffer);
      }

      this.emit('connected');
    };

    dc.onclose = () => {
      this.connected = false;
      this.emit('close');
    };

    dc.onerror = (event) => {
      const error = (event as RTCErrorEvent).error ?? new Error('data channel error');
      this.emit('error', error);
    };

    dc.onmessage = (event) => {
      const data = event.data;
      const chunk =
        data instanceof ArrayBuffer
          ? new Uint8Array(data)
          : new Uint8Array(data.buffer, data.byteOffset, data.byteLength);

      // Decode encapsulated packets
      this.dec.push(chunk);
      for (;;) {
        const pkt = this.dec.popData();
        if (!pkt) break;
        this.emit('packet', pkt);
      }
    };
  }

  private async waitForIceGathering(pc: RTCPeerConnection): Promise<void> {
    if (pc.iceGatheringState === 'complete') {
      return;
    }

    await new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => {
        // Timeout is OK - we may have enough candidates
        resolve();
      }, this.iceGatheringTimeout);

      pc.onicegatheringstatechange = () => {
        if (pc.iceGatheringState === 'complete') {
          clearTimeout(timeout);
          resolve();
        }
      };

      pc.onicecandidate = (event) => {
        // null candidate means gathering is complete
        if (event.candidate === null) {
          clearTimeout(timeout);
          resolve();
        }
      };

      pc.onconnectionstatechange = () => {
        if (pc.connectionState === 'failed') {
          clearTimeout(timeout);
          reject(new Error('ICE connection failed'));
        }
      };
    });
  }

  private async waitForDataChannelOpen(dc: RTCDataChannel): Promise<void> {
    if (dc.readyState === 'open') {
      return;
    }

    await new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error('data channel open timeout'));
      }, 30000);

      const cleanup = () => {
        clearTimeout(timeout);
        dc.removeEventListener('open', onOpen);
        dc.removeEventListener('error', onError);
      };

      const onOpen = () => {
        cleanup();
        resolve();
      };

      const onError = (event: Event) => {
        cleanup();
        const error = (event as RTCErrorEvent).error ?? new Error('data channel error');
        reject(error);
      };

      dc.addEventListener('open', onOpen);
      dc.addEventListener('error', onError);
    });
  }

  /**
   * Reset connection state (for cleanup after errors).
   */
  private cleanup(): void {
    this.peerConnection = undefined;
    this.dataChannel = undefined;
    this.connected = false;
    this.turbotunnelSent = false;
  }

  /**
   * Send an encapsulated packet through the data channel.
   */
  sendPacket(pkt: Uint8Array): void {
    if (!this.dataChannel || this.dataChannel.readyState !== 'open') {
      throw new Error('data channel not connected');
    }
    const encoded = encodeEncapsulatedData(pkt);
    // Use slice() to get a proper ArrayBuffer copy
    const arrayBuffer = encoded.buffer.slice(
      encoded.byteOffset,
      encoded.byteOffset + encoded.byteLength
    ) as ArrayBuffer;
    this.dataChannel.send(arrayBuffer);
  }

  /**
   * Close the WebRTC connection.
   */
  close(): void {
    // Try to flush decoder state
    try {
      this.dec.finish();
    } catch {
      // ignore
    }

    const dc = this.dataChannel;
    if (dc) {
      dc.close();
      this.dataChannel = undefined;
    }

    const pc = this.peerConnection;
    if (pc) {
      pc.close();
      this.peerConnection = undefined;
    }

    this.connected = false;
  }

  /**
   * Check if the connection is open.
   */
  isConnected(): boolean {
    return this.connected && this.dataChannel?.readyState === 'open';
  }
}
