import test from 'ava';
import { SnowflakeWebRtcDownlink } from './webrtc-downlink.ts';

test('SnowflakeWebRtcDownlink throws without RTCPeerConnection', (t) => {
  // In Node.js environment without polyfill, RTCPeerConnection is undefined
  // This tests the error handling for that case
  const error = t.throws(() => {
    new SnowflakeWebRtcDownlink({
      // Explicitly set to undefined to simulate missing WebRTC
      RTCPeerConnection: undefined as unknown as typeof RTCPeerConnection,
    });
  });
  t.true(error?.message.includes('RTCPeerConnection not available'));
});

test('SnowflakeWebRtcDownlink generates clientId if not provided', (t) => {
  // Create a mock RTCPeerConnection to allow instantiation
  const MockRTCPeerConnection = class {
    constructor() {}
  } as unknown as typeof RTCPeerConnection;

  const downlink = new SnowflakeWebRtcDownlink({
    RTCPeerConnection: MockRTCPeerConnection,
  });

  t.is(downlink.clientId.byteLength, 8);
});

test('SnowflakeWebRtcDownlink accepts custom clientId', (t) => {
  const MockRTCPeerConnection = class {
    constructor() {}
  } as unknown as typeof RTCPeerConnection;

  const customClientId = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
  const downlink = new SnowflakeWebRtcDownlink({
    RTCPeerConnection: MockRTCPeerConnection,
    clientId: customClientId,
  });

  t.deepEqual(downlink.clientId, customClientId);
});

test('SnowflakeWebRtcDownlink isConnected returns false initially', (t) => {
  const MockRTCPeerConnection = class {
    constructor() {}
  } as unknown as typeof RTCPeerConnection;

  const downlink = new SnowflakeWebRtcDownlink({
    RTCPeerConnection: MockRTCPeerConnection,
  });

  t.false(downlink.isConnected());
});

test('SnowflakeWebRtcDownlink sendPacket throws when not connected', (t) => {
  const MockRTCPeerConnection = class {
    constructor() {}
  } as unknown as typeof RTCPeerConnection;

  const downlink = new SnowflakeWebRtcDownlink({
    RTCPeerConnection: MockRTCPeerConnection,
  });

  const error = t.throws(() => {
    downlink.sendPacket(new Uint8Array([1, 2, 3]));
  });
  t.true(error?.message.includes('not connected'));
});

test('SnowflakeWebRtcDownlink close is safe to call when not connected', (t) => {
  const MockRTCPeerConnection = class {
    constructor() {}
  } as unknown as typeof RTCPeerConnection;

  const downlink = new SnowflakeWebRtcDownlink({
    RTCPeerConnection: MockRTCPeerConnection,
  });

  // Should not throw
  t.notThrows(() => {
    downlink.close();
  });
});
