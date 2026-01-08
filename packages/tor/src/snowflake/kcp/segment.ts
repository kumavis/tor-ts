// KCP segment codec (wire format) compatible with xtaci/kcp-go and skywind3000/kcp.
//
// Header layout (little-endian):
//  0:4  conv (uint32)
//  4:5  cmd  (uint8)
//  5:6  frg  (uint8)
//  6:8  wnd  (uint16)
//  8:12 ts   (uint32)
// 12:16 sn   (uint32)
// 16:20 una  (uint32)
// 20:24 len  (uint32)
// 24:   data

export const KCP_HEADER_SIZE = 24;

export const KCP_CMD = {
  PUSH: 81,
  ACK: 82,
  WASK: 83,
  WINS: 84,
} as const;

export type KcpCmd = (typeof KCP_CMD)[keyof typeof KCP_CMD];

export type KcpSegment = {
  conv: number; // uint32
  cmd: KcpCmd; // uint8
  frg: number; // uint8
  wnd: number; // uint16
  ts: number; // uint32
  sn: number; // uint32
  una: number; // uint32
  data: Uint8Array;
};

export function encodeKcpSegment(seg: KcpSegment): Uint8Array {
  if (seg.data.byteLength > 0xffffffff) throw new Error('segment data too large');
  const out = new Uint8Array(KCP_HEADER_SIZE + seg.data.byteLength);
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
  view.setUint32(0, seg.conv >>> 0, true);
  view.setUint8(4, seg.cmd);
  view.setUint8(5, seg.frg & 0xff);
  view.setUint16(6, seg.wnd & 0xffff, true);
  view.setUint32(8, seg.ts >>> 0, true);
  view.setUint32(12, seg.sn >>> 0, true);
  view.setUint32(16, seg.una >>> 0, true);
  view.setUint32(20, seg.data.byteLength >>> 0, true);
  out.set(seg.data, KCP_HEADER_SIZE);
  return out;
}

export function decodeKcpSegmentsFromPacket(pkt: Uint8Array): KcpSegment[] {
  const out: KcpSegment[] = [];
  let off = 0;
  while (off < pkt.byteLength) {
    if (pkt.byteLength - off < KCP_HEADER_SIZE) {
      throw new Error(`short kcp packet: ${pkt.byteLength - off} bytes`);
    }
    const view = new DataView(pkt.buffer, pkt.byteOffset + off, pkt.byteLength - off);
    const conv = view.getUint32(0, true);
    const cmd = view.getUint8(4) as KcpCmd;
    const frg = view.getUint8(5);
    const wnd = view.getUint16(6, true);
    const ts = view.getUint32(8, true);
    const sn = view.getUint32(12, true);
    const una = view.getUint32(16, true);
    const len = view.getUint32(20, true);

    if (pkt.byteLength - off < KCP_HEADER_SIZE + len) {
      throw new Error('truncated kcp segment payload');
    }

    const data = pkt.subarray(off + KCP_HEADER_SIZE, off + KCP_HEADER_SIZE + len);
    out.push({ conv, cmd, frg, wnd, ts, sn, una, data });
    off += KCP_HEADER_SIZE + len;
  }
  return out;
}

