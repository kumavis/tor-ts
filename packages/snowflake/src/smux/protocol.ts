export const SMUX_CMD = {
  SYN: 0,
  FIN: 1,
  PSH: 2,
  NOP: 3,
  UPD: 4,
} as const;

export type SmuxCmd = (typeof SMUX_CMD)[keyof typeof SMUX_CMD];

export const SMUX_HEADER_SIZE = 8;
export const SMUX_UPD_SIZE = 8;

export type SmuxFrame = {
  ver: number; // uint8
  cmd: SmuxCmd; // uint8
  sid: number; // uint32
  data: Uint8Array; // length <= 65535
};

export function encodeSmuxFrame(frame: SmuxFrame): Uint8Array {
  if (frame.data.byteLength > 0xffff) {
    throw new Error(`smux frame too large: ${frame.data.byteLength}`);
  }
  const out = new Uint8Array(SMUX_HEADER_SIZE + frame.data.byteLength);
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
  view.setUint8(0, frame.ver & 0xff);
  view.setUint8(1, frame.cmd & 0xff);
  view.setUint16(2, frame.data.byteLength, true);
  view.setUint32(4, frame.sid >>> 0, true);
  out.set(frame.data, SMUX_HEADER_SIZE);
  return out;
}

export function decodeSmuxHeader(hdr: Uint8Array): {
  ver: number;
  cmd: SmuxCmd;
  len: number;
  sid: number;
} {
  if (hdr.byteLength !== SMUX_HEADER_SIZE) {
    throw new Error(`expected ${SMUX_HEADER_SIZE} byte header, got ${hdr.byteLength}`);
  }
  const view = new DataView(hdr.buffer, hdr.byteOffset, hdr.byteLength);
  const ver = view.getUint8(0);
  const cmd = view.getUint8(1) as SmuxCmd;
  const len = view.getUint16(2, true);
  const sid = view.getUint32(4, true);
  return { ver, cmd, len, sid };
}

export function encodeUpdPayload(consumed: number, window: number): Uint8Array {
  const out = new Uint8Array(SMUX_UPD_SIZE);
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
  view.setUint32(0, consumed >>> 0, true);
  view.setUint32(4, window >>> 0, true);
  return out;
}

export function decodeUpdPayload(p: Uint8Array): { consumed: number; window: number } {
  if (p.byteLength !== SMUX_UPD_SIZE) {
    throw new Error(`expected ${SMUX_UPD_SIZE} byte UPD payload, got ${p.byteLength}`);
  }
  const view = new DataView(p.buffer, p.byteOffset, p.byteLength);
  const consumed = view.getUint32(0, true);
  const window = view.getUint32(4, true);
  return { consumed, window };
}
