// Stream frame plaintext (LEB128 stream id || flags || payload).

export interface ChannelStreamFrame {
  stream: number;
  flags: number;
  payload: Uint8Array;
}

export const FLAG_DATA = 0;
export const FLAG_END = 1;
export const FLAG_RESET = 2;

export function encodeStreamFrame(f: ChannelStreamFrame): Uint8Array {
  if (!Number.isInteger(f.stream) || f.stream < 0 || f.stream > 0xffffffff) throw new Error("bad stream id");
  if (!Number.isInteger(f.flags) || f.flags < 0 || f.flags > 0xff) throw new Error("bad flags");
  const varint: number[] = [];
  let v = f.stream;
  while (v > 0x7f) {
    varint.push((v & 0x7f) | 0x80);
    v = Math.floor(v / 128);
  }
  varint.push(v);
  const out = new Uint8Array(varint.length + 1 + f.payload.length);
  out.set(varint, 0);
  out[varint.length] = f.flags;
  out.set(f.payload, varint.length + 1);
  return out;
}

export function decodeStreamFrame(b: Uint8Array): ChannelStreamFrame {
  let stream = 0;
  let shift = 1;
  let off = 0;
  for (;;) {
    if (off === 5) throw new Error("bad stream varint");
    const byte = b[off];
    if (byte === undefined) throw new Error("truncated stream frame");
    stream += (byte & 0x7f) * shift;
    off += 1;
    if ((byte & 0x80) === 0) {
      if (off > 1 && byte === 0) throw new Error("non-canonical stream varint");
      break;
    }
    shift *= 128;
  }
  if (stream > 0xffffffff) throw new Error("bad stream id");
  const flags = b[off];
  if (flags === undefined) throw new Error("truncated stream frame");
  return { stream, flags, payload: b.slice(off + 1) };
}
