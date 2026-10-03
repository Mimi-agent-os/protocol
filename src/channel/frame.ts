// Every channel wire unit, handshake chunk or record alike, is u16 big-endian length || bytes.

export function frame(bytes: Uint8Array): Uint8Array {
  if (bytes.length > 0xffff) throw new Error("frame too large");
  const out = new Uint8Array(2 + bytes.length);
  out[0] = bytes.length >>> 8;
  out[1] = bytes.length & 0xff;
  out.set(bytes, 2);
  return out;
}

export class FrameDecodeError extends Error {
  public constructor() {
    super("bad frame length");
    this.name = "FrameDecodeError";
  }
}

export class FrameDecoder {
  #highByte: number | null = null;
  #body: Uint8Array | null = null;
  #written = 0;
  #minLen: number;
  #maxLen: number;

  public constructor(minLen = 0, maxLen = 0xffff) {
    if (!Number.isInteger(minLen) || !Number.isInteger(maxLen) || minLen < 0 || maxLen > 0xffff || minLen > maxLen) {
      throw new Error("bad frame bounds");
    }
    this.#minLen = minLen;
    this.#maxLen = maxLen;
  }

  public setBounds(minLen: number, maxLen: number): void {
    if (this.#highByte !== null || this.#body !== null) throw new Error("cannot change bounds mid-frame");
    if (!Number.isInteger(minLen) || !Number.isInteger(maxLen) || minLen < 0 || maxLen > 0xffff || minLen > maxLen) {
      throw new Error("bad frame bounds");
    }
    this.#minLen = minLen;
    this.#maxLen = maxLen;
  }

  // Yield frames as they are decoded so callers can stop on a terminal state
  // without first materializing every frame in a hostile coalesced chunk.
  public *feed(bytes: Uint8Array): IterableIterator<Uint8Array> {
    let offset = 0;
    while (offset < bytes.length) {
      if (this.#body !== null) {
        const count = Math.min(this.#body.length - this.#written, bytes.length - offset);
        this.#body.set(bytes.subarray(offset, offset + count), this.#written);
        this.#written += count;
        offset += count;
        if (this.#written < this.#body.length) break;
        const body = this.#body;
        this.#body = null;
        this.#written = 0;
        yield body;
        continue;
      }

      if (this.#highByte === null) this.#highByte = bytes[offset++]!;
      if (offset === bytes.length) break;
      const length = (this.#highByte << 8) | bytes[offset++]!;
      this.#highByte = null;
      if (length < this.#minLen || length > this.#maxLen) throw new FrameDecodeError();

      if (bytes.length - offset >= length) {
        // Do not let a later mutation of the transport buffer alter a decoded frame.
        const body = bytes.slice(offset, offset + length);
        offset += length;
        yield body;
        continue;
      }
      // Allocate once per fragmented frame; growing the tail on every feed is quadratic.
      this.#body = new Uint8Array(length);
    }
  }

  public clear(): void {
    this.#highByte = null;
    this.#body = null;
    this.#written = 0;
  }
}
