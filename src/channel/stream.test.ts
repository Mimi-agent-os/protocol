import { test } from "node:test";
import assert from "node:assert/strict";
import { FLAG_END, encodeStreamFrame, decodeStreamFrame, type ChannelStreamFrame } from "./stream.ts";

test("stream frames round-trip, including multi-byte LEB128 stream ids", () => {
  for (const stream of [0, 1, 127, 128, 300, 16383, 16384, 1_000_000, 0xffffffff]) {
    const frame: ChannelStreamFrame = { stream, flags: FLAG_END, payload: Uint8Array.from([1, 2, 3]) };
    const decoded = decodeStreamFrame(encodeStreamFrame(frame));
    assert.equal(decoded.stream, stream);
    assert.equal(decoded.flags, FLAG_END);
    assert.deepEqual(decoded.payload, frame.payload);
  }
});

test("stream id 300 has the canonical two-byte LEB128 encoding", () => {
  const wire = encodeStreamFrame({ stream: 300, flags: FLAG_END, payload: Uint8Array.of(0xaa) });
  assert.deepEqual(wire, Uint8Array.of(0xac, 0x02, FLAG_END, 0xaa));
});

test("stream frame encoding accepts the full u8 flags range and rejects values outside integer bounds", () => {
  const maxFlags = decodeStreamFrame(encodeStreamFrame({ stream: 0, flags: 0xff, payload: new Uint8Array() }));
  assert.equal(maxFlags.flags, 0xff);
  for (const stream of [-1, 0x1_0000_0000, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
    assert.throws(
      () => encodeStreamFrame({ stream, flags: 0, payload: new Uint8Array(0) }),
      /bad stream id/,
    );
  }
  for (const flags of [-1, 0x100, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
    assert.throws(
      () => encodeStreamFrame({ stream: 0, flags, payload: new Uint8Array(0) }),
      /bad flags/,
    );
  }
});

test("stream frame decoding rejects truncated, overflowing, and non-canonical varints", () => {
  const cases = [
    ["unterminated id", [0x80], /truncated stream frame/],
    ["missing flags", [3], /truncated stream frame/],
    ["u32 overflow", [0x80, 0x80, 0x80, 0x80, 0x10, 0], /bad stream id/],
    ["six-byte id", [0x80, 0x80, 0x80, 0x80, 0x80, 0], /bad stream varint/],
    ["overlong zero", [0x80, 0x00, 0], /non-canonical/],
    ["overlong one", [0x81, 0x00, 0], /non-canonical/],
    ["overlong 127", [0xff, 0x80, 0x00, 0], /non-canonical/],
  ] as const;

  for (const [name, bytes, expected] of cases) {
    assert.throws(() => decodeStreamFrame(Uint8Array.from(bytes)), expected, name);
  }
});
