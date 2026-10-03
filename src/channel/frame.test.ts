import assert from "node:assert/strict";
import { test } from "node:test";
import { concatBytes } from "@noble/hashes/utils.js";
import { frame, FrameDecodeError, FrameDecoder } from "./frame.ts";

test("framing preserves empty frames and order across every chunk boundary", () => {
  const payloads = [new Uint8Array(0), Uint8Array.of(1, 2, 3), new Uint8Array(0), Uint8Array.of(4, 5)];
  const wire = concatBytes(...payloads.map(frame));
  for (let cut = 0; cut <= wire.length; cut++) {
    const decoder = new FrameDecoder();
    assert.deepEqual([...decoder.feed(wire.subarray(0, cut)), ...decoder.feed(wire.subarray(cut))], payloads);
    assert.deepEqual([...decoder.feed(new Uint8Array(0))], []);
  }
});

test("a maximum frame reassembles from single bytes without retaining caller buffers", () => {
  const payload = Uint8Array.from({ length: 65535 }, (_, i) => i & 0xff);
  const wire = frame(payload);
  const decoder = new FrameDecoder();
  const chunk = new Uint8Array(1);
  const received: Uint8Array[] = [];
  for (const byte of wire) {
    chunk[0] = byte;
    received.push(...decoder.feed(chunk));
    chunk[0] = 0;
  }
  assert.deepEqual(received, [payload]);
  assert.throws(() => frame(new Uint8Array(65536)), /frame too large/);
});

test("minimum frame length is checked as soon as its split header completes", () => {
  const decoder = new FrameDecoder(16);
  assert.deepEqual([...decoder.feed(Uint8Array.of(0))], []);
  assert.throws(() => [...decoder.feed(Uint8Array.of(15))], FrameDecodeError);
  const valid = new FrameDecoder(16);
  assert.deepEqual([...valid.feed(frame(new Uint8Array(16)))], [new Uint8Array(16)]);
});

test("a declared length above the maximum is rejected and the decoder recovers", () => {
  const decoder = new FrameDecoder(0, 32);
  assert.throws(() => [...decoder.feed(Uint8Array.of(0, 33))], FrameDecodeError);
  assert.deepEqual([...decoder.feed(frame(new Uint8Array(32)))], [new Uint8Array(32)]);
});

test("frame bounds must be ordered u16 integers and cannot change mid-frame", () => {
  for (const [min, max] of [
    [-1, 0],
    [0, 0x10000],
    [0.5, 1],
    [0, Number.NaN],
    [2, 1],
  ] as const) {
    assert.throws(() => new FrameDecoder(min, max), /bad frame bounds/);
    assert.throws(() => new FrameDecoder().setBounds(min, max), /bad frame bounds/);
  }

  const adjustable = new FrameDecoder();
  adjustable.setBounds(2, 2);
  assert.throws(() => [...adjustable.feed(frame(Uint8Array.of(1)))], FrameDecodeError);
  assert.deepEqual([...adjustable.feed(frame(Uint8Array.of(1, 2)))], [Uint8Array.of(1, 2)]);

  const partial = new FrameDecoder();
  assert.deepEqual([...partial.feed(Uint8Array.of(0))], []);
  assert.throws(() => partial.setBounds(0, 32), /mid-frame/);
});

test("clear discards both a partial header and a partial body", () => {
  const wire = frame(Uint8Array.of(1, 2, 3));
  for (const cut of [1, 2, 3, 4]) {
    const decoder = new FrameDecoder();
    assert.deepEqual([...decoder.feed(wire.subarray(0, cut))], []);
    decoder.clear();
    assert.deepEqual([...decoder.feed(wire)], [Uint8Array.of(1, 2, 3)]);
  }
});

test("complete frames do not alias the caller's transport buffer", () => {
  const wire = frame(Uint8Array.of(1, 2, 3));
  const decoded = [...new FrameDecoder().feed(wire)][0]!;
  wire.fill(9);
  assert.deepEqual(decoded, Uint8Array.of(1, 2, 3));
});

test("feed yields a frame before inspecting a hostile suffix", () => {
  const frames = new FrameDecoder(0, 0).feed(Uint8Array.of(0, 0, 0, 1));
  assert.deepEqual(frames.next(), { value: new Uint8Array(0), done: false });
  assert.throws(() => frames.next(), /bad frame length/);
});
