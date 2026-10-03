import { test } from "node:test";
import assert from "node:assert/strict";
import { concatBytes } from "@noble/hashes/utils.js";
import { CipherState } from "./noise.ts";
import { RecordLayer, MAX_RECORD } from "./records.ts";

const K1 = new Uint8Array(32).fill(1);
const K2 = new Uint8Array(32).fill(2);

function pair(): { a: RecordLayer; b: RecordLayer } {
  return {
    a: new RecordLayer(new CipherState(K1), new CipherState(K2)),
    b: new RecordLayer(new CipherState(K2), new CipherState(K1)),
  };
}

test("records reassemble across fragmented feeds", () => {
  const { a, b } = pair();
  const first = Uint8Array.from([1, 2, 3]);
  const second = Uint8Array.from([4, 5, 6, 7, 8]);
  const wire = concatBytes(a.seal(first), a.seal(second), a.seal(new Uint8Array(0)));
  const got: Uint8Array[] = [];
  for (let i = 0; i < wire.length; i += 1) got.push(...b.feed(wire.subarray(i, i + 1)));
  assert.equal(got.length, 3);
  assert.deepEqual(got[0], first);
  assert.deepEqual(got[1], second);
  assert.deepEqual(got[2], new Uint8Array(0));
});

test("seal rejects plaintext above the record ceiling and takes the maximum exactly", () => {
  const { a, b } = pair();
  assert.throws(() => a.seal(new Uint8Array(MAX_RECORD - 16 + 1)));
  const framed = a.seal(new Uint8Array(MAX_RECORD - 16));
  assert.equal(framed.length, 2 + MAX_RECORD);
  const got = b.feed(framed);
  assert.equal(got.length, 1);
  assert.equal(got[0]!.length, MAX_RECORD - 16);
});

test("feed throws on a tampered MAC and on an impossible length", () => {
  const { a, b } = pair();
  const framed = a.seal(Uint8Array.from([9, 9, 9]));
  framed[framed.length - 1] = framed[framed.length - 1]! ^ 1;
  assert.throws(() => b.feed(framed));
  const { b: fresh } = pair();
  assert.throws(() => fresh.feed(Uint8Array.from([0, 0]))); // declared length 0 cannot carry a tag
  const { b: fresh2 } = pair();
  assert.throws(() => fresh2.feed(Uint8Array.from([0, 15])));
});

test("freshly installed states communicate in both directions", () => {
  const { a, b } = pair();
  b.feed(a.seal(Uint8Array.from([1])));
  b.feed(a.seal(Uint8Array.from([2])));
  const K3 = new Uint8Array(32).fill(3);
  const K4 = new Uint8Array(32).fill(4);
  a.install(new CipherState(K3), new CipherState(K4));
  b.install(new CipherState(K4), new CipherState(K3));
  const framed = a.seal(Uint8Array.from([7, 7]));
  const got = b.feed(framed);
  assert.deepEqual(got, [Uint8Array.from([7, 7])]);
  const back = a.feed(b.seal(Uint8Array.from([8])));
  assert.deepEqual(back, [Uint8Array.from([8])]);
  a.destroy();
  b.destroy();
});

test("install preserves reused and swapped states, including their nonces", () => {
  const reusedSend = new CipherState(K1);
  const replacedRecv = new CipherState(K2);
  const nextRecv = new CipherState(new Uint8Array(32).fill(3));
  reusedSend.encrypt(new Uint8Array());
  const reused = new RecordLayer(reusedSend, replacedRecv);
  reused.install(reusedSend, nextRecv);
  assert.deepEqual(reusedSend.key, K1);
  assert.equal(reusedSend.nonce, 1n);
  assert.throws(() => replacedRecv.key, /destroyed/);
  reused.destroy();

  const oldSend = new CipherState(K1);
  const oldRecv = new CipherState(K2);
  const swapped = new RecordLayer(oldSend, oldRecv);
  swapped.install(oldRecv, oldSend);
  assert.deepEqual(oldSend.key, K1);
  assert.deepEqual(oldRecv.key, K2);
  swapped.destroy();
});

test("install wipes replaced keys and destroy is terminal", () => {
  const oldSend = new CipherState(K1);
  const oldRecv = new CipherState(K2);
  const records = new RecordLayer(oldSend, oldRecv);
  const nextSend = new CipherState(new Uint8Array(32).fill(3));
  const nextRecv = new CipherState(new Uint8Array(32).fill(4));

  records.install(nextSend, nextRecv);
  assert.throws(() => oldSend.key, /destroyed/);
  assert.throws(() => oldRecv.key, /destroyed/);
  records.destroy();
  records.destroy();
  assert.throws(() => nextSend.key, /destroyed/);
  assert.throws(() => nextRecv.key, /destroyed/);
  assert.throws(() => records.seal(new Uint8Array()), /record layer destroyed/);
  assert.throws(() => records.open(new Uint8Array(16)), /record layer destroyed/);
  assert.throws(() => records.feed(new Uint8Array()), /record layer destroyed/);
  const rejectedSend = new CipherState(K1);
  const rejectedRecv = new CipherState(K2);
  assert.throws(() => records.install(rejectedSend, rejectedRecv), /record layer destroyed/);
  assert.deepEqual(rejectedSend.key, K1);
  assert.deepEqual(rejectedRecv.key, K2);
  rejectedSend.destroy();
  rejectedRecv.destroy();
});
