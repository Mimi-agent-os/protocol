import { x25519 } from "@noble/curves/ed25519.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { CipherState, createDeterministicHandshake, Handshake, type HandshakeOptions } from "./noise.ts";

interface VectorMessage {
  payload: string;
  ciphertext: string;
}

interface Vector {
  protocol_name: string;
  init_prologue: string;
  init_static?: string;
  init_ephemeral: string;
  init_remote_static?: string;
  init_psks?: string[];
  resp_prologue: string;
  resp_static?: string;
  resp_ephemeral: string;
  resp_psks?: string[];
  handshake_hash: string;
  messages: VectorMessage[];
}

const vectorsPath = new URL("./fixtures/noise-vectors.json", import.meta.url);
const { vectors } = JSON.parse(readFileSync(vectorsPath, "utf8")) as { vectors: Vector[] };

test("vector file carries all five required patterns", () => {
  assert.deepEqual(
    vectors.map((v) => v.protocol_name).sort(),
    ["NN", "XX", "IK", "IKpsk2", "XXpsk3"].map((p) => `Noise_${p}_25519_ChaChaPoly_SHA256`).sort(),
  );
});

for (const v of vectors) {
  const pattern = v.protocol_name.split("_")[1];
  if (pattern !== "NN" && pattern !== "XX" && pattern !== "IK" && pattern !== "IKpsk2" && pattern !== "XXpsk3") {
    throw new Error(`unsupported protocol in vector file: ${v.protocol_name}`);
  }
  test(`${v.protocol_name} is byte-exact`, () => {
    const initOpts: HandshakeOptions = {
      pattern,
      initiator: true,
      prologue: hexToBytes(v.init_prologue),
    };
    if (v.init_static !== undefined) initOpts.s = hexToBytes(v.init_static);
    if (v.init_remote_static !== undefined) initOpts.rs = hexToBytes(v.init_remote_static);
    if (v.init_psks !== undefined) initOpts.psks = v.init_psks.map(hexToBytes);
    const respOpts: HandshakeOptions = {
      pattern,
      initiator: false,
      prologue: hexToBytes(v.resp_prologue),
    };
    if (v.resp_static !== undefined) respOpts.s = hexToBytes(v.resp_static);
    if (v.resp_psks !== undefined) respOpts.psks = v.resp_psks.map(hexToBytes);
    const init = createDeterministicHandshake(initOpts, hexToBytes(v.init_ephemeral));
    const resp = createDeterministicHandshake(respOpts, hexToBytes(v.resp_ephemeral));

    let writer = init;
    let reader = resp;
    let i = 0;
    while (!(init.complete && resp.complete)) {
      const m = v.messages[i];
      if (!m) throw new Error("vector ended before the handshake completed");
      assert.equal(bytesToHex(writer.writeMessage(hexToBytes(m.payload))), m.ciphertext);
      assert.equal(bytesToHex(reader.readMessage(hexToBytes(m.ciphertext))), m.payload);
      [writer, reader] = [reader, writer];
      i += 1;
    }

    const initCs = init.split();
    const respCs = resp.split();
    assert.equal(bytesToHex(init.handshakeHash), v.handshake_hash);
    assert.equal(bytesToHex(resp.handshakeHash), v.handshake_hash);
    if (v.resp_static !== undefined) {
      const rs = init.remoteStatic;
      if (!rs) throw new Error("initiator is missing the responder static");
      assert.equal(bytesToHex(rs), bytesToHex(x25519.getPublicKey(hexToBytes(v.resp_static))));
    } else {
      assert.equal(init.remoteStatic, null);
    }
    if (v.init_static !== undefined) {
      const rs = resp.remoteStatic;
      if (!rs) throw new Error("responder never learned the initiator static");
      assert.equal(bytesToHex(rs), bytesToHex(x25519.getPublicKey(hexToBytes(v.init_static))));
    }

    if (i >= v.messages.length) throw new Error("vector carries no transport messages");
    let fromInitiator = writer === init; // transport continues the handshake alternation
    for (; i < v.messages.length; i += 1) {
      const m = v.messages[i];
      if (!m) throw new Error("unreachable");
      const tx = fromInitiator ? initCs.send : respCs.send;
      const rx = fromInitiator ? respCs.recv : initCs.recv;
      assert.equal(bytesToHex(tx.encrypt(hexToBytes(m.payload))), m.ciphertext);
      assert.equal(bytesToHex(rx.decrypt(hexToBytes(m.ciphertext))), m.payload);
      fromInitiator = !fromInitiator;
    }
    initCs.send.destroy();
    initCs.recv.destroy();
    respCs.send.destroy();
    respCs.recv.destroy();
  });
}

test("a flipped ciphertext byte makes readMessage throw", () => {
  const init = new Handshake({ pattern: "XX", initiator: true, s: new Uint8Array(32).fill(1) });
  const resp = new Handshake({ pattern: "XX", initiator: false, s: new Uint8Array(32).fill(3) });
  resp.readMessage(init.writeMessage());
  const message2 = resp.writeMessage();
  assert.equal(message2.length, 96);
  const tampered = message2.slice();
  tampered[40] = tampered[40]! ^ 1; // inside the encrypted static
  assert.throws(() => init.readMessage(tampered));
  init.destroy();
  resp.destroy();
});

test("a wrong psk fails message 2 of IKpsk2", () => {
  const respStatic = new Uint8Array(32).fill(5);
  const init = new Handshake({
    pattern: "IKpsk2",
    initiator: true,
    s: new Uint8Array(32).fill(1),
    rs: x25519.getPublicKey(respStatic),
    psks: [new Uint8Array(32).fill(7)],
  });
  const resp = new Handshake({
    pattern: "IKpsk2",
    initiator: false,
    s: respStatic,
    psks: [new Uint8Array(32).fill(8)],
  });
  resp.readMessage(init.writeMessage()); // message 1 mixes no psk yet, so it still crosses
  const message2 = resp.writeMessage();
  assert.throws(() => init.readMessage(message2));
  init.destroy();
  resp.destroy();
});

test("Noise constructors reject malformed keys, PSK counts, and missing pre-message statics", () => {
  const key = new Uint8Array(32).fill(1);
  const shortKey = key.subarray(1);
  for (const construct of [
    () => new CipherState(shortKey),
    () => new Handshake({ pattern: "XX", initiator: true, s: shortKey }),
    () => new Handshake({ pattern: "IK", initiator: true, rs: shortKey }),
    () => new Handshake({ pattern: "XXpsk3", initiator: true, s: key, psks: [shortKey] }),
  ]) {
    assert.throws(construct, /32 bytes/);
  }

  assert.throws(() => new Handshake({ pattern: "NN", initiator: true, psks: [key] }), /exactly 0 psk/);
  assert.throws(() => new Handshake({ pattern: "XXpsk3", initiator: true, s: key }), /exactly 1 psk/);
  assert.throws(() => new Handshake({ pattern: "IK", initiator: true, s: key }), /initiator needs rs/);
  assert.throws(() => new Handshake({ pattern: "IK", initiator: false }), /responder needs s/);
});

test("handshake state enforces message turns and completion", () => {
  const init = createDeterministicHandshake({ pattern: "NN", initiator: true }, new Uint8Array(32).fill(1));
  const resp = createDeterministicHandshake({ pattern: "NN", initiator: false }, new Uint8Array(32).fill(2));

  assert.throws(() => resp.writeMessage(), /peer writes this message/);
  assert.throws(() => init.readMessage(new Uint8Array()), /we write this message/);
  assert.throws(() => init.split(), /handshake not complete/);
  const message1 = init.writeMessage();
  assert.throws(() => init.writeMessage(), /peer writes this message/);
  resp.readMessage(message1);
  assert.throws(() => resp.readMessage(new Uint8Array()), /we write this message/);
  init.readMessage(resp.writeMessage());
  assert.throws(() => init.writeMessage(), /handshake already complete/);
  assert.throws(() => resp.readMessage(new Uint8Array()), /handshake already complete/);
  init.destroy();
  resp.destroy();
});

test("handshake parsing rejects truncated fields and low-order peer keys", () => {
  const truncatedEphemeral = createDeterministicHandshake(
    { pattern: "NN", initiator: false },
    new Uint8Array(32).fill(2),
  );
  assert.throws(() => truncatedEphemeral.readMessage(new Uint8Array(31)), /truncated handshake message/);
  truncatedEphemeral.destroy();

  const init = createDeterministicHandshake(
    { pattern: "XX", initiator: true, s: new Uint8Array(32).fill(1) },
    new Uint8Array(32).fill(2),
  );
  const resp = createDeterministicHandshake(
    { pattern: "XX", initiator: false, s: new Uint8Array(32).fill(3) },
    new Uint8Array(32).fill(4),
  );
  resp.readMessage(init.writeMessage());
  const message2 = resp.writeMessage();
  assert.throws(() => init.readMessage(message2.subarray(0, 32 + 48 - 1)), /truncated handshake message/);
  init.destroy();
  resp.destroy();

  const lowOrder = createDeterministicHandshake({ pattern: "NN", initiator: false }, new Uint8Array(32).fill(5));
  lowOrder.readMessage(new Uint8Array(32));
  assert.throws(() => lowOrder.writeMessage());
  lowOrder.destroy();
});

test("handshake result getters return copies", () => {
  const remoteStatic = x25519.getPublicKey(new Uint8Array(32).fill(2));
  const handshake = createDeterministicHandshake(
    { pattern: "IK", initiator: true, s: new Uint8Array(32).fill(1), rs: remoteStatic },
    new Uint8Array(32).fill(3),
  );
  const expectedHash = handshake.handshakeHash;
  const exposedHash = handshake.handshakeHash;
  const exposedRemote = handshake.remoteStatic;
  if (!exposedRemote) throw new Error("missing configured remote static");

  exposedHash.fill(0);
  exposedRemote.fill(0);
  assert.deepEqual(handshake.handshakeHash, expectedHash);
  assert.deepEqual(handshake.remoteStatic, remoteStatic);
  handshake.destroy();
});

test("nonces advance only on successful AEAD calls", () => {
  const key = new Uint8Array(32).fill(9);
  const pt = hexToBytes("00112233445566778899");
  const tx = new CipherState(key);
  const rx = new CipherState(key);
  assert.equal(bytesToHex(tx.key), bytesToHex(key));
  assert.equal(tx.nonce, 0n);
  const c0 = tx.encrypt(pt);
  const c1 = tx.encrypt(pt);
  assert.equal(tx.nonce, 2n);
  assert.notEqual(bytesToHex(c0), bytesToHex(c1));
  assert.equal(bytesToHex(rx.decrypt(c0)), bytesToHex(pt));
  assert.equal(rx.nonce, 1n);
  const bad = c1.slice();
  bad[0] = bad[0]! ^ 1;
  assert.throws(() => rx.decrypt(bad));
  assert.equal(rx.nonce, 1n);
  assert.equal(bytesToHex(rx.decrypt(c1)), bytesToHex(pt));
  assert.equal(rx.nonce, 2n);
  tx.destroy();
  rx.destroy();
});

test("split is one-shot and keeps public handshake results available", () => {
  const init = createDeterministicHandshake({ pattern: "NN", initiator: true }, new Uint8Array(32).fill(1));
  const resp = createDeterministicHandshake({ pattern: "NN", initiator: false }, new Uint8Array(32).fill(2));
  resp.readMessage(init.writeMessage());
  init.readMessage(resp.writeMessage());
  const hash = bytesToHex(init.handshakeHash);
  const initCs = init.split();
  const respCs = resp.split();

  assert.equal(bytesToHex(respCs.recv.decrypt(initCs.send.encrypt(Uint8Array.of(1, 2, 3)))), "010203");
  assert.equal(bytesToHex(init.handshakeHash), hash);
  assert.equal(init.remoteStatic, null);
  assert.throws(() => init.split(), /handshake already split/);
  assert.throws(() => resp.split(), /handshake already split/);
  initCs.send.destroy();
  initCs.recv.destroy();
  respCs.send.destroy();
  respCs.recv.destroy();
});

test("public HandshakeOptions cannot force ephemeral-key reuse", () => {
  const ephemeral = new Uint8Array(32).fill(7);
  const options: HandshakeOptions = {
    pattern: "NN",
    initiator: true,
    // @ts-expect-error deterministic ephemerals are deliberately not part of the public API
    e: ephemeral,
  };
  const firstHandshake = new Handshake(options);
  const secondHandshake = new Handshake(options);
  const first = firstHandshake.writeMessage();
  const second = secondHandshake.writeMessage();
  const injectedPublic = x25519.getPublicKey(ephemeral);

  assert.notDeepEqual(first, second);
  assert.notDeepEqual(first.subarray(0, 32), injectedPublic);
  assert.notDeepEqual(second.subarray(0, 32), injectedPublic);
  firstHandshake.destroy();
  secondHandshake.destroy();
});

test("destroy makes a CipherState permanently unusable", () => {
  const key = new Uint8Array(32).fill(9);
  const cipher = new CipherState(key);
  const exposedCopy = cipher.key;
  cipher.destroy();
  cipher.destroy();

  assert.deepEqual(key, new Uint8Array(32).fill(9), "CipherState must not wipe caller-owned input");
  assert.deepEqual(exposedCopy, key, "destroy must not mutate previously returned key copies");
  assert.throws(() => cipher.key, /cipher state destroyed/);
  assert.throws(() => cipher.encrypt(Uint8Array.of(1)), /cipher state destroyed/);
  assert.throws(() => cipher.decrypt(new Uint8Array(16)), /cipher state destroyed/);
});

test("destroy aborts a Handshake without mutating caller-owned secrets", () => {
  const localStatic = new Uint8Array(32).fill(1);
  const remoteStatic = x25519.getPublicKey(new Uint8Array(32).fill(2));
  const ephemeral = new Uint8Array(32).fill(3);
  const psk = new Uint8Array(32).fill(4);
  const handshake = createDeterministicHandshake(
    { pattern: "IKpsk2", initiator: true, s: localStatic, rs: remoteStatic, psks: [psk] },
    ephemeral,
  );
  handshake.writeMessage();
  handshake.destroy();
  handshake.destroy();

  assert.deepEqual(localStatic, new Uint8Array(32).fill(1));
  assert.deepEqual(ephemeral, new Uint8Array(32).fill(3));
  assert.deepEqual(psk, new Uint8Array(32).fill(4));
  assert.throws(() => handshake.writeMessage(), /handshake destroyed/);
  assert.throws(() => handshake.readMessage(new Uint8Array()), /handshake destroyed/);
  assert.throws(() => handshake.split(), /handshake destroyed/);
});
