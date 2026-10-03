import { x25519 } from "@noble/curves/ed25519.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes } from "@noble/hashes/utils.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import { CipherState, Handshake } from "./noise.ts";
import { RecordLayer } from "./records.ts";
import { FLAG_DATA, FLAG_END, encodeStreamFrame, decodeStreamFrame } from "./stream.ts";
import { ClientSession, ServerSession, type ClientEvent, type ServerEvent } from "./session.ts";

const utf8 = new TextEncoder();
const utf8d = new TextDecoder();
const clientPriv = new Uint8Array(32).fill(7);
const clientPub = x25519.getPublicKey(clientPriv);
const gatewayPriv = new Uint8Array(32).fill(9);
const gatewayPub = x25519.getPublicKey(gatewayPriv);

function frame(chunk: Uint8Array): Uint8Array {
  const out = new Uint8Array(2 + chunk.length);
  out[0] = chunk.length >>> 8;
  out[1] = chunk.length & 0xff;
  out.set(chunk, 2);
  return out;
}

// Delivers every byte stream in odd-sized slices so buffering across chunk boundaries is exercised.
function pump(client: ClientSession, server: ServerSession, slice = 3): { cEvents: ClientEvent[]; sEvents: ServerEvent[] } {
  const cEvents: ClientEvent[] = [];
  const sEvents: ServerEvent[] = [];
  let toServer = concatBytes(...client.start());
  let toClient: Uint8Array = new Uint8Array(0);
  let rounds = 0;
  for (; rounds < 32 && (toServer.length > 0 || toClient.length > 0); rounds += 1) {
    const serverOut: Uint8Array[] = [];
    for (let i = 0; i < toServer.length; i += slice) {
      const r = server.feed(toServer.subarray(i, i + slice));
      serverOut.push(...r.out);
      sEvents.push(...r.events);
    }
    toServer = new Uint8Array(0);
    const clientOut: Uint8Array[] = [];
    toClient = concatBytes(toClient, ...serverOut);
    for (let i = 0; i < toClient.length; i += slice) {
      const r = client.feed(toClient.subarray(i, i + slice));
      clientOut.push(...r.out);
      cEvents.push(...r.events);
    }
    toClient = new Uint8Array(0);
    toServer = concatBytes(...clientOut);
  }
  if (toServer.length > 0 || toClient.length > 0) throw new Error(`session exchange did not settle after ${rounds} rounds`);
  return { cEvents, sEvents };
}

test("happy path: both sides get ready and exchange app frames over odd chunk boundaries", () => {
  const client = new ClientSession({ s: clientPriv, gatewayPub, protocol: 7 });
  const server = new ServerSession({ s: gatewayPriv, protocol: 7, lookup: () => "active" });
  const { cEvents, sEvents } = pump(client, server);
  const ready = cEvents.find((e) => e.type === "ready");
  if (!ready || ready.type !== "ready") throw new Error("client never got ready");
  assert.deepEqual(ready.info, { protocol: 7 });
  const hello = sEvents.find((e) => e.type === "hello");
  if (!hello || hello.type !== "hello") throw new Error("server never said hello");
  assert.deepEqual(hello.clientPub, clientPub);
  assert.ok(sEvents.some((e) => e.type === "ready"));
  assert.ok(!cEvents.some((e) => e.type === "close") && !sEvents.some((e) => e.type === "close"));

  const ping = { stream: 1, flags: FLAG_DATA, payload: utf8.encode("ping") };
  const atServer = server.feed(concatBytes(...client.send(ping)));
  assert.equal(atServer.events.length, 1);
  assert.deepEqual(atServer.events[0], { type: "frame", frame: ping });
  const pong = { stream: 300, flags: FLAG_DATA, payload: utf8.encode("pong") };
  const atClient = client.feed(concatBytes(...server.send(pong)));
  assert.deepEqual(atClient.events, [{ type: "frame", frame: pong }]);
});

test("reject closes only after msg2 + kem pub, indistinguishably from accepted sessions until then", () => {
  const msg1Outputs: number[] = [];
  for (const status of ["reject", "pending", "active"] as const) {
    const client = new ClientSession({ s: clientPriv, gatewayPub, protocol: 7 });
    const server = new ServerSession({ s: gatewayPriv, protocol: 7, lookup: () => status });
    const msg1 = concatBytes(...client.start());
    const r1 = server.feed(msg1);
    assert.ok(concatBytes(...r1.out).length > 0, "server must reply to msg1 even for a doomed client");
    assert.ok(!r1.events.some((e) => e.type === "close"));
    msg1Outputs.push(concatBytes(...r1.out).length);
    if (status === "reject") {
      const kemRecord = concatBytes(...client.feed(concatBytes(...r1.out)).out);
      assert.ok(kemRecord.length > 0);
      const r2 = server.feed(kemRecord);
      assert.deepEqual(r2.out, []);
      assert.deepEqual(r2.events, [{ type: "close" }]);
      assert.deepEqual(server.feed(utf8.encode("anything")), { out: [], events: [] });
    }
  }
  assert.equal(new Set(msg1Outputs).size, 1, "transcript length must not leak the lookup result before the kem step");
});

test("lookup fails closed on every runtime value outside the declared allowlist", async () => {
  let thenableObserved = false;
  const rejectingThenable = {
    then(_resolve: (value: unknown) => void, reject: (reason: unknown) => void): void {
      thenableObserved = true;
      reject(new Error("thenable rejected"));
    },
  };
  for (const invalid of [undefined, null, "typo", Promise.resolve("active"), Promise.reject(new Error("lookup rejected")), rejectingThenable]) {
    const client = new ClientSession({ s: clientPriv, gatewayPub, protocol: 7 });
    const lookup = (() => invalid) as unknown as (pub: Uint8Array) => "active" | "pending" | "reject";
    const server = new ServerSession({ s: gatewayPriv, protocol: 7, lookup });
    const msg2 = server.feed(concatBytes(...client.start())).out;
    const kem = client.feed(concatBytes(...msg2)).out;
    const result = server.feed(concatBytes(...kem));
    assert.deepEqual(result, { out: [], events: [{ type: "close" }] });
  }
  await Promise.resolve();
  assert.equal(thenableObserved, true);
});

test("a synchronous lookup failure propagates and leaves the server terminal", () => {
  const sentinel = new Error("lookup failed");
  const client = new ClientSession({ s: clientPriv, gatewayPub, protocol: 7 });
  const server = new ServerSession({
    s: gatewayPriv,
    protocol: 7,
    lookup: () => {
      throw sentinel;
    },
  });
  try {
    const msg2 = server.feed(concatBytes(...client.start())).out;
    const kem = client.feed(concatBytes(...msg2)).out;
    assert.throws(() => server.feed(concatBytes(...kem)), (error) => error === sentinel);
    assert.deepEqual(server.feed(Uint8Array.of(0, 0)), { out: [], events: [] });
    assert.throws(() => server.send({ stream: 1, flags: FLAG_DATA, payload: new Uint8Array() }), /not ready/);
  } finally {
    client.destroy();
    server.destroy();
  }
});

test("mutating the hello event cannot change the client key used for lookup", () => {
  const client = new ClientSession({ s: clientPriv, gatewayPub, protocol: 7 });
  const server = new ServerSession({
    s: gatewayPriv,
    protocol: 7,
    lookup: (pub) => {
      assert.deepEqual(pub, clientPub);
      return "active";
    },
  });
  const msg1 = server.feed(concatBytes(...client.start()));
  const hello = msg1.events[0];
  if (hello?.type !== "hello") throw new Error("server never said hello");
  hello.clientPub.fill(0);

  const kem = client.feed(concatBytes(...msg1.out));
  assert.doesNotThrow(() => server.feed(concatBytes(...kem.out)));
});

test("a Noise failure during start closes the client machine", () => {
  const client = new ClientSession({ s: clientPriv, gatewayPub: new Uint8Array(32), protocol: 7 });
  assert.throws(() => client.start());
  assert.deepEqual(client.feed(frame(new Uint8Array(0))), { out: [], events: [] });
});

test("client feed before start throws without poisoning the frame decoder", () => {
  const client = new ClientSession({ s: clientPriv, gatewayPub, protocol: 7 });
  const server = new ServerSession({ s: gatewayPriv, protocol: 7, lookup: () => "active" });

  assert.throws(() => client.feed(Uint8Array.of(0)), /not started/);
  const msg2 = server.feed(concatBytes(...client.start())).out;
  assert.equal(client.feed(concatBytes(...msg2)).out.length, 1);
});

test("destroy cancels session machines and is terminal", () => {
  const client = new ClientSession({ s: clientPriv, gatewayPub, protocol: 7 });
  const server = new ServerSession({ s: gatewayPriv, protocol: 7, lookup: () => "active" });

  client.destroy();
  client.destroy();
  server.destroy();
  server.destroy();
  assert.deepEqual(client.feed(new Uint8Array()), { out: [], events: [] });
  assert.deepEqual(server.feed(new Uint8Array()), { out: [], events: [] });
  assert.throws(() => client.start(), /already started/);
  assert.throws(() => client.send({ stream: 0, flags: 0, payload: new Uint8Array() }), /not ready/);
  assert.throws(() => server.send({ stream: 0, flags: 0, payload: new Uint8Array() }), /not ready/);
  assert.throws(() => server.activate(), /nothing to activate/);
});

test("handshake framing rejects oversized bodies and coalesced empty-frame bursts immediately", () => {
  for (const hostile of [Uint8Array.of(0xff, 0xff), new Uint8Array(200_000)]) {
    const server = new ServerSession({ s: gatewayPriv, protocol: 7, lookup: () => "active" });
    assert.throws(() => server.feed(hostile), /bad frame length/);
    assert.deepEqual(server.feed(concatBytes(...new ClientSession({ s: clientPriv, gatewayPub, protocol: 7 }).start())), { out: [], events: [] });
  }
});

test("protocol mismatch surfaces a typed error naming the gateway's version on the client and closes both sides", () => {
  const client = new ClientSession({ s: clientPriv, gatewayPub, protocol: 7 });
  const server = new ServerSession({ s: gatewayPriv, protocol: 8, lookup: () => "active" });
  const { cEvents, sEvents } = pump(client, server);
  assert.deepEqual(cEvents.filter((e) => e.type === "error"), [{ type: "error", code: "incompatible_protocol", peer: 8 }]);
  assert.ok(cEvents.some((e) => e.type === "close"));
  assert.ok(!cEvents.some((e) => e.type === "ready"));
  assert.ok(sEvents.some((e) => e.type === "close"));
  assert.ok(!sEvents.some((e) => e.type === "ready"));
  assert.throws(() => client.send({ stream: 1, flags: FLAG_DATA, payload: new Uint8Array(0) }));
});

test("the client fails closed on an unknown activation status", () => {
  const client = new ClientSession({ s: clientPriv, gatewayPub, protocol: 7 });
  const hs = new Handshake({ pattern: "IK", initiator: false, prologue: utf8.encode("mimi/session/v1"), s: gatewayPriv });
  let records: RecordLayer | null = null;
  const sensitive: Uint8Array[] = [];
  try {
    hs.readMessage(client.start()[0]!.subarray(2));
    const msg2 = frame(hs.writeMessage());
    const { send, recv } = hs.split();
    const handshakeHash = hs.handshakeHash;
    sensitive.push(handshakeHash);
    records = new RecordLayer(send, recv);
    const kemPublicKey = records.feed(client.feed(msg2).out[0]!)[0]!;
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(kemPublicKey);
    sensitive.push(sharedSecret);
    const kemReply = records.seal(cipherText);
    const oldRecvKey = recv.key;
    const oldSendKey = send.key;
    const c2gIkm = concatBytes(oldRecvKey, sharedSecret);
    const g2cIkm = concatBytes(oldSendKey, sharedSecret);
    sensitive.push(oldRecvKey, oldSendKey, c2gIkm, g2cIkm);
    const c2g = hkdf(sha256, c2gIkm, handshakeHash, utf8.encode("mimi/pq1/c2g"), 32);
    const g2c = hkdf(sha256, g2cIkm, handshakeHash, utf8.encode("mimi/pq1/g2c"), 32);
    sensitive.push(c2g, g2c);
    records.install(new CipherState(g2c), new CipherState(c2g));
    assert.deepEqual(client.feed(kemReply), { out: [], events: [] });

    const invalidInfo = records.seal(encodeStreamFrame({
      stream: 0,
      flags: FLAG_END,
      payload: utf8.encode(JSON.stringify({ t: "server_info", protocol: 7, activation: "approved" })),
    }));
    assert.deepEqual(client.feed(invalidInfo), { out: [], events: [{ type: "close" }] });
    assert.throws(() => client.send({ stream: 1, flags: FLAG_DATA, payload: new Uint8Array() }), /not ready/);
  } finally {
    client.destroy();
    records?.destroy();
    hs.destroy();
    for (const secret of sensitive) secret.fill(0);
  }
});

test("pending sessions are gated to stream 0 until activate() unlocks them", () => {
  {
    const client = new ClientSession({ s: clientPriv, gatewayPub, protocol: 7 });
    const server = new ServerSession({ s: gatewayPriv, protocol: 7, lookup: () => "pending" });
    const { cEvents } = pump(client, server);
    const ready = cEvents.find((e) => e.type === "ready");
    if (!ready || ready.type !== "ready") throw new Error("client never got ready");
    assert.deepEqual(ready.info, { protocol: 7, activation: "pending" });
    assert.throws(() => server.send({ stream: 1, flags: FLAG_DATA, payload: new Uint8Array(0) }));
    const appFrame = client.send({ stream: 1, flags: FLAG_DATA, payload: utf8.encode("too early") });
    assert.deepEqual(server.feed(concatBytes(...appFrame)).events, [{ type: "close" }]);
  }
  {
    const client = new ClientSession({ s: clientPriv, gatewayPub, protocol: 7 });
    const server = new ServerSession({ s: gatewayPriv, protocol: 7, lookup: () => "pending" });
    pump(client, server);
    const r = client.feed(concatBytes(...server.activate()));
    assert.equal(r.events.length, 1);
    const e = r.events[0];
    if (!e || e.type !== "frame") throw new Error("activation did not surface as a frame");
    assert.equal(e.frame.stream, 0);
    assert.equal(e.frame.flags, FLAG_END);
    assert.deepEqual(JSON.parse(utf8d.decode(e.frame.payload)), { t: "activated" });
    const ping = { stream: 4, flags: FLAG_DATA, payload: utf8.encode("now allowed") };
    assert.deepEqual(server.feed(concatBytes(...client.send(ping))).events, [{ type: "frame", frame: ping }]);
    const pong = { stream: 4, flags: FLAG_DATA, payload: utf8.encode("welcome") };
    assert.deepEqual(client.feed(concatBytes(...server.send(pong))).events, [{ type: "frame", frame: pong }]);
  }
});

test("a pending server cannot activate before client_ready", () => {
  const client = new ClientSession({ s: clientPriv, gatewayPub, protocol: 7 });
  const server = new ServerSession({ s: gatewayPriv, protocol: 7, lookup: () => "pending" });
  const msg2 = server.feed(concatBytes(...client.start())).out;
  const kem = client.feed(concatBytes(...msg2)).out;
  const serverReply = server.feed(concatBytes(...kem));
  assert.equal(serverReply.out.length, 2);
  assert.throws(() => server.activate(), /nothing to activate/);
  const ready = client.feed(concatBytes(...serverReply.out)).out;
  assert.deepEqual(server.feed(concatBytes(...ready)).events, [{ type: "ready" }]);
  assert.doesNotThrow(() => server.activate());
});

test("a tampered kem ciphertext record makes the client throw", () => {
  const client = new ClientSession({ s: clientPriv, gatewayPub, protocol: 7 });
  const server = new ServerSession({ s: gatewayPriv, protocol: 7, lookup: () => "active" });
  const msg2 = concatBytes(...server.feed(concatBytes(...client.start())).out);
  const kemRecord = concatBytes(...client.feed(msg2).out);
  const serverReply = server.feed(kemRecord).out;
  const kemCt = serverReply[0]!; // first record back is the kem ciphertext
  const serverInfo = serverReply[1]!;
  const validKemCt = kemCt.slice();
  kemCt[kemCt.length - 1] = kemCt[kemCt.length - 1]! ^ 1;
  assert.throws(() => client.feed(kemCt));
  assert.deepEqual(client.feed(validKemCt), { out: [], events: [] });
  assert.deepEqual(client.feed(serverInfo), { out: [], events: [] });
  assert.throws(() => client.send({ stream: 1, flags: FLAG_DATA, payload: new Uint8Array(0) }));
});

// A scripted client built from the public noise/record/kem pieces must interop with the real
// ServerSession, proving the server derives exactly the specified rekey — and that the old
// CipherStates cannot read anything sealed after it.
test("rekey follows the pq1 recipe and retires the noise transport keys", () => {
  const server = new ServerSession({ s: gatewayPriv, protocol: 7, lookup: () => "active" });
  const hs = new Handshake({ pattern: "IK", initiator: true, prologue: utf8.encode("mimi/session/v1"), s: clientPriv, rs: gatewayPub });
  let records: RecordLayer | null = null;
  let staleRecv: CipherState | null = null;
  const sensitive: Uint8Array[] = [];
  try {
    const r1 = server.feed(frame(hs.writeMessage()));
    hs.readMessage(r1.out[0]!.subarray(2));
    const { send, recv } = hs.split();
    const oldSendKey = send.key;
    const oldRecvKey = recv.key;
    const handshakeHash = hs.handshakeHash;
    sensitive.push(oldSendKey, oldRecvKey, handshakeHash);
    records = new RecordLayer(send, recv);
    const kem = ml_kem768.keygen();
    sensitive.push(kem.secretKey);
    const r2 = server.feed(records.seal(kem.publicKey));
    assert.equal(r2.out.length, 2); // kem ciphertext record, then server_info under the new keys
    const kemCt = records.feed(r2.out[0]!)[0]!;
    assert.equal(kemCt.length, 1088);
    const shared = ml_kem768.decapsulate(kemCt, kem.secretKey);
    sensitive.push(shared);

    const infoCiphertext = r2.out[1]!.subarray(2);
    staleRecv = new CipherState(oldRecvKey);
    staleRecv.decrypt(r2.out[0]!.subarray(2)); // replay the kem record to reach nonce 1, where server_info would sit without a rekey
    assert.throws(() => staleRecv!.decrypt(infoCiphertext), "old g2c CipherState must not decrypt post-rekey records");

    const c2gIkm = concatBytes(oldSendKey, shared);
    const g2cIkm = concatBytes(oldRecvKey, shared);
    const newSendKey = hkdf(sha256, c2gIkm, handshakeHash, utf8.encode("mimi/pq1/c2g"), 32);
    const newRecvKey = hkdf(sha256, g2cIkm, handshakeHash, utf8.encode("mimi/pq1/g2c"), 32);
    sensitive.push(c2gIkm, g2cIkm, newSendKey, newRecvKey);
    records.install(new CipherState(newSendKey), new CipherState(newRecvKey));
    assert.throws(() => send.key, /destroyed/);
    assert.throws(() => recv.key, /destroyed/);
    const info = decodeStreamFrame(records.feed(r2.out[1]!)[0]!);
    assert.equal(info.stream, 0);
    assert.deepEqual(JSON.parse(utf8d.decode(info.payload)), { t: "server_info", protocol: 7 });

    const readyMsg = { stream: 0, flags: FLAG_END, payload: utf8.encode(JSON.stringify({ t: "client_ready", protocol: 7 })) };
    const r3 = server.feed(records.seal(encodeStreamFrame(readyMsg)));
    assert.deepEqual(r3.events, [{ type: "ready" }]);
    const app = { stream: 2, flags: FLAG_DATA, payload: utf8.encode("post-rekey") };
    assert.deepEqual(records.feed(concatBytes(...server.send(app))), [encodeStreamFrame(app)]);
  } finally {
    staleRecv?.destroy();
    records?.destroy();
    hs.destroy();
    server.destroy();
    for (const secret of sensitive) secret.fill(0);
  }
});

test("control messages require an END-terminated stream-0 JSON object", () => {
  for (const control of [
    { stream: 0, flags: FLAG_DATA, payload: utf8.encode(JSON.stringify({ t: "client_ready", protocol: 7 })) },
    { stream: 1, flags: FLAG_END, payload: utf8.encode(JSON.stringify({ t: "client_ready", protocol: 7 })) },
    { stream: 0, flags: FLAG_END, payload: utf8.encode("{") },
    { stream: 0, flags: FLAG_END, payload: utf8.encode("null") },
    { stream: 0, flags: FLAG_END, payload: utf8.encode("[]") },
  ]) {
    const server = new ServerSession({ s: gatewayPriv, protocol: 7, lookup: () => "active" });
    const hs = new Handshake({ pattern: "IK", initiator: true, prologue: utf8.encode("mimi/session/v1"), s: clientPriv, rs: gatewayPub });
    let records: RecordLayer | null = null;
    const sensitive: Uint8Array[] = [];
    try {
      const r1 = server.feed(frame(hs.writeMessage()));
      hs.readMessage(r1.out[0]!.subarray(2));
      const { send, recv } = hs.split();
      records = new RecordLayer(send, recv);
      const kem = ml_kem768.keygen();
      sensitive.push(kem.secretKey);
      const r2 = server.feed(records.seal(kem.publicKey));
      const kemCt = records.feed(r2.out[0]!)[0]!;
      const shared = ml_kem768.decapsulate(kemCt, kem.secretKey);
      sensitive.push(shared);
      const oldSendKey = send.key;
      const oldRecvKey = recv.key;
      const handshakeHash = hs.handshakeHash;
      sensitive.push(oldSendKey, oldRecvKey, handshakeHash);
      const c2gIkm = concatBytes(oldSendKey, shared);
      const g2cIkm = concatBytes(oldRecvKey, shared);
      sensitive.push(c2gIkm, g2cIkm);
      const c2g = hkdf(sha256, c2gIkm, handshakeHash, utf8.encode("mimi/pq1/c2g"), 32);
      const g2c = hkdf(sha256, g2cIkm, handshakeHash, utf8.encode("mimi/pq1/g2c"), 32);
      sensitive.push(c2g, g2c);
      records.install(new CipherState(c2g), new CipherState(g2c));
      records.feed(r2.out[1]!);
      assert.deepEqual(server.feed(records.seal(encodeStreamFrame(control))).events, [{ type: "close" }]);
      assert.deepEqual(server.feed(Uint8Array.of(0, 0)), { out: [], events: [] });
    } finally {
      records?.destroy();
      hs.destroy();
      server.destroy();
      for (const secret of sensitive) secret.fill(0);
    }
  }
});
