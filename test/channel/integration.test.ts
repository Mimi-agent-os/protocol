import { x25519 } from "@noble/curves/ed25519.js";
import { concatBytes } from "@noble/hashes/utils.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ClientSession,
  FLAG_DATA,
  FLAG_END,
  PairingInitiator,
  PairingResponder,
  ServerSession,
  makeInviteUri,
  newInvite,
  parseInviteUri,
  type ClientEvent,
  type ServerEvent,
  type ChannelStreamFrame,
} from "../../src/index.ts";

const utf8 = new TextEncoder();
const PROTOCOL = 1;
const gatewayPriv = new Uint8Array(32).fill(0x31);
const gatewayPub = x25519.getPublicKey(gatewayPriv);
const clientPriv = new Uint8Array(32).fill(0x42);
const SLICES = [1, 3, 7, 13, 1021, 4093];

interface Endpoint<E> {
  feed(bytes: Uint8Array): { out: Uint8Array[]; events: E[] };
}

// In-memory wire: the byte stream reaches the endpoint in a cycle of odd-sized slices.
function deliver<E>(chunks: Uint8Array[], to: Endpoint<E>): { out: Uint8Array[]; events: E[] } {
  const bytes = concatBytes(...chunks);
  const out: Uint8Array[] = [];
  const events: E[] = [];
  let i = 0;
  for (let off = 0; off < bytes.length; i += 1) {
    const size = SLICES[i % SLICES.length]!;
    const r = to.feed(bytes.subarray(off, off + size));
    out.push(...r.out);
    events.push(...r.events);
    off += size;
  }
  return { out, events };
}

// Runs both directions of a duplex until neither side has anything left to say.
function converse<A, B>(a: Endpoint<A>, b: Endpoint<B>, opening: Uint8Array[]) {
  const aEvents: A[] = [];
  const bEvents: B[] = [];
  const aToB: Uint8Array[] = [];
  const bToA: Uint8Array[] = [];
  let pending = opening;
  let rounds = 0;
  for (; rounds < 32 && pending.length > 0; rounds += 1) {
    aToB.push(...pending);
    const atB = deliver(pending, b);
    bEvents.push(...atB.events);
    bToA.push(...atB.out);
    const atA = deliver(atB.out, a);
    aEvents.push(...atA.events);
    pending = atA.out;
  }
  if (pending.length > 0) throw new Error(`duplex exchange did not settle after ${rounds} rounds`);
  return { aEvents, bEvents, aToB: concatBytes(...aToB), bToA: concatBytes(...bToA) };
}

function pairDevice(): Uint8Array {
  const t = 50_000;
  const invite = newInvite(t);
  const uri = makeInviteUri(gatewayPub, invite);
  assert.deepEqual(parseInviteUri(uri).gwPub, gatewayPub);
  const responder = new PairingResponder({ s: gatewayPriv, invite, now: () => t });
  const initiator = new PairingInitiator({ s: clientPriv, uri, deviceName: "phone" });
  const { aEvents, bEvents } = converse(initiator, responder, initiator.start());
  const enrolled = bEvents[0];
  if (aEvents[0]?.type !== "enrolled" || enrolled?.type !== "enrolled") throw new Error("pairing did not enroll");
  return enrolled.clientPub;
}

function connect() {
  const enrolledPub = pairDevice();
  const client = new ClientSession({ s: clientPriv, gatewayPub, protocol: PROTOCOL });
  const server = new ServerSession({ s: gatewayPriv, protocol: PROTOCOL, lookup: (pub) => (pub.join(",") === enrolledPub.join(",") ? "active" : "reject") });
  const run = converse<ClientEvent, ServerEvent>(client, server, client.start());
  return { client, server, ...run };
}

test("an active session moves 200 KiB each way as END-terminated stream frames", () => {
  const { client, server, aEvents, bEvents } = connect();
  assert.ok(aEvents.some((e) => e.type === "ready"));
  assert.ok(bEvents.some((e) => e.type === "ready"));
  const payload = new Uint8Array(200 * 1024);
  for (let i = 0; i < payload.length; i += 1) payload[i] = Math.imul(i + 1, 2654435761) >>> 24;
  const CHUNK = 32_749;

  for (const [from, to] of [[client, server], [server, client]] as const) {
    const wire: Uint8Array[] = [];
    for (let off = 0; off < payload.length; off += CHUNK) {
      const end = Math.min(off + CHUNK, payload.length);
      wire.push(...from.send({ stream: 3, flags: end === payload.length ? FLAG_END : FLAG_DATA, payload: payload.subarray(off, end) }));
    }
    const { events } = deliver<ClientEvent | ServerEvent>(wire, to);
    assert.ok(events.length > 1);
    const parts: Uint8Array[] = [];
    events.forEach((e, i) => {
      if (e.type !== "frame") throw new Error(`unexpected ${e.type} event`);
      assert.equal(e.frame.stream, 3);
      assert.equal(e.frame.flags, i === events.length - 1 ? FLAG_END : FLAG_DATA);
      parts.push(e.frame.payload);
    });
    assert.deepEqual(concatBytes(...parts), payload);
  }
});

test("reconnecting with the same statics derives fresh keys and rejects old records", () => {
  const first = connect();
  const oldToServer = first.client.send({ stream: 3, flags: FLAG_DATA, payload: utf8.encode("from the old session") });
  const oldToClient = first.server.send({ stream: 3, flags: FLAG_DATA, payload: utf8.encode("to the old session") });
  assert.equal(deliver(oldToServer, first.server).events.length, 1);

  const second = connect();
  assert.ok(second.aEvents.some((e) => e.type === "ready"));
  assert.notDeepEqual(second.aToB, first.aToB);
  assert.notDeepEqual(second.bToA, first.bToA);
  const fresh: ChannelStreamFrame = { stream: 3, flags: FLAG_DATA, payload: utf8.encode("from the old session") };
  const freshToServer = second.client.send(fresh);
  const freshToClient = second.server.send({ stream: 3, flags: FLAG_DATA, payload: utf8.encode("to the new session") });
  assert.notDeepEqual(concatBytes(...freshToServer), concatBytes(...oldToServer));

  assert.throws(() => second.server.feed(concatBytes(...oldToServer)));
  assert.deepEqual(second.server.feed(concatBytes(...freshToServer)), { out: [], events: [] });
  assert.throws(() => second.server.send(fresh));
  assert.throws(() => second.client.feed(concatBytes(...oldToClient)));
  assert.deepEqual(second.client.feed(concatBytes(...freshToClient)), { out: [], events: [] });
  assert.throws(() => second.client.send(fresh));
});
