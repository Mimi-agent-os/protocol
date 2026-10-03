import { x25519 } from "@noble/curves/ed25519.js";
import { concatBytes } from "@noble/hashes/utils.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac, hkdfSync } from "node:crypto";
import { Handshake } from "./noise.ts";
import {
  type InitiatorEvent,
  type ResponderEvent,
  PairingInitiator,
  PairingResponder,
  deriveSas,
} from "./pairing.ts";
import { makeInviteUri, newInvite } from "./pairing-invite.ts";

const gwPriv = new Uint8Array(32).fill(11);
const gwPub = x25519.getPublicKey(gwPriv);
const clientPriv = new Uint8Array(32).fill(22);
const utf8 = new TextEncoder();

function wireFrame(message: Uint8Array): Uint8Array {
  return concatBytes(Uint8Array.of(message.length >>> 8, message.length & 0xff), message);
}

function authenticateInvite(secret: Uint8Array, message: Uint8Array): Uint8Array {
  return createHmac("sha256", secret).update("mimi/pair-auth/v2").update(message).digest();
}

function authenticatedFrame(secret: Uint8Array, message: Uint8Array): Uint8Array {
  const authenticator = authenticateInvite(secret, message);
  try {
    return wireFrame(concatBytes(authenticator, message));
  } finally {
    authenticator.fill(0);
  }
}

function rawMessage1(invite: ReturnType<typeof newInvite>, s = clientPriv, inviteId = invite.id): { hs: Handshake; wire: Uint8Array } {
  const hs = new Handshake({
    pattern: "IKpsk2",
    initiator: true,
    prologue: utf8.encode("mimi/pair/v2"),
    s,
    rs: gwPub,
    psks: [invite.secret],
  });
  const message = hs.writeMessage(utf8.encode(JSON.stringify({ invite: inviteId })));
  return { hs, wire: authenticatedFrame(invite.secret, message) };
}

function rawHandshake(invite: ReturnType<typeof newInvite>, responder: PairingResponder, s = clientPriv): Handshake {
  const { hs, wire } = rawMessage1(invite, s);
  const reply = responder.feed(wire);
  assert.equal(reply.out.length, 1);
  hs.readMessage(reply.out[0]!.subarray(2));
  return hs;
}

// Delivers the frames in 3-byte chunks so every frame boundary lands mid-chunk.
function pump<E>(frames: Uint8Array[], to: { feed(b: Uint8Array): { out: Uint8Array[]; events: E[] } }): { out: Uint8Array[]; events: E[] } {
  const all = concatBytes(...frames);
  const out: Uint8Array[] = [];
  const events: E[] = [];
  for (let i = 0; i < all.length; i += 3) {
    const r = to.feed(all.subarray(i, Math.min(i + 3, all.length)));
    out.push(...r.out);
    events.push(...r.events);
  }
  return { out, events };
}

test("deriveSas is a deterministic 6-digit code", () => {
  const hash = Uint8Array.from({ length: 32 }, (_, i) => i);
  const sas = deriveSas(hash);
  const independentlyDerived = Buffer.from(hkdfSync("sha256", hash, Buffer.alloc(0), "mimi/approve-sas", 8));
  assert.equal(sas, String(independentlyDerived.readBigUInt64BE() % 1_000_000n).padStart(6, "0"));
  assert.equal(sas, "628815");
});

test("happy path over fragmented delivery yields the same sas on both ends", () => {
  let t = 1_000;
  const invite = newInvite(t);
  const responder = new PairingResponder({ s: gwPriv, invite, now: () => t });
  const initiator = new PairingInitiator({ s: clientPriv, uri: makeInviteUri(gwPub, invite), deviceName: "laptop" });

  const r1 = pump<ResponderEvent>(initiator.start(), responder);
  assert.equal(r1.out.length, 1);
  assert.deepEqual(r1.events, []);

  t += 5_000;
  const r2 = pump<InitiatorEvent>(r1.out, initiator);
  assert.equal(r2.out.length, 1);
  assert.deepEqual(r2.events, []);

  const r3 = pump<ResponderEvent>(r2.out, responder);
  assert.equal(r3.out.length, 1);
  assert.equal(r3.events.length, 1);
  const enrolled = r3.events[0]!;
  if (enrolled.type !== "enrolled") throw new Error("responder did not enroll");
  assert.equal(enrolled.deviceName, "laptop");
  assert.deepEqual(enrolled.clientPub, x25519.getPublicKey(clientPriv));
  assert.match(enrolled.sas, /^\d{6}$/);

  const r4 = pump<InitiatorEvent>(r3.out, initiator);
  assert.deepEqual(r4.out, []);
  assert.deepEqual(r4.events, [{ type: "enrolled", sas: enrolled.sas }]);
});

test("a coalesced trailing frame cannot add a second terminal event", () => {
  const invite = newInvite(0);
  const responder = new PairingResponder({ s: gwPriv, invite, now: () => 0 });
  const initiator = new PairingInitiator({ s: clientPriv, uri: makeInviteUri(gwPub, invite), deviceName: "phone" });
  const msg2 = responder.feed(initiator.start()[0]!).out;
  const confirm = initiator.feed(msg2[0]!).out;
  const ok = responder.feed(confirm[0]!).out[0]!;

  const result = initiator.feed(concatBytes(ok, Uint8Array.of(0, 0)));
  assert.equal(result.events.length, 1);
  assert.equal(result.events[0]?.type, "enrolled");
});

test("a coalesced hostile suffix cannot discard the responder's terminal reply", () => {
  const invite = newInvite(0);
  const responder = new PairingResponder({ s: gwPriv, invite, now: () => 0 });
  const initiator = new PairingInitiator({ s: clientPriv, uri: makeInviteUri(gwPub, invite), deviceName: "phone" });
  const msg2 = responder.feed(initiator.start()[0]!).out;
  const confirm = initiator.feed(msg2[0]!).out[0]!;

  const result = responder.feed(concatBytes(confirm, Uint8Array.of(0, 0)));
  assert.equal(result.out.length, 1);
  assert.equal(result.events.length, 1);
  assert.equal(result.events[0]?.type, "enrolled");
  assert.equal(initiator.feed(result.out[0]!).events[0]?.type, "enrolled");
});

test("an invalid suffix cannot escape a confirmation from a closed initiator", () => {
  const invite = newInvite(0);
  const responder = new PairingResponder({ s: gwPriv, invite, now: () => 0 });
  const initiator = new PairingInitiator({ s: clientPriv, uri: makeInviteUri(gwPub, invite), deviceName: "phone" });
  const msg2 = responder.feed(initiator.start()[0]!).out[0]!;

  const result = initiator.feed(concatBytes(msg2, Uint8Array.of(0, 0)));
  assert.deepEqual(result, { out: [], events: [{ type: "closed" }] });
});

test("feed before start throws without poisoning the frame decoder", () => {
  const invite = newInvite(0);
  const responder = new PairingResponder({ s: gwPriv, invite, now: () => 0 });
  const initiator = new PairingInitiator({ s: clientPriv, uri: makeInviteUri(gwPub, invite), deviceName: "phone" });

  assert.throws(() => initiator.feed(Uint8Array.of(0)), /not started/);
  const msg2 = responder.feed(initiator.start()[0]!).out[0]!;
  assert.equal(initiator.feed(msg2).out.length, 1);
});

test("destroy cancels pairing machines and is terminal", () => {
  const invite = newInvite(0);
  const responder = new PairingResponder({ s: gwPriv, invite, now: () => 0 });
  const initiator = new PairingInitiator({ s: clientPriv, uri: makeInviteUri(gwPub, invite), deviceName: "phone" });

  responder.destroy();
  responder.destroy();
  initiator.destroy();
  initiator.destroy();
  assert.deepEqual(responder.feed(new Uint8Array()), { out: [], events: [] });
  assert.deepEqual(responder.expire(), []);
  assert.deepEqual(initiator.feed(new Uint8Array()), { out: [], events: [] });
  assert.throws(() => initiator.start(), /already started/);
});

test("a Noise failure during start closes the initiator machine", () => {
  const invite = newInvite(0);
  const initiator = new PairingInitiator({
    s: clientPriv,
    uri: makeInviteUri(new Uint8Array(32), invite),
    deviceName: "phone",
  });
  assert.throws(() => initiator.start());
  assert.deepEqual(initiator.feed(Uint8Array.of(0, 0)), { out: [], events: [] });
});

test("a malformed decrypted confirmation ends that handshake attempt", () => {
  const invite = newInvite(0);
  const responder = new PairingResponder({ s: gwPriv, invite, now: () => 0 });
  for (const payload of ["{", JSON.stringify({ t: "pair_confirm" })]) {
    const hs = rawHandshake(invite, responder);
    const { send, recv } = hs.split();
    hs.destroy();
    recv.destroy();
    const malformed = responder.feed(wireFrame(send.encrypt(utf8.encode(payload))));
    send.destroy();
    assert.deepEqual(malformed, { out: [], events: [{ type: "closed", reason: "bad" }] });
  }

  const retry = new PairingInitiator({ s: clientPriv, uri: makeInviteUri(gwPub, invite), deviceName: "phone" });
  const r1 = pump<ResponderEvent>(retry.start(), responder);
  const r2 = pump<InitiatorEvent>(r1.out, retry);
  const r3 = pump<ResponderEvent>(r2.out, responder);
  assert.equal(r3.events[0]?.type, "enrolled");
});

test("a tampered final reply closes the initiator", () => {
  const invite = newInvite(0);
  const responder = new PairingResponder({ s: gwPriv, invite, now: () => 0 });
  const initiator = new PairingInitiator({ s: clientPriv, uri: makeInviteUri(gwPub, invite), deviceName: "phone" });
  const msg2 = responder.feed(initiator.start()[0]!).out[0]!;
  const confirm = initiator.feed(msg2).out[0]!;
  const reply = responder.feed(confirm).out[0]!;
  reply[reply.length - 1] = reply[reply.length - 1]! ^ 1;
  assert.deepEqual(initiator.feed(reply), { out: [], events: [{ type: "closed" }] });
  assert.deepEqual(initiator.feed(reply), { out: [], events: [] });
});

test("wrong-secret attempts and byte-identical retransmits do not spend authenticated debits", () => {
  let t = 0;
  const invite = newInvite(t);
  const uri = makeInviteUri(gwPub, invite);
  const responder = new PairingResponder({ s: gwPriv, invite, now: () => t });

  const wrongUri = makeInviteUri(gwPub, { ...invite, secret: new Uint8Array(32).fill(9) });
  for (let i = 0; i < 4; i++) {
    const wrong = new PairingInitiator({ s: new Uint8Array(32).fill(40 + i), uri: wrongUri, deviceName: "wrong" });
    const reply = responder.feed(wrong.start()[0]!);
    assert.equal(reply.out.length, 1);
    assert.deepEqual(reply.events, []);
    assert.deepEqual(wrong.feed(reply.out[0]!).events, [{ type: "closed" }]);
  }

  const { hs, wire } = rawMessage1(invite);
  const first = responder.feed(wire);
  assert.equal(first.out.length, 1);
  assert.deepEqual(first.events, []);
  const expectedReply = first.out[0]!.slice();
  first.out[0]!.fill(0);

  for (let i = 0; i < 4; i++) assert.deepEqual(responder.feed(wire.slice()), { out: [expectedReply], events: [] });
  hs.readMessage(expectedReply.subarray(2));
  const firstStates = hs.split();
  hs.destroy();
  firstStates.recv.destroy();
  const firstFailure = responder.feed(wireFrame(firstStates.send.encrypt(utf8.encode("{}"))));
  firstStates.send.destroy();
  assert.deepEqual(firstFailure, { out: [], events: [{ type: "closed", reason: "bad" }] });

  for (let i = 1; i < 3; i += 1) {
    const hs = rawHandshake(invite, responder, new Uint8Array(32).fill(22 + i));
    const { send, recv } = hs.split();
    hs.destroy();
    recv.destroy();
    const failed = responder.feed(wireFrame(send.encrypt(utf8.encode("{}"))));
    send.destroy();
    assert.deepEqual(failed, { out: [], events: [{ type: "closed", reason: "bad" }] });
  }
  const fourth = responder.feed(new PairingInitiator({ s: clientPriv, uri, deviceName: "x" }).start()[0]!);
  assert.equal(fourth.out.length, 1);
  assert.deepEqual(fourth.events, [{ type: "closed", reason: "debits" }]);
  const afterLimit = new PairingInitiator({ s: clientPriv, uri, deviceName: "x" }).start()[0]!;
  assert.deepEqual(responder.feed(afterLimit), { out: [], events: [] });
});

test("authenticated malformed Noise messages spend debits before Noise processing", () => {
  const invite = newInvite(0);
  const uri = makeInviteUri(gwPub, invite);
  const responder = new PairingResponder({ s: gwPriv, invite, now: () => 0 });

  for (let i = 0; i < 3; i++) {
    const malformed = new Uint8Array(96);
    malformed[0] = i;
    assert.deepEqual(responder.feed(authenticatedFrame(invite.secret, malformed)), {
      out: [],
      events: [{ type: "closed", reason: "bad" }],
    });
  }

  const initiator = new PairingInitiator({ s: clientPriv, uri, deviceName: "phone" });
  const limited = responder.feed(initiator.start()[0]!);
  assert.equal(limited.out.length, 1);
  assert.deepEqual(limited.events, [{ type: "closed", reason: "debits" }]);
  assert.deepEqual(responder.feed(new Uint8Array()), { out: [], events: [] });
  initiator.destroy();
});

test("a wrong secret gets a deterministic uniform reply", () => {
  const invite = newInvite(0);
  const responder = new PairingResponder({ s: gwPriv, invite, now: () => 0 });
  const wrongUri = makeInviteUri(gwPub, { ...invite, secret: new Uint8Array(32).fill(9) });

  const attacker = new PairingInitiator({ s: new Uint8Array(32).fill(7), uri: wrongUri, deviceName: "evil" });
  const request = attacker.start()[0]!;
  const r1 = responder.feed(request);
  assert.equal(r1.out.length, 1);
  assert.deepEqual(r1.events, []);
  assert.equal(r1.out[0]!.length, 50);
  assert.deepEqual(responder.feed(request.slice()), r1, "invalid retransmits get a cheap deterministic dummy reply");
  assert.deepEqual(attacker.feed(r1.out[0]!).events, [{ type: "closed" }]);
  responder.destroy();
});

test("an interleaved wrong-secret message cannot replace a genuine pending attempt", () => {
  const invite = newInvite(0);
  const responder = new PairingResponder({ s: gwPriv, invite, now: () => 0 });
  const genuine = new PairingInitiator({ s: clientPriv, uri: makeInviteUri(gwPub, invite), deviceName: "phone" });
  const first = responder.feed(genuine.start()[0]!);
  assert.equal(first.out.length, 1);

  const wrongUri = makeInviteUri(gwPub, { ...invite, secret: new Uint8Array(32).fill(9) });
  const attacker = new PairingInitiator({ s: new Uint8Array(32).fill(7), uri: wrongUri, deviceName: "evil" });
  const interleaved = responder.feed(attacker.start()[0]!);
  assert.equal(interleaved.out.length, 1);
  assert.deepEqual(interleaved.events, []);
  assert.deepEqual(attacker.feed(interleaved.out[0]!).events, [{ type: "closed" }]);

  const confirm = genuine.feed(first.out[0]!);
  const accepted = responder.feed(confirm.out[0]!);
  assert.equal(accepted.events[0]?.type, "enrolled");
  assert.equal(accepted.events[0]?.type === "enrolled" && accepted.events[0].deviceName, "phone");
});

test("an interleaved authenticated holder cannot replace a genuine pending attempt", () => {
  const invite = newInvite(0);
  const uri = makeInviteUri(gwPub, invite);
  const responder = new PairingResponder({ s: gwPriv, invite, now: () => 0 });
  const genuine = new PairingInitiator({ s: clientPriv, uri, deviceName: "phone" });
  const genuineReply = responder.feed(genuine.start()[0]!).out[0]!;
  const genuineConfirm = genuine.feed(genuineReply).out[0]!;

  const competing = new PairingInitiator({ s: new Uint8Array(32).fill(23), uri, deviceName: "tablet" });
  const competingReply = responder.feed(competing.start()[0]!);
  assert.equal(competingReply.out.length, 1);
  assert.deepEqual(competingReply.events, []);
  const competingConfirm = competing.feed(competingReply.out[0]!).out[0]!;
  assert.deepEqual(responder.feed(competingConfirm), { out: [], events: [{ type: "closed", reason: "bad" }] });

  const accepted = responder.feed(genuineConfirm);
  assert.equal(accepted.events[0]?.type, "enrolled");
  assert.equal(accepted.events[0]?.type === "enrolled" && accepted.events[0].deviceName, "phone");
  assert.equal(genuine.feed(accepted.out[0]!).events[0]?.type, "enrolled");
  competing.destroy();
});

test("fresh authenticated contenders consume a pending responder's remaining debits", () => {
  const invite = newInvite(0);
  const uri = makeInviteUri(gwPub, invite);
  const responder = new PairingResponder({ s: gwPriv, invite, now: () => 0 });
  const initiators = [22, 23, 24, 25].map((byte) => new PairingInitiator({
    s: new Uint8Array(32).fill(byte),
    uri,
    deviceName: "device",
  }));
  try {
    for (const initiator of initiators.slice(0, 3)) {
      const result = responder.feed(initiator.start()[0]!);
      assert.equal(result.out.length, 1);
      assert.deepEqual(result.events, []);
    }
    const limited = responder.feed(initiators[3]!.start()[0]!);
    assert.equal(limited.out.length, 1);
    assert.deepEqual(limited.events, [{ type: "closed", reason: "debits" }]);
  } finally {
    for (const initiator of initiators) initiator.destroy();
    responder.destroy();
  }
});

test("a bad frame during confirmation does not consume the pending enrollment", () => {
  const invite = newInvite(0);
  const responder = new PairingResponder({ s: gwPriv, invite, now: () => 0 });
  const initiator = new PairingInitiator({ s: clientPriv, uri: makeInviteUri(gwPub, invite), deviceName: "phone" });
  const reply = responder.feed(initiator.start()[0]!).out[0]!;
  const confirm = initiator.feed(reply).out[0]!;

  assert.deepEqual(responder.feed(Uint8Array.of(0, 0)), { out: [], events: [{ type: "closed", reason: "bad" }] });
  const accepted = responder.feed(confirm);
  assert.equal(accepted.events[0]?.type, "enrolled");
  assert.equal(initiator.feed(accepted.out[0]!).events[0]?.type, "enrolled");
});

test("the responder snapshots its invite and device names are bounded", () => {
  const invite = newInvite(0);
  const uri = makeInviteUri(gwPub, invite);
  const responder = new PairingResponder({ s: gwPriv, invite, now: () => 1 });
  invite.id = "AAAAAAAAAA";
  invite.secret.fill(0);
  invite.expiresAt = 0;

  const initiator = new PairingInitiator({ s: clientPriv, uri, deviceName: "phone" });
  const r1 = pump<ResponderEvent>(initiator.start(), responder);
  const r2 = pump<InitiatorEvent>(r1.out, initiator);
  assert.equal(pump<ResponderEvent>(r2.out, responder).events[0]?.type, "enrolled");

  const fresh = newInvite(0);
  const freshUri = makeInviteUri(gwPub, fresh);
  assert.doesNotThrow(() => new PairingInitiator({ s: clientPriv, uri: freshUri, deviceName: "😀".repeat(64) }));
  assert.throws(() => new PairingInitiator({ s: clientPriv, uri: freshUri, deviceName: "x".repeat(65) }), /device name/);
  assert.throws(() => new PairingInitiator({ s: clientPriv, uri: freshUri, deviceName: "😀".repeat(65) }), /device name/);
});

test("the responder rejects an authenticated oversized device name", () => {
  const invite = newInvite(0);
  const responder = new PairingResponder({ s: gwPriv, invite, now: () => 0 });
  const hs = rawHandshake(invite, responder);
  const { send, recv } = hs.split();
  hs.destroy();
  recv.destroy();
  const confirm = wireFrame(send.encrypt(utf8.encode(JSON.stringify({ t: "pair_confirm", name: "x".repeat(65) }))));
  send.destroy();
  assert.deepEqual(responder.feed(confirm), { out: [], events: [{ type: "closed", reason: "bad" }] });
});

test("stage bounds reject oversized frames without consuming the responder invite", () => {
  const invite = newInvite(0);
  const uri = makeInviteUri(gwPub, invite);
  const responder = new PairingResponder({ s: gwPriv, invite, now: () => 0 });
  assert.deepEqual(responder.feed(Uint8Array.of(0x02, 0x01)), { out: [], events: [{ type: "closed", reason: "bad" }] });
  const retry = responder.feed(new PairingInitiator({ s: clientPriv, uri, deviceName: "phone" }).start()[0]!);
  assert.equal(retry.out.length, 1);
  assert.deepEqual(retry.events, []);

  const initiator = new PairingInitiator({ s: clientPriv, uri, deviceName: "phone" });
  initiator.start();
  assert.deepEqual(initiator.feed(Uint8Array.of(0, 49)), { out: [], events: [{ type: "closed" }] });
  assert.deepEqual(initiator.feed(new Uint8Array()), { out: [], events: [] });
});

test("invite expiry is open immediately before the deadline and closed at it", () => {
  let t = 0;
  const invite = newInvite(t);
  const responder = new PairingResponder({ s: gwPriv, invite, now: () => t });
  assert.deepEqual(responder.expire(), []);
  t = 119_999;
  assert.deepEqual(responder.expire(), []);
  t = 120_000;
  assert.deepEqual(responder.expire(), [{ type: "closed", reason: "timeout" }]);
  assert.deepEqual(responder.expire(), []);
  const late = responder.feed(new PairingInitiator({ s: clientPriv, uri: makeInviteUri(gwPub, invite), deviceName: "x" }).start()[0]!);
  assert.deepEqual(late, { out: [], events: [] });
});

test("the confirm deadline is open at 9,999ms and drops only the stale attempt at 10,000ms", () => {
  let t = 0;
  const invite = newInvite(t);
  const uri = makeInviteUri(gwPub, invite);
  const responder = new PairingResponder({ s: gwPriv, invite, now: () => t });
  const initiator = new PairingInitiator({ s: clientPriv, uri, deviceName: "slow" });

  const r1 = responder.feed(initiator.start()[0]!);
  assert.equal(r1.out.length, 1);
  const r2 = pump<InitiatorEvent>(r1.out, initiator);
  assert.equal(r2.out.length, 1);

  t = 9_999;
  assert.deepEqual(responder.expire(), []);
  t = 10_000;
  assert.deepEqual(responder.expire(), [{ type: "pending_expired" }]);
  assert.deepEqual(responder.expire(), []);
  // The abandoned confirmation is now an undersized first frame; it closes that stream, not the invite.
  assert.deepEqual(responder.feed(r2.out[0]!), { out: [], events: [{ type: "closed", reason: "bad" }] });
  initiator.destroy();

  const fresh = new PairingInitiator({ s: new Uint8Array(32).fill(23), uri, deviceName: "fresh" });
  const f1 = responder.feed(fresh.start()[0]!);
  assert.equal(f1.out.length, 1);
  assert.deepEqual(f1.events, []);
  const f2 = pump<InitiatorEvent>(f1.out, fresh);
  assert.equal(pump<ResponderEvent>(f2.out, responder).events[0]?.type, "enrolled");
  fresh.destroy();
});

test("a stale pending slot expires on the next frame, which is still served", () => {
  let t = 0;
  const invite = newInvite(t);
  const uri = makeInviteUri(gwPub, invite);
  const responder = new PairingResponder({ s: gwPriv, invite, now: () => t });
  const abandoned = new PairingInitiator({ s: clientPriv, uri, deviceName: "abandoned" });
  assert.deepEqual(responder.feed(abandoned.start()[0]!).events, []);
  abandoned.destroy();

  t = 11_000;
  const second = new PairingInitiator({ s: new Uint8Array(32).fill(23), uri, deviceName: "second" });
  const r1 = responder.feed(second.start()[0]!);
  assert.deepEqual(r1.events, [{ type: "pending_expired" }]);
  assert.equal(r1.out.length, 1);
  const r2 = pump<InitiatorEvent>(r1.out, second);
  assert.equal(pump<ResponderEvent>(r2.out, responder).events[0]?.type, "enrolled");
  second.destroy();
});

test("the invite window closes a responder that still holds a pending attempt", () => {
  let t = 0;
  const invite = newInvite(t);
  const responder = new PairingResponder({ s: gwPriv, invite, now: () => t });
  const initiator = new PairingInitiator({ s: clientPriv, uri: makeInviteUri(gwPub, invite), deviceName: "slow" });
  assert.equal(responder.feed(initiator.start()[0]!).out.length, 1);
  t = 120_000;
  assert.deepEqual(responder.expire(), [{ type: "closed", reason: "timeout" }]);
  initiator.destroy();
});
